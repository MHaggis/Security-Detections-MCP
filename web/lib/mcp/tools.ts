/**
 * Hosted MCP tool registration.
 *
 * Registers ~25 read-only detection/coverage tools on a given MCP server
 * instance. Call registerHostedTools(server) from the route handler.
 *
 * Uses the modern SDK `registerTool()` API (not the deprecated `tool()`)
 * so we can set:
 *   - title       — human-readable display name
 *   - annotations — readOnlyHint, destructiveHint, idempotentHint, openWorldHint
 *   - _meta       — platform metadata for clients that surface it
 *
 * All tools in this module are READ-ONLY, IDEMPOTENT, and operate on a
 * CLOSED-WORLD corpus (our indexed detection set), so the annotations
 * below apply uniformly and Claude Code / Cursor will not prompt the
 * user on repeated calls.
 */

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  searchDetections,
  getDetectionById,
  getRawYaml,
  listDetections,
  getStats,
  getCoverageSummary,
  getThreatProfileGaps,
  getTechniqueIntelligence,
  getTechniqueFull,
  compareSourcesForTechnique,
  listBySource,
  listBySeverity,
  listByDetectionType,
  listByMitre,
  listByMitreTactic,
  searchByFilter,
  listByAnalyticStory,
  getActorProfile,
  getActorIntelligence,
  compareActors,
  listActors,
  generateNavigatorLayer,
} from './db';

// ─── Schemas shared across tools ──────────────────────────────────────────

const SOURCE_ENUM = z.enum(['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql', 'jamf_protect']);
const SEVERITY_ENUM = z.enum(['informational', 'low', 'medium', 'high', 'critical']);
const TACTIC_ENUM = z.enum([
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
]);
const THREAT_PROFILE_ENUM = z.enum([
  'ransomware',
  'apt',
  'initial-access',
  'persistence',
  'credential-access',
  'defense-evasion',
]);

// ─── Shared annotations + helpers ─────────────────────────────────────────

// All hosted tools are read-only queries against our detection corpus.
const READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

const META = {
  'detect.michaelhaag.org/category': 'security-detections',
  'detect.michaelhaag.org/version': '1.0.0',
} as const;

type McpTextContent = { type: 'text'; text: string };
type McpToolResult = { content: McpTextContent[]; isError?: boolean };

function json(result: unknown): McpToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
}

function err(message: string, extra?: Record<string, unknown>): McpToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify({ error: true, message, ...(extra ?? {}) }) }],
    isError: true,
  };
}

async function safe(name: string, fn: () => Promise<McpToolResult>): Promise<McpToolResult> {
  try {
    return await fn();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[mcp-tool:${name}] ${msg}`);
    return err(`${name} failed: ${msg}`);
  }
}

// ─── Tool registration ────────────────────────────────────────────────────

export function registerHostedTools(server: McpServer): void {
  // ─── Search & retrieval ────────────────────────────────────────────────

  server.registerTool(
    'search',
    {
      title: 'Search Detections',
      description:
        'Full-text search across all detection rules (name, description, query). Supports multi-word AND queries. Returns up to 50 detections by default.',
      inputSchema: {
        query: z.string().min(1).describe('Search query (words are AND-combined)'),
        limit: z.number().int().min(1).max(100).optional().describe('Max results (default 50)'),
        source_type: SOURCE_ENUM.optional().describe('Filter by detection source'),
      },
      annotations: { title: 'Search Detections', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ query, limit, source_type }) =>
      safe('search', async () => {
        const results = await searchDetections(query, limit ?? 50, source_type);
        if (results.length === 0) {
          return json({
            count: 0,
            detections: [],
            hint: 'No results. Try broader keywords, remove filters, or use list_by_mitre with a technique ID.',
          });
        }
        return json({ count: results.length, detections: results });
      }),
  );

  server.registerTool(
    'get_by_id',
    {
      title: 'Get Detection by ID',
      description: 'Get full details for a single detection by its ID (Sigma UUID or Splunk/Elastic slug).',
      inputSchema: {
        id: z.string().min(1).describe('Detection ID'),
      },
      annotations: { title: 'Get Detection by ID', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ id }) =>
      safe('get_by_id', async () => {
        const detection = await getDetectionById(id);
        if (!detection) return err(`Detection not found: ${id}`, { hint: 'Use search() first to find valid IDs.' });
        return json(detection);
      }),
  );

  server.registerTool(
    'get_raw_yaml',
    {
      title: 'Get Raw YAML',
      description: 'Get the original YAML content for a detection (useful for copying the rule verbatim).',
      inputSchema: {
        id: z.string().min(1).describe('Detection ID'),
      },
      annotations: { title: 'Get Raw YAML', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ id }) =>
      safe('get_raw_yaml', async () => {
        const yaml = await getRawYaml(id);
        if (!yaml) return err(`No raw YAML found for: ${id}`);
        return json({ id, yaml });
      }),
  );

  server.registerTool(
    'list_all',
    {
      title: 'List Detections',
      description: 'List detections with pagination. Prefer search() or list_by_* filters for targeted queries.',
      inputSchema: {
        limit: z.number().int().min(1).max(100).optional().describe('Max results (default 50, hard cap 100)'),
        offset: z.number().int().min(0).optional().describe('Offset for pagination'),
        source_type: SOURCE_ENUM.optional(),
      },
      annotations: { title: 'List Detections', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ limit, offset, source_type }) =>
      safe('list_all', async () => {
        const results = await listDetections(limit ?? 50, offset ?? 0, source_type);
        return json({ count: results.length, offset: offset ?? 0, limit: limit ?? 50, detections: results });
      }),
  );

  // ─── Stats & coverage ─────────────────────────────────────────────────

  server.registerTool(
    'get_stats',
    {
      title: 'Get Detection Stats',
      description: 'Get summary statistics about the indexed detection corpus (total detections, per-source counts, last sync).',
      inputSchema: {},
      annotations: { title: 'Get Detection Stats', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async () => safe('get_stats', async () => json(await getStats())),
  );

  server.registerTool(
    'get_coverage_summary',
    {
      title: 'Coverage Summary',
      description:
        'Get overall MITRE ATT&CK coverage summary — total techniques, covered techniques, coverage %, breakdowns by source and tactic, weakest/strongest tactics.',
      inputSchema: {},
      annotations: { title: 'Coverage Summary', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async () => safe('get_coverage_summary', async () => json(await getCoverageSummary())),
  );

  server.registerTool(
    'analyze_coverage',
    {
      title: 'Analyze Coverage',
      description: 'Alias for get_coverage_summary — returns the same comprehensive coverage report.',
      inputSchema: {},
      annotations: { title: 'Analyze Coverage', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async () => safe('analyze_coverage', async () => json(await getCoverageSummary())),
  );

  server.registerTool(
    'identify_gaps',
    {
      title: 'Identify Detection Gaps',
      description:
        'Identify detection gaps for a specific threat profile (ransomware, apt, initial-access, persistence, credential-access, defense-evasion). Returns prioritized uncovered techniques.',
      inputSchema: {
        threat_profile: THREAT_PROFILE_ENUM.describe('Threat profile to analyze'),
      },
      annotations: { title: 'Identify Detection Gaps', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ threat_profile }) =>
      safe('identify_gaps', async () => json(await getThreatProfileGaps(threat_profile))),
  );

  server.registerTool(
    'get_technique_intelligence',
    {
      title: 'Technique Intelligence',
      description:
        'Deep intelligence for a single MITRE technique ID: detections by source, actors using it, related sub-techniques, coverage gaps.',
      inputSchema: {
        technique_id: z
          .string()
          .regex(/^T\d{4}(\.\d{3})?$/)
          .describe('MITRE technique ID like T1059 or T1059.001'),
      },
      annotations: { title: 'Technique Intelligence', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ technique_id }) =>
      safe('get_technique_intelligence', async () => json(await getTechniqueIntelligence(technique_id))),
  );

  server.registerTool(
    'get_technique_full',
    {
      title: 'Full Technique Detail',
      description:
        'Full technique detail: all covering detections (paginated), actors using it, procedures, per-source breakdown.',
      inputSchema: {
        technique_id: z.string().regex(/^T\d{4}(\.\d{3})?$/).describe('MITRE technique ID'),
        detection_limit: z.number().int().min(1).max(100).optional().describe('Max detections to return (default 50)'),
      },
      annotations: { title: 'Full Technique Detail', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ technique_id, detection_limit }) =>
      safe('get_technique_full', async () => json(await getTechniqueFull(technique_id, detection_limit ?? 50))),
  );

  server.registerTool(
    'compare_sources',
    {
      title: 'Cross-Source Comparison',
      description:
        'Cross-source comparison for a MITRE technique: how many detections does each source (Sigma, Splunk, Elastic, KQL, Sublime, CQL) have for this technique, and which sources have no coverage.',
      inputSchema: {
        technique_id: z.string().regex(/^T\d{4}(\.\d{3})?$/).describe('MITRE technique ID'),
      },
      annotations: { title: 'Cross-Source Comparison', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ technique_id }) =>
      safe('compare_sources', async () => json(await compareSourcesForTechnique(technique_id))),
  );

  server.registerTool(
    'generate_navigator_layer',
    {
      title: 'Generate Navigator Layer',
      description:
        'Generate a MITRE ATT&CK Navigator JSON layer showing covered techniques. Output can be pasted directly into the Navigator web app.',
      inputSchema: {
        name: z.string().optional().describe('Layer name shown in Navigator'),
        source_type: SOURCE_ENUM.optional().describe('Limit the layer to one source'),
      },
      annotations: { title: 'Generate Navigator Layer', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ name, source_type }) =>
      safe('generate_navigator_layer', async () =>
        json(await generateNavigatorLayer({ name, sourceType: source_type })),
      ),
  );

  // ─── Filters ──────────────────────────────────────────────────────────

  server.registerTool(
    'list_by_source',
    {
      title: 'List by Source',
      description: 'List detections from a specific source (sigma, splunk_escu, elastic, kql, sublime, crowdstrike_cql, jamf_protect).',
      inputSchema: {
        source_type: SOURCE_ENUM,
        limit: z.number().int().min(1).max(100).optional(),
      },
      annotations: { title: 'List by Source', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ source_type, limit }) =>
      safe('list_by_source', async () =>
        json({ source_type, detections: await listBySource(source_type, limit ?? 50) }),
      ),
  );

  server.registerTool(
    'list_by_severity',
    {
      title: 'List by Severity',
      description: 'List detections at a specific severity (informational, low, medium, high, critical).',
      inputSchema: {
        severity: SEVERITY_ENUM,
        limit: z.number().int().min(1).max(100).optional(),
      },
      annotations: { title: 'List by Severity', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ severity, limit }) =>
      safe('list_by_severity', async () =>
        json({ severity, detections: await listBySeverity(severity, limit ?? 50) }),
      ),
  );

  server.registerTool(
    'list_by_detection_type',
    {
      title: 'List by Detection Type',
      description: 'List detections by detection type (e.g., "TTP", "Anomaly", "Hunting", "Correlation").',
      inputSchema: {
        detection_type: z.string().min(1).describe('Detection type label'),
        limit: z.number().int().min(1).max(100).optional(),
      },
      annotations: { title: 'List by Detection Type', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ detection_type, limit }) =>
      safe('list_by_detection_type', async () =>
        json({ detection_type, detections: await listByDetectionType(detection_type, limit ?? 50) }),
      ),
  );

  server.registerTool(
    'list_by_mitre',
    {
      title: 'List by MITRE Technique',
      description: 'List detections that reference a specific MITRE technique ID (via the detection_techniques junction table).',
      inputSchema: {
        technique_id: z.string().regex(/^T\d{4}(\.\d{3})?$/).describe('MITRE technique ID like T1059.001'),
        limit: z.number().int().min(1).max(100).optional(),
      },
      annotations: { title: 'List by MITRE Technique', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ technique_id, limit }) =>
      safe('list_by_mitre', async () =>
        json({ technique_id, detections: await listByMitre(technique_id, limit ?? 50) }),
      ),
  );

  server.registerTool(
    'list_by_mitre_tactic',
    {
      title: 'List by MITRE Tactic',
      description: 'List detections that map to a specific MITRE tactic (e.g., credential-access, defense-evasion).',
      inputSchema: {
        tactic: TACTIC_ENUM,
        limit: z.number().int().min(1).max(100).optional(),
      },
      annotations: { title: 'List by MITRE Tactic', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ tactic, limit }) =>
      safe('list_by_mitre_tactic', async () =>
        json({ tactic, detections: await listByMitreTactic(tactic, limit ?? 50) }),
      ),
  );

  server.registerTool(
    'list_by_cve',
    {
      title: 'List by CVE',
      description: 'Find detections that reference a specific CVE ID.',
      inputSchema: {
        cve: z.string().regex(/^CVE-\d{4}-\d{4,7}$/).describe('CVE identifier like CVE-2024-12345'),
        limit: z.number().int().min(1).max(50).optional(),
      },
      annotations: { title: 'List by CVE', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ cve, limit }) =>
      safe('list_by_cve', async () => json(await searchByFilter('cve', cve, limit ?? 20))),
  );

  server.registerTool(
    'list_by_process_name',
    {
      title: 'List by Process Name',
      description: 'Find detections that monitor a specific process name (e.g., rundll32.exe, powershell.exe).',
      inputSchema: {
        process_name: z.string().min(1).describe('Process executable name'),
        limit: z.number().int().min(1).max(50).optional(),
      },
      annotations: { title: 'List by Process Name', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ process_name, limit }) =>
      safe('list_by_process_name', async () => json(await searchByFilter('process_name', process_name, limit ?? 20))),
  );

  server.registerTool(
    'list_by_data_source',
    {
      title: 'List by Data Source',
      description: 'Find detections that require a specific data source (e.g., "Sysmon", "Windows Event Log", "Process Creation").',
      inputSchema: {
        data_source: z.string().min(1).describe('Data source name'),
        limit: z.number().int().min(1).max(50).optional(),
      },
      annotations: { title: 'List by Data Source', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ data_source, limit }) =>
      safe('list_by_data_source', async () => json(await searchByFilter('data_source', data_source, limit ?? 20))),
  );

  server.registerTool(
    'list_by_analytic_story',
    {
      title: 'List by Analytic Story',
      description: 'List detections that belong to a Splunk Analytic Story (e.g., "Ransomware", "Cloud Federated Credential Abuse").',
      inputSchema: {
        story: z.string().min(1).describe('Analytic story name'),
        limit: z.number().int().min(1).max(100).optional(),
      },
      annotations: { title: 'List by Analytic Story', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ story, limit }) =>
      safe('list_by_analytic_story', async () =>
        json({ story, detections: await listByAnalyticStory(story, limit ?? 50) }),
      ),
  );

  // ─── Threat actors ────────────────────────────────────────────────────

  server.registerTool(
    'list_actors',
    {
      title: 'List Threat Actors',
      description: 'List or search MITRE ATT&CK threat actors. Pass a query to search by name or alias.',
      inputSchema: {
        query: z.string().optional().describe('Search term (matches name and aliases)'),
        limit: z.number().int().min(1).max(200).optional(),
      },
      annotations: { title: 'List Threat Actors', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ query, limit }) =>
      safe('list_actors', async () => json({ actors: await listActors(limit ?? 50, query) })),
  );

  server.registerTool(
    'get_actor_profile',
    {
      title: 'Threat Actor Profile',
      description: 'Get a full profile for a threat actor: description, aliases, technique list, and detection coverage %.',
      inputSchema: {
        actor_name: z.string().min(1).describe('Threat actor name (e.g., "APT29", "FIN7")'),
      },
      annotations: { title: 'Threat Actor Profile', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ actor_name }) =>
      safe('get_actor_profile', async () => json(await getActorProfile(actor_name))),
  );

  server.registerTool(
    'analyze_actor_coverage',
    {
      title: 'Analyze Actor Coverage',
      description:
        'Deep intelligence about a threat actor: per-tactic coverage breakdown, covered techniques with detection counts, and all uncovered technique gaps.',
      inputSchema: {
        actor_name: z.string().min(1).describe('Threat actor name'),
      },
      annotations: { title: 'Analyze Actor Coverage', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ actor_name }) =>
      safe('analyze_actor_coverage', async () => json(await getActorIntelligence(actor_name))),
  );

  server.registerTool(
    'compare_actor_coverage',
    {
      title: 'Compare Actor Coverage',
      description:
        'Compare two or more threat actors side-by-side: total techniques, coverage %, shared gaps, unique gaps.',
      inputSchema: {
        actor_names: z.array(z.string().min(1)).min(2).max(5).describe('Between 2 and 5 actor names to compare'),
      },
      annotations: { title: 'Compare Actor Coverage', ...READ_ONLY_ANNOTATIONS },
      _meta: META,
    },
    async ({ actor_names }) =>
      safe('compare_actor_coverage', async () => json(await compareActors(actor_names))),
  );
}
