#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  CompleteRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import {
  searchDetections,
  getDetectionById,
  listDetections,
  listBySource,
  listByMitre,
  listByLogsource,
  listBySeverity,
  listByCve,
  listByAnalyticStory,
  listByProcessName,
  listByDetectionType,
  listByDataSource,
  listByMitreTactic,
  listByKqlCategory,
  listByKqlTag,
  listByKqlDatasource,
  getStats,
  getRawYaml,
  getDbPath,
  initDb,
  recreateDb,
  searchStories,
  getStoryByName,
  listStories,
  listStoriesByCategory,
  getTechniqueIds,
  analyzeCoverage,
  identifyGaps,
  suggestDetections,
  getDistinctTechniqueIds,
  getDistinctCves,
  getDistinctProcessNames,
  validateTechniqueId,
} from './db.js';
import { indexDetections, needsIndexing } from './indexer.js';

// Parse comma-separated paths from env var
function parsePaths(envVar: string | undefined): string[] {
  if (!envVar) return [];
  return envVar.split(',').map(p => p.trim()).filter(p => p.length > 0);
}

// Get configured paths from environment
const SIGMA_PATHS = parsePaths(process.env.SIGMA_PATHS);
const SPLUNK_PATHS = parsePaths(process.env.SPLUNK_PATHS);
const ELASTIC_PATHS = parsePaths(process.env.ELASTIC_PATHS);
const STORY_PATHS = parsePaths(process.env.STORY_PATHS);
const KQL_PATHS = parsePaths(process.env.KQL_PATHS);

// Auto-index on startup if paths are configured and DB is empty
function autoIndex(): void {
  if (SIGMA_PATHS.length === 0 && SPLUNK_PATHS.length === 0 && ELASTIC_PATHS.length === 0 && KQL_PATHS.length === 0) {
    return;
  }
  
  initDb();
  
  if (needsIndexing()) {
    console.error('[security-detections-mcp] Auto-indexing detections...');
    const result = indexDetections(SIGMA_PATHS, SPLUNK_PATHS, STORY_PATHS, ELASTIC_PATHS, KQL_PATHS);
    let msg = `[security-detections-mcp] Indexed ${result.total} detections (${result.sigma_indexed} Sigma, ${result.splunk_indexed} Splunk, ${result.elastic_indexed} Elastic, ${result.kql_indexed} KQL)`;
    if (result.stories_indexed > 0) {
      msg += `, ${result.stories_indexed} stories`;
    }
    console.error(msg);
  }
}

// Server instructions - usage guide with examples (moved from tool descriptions per best practices)
const SERVER_INSTRUCTIONS = `# Security Detections MCP - Usage Guide

## Tool Examples

### Searching
- search("powershell base64") - Find PowerShell encoding detections
- search("CVE-2024") - Find vulnerability-specific rules
- search("ransomware encryption") - Find ransomware behaviors

### Technique Coverage
- list_by_mitre("T1059.001") - PowerShell detections
- list_by_mitre("T1547.001") - Registry run key persistence
- list_by_mitre_tactic("credential-access") - All cred theft detections

### Gap Analysis
- identify_gaps("ransomware") - Find ransomware coverage gaps
- identify_gaps("apt") - Find APT coverage gaps
- analyze_coverage() - Get full tactic breakdown

### Chaining Tools
1. Start broad: get_stats() to see inventory size
2. Narrow down: list_by_mitre_tactic("execution")
3. Deep dive: get_by_id("detection-id") for full details
4. Get source: get_raw_yaml("detection-id") for original YAML

## Output Notes
- Results are JSON arrays of detection objects
- Use 'limit' parameter to control response size
- Detections include: name, description, query, mitre_ids, severity
- Use get_raw_yaml() when you need the exact original format

## Interactive Tools
- prioritize_gaps: Presents form to select which gaps to address
- plan_detection_sprint: Interactive sprint configuration
- rebuild_index: Requires confirmation before execution

## Common Argument Values
### Tactics
reconnaissance, resource-development, initial-access, execution, persistence,
privilege-escalation, defense-evasion, credential-access, discovery,
lateral-movement, collection, command-and-control, exfiltration, impact

### Source Types
sigma, splunk_escu, elastic, kql

### Severity Levels
informational, low, medium, high, critical

### Threat Profiles (for identify_gaps)
ransomware, apt, initial-access, persistence, credential-access, defense-evasion`;

// Create MCP server with instructions and full capabilities
// Note: elicitation is a client capability - server uses server.elicitInput() when available
const server = new Server(
  {
    name: 'security-detections-mcp',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
      prompts: {},
      resources: {},
      completions: {},
    },
    instructions: SERVER_INSTRUCTIONS,
  }
);

// Define available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'search',
        description: 'Full-text search across all detection fields (name, description, query, MITRE IDs, tags, CVEs, analytic stories, process names, file paths, registry paths)',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query (FTS5 syntax supported). Examples: "powershell.exe", "CVE-2024", "DLL sideloading", "web server"',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 50)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_by_id',
        description: 'Get a single detection by its ID',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Detection ID (UUID for Sigma, or Splunk detection ID)',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'list_all',
        description: 'List all detections with pagination',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
        },
      },
      {
        name: 'list_by_source',
        description: 'List detections filtered by source type',
        inputSchema: {
          type: 'object',
          properties: {
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Source type to filter by',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['source_type'],
        },
      },
      {
        name: 'list_by_mitre',
        description: 'List detections that map to a specific MITRE ATT&CK technique',
        inputSchema: {
          type: 'object',
          properties: {
            technique_id: {
              type: 'string',
              description: 'MITRE ATT&CK technique ID (e.g., T1059.001)',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['technique_id'],
        },
      },
      {
        name: 'list_by_logsource',
        description: 'List Sigma detections filtered by logsource (category, product, or service)',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description: 'Logsource category (e.g., process_creation, network_connection)',
            },
            product: {
              type: 'string',
              description: 'Logsource product (e.g., windows, linux, aws)',
            },
            service: {
              type: 'string',
              description: 'Logsource service (e.g., sysmon, security, powershell)',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
        },
      },
      {
        name: 'list_by_severity',
        description: 'List detections filtered by severity level',
        inputSchema: {
          type: 'object',
          properties: {
            level: {
              type: 'string',
              enum: ['informational', 'low', 'medium', 'high', 'critical'],
              description: 'Severity level to filter by',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['level'],
        },
      },
      {
        name: 'list_by_cve',
        description: 'List detections that cover a specific CVE vulnerability',
        inputSchema: {
          type: 'object',
          properties: {
            cve_id: {
              type: 'string',
              description: 'CVE ID (e.g., CVE-2024-27198, CVE-2021-44228)',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['cve_id'],
        },
      },
      {
        name: 'list_by_analytic_story',
        description: 'List Splunk detections that belong to a specific analytic story (e.g., "Ransomware", "Data Destruction")',
        inputSchema: {
          type: 'object',
          properties: {
            story: {
              type: 'string',
              description: 'Analytic story name or partial match (e.g., "Ransomware", "Windows Persistence")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['story'],
        },
      },
      {
        name: 'list_by_process_name',
        description: 'List detections that reference a specific process name (e.g., "powershell.exe", "w3wp.exe", "cmd.exe")',
        inputSchema: {
          type: 'object',
          properties: {
            process_name: {
              type: 'string',
              description: 'Process name to search for (e.g., "powershell.exe", "cmd.exe", "nginx.exe")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['process_name'],
        },
      },
      {
        name: 'list_by_detection_type',
        description: 'List detections by type (TTP, Anomaly, Hunting, Correlation)',
        inputSchema: {
          type: 'object',
          properties: {
            detection_type: {
              type: 'string',
              enum: ['TTP', 'Anomaly', 'Hunting', 'Correlation'],
              description: 'Detection type to filter by',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['detection_type'],
        },
      },
      {
        name: 'list_by_data_source',
        description: 'List detections that use a specific data source (e.g., "Sysmon", "Windows Security", "process_creation")',
        inputSchema: {
          type: 'object',
          properties: {
            data_source: {
              type: 'string',
              description: 'Data source to search for (e.g., "Sysmon", "Windows Security", "process_creation")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['data_source'],
        },
      },
      {
        name: 'list_by_mitre_tactic',
        description: 'List detections by MITRE ATT&CK tactic (e.g., "execution", "persistence", "credential-access")',
        inputSchema: {
          type: 'object',
          properties: {
            tactic: {
              type: 'string',
              enum: ['reconnaissance', 'resource-development', 'initial-access', 'execution', 
                     'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
                     'discovery', 'lateral-movement', 'collection', 'command-and-control', 
                     'exfiltration', 'impact'],
              description: 'MITRE ATT&CK tactic to filter by',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['tactic'],
        },
      },
      {
        name: 'list_by_kql_category',
        description: 'List KQL detections filtered by category (e.g., "Defender For Endpoint", "Azure Active Directory", "Threat Hunting")',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description: 'KQL category derived from folder path (e.g., "Defender For Endpoint", "DFIR", "Sentinel")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['category'],
        },
      },
      {
        name: 'list_by_kql_tag',
        description: 'List KQL detections filtered by tag (e.g., "ransomware", "hunting", "ti-feed")',
        inputSchema: {
          type: 'object',
          properties: {
            tag: {
              type: 'string',
              description: 'Tag to filter by (e.g., "ransomware", "dfir", "apt")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['tag'],
        },
      },
      {
        name: 'list_by_kql_datasource',
        description: 'List KQL detections that use a specific Microsoft data source (e.g., "DeviceProcessEvents", "SigninLogs", "EmailEvents")',
        inputSchema: {
          type: 'object',
          properties: {
            data_source: {
              type: 'string',
              description: 'Microsoft KQL table name (e.g., "DeviceProcessEvents", "AADSignInEventsBeta", "CloudAppEvents")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['data_source'],
        },
      },
      {
        name: 'search_stories',
        description: 'Search analytic stories by narrative, description, or name. Stories provide rich context about threat campaigns and detection strategies.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query for stories (e.g., "ransomware encryption", "credential theft", "persistence")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 20)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_story',
        description: 'Get detailed information about a specific analytic story by name',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Story name (e.g., "Ransomware", "Windows Persistence Techniques")',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'list_stories',
        description: 'List all analytic stories with pagination',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
        },
      },
      {
        name: 'list_stories_by_category',
        description: 'List analytic stories by category (e.g., "Malware", "Adversary Tactics", "Abuse")',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description: 'Story category (e.g., "Malware", "Adversary Tactics", "Abuse", "Cloud Security")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['category'],
        },
      },
      {
        name: 'get_stats',
        description: 'Get statistics about the indexed detections and stories',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'rebuild_index',
        description: 'Force re-index all detections and stories from configured paths',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_raw_yaml',
        description: 'Get the original YAML content for a detection',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Detection ID',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_technique_ids',
        description: 'Get ONLY unique MITRE technique IDs (lightweight - no full detection data). Use this for Navigator layer generation or coverage analysis.',
        inputSchema: {
          type: 'object',
          properties: {
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Filter by source type',
            },
            tactic: {
              type: 'string',
              enum: ['reconnaissance', 'resource-development', 'initial-access', 'execution', 
                     'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
                     'discovery', 'lateral-movement', 'collection', 'command-and-control', 
                     'exfiltration', 'impact'],
              description: 'Filter by MITRE tactic',
            },
            severity: {
              type: 'string',
              enum: ['informational', 'low', 'medium', 'high', 'critical'],
              description: 'Filter by severity',
            },
          },
        },
      },
      {
        name: 'analyze_coverage',
        description: 'Get coverage analysis with stats by tactic, top covered techniques, and weak spots. Returns summary data, not raw detections. Use this instead of listing detections and processing manually.',
        inputSchema: {
          type: 'object',
          properties: {
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Filter by source type (optional - analyzes all if not specified)',
            },
          },
        },
      },
      {
        name: 'identify_gaps',
        description: 'Identify detection gaps based on a threat profile (ransomware, apt, initial-access, persistence, credential-access, defense-evasion). Returns prioritized gaps with recommendations.',
        inputSchema: {
          type: 'object',
          properties: {
            threat_profile: {
              type: 'string',
              enum: ['ransomware', 'apt', 'initial-access', 'persistence', 'credential-access', 'defense-evasion'],
              description: 'Threat profile to analyze gaps against',
            },
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Filter by source type (optional)',
            },
          },
          required: ['threat_profile'],
        },
      },
      {
        name: 'suggest_detections',
        description: 'Get detection suggestions for a specific technique. Returns existing detections, required data sources, and detection ideas.',
        inputSchema: {
          type: 'object',
          properties: {
            technique_id: {
              type: 'string',
              description: 'MITRE technique ID (e.g., T1059.001, T1547.001)',
            },
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Filter by source type (optional)',
            },
          },
          required: ['technique_id'],
        },
      },
      // Interactive tools using elicitation
      {
        name: 'prioritize_gaps',
        description: 'Interactive gap prioritization. Analyzes gaps for a threat profile and presents a form to select which gaps to focus on.',
        inputSchema: {
          type: 'object',
          properties: {
            threat_profile: {
              type: 'string',
              enum: ['ransomware', 'apt', 'initial-access', 'persistence', 'credential-access', 'defense-evasion'],
              description: 'Threat profile to analyze',
            },
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Filter by source type (optional)',
            },
          },
          required: ['threat_profile'],
        },
      },
      {
        name: 'plan_detection_sprint',
        description: 'Interactive detection sprint planner. Presents a form to configure sprint capacity, threat focus, and data sources.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'analyze_threat_actor',
        description: 'Interactive threat actor analysis. Asks context questions (industry, concerns, environment) then provides tailored analysis.',
        inputSchema: {
          type: 'object',
          properties: {
            actor_name: {
              type: 'string',
              description: 'Threat actor name (e.g., APT29, Lazarus Group, Volt Typhoon)',
            },
          },
          required: ['actor_name'],
        },
      },
      {
        name: 'smart_compare',
        description: 'Interactively compare detections across sources, tactics, or techniques. Dynamically shows what you have.',
        inputSchema: {
          type: 'object',
          properties: {
            topic: {
              type: 'string',
              description: 'Topic to compare (e.g., "powershell", "credential dumping", "T1059")',
            },
          },
          required: ['topic'],
        },
      },
      // Lightweight summary tools
      {
        name: 'get_coverage_summary',
        description: 'Get a lightweight coverage summary (~200 bytes) with tactic percentages. Use this for quick overviews instead of full analyze_coverage.',
        inputSchema: {
          type: 'object',
          properties: {
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Filter by source type (optional)',
            },
          },
        },
      },
      {
        name: 'get_top_gaps',
        description: 'Get just the top 5 gaps (~300 bytes) for a threat profile. Use this for quick gap checks.',
        inputSchema: {
          type: 'object',
          properties: {
            threat_profile: {
              type: 'string',
              enum: ['ransomware', 'apt', 'initial-access', 'persistence', 'credential-access', 'defense-evasion'],
              description: 'Threat profile to check',
            },
          },
          required: ['threat_profile'],
        },
      },
      {
        name: 'get_technique_count',
        description: 'Get just the detection count for a technique (~50 bytes). Use this for quick coverage checks.',
        inputSchema: {
          type: 'object',
          properties: {
            technique_id: {
              type: 'string',
              description: 'MITRE technique ID (e.g., T1059.001)',
            },
          },
          required: ['technique_id'],
        },
      },
    ],
  };
});

// =============================================================================
// MCP PROMPTS - Expert Detection Engineering Workflows
// =============================================================================

const PROMPTS = [
  {
    name: 'ransomware-readiness-assessment',
    description: 'Comprehensive ransomware detection coverage analysis with gap identification, risk scoring, and prioritized remediation roadmap. Perfect for security assessments and board reporting.',
    arguments: [
      { name: 'priority_focus', description: 'Focus area: "prevention", "detection", "response", or "all" (default: all)', required: false },
    ],
  },
  {
    name: 'apt-threat-emulation',
    description: 'Assess detection coverage against a specific APT group. Maps group TTPs to your detections, identifies blind spots, and generates a purple team test plan.',
    arguments: [
      { name: 'threat_actor', description: 'APT group name (e.g., APT29, Lazarus Group, Volt Typhoon, Scattered Spider)', required: true },
      { name: 'include_test_plan', description: 'Generate atomic test recommendations (default: true)', required: false },
    ],
  },
  {
    name: 'purple-team-exercise',
    description: 'Generate a complete purple team exercise plan with attack simulations, expected detections, and validation procedures for a specific tactic or technique.',
    arguments: [
      { name: 'scope', description: 'MITRE tactic (e.g., "initial-access", "persistence") or technique ID (e.g., "T1059.001")', required: true },
      { name: 'environment', description: 'Target environment: "windows", "linux", "cloud", "hybrid" (default: hybrid)', required: false },
    ],
  },
  {
    name: 'soc-investigation-assist',
    description: 'SOC analyst investigation assistant. Given an alert or indicator, provides triage guidance, related detections, hunting queries, and escalation criteria.',
    arguments: [
      { name: 'indicator', description: 'The alert name, process name, technique, or IOC to investigate', required: true },
      { name: 'context', description: 'Additional context (e.g., "seen on domain controller", "after hours activity")', required: false },
    ],
  },
  {
    name: 'detection-engineering-sprint',
    description: 'Generate a prioritized detection engineering backlog for a sprint. Analyzes gaps, considers threat landscape, and produces actionable user stories with acceptance criteria.',
    arguments: [
      { name: 'sprint_capacity', description: 'Number of detections to target (default: 5)', required: false },
      { name: 'threat_focus', description: 'Focus: "ransomware", "apt", "insider", "cloud", or "balanced" (default: balanced)', required: false },
    ],
  },
  {
    name: 'executive-security-briefing',
    description: 'Generate a C-level security posture briefing. Translates technical detection coverage into business risk language with metrics, trends, and investment recommendations.',
    arguments: [
      { name: 'audience', description: 'Target audience: "board", "ciso", "cto" (default: ciso)', required: false },
      { name: 'include_benchmarks', description: 'Include industry benchmark comparisons (default: true)', required: false },
    ],
  },
  {
    name: 'cve-response-assessment',
    description: 'Rapid assessment of detection coverage for a new CVE or emerging threat. Identifies existing coverage, gaps, and provides immediate detection recommendations.',
    arguments: [
      { name: 'cve_or_threat', description: 'CVE ID (e.g., CVE-2024-27198) or threat name (e.g., "Log4Shell", "ProxyShell")', required: true },
    ],
  },
  {
    name: 'data-source-gap-analysis',
    description: 'Analyze what data sources you need to improve detection coverage. Maps current capabilities to required telemetry and prioritizes collection improvements.',
    arguments: [
      { name: 'target_coverage', description: 'Target: specific tactic, technique, or "comprehensive" (default: comprehensive)', required: false },
    ],
  },
  {
    name: 'detection-quality-review',
    description: 'Deep-dive quality review of detections for a specific technique. Analyzes detection logic, identifies bypasses, suggests improvements, and rates effectiveness.',
    arguments: [
      { name: 'technique_id', description: 'MITRE technique ID to review (e.g., T1059.001)', required: true },
    ],
  },
  {
    name: 'threat-landscape-sync',
    description: 'Sync your detection coverage with the current threat landscape. Analyzes top threat actors, recent campaigns, and emerging techniques to identify priority gaps.',
    arguments: [
      { name: 'industry', description: 'Your industry vertical for threat relevance (e.g., "finance", "healthcare", "technology")', required: false },
    ],
  },
  {
    name: 'detection-coverage-diff',
    description: 'Compare detection coverage between two states or against a threat profile. Useful for measuring progress or planning improvements.',
    arguments: [
      { name: 'compare_against', description: 'Comparison target: APT group name, threat profile, or "baseline"', required: true },
    ],
  },
];

// List available prompts
server.setRequestHandler(ListPromptsRequestSchema, async () => {
  return { prompts: PROMPTS };
});

// =============================================================================
// MCP RESOURCES - Readable Context for LLMs
// =============================================================================

server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return {
    resources: [
      {
        uri: 'detection://stats',
        name: 'Detection Statistics',
        description: 'Current inventory statistics including counts by source, severity, tactic',
        mimeType: 'application/json',
      },
      {
        uri: 'detection://coverage-summary',
        name: 'Coverage Summary',
        description: 'Tactic-by-tactic coverage percentages',
        mimeType: 'application/json',
      },
      {
        uri: 'detection://gaps/ransomware',
        name: 'Ransomware Gaps',
        description: 'Current ransomware detection gaps',
        mimeType: 'application/json',
      },
      {
        uri: 'detection://gaps/apt',
        name: 'APT Gaps',
        description: 'Current APT detection gaps',
        mimeType: 'application/json',
      },
      {
        uri: 'detection://top-techniques',
        name: 'Top Covered Techniques',
        description: 'Top 20 techniques with most detection coverage',
        mimeType: 'application/json',
      },
    ],
  };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;
  
  switch (uri) {
    case 'detection://stats': {
      const stats = getStats();
      return {
        contents: [{
          uri,
          mimeType: 'application/json',
          text: JSON.stringify(stats, null, 2),
        }],
      };
    }
    
    case 'detection://coverage-summary': {
      const report = analyzeCoverage();
      const summary = {
        total_techniques: report.summary.total_techniques,
        total_detections: report.summary.total_detections,
        coverage_by_tactic: Object.fromEntries(
          Object.entries(report.summary.coverage_by_tactic).map(
            ([tactic, data]) => [tactic, `${data.percent}%`]
          )
        ),
      };
      return {
        contents: [{
          uri,
          mimeType: 'application/json',
          text: JSON.stringify(summary, null, 2),
        }],
      };
    }
    
    case 'detection://gaps/ransomware': {
      const gaps = identifyGaps('ransomware');
      return {
        contents: [{
          uri,
          mimeType: 'application/json',
          text: JSON.stringify({
            threat_profile: gaps.threat_profile,
            total_gaps: gaps.total_gaps,
            critical_gaps: gaps.critical_gaps.slice(0, 10),
            recommendations: gaps.recommendations,
          }, null, 2),
        }],
      };
    }
    
    case 'detection://gaps/apt': {
      const gaps = identifyGaps('apt');
      return {
        contents: [{
          uri,
          mimeType: 'application/json',
          text: JSON.stringify({
            threat_profile: gaps.threat_profile,
            total_gaps: gaps.total_gaps,
            critical_gaps: gaps.critical_gaps.slice(0, 10),
            recommendations: gaps.recommendations,
          }, null, 2),
        }],
      };
    }
    
    case 'detection://top-techniques': {
      const report = analyzeCoverage();
      return {
        contents: [{
          uri,
          mimeType: 'application/json',
          text: JSON.stringify({
            top_covered: report.top_covered,
            weak_coverage: report.weak_coverage,
          }, null, 2),
        }],
      };
    }
    
    default:
      throw new Error(`Unknown resource: ${uri}`);
  }
});

// =============================================================================
// MCP COMPLETIONS - Argument Autocomplete
// =============================================================================

// Static lists for completions
const TACTIC_COMPLETIONS = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact'
];

const SEVERITY_COMPLETIONS = ['informational', 'low', 'medium', 'high', 'critical'];
const SOURCE_TYPE_COMPLETIONS = ['sigma', 'splunk_escu', 'elastic', 'kql'];
const THREAT_PROFILE_COMPLETIONS = ['ransomware', 'apt', 'initial-access', 'persistence', 'credential-access', 'defense-evasion'];
const DETECTION_TYPE_COMPLETIONS = ['TTP', 'Anomaly', 'Hunting', 'Correlation'];

server.setRequestHandler(CompleteRequestSchema, async (request) => {
  const { argument } = request.params;
  const argName = argument.name;
  const value = argument.value || '';
  
  let completions: string[] = [];
  
  // Match argument name to appropriate completions
  switch (argName) {
    case 'technique_id':
      completions = getDistinctTechniqueIds(value, 10);
      break;
      
    case 'cve_id':
      completions = getDistinctCves(value, 10);
      break;
      
    case 'process_name':
      completions = getDistinctProcessNames(value, 10);
      break;
      
    case 'tactic':
      completions = TACTIC_COMPLETIONS.filter(t => 
        t.toLowerCase().startsWith(value.toLowerCase())
      );
      break;
      
    case 'level':
    case 'severity':
      completions = SEVERITY_COMPLETIONS.filter(s => 
        s.toLowerCase().startsWith(value.toLowerCase())
      );
      break;
      
    case 'source_type':
      completions = SOURCE_TYPE_COMPLETIONS.filter(s => 
        s.toLowerCase().startsWith(value.toLowerCase())
      );
      break;
      
    case 'threat_profile':
      completions = THREAT_PROFILE_COMPLETIONS.filter(t => 
        t.toLowerCase().startsWith(value.toLowerCase())
      );
      break;
      
    case 'detection_type':
      completions = DETECTION_TYPE_COMPLETIONS.filter(d => 
        d.toLowerCase().startsWith(value.toLowerCase())
      );
      break;
      
    default:
      completions = [];
  }
  
  return {
    completion: {
      values: completions.slice(0, 10),
      hasMore: completions.length > 10,
    },
  };
});

// Handle prompt requests
server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  switch (name) {
    case 'ransomware-readiness-assessment': {
      const focus = args?.priority_focus || 'all';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `# Ransomware Readiness Assessment

You are a senior detection engineer conducting a comprehensive ransomware readiness assessment. Your goal is to provide an actionable, risk-scored analysis that can be used for security planning and executive reporting.

## Assessment Scope
Focus area: ${focus}

## Required Analysis Steps

### Phase 1: Current State Assessment
1. **Get baseline statistics** using \`get_stats\` to understand overall detection inventory
2. **Analyze ransomware-specific coverage** using \`identify_gaps\` with threat_profile "ransomware"
3. **Review coverage by tactic** using \`analyze_coverage\` to see tactic-level distribution

### Phase 2: Threat-Informed Gap Analysis
4. **Map to ransomware kill chain stages:**
   - Initial Access (phishing, exploitation)
   - Execution (scripts, malware)
   - Persistence (scheduled tasks, registry)
   - Privilege Escalation (token manipulation, UAC bypass)
   - Defense Evasion (disabling security tools, clearing logs)
   - Credential Access (LSASS dumping, Kerberoasting)
   - Discovery (network scanning, AD enumeration)
   - Lateral Movement (RDP, PsExec, WMI)
   - Collection (staging data)
   - Impact (encryption, data destruction)

5. **For top 5 critical gaps**, use \`suggest_detections\` to get specific recommendations

### Phase 3: Risk Scoring
6. Calculate coverage scores:
   - Per kill chain stage (0-100%)
   - Overall ransomware readiness score
   - Time-to-detect estimation for each stage

### Phase 4: Remediation Roadmap
7. Generate prioritized recommendations:
   - **Immediate (Week 1)**: Critical blind spots
   - **Short-term (Month 1)**: High-value detections
   - **Medium-term (Quarter)**: Comprehensive coverage
   - **Long-term**: Advanced analytics and ML

## Output Format

### Executive Summary
- Overall Readiness Score: X/100
- Critical Gaps: X
- Key Risk: [One sentence]

### Coverage Heatmap by Kill Chain Stage
| Stage | Coverage | Risk Level | Priority |
|-------|----------|------------|----------|

### Critical Findings
[Numbered list with severity, gap description, and business impact]

### Recommended Detection Investments
[Prioritized list with effort estimation and expected risk reduction]

### Quick Wins (Implement This Week)
[Specific detections that can be deployed immediately]

### Metrics for Tracking Progress
[KPIs to measure improvement over time]

Begin the assessment now, using the tools systematically to build a complete picture.`
            }
          }
        ]
      };
    }
    
    case 'apt-threat-emulation': {
      const actor = args?.threat_actor || 'APT29';
      const includeTestPlan = args?.include_test_plan !== 'false';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `# APT Threat Emulation Assessment: ${actor}

You are a threat intelligence analyst and purple team lead conducting an adversary emulation assessment. Your goal is to evaluate detection coverage against ${actor}'s known TTPs and provide a realistic threat emulation plan.

## Assessment Workflow

### Phase 1: Threat Actor Intelligence
1. **Research the threat actor** using MITRE ATT&CK tools:
   - Use \`search_groups\` to find the group ID for "${actor}"
   - Use \`get_group\` to get detailed information about the group
   - Use \`get_group_techniques\` to get ALL techniques attributed to this actor

2. **Document actor profile:**
   - Known aliases
   - Attribution/origin
   - Target industries and regions
   - Notable campaigns
   - Primary objectives (espionage, financial, disruption)

### Phase 2: TTP Coverage Analysis
3. **Map techniques to your detections:**
   - For each technique used by ${actor}, use \`list_by_mitre\` to find existing detections
   - Track: technique ID, technique name, number of detections, detection quality

4. **Calculate coverage metrics:**
   - Total techniques used by actor: X
   - Techniques with detections: Y
   - Coverage percentage: Y/X
   - Techniques with 0 detections (blind spots)
   - Techniques with weak coverage (1 detection)

5. **Identify critical gaps** - prioritize by:
   - Technique prevalence in actor's operations
   - Detection difficulty
   - Potential impact if missed

### Phase 3: Detection Gap Deep-Dive
6. **For top 10 uncovered techniques**, use \`suggest_detections\` to get:
   - Required data sources
   - Detection strategies
   - Example detection logic

7. **Use \`get_technique\`** from MITRE ATT&CK for each gap to understand:
   - Technique description and procedure examples
   - Detection guidance from MITRE
   - Mitigations available

### Phase 4: Purple Team Exercise Plan ${includeTestPlan ? '(INCLUDED)' : '(SKIPPED)'}
${includeTestPlan ? `
8. **Generate adversary emulation plan:**
   
   For each phase of a typical ${actor} intrusion:
   
   a) **Initial Access Simulation**
      - Specific technique to test
      - Tool/method for simulation
      - Expected detection(s) to fire
      - Success criteria
   
   b) **Persistence Establishment**
      - Technique and procedure
      - Atomic Red Team test ID (if applicable)
      - Expected alerts
   
   c) **Privilege Escalation**
      - Attack simulation method
      - Detection validation steps
   
   d) **Lateral Movement**
      - Movement technique
      - Validation procedure
   
   e) **Objective Execution**
      - Final action simulation
      - Detection expectations

9. **Document test procedures:**
   - Pre-test checklist
   - Safety controls
   - Rollback procedures
   - Evidence collection requirements
` : ''}

## Output Format

### Threat Actor Profile
| Attribute | Value |
|-----------|-------|
| Group ID | |
| Aliases | |
| Origin | |
| Targets | |
| Active Since | |

### Coverage Assessment
**Overall Coverage: X%** (Y of Z techniques)

| Risk Level | Count | Description |
|------------|-------|-------------|
| 🔴 Critical Gaps | | No detection, high-impact techniques |
| 🟠 Weak Coverage | | Single detection, easily bypassed |
| 🟡 Moderate | | Multiple detections, some gaps |
| 🟢 Strong | | Robust multi-layer detection |

### Technique Coverage Matrix
| Technique ID | Name | Detections | Gap Risk | Priority |
|--------------|------|------------|----------|----------|

### Critical Blind Spots (Action Required)
[Detailed analysis of top gaps with detection recommendations]

${includeTestPlan ? `
### Purple Team Test Plan
[Structured test scenarios with procedures and expected outcomes]

### Validation Checklist
[ ] Pre-test coordination complete
[ ] Safety controls in place
[ ] Detection baseline captured
[ ] Test execution documented
[ ] Results analyzed
[ ] Gaps remediated
[ ] Re-test scheduled
` : ''}

### Recommendations
1. Immediate actions
2. Detection development priorities
3. Data collection improvements
4. Long-term capability gaps

Begin the assessment now.`
            }
          }
        ]
      };
    }
    
    case 'purple-team-exercise': {
      const scope = args?.scope || 'execution';
      const environment = args?.environment || 'hybrid';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `# Purple Team Exercise Planning: ${scope}

You are a purple team lead designing an exercise to validate detection capabilities for **${scope}** in a **${environment}** environment.

## Exercise Design Workflow

### Phase 1: Scope Definition
1. **Determine exercise boundaries:**
   - If "${scope}" is a tactic (e.g., "execution", "persistence"):
     - Use \`list_techniques_by_tactic\` to get all techniques in this tactic
     - Select top 10 most relevant techniques for testing
   - If "${scope}" is a technique ID (e.g., "T1059.001"):
     - Use \`get_technique\` to get full details
     - Include sub-techniques if applicable

2. **Map current detection coverage:**
   - Use \`list_by_mitre_tactic\` or \`list_by_mitre\` depending on scope
   - Document existing detections for each in-scope technique
   - Identify gaps and weak spots

### Phase 2: Test Case Development
3. **For each technique in scope**, create test cases:
   
   Use \`get_technique\` to understand:
   - Procedure examples (how attackers actually do this)
   - Required permissions/access
   - Detection opportunities
   
   Use \`suggest_detections\` to identify:
   - Data sources needed
   - Detection logic approaches
   - Expected observables

4. **Design atomic tests:**

   For each test case, document:
   
   **Test ID**: PT-{scope}-{number}
   **Technique**: T1XXX.XXX - Name
   **Objective**: What are we validating?
   
   **Prerequisites**:
   - Required access/permissions
   - Environment setup
   - Tools needed
   
   **Execution Steps**:
   1. Step-by-step attack procedure
   2. Commands/actions to perform
   3. Expected system behavior
   
   **Expected Detections**:
   - Detection name(s) that should fire
   - Alert fields to verify
   - Timeline expectations
   
   **Validation Criteria**:
   - [ ] Alert generated within X minutes
   - [ ] Correct technique mapped
   - [ ] Sufficient context for investigation
   - [ ] No false positive on similar benign activity
   
   **Cleanup**:
   - Rollback steps
   - Artifact removal

### Phase 3: Exercise Execution Plan
5. **Create execution timeline:**

   | Time | Activity | Team | Notes |
   |------|----------|------|-------|
   | T-1d | Pre-brief | All | Review scope and safety |
   | T-0 | Begin exercise | Red | Start test execution |
   | T+30m | First check | Blue | Review initial alerts |
   | ... | ... | ... | ... |

6. **Safety controls:**
   - Scope limitations (what's off-limits)
   - Kill switch procedures
   - Escalation contacts
   - Rollback triggers

### Phase 4: Metrics and Reporting
7. **Define success metrics:**

   | Metric | Target | Measurement |
   |--------|--------|-------------|
   | Detection Rate | >80% | Tests detected / Tests run |
   | MTTD | <15 min | Time from execution to alert |
   | Alert Quality | >90% | Actionable alerts / Total alerts |
   | False Positive Rate | <10% | FPs / Total alerts |

## Environment Specifics: ${environment}

${environment === 'windows' || environment === 'hybrid' ? `
### Windows-Specific Considerations
- Ensure Sysmon is configured with appropriate config
- Enable PowerShell Script Block Logging
- Enable Command Line Process Auditing
- Verify Windows Event Log collection
- Test with both local and domain accounts
` : ''}
${environment === 'linux' || environment === 'hybrid' ? `
### Linux-Specific Considerations
- Ensure auditd rules are configured
- Verify syslog collection
- Enable bash history logging
- Test with root and non-root users
- Consider container vs host differences
` : ''}
${environment === 'cloud' || environment === 'hybrid' ? `
### Cloud-Specific Considerations
- Verify cloud audit log collection (CloudTrail, Activity Log, etc.)
- Test across different account/subscription types
- Consider API-based attacks
- Include identity-based attack scenarios
- Test cloud-native and lift-and-shift scenarios
` : ''}

## Output Format

### Exercise Overview
**Scope**: ${scope}
**Environment**: ${environment}
**Techniques in Scope**: X
**Estimated Duration**: X hours
**Risk Level**: Low/Medium/High

### Detection Baseline
| Technique | Current Detections | Expected Outcome | Gap Risk |
|-----------|-------------------|------------------|----------|

### Test Cases
[Detailed test cases for each technique]

### Execution Timeline
[Hour-by-hour exercise schedule]

### Safety Plan
[Scope limits, kill switches, contacts]

### Success Criteria
[Metrics and pass/fail thresholds]

### Post-Exercise Actions
1. Detection gap remediation
2. Alert tuning requirements
3. Runbook updates needed
4. Re-test schedule

Begin planning the exercise now.`
            }
          }
        ]
      };
    }
    
    case 'soc-investigation-assist': {
      const indicator = args?.indicator || 'suspicious process';
      const context = args?.context || '';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `# SOC Investigation Assistant

You are a senior SOC analyst assisting with the investigation of: **${indicator}**
${context ? `\nAdditional context: ${context}` : ''}

## Investigation Workflow

### Phase 1: Initial Triage
1. **Identify related detections:**
   - Use \`search\` to find detections related to "${indicator}"
   - Look for process names, technique patterns, or behavioral indicators
   - Document which detections might have fired

2. **Map to MITRE ATT&CK:**
   - Use \`search_techniques\` to identify likely technique(s)
   - Get technique details with \`get_technique\`
   - Understand the attack context and typical procedure

3. **Assess severity:**
   - Technique risk level
   - Asset criticality (if context provided)
   - Known threat actor associations

### Phase 2: Enrichment
4. **Gather threat intelligence:**
   - Check if technique is associated with specific groups using \`search_groups\`
   - Identify if this is part of a known attack pattern
   - Document any relevant campaigns or malware families

5. **Find related indicators:**
   - What other techniques typically accompany this one?
   - What should we look for before/after this activity?
   - Use \`get_technique\` to check related techniques

### Phase 3: Detection Review
6. **Analyze available detections:**
   - Use \`list_by_mitre\` for the identified technique(s)
   - Review detection logic quality
   - Identify any detection gaps in the attack chain

7. **Generate hunting queries:**
   - Based on the technique's data sources
   - Look for related activity that might not alert
   - Identify scope of potential compromise

### Phase 4: Response Guidance
8. **Document investigation steps:**

   **Immediate Questions to Answer:**
   - Is this malicious or legitimate?
   - What is the scope of impact?
   - Is the activity ongoing?
   - What is the source/entry point?

   **Evidence to Collect:**
   - Relevant log entries
   - Process execution history
   - Network connections
   - File modifications
   - User context

   **Escalation Criteria:**
   - When to escalate to Tier 2/3
   - When to invoke IR
   - Management notification triggers

## Output Format

### Alert Triage Summary
| Field | Value |
|-------|-------|
| Indicator | ${indicator} |
| Likely Technique | T1XXX - Name |
| Severity | Critical/High/Medium/Low |
| Confidence | High/Medium/Low |
| Recommended Action | Investigate/Escalate/Close |

### MITRE ATT&CK Context
**Technique**: [ID and Name]
**Tactic**: [Parent tactic]
**Description**: [Brief description]
**Threat Actors**: [Known groups using this technique]

### Related Detections in Your Environment
| Detection Name | Confidence | Data Source |
|----------------|------------|-------------|

### Investigation Checklist
- [ ] Verify alert is not false positive
- [ ] Identify affected systems
- [ ] Check for lateral movement indicators
- [ ] Review user account activity
- [ ] Check for persistence mechanisms
- [ ] Document timeline of events

### Hunting Queries
\`\`\`
[Relevant KQL/SPL queries for deeper investigation]
\`\`\`

### Questions to Answer
1. [Specific questions for this investigation]

### Escalation Decision Tree
\`\`\`
If [condition] → Escalate to [team]
If [condition] → Invoke IR playbook [name]
If [benign indicators] → Document and close
\`\`\`

### Related Activity to Hunt For
[Techniques and indicators commonly seen with this activity]

Begin the investigation assistance now.`
            }
          }
        ]
      };
    }
    
    case 'detection-engineering-sprint': {
      const capacity = args?.sprint_capacity || '5';
      const focus = args?.threat_focus || 'balanced';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `# Detection Engineering Sprint Planning

You are a detection engineering lead planning the next sprint. Generate a prioritized backlog of ${capacity} detections based on threat-informed analysis.

## Sprint Focus: ${focus}

## Planning Workflow

### Phase 1: Gap Analysis
1. **Assess current state:**
   - Use \`get_stats\` for inventory overview
   - Use \`analyze_coverage\` for tactic distribution
   - Identify weakest areas

2. **Identify gaps by focus area:**
${focus === 'ransomware' || focus === 'balanced' ? `
   - Use \`identify_gaps\` with threat_profile "ransomware"
` : ''}
${focus === 'apt' || focus === 'balanced' ? `
   - Use \`identify_gaps\` with threat_profile "apt"
` : ''}
${focus === 'insider' || focus === 'balanced' ? `
   - Review credential-access and data collection techniques
` : ''}
${focus === 'cloud' || focus === 'balanced' ? `
   - Focus on cloud-specific techniques and data sources
` : ''}

3. **Prioritize by risk:**
   - Technique prevalence in wild
   - Business impact if exploited
   - Current detection blind spots
   - Data source availability

### Phase 2: Backlog Creation
4. **For each selected technique:**
   - Use \`get_technique\` for full details
   - Use \`suggest_detections\` for implementation guidance
   - Use \`get_data_sources\` to understand requirements
   - Use \`get_mitigations\` for context

5. **Create user stories:**

   **Format for each detection:**
   
   ---
   **Story ID**: DE-SPRINT-{number}
   **Title**: Detect [Technique Name] via [Method]
   **Technique**: T1XXX.XXX
   **Priority**: P1/P2/P3
   **Story Points**: X
   
   **As a** SOC analyst
   **I want** detection for [specific behavior]
   **So that** I can identify [threat scenario]
   
   **Acceptance Criteria:**
   - [ ] Detection fires on [specific test case]
   - [ ] Alert includes [required fields]
   - [ ] False positive rate < X%
   - [ ] Documentation complete
   - [ ] Runbook updated
   
   **Data Sources Required:**
   - [List of required telemetry]
   
   **Detection Logic Approach:**
   - [High-level detection strategy]
   
   **Test Cases:**
   1. [Atomic test or manual procedure]
   2. [Bypass attempt to validate]
   
   **Dependencies:**
   - [Data source availability]
   - [Related detections]
   
   ---

### Phase 3: Sprint Capacity Planning
6. **Estimate effort:**
   - Simple detection (existing data, clear logic): 2 points
   - Medium detection (some complexity): 5 points
   - Complex detection (new data source, ML): 8 points

7. **Balance the sprint:**
   - Mix of quick wins and strategic investments
   - Consider dependencies
   - Account for testing and documentation

## Output Format

### Sprint Overview
| Metric | Value |
|--------|-------|
| Sprint Goal | Improve ${focus} detection coverage |
| Capacity | ${capacity} detections |
| Total Story Points | X |
| Coverage Improvement | +X% for [tactic] |

### Risk-Prioritized Gap Analysis
| Rank | Technique | Risk Score | Current State | Effort |
|------|-----------|------------|---------------|--------|

### Sprint Backlog
[${capacity} detailed user stories]

### Definition of Done
- [ ] Detection logic implemented and deployed
- [ ] Test cases executed with >80% detection rate
- [ ] False positive baseline established
- [ ] Alert documented with triage guidance
- [ ] Runbook created or updated
- [ ] Peer review completed

### Dependencies and Blockers
- Data sources needed
- Infrastructure requirements
- Team skill gaps

### Success Metrics
| Metric | Before Sprint | Target | Measurement |
|--------|---------------|--------|-------------|

### Stretch Goals
[Additional detections if capacity allows]

Begin sprint planning now.`
            }
          }
        ]
      };
    }
    
    case 'executive-security-briefing': {
      const audience = args?.audience || 'ciso';
      const includeBenchmarks = args?.include_benchmarks !== 'false';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `# Executive Security Posture Briefing

You are preparing a security detection briefing for the **${audience.toUpperCase()}**. Translate technical metrics into business risk language.

## Briefing Workflow

### Phase 1: Data Collection
1. **Gather metrics:**
   - Use \`get_stats\` for current detection inventory
   - Use \`analyze_coverage\` for tactic-level analysis
   - Calculate coverage percentages

2. **Assess threat landscape:**
   - Use \`identify_gaps\` with "ransomware" profile
   - Use \`identify_gaps\` with "apt" profile
   - Note critical blind spots

### Phase 2: Business Translation
3. **Risk quantification:**
   - Map detection gaps to potential business impact
   - Estimate exposure in business terms
   - Calculate risk reduction from improvements

4. **Trend analysis:**
   - Compare current state to previous periods
   - Highlight improvements and regressions
   - Show trajectory

${includeBenchmarks ? `
### Phase 3: Benchmarking
5. **Industry comparison:**
   - Compare coverage to industry averages (estimate based on MITRE coverage)
   - Identify areas where we lead/lag
   - Contextualize investment needs
` : ''}

## ${audience.toUpperCase()}-Specific Focus

${audience === 'board' ? `
**Board-Level Priorities:**
- Business risk in dollar terms
- Regulatory compliance status
- Competitive positioning
- Investment recommendations with ROI
- Simple risk ratings (red/yellow/green)
` : ''}
${audience === 'ciso' ? `
**CISO-Level Priorities:**
- Coverage metrics by threat type
- Gap analysis with remediation timeline
- Team capacity and resource needs
- Technology investment priorities
- Peer comparison and maturity assessment
` : ''}
${audience === 'cto' ? `
**CTO-Level Priorities:**
- Technology stack effectiveness
- Data pipeline requirements
- Integration opportunities
- Automation potential
- Technical debt in security tooling
` : ''}

## Output Format

### Executive Summary (30-Second Version)
> [2-3 sentences on overall security detection posture, key risk, and recommended action]

### Security Detection Posture Score
**Overall Score: X/100** [▲/▼ vs last period]

| Category | Score | Trend | Risk Level |
|----------|-------|-------|------------|
| Ransomware Protection | X/100 | | |
| APT Defense | X/100 | | |
| Insider Threat | X/100 | | |
| Cloud Security | X/100 | | |

### Key Findings

🔴 **Critical Gaps** (Immediate Attention Required)
- [Gap 1 with business impact]
- [Gap 2 with business impact]

🟡 **Areas of Concern** (Monitor Closely)
- [Finding with context]

🟢 **Strengths** (Maintain Investment)
- [Strength with value]

### Risk Exposure Analysis
| Threat Scenario | Detection Capability | Potential Impact | Risk Rating |
|-----------------|---------------------|------------------|-------------|
| Ransomware Attack | X% covered | $X-XM | High/Med/Low |
| Data Breach | X% covered | $X-XM | High/Med/Low |
| Supply Chain Compromise | X% covered | $X-XM | High/Med/Low |

${includeBenchmarks ? `
### Industry Benchmarking
| Metric | Our Score | Industry Average | Percentile |
|--------|-----------|------------------|------------|
| MITRE Coverage | X% | ~60% | Xth |
| Detection Count | X | ~500 | Xth |
| Response Capability | X | X | Xth |
` : ''}

### Investment Recommendations

| Priority | Initiative | Investment | Risk Reduction | Timeline |
|----------|-----------|------------|----------------|----------|
| 1 | [Initiative] | $X | X% reduction | Q1 |
| 2 | [Initiative] | $X | X% reduction | Q2 |
| 3 | [Initiative] | $X | X% reduction | H2 |

### Progress Since Last Review
[Key improvements and achievements]

### Next Review Objectives
[What we aim to achieve by next briefing]

Generate the briefing now.`
            }
          }
        ]
      };
    }
    
    case 'cve-response-assessment': {
      const cve = args?.cve_or_threat || 'emerging threat';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `# CVE/Emerging Threat Response Assessment: ${cve}

You are a threat intelligence analyst conducting rapid assessment of detection coverage for **${cve}**. Time is critical - provide actionable intelligence quickly.

## Rapid Assessment Workflow

### Phase 1: Threat Research (5 minutes)
1. **Identify threat characteristics:**
   - Use \`search\` for "${cve}" to find any existing detections
   - Use \`list_by_cve\` if this is a CVE ID
   - Use \`search_techniques\` to find related MITRE techniques

2. **Map to attack patterns:**
   - Initial access method
   - Exploitation technique
   - Post-exploitation behavior
   - Typical attack chain

### Phase 2: Coverage Assessment (5 minutes)
3. **Check existing detections:**
   - For each identified technique, use \`list_by_mitre\`
   - Document detection coverage
   - Identify complete blind spots

4. **Assess detection quality:**
   - Would existing detections catch this specific exploitation?
   - Are there bypasses specific to this threat?

### Phase 3: Gap Remediation (10 minutes)
5. **Generate immediate detections:**
   - Use \`suggest_detections\` for uncovered techniques
   - Prioritize by attack chain position
   - Focus on high-confidence indicators

6. **Identify quick wins:**
   - Existing detections to tune
   - Signatures to add
   - Rules to enable

### Phase 4: Response Recommendations
7. **Document for incident response:**
   - IOCs to hunt for
   - Affected systems/software
   - Mitigation steps
   - Detection timeline

## Output Format

### ⚠️ THREAT SUMMARY: ${cve}
| Attribute | Value |
|-----------|-------|
| Severity | Critical/High/Medium/Low |
| Exploitation Status | Active/POC/Theoretical |
| Patch Available | Yes/No |
| Our Exposure | High/Medium/Low |

### MITRE ATT&CK Mapping
| Technique | Name | Attack Phase | Covered? |
|-----------|------|--------------|----------|

### Current Detection Coverage
**Coverage Score: X/10**

✅ **Covered:**
- [Detections that would catch this]

❌ **Gaps:**
- [Missing detections needed]

### Immediate Actions Required

**🔴 NOW (Within 1 Hour):**
1. [Action with specific instructions]

**🟠 TODAY (Within 24 Hours):**
1. [Action with specific instructions]

**🟡 THIS WEEK:**
1. [Action with specific instructions]

### Recommended Detection Rules
\`\`\`
[Ready-to-deploy detection logic]
\`\`\`

### Hunting Queries
\`\`\`
[Queries to find existing compromise]
\`\`\`

### IOCs to Monitor
| Type | Value | Confidence |
|------|-------|------------|

### Affected Systems Check
- [ ] Identify vulnerable systems
- [ ] Check for exploitation indicators
- [ ] Verify patch status
- [ ] Enable enhanced monitoring

### Escalation Criteria
- Escalate immediately if: [conditions]
- Notify management if: [conditions]
- Invoke IR if: [conditions]

### Status Updates
- [ ] Initial assessment complete
- [ ] Detections deployed
- [ ] Hunt completed
- [ ] All-clear or incident declared

Begin rapid assessment now.`
            }
          }
        ]
      };
    }
    
    case 'data-source-gap-analysis': {
      const target = args?.target_coverage || 'comprehensive';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `# Data Source Gap Analysis

You are a detection engineering architect analyzing what data sources are needed to improve detection coverage${target !== 'comprehensive' ? ` for ${target}` : ''}.

## Analysis Workflow

### Phase 1: Current State Assessment
1. **Inventory existing data:**
   - Use \`get_stats\` to see current detection distribution
   - Note \`by_logsource_product\` for data source breakdown
   - Use \`analyze_coverage\` to see coverage by tactic

2. **Map detections to data sources:**
   - Which data sources power your strongest coverage?
   - Which tactics have poor coverage and why?

### Phase 2: Gap Identification
3. **Identify high-value gaps:**
${target === 'comprehensive' ? `
   - Use \`identify_gaps\` with each threat profile (ransomware, apt, etc.)
   - For each gap, use \`get_data_sources\` from MITRE to see what telemetry is needed
` : `
   - Focus on ${target} techniques
   - Use \`list_by_mitre_tactic\` or \`list_by_mitre\` for current coverage
   - Use \`get_data_sources\` for uncovered techniques
`}

4. **Categorize missing data sources:**
   - **Endpoint telemetry** (process, file, registry, network)
   - **Network telemetry** (flow, DNS, proxy, firewall)
   - **Identity telemetry** (authentication, authorization)
   - **Cloud telemetry** (API, configuration, workload)
   - **Application telemetry** (web, database, custom apps)

### Phase 3: Prioritization
5. **Score each data source need:**

   | Factor | Weight |
   |--------|--------|
   | Techniques it enables | 40% |
   | Threat profile relevance | 25% |
   | Implementation effort | 20% |
   | Operational cost | 15% |

6. **Calculate ROI:**
   - Detections enabled per data source
   - Coverage improvement percentage
   - Techniques unlocked

### Phase 4: Implementation Roadmap
7. **Sequence recommendations:**
   - Quick wins (data already collected but not ingested)
   - Medium effort (new collection, existing tools)
   - Major projects (new tools, infrastructure)

## Output Format

### Executive Summary
> [Current data collection gaps and their impact on detection capability]

### Current Data Source Inventory
| Data Source | Collection Status | Detection Count | Tactics Covered |
|-------------|-------------------|-----------------|-----------------|

### Critical Data Gaps
| Priority | Data Source | Techniques Enabled | Detection Uplift | Effort |
|----------|-------------|-------------------|------------------|--------|

### Data Source Requirements by Tactic
| Tactic | Current Coverage | Primary Gaps | Data Sources Needed |
|--------|------------------|--------------|---------------------|
| Initial Access | X% | [Techniques] | [Data sources] |
| Execution | X% | [Techniques] | [Data sources] |
| Persistence | X% | [Techniques] | [Data sources] |
| ... | | | |

### Detailed Recommendations

#### Tier 1: Quick Wins (1-2 weeks)
[Data sources that can be enabled quickly with high value]

#### Tier 2: Medium Effort (1-3 months)
[Data sources requiring moderate implementation effort]

#### Tier 3: Strategic Investments (3-6 months)
[Major data collection initiatives]

### Implementation Requirements
| Data Source | Collection Method | Storage Estimate | Processing Needs |
|-------------|-------------------|------------------|------------------|

### Cost-Benefit Analysis
| Initiative | Annual Cost | Techniques Covered | Cost per Technique |
|------------|-------------|-------------------|-------------------|

### Collection Quality Requirements
For each recommended data source:
- Required fields
- Retention needs
- Parsing requirements
- Integration points

### Dependencies
- Infrastructure requirements
- Team skills needed
- Vendor support required

Begin the analysis now.`
            }
          }
        ]
      };
    }
    
    case 'detection-quality-review': {
      const techniqueId = args?.technique_id || 'T1059.001';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `# Detection Quality Review: ${techniqueId}

You are a senior detection engineer conducting a deep-dive quality review of detections for technique **${techniqueId}**.

## Review Workflow

### Phase 1: Technique Understanding
1. **Research the technique:**
   - Use \`get_technique\` from MITRE ATT&CK for ${techniqueId}
   - Understand:
     - Technique description and scope
     - Sub-techniques (if applicable)
     - Platforms affected
     - Required permissions
     - Defense bypasses noted
   
2. **Get detection guidance:**
   - Use \`get_data_sources\` to understand what telemetry to use
   - Review MITRE's detection recommendations

### Phase 2: Current Detection Analysis
3. **Inventory existing detections:**
   - Use \`list_by_mitre\` for ${techniqueId}
   - For each detection, use \`get_by_id\` for full details
   - If available, use \`get_raw_yaml\` for detection logic

4. **Assess each detection:**

   For each detection, evaluate:
   
   | Criteria | Rating (1-5) | Notes |
   |----------|--------------|-------|
   | **Coverage Completeness** | | Does it catch all variants? |
   | **False Positive Risk** | | How specific is it? |
   | **Evasion Resistance** | | Can it be easily bypassed? |
   | **Performance Impact** | | Resource efficient? |
   | **Alert Quality** | | Actionable information? |
   | **Documentation** | | Clear triage guidance? |

### Phase 3: Gap and Bypass Analysis
5. **Identify detection gaps:**
   - Variants not covered
   - Procedure examples from MITRE not detected
   - Known evasion techniques

6. **Analyze potential bypasses:**
   - Command obfuscation
   - Alternative tools/methods
   - Living-off-the-land alternatives
   - Timing-based evasion

7. **Use \`suggest_detections\` for improvement ideas**

### Phase 4: Recommendations
8. **Generate improvement plan:**
   - Detection logic enhancements
   - New detections needed
   - Alert enrichment opportunities
   - Correlation rule ideas

## Output Format

### Technique Overview
| Attribute | Value |
|-----------|-------|
| Technique ID | ${techniqueId} |
| Name | [Name] |
| Tactic(s) | [Tactics] |
| Platforms | [Platforms] |
| Data Sources | [Sources] |

### Detection Inventory
| Detection | Source | Quality Score | Key Strengths | Key Weaknesses |
|-----------|--------|---------------|---------------|----------------|

### Individual Detection Reviews

#### Detection 1: [Name]
**Overall Quality: X/5** ⭐⭐⭐⭐⭐

**Strengths:**
- [Strength 1]
- [Strength 2]

**Weaknesses:**
- [Weakness 1]
- [Weakness 2]

**Detection Logic Review:**
\`\`\`
[Logic with comments on quality]
\`\`\`

**Recommended Improvements:**
1. [Improvement]

---
[Repeat for each detection]

### Coverage Gap Analysis
| Gap Type | Description | Risk | Recommendation |
|----------|-------------|------|----------------|
| Variant | [Description] | High/Med/Low | [Action] |
| Evasion | [Description] | High/Med/Low | [Action] |
| Data | [Description] | High/Med/Low | [Action] |

### Known Bypass Techniques
| Bypass Method | Currently Detected? | Mitigation |
|---------------|---------------------|------------|

### Recommended New Detections
| Priority | Detection Concept | Rationale | Effort |
|----------|-------------------|-----------|--------|

### Enhanced Detection Logic
\`\`\`
[Improved or new detection logic]
\`\`\`

### Correlation Opportunities
[Rules that combine multiple signals for higher fidelity]

### Quality Improvement Roadmap
| Phase | Actions | Expected Improvement |
|-------|---------|---------------------|
| Immediate | [Actions] | +X quality points |
| Short-term | [Actions] | +X quality points |
| Long-term | [Actions] | +X quality points |

### Final Quality Assessment
**Current State**: X/10
**Target State**: Y/10
**Effort to Achieve**: [Estimate]

Begin the quality review now.`
            }
          }
        ]
      };
    }
    
    case 'threat-landscape-sync': {
      const industry = args?.industry || 'general';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `# Threat Landscape Synchronization

Analyze current threat landscape and sync detection priorities${industry !== 'general' ? ` for the ${industry} industry` : ''}.

## Sync Workflow

### Phase 1: Threat Actor Analysis
1. **Identify relevant threat actors:**
   - Use \`get_common_groups\` to see top threat actors by technique count
   - Use \`search_groups\` to find actors targeting ${industry !== 'general' ? industry : 'your organization type'}
   
2. **For top 5 relevant actors:**
   - Use \`get_group\` for detailed profile
   - Use \`get_group_techniques\` for their TTPs
   - Note recent activity and campaigns

### Phase 2: Technique Trending
3. **Identify high-priority techniques:**
   - Techniques used by multiple relevant actors
   - Recently observed techniques
   - Techniques with high impact potential
   
4. **Map to your coverage:**
   - For each high-priority technique, use \`list_by_mitre\`
   - Use \`quick_coverage_check\` for rapid actor coverage assessment

### Phase 3: Gap Prioritization
5. **Threat-informed gap analysis:**
   - Use \`identify_gaps\` with relevant threat profiles
   - Cross-reference with actor techniques
   - Prioritize by:
     - Actor relevance to your industry
     - Technique prevalence
     - Current detection coverage

6. **Generate priority recommendations:**
   - Use \`suggest_detections\` for top gaps
   - Focus on techniques used by multiple actors

### Phase 4: Strategic Planning
7. **Build detection roadmap:**
   - Quick wins (high impact, low effort)
   - Strategic investments (emerging threats)
   - Long-term capabilities (advanced detection)

## Industry Context: ${industry}
${industry === 'finance' ? `
**Finance Industry Threats:**
- Nation-state espionage (APT groups)
- Ransomware operations
- Business email compromise
- ATM/payment card attacks
- Insider threats
` : ''}
${industry === 'healthcare' ? `
**Healthcare Industry Threats:**
- Ransomware (high frequency target)
- Medical device attacks
- Patient data theft
- Supply chain compromise
- Research espionage
` : ''}
${industry === 'technology' ? `
**Technology Industry Threats:**
- IP theft / espionage
- Supply chain attacks
- Cloud infrastructure attacks
- Developer targeting
- Ransomware
` : ''}
${industry === 'general' ? `
**General Threat Landscape:**
- Ransomware across all sectors
- Nation-state activities increasing
- Supply chain attacks rising
- Cloud migration risks
- Living-off-the-land techniques
` : ''}

## Output Format

### Threat Landscape Executive Summary
> [Current state of threats relevant to ${industry !== 'general' ? industry : 'organizations'} and your detection alignment]

### Top Threat Actors
| Rank | Actor | Relevance | Techniques | Your Coverage | Gap Risk |
|------|-------|-----------|------------|---------------|----------|

### Actor Profile Deep-Dives
[For top 3 relevant actors]

#### [Actor Name]
- **Overview**: [Description]
- **Recent Activity**: [Campaigns]
- **Key TTPs**: [Techniques]
- **Your Coverage**: X% of their techniques
- **Critical Gaps**: [Uncovered techniques]

### Trending Techniques
| Technique | Actors Using | Your Coverage | Trend | Priority |
|-----------|--------------|---------------|-------|----------|

### Coverage Against Top Actors
| Actor | Total TTPs | Covered | Coverage % | Status |
|-------|------------|---------|------------|--------|
| [Actor] | X | Y | Z% | 🟢/🟡/🔴 |

### Priority Gap Matrix
| Gap | Used By | Impact | Effort | Priority Score |
|-----|---------|--------|--------|----------------|

### Recommended Detection Investments
**Immediate (This Sprint):**
1. [Detection] - Covers [X actors], addresses [Y techniques]

**Short-term (This Quarter):**
1. [Detection] - Rationale

**Strategic (This Year):**
1. [Capability] - Rationale

### Threat-Informed Roadmap
| Quarter | Focus | Detection Goals | Actor Coverage Target |
|---------|-------|-----------------|----------------------|
| Q1 | [Focus] | X new detections | +Y% coverage |
| Q2 | [Focus] | X new detections | +Y% coverage |
| Q3-Q4 | [Focus] | X new detections | +Y% coverage |

### Intelligence Requirements
- Threat feeds to subscribe to
- Actor tracking priorities  
- Technique monitoring focus

### Next Sync Review
- Schedule: [Recommended cadence]
- Focus areas for next review
- Metrics to track

Begin the threat landscape sync now.`
            }
          }
        ]
      };
    }
    
    case 'detection-coverage-diff': {
      const compareAgainst = args?.compare_against || 'baseline';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `# Detection Coverage Comparison: vs ${compareAgainst}

Compare current detection coverage against **${compareAgainst}** to identify improvements needed or progress made.

## Comparison Workflow

### Phase 1: Baseline Establishment
1. **Get current coverage:**
   - Use \`get_stats\` for overall metrics
   - Use \`get_technique_ids\` for full technique list
   - Use \`analyze_coverage\` for detailed breakdown

### Phase 2: Target Comparison
${compareAgainst === 'baseline' ? `
2. **Compare against industry baseline:**
   - Typical enterprise: ~200-400 MITRE techniques covered
   - Mature security program: ~60-70% technique coverage
   - Advanced: 80%+ with multiple detections per technique
` : `
2. **Compare against ${compareAgainst}:**
   - If this is an APT group: Use \`search_groups\` then \`get_group_techniques\`
   - Use \`find_group_gaps\` for direct gap analysis
   - Use \`quick_coverage_check\` for rapid assessment
`}

### Phase 3: Diff Analysis
3. **Calculate differences:**
   - Techniques in target but not covered
   - Techniques covered but not in target (excess)
   - Overlap analysis

4. **Prioritize the delta:**
   - Critical gaps (high-impact, uncovered)
   - Improvement opportunities
   - Potential over-investment areas

### Phase 4: Recommendations
5. **Generate action plan:**
   - Use \`suggest_detections\` for top gaps
   - Estimate effort to close gaps
   - Project coverage improvement

## Output Format

### Comparison Summary
| Metric | Current | Target (${compareAgainst}) | Delta |
|--------|---------|---------------------------|-------|
| Total Techniques | X | Y | +/-Z |
| Coverage % | X% | Y% | +/-Z% |
| Avg Detections/Technique | X | Y | +/-Z |

### Visual Comparison
\`\`\`
Current:  ████████████░░░░░░░░ ${'{'}X%{'}'}
Target:   ██████████████████░░ ${'{'}Y%{'}'}
Gap:      ░░░░░░████░░░░░░░░░░ ${'{'}Z%{'}'}
\`\`\`

### Coverage by Tactic
| Tactic | Current | Target | Gap | Priority |
|--------|---------|--------|-----|----------|

### Gap Analysis

#### Critical Gaps (Must Address)
| Technique | Name | Why Critical | Effort |
|-----------|------|--------------|--------|

#### Moderate Gaps (Should Address)
| Technique | Name | Rationale | Effort |
|-----------|------|-----------|--------|

#### Nice-to-Have
| Technique | Name | Rationale | Effort |
|-----------|------|-----------|--------|

### Coverage You Have (Target Doesn't Require)
[Techniques you cover that aren't in the comparison target - may indicate over-investment or good bonus coverage]

### Path to Parity
| Phase | Detections to Add | Coverage Impact | Timeline |
|-------|-------------------|-----------------|----------|
| 1 | X | +Y% | Z weeks |
| 2 | X | +Y% | Z weeks |
| 3 | X | +Y% | Z weeks |

### Effort Estimation
| Category | Detection Count | Story Points | Team Weeks |
|----------|-----------------|--------------|------------|
| Quick Wins | X | Y | Z |
| Medium Effort | X | Y | Z |
| Complex | X | Y | Z |
| **Total** | **X** | **Y** | **Z** |

### Progress Tracking Metrics
- Current coverage vs target: X%
- Detections to parity: X
- Estimated time to parity: X weeks
- Weekly detection velocity needed: X

### Recommendations
1. [Prioritized recommendation]
2. [Second priority]
3. [Third priority]

Begin the comparison now.`
            }
          }
        ]
      };
    }
    
    default:
      throw new Error(`Unknown prompt: ${name}`);
  }
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  try {
    switch (name) {
      case 'search': {
        const query = args?.query as string;
        let limit = (args?.limit as number) || 50;
        let sourceFilter: string | undefined = args?.source_type as string | undefined;
        
        if (!query) {
          return { 
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                error: true,
                code: 'MISSING_REQUIRED_ARG',
                message: 'query is required',
                examples: ['powershell base64', 'CVE-2024', 'ransomware encryption'],
                hint: 'FTS5 syntax supported for advanced queries'
              }, null, 2)
            }] 
          };
        }
        
        // Smart elicitation: ask user for search preferences
        try {
          // First, do a quick preview to show what's available
          const previewResults = searchDetections(query, 100);
          
          if (previewResults.length > 10) {
            // Count by source for dynamic options
            const bySrc: Record<string, number> = {};
            for (const r of previewResults) {
              bySrc[r.source_type] = (bySrc[r.source_type] || 0) + 1;
            }
            
            // Build dynamic source options with counts
            const sourceOptions = Object.entries(bySrc)
              .sort((a, b) => b[1] - a[1])
              .map(([src, count]) => src);
            const sourceLabels = Object.entries(bySrc)
              .sort((a, b) => b[1] - a[1])
              .map(([src, count]) => `${src} (${count} results)`);
            
            // Add "all" option
            sourceOptions.unshift('all');
            sourceLabels.unshift(`All sources (${previewResults.length} total)`);
            
            const elicitResult = await server.elicitInput({
              message: `Found ${previewResults.length} results for "${query}". Refine your search:`,
              requestedSchema: {
                type: 'object' as const,
                properties: {
                  source: {
                    type: 'string' as const,
                    title: 'Which source?',
                    description: 'Filter results by detection source',
                    enum: sourceOptions,
                    enumNames: sourceLabels,
                    default: 'all',
                  },
                  max_results: {
                    type: 'number' as const,
                    title: 'How many results?',
                    description: 'Maximum results to return',
                    minimum: 5,
                    maximum: 100,
                    default: 20,
                  },
                },
                required: ['source'],
              },
            });
            
            if (elicitResult.action === 'accept' && elicitResult.content) {
              sourceFilter = elicitResult.content.source as string;
              if (sourceFilter === 'all') sourceFilter = undefined;
              limit = (elicitResult.content.max_results as number) || 20;
            }
          }
        } catch (e) {
          // Elicitation not supported - continue with defaults
        }
        
        // Apply filters
        let results = searchDetections(query, 200);
        if (sourceFilter) {
          results = results.filter(r => r.source_type === sourceFilter);
        }
        results = results.slice(0, limit);
        
        // Add helpful suggestions if no results
        if (results.length === 0) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                results: [],
                suggestions: {
                  try_broader: 'Try a simpler query or single keyword',
                  try_tools: ['list_by_mitre_tactic', 'list_by_severity', 'list_by_source'],
                  tip: 'Use quotes for exact phrases, OR for alternatives'
                }
              }, null, 2),
            }],
          };
        }
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'get_by_id': {
        const id = args?.id as string;
        
        if (!id) {
          return { 
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                error: true,
                code: 'MISSING_REQUIRED_ARG',
                message: 'id is required',
                hint: 'Use search or list tools to find detection IDs first'
              }, null, 2)
            }] 
          };
        }
        
        const detection = getDetectionById(id);
        if (!detection) {
          return { 
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                error: true,
                code: 'NOT_FOUND',
                message: `Detection not found: ${id}`,
                suggestions: {
                  try_search: 'Use search("keyword") to find detections',
                  try_list: 'Use list_all or list_by_source to browse',
                  tip: 'Sigma IDs are UUIDs, Splunk IDs are slug-format'
                }
              }, null, 2)
            }] 
          };
        }
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(detection, null, 2),
          }],
        };
      }
      
      case 'list_all': {
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        const results = listDetections(limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_source': {
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic';
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!sourceType) {
          return { content: [{ type: 'text', text: 'Error: source_type is required' }] };
        }
        
        const results = listBySource(sourceType, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_mitre': {
        const techniqueId = args?.technique_id as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!techniqueId) {
          return { 
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                error: true,
                code: 'MISSING_REQUIRED_ARG',
                message: 'technique_id is required',
                examples: ['T1059.001', 'T1547.001', 'T1003.001'],
                hint: 'Use format T####.### (e.g., T1059.001 for PowerShell)'
              }, null, 2)
            }] 
          };
        }
        
        const results = listByMitre(techniqueId, limit, offset);
        
        // Add suggestions if no results
        if (results.length === 0) {
          const validation = validateTechniqueId(techniqueId);
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                results: [],
                technique_id: techniqueId,
                suggestions: {
                  message: validation.suggestion || 'No detections found for this technique',
                  similar_techniques: validation.similar,
                  try_search: `search("${techniqueId.split('.')[0]}") for broader results`,
                  tip: 'Parent techniques (T1059) may catch sub-techniques (T1059.001)'
                }
              }, null, 2),
            }],
          };
        }
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_logsource': {
        const category = args?.category as string | undefined;
        const product = args?.product as string | undefined;
        const service = args?.service as string | undefined;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        const results = listByLogsource(category, product, service, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_severity': {
        const level = args?.level as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!level) {
          return { content: [{ type: 'text', text: 'Error: level is required' }] };
        }
        
        const results = listBySeverity(level, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_cve': {
        const cveId = args?.cve_id as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!cveId) {
          return { content: [{ type: 'text', text: 'Error: cve_id is required' }] };
        }
        
        const results = listByCve(cveId, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_analytic_story': {
        const story = args?.story as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!story) {
          return { content: [{ type: 'text', text: 'Error: story is required' }] };
        }
        
        const results = listByAnalyticStory(story, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_process_name': {
        const processName = args?.process_name as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!processName) {
          return { content: [{ type: 'text', text: 'Error: process_name is required' }] };
        }
        
        const results = listByProcessName(processName, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_detection_type': {
        const detectionType = args?.detection_type as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!detectionType) {
          return { content: [{ type: 'text', text: 'Error: detection_type is required' }] };
        }
        
        const results = listByDetectionType(detectionType, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_data_source': {
        const dataSource = args?.data_source as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!dataSource) {
          return { content: [{ type: 'text', text: 'Error: data_source is required' }] };
        }
        
        const results = listByDataSource(dataSource, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_mitre_tactic': {
        const tactic = args?.tactic as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!tactic) {
          return { content: [{ type: 'text', text: 'Error: tactic is required' }] };
        }
        
        const results = listByMitreTactic(tactic, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_kql_category': {
        const category = args?.category as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!category) {
          return { content: [{ type: 'text', text: 'Error: category is required' }] };
        }
        
        const results = listByKqlCategory(category, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_kql_tag': {
        const tag = args?.tag as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!tag) {
          return { content: [{ type: 'text', text: 'Error: tag is required' }] };
        }
        
        const results = listByKqlTag(tag, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_kql_datasource': {
        const dataSource = args?.data_source as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!dataSource) {
          return { content: [{ type: 'text', text: 'Error: data_source is required' }] };
        }
        
        const results = listByKqlDatasource(dataSource, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'search_stories': {
        const query = args?.query as string;
        const limit = (args?.limit as number) || 20;
        
        if (!query) {
          return { content: [{ type: 'text', text: 'Error: query is required' }] };
        }
        
        const results = searchStories(query, limit);
        if (results.length === 0) {
          return {
            content: [{
              type: 'text',
              text: 'No stories found. Stories are optional - set STORY_PATHS env var to index them.',
            }],
          };
        }
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'get_story': {
        const storyName = args?.name as string;
        
        if (!storyName) {
          return { content: [{ type: 'text', text: 'Error: name is required' }] };
        }
        
        const story = getStoryByName(storyName);
        if (!story) {
          return { content: [{ type: 'text', text: `Story not found: ${storyName}. Stories are optional - set STORY_PATHS env var to index them.` }] };
        }
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(story, null, 2),
          }],
        };
      }
      
      case 'list_stories': {
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        const results = listStories(limit, offset);
        if (results.length === 0) {
          return {
            content: [{
              type: 'text',
              text: 'No stories indexed. Stories are optional - set STORY_PATHS env var to index them.',
            }],
          };
        }
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_stories_by_category': {
        const category = args?.category as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!category) {
          return { content: [{ type: 'text', text: 'Error: category is required' }] };
        }
        
        const results = listStoriesByCategory(category, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'get_stats': {
        const stats = getStats();
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(stats, null, 2),
          }],
        };
      }
      
      case 'rebuild_index': {
        if (SIGMA_PATHS.length === 0 && SPLUNK_PATHS.length === 0 && ELASTIC_PATHS.length === 0 && KQL_PATHS.length === 0) {
          return {
            content: [{
              type: 'text',
              text: 'Error: No paths configured. Set SIGMA_PATHS, SPLUNK_PATHS, ELASTIC_PATHS, and/or KQL_PATHS environment variables.',
            }],
          };
        }
        
        // Use elicitation to confirm destructive action
        try {
          const currentStats = getStats();
          const elicitResult = await server.elicitInput({
            message: `This will DELETE and rebuild the entire detection index.\n\nCurrent index: ${currentStats.total} detections\n\nAre you sure you want to proceed?`,
            requestedSchema: {
              type: 'object' as const,
              properties: {
                confirm: {
                  type: 'boolean' as const,
                  title: 'Yes, rebuild the index',
                  description: 'Check this box to confirm you want to delete and rebuild',
                  default: false,
                },
              },
              required: ['confirm'],
            },
          });
          
          // Check if user confirmed
          if (elicitResult.action !== 'accept' || !elicitResult.content?.confirm) {
            return {
              content: [{
                type: 'text',
                text: 'Index rebuild cancelled.',
              }],
            };
          }
        } catch (e) {
          // Elicitation not supported by client - proceed without confirmation
          console.error('[security-detections-mcp] Elicitation not supported, proceeding without confirmation');
        }
        
        // Recreate DB to apply schema changes
        recreateDb();
        
        const result = indexDetections(SIGMA_PATHS, SPLUNK_PATHS, STORY_PATHS, ELASTIC_PATHS, KQL_PATHS);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              message: 'Index rebuilt successfully',
              ...result,
              stories_note: STORY_PATHS.length === 0 ? 'No STORY_PATHS configured - stories not indexed' : undefined,
              elastic_note: ELASTIC_PATHS.length === 0 ? 'No ELASTIC_PATHS configured - Elastic rules not indexed' : undefined,
              kql_note: KQL_PATHS.length === 0 ? 'No KQL_PATHS configured - KQL queries not indexed' : undefined,
              db_path: getDbPath(),
            }, null, 2),
          }],
        };
      }
      
      case 'get_raw_yaml': {
        const id = args?.id as string;
        
        if (!id) {
          return { content: [{ type: 'text', text: 'Error: id is required' }] };
        }
        
        const yaml = getRawYaml(id);
        if (!yaml) {
          return { content: [{ type: 'text', text: `Detection not found: ${id}` }] };
        }
        
        return {
          content: [{
            type: 'text',
            text: yaml,
          }],
        };
      }
      
      case 'get_technique_ids': {
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic' | undefined;
        const tactic = args?.tactic as string | undefined;
        const severity = args?.severity as string | undefined;
        
        const techniqueIds = getTechniqueIds({
          source_type: sourceType,
          tactic,
          severity,
        });
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              count: techniqueIds.length,
              technique_ids: techniqueIds,
            }, null, 2),
          }],
        };
      }
      
      case 'analyze_coverage': {
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic' | undefined;
        
        const report = analyzeCoverage(sourceType);
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(report, null, 2),
          }],
        };
      }
      
      case 'identify_gaps': {
        const threatProfile = args?.threat_profile as string;
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic' | undefined;
        
        if (!threatProfile) {
          return { 
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                error: true,
                code: 'MISSING_REQUIRED_ARG',
                message: 'threat_profile is required',
                valid_values: ['ransomware', 'apt', 'initial-access', 'persistence', 'credential-access', 'defense-evasion'],
                hint: 'Each profile contains commonly used techniques for that threat type'
              }, null, 2)
            }] 
          };
        }
        
        const gaps = identifyGaps(threatProfile, sourceType);
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(gaps, null, 2),
          }],
        };
      }
      
      case 'suggest_detections': {
        const techniqueId = args?.technique_id as string;
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic' | undefined;
        
        if (!techniqueId) {
          return { 
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                error: true,
                code: 'MISSING_REQUIRED_ARG',
                message: 'technique_id is required',
                examples: ['T1059.001', 'T1547.001', 'T1003.001'],
                hint: 'Use format T####.### (e.g., T1059.001 for PowerShell)'
              }, null, 2)
            }] 
          };
        }
        
        // Validate technique ID format
        const validation = validateTechniqueId(techniqueId);
        if (!validation.valid) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: true,
                code: 'INVALID_TECHNIQUE_ID',
                message: validation.error,
                suggestion: validation.suggestion,
                similar: validation.similar,
              }, null, 2)
            }]
          };
        }
        
        const suggestions = suggestDetections(techniqueId, sourceType);
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(suggestions, null, 2),
          }],
        };
      }
      
      // Interactive gap prioritization (uses elicitation in supported clients)
      case 'prioritize_gaps': {
        const threatProfile = args?.threat_profile as string;
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic' | undefined;
        
        if (!threatProfile) {
          return { 
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                error: true,
                code: 'MISSING_REQUIRED_ARG',
                message: 'threat_profile is required',
                valid_values: THREAT_PROFILE_COMPLETIONS,
                hint: 'Choose a threat profile to analyze gaps against'
              }, null, 2)
            }] 
          };
        }
        
        const gaps = identifyGaps(threatProfile, sourceType);
        
        // If there are gaps, use elicitation to let user select which to prioritize
        if (gaps.total_gaps > 0 && gaps.critical_gaps.length > 0) {
          try {
            const topGaps = gaps.critical_gaps.slice(0, 5);
            const elicitResult = await server.elicitInput({
              message: `Found ${gaps.total_gaps} gaps for ${threatProfile}. Select your prioritization strategy:`,
              requestedSchema: {
                type: 'object' as const,
                properties: {
                  priority_technique: {
                    type: 'string' as const,
                    title: 'Top priority technique to address',
                    description: 'Select the most critical gap to focus on first',
                    enum: topGaps.map(g => g.technique),
                    enumNames: topGaps.map(g => `${g.technique} - ${g.reason}`),
                  },
                  strategy: {
                    type: 'string' as const,
                    title: 'Prioritization strategy',
                    description: 'How should we prioritize the remaining gaps?',
                    enum: ['quick-wins', 'high-impact', 'comprehensive'],
                    enumNames: ['Quick Wins (easiest first)', 'High Impact (most critical first)', 'Comprehensive (all gaps)'],
                    default: 'high-impact',
                  },
                  include_suggestions: {
                    type: 'boolean' as const,
                    title: 'Include detection suggestions',
                    description: 'Get detailed detection ideas for selected gaps',
                    default: true,
                  },
                },
                required: ['priority_technique', 'strategy'],
              },
            });
            
            if (elicitResult.action === 'accept' && elicitResult.content) {
              const selectedTechnique = elicitResult.content.priority_technique as string;
              const strategy = elicitResult.content.strategy as string;
              const includeSuggestions = elicitResult.content.include_suggestions as boolean;
              
              // Get suggestions for the selected technique if requested
              let suggestions = null;
              if (includeSuggestions && selectedTechnique) {
                suggestions = suggestDetections(selectedTechnique, sourceType);
              }
              
              return {
                content: [{
                  type: 'text',
                  text: JSON.stringify({
                    user_selection: {
                      priority_technique: selectedTechnique,
                      strategy,
                      include_suggestions: includeSuggestions,
                    },
                    threat_profile: gaps.threat_profile,
                    total_gaps: gaps.total_gaps,
                    coverage_percent: Math.round((gaps.covered.length / (gaps.covered.length + gaps.total_gaps)) * 100),
                    prioritized_gaps: strategy === 'quick-wins' 
                      ? gaps.critical_gaps.filter(g => g.priority !== 'P0').slice(0, 5)
                      : gaps.critical_gaps.slice(0, 5),
                    selected_technique_suggestions: suggestions,
                    next_steps: [
                      `1. Start with ${selectedTechnique}`,
                      `2. Use suggest_detections("${selectedTechnique}") for detection ideas`,
                      `3. Review data source requirements`,
                      `4. Write and test detection`,
                    ],
                  }, null, 2),
                }],
              };
            }
          } catch (e) {
            // Elicitation not supported - fall through to standard response
            console.error('[security-detections-mcp] Elicitation not supported');
          }
        }
        
        // Standard response (no elicitation or no gaps)
        const prioritizedGaps = {
          threat_profile: gaps.threat_profile,
          total_gaps: gaps.total_gaps,
          summary: `Found ${gaps.total_gaps} gaps for ${threatProfile} profile`,
          p0_critical: gaps.critical_gaps.filter(g => g.priority === 'P0').slice(0, 5),
          p1_high: gaps.critical_gaps.filter(g => g.priority === 'P1').slice(0, 5),
          p2_medium: gaps.critical_gaps.filter(g => g.priority === 'P2').slice(0, 5),
          covered_count: gaps.covered.length,
          coverage_percent: Math.round((gaps.covered.length / (gaps.covered.length + gaps.total_gaps)) * 100),
          recommendations: gaps.recommendations,
        };
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(prioritizedGaps, null, 2),
          }],
        };
      }
      
      // Interactive threat actor analysis with DYNAMIC elicitation
      case 'analyze_threat_actor': {
        const actorName = args?.actor_name as string;
        
        if (!actorName) {
          return { 
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                error: true,
                code: 'MISSING_REQUIRED_ARG',
                message: 'actor_name is required',
                examples: ['APT29', 'APT28', 'Lazarus Group', 'Volt Typhoon'],
              }, null, 2)
            }] 
          };
        }
        
        // Get your ACTUAL coverage data to show in the form
        const stats = getStats();
        const coverage = analyzeCoverage();
        
        // Build dynamic source options with YOUR actual counts
        const sourceOptions: string[] = ['all'];
        const sourceLabels: string[] = [`All sources (${stats.total} detections)`];
        
        if (stats.sigma > 0) {
          sourceOptions.push('sigma');
          sourceLabels.push(`Sigma (${stats.sigma} rules)`);
        }
        if (stats.splunk_escu > 0) {
          sourceOptions.push('splunk_escu');
          sourceLabels.push(`Splunk ESCU (${stats.splunk_escu} detections)`);
        }
        if (stats.elastic > 0) {
          sourceOptions.push('elastic');
          sourceLabels.push(`Elastic (${stats.elastic} rules)`);
        }
        if (stats.kql > 0) {
          sourceOptions.push('kql');
          sourceLabels.push(`KQL (${stats.kql} queries)`);
        }
        
        // Find your weakest tactics to show as concerns
        const tacticsByStrength = Object.entries(coverage.summary.coverage_by_tactic)
          .sort((a, b) => a[1].percent - b[1].percent);
        const weakestTactics = tacticsByStrength.slice(0, 5).map(([t, d]) => t);
        const weakestLabels = tacticsByStrength.slice(0, 5).map(([t, d]) => `${t} (${d.percent}% coverage)`);
        
        // Use elicitation with DYNAMIC data
        try {
          const elicitResult = await server.elicitInput({
            message: `Analyzing ${actorName} against your ${stats.total} detections.\n\nYour coverage: ${coverage.summary.total_techniques} MITRE techniques\nWeakest area: ${weakestTactics[0]} (${tacticsByStrength[0][1].percent}%)`,
            requestedSchema: {
              type: 'object' as const,
              properties: {
                focus_source: {
                  type: 'string' as const,
                  title: 'Analyze which detection source?',
                  description: 'Focus analysis on specific source or all',
                  enum: sourceOptions,
                  enumNames: sourceLabels,
                  default: 'all',
                },
                focus_tactic: {
                  type: 'string' as const,
                  title: 'Focus on which tactic? (Your weakest shown)',
                  description: 'Prioritize gaps in this area',
                  enum: ['all', ...weakestTactics],
                  enumNames: ['All tactics', ...weakestLabels],
                  default: 'all',
                },
                analysis_depth: {
                  type: 'string' as const,
                  title: 'Analysis depth?',
                  description: 'How detailed should the analysis be?',
                  enum: ['quick', 'standard', 'deep'],
                  enumNames: ['Quick (top 5 gaps)', 'Standard (top 10 + suggestions)', 'Deep (all gaps + detection ideas)'],
                  default: 'standard',
                },
              },
              required: ['focus_source', 'analysis_depth'],
            },
          });
          
          if (elicitResult.action === 'accept' && elicitResult.content) {
            const focusSource = elicitResult.content.focus_source as string;
            const focusTactic = elicitResult.content.focus_tactic as string;
            const depth = elicitResult.content.analysis_depth as string;
            
            // Get coverage filtered by user selection
            const sourceType = focusSource === 'all' ? undefined : focusSource as 'sigma' | 'splunk_escu' | 'elastic';
            const filteredCoverage = analyzeCoverage(sourceType);
            const coveredTechniques = getTechniqueIds({ source_type: sourceType });
            
            // Determine result limit based on depth
            const gapLimit = depth === 'quick' ? 5 : depth === 'standard' ? 10 : 50;
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  actor: actorName,
                  analysis_config: {
                    source: focusSource,
                    tactic_focus: focusTactic,
                    depth,
                  },
                  your_coverage: {
                    total_detections: focusSource === 'all' ? stats.total : stats[focusSource as keyof typeof stats],
                    techniques_covered: coveredTechniques.length,
                    weakest_tactic: weakestTactics[0],
                    weakest_coverage: `${tacticsByStrength[0][1].percent}%`,
                  },
                  recommendations: [
                    `Use "apt-threat-emulation for ${actorName}" prompt for full TTP mapping`,
                    focusTactic !== 'all' ? `Priority: Improve ${focusTactic} coverage (currently ${coverage.summary.coverage_by_tactic[focusTactic]?.percent || 0}%)` : null,
                    `Analyze ${focusSource === 'all' ? 'all sources' : focusSource} for ${actorName} TTPs`,
                  ].filter(Boolean),
                  next_command: `Use apt-threat-emulation for ${actorName}`,
                }, null, 2),
              }],
            };
          }
          
          return { content: [{ type: 'text', text: 'Analysis cancelled.' }] };
          
        } catch (e) {
          // Elicitation not supported
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                actor: actorName,
                your_stats: { total: stats.total, techniques: coverage.summary.total_techniques },
                suggestion: `Use "apt-threat-emulation for ${actorName}" prompt`,
              }, null, 2),
            }],
          };
        }
      }
      
      // Interactive sprint planning
      case 'plan_detection_sprint': {
        // Get current state for context
        const stats = getStats();
        const coverage = analyzeCoverage();
        const ransomwareGaps = identifyGaps('ransomware');
        const aptGaps = identifyGaps('apt');
        
        const sprintPlan = {
          current_state: {
            total_detections: stats.total,
            total_techniques: coverage.summary.total_techniques,
            mitre_coverage: stats.mitre_coverage,
          },
          
          gap_summary: {
            ransomware: {
              total_gaps: ransomwareGaps.total_gaps,
              critical: ransomwareGaps.critical_gaps.filter(g => g.priority === 'P0').length,
            },
            apt: {
              total_gaps: aptGaps.total_gaps,
              critical: aptGaps.critical_gaps.filter(g => g.priority === 'P0').length,
            },
          },
          
          // Sprint configuration options
          configuration_options: {
            sprint_capacity: {
              description: 'How many detections can your team write?',
              suggested_values: [5, 10, 15, 20],
              default: 10,
            },
            threat_focus: {
              description: 'Primary threat focus',
              options: ['ransomware', 'apt', 'initial-access', 'persistence', 'credential-access', 'balanced'],
              default: 'balanced',
            },
            data_sources: {
              description: 'Primary data source available',
              options: ['Sysmon', 'Windows Security', 'EDR', 'Cloud Logs', 'Network', 'All'],
              default: 'All',
            },
          },
          
          // Recommended sprint backlog (default configuration)
          recommended_backlog: [
            ...ransomwareGaps.critical_gaps.filter(g => g.priority === 'P0').slice(0, 3),
            ...aptGaps.critical_gaps.filter(g => g.priority === 'P0').slice(0, 2),
          ].map((g, i) => ({
            priority: i + 1,
            technique: g.technique,
            reason: g.reason,
            effort: 'Medium',
          })),
          
          // Weak coverage to consider
          weak_coverage_candidates: coverage.weak_coverage.slice(0, 5),
        };
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(sprintPlan, null, 2),
          }],
        };
      }
      
      // Lightweight summary tools
      case 'get_coverage_summary': {
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic' | undefined;
        const report = analyzeCoverage(sourceType);
        
        // Return minimal data - just percentages
        const summary = {
          techniques: report.summary.total_techniques,
          detections: report.summary.total_detections,
          by_tactic: Object.fromEntries(
            Object.entries(report.summary.coverage_by_tactic).map(
              ([tactic, data]) => [tactic, `${data.percent}%`]
            )
          ),
        };
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(summary, null, 2),
          }],
        };
      }
      
      case 'get_top_gaps': {
        const threatProfile = args?.threat_profile as string;
        
        if (!threatProfile) {
          return { 
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                error: true,
                code: 'MISSING_REQUIRED_ARG',
                message: 'threat_profile is required',
                valid_values: THREAT_PROFILE_COMPLETIONS,
              }, null, 2)
            }] 
          };
        }
        
        const gaps = identifyGaps(threatProfile);
        
        // Return minimal data - just top 5 technique IDs
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              profile: threatProfile,
              gaps: gaps.critical_gaps.slice(0, 5).map(g => g.technique),
              total: gaps.total_gaps,
            }, null, 2),
          }],
        };
      }
      
      case 'get_technique_count': {
        const techniqueId = args?.technique_id as string;
        
        if (!techniqueId) {
          return { 
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                error: true,
                code: 'MISSING_REQUIRED_ARG', 
                message: 'technique_id is required',
                examples: ['T1059.001', 'T1547.001'],
              }, null, 2)
            }] 
          };
        }
        
        const detections = listByMitre(techniqueId, 1000, 0);
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              technique: techniqueId,
              count: detections.length,
            }, null, 2),
          }],
        };
      }
      
      // Smart compare with dynamic elicitation
      case 'smart_compare': {
        const topic = args?.topic as string;
        
        if (!topic) {
          return { 
            content: [{ 
              type: 'text', 
              text: JSON.stringify({
                error: true,
                code: 'MISSING_REQUIRED_ARG',
                message: 'topic is required',
                examples: ['powershell', 'credential dumping', 'T1059.001', 'ransomware'],
              }, null, 2)
            }] 
          };
        }
        
        // Search to see what we have for this topic
        const allResults = searchDetections(topic, 500);
        
        if (allResults.length === 0) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                topic,
                found: 0,
                suggestion: 'No detections found. Try a broader search term.',
              }, null, 2),
            }],
          };
        }
        
        // Analyze what we found - group by source AND tactic
        const bySource: Record<string, number> = {};
        const byTactic: Record<string, number> = {};
        const bySeverity: Record<string, number> = {};
        
        for (const r of allResults) {
          bySource[r.source_type] = (bySource[r.source_type] || 0) + 1;
          if (r.severity) bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1;
          for (const tactic of (r.mitre_tactics || [])) {
            byTactic[tactic] = (byTactic[tactic] || 0) + 1;
          }
        }
        
        // Build DYNAMIC options based on what was found
        const sourceOpts = Object.keys(bySource).sort((a, b) => bySource[b] - bySource[a]);
        const sourceLabels = sourceOpts.map(s => `${s} (${bySource[s]})`);
        
        const tacticOpts = Object.keys(byTactic).sort((a, b) => byTactic[b] - byTactic[a]).slice(0, 8);
        const tacticLabels = tacticOpts.map(t => `${t} (${byTactic[t]})`);
        
        const severityOpts = Object.keys(bySeverity).sort((a, b) => {
          const order = ['critical', 'high', 'medium', 'low', 'informational'];
          return order.indexOf(a) - order.indexOf(b);
        });
        const severityLabels = severityOpts.map(s => `${s} (${bySeverity[s]})`);
        
        try {
          const elicitResult = await server.elicitInput({
            message: `Found ${allResults.length} detections for "${topic}"\n\nBreakdown:\n• Sources: ${sourceOpts.map(s => `${s}(${bySource[s]})`).join(', ')}\n• Top tactics: ${tacticOpts.slice(0,3).join(', ')}`,
            requestedSchema: {
              type: 'object' as const,
              properties: {
                compare_by: {
                  type: 'string' as const,
                  title: 'Compare by what?',
                  description: 'How to slice the comparison',
                  enum: ['source', 'tactic', 'severity', 'all'],
                  enumNames: ['By Source (Sigma vs Splunk vs Elastic vs KQL)', 'By MITRE Tactic', 'By Severity', 'Show everything'],
                  default: 'source',
                },
                filter_source: {
                  type: 'string' as const,
                  title: 'Filter to specific source?',
                  description: 'Optional: focus on one source',
                  enum: ['none', ...sourceOpts],
                  enumNames: ['No filter (all sources)', ...sourceLabels],
                  default: 'none',
                },
                filter_tactic: {
                  type: 'string' as const,
                  title: 'Filter to specific tactic?',
                  description: 'Optional: focus on one tactic',
                  enum: ['none', ...tacticOpts],
                  enumNames: ['No filter (all tactics)', ...tacticLabels],
                  default: 'none',
                },
                show_queries: {
                  type: 'boolean' as const,
                  title: 'Include detection queries?',
                  description: 'Show the actual detection logic',
                  default: false,
                },
              },
              required: ['compare_by'],
            },
          });
          
          if (elicitResult.action === 'accept' && elicitResult.content) {
            const compareBy = elicitResult.content.compare_by as string;
            const filterSource = elicitResult.content.filter_source as string;
            const filterTactic = elicitResult.content.filter_tactic as string;
            const showQueries = elicitResult.content.show_queries as boolean;
            
            // Apply filters
            let filtered = allResults;
            if (filterSource && filterSource !== 'none') {
              filtered = filtered.filter(r => r.source_type === filterSource);
            }
            if (filterTactic && filterTactic !== 'none') {
              filtered = filtered.filter(r => r.mitre_tactics?.includes(filterTactic));
            }
            
            // Build comparison based on user choice
            const compBySource: Record<string, unknown[]> = {};
            const compByTactic: Record<string, unknown[]> = {};
            const compBySeverity: Record<string, unknown[]> = {};
            
            if (compareBy === 'source' || compareBy === 'all') {
              for (const r of filtered) {
                if (!compBySource[r.source_type]) {
                  compBySource[r.source_type] = [];
                }
                compBySource[r.source_type].push({
                  name: r.name,
                  severity: r.severity,
                  mitre: r.mitre_ids?.slice(0, 3),
                  query: showQueries ? r.query?.substring(0, 200) : undefined,
                });
              }
            }
            
            if (compareBy === 'tactic' || compareBy === 'all') {
              for (const r of filtered) {
                for (const tactic of (r.mitre_tactics || ['unknown'])) {
                  if (!compByTactic[tactic]) {
                    compByTactic[tactic] = [];
                  }
                  compByTactic[tactic].push({
                    name: r.name,
                    source: r.source_type,
                    severity: r.severity,
                  });
                }
              }
            }
            
            if (compareBy === 'severity' || compareBy === 'all') {
              for (const r of filtered) {
                const sev = r.severity || 'unknown';
                if (!compBySeverity[sev]) {
                  compBySeverity[sev] = [];
                }
                compBySeverity[sev].push({
                  name: r.name,
                  source: r.source_type,
                });
              }
            }
            
            const comparison: Record<string, unknown> = {};
            if (Object.keys(compBySource).length > 0) comparison.by_source = compBySource;
            if (Object.keys(compByTactic).length > 0) comparison.by_tactic = compByTactic;
            if (Object.keys(compBySeverity).length > 0) comparison.by_severity = compBySeverity;
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  topic,
                  total_found: allResults.length,
                  after_filters: filtered.length,
                  filters_applied: {
                    source: filterSource !== 'none' ? filterSource : null,
                    tactic: filterTactic !== 'none' ? filterTactic : null,
                  },
                  comparison,
                }, null, 2),
              }],
            };
          }
          
          return { content: [{ type: 'text', text: 'Comparison cancelled.' }] };
          
        } catch (e) {
          // No elicitation - return summary
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                topic,
                total: allResults.length,
                by_source: bySource,
                by_tactic: byTactic,
                by_severity: bySeverity,
              }, null, 2),
            }],
          };
        }
      }
      
      default:
        return {
          content: [{
            type: 'text',
            text: `Unknown tool: ${name}`,
          }],
        };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      content: [{
        type: 'text',
        text: `Error: ${message}`,
      }],
    };
  }
});

// Main entry point
async function main() {
  // Auto-index on startup
  autoIndex();
  
  // Start MCP server
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  console.error('[security-detections-mcp] Server started');
}

main().catch((error) => {
  console.error('[security-detections-mcp] Fatal error:', error);
  process.exit(1);
});
