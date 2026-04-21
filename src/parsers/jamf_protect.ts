import { readFileSync } from 'fs';
import { parse as parseYaml } from 'yaml';
import { createHash } from 'crypto';
import type { Detection, JamfProtectRule } from '../types.js';

// MITRE tactic normalization: Jamf's `MitreCategories` mixes CamelCase (`CredentialAccess`),
// spaced (`Credential Access`), and Jamf-specific labels (`LivingOffTheLand`). Normalize the
// input by lowercasing and stripping whitespace, then map to MITRE tactic kebab-case.
const TACTIC_MAP: Record<string, string> = {
  reconnaissance: 'reconnaissance',
  resourcedevelopment: 'resource-development',
  initialaccess: 'initial-access',
  execution: 'execution',
  persistence: 'persistence',
  privilegeescalation: 'privilege-escalation',
  defenseevasion: 'defense-evasion',
  credentialaccess: 'credential-access',
  discovery: 'discovery',
  lateralmovement: 'lateral-movement',
  collection: 'collection',
  commandandcontrol: 'command-and-control',
  exfiltration: 'exfiltration',
  impact: 'impact',
};

// Best-effort mapping for Jamf-specific labels → MITRE techniques + tactics.
// Claims are approximate and lossy but give the coverage-analysis tooling something to work with.
const JAMF_LABEL_MAP: Record<string, { techniques: string[]; tactics: string[] }> = {
  livingofftheland: {
    techniques: ['T1059', 'T1218'],
    tactics: ['execution', 'defense-evasion'],
  },
  knownmalware: {
    techniques: ['T1204.002'],
    tactics: ['execution'],
  },
  knownmaliciousfile: {
    techniques: ['T1204.002'],
    tactics: ['execution'],
  },
  adversaryinthemiddle: {
    techniques: ['T1557'],
    tactics: ['credential-access'],
  },
  credentialharvesting: {
    techniques: ['T1555'],
    tactics: ['credential-access'],
  },
  exploitation: {
    techniques: ['T1203', 'T1068'],
    tactics: ['execution', 'privilege-escalation'],
  },
  systemtampering: {
    techniques: ['T1565'],
    tactics: ['impact'],
  },
  visibility: {
    techniques: [],
    tactics: ['discovery'],
  },
  systemvisibility: {
    techniques: [],
    tactics: ['discovery'],
  },
};

const TECHNIQUE_ID_RE = /^t(\d{4}(?:\.\d{3})?)$/;

interface MitreExtraction {
  ids: string[];
  tactics: string[];
  rawLabels: string[];
}

function extractMitre(raw: string[] | null | undefined): MitreExtraction {
  const ids = new Set<string>();
  const tactics = new Set<string>();
  const rawLabels: string[] = [];
  if (!raw) return { ids: [], tactics: [], rawLabels: [] };

  for (const entry of raw) {
    if (typeof entry !== 'string') continue;
    rawLabels.push(entry);
    const normalized = entry.toLowerCase().replace(/[\s_-]/g, '');

    const techMatch = normalized.match(TECHNIQUE_ID_RE);
    if (techMatch) {
      ids.add(`T${techMatch[1].toUpperCase()}`);
      continue;
    }

    if (TACTIC_MAP[normalized]) {
      tactics.add(TACTIC_MAP[normalized]);
      continue;
    }

    const labelMapping = JAMF_LABEL_MAP[normalized];
    if (labelMapping) {
      labelMapping.techniques.forEach(t => ids.add(t));
      labelMapping.tactics.forEach(t => tactics.add(t));
    }
  }

  return { ids: [...ids], tactics: [...tactics], rawLabels };
}

function extractDataSources(inputType: string | undefined): string[] {
  const base = 'macOS Endpoint Security';
  switch (inputType) {
    case 'GPProcessEvent':
      return ['Process Events', base];
    case 'GPFSEvent':
      return ['File System Events', base];
    case 'GPKeylogRegisterEvent':
      return ['Keylog Register Events', base];
    case 'GPUSBEvent':
      return ['USB Events', base];
    default:
      return inputType ? [inputType, base] : [base];
  }
}

// Pull process names from NSPredicate filter text.
// Jamf filters reference processes via `path.lastPathComponent == "<name>"` or
// `signingInfo.appid == "com.apple.<name>"`.
function extractProcessNames(filter: string): string[] {
  const names = new Set<string>();

  const lastComponentRe = /lastPathComponent\s*==\s*"([^"]+)"/gi;
  let m: RegExpExecArray | null;
  while ((m = lastComponentRe.exec(filter)) !== null) {
    if (m[1]) names.add(m[1]);
  }

  const appidRe = /signingInfo\.appid\s*==\s*"com\.apple\.([A-Za-z0-9_.-]+)"/gi;
  while ((m = appidRe.exec(filter)) !== null) {
    if (m[1]) names.add(m[1]);
  }

  return [...names];
}

// Pull quoted absolute-path references from NSPredicate filter text.
function extractFilePaths(filter: string): string[] {
  const paths = new Set<string>();
  const re = /"(\/[^"\s]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(filter)) !== null) {
    const candidate = m[1];
    if (candidate.length < 3) continue;
    // Skip bundle identifiers and uri-ish schemes.
    if (!candidate.startsWith('/')) continue;
    paths.add(candidate);
  }
  return [...paths];
}

function normalizeSeverity(severity: string | undefined): string | null {
  if (!severity) return null;
  return severity.toLowerCase();
}

function generateId(filePath: string, name: string, uuid: string | undefined): string {
  // Upstream Jamf content occasionally reuses the same uuid across different files
  // (e.g. openclaw_directory_created vs openclaw_onboard both declare the same uuid).
  // Incorporate the filename into the hash so each file produces a unique id; keep
  // the uuid as a prefix when available so it's still recognizable.
  const basename = filePath.split('/').pop() || filePath;
  const hash = createHash('sha256').update(`${filePath}:${name}`).digest('hex').substring(0, 12);
  if (uuid) {
    return `jamf-${uuid}-${hash}`;
  }
  return `jamf-${createHash('sha256').update(`${basename}:${name}`).digest('hex').substring(0, 32)}`;
}

export function parseJamfProtectFile(filePath: string): Detection | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const rule = parseYaml(content) as JamfProtectRule | null;

    if (!rule || typeof rule !== 'object') return null;
    if (!rule.name || !rule.filter) return null;

    const mitre = extractMitre(rule.MitreCategories ?? null);

    const baseTags: string[] = Array.isArray(rule.tags)
      ? (rule.tags as unknown[]).filter((t): t is string => typeof t === 'string')
      : [];
    const categoryTags: string[] = Array.isArray(rule.categories)
      ? (rule.categories as unknown[]).filter((t): t is string => typeof t === 'string')
      : [];
    // Preserve the raw Jamf MITRE labels so their original semantics stay searchable.
    const tags = [...new Set([...baseTags, ...categoryTags, ...mitre.rawLabels])];

    const description = rule.longDescription || rule.shortDescription || '';
    const id = generateId(filePath, rule.name, rule.uuid);

    const detection: Detection = {
      id,
      name: rule.label || rule.name,
      description,
      query: rule.filter,
      source_type: 'jamf_protect',
      mitre_ids: mitre.ids,
      logsource_category: rule.inputType || null,
      logsource_product: 'macos',
      logsource_service: 'jamf_protect',
      severity: normalizeSeverity(rule.severity),
      status: null,
      author: 'Jamf',
      date_created: null,
      date_modified: null,
      references: [],
      falsepositives: [],
      tags,
      file_path: filePath,
      raw_yaml: content,

      cves: [],
      analytic_stories: [],
      data_sources: extractDataSources(rule.inputType),
      detection_type: 'TTP',
      asset_type: 'Endpoint',
      security_domain: 'endpoint',
      process_names: extractProcessNames(rule.filter),
      file_paths: extractFilePaths(rule.filter),
      registry_paths: [],
      mitre_tactics: mitre.tactics,
      platforms: ['macos'],
      kql_category: null,
      kql_tags: [],
      kql_keywords: [],

      sublime_attack_types: [],
      sublime_detection_methods: [],
      sublime_tactics: [],
    };

    return detection;
  } catch {
    return null;
  }
}
