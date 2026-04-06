import { readFileSync } from 'fs';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { createHash } from 'crypto';
import type { Detection, SigmaRule } from '../types.js';

// Extract MITRE ATT&CK IDs from Sigma tags
// Tags like: attack.t1059.001, attack.execution, attack.s0154, attack.g0032
function extractMitreIds(tags: string[] | undefined): string[] {
  if (!tags) return [];
  
  const mitreIds: string[] = [];
  for (const tag of tags) {
    const lower = tag.toLowerCase();
    // Match technique IDs: attack.t1234 or attack.t1234.001
    const techMatch = lower.match(/^attack\.t(\d{4}(?:\.\d{3})?)$/);
    if (techMatch) {
      mitreIds.push(`T${techMatch[1].toUpperCase()}`);
      continue;
    }
    // Match software IDs: attack.s1234
    const softMatch = lower.match(/^attack\.s(\d{4})$/);
    if (softMatch) {
      mitreIds.push(`S${softMatch[1]}`);
      continue;
    }
    // Match group IDs: attack.g1234
    const groupMatch = lower.match(/^attack\.g(\d{4})$/);
    if (groupMatch) {
      mitreIds.push(`G${groupMatch[1]}`);
    }
  }
  return mitreIds;
}

// Extract MITRE tactics from tags (attack.execution, attack.persistence, etc)
function extractMitreTactics(tags: string[] | undefined): string[] {
  if (!tags) return [];
  
  const validTactics = [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact'
  ];
  
  const tactics: string[] = [];
  for (const tag of tags) {
    const lower = tag.toLowerCase();
    if (lower.startsWith('attack.')) {
      const tactic = lower.replace('attack.', '');
      if (validTactics.includes(tactic)) {
        tactics.push(tactic);
      }
    }
  }
  return [...new Set(tactics)];
}

// Extract CVE IDs from tags
// Tags like: cve.2021-1675, cve.2024-27198
function extractCves(tags: string[] | undefined): string[] {
  if (!tags) return [];
  
  const cves: string[] = [];
  for (const tag of tags) {
    const lower = tag.toLowerCase();
    // Match CVE tags: cve.2021-1675 -> CVE-2021-1675
    const cveMatch = lower.match(/^cve\.(\d{4}-\d+)$/);
    if (cveMatch) {
      cves.push(`CVE-${cveMatch[1].toUpperCase()}`);
    }
  }
  return cves;
}

// Extract process names from detection logic
// Looks for patterns like Image|endswith: '\cmd.exe' or ParentImage|endswith: '\powershell.exe'
function extractProcessNames(detection: Record<string, unknown>): string[] {
  const processNames = new Set<string>();
  
  // Recursively search for process-related fields
  function searchObject(obj: unknown): void {
    if (!obj || typeof obj !== 'object') return;
    
    if (Array.isArray(obj)) {
      for (const item of obj) {
        if (typeof item === 'string') {
          extractProcessFromString(item);
        } else {
          searchObject(item);
        }
      }
      return;
    }
    
    const record = obj as Record<string, unknown>;
    for (const [key, value] of Object.entries(record)) {
      const keyLower = key.toLowerCase();
      
      // Process-related field patterns
      const isProcessField = keyLower.includes('image') || 
                            keyLower.includes('process') ||
                            keyLower.includes('parentimage') ||
                            keyLower.includes('originalfilename') ||
                            keyLower.includes('commandline') ||
                            keyLower.includes('parentcommandline');
      
      if (isProcessField && typeof value === 'string') {
        extractProcessFromString(value);
      } else if (isProcessField && Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'string') {
            extractProcessFromString(item);
          }
        }
      } else if (typeof value === 'object') {
        searchObject(value);
      }
    }
  }
  
  function extractProcessFromString(str: string): void {
    // Match patterns like \cmd.exe, \powershell.exe, \\nginx.exe etc
    const exeMatches = str.match(/\\([^\\]+\.exe)/gi);
    if (exeMatches) {
      for (const match of exeMatches) {
        const name = match.replace(/^\\+/, '').toLowerCase();
        if (name && !name.includes('*') && name.length > 4) {
          processNames.add(name);
        }
      }
    }
    
    // Also look for just process names that end with .exe
    if (str.toLowerCase().endsWith('.exe')) {
      const parts = str.split(/[\\\/]/);
      const name = parts[parts.length - 1].toLowerCase();
      if (name && !name.includes('*') && name.length > 4) {
        processNames.add(name);
      }
    }
  }
  
  searchObject(detection);
  return [...processNames];
}

// Extract file paths from detection logic
function extractFilePaths(detection: Record<string, unknown>): string[] {
  const filePaths = new Set<string>();
  
  function searchObject(obj: unknown): void {
    if (!obj || typeof obj !== 'object') return;
    
    if (Array.isArray(obj)) {
      for (const item of obj) {
        if (typeof item === 'string') {
          extractPathFromString(item);
        } else {
          searchObject(item);
        }
      }
      return;
    }
    
    const record = obj as Record<string, unknown>;
    for (const [key, value] of Object.entries(record)) {
      const keyLower = key.toLowerCase();
      
      // File path related fields
      const isPathField = keyLower.includes('targetfilename') ||
                         keyLower.includes('imageloaded') ||
                         keyLower.includes('filepath') ||
                         keyLower.includes('currentdirectory') ||
                         keyLower.includes('image') ||
                         keyLower.includes('sourcefilename');
      
      if (isPathField && typeof value === 'string') {
        extractPathFromString(value);
      } else if (isPathField && Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'string') {
            extractPathFromString(item);
          }
        }
      } else if (typeof value === 'object') {
        searchObject(value);
      }
    }
  }
  
  function extractPathFromString(str: string): void {
    // Look for common Windows paths that are interesting
    const interestingPaths = [
      'C:\\Windows\\Temp',
      'C:\\Windows\\System32',
      'C:\\Windows\\SysWOW64',
      'C:\\ProgramData',
      'C:\\Users\\Public',
      'C:\\Program Files',
      'C:\\Program Files (x86)',
      '\\AppData\\Local\\Temp',
      '\\AppData\\Roaming',
    ];
    
    for (const path of interestingPaths) {
      if (str.toLowerCase().includes(path.toLowerCase())) {
        filePaths.add(path);
      }
    }
    
    // Also extract Temp paths and suspicious directories
    if (str.toLowerCase().includes('\\temp\\') || str.toLowerCase().includes('\\tmp\\')) {
      filePaths.add('Temp directory');
    }
    if (str.toLowerCase().includes('\\appdata\\')) {
      filePaths.add('AppData directory');
    }
  }
  
  searchObject(detection);
  return [...filePaths];
}

// Extract registry paths from detection logic
function extractRegistryPaths(detection: Record<string, unknown>): string[] {
  const registryPaths = new Set<string>();
  
  function searchObject(obj: unknown): void {
    if (!obj || typeof obj !== 'object') return;
    
    if (Array.isArray(obj)) {
      for (const item of obj) {
        if (typeof item === 'string') {
          extractRegistryFromString(item);
        } else {
          searchObject(item);
        }
      }
      return;
    }
    
    const record = obj as Record<string, unknown>;
    for (const [key, value] of Object.entries(record)) {
      const keyLower = key.toLowerCase();
      
      // Registry related fields
      const isRegistryField = keyLower.includes('targetobject') ||
                             keyLower.includes('registry') ||
                             keyLower.includes('objectname') ||
                             keyLower.includes('details');
      
      if (isRegistryField && typeof value === 'string') {
        extractRegistryFromString(value);
      } else if (isRegistryField && Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'string') {
            extractRegistryFromString(item);
          }
        }
      } else if (typeof value === 'object') {
        searchObject(value);
      }
    }
  }
  
  function extractRegistryFromString(str: string): void {
    // Interesting registry paths
    const interestingKeys = [
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKLM\\SYSTEM\\CurrentControlSet\\Services',
      'Active Setup',
      'Image File Execution Options',
      'AppInit_DLLs',
      'Winlogon',
      'Shell Folders',
      'Environment',
      'Classes\\CLSID',
    ];
    
    for (const key of interestingKeys) {
      if (str.toLowerCase().includes(key.toLowerCase())) {
        registryPaths.add(key);
      }
    }
    
    // Extract Run keys
    if (str.toLowerCase().includes('\\run\\') || str.toLowerCase().includes('\\runonce\\')) {
      registryPaths.add('Run/RunOnce keys');
    }
    if (str.toLowerCase().includes('\\services\\')) {
      registryPaths.add('Services registry');
    }
  }
  
  searchObject(detection);
  return [...registryPaths];
}

// Generate a stable ID from file path and title if no UUID present
function generateId(filePath: string, title: string): string {
  const hash = createHash('sha256')
    .update(`${filePath}:${title}`)
    .digest('hex')
    .substring(0, 32);
  return `sigma-${hash}`;
}

// Normalize falsepositives field (can be string or array)
function normalizeFalsePositives(fp: string | string[] | undefined): string[] {
  if (!fp) return [];
  if (typeof fp === 'string') return [fp];
  return fp;
}

// Determine detection type based on Sigma level and status
function determineDetectionType(rule: SigmaRule): string | null {
  // Sigma doesn't have direct type, but we can infer from status/level
  if (rule.status === 'experimental' || rule.status === 'test') {
    return 'Hunting';
  }
  // Most stable Sigma rules are TTPs
  return 'TTP';
}

// Determine data sources from logsource
function extractDataSources(rule: SigmaRule): string[] {
  const sources: string[] = [];
  
  if (rule.logsource) {
    if (rule.logsource.product) {
      sources.push(rule.logsource.product);
    }
    if (rule.logsource.service) {
      sources.push(rule.logsource.service);
    }
    if (rule.logsource.category) {
      // Map categories to friendly names
      const categoryMap: Record<string, string> = {
        'process_creation': 'Process Creation Events',
        'image_load': 'Image Load Events',
        'file_event': 'File Events',
        'registry_event': 'Registry Events',
        'registry_set': 'Registry Set Events',
        'registry_add': 'Registry Add Events',
        'registry_delete': 'Registry Delete Events',
        'network_connection': 'Network Connection Events',
        'dns_query': 'DNS Query Events',
        'pipe_created': 'Named Pipe Events',
        'wmi_event': 'WMI Events',
        'driver_load': 'Driver Load Events',
        'create_remote_thread': 'Remote Thread Creation',
        'process_access': 'Process Access Events',
      };
      const friendly = categoryMap[rule.logsource.category] || rule.logsource.category;
      sources.push(friendly);
    }
  }
  
  return sources;
}

export function parseSigmaFile(filePath: string): Detection | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const rule = parseYaml(content) as SigmaRule;
    
    // title is required
    if (!rule.title) {
      return null;
    }
    
    // logsource and detection are required
    if (!rule.logsource || !rule.detection) {
      return null;
    }
    
    const id = rule.id || generateId(filePath, rule.title);
    
    const detection: Detection = {
      id,
      name: rule.title,
      description: rule.description || '',
      query: stringifyYaml(rule.detection),
      source_type: 'sigma',
      mitre_ids: extractMitreIds(rule.tags),
      logsource_category: rule.logsource.category || null,
      logsource_product: rule.logsource.product || null,
      logsource_service: rule.logsource.service || null,
      severity: rule.level || null,
      status: rule.status || null,
      author: rule.author || null,
      date_created: rule.date || null,
      date_modified: rule.modified || null,
      references: rule.references || [],
      falsepositives: normalizeFalsePositives(rule.falsepositives),
      tags: rule.tags || [],
      file_path: filePath,
      raw_yaml: content,
      
      // New enhanced fields
      cves: extractCves(rule.tags),
      analytic_stories: [], // Sigma doesn't have analytic stories
      data_sources: extractDataSources(rule),
      detection_type: determineDetectionType(rule),
      asset_type: rule.logsource.product === 'windows' ? 'Endpoint' : 
                  rule.logsource.product === 'linux' ? 'Endpoint' :
                  rule.logsource.product === 'aws' ? 'Cloud' :
                  rule.logsource.product === 'azure' ? 'Cloud' :
                  rule.logsource.product === 'gcp' ? 'Cloud' : null,
      security_domain: rule.logsource.category?.includes('network') ? 'network' :
                       rule.logsource.product === 'windows' ? 'endpoint' :
                       rule.logsource.product === 'linux' ? 'endpoint' : null,
      process_names: extractProcessNames(rule.detection),
      file_paths: extractFilePaths(rule.detection),
      registry_paths: extractRegistryPaths(rule.detection),
      mitre_tactics: extractMitreTactics(rule.tags),
      platforms: rule.logsource.product ? [rule.logsource.product] : [],
      kql_category: null,
      kql_tags: [],
      kql_keywords: [],
      sublime_attack_types: [],
      sublime_detection_methods: [],
      sublime_tactics: [],
    };

    return detection;
  } catch (err) {
    // Skip files that can't be parsed
    return null;
  }
}
