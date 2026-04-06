import { readFileSync } from 'fs';
import * as TOML from '@iarna/toml';
import type { Detection, ElasticRule } from '../types.js';

// Extract MITRE technique IDs from threat array
function extractMitreIds(threats: ElasticRule['rule']['threat']): string[] {
  if (!threats) return [];
  
  const mitreIds: string[] = [];
  for (const threat of threats) {
    if (threat.technique) {
      for (const tech of threat.technique) {
        if (tech.id) {
          mitreIds.push(tech.id);
        }
        // Also get subtechniques
        if (tech.subtechnique) {
          for (const sub of tech.subtechnique) {
            if (sub.id) {
              mitreIds.push(sub.id);
            }
          }
        }
      }
    }
  }
  return [...new Set(mitreIds)];
}

// Extract MITRE tactics from threat array
function extractMitreTactics(threats: ElasticRule['rule']['threat']): string[] {
  if (!threats) return [];
  
  const tactics: string[] = [];
  for (const threat of threats) {
    if (threat.tactic?.name) {
      // Normalize tactic name to lowercase with hyphens
      const tactic = threat.tactic.name.toLowerCase().replace(/\s+/g, '-');
      tactics.push(tactic);
    }
  }
  return [...new Set(tactics)];
}

// Extract process names from query
function extractProcessNames(query: string | undefined): string[] {
  if (!query) return [];
  
  const processNames = new Set<string>();
  
  // Match patterns like process.name : "cmd.exe" or process.executable : "*\\powershell.exe"
  const patterns = [
    /process\.(?:name|executable)\s*:\s*["']?\*?\\?([^"'\s\*]+\.exe)/gi,
    /process\.(?:name|executable)\s*:\s*\(\s*["']?([^"'\)\s]+\.exe)/gi,
    /"([^"]+\.exe)"/gi,
  ];
  
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(query)) !== null) {
      const name = match[1].replace(/^\*?\\?/, '').toLowerCase();
      if (name.endsWith('.exe') && !name.includes('*') && name.length > 4) {
        processNames.add(name);
      }
    }
  }
  
  // Also look for common process names mentioned
  const commonProcesses = [
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe',
    'msiexec.exe', 'schtasks.exe', 'at.exe', 'wmic.exe', 'net.exe', 'netsh.exe'
  ];
  
  const queryLower = query.toLowerCase();
  for (const proc of commonProcesses) {
    if (queryLower.includes(proc)) {
      processNames.add(proc);
    }
  }
  
  return [...processNames];
}

// Extract file paths from query
function extractFilePaths(query: string | undefined): string[] {
  if (!query) return [];
  
  const filePaths = new Set<string>();
  const queryLower = query.toLowerCase();
  
  const interestingPaths = [
    'C:\\Windows\\Temp',
    'C:\\Windows\\System32',
    'C:\\ProgramData',
    '\\AppData\\Local\\Temp',
    '\\AppData\\Roaming',
  ];
  
  for (const path of interestingPaths) {
    if (queryLower.includes(path.toLowerCase())) {
      filePaths.add(path);
    }
  }
  
  if (queryLower.includes('\\temp\\') || queryLower.includes('/tmp/')) {
    filePaths.add('Temp directory');
  }
  
  return [...filePaths];
}

// Extract registry paths from query
function extractRegistryPaths(query: string | undefined): string[] {
  if (!query) return [];
  
  const registryPaths = new Set<string>();
  const queryLower = query.toLowerCase();
  
  const interestingKeys = [
    'CurrentVersion\\Run',
    'CurrentControlSet\\Services',
    'Image File Execution Options',
    'AppInit_DLLs',
    'Winlogon',
  ];
  
  for (const key of interestingKeys) {
    if (queryLower.includes(key.toLowerCase())) {
      registryPaths.add(key);
    }
  }
  
  if (queryLower.includes('\\run\\') || queryLower.includes('\\runonce\\')) {
    registryPaths.add('Run/RunOnce keys');
  }
  
  return [...registryPaths];
}

// Map Elastic severity to normalized format
function mapSeverity(severity: string | undefined): string | null {
  if (!severity) return null;
  const s = severity.toLowerCase();
  if (s === 'low') return 'low';
  if (s === 'medium') return 'medium';
  if (s === 'high') return 'high';
  if (s === 'critical') return 'critical';
  return s;
}

// Determine asset type from tags
function extractAssetType(tags: string[] | undefined): string | null {
  if (!tags) return null;
  
  for (const tag of tags) {
    const t = tag.toLowerCase();
    if (t.includes('endpoint')) return 'Endpoint';
    if (t.includes('network')) return 'Network';
    if (t.includes('cloud')) return 'Cloud';
  }
  return null;
}

// Determine OS/product from tags or index
function extractProduct(tags: string[] | undefined, indices: string[] | undefined): string | null {
  if (tags) {
    for (const tag of tags) {
      const t = tag.toLowerCase();
      if (t.includes('os: windows')) return 'windows';
      if (t.includes('os: linux')) return 'linux';
      if (t.includes('os: macos')) return 'macos';
    }
  }
  
  if (indices) {
    for (const idx of indices) {
      const i = idx.toLowerCase();
      if (i.includes('windows')) return 'windows';
      if (i.includes('linux')) return 'linux';
      if (i.includes('macos')) return 'macos';
    }
  }
  
  return null;
}

// Extract data sources from tags and index
function extractDataSources(tags: string[] | undefined, indices: string[] | undefined): string[] {
  const sources: string[] = [];
  
  if (tags) {
    for (const tag of tags) {
      if (tag.startsWith('Data Source:')) {
        sources.push(tag.replace('Data Source:', '').trim());
      }
    }
  }
  
  if (indices) {
    for (const idx of indices) {
      sources.push(idx);
    }
  }
  
  return sources;
}

export function parseElasticFile(filePath: string): Detection | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const rule = TOML.parse(content) as unknown as ElasticRule;
    
    // Validate required fields
    if (!rule.rule?.name || !rule.rule?.rule_id) {
      return null;
    }
    
    const threats = rule.rule.threat || [];
    
    const detection: Detection = {
      id: rule.rule.rule_id,
      name: rule.rule.name,
      description: rule.rule.description || '',
      query: rule.rule.query || '',
      source_type: 'elastic',
      mitre_ids: extractMitreIds(threats),
      logsource_category: rule.rule.type || null,  // eql, query, threshold, etc.
      logsource_product: extractProduct(rule.rule.tags, rule.rule.index),
      logsource_service: rule.rule.language || null,  // eql, kql, lucene
      severity: mapSeverity(rule.rule.severity),
      status: rule.metadata?.maturity || null,
      author: rule.rule.author?.join(', ') || null,
      date_created: rule.metadata?.creation_date || null,
      date_modified: rule.metadata?.updated_date || null,
      references: rule.rule.references || [],
      falsepositives: rule.rule.false_positives || [],
      tags: rule.rule.tags || [],
      file_path: filePath,
      raw_yaml: content,  // Actually TOML, but same field
      
      // Enhanced fields
      cves: [],  // Could extract from description/references if needed
      analytic_stories: [],  // Elastic doesn't have this concept
      data_sources: extractDataSources(rule.rule.tags, rule.rule.index),
      detection_type: rule.rule.type === 'machine_learning' ? 'Anomaly' : 'TTP',
      asset_type: extractAssetType(rule.rule.tags),
      security_domain: extractAssetType(rule.rule.tags)?.toLowerCase() || null,
      process_names: extractProcessNames(rule.rule.query),
      file_paths: extractFilePaths(rule.rule.query),
      registry_paths: extractRegistryPaths(rule.rule.query),
      mitre_tactics: extractMitreTactics(threats),
      platforms: [],
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
