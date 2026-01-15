import { readFileSync, statSync } from 'fs';
import { basename, dirname, relative } from 'path';
import { createHash } from 'crypto';
import type { Detection } from '../types.js';

// Generate a stable ID from file path
function generateId(filePath: string, name: string): string {
  const hash = createHash('sha256').update(filePath + name).digest('hex').substring(0, 12);
  return `kql-${hash}`;
}

// Extract MITRE technique IDs from markdown content
function extractMitreIds(content: string): string[] {
  const ids = new Set<string>();
  
  // Match technique IDs in tables (e.g., | T1059.001 |)
  const tableMatches = content.matchAll(/\|\s*(T\d{4}(?:\.\d{3})?)\s*\|/g);
  for (const match of tableMatches) {
    ids.add(match[1]);
  }
  
  // Match technique IDs in links
  const linkMatches = content.matchAll(/attack\.mitre\.org\/techniques\/(T\d{4})(?:\/([\d]+))?/g);
  for (const match of linkMatches) {
    if (match[2]) {
      ids.add(`${match[1]}.${match[2].padStart(3, '0')}`);
    } else {
      ids.add(match[1]);
    }
  }
  
  // Match standalone technique IDs
  const standaloneMatches = content.matchAll(/\b(T\d{4}(?:\.\d{3})?)\b/g);
  for (const match of standaloneMatches) {
    ids.add(match[1]);
  }
  
  return Array.from(ids);
}

// Extract MITRE tactics from technique IDs
function extractMitreTactics(mitreIds: string[]): string[] {
  const tactics = new Set<string>();
  
  // Map technique prefixes to tactics
  const tacticPrefixes: Record<string, string[]> = {
    'T1595': ['reconnaissance'],
    'T1592': ['reconnaissance'],
    'T1589': ['reconnaissance'],
    'T1590': ['reconnaissance'],
    'T1591': ['reconnaissance'],
    'T1598': ['reconnaissance'],
    'T1059': ['execution'],
    'T1204': ['execution'],
    'T1047': ['execution'],
    'T1053': ['execution', 'persistence', 'privilege-escalation'],
    'T1003': ['credential-access'],
    'T1110': ['credential-access'],
    'T1555': ['credential-access'],
    'T1558': ['credential-access'],
    'T1539': ['credential-access'],
    'T1552': ['credential-access'],
    'T1547': ['persistence', 'privilege-escalation'],
    'T1546': ['persistence', 'privilege-escalation'],
    'T1543': ['persistence', 'privilege-escalation'],
    'T1136': ['persistence'],
    'T1098': ['persistence'],
    'T1078': ['defense-evasion', 'persistence', 'privilege-escalation', 'initial-access'],
    'T1134': ['defense-evasion', 'privilege-escalation'],
    'T1055': ['defense-evasion', 'privilege-escalation'],
    'T1027': ['defense-evasion'],
    'T1070': ['defense-evasion'],
    'T1036': ['defense-evasion'],
    'T1218': ['defense-evasion'],
    'T1562': ['defense-evasion'],
    'T1087': ['discovery'],
    'T1082': ['discovery'],
    'T1083': ['discovery'],
    'T1018': ['discovery'],
    'T1069': ['discovery'],
    'T1057': ['discovery'],
    'T1021': ['lateral-movement'],
    'T1071': ['command-and-control'],
    'T1105': ['command-and-control'],
    'T1041': ['exfiltration'],
    'T1486': ['impact'],
    'T1490': ['impact'],
    'T1485': ['impact'],
    'T1190': ['initial-access'],
    'T1566': ['initial-access'],
    'T1133': ['persistence', 'initial-access'],
  };
  
  for (const id of mitreIds) {
    const baseId = id.split('.')[0];
    if (tacticPrefixes[baseId]) {
      for (const tactic of tacticPrefixes[baseId]) {
        tactics.add(tactic);
      }
    }
  }
  
  return Array.from(tactics);
}

// Extract KQL queries from markdown code blocks
function extractKqlQueries(content: string): string[] {
  const queries: string[] = [];
  
  // Match ```KQL or ```kql blocks
  const kqlBlocks = content.matchAll(/```(?:KQL|kql)\s*\n([\s\S]*?)```/gi);
  for (const match of kqlBlocks) {
    const query = match[1].trim();
    if (query.length > 0) {
      queries.push(query);
    }
  }
  
  return queries;
}

// Extract title from markdown (first # heading)
function extractTitle(content: string): string | null {
  const match = content.match(/^#\s+(.+)$/m);
  return match ? match[1].trim() : null;
}

// Extract description from markdown
function extractDescription(content: string): string {
  // Look for #### Description section
  const descMatch = content.match(/####\s*Description\s*\n+([\s\S]*?)(?=\n##|\n####|\n\||\n```|$)/i);
  if (descMatch) {
    return descMatch[1].trim().split('\n')[0]; // First paragraph only
  }
  
  // Fallback: first non-heading paragraph after title
  const lines = content.split('\n');
  let foundTitle = false;
  for (const line of lines) {
    if (line.startsWith('# ')) {
      foundTitle = true;
      continue;
    }
    if (foundTitle && line.trim().length > 0 && !line.startsWith('#') && !line.startsWith('|')) {
      return line.trim();
    }
  }
  
  return '';
}

// Extract references from markdown
function extractReferences(content: string): string[] {
  const refs: string[] = [];
  
  // Look for #### References section
  const refMatch = content.match(/####\s*References\s*\n+([\s\S]*?)(?=\n##|\n####|$)/i);
  if (refMatch) {
    const refLines = refMatch[1].split('\n');
    for (const line of refLines) {
      const urlMatch = line.match(/https?:\/\/[^\s\)]+/);
      if (urlMatch) {
        refs.push(urlMatch[0]);
      }
    }
  }
  
  return refs;
}

// Extract author from markdown
function extractAuthor(content: string): string | null {
  const authorMatch = content.match(/####\s*Author.*?\n+(?:.*?Name:\s*)?([^\n]+)/i);
  if (authorMatch) {
    const name = authorMatch[1].trim().replace(/^-\s*/, '');
    if (name && !name.startsWith('**')) {
      return name;
    }
  }
  return null;
}

// Extract category from file path
function extractCategory(filePath: string, basePath: string): string {
  const relPath = relative(basePath, filePath);
  const parts = relPath.split('/');
  // Return first directory name as category
  return parts.length > 1 ? parts[0] : 'Uncategorized';
}

// Extract data sources (KQL tables) from query
function extractDataSources(query: string): string[] {
  const sources = new Set<string>();
  
  // Common Microsoft security table names
  const knownTables = [
    'DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents',
    'DeviceRegistryEvents', 'DeviceLogonEvents', 'DeviceEvents',
    'DeviceImageLoadEvents', 'DeviceInfo', 'DeviceTvmSoftwareInventory',
    'AlertInfo', 'AlertEvidence', 'IdentityInfo', 'IdentityLogonEvents',
    'IdentityQueryEvents', 'IdentityDirectoryEvents', 'CloudAppEvents',
    'EmailEvents', 'EmailAttachmentInfo', 'EmailUrlInfo', 'UrlClickEvents',
    'AADSignInEventsBeta', 'AADSpnSignInEventsBeta', 'SigninLogs',
    'AuditLogs', 'SecurityEvent', 'SecurityAlert', 'Syslog',
    'CommonSecurityLog', 'ThreatIntelligenceIndicator', 'BehaviorAnalytics',
    'OfficeActivity', 'AzureActivity', 'AWSCloudTrail', 'GCPAuditLogs'
  ];
  
  for (const table of knownTables) {
    const regex = new RegExp(`\\b${table}\\b`, 'i');
    if (regex.test(query)) {
      sources.add(table);
    }
  }
  
  return Array.from(sources);
}

// Extract process names from query
function extractProcessNames(query: string): string[] {
  const processes = new Set<string>();
  
  // Match .exe files
  const exeMatches = query.matchAll(/["']?(\w+\.exe)["']?/gi);
  for (const match of exeMatches) {
    processes.add(match[1].toLowerCase());
  }
  
  return Array.from(processes);
}

// Extract keywords from content for search
function extractKeywords(content: string, query: string): string[] {
  const keywords = new Set<string>();
  
  // Extract important security terms
  const securityTerms = [
    'ransomware', 'malware', 'phishing', 'credential', 'lateral movement',
    'persistence', 'privilege escalation', 'exfiltration', 'command and control',
    'c2', 'backdoor', 'rootkit', 'exploit', 'vulnerability', 'brute force',
    'spray', 'injection', 'mimikatz', 'bloodhound', 'cobalt strike', 'empire',
    'powershell', 'wmi', 'psexec', 'admin$', 'scheduled task', 'service',
    'registry', 'startup', 'amsi', 'defender', 'edr', 'bypass', 'evasion'
  ];
  
  const combined = (content + ' ' + query).toLowerCase();
  for (const term of securityTerms) {
    if (combined.includes(term)) {
      keywords.add(term);
    }
  }
  
  return Array.from(keywords);
}

// Extract tags from content
function extractTags(content: string, category: string): string[] {
  const tags = new Set<string>();
  
  // Add category as tag
  tags.add(category.toLowerCase().replace(/\s+/g, '-'));
  
  // Check for threat actor mentions
  const actorPatterns = ['APT', 'STORM-', 'FIN', 'UNC', 'DEV-'];
  for (const pattern of actorPatterns) {
    const match = content.match(new RegExp(`${pattern}[\\d]+`, 'gi'));
    if (match) {
      match.forEach(m => tags.add(m.toUpperCase()));
    }
  }
  
  // Check for common topic tags
  const topicPatterns = [
    'ransomware', 'hunting', 'detection', 'dfir', 'threat-intelligence',
    'ti-feed', 'ioc', 'behavior', 'anomaly'
  ];
  const titleAndContent = content.toLowerCase();
  for (const topic of topicPatterns) {
    if (titleAndContent.includes(topic.replace('-', ' ')) || titleAndContent.includes(topic)) {
      tags.add(topic);
    }
  }
  
  return Array.from(tags);
}

// Determine platform from content and queries
function extractPlatforms(content: string, dataSources: string[]): string[] {
  const platforms = new Set<string>();
  
  // Check for platform indicators
  if (dataSources.some(ds => ds.startsWith('Device'))) {
    platforms.add('windows');
  }
  if (dataSources.some(ds => ds.includes('AAD') || ds.includes('Signin') || ds.includes('Audit'))) {
    platforms.add('azure-ad');
  }
  if (dataSources.some(ds => ds.includes('Email') || ds.includes('Office'))) {
    platforms.add('office-365');
  }
  if (dataSources.some(ds => ds.includes('AWS'))) {
    platforms.add('aws');
  }
  if (dataSources.some(ds => ds.includes('GCP'))) {
    platforms.add('gcp');
  }
  if (content.toLowerCase().includes('sentinel')) {
    platforms.add('azure-sentinel');
  }
  if (content.toLowerCase().includes('defender')) {
    platforms.add('microsoft-defender');
  }
  
  return Array.from(platforms);
}

// Parse a raw .kql file (just query content, filename is title)
export function parseRawKqlFile(filePath: string, basePath: string): Detection | null {
  try {
    const stat = statSync(filePath);
    if (!stat.isFile()) {
      return null;
    }
    
    const content = readFileSync(filePath, 'utf-8');
    const query = content.trim();
    
    if (!query || query.length < 10) {
      return null;
    }
    
    // Title from filename (remove .kql extension)
    const fileName = basename(filePath, '.kql');
    const title = fileName;
    
    const id = generateId(filePath, title);
    const category = extractCategory(filePath, basePath);
    const dataSources = extractDataSources(query);
    const processNames = extractProcessNames(query);
    const keywords = extractKeywords(query, query);
    const tags = extractTags(query, category);
    const platforms = extractPlatforms(query, dataSources);
    
    // Extract CVEs from query comments or content
    const cves: string[] = [];
    const cveMatches = query.matchAll(/CVE-\d{4}-\d+/gi);
    for (const match of cveMatches) {
      cves.push(match[0].toUpperCase());
    }
    
    // Extract description from first comment line if present
    let description = '';
    const commentMatch = query.match(/\/\/\s*(.+)/);
    if (commentMatch) {
      description = commentMatch[1].trim();
    }
    
    const detection: Detection = {
      id,
      name: title,
      description,
      query,
      source_type: 'kql',
      mitre_ids: [],
      logsource_category: null,
      logsource_product: 'microsoft',
      logsource_service: 'kql',
      severity: null,
      status: null,
      author: null,
      date_created: null,
      date_modified: null,
      references: [],
      falsepositives: [],
      tags,
      file_path: filePath,
      raw_yaml: content,
      
      cves,
      analytic_stories: [],
      data_sources: dataSources,
      detection_type: 'Hunting',
      asset_type: dataSources.some(ds => ds.startsWith('Device')) ? 'Endpoint' : 'Cloud',
      security_domain: dataSources.some(ds => ds.startsWith('Device')) ? 'endpoint' : 
                       dataSources.some(ds => ds.includes('Email')) ? 'email' : 'identity',
      process_names: processNames,
      file_paths: [],
      registry_paths: [],
      mitre_tactics: [],
      platforms,
      kql_category: category,
      kql_tags: tags,
      kql_keywords: keywords,
    };
    
    return detection;
  } catch {
    return null;
  }
}

// Parse markdown file with KQL code blocks (Bert-JanP format)
export function parseKqlFile(filePath: string, basePath: string): Detection | null {
  try {
    const stat = statSync(filePath);
    if (!stat.isFile()) {
      return null;
    }
    
    const content = readFileSync(filePath, 'utf-8');
    
    // Extract title
    const title = extractTitle(content);
    if (!title) {
      return null;
    }
    
    // Extract KQL queries
    const queries = extractKqlQueries(content);
    if (queries.length === 0) {
      return null; // Skip files without KQL queries
    }
    
    // Use first query (usually Defender XDR)
    const query = queries[0];
    
    const id = generateId(filePath, title);
    const description = extractDescription(content);
    const mitreIds = extractMitreIds(content);
    const references = extractReferences(content);
    const author = extractAuthor(content);
    const category = extractCategory(filePath, basePath);
    const dataSources = extractDataSources(query);
    const processNames = extractProcessNames(query);
    const keywords = extractKeywords(content, query);
    const tags = extractTags(content, category);
    const platforms = extractPlatforms(content, dataSources);
    const mitreTactics = extractMitreTactics(mitreIds);
    
    const detection: Detection = {
      id,
      name: title,
      description,
      query,
      source_type: 'kql',
      mitre_ids: mitreIds,
      logsource_category: null,
      logsource_product: 'microsoft',
      logsource_service: 'kql',
      severity: null,
      status: null,
      author,
      date_created: null,
      date_modified: null,
      references,
      falsepositives: [],
      tags,
      file_path: filePath,
      raw_yaml: content, // Store original markdown
      
      cves: [],
      analytic_stories: [],
      data_sources: dataSources,
      detection_type: 'Hunting',
      asset_type: dataSources.some(ds => ds.startsWith('Device')) ? 'Endpoint' : 'Cloud',
      security_domain: dataSources.some(ds => ds.startsWith('Device')) ? 'endpoint' : 
                       dataSources.some(ds => ds.includes('Email')) ? 'email' : 'identity',
      process_names: processNames,
      file_paths: [],
      registry_paths: [],
      mitre_tactics: mitreTactics,
      platforms,
      kql_category: category,
      kql_tags: tags,
      kql_keywords: keywords,
    };
    
    return detection;
  } catch {
    return null;
  }
}
