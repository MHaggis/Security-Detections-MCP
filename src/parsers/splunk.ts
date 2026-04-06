import { readFileSync } from 'fs';
import { parse as parseYaml } from 'yaml';
import type { Detection, SplunkDetection } from '../types.js';

// Extract process names from SPL search query
function extractProcessNames(search: string): string[] {
  const processNames = new Set<string>();
  
  // Common patterns in SPL for process names
  // e.g., Processes.process_name IN ("cmd.exe", "powershell.exe")
  // or parent_process_name="w3wp.exe"
  const patterns = [
    /process_name\s*(?:IN|=)\s*\(?["']?([^"'\)]+)["']?\)?/gi,
    /parent_process_name\s*(?:IN|=)\s*\(?["']?([^"'\)]+)["']?\)?/gi,
    /Image\|endswith:\s*\\([^\s,]+\.exe)/gi,
    /ParentImage\|endswith:\s*\\([^\s,]+\.exe)/gi,
    /"([^"]+\.exe)"/gi,
    /'([^']+\.exe)'/gi,
  ];
  
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(search)) !== null) {
      const value = match[1];
      // Handle comma-separated values like "cmd.exe", "powershell.exe"
      const names = value.split(',').map(n => n.trim().replace(/["']/g, '').toLowerCase());
      for (const name of names) {
        if (name.endsWith('.exe') && !name.includes('*') && name.length > 4) {
          processNames.add(name);
        }
      }
    }
  }
  
  // Also look for common process name patterns
  const commonProcesses = [
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe',
    'w3wp.exe', 'httpd.exe', 'nginx.exe', 'tomcat.exe', 'java.exe', 'javaw.exe',
    'python.exe', 'perl.exe', 'ruby.exe', 'node.exe', 'php.exe',
    'schtasks.exe', 'at.exe', 'wmic.exe', 'msiexec.exe', 'reg.exe', 'net.exe',
    'net1.exe', 'netsh.exe', 'sc.exe', 'tasklist.exe', 'taskkill.exe'
  ];
  
  const searchLower = search.toLowerCase();
  for (const proc of commonProcesses) {
    if (searchLower.includes(proc)) {
      processNames.add(proc);
    }
  }
  
  return [...processNames];
}

// Extract file paths from SPL
function extractFilePaths(search: string): string[] {
  const filePaths = new Set<string>();
  
  const interestingPaths = [
    'C:\\Windows\\Temp',
    'C:\\Windows\\System32',
    'C:\\Windows\\SysWOW64',
    'C:\\ProgramData',
    'C:\\Users\\Public',
    'C:\\Program Files',
    '\\AppData\\Local\\Temp',
    '\\AppData\\Roaming',
  ];
  
  const searchLower = search.toLowerCase();
  for (const path of interestingPaths) {
    if (searchLower.includes(path.toLowerCase())) {
      filePaths.add(path);
    }
  }
  
  if (searchLower.includes('\\temp\\') || searchLower.includes('\\tmp\\')) {
    filePaths.add('Temp directory');
  }
  if (searchLower.includes('\\appdata\\')) {
    filePaths.add('AppData directory');
  }
  
  return [...filePaths];
}

// Extract registry paths from SPL
function extractRegistryPaths(search: string): string[] {
  const registryPaths = new Set<string>();
  
  const interestingKeys = [
    'CurrentVersion\\Run',
    'CurrentControlSet\\Services',
    'Active Setup',
    'Image File Execution Options',
    'AppInit_DLLs',
    'Winlogon',
    'Shell Folders',
    'Environment',
    'Classes\\CLSID',
  ];
  
  const searchLower = search.toLowerCase();
  for (const key of interestingKeys) {
    if (searchLower.includes(key.toLowerCase())) {
      registryPaths.add(key);
    }
  }
  
  if (searchLower.includes('\\run\\') || searchLower.includes('\\runonce\\')) {
    registryPaths.add('Run/RunOnce keys');
  }
  if (searchLower.includes('\\services\\')) {
    registryPaths.add('Services registry');
  }
  
  return [...registryPaths];
}

// Extract MITRE tactics from attack IDs
function extractMitreTactics(mitreIds: string[] | undefined): string[] {
  if (!mitreIds) return [];
  
  // Map technique IDs to their primary tactics (simplified)
  // In a full implementation, we'd use MITRE ATT&CK data
  const tactics = new Set<string>();
  
  const tacticPrefixes: Record<string, string[]> = {
    'T1059': ['execution'], // Command and Scripting Interpreter
    'T1053': ['execution', 'persistence', 'privilege-escalation'], // Scheduled Task/Job
    'T1547': ['persistence', 'privilege-escalation'], // Boot or Logon Autostart Execution
    'T1548': ['privilege-escalation', 'defense-evasion'], // Abuse Elevation Control Mechanism
    'T1055': ['defense-evasion', 'privilege-escalation'], // Process Injection
    'T1036': ['defense-evasion'], // Masquerading
    'T1003': ['credential-access'], // OS Credential Dumping
    'T1069': ['discovery'], // Permission Groups Discovery
    'T1021': ['lateral-movement'], // Remote Services
    'T1560': ['collection'], // Archive Collected Data
    'T1071': ['command-and-control'], // Application Layer Protocol
    'T1041': ['exfiltration'], // Exfiltration Over C2 Channel
    'T1486': ['impact'], // Data Encrypted for Impact
    'T1190': ['initial-access'], // Exploit Public-Facing Application
    'T1133': ['persistence', 'initial-access'], // External Remote Services
    'T1574': ['persistence', 'privilege-escalation', 'defense-evasion'], // Hijack Execution Flow (DLL stuff)
  };
  
  for (const id of mitreIds) {
    // Get base technique ID (e.g., T1059 from T1059.001)
    const baseId = id.split('.')[0];
    if (tacticPrefixes[baseId]) {
      for (const tactic of tacticPrefixes[baseId]) {
        tactics.add(tactic);
      }
    }
  }
  
  return [...tactics];
}

export function parseSplunkFile(filePath: string): Detection | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const rule = parseYaml(content) as SplunkDetection;
    
    // name and id are required
    if (!rule.name || !rule.id) {
      return null;
    }
    
    // search is required
    if (!rule.search) {
      return null;
    }
    
    const detection: Detection = {
      id: rule.id,
      name: rule.name,
      description: rule.description || '',
      query: rule.search,
      source_type: 'splunk_escu',
      mitre_ids: rule.tags?.mitre_attack_id || [],
      logsource_category: null,
      logsource_product: null,
      logsource_service: null,
      severity: null, // Could map from risk score if available
      status: rule.status || null,
      author: rule.author || null,
      date_created: rule.date || null,
      date_modified: null,
      references: rule.references || [],
      falsepositives: rule.known_false_positives ? [rule.known_false_positives] : [],
      tags: rule.tags?.analytic_story || [],
      file_path: filePath,
      raw_yaml: content,
      
      // Enhanced fields
      cves: rule.tags?.cve || [],
      analytic_stories: rule.tags?.analytic_story || [],
      data_sources: rule.data_source || [],
      detection_type: rule.type || null,
      asset_type: rule.tags?.asset_type as string || null,
      security_domain: rule.tags?.security_domain as string || null,
      process_names: extractProcessNames(rule.search),
      file_paths: extractFilePaths(rule.search),
      registry_paths: extractRegistryPaths(rule.search),
      mitre_tactics: extractMitreTactics(rule.tags?.mitre_attack_id),
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
