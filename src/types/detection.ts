/**
 * Detection Types
 * Core detection interfaces for Sigma, Splunk ESCU, Elastic, and KQL rules
 */

/**
 * Unified detection schema - normalized from Sigma, Splunk ESCU, Elastic, and KQL sources
 */
export interface Detection {
  id: string;
  name: string;
  description: string;
  query: string; // detection logic (YAML for Sigma, SPL for Splunk, EQL/KQL for Elastic)
  source_type: 'sigma' | 'splunk_escu' | 'elastic' | 'kql';
  mitre_ids: string[];
  logsource_category: string | null;
  logsource_product: string | null;
  logsource_service: string | null;
  severity: string | null;
  status: string | null;
  author: string | null;
  date_created: string | null;
  date_modified: string | null;
  references: string[];
  falsepositives: string[];
  tags: string[];
  file_path: string;
  raw_yaml: string;
  
  // Enhanced fields for better semantic search
  cves: string[];                    // CVE IDs (e.g., CVE-2024-27198)
  analytic_stories: string[];        // Splunk analytic stories
  data_sources: string[];            // Data sources (e.g., Sysmon EventID 1, Windows Security)
  detection_type: string | null;     // TTP, Anomaly, Hunting, Correlation
  asset_type: string | null;         // Endpoint, Web Server, Cloud, Network
  security_domain: string | null;    // endpoint, network, cloud, access
  process_names: string[];           // Process names referenced in detection (w3wp.exe, cmd.exe, etc)
  file_paths: string[];              // Interesting file paths referenced (C:\Windows\Temp, etc)
  registry_paths: string[];          // Registry paths referenced
  mitre_tactics: string[];           // MITRE tactics extracted from tags (execution, persistence, etc)
  platforms: string[];               // Platforms extracted from metadata (windows, linux, azure, etc.)
  kql_category: string | null;       // Category derived from path (e.g., "Defender For Endpoint")
  kql_tags: string[];                // Tags/keywords extracted from KQL markdown or metadata
  kql_keywords: string[];            // Lightweight extracted keywords for search
}

/**
 * Lightweight detection summary - for fast retrieval without full query/yaml bloat
 */
export interface DetectionSummary {
  id: string;
  name: string;
  source_type: 'sigma' | 'splunk_escu' | 'elastic' | 'kql';
  mitre_ids: string[];
  severity: string | null;
  mitre_tactics: string[];
}

/**
 * Sigma rule structure based on official Sigma specification
 * @see https://github.com/SigmaHQ/sigma-specification
 */
export interface SigmaRule {
  title: string;
  id?: string;
  name?: string;
  status?: 'stable' | 'test' | 'experimental' | 'deprecated' | 'unsupported';
  description?: string;
  license?: string;
  author?: string;
  references?: string[];
  date?: string;
  modified?: string;
  logsource: {
    category?: string;
    product?: string;
    service?: string;
    definition?: string;
  };
  detection: Record<string, unknown>;
  fields?: string[];
  falsepositives?: string | string[];
  level?: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  tags?: string[];
  related?: Array<{ id: string; type: string }>;
  scope?: string[];
  taxonomy?: string;
}

/**
 * Splunk ESCU (Enterprise Security Content Updates) detection structure
 */
export interface SplunkDetection {
  name: string;
  id: string;
  version?: number;
  date?: string;
  author?: string;
  status?: string;
  type?: string;
  description?: string;
  data_source?: string[];
  search: string;
  how_to_implement?: string;
  known_false_positives?: string;
  references?: string[];
  tags?: {
    analytic_story?: string[];
    asset_type?: string;
    mitre_attack_id?: string[];
    product?: string[];
    security_domain?: string;
    cve?: string[];
    [key: string]: unknown;
  };
}

/**
 * Elastic detection rule structure (TOML format)
 * @see https://github.com/elastic/detection-rules
 */
export interface ElasticRule {
  metadata: {
    creation_date?: string;
    integration?: string[];
    maturity?: string;
    updated_date?: string;
  };
  rule: {
    author?: string[];
    description?: string;
    from?: string;
    index?: string[];
    language?: string;  // eql, kql, lucene, esql
    license?: string;
    name: string;
    references?: string[];
    risk_score?: number;
    rule_id: string;
    severity?: string;
    tags?: string[];
    type?: string;  // query, eql, threshold, machine_learning, etc.
    query?: string;
    note?: string;  // investigation guide
    threat?: ElasticThreat[];
    false_positives?: string[];
  };
}

/**
 * Elastic MITRE ATT&CK threat mapping
 */
export interface ElasticThreat {
  framework?: string;
  tactic?: {
    id?: string;
    name?: string;
    reference?: string;
  };
  technique?: ElasticTechnique[];
}

/**
 * Elastic MITRE ATT&CK technique reference
 */
export interface ElasticTechnique {
  id?: string;
  name?: string;
  reference?: string;
  subtechnique?: ElasticTechnique[];
}
