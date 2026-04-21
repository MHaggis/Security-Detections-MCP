/**
 * Detection Types
 * Core detection interfaces for Sigma, Splunk ESCU, Elastic, KQL, Sublime, and CrowdStrike CQL rules
 */

/**
 * Unified detection schema - normalized from Sigma, Splunk ESCU, Elastic, KQL, Sublime, and CrowdStrike CQL sources
 */
export interface Detection {
  id: string;
  name: string;
  description: string;
  query: string; // detection logic (YAML for Sigma, SPL for Splunk, EQL/KQL for Elastic, MQL for Sublime)
  source_type: 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | 'sublime' | 'crowdstrike_cql' | 'jamf_protect';
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
  detection_type: string | null;     // TTP, Anomaly, Hunting, Correlation, Rule, Exclusion
  asset_type: string | null;         // Endpoint, Web Server, Cloud, Network, Email
  security_domain: string | null;    // endpoint, network, cloud, access
  process_names: string[];           // Process names referenced in detection (w3wp.exe, cmd.exe, etc)
  file_paths: string[];              // Interesting file paths referenced (C:\Windows\Temp, etc)
  registry_paths: string[];          // Registry paths referenced
  mitre_tactics: string[];           // MITRE tactics extracted from tags (execution, persistence, etc)
  platforms: string[];               // Platforms extracted from metadata (windows, linux, azure, etc.)
  kql_category: string | null;       // Category derived from path (e.g., "Defender For Endpoint")
  kql_tags: string[];                // Tags/keywords extracted from KQL markdown or metadata
  kql_keywords: string[];            // Lightweight extracted keywords for search

  // Sublime-specific fields
  sublime_attack_types: string[];    // Sublime attack types (BEC/Fraud, Credential Phishing, etc.)
  sublime_detection_methods: string[]; // Sublime detection methods (Content analysis, URL analysis, etc.)
  sublime_tactics: string[];         // Sublime tactics_and_techniques (Evasion, Impersonation: Brand, etc.)
}

/**
 * Lightweight detection summary - for fast retrieval without full query/yaml bloat
 */
export interface DetectionSummary {
  id: string;
  name: string;
  source_type: 'sigma' | 'splunk_escu' | 'elastic' | 'kql' | 'sublime' | 'crowdstrike_cql' | 'jamf_protect';
  mitre_ids: string[];
  severity: string | null;
  mitre_tactics: string[];
}

/**
 * Sublime Security rule structure (YAML format with MQL source)
 * @see https://github.com/sublime-security/sublime-rules
 */
export interface SublimeRule {
  name: string;
  description: string;
  type: 'rule' | 'exclusion';
  source: string; // MQL (Message Query Language) query
  id?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  references?: string[];
  tags?: string[];
  authors?: Array<{ name?: string; twitter?: string; github?: string; email?: string }>;
  attack_types?: string[];
  tactics_and_techniques?: string[];
  detection_methods?: string[];
  false_positives?: string[];
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

/**
 * Jamf Protect custom analytic detection structure (YAML with NSPredicate filter).
 * @see https://github.com/jamf/jamfprotect/tree/main/custom_analytic_detections
 */
export interface JamfProtectRule {
  name: string;
  uuid?: string;
  label?: string;
  shortDescription?: string;
  longDescription?: string;
  level?: number;
  inputType?: 'GPProcessEvent' | 'GPFSEvent' | 'GPKeylogRegisterEvent' | 'GPUSBEvent' | string;
  filter: string;
  severity?: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical' | string;
  categories?: string[];
  MitreCategories?: string[] | null;
  tags?: string[] | null;
  snapshotFiles?: string[] | null;
  actions?: Array<{ name?: string } | string>;
  context?: string[] | null;
  version?: number;
  remediation?: string | null;
}

/**
 * CQL Hub rule structure (CrowdStrike Query Language)
 * @see https://github.com/ByteRay-Labs/Query-Hub
 */
export interface CqlHubRule {
  name: string;
  cql: string;
  mitre_ids?: string[];
  description?: string;
  author?: string;
  log_sources?: string[];
  tags?: string[];
  cs_required_modules?: string[];
  explanation?: string;
}
