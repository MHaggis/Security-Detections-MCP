# Security Detections MCP - Complete Tools Reference

## Introduction

The Security Detections MCP provides **69+ tools** organized by function for comprehensive detection engineering, coverage analysis, and knowledge management. Each tool includes detailed parameters, return values, and usage examples. Tools can be used individually or combined in powerful workflows.

This reference covers:
- **Detection Search & Retrieval** (8 tools) - Find and retrieve detection rules
- **Story Tools** (4 tools) - Work with analytic stories
- **Classification Filters** (11 tools) - Filter detections by various attributes
- **Coverage & Analysis Tools** (7 tools) - Analyze MITRE ATT&CK coverage and gaps
- **Engineering Intelligence Tools** (8 tools) - Get patterns, templates, and references
- **Knowledge Graph Tools** (12 tools) - Build and query tribal knowledge
- **Dynamic Table Tools** (6 tools) - Create and manage custom data storage
- **Cache & Templates** (8 tools) - Save queries and reusable templates
- **Autonomous Analysis** (3 tools) - Automated comprehensive analysis
- **Comparison Tools** (4 tools) - Compare detections across sources

---

## Tools by Category

### DETECTION SEARCH & RETRIEVAL TOOLS (8 tools)

#### search
**Description:** Full-text search across all detection fields (name, description, query, MITRE IDs, tags, CVEs, analytic stories, process names, file paths, registry paths). Supports FTS5 syntax for advanced queries.

**Input Parameters:**
- `query` (string, required) - Search query. Examples: "powershell.exe", "CVE-2024", "DLL sideloading", "web server"
- `limit` (number, optional) - Max results to return (default: 50)
- `source_type` (enum, optional) - Filter by source: "sigma", "splunk_escu", "elastic", "kql"

**Output:** Array of detection objects matching the search query

**Example:**
```json
{
  "query": "powershell.exe AND NOT legitimate",
  "limit": 20,
  "source_type": "splunk_escu"
}
```

**Related Tools:** `get_by_id`, `list_by_source`, `get_detection_list`

**Notes:** Supports FTS5 full-text search syntax including AND, OR, NOT operators and phrase matching.

---

#### get_by_id
**Description:** Get a single detection by its unique ID (UUID for Sigma, or Splunk detection ID).

**Input Parameters:**
- `id` (string, required) - Detection ID (UUID for Sigma, or Splunk detection ID)

**Output:** Single detection object with full details

**Example:**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**Related Tools:** `search`, `get_raw_yaml`, `get_stats`

**Notes:** Fast lookup for known detection IDs. Use `search` if you only know the name.

---

#### list_all
**Description:** List all detections with pagination support. Returns complete detection objects.

**Input Parameters:**
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of detection objects

**Example:**
```json
{
  "limit": 50,
  "offset": 0
}
```

**Related Tools:** `list_by_source`, `get_stats`, `get_detection_list`

**Notes:** Use pagination for large result sets. Consider filtering with other tools for better performance.

---

#### list_by_source
**Description:** List detections filtered by source type (Sigma, Splunk ESCU, Elastic, KQL).

**Input Parameters:**
- `source_type` (enum, required) - Source type: "sigma", "splunk_escu", "elastic", "kql"
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of detection objects from the specified source

**Example:**
```json
{
  "source_type": "sigma",
  "limit": 100
}
```

**Related Tools:** `search`, `compare_sources`, `count_by_source`

**Notes:** Useful for source-specific analysis or when migrating between detection formats.

---

#### list_by_mitre
**Description:** List detections that map to a specific MITRE ATT&CK technique.

**Input Parameters:**
- `technique_id` (string, required) - MITRE ATT&CK technique ID (e.g., "T1059.001")
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of detection objects covering the specified technique

**Example:**
```json
{
  "technique_id": "T1059.001",
  "limit": 50
}
```

**Related Tools:** `suggest_detections`, `get_technique_count`, `analyze_coverage`

**Notes:** Essential for technique-based coverage analysis and gap identification.

---

#### list_by_severity
**Description:** List detections filtered by severity level.

**Input Parameters:**
- `level` (enum, required) - Severity level: "informational", "low", "medium", "high", "critical"
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of detection objects with the specified severity

**Example:**
```json
{
  "level": "high",
  "limit": 100
}
```

**Related Tools:** `get_stats`, `search`, `list_all`

**Notes:** Useful for prioritizing detections by severity or filtering high-priority alerts.

---

#### get_raw_yaml
**Description:** Get the original YAML content for a detection. Returns the complete source file content.

**Input Parameters:**
- `id` (string, required) - Detection ID

**Output:** Raw YAML string content

**Example:**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**Related Tools:** `get_by_id`, `search`, `suggest_detection_template`

**Notes:** Essential for editing detections or understanding their complete structure. Use when you need the full YAML file.

---

#### get_stats
**Description:** Get statistics about the indexed detections and stories. Returns counts by source, severity, MITRE tactic, detection type, and more.

**Input Parameters:** None

**Output:** Statistics object with counts and breakdowns

**Example:**
```json
{}
```

**Related Tools:** `analyze_coverage`, `get_coverage_summary`, `list_all`

**Notes:** Lightweight overview of the entire detection corpus. Use for dashboard metrics or initial assessment.

---

### STORY TOOLS (4 tools)

#### search_stories
**Description:** Search analytic stories by narrative, description, or name. Stories provide rich context about threat campaigns and detection strategies.

**Input Parameters:**
- `query` (string, required) - Search query for stories (e.g., "ransomware encryption", "credential theft", "persistence")
- `limit` (number, optional) - Max results to return (default: 20)

**Output:** Array of story objects matching the query

**Example:**
```json
{
  "query": "ransomware encryption",
  "limit": 10
}
```

**Related Tools:** `get_story`, `list_stories`, `list_by_analytic_story`

**Notes:** Stories group related detections and provide threat context. Use to understand detection strategies.

---

#### get_story
**Description:** Get detailed information about a specific analytic story by name, including narrative, related detections, and MITRE mappings.

**Input Parameters:**
- `name` (string, required) - Story name (e.g., "Ransomware", "Windows Persistence Techniques")

**Output:** Complete story object with details

**Example:**
```json
{
  "name": "Ransomware"
}
```

**Related Tools:** `search_stories`, `list_by_analytic_story`, `list_stories_by_category`

**Notes:** Stories provide comprehensive threat context and detection grouping strategies.

---

#### list_stories
**Description:** List all analytic stories with pagination support.

**Input Parameters:**
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of story objects

**Example:**
```json
{
  "limit": 50,
  "offset": 0
}
```

**Related Tools:** `list_stories_by_category`, `search_stories`, `get_stats`

**Notes:** Use to browse all available analytic stories or build story catalogs.

---

#### list_stories_by_category
**Description:** List analytic stories by category (e.g., "Malware", "Adversary Tactics", "Abuse", "Cloud Security").

**Input Parameters:**
- `category` (string, required) - Story category (e.g., "Malware", "Adversary Tactics", "Abuse", "Cloud Security")
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of story objects in the specified category

**Example:**
```json
{
  "category": "Ransomware",
  "limit": 20
}
```

**Related Tools:** `list_stories`, `search_stories`, `get_story`

**Notes:** Categories include: Adversary Tactics, Account Compromise, Unauthorized Software, Best Practices, Cloud Security, Command and Control, Lateral Movement, Ransomware, Privilege Escalation, Malware, Vulnerability, Data Destruction.

---

### CLASSIFICATION FILTERS (11 tools)

#### list_by_mitre_tactic
**Description:** List detections by MITRE ATT&CK tactic (e.g., "execution", "persistence", "credential-access").

**Input Parameters:**
- `tactic` (enum, required) - MITRE ATT&CK tactic: "reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of detection objects for the specified tactic

**Example:**
```json
{
  "tactic": "execution",
  "limit": 100
}
```

**Related Tools:** `analyze_coverage`, `get_coverage_summary`, `identify_gaps`

**Notes:** Tactics represent the high-level attack stages. Use for tactic-level coverage analysis.

---

#### list_by_cve
**Description:** List detections that cover a specific CVE vulnerability.

**Input Parameters:**
- `cve_id` (string, required) - CVE ID (e.g., "CVE-2024-27198", "CVE-2021-44228")
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of detection objects covering the CVE

**Example:**
```json
{
  "cve_id": "CVE-2021-44228",
  "limit": 50
}
```

**Related Tools:** `search`, `get_stats`, `list_all`

**Notes:** Essential for vulnerability response and CVE coverage assessment.

---

#### list_by_process_name
**Description:** List detections that reference a specific process name (e.g., "powershell.exe", "w3wp.exe", "cmd.exe").

**Input Parameters:**
- `process_name` (string, required) - Process name to search for (e.g., "powershell.exe", "cmd.exe", "nginx.exe")
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of detection objects referencing the process

**Example:**
```json
{
  "process_name": "powershell.exe",
  "limit": 50
}
```

**Related Tools:** `search`, `get_query_patterns`, `find_similar_detections`

**Notes:** Useful for process-specific threat hunting or understanding detection coverage for specific executables.

---

#### list_by_data_source
**Description:** List detections that use a specific data source (e.g., "Sysmon", "Windows Security", "process_creation").

**Input Parameters:**
- `data_source` (string, required) - Data source to search for (e.g., "Sysmon", "Windows Security", "process_creation")
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of detection objects using the data source

**Example:**
```json
{
  "data_source": "Sysmon",
  "limit": 100
}
```

**Related Tools:** `get_field_reference`, `list_by_logsource`, `suggest_detections`

**Notes:** Critical for data source gap analysis and understanding detection dependencies.

---

#### list_by_logsource
**Description:** List Sigma detections filtered by logsource (category, product, or service).

**Input Parameters:**
- `category` (string, optional) - Logsource category (e.g., "process_creation", "network_connection")
- `product` (string, optional) - Logsource product (e.g., "windows", "linux", "aws")
- `service` (string, optional) - Logsource service (e.g., "sysmon", "security", "powershell")
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of Sigma detection objects matching the logsource criteria

**Example:**
```json
{
  "product": "windows",
  "service": "sysmon",
  "limit": 50
}
```

**Related Tools:** `list_by_data_source`, `list_by_source`, `search`

**Notes:** Sigma-specific filtering. At least one logsource parameter should be provided.

---

#### list_by_detection_type
**Description:** List detections by type (TTP, Anomaly, Hunting, Correlation).

**Input Parameters:**
- `detection_type` (enum, required) - Detection type: "TTP", "Anomaly", "Hunting", "Correlation"
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of detection objects of the specified type

**Example:**
```json
{
  "detection_type": "TTP",
  "limit": 100
}
```

**Related Tools:** `get_stats`, `list_all`, `generate_rba_structure`

**Notes:** Detection types indicate the detection methodology. TTP = technique-based, Anomaly = statistical, Hunting = exploratory.

---

#### list_by_analytic_story
**Description:** List Splunk detections that belong to a specific analytic story (e.g., "Ransomware", "Data Destruction").

**Input Parameters:**
- `story` (string, required) - Analytic story name or partial match (e.g., "Ransomware", "Windows Persistence")
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of detection objects in the specified story

**Example:**
```json
{
  "story": "Ransomware",
  "limit": 50
}
```

**Related Tools:** `get_story`, `search_stories`, `list_stories`

**Notes:** Stories group related detections. Use to see all detections for a threat scenario.

---

#### list_by_kql_category
**Description:** List KQL detections filtered by category (e.g., "Defender For Endpoint", "Azure Active Directory", "Threat Hunting").

**Input Parameters:**
- `category` (string, required) - KQL category derived from folder path (e.g., "Defender For Endpoint", "DFIR", "Sentinel")
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of KQL detection objects in the category

**Example:**
```json
{
  "category": "Defender For Endpoint",
  "limit": 50
}
```

**Related Tools:** `list_by_source`, `list_by_kql_tag`, `list_by_kql_datasource`

**Notes:** KQL-specific categorization. Categories reflect Microsoft security product organization.

---

#### list_by_kql_tag
**Description:** List KQL detections filtered by tag (e.g., "ransomware", "hunting", "ti-feed").

**Input Parameters:**
- `tag` (string, required) - Tag to filter by (e.g., "ransomware", "dfir", "apt")
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of KQL detection objects with the tag

**Example:**
```json
{
  "tag": "ransomware",
  "limit": 50
}
```

**Related Tools:** `list_by_kql_category`, `list_by_source`, `search`

**Notes:** Tags provide flexible categorization for KQL detections.

---

#### list_by_kql_datasource
**Description:** List KQL detections that use a specific Microsoft data source (e.g., "DeviceProcessEvents", "SigninLogs", "EmailEvents").

**Input Parameters:**
- `data_source` (string, required) - Microsoft KQL table name (e.g., "DeviceProcessEvents", "AADSignInEventsBeta", "CloudAppEvents")
- `limit` (number, optional) - Max results to return (default: 100)
- `offset` (number, optional) - Offset for pagination (default: 0)

**Output:** Array of KQL detection objects using the data source

**Example:**
```json
{
  "data_source": "DeviceProcessEvents",
  "limit": 50
}
```

**Related Tools:** `list_by_data_source`, `get_field_reference`, `list_by_kql_category`

**Notes:** Microsoft-specific data source filtering. Essential for Microsoft Sentinel/KQL coverage analysis.

---

#### list_by_name_pattern
**Description:** List detections whose NAME matches a pattern, grouped by source. Returns just name + ID pairs (lightweight).

**Input Parameters:**
- `pattern` (string, required) - Pattern to match in detection names (e.g., "PowerShell", "WMI", "Registry")
- `source_type` (enum, optional) - Filter to specific source: "sigma", "splunk_escu", "elastic", "kql"

**Output:** Array of detection name/ID pairs grouped by source

**Example:**
```json
{
  "pattern": "PowerShell",
  "source_type": "splunk_escu"
}
```

**Related Tools:** `search`, `get_detection_list`, `list_all`

**Notes:** Lightweight name-based search. Use when you only need names and IDs, not full detection objects.

---

### COVERAGE & ANALYSIS TOOLS (7 tools)

#### analyze_coverage
**Description:** Get comprehensive coverage analysis with stats by tactic, top covered techniques, and weak spots. Returns summary data, not raw detections. Use this instead of listing detections and processing manually.

**Input Parameters:**
- `source_type` (enum, optional) - Filter by source type: "sigma", "splunk_escu", "elastic", "kql" (optional - analyzes all if not specified)

**Output:** Coverage analysis object with tactic breakdowns, top techniques, and coverage percentages

**Example:**
```json
{
  "source_type": "splunk_escu"
}
```

**Related Tools:** `get_coverage_summary`, `identify_gaps`, `get_technique_ids`

**Notes:** Comprehensive analysis tool. Use for detailed coverage assessment. For quick overviews, use `get_coverage_summary` instead.

---

#### identify_gaps
**Description:** Identify detection gaps based on a threat profile (ransomware, apt, initial-access, persistence, credential-access, defense-evasion). Returns prioritized gaps with recommendations.

**Input Parameters:**
- `threat_profile` (enum, required) - Threat profile: "ransomware", "apt", "initial-access", "persistence", "credential-access", "defense-evasion"
- `source_type` (enum, optional) - Filter by source type: "sigma", "splunk_escu", "elastic", "kql"

**Output:** Gap analysis object with prioritized gaps, missing techniques, and recommendations

**Example:**
```json
{
  "threat_profile": "ransomware",
  "source_type": "splunk_escu"
}
```

**Related Tools:** `suggest_detections`, `get_top_gaps`, `auto_gap_report`

**Notes:** Essential for gap analysis. Use `get_top_gaps` for quick gap checks. Use `auto_gap_report` for comprehensive stored analysis.

---

#### suggest_detections
**Description:** Get detection suggestions for a specific technique. Returns existing detections, required data sources, and detection ideas.

**Input Parameters:**
- `technique_id` (string, required) - MITRE technique ID (e.g., "T1059.001", "T1547.001")
- `source_type` (enum, optional) - Filter by source type: "sigma", "splunk_escu", "elastic", "kql"

**Output:** Detection suggestions object with existing detections, data source requirements, and detection ideas

**Example:**
```json
{
  "technique_id": "T1059.001",
  "source_type": "splunk_escu"
}
```

**Related Tools:** `identify_gaps`, `get_query_patterns`, `suggest_detection_template`

**Notes:** Use when you know the technique but need detection ideas. Combines well with `get_query_patterns` for implementation.

---

#### get_technique_ids
**Description:** Get ONLY unique MITRE technique IDs (lightweight - no full detection data). Use this for Navigator layer generation or coverage analysis.

**Input Parameters:**
- `source_type` (enum, optional) - Filter by source type: "sigma", "splunk_escu", "elastic", "kql"
- `tactic` (enum, optional) - Filter by MITRE tactic
- `severity` (enum, optional) - Filter by severity: "informational", "low", "medium", "high", "critical"

**Output:** Array of unique technique IDs

**Example:**
```json
{
  "source_type": "splunk_escu",
  "tactic": "execution"
}
```

**Related Tools:** `analyze_coverage`, `get_coverage_summary`, `list_by_mitre`

**Notes:** Lightweight tool for coverage visualization. Perfect for generating ATT&CK Navigator layers.

---

#### get_coverage_summary
**Description:** Get a lightweight coverage summary (~200 bytes) with tactic percentages. Use this for quick overviews instead of full `analyze_coverage`.

**Input Parameters:**
- `source_type` (enum, optional) - Filter by source type: "sigma", "splunk_escu", "elastic", "kql"

**Output:** Coverage summary object with tactic percentages

**Example:**
```json
{
  "source_type": "splunk_escu"
}
```

**Related Tools:** `analyze_coverage`, `get_stats`, `get_technique_ids`

**Notes:** Fast overview tool. Use when you only need percentages, not detailed analysis.

---

#### get_top_gaps
**Description:** Get just the top 5 gaps (~300 bytes) for a threat profile. Use this for quick gap checks.

**Input Parameters:**
- `threat_profile` (enum, required) - Threat profile: "ransomware", "apt", "initial-access", "persistence", "credential-access", "defense-evasion"

**Output:** Top 5 gaps object with technique IDs and brief descriptions

**Example:**
```json
{
  "threat_profile": "ransomware"
}
```

**Related Tools:** `identify_gaps`, `suggest_detections`, `auto_gap_report`

**Notes:** Quick gap check tool. Use `identify_gaps` for comprehensive analysis.

---

#### get_technique_count
**Description:** Get just the detection count for a technique (~50 bytes). Use this for quick coverage checks.

**Input Parameters:**
- `technique_id` (string, required) - MITRE technique ID (e.g., "T1059.001")

**Output:** Count object with technique ID and detection count

**Example:**
```json
{
  "technique_id": "T1059.001"
}
```

**Related Tools:** `list_by_mitre`, `suggest_detections`, `get_coverage_summary`

**Notes:** Fastest coverage check. Use to quickly verify if a technique has coverage.

---

### ENGINEERING INTELLIGENCE TOOLS (8 tools)

#### get_query_patterns
**Description:** Get common query patterns for a MITRE technique based on existing detections. Returns SPL structure, common fields, macros used, and example queries. Use this before writing a detection to learn the conventions.

**Input Parameters:**
- `technique_id` (string, required) - MITRE technique ID (e.g., "T1059.001", "T1003.001")
- `source_type` (enum, optional) - Filter patterns by source type: "sigma", "splunk_escu", "elastic", "kql"

**Output:** Query patterns object with structure, fields, macros, and examples

**Example:**
```json
{
  "technique_id": "T1059.001",
  "source_type": "splunk_escu"
}
```

**Related Tools:** `suggest_detection_template`, `get_macro_reference`, `get_field_reference`

**Notes:** Essential for learning detection conventions. Use before writing new detections to follow best practices.

---

#### get_field_reference
**Description:** Get available fields for a Splunk data model with usage examples. Use this to understand what fields are available when writing a detection query.

**Input Parameters:**
- `data_model` (string, required) - Data model name (e.g., "Endpoint.Processes", "Endpoint.Filesystem", "Network_Traffic.All_Traffic")

**Output:** Field reference object with available fields and usage examples

**Example:**
```json
{
  "data_model": "Endpoint.Processes"
}
```

**Related Tools:** `get_query_patterns`, `get_macro_reference`, `suggest_detection_template`

**Notes:** Critical for Splunk detection engineering. Use to understand data model structure.

---

#### get_macro_reference
**Description:** Get common Splunk macros and their usage patterns. Essential for writing detections that follow repository conventions.

**Input Parameters:**
- `filter` (string, optional) - Filter macros by name (e.g., "security_content")

**Output:** Macro reference object with macro names, descriptions, and usage examples

**Example:**
```json
{
  "filter": "security_content"
}
```

**Related Tools:** `get_query_patterns`, `get_field_reference`, `suggest_detection_template`

**Notes:** Macros enforce consistency. Use to learn repository conventions.

---

#### find_similar_detections
**Description:** Find existing detections similar to what you want to create. Use this to learn from existing detection logic and structure.

**Input Parameters:**
- `description` (string, required) - Describe the behavior you want to detect (e.g., "PowerShell downloading files", "process injection via CreateRemoteThread")
- `technique_id` (string, optional) - MITRE technique ID to narrow search
- `source_type` (enum, optional) - Filter by source type: "sigma", "splunk_escu", "elastic", "kql"
- `limit` (number, optional) - Maximum results (default: 5)

**Output:** Array of similar detection objects

**Example:**
```json
{
  "description": "PowerShell executing encoded commands",
  "technique_id": "T1059.001",
  "limit": 5
}
```

**Related Tools:** `suggest_detection_template`, `get_query_patterns`, `search`

**Notes:** Uses semantic similarity. Great for finding reference implementations.

---

#### suggest_detection_template
**Description:** Generate a detection template based on technique, learned patterns, and conventions. Returns YAML structure ready for customization.

**Input Parameters:**
- `technique_id` (string, required) - MITRE technique ID (e.g., "T1059.001")
- `description` (string, required) - What behavior to detect (e.g., "PowerShell executing encoded commands")
- `data_model` (string, optional) - Data model (e.g., "Endpoint.Processes"). If not specified, will use most common for technique.
- `detection_type` (enum, optional) - Detection type: "TTP", "Anomaly", "Hunting" (default: "TTP")
- `platform` (enum, optional) - Target platform: "Windows", "Linux", "macOS", "AWS", "Azure", "GCP" (default: "Windows")

**Output:** Detection template YAML structure

**Example:**
```json
{
  "technique_id": "T1059.001",
  "description": "PowerShell executing base64 encoded commands",
  "data_model": "Endpoint.Processes",
  "detection_type": "TTP",
  "platform": "Windows"
}
```

**Related Tools:** `get_query_patterns`, `generate_rba_structure`, `find_similar_detections`

**Notes:** Generates complete detection templates following repository conventions. Customize the output for your specific needs.

---

#### generate_rba_structure
**Description:** Generate RBA (Risk-Based Alerting) structure for a detection based on learned patterns and best practices.

**Input Parameters:**
- `detection_type` (enum, required) - Type of detection: "TTP", "Anomaly", "Hunting", "Correlation"
- `severity` (enum, required) - Detection severity: "low", "medium", "high", "critical"
- `description` (string, required) - What the detection identifies (for message generation)
- `fields_available` (array, optional) - Fields available in the detection (e.g., ["dest", "user", "process_name"])

**Output:** RBA structure object with risk objects, scores, and message template

**Example:**
```json
{
  "detection_type": "TTP",
  "severity": "high",
  "description": "Suspicious PowerShell execution",
  "fields_available": ["dest", "user", "process_name"]
}
```

**Related Tools:** `suggest_detection_template`, `get_query_patterns`, `list_by_detection_type`

**Notes:** RBA structures assign risk scores to entities. Use when creating Splunk detections.

---

#### extract_patterns
**Description:** Extract and store patterns from all indexed detections. Run this to populate the pattern database for template generation.

**Input Parameters:**
- `force` (boolean, optional) - Force re-extraction even if patterns exist (default: false)

**Output:** Extraction summary with pattern counts

**Example:**
```json
{
  "force": false
}
```

**Related Tools:** `suggest_detection_template`, `get_query_patterns`, `learn_from_feedback`

**Notes:** Background operation. Run periodically to update pattern database. Use `force: true` to rebuild.

---

#### learn_from_feedback
**Description:** Store user preference or correction to improve future suggestions. Call this when user modifies generated content to build tribal knowledge.

**Input Parameters:**
- `feedback_type` (enum, required) - Type of feedback: "naming", "query_structure", "rba_score", "field_usage", "style", "macro_usage"
- `original` (string, required) - What was originally suggested
- `corrected` (string, required) - What the user changed it to
- `context` (string, optional) - Additional context (technique, detection type, etc.)

**Output:** Confirmation of stored feedback

**Example:**
```json
{
  "feedback_type": "naming",
  "original": "Suspicious_PowerShell_Execution",
  "corrected": "PowerShell_Encoded_Command_Execution",
  "context": "T1059.001 detection"
}
```

**Related Tools:** `suggest_detection_template`, `get_query_patterns`, `add_learning`

**Notes:** Builds tribal knowledge over time. Use whenever you modify generated content to improve future suggestions.

---

### KNOWLEDGE GRAPH TOOLS (12 tools)

#### create_entity
**Description:** Create a knowledge entity representing a security concept. Use this to build the knowledge graph with threat actors, techniques, detections, campaigns, tools, vulnerabilities, and data sources.

**Input Parameters:**
- `name` (string, required) - Unique name for the entity (e.g., "APT29", "T1059.001", "Cobalt Strike")
- `entity_type` (enum, required) - Type of entity: "threat_actor", "technique", "detection", "campaign", "tool", "vulnerability", "data_source"

**Output:** Created entity object

**Example:**
```json
{
  "name": "APT29",
  "entity_type": "threat_actor"
}
```

**Related Tools:** `create_relation`, `add_observation`, `open_entity`

**Notes:** Entities are the nodes in the knowledge graph. Create entities before creating relations.

---

#### create_relation
**Description:** Create a relationship between two entities WITH reasoning explaining WHY they're connected. This is the core of tribal knowledge - capturing not just the connection but the insight behind it.

**Input Parameters:**
- `from_entity` (string, required) - Name of the source entity
- `to_entity` (string, required) - Name of the target entity
- `relation_type` (string, required) - Type of relationship: "uses", "targets", "detects", "covers", "mitigates", "exploits", "attributed_to", "depends_on", "related_to"
- `reasoning` (string, required) - WHY does this relationship exist? This captures tribal knowledge.
- `confidence` (number, optional) - Confidence in this relationship (0.0-1.0, default: 1.0)

**Output:** Created relation object

**Example:**
```json
{
  "from_entity": "APT29",
  "to_entity": "Cobalt Strike",
  "relation_type": "uses",
  "reasoning": "APT29 consistently uses Cobalt Strike for command and control in their campaigns, as documented in multiple threat reports",
  "confidence": 0.9
}
```

**Related Tools:** `create_entity`, `add_observation`, `read_graph`

**Notes:** The reasoning field is critical - explain WHY this connection exists. This builds tribal knowledge.

---

#### add_observation
**Description:** Add a fact or observation about an entity. Observations capture point-in-time knowledge that can be queried later.

**Input Parameters:**
- `entity_name` (string, required) - Name of the entity this observation is about
- `observation` (string, required) - The fact or observation to record
- `source` (string, optional) - Source of this observation (e.g., "CISA Advisory", "user input", "threat report")
- `confidence` (number, optional) - Confidence in this observation (0.0-1.0, default: 1.0)

**Output:** Created observation object

**Example:**
```json
{
  "entity_name": "APT29",
  "observation": "APT29 has been active since at least 2008",
  "source": "CISA Advisory",
  "confidence": 1.0
}
```

**Related Tools:** `create_entity`, `open_entity`, `search_knowledge`

**Notes:** Observations capture facts. Use for point-in-time knowledge that doesn't fit into relations.

---

#### delete_entity
**Description:** Remove an entity from the knowledge graph. This also removes all relations and observations associated with the entity.

**Input Parameters:**
- `name` (string, required) - Name or ID of the entity to delete

**Output:** Confirmation of deletion

**Example:**
```json
{
  "name": "Outdated_Entity"
}
```

**Related Tools:** `open_entity`, `read_graph`, `delete_observation`

**Notes:** Cascades to relations and observations. Use with caution.

---

#### delete_observation
**Description:** Remove a specific observation by its ID. Use `open_entity` first to find observation IDs.

**Input Parameters:**
- `observation_id` (string, required) - UUID of the observation to delete

**Output:** Confirmation of deletion

**Example:**
```json
{
  "observation_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**Related Tools:** `open_entity`, `add_observation`, `delete_entity`

**Notes:** Use `open_entity` to find observation IDs before deletion.

---

#### search_knowledge
**Description:** Search across all knowledge types: entities, relations, observations, decisions, and learnings. Uses full-text search to find relevant tribal knowledge.

**Input Parameters:**
- `query` (string, required) - Search query (supports FTS5 syntax)
- `limit` (number, optional) - Maximum results to return (default: 30)

**Output:** Array of knowledge objects matching the query

**Example:**
```json
{
  "query": "PowerShell execution",
  "limit": 20
}
```

**Related Tools:** `read_graph`, `get_relevant_decisions`, `get_learnings`

**Notes:** Unified search across all knowledge types. Use to find relevant tribal knowledge.

---

#### read_graph
**Description:** Read the entire knowledge graph or a filtered subgraph. Returns entities, relations, and observations.

**Input Parameters:**
- `entity_type` (string, optional) - Filter to specific entity type (threat_actor, technique, detection, etc.)
- `limit` (number, optional) - Maximum entities/relations to return (default: 500)

**Output:** Knowledge graph object with entities, relations, and observations

**Example:**
```json
{
  "entity_type": "threat_actor",
  "limit": 100
}
```

**Related Tools:** `open_entity`, `search_knowledge`, `create_entity`

**Notes:** Use to get an overview of stored knowledge or filter by entity type.

---

#### open_entity
**Description:** Get complete information about a specific entity including all its relations and observations. This is the detailed view of a single knowledge node.

**Input Parameters:**
- `name` (string, required) - Name or ID of the entity to open

**Output:** Complete entity object with relations and observations

**Example:**
```json
{
  "name": "APT29"
}
```

**Related Tools:** `create_entity`, `create_relation`, `read_graph`

**Notes:** Detailed entity view. Use to understand an entity's complete context.

---

#### log_decision
**Description:** Record WHY a significant decision was made. This is the gold of tribal knowledge - capturing the reasoning process so future agents can understand past decisions.

**Input Parameters:**
- `decision_type` (string, required) - Type of decision: "gap_identified", "detection_recommended", "coverage_mapped", "priority_assigned", "false_positive_tuning", "threat_assessment", "data_source_selected"
- `context` (string, required) - The situation/context that led to this decision
- `decision` (string, required) - The actual decision that was made
- `reasoning` (string, required) - DETAILED explanation of WHY this decision was made - this is the tribal knowledge
- `entities_involved` (array, optional) - Names of entities involved in this decision
- `outcome` (string, optional) - Optional outcome or result of the decision
- `session_id` (string, optional) - Optional session ID to group related decisions

**Output:** Logged decision object

**Example:**
```json
{
  "decision_type": "gap_identified",
  "context": "Analyzing ransomware detection coverage",
  "decision": "Identified T1486 (Data Encrypted for Impact) as high-priority gap",
  "reasoning": "Ransomware attacks consistently use encryption, but we only have 2 detections covering T1486. This is insufficient given ransomware's prevalence and impact.",
  "entities_involved": ["T1486", "Ransomware"],
  "session_id": "session_123"
}
```

**Related Tools:** `get_relevant_decisions`, `add_learning`, `create_relation`

**Notes:** The reasoning field is critical - be detailed. This helps future analysis understand past decisions.

---

#### add_learning
**Description:** Store a pattern or insight derived from analysis for future reference. Learnings are reusable knowledge that can help future sessions.

**Input Parameters:**
- `learning_type` (string, required) - Type of learning: "detection_pattern", "gap_pattern", "user_preference", "false_positive_pattern", "threat_pattern", "correlation_insight", "data_quality_insight"
- `title` (string, required) - Short title for this learning
- `insight` (string, required) - The actual insight or pattern learned
- `evidence` (string, optional) - Evidence supporting this learning (observations, decisions that led to it)
- `applications` (string, optional) - How this learning can be applied in practice

**Output:** Created learning object

**Example:**
```json
{
  "learning_type": "detection_pattern",
  "title": "PowerShell detection needs parent filtering",
  "insight": "Detections for T1059.001 need process parent filtering to reduce false positives in development environments",
  "evidence": "Analysis of 15 PowerShell detections showed 60% FP rate without parent filtering",
  "applications": "Always include parent_process filtering when writing PowerShell detections"
}
```

**Related Tools:** `get_learnings`, `log_decision`, `learn_from_feedback`

**Notes:** Learnings capture reusable patterns. Use to build institutional knowledge.

---

#### get_relevant_decisions
**Description:** Get past decisions relevant to the current context. Uses full-text search to find tribal knowledge that applies to your current analysis.

**Input Parameters:**
- `context_query` (string, required) - Description of current context to find relevant decisions (e.g., "ransomware detection gaps", "credential theft coverage")
- `decision_type` (string, optional) - Optional filter by decision type
- `session_id` (string, optional) - Optional filter by session
- `limit` (number, optional) - Maximum decisions to return (default: 20)

**Output:** Array of relevant decision objects

**Example:**
```json
{
  "context_query": "ransomware detection gaps",
  "limit": 10
}
```

**Related Tools:** `log_decision`, `get_learnings`, `search_knowledge`

**Notes:** Use to see how similar situations were handled before and maintain consistency.

---

#### get_learnings
**Description:** Get applicable learnings for the current task. Returns patterns and insights that may help with the current analysis.

**Input Parameters:**
- `task_query` (string, required) - Description of current task to find relevant learnings (e.g., "writing PowerShell detection", "analyzing APT coverage")
- `learning_type` (string, optional) - Optional filter by learning type
- `limit` (number, optional) - Maximum learnings to return (default: 10)
- `mark_applied` (boolean, optional) - If true, increment the times_applied counter for returned learnings

**Output:** Array of relevant learning objects

**Example:**
```json
{
  "task_query": "writing PowerShell detection",
  "learning_type": "detection_pattern",
  "limit": 5,
  "mark_applied": true
}
```

**Related Tools:** `add_learning`, `get_relevant_decisions`, `suggest_detection_template`

**Notes:** Use to apply proven patterns to new situations and avoid known pitfalls.

---

### DYNAMIC TABLE TOOLS (6 tools)

#### create_table
**Description:** Create a new custom table to store analysis data. Use this to persist findings, research results, or any structured data you want to retrieve later.

**Input Parameters:**
- `name` (string, required) - Table name (alphanumeric and underscores, must start with letter). Examples: "my_analysis", "cve_research", "custom_mappings"
- `description` (string, required) - Human-readable description of what this table stores
- `columns` (array, required) - Column definitions for the table schema. Each column object includes:
  - `name` (string, required) - Column name
  - `type` (enum, required) - SQLite data type: "TEXT", "INTEGER", "REAL", "BLOB"
  - `nullable` (boolean, optional) - Allow NULL values (default: true)
  - `primary_key` (boolean, optional) - Is this the primary key?
  - `unique` (boolean, optional) - Must values be unique?

**Output:** Created table object with schema

**Example:**
```json
{
  "name": "gap_analysis_results",
  "description": "Stores gap analysis findings for different threat profiles",
  "columns": [
    {
      "name": "id",
      "type": "TEXT",
      "primary_key": true,
      "nullable": false
    },
    {
      "name": "threat_profile",
      "type": "TEXT",
      "nullable": false
    },
    {
      "name": "technique_id",
      "type": "TEXT",
      "nullable": false
    },
    {
      "name": "priority",
      "type": "TEXT"
    },
    {
      "name": "created_at",
      "type": "TEXT"
    }
  ]
}
```

**Related Tools:** `insert_row`, `query_table`, `describe_table`

**Notes:** Pre-built tables available: gap_analyses, source_comparisons, threat_actor_profiles, detection_recommendations. Use custom tables for session-specific analysis.

---

#### insert_row
**Description:** Insert a row of data into a dynamic table. Data is validated against the table schema.

**Input Parameters:**
- `table_name` (string, required) - Name of the table to insert into
- `data` (object, required) - Key-value pairs matching the table schema. Use JSON for complex values (arrays, nested objects).
- `row_id` (string, optional) - Optional: Custom row ID. If not provided, a UUID is generated.

**Output:** Inserted row object with ID

**Example:**
```json
{
  "table_name": "gap_analysis_results",
  "data": {
    "threat_profile": "ransomware",
    "technique_id": "T1486",
    "priority": "high",
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

**Related Tools:** `create_table`, `query_table`, `list_tables`

**Notes:** Data must match table schema. Use JSON strings for complex nested data.

---

#### query_table
**Description:** Query data from a dynamic table with optional filtering, sorting, and pagination.

**Input Parameters:**
- `table_name` (string, required) - Name of the table to query
- `where` (object, optional) - Filter conditions as key-value pairs. Use % for LIKE patterns.
- `select` (array, optional) - Columns to return (default: all)
- `order_by` (array, optional) - Sort order. Each item includes:
  - `column` (string) - Column name
  - `direction` (enum) - "ASC" or "DESC"
- `limit` (number, optional) - Maximum rows to return (default: 100)
- `offset` (number, optional) - Number of rows to skip (for pagination)

**Output:** Array of row objects matching the query

**Example:**
```json
{
  "table_name": "gap_analysis_results",
  "where": {
    "threat_profile": "ransomware",
    "priority": "high"
  },
  "order_by": [
    {
      "column": "created_at",
      "direction": "DESC"
    }
  ],
  "limit": 50
}
```

**Related Tools:** `insert_row`, `describe_table`, `create_table`

**Notes:** Filter examples: Exact match `{"status": "completed"}`, LIKE match `{"name": "%ransomware%"}`.

---

#### list_tables
**Description:** List all dynamic tables created by the LLM, including pre-built analysis tables and their statistics.

**Input Parameters:**
- `include_prebuilt` (boolean, optional) - Include pre-built analysis tables in the list (default: true)

**Output:** Array of table objects with names, descriptions, and row counts

**Example:**
```json
{
  "include_prebuilt": true
}
```

**Related Tools:** `describe_table`, `create_table`, `query_table`

**Notes:** Pre-built tables: gap_analyses, source_comparisons, threat_actor_profiles, detection_recommendations.

---

#### drop_table
**Description:** Remove a dynamic table and all its data. Use with caution - this is irreversible.

**Input Parameters:**
- `table_name` (string, required) - Name of the table to drop
- `confirm` (boolean, required) - Must be true to confirm deletion

**Output:** Confirmation of deletion

**Example:**
```json
{
  "table_name": "temp_analysis",
  "confirm": true
}
```

**Related Tools:** `list_tables`, `create_table`, `query_table`

**Notes:** Irreversible operation. Use `confirm: true` to proceed.

---

#### describe_table
**Description:** Get detailed schema information and statistics for a dynamic table.

**Input Parameters:**
- `table_name` (string, required) - Name of the table to describe

**Output:** Table schema object with columns, types, constraints, and statistics

**Example:**
```json
{
  "table_name": "gap_analysis_results"
}
```

**Related Tools:** `create_table`, `query_table`, `list_tables`

**Notes:** Use to understand table structure before querying or inserting.

---

### CACHE & TEMPLATES (8 tools)

#### save_query
**Description:** Save a query result for quick retrieval later. Useful for caching frequently needed data.

**Input Parameters:**
- `name` (string, required) - Name for the saved query (e.g., "powershell_splunk_detections")
- `query_type` (string, required) - Type of query (e.g., "detection_list", "comparison", "coverage")
- `data` (object, required) - The data to save (any JSON object)
- `ttl_minutes` (number, optional) - Time-to-live in minutes (optional, default: no expiry)

**Output:** Saved query confirmation

**Example:**
```json
{
  "name": "ransomware_gaps_2024",
  "query_type": "gap_analysis",
  "data": {
    "threat_profile": "ransomware",
    "gaps": [...]
  },
  "ttl_minutes": 1440
}
```

**Related Tools:** `get_saved_query`, `list_saved_queries`, `save_template`

**Notes:** Use TTL for time-sensitive data. Queries persist across sessions.

---

#### get_saved_query
**Description:** Retrieve a previously saved query result by name.

**Input Parameters:**
- `name` (string, required) - Name of the saved query

**Output:** Saved query object with data and metadata

**Example:**
```json
{
  "name": "ransomware_gaps_2024"
}
```

**Related Tools:** `save_query`, `list_saved_queries`, `run_template`

**Notes:** Fast retrieval of cached results. Check expiry before using.

---

#### list_saved_queries
**Description:** List all saved queries, optionally filtered by type.

**Input Parameters:**
- `query_type` (string, optional) - Optional: filter by query type

**Output:** Array of saved query objects with names, types, and metadata

**Example:**
```json
{
  "query_type": "gap_analysis"
}
```

**Related Tools:** `save_query`, `get_saved_query`, `list_templates`

**Notes:** Use to discover available cached queries.

---

#### save_template
**Description:** Save a reusable query template with {{placeholders}}. Templates can contain SQL queries or tool-chain definitions for future execution.

**Input Parameters:**
- `name` (string, required) - Unique name for the template (e.g., "ransomware_gaps", "technique_coverage")
- `template` (string, required) - The query template with {{param}} placeholders (e.g., "SELECT * FROM detections WHERE mitre_ids LIKE '%{{technique}}%'")
- `description` (string, optional) - Human-readable description of what this template does

**Output:** Saved template confirmation

**Example:**
```json
{
  "name": "technique_detections",
  "template": "SELECT * FROM detections WHERE mitre_ids LIKE '%{{technique}}%' AND source_type = '{{source}}'",
  "description": "Find all detections for a technique from a specific source"
}
```

**Related Tools:** `run_template`, `list_templates`, `get_template`

**Notes:** Templates enable reusable query patterns. Use {{param}} syntax for placeholders.

---

#### run_template
**Description:** Execute a saved query template with the provided parameters. Returns the query results.

**Input Parameters:**
- `name` (string, required) - Name of the saved template to execute
- `params` (object, optional) - Parameter values to substitute into the template (e.g., {"technique": "T1486", "source": "splunk_escu"})

**Output:** Query results from template execution

**Example:**
```json
{
  "name": "technique_detections",
  "params": {
    "technique": "T1486",
    "source": "splunk_escu"
  }
}
```

**Related Tools:** `save_template`, `get_template`, `list_templates`

**Notes:** Parameters replace {{placeholders}} in the template. Use for repeated query patterns.

---

#### list_templates
**Description:** List all saved query templates with their names, descriptions, and usage statistics.

**Input Parameters:**
- `sort_by` (enum, optional) - Field to sort by: "name", "created_at", "use_count" (default: "use_count")
- `limit` (number, optional) - Maximum number of templates to return (default: 50)

**Output:** Array of template objects with metadata

**Example:**
```json
{
  "sort_by": "use_count",
  "limit": 20
}
```

**Related Tools:** `save_template`, `get_template`, `run_template`

**Notes:** Use to discover available templates and their usage patterns.

---

#### get_template
**Description:** Get the full details of a saved query template including the template string and parameters.

**Input Parameters:**
- `name` (string, required) - Name of the template to retrieve

**Output:** Complete template object with template string and metadata

**Example:**
```json
{
  "name": "technique_detections"
}
```

**Related Tools:** `save_template`, `run_template`, `list_templates`

**Notes:** Use to review template structure before execution or editing.

---

#### delete_template
**Description:** Delete a saved query template by name.

**Input Parameters:**
- `name` (string, required) - Name of the template to delete

**Output:** Confirmation of deletion

**Example:**
```json
{
  "name": "outdated_template"
}
```

**Related Tools:** `list_templates`, `save_template`, `get_template`

**Notes:** Irreversible operation. Use to clean up unused templates.

---

### AUTONOMOUS ANALYSIS (3 tools)

#### auto_analyze_coverage
**Description:** Automatically analyze detection coverage, identify gaps across threat profiles, and store findings for future reference.

**Input Parameters:**
- `threat_profiles` (array, optional) - Threat profiles to analyze. Options: "ransomware", "apt", "initial-access", "persistence", "credential-access", "defense-evasion". Default: ["ransomware", "apt"]
- `store_results` (boolean, optional) - Store results in dynamic tables for persistence (default: true)
- `analysis_name` (string, optional) - Optional name for this analysis run (defaults to timestamp-based name)
- `session_id` (string, optional) - Optional session ID to group related analyses

**Output:** Analysis summary with coverage stats, gaps, and stored results

**Example:**
```json
{
  "threat_profiles": ["ransomware", "apt"],
  "store_results": true,
  "analysis_name": "Q1_2024_coverage_analysis",
  "session_id": "session_123"
}
```

**Related Tools:** `analyze_coverage`, `identify_gaps`, `auto_gap_report`

**Notes:** Comprehensive automated analysis. Results persist in dynamic tables. Use for stored, comprehensive analysis.

---

#### auto_gap_report
**Description:** Generate a comprehensive gap report comparing detection coverage across sources (Sigma, Splunk ESCU, Elastic, KQL) and threat profiles.

**Input Parameters:**
- `report_name` (string, optional) - Name for this report (defaults to timestamp-based name)
- `compare_sources` (boolean, optional) - Include source comparison analysis (default: true)
- `include_recommendations` (boolean, optional) - Generate prioritized recommendations (default: true)
- `priority_tactics` (array, optional) - Tactics to prioritize in recommendations. Options: "execution", "persistence", "credential-access", "defense-evasion", "lateral-movement", "exfiltration", "impact"
- `session_id` (string, optional) - Optional session ID to group related reports

**Output:** Comprehensive gap report with source comparisons, prioritized gaps, and recommendations

**Example:**
```json
{
  "report_name": "Q1_2024_gap_report",
  "compare_sources": true,
  "include_recommendations": true,
  "priority_tactics": ["execution", "persistence", "credential-access"],
  "session_id": "session_123"
}
```

**Related Tools:** `identify_gaps`, `auto_analyze_coverage`, `auto_compare_sources`

**Notes:** Executive-level reporting tool. Stores complete report in dynamic tables. Use for comprehensive gap analysis.

---

#### auto_compare_sources
**Description:** Autonomously compare detection coverage across different sources (Sigma, Splunk ESCU, Elastic, KQL) with detailed reasoning and analysis.

**Input Parameters:**
- `techniques_to_compare` (array, optional) - Specific MITRE technique IDs to compare (e.g., ["T1059.001", "T1003.001"]). If not provided, uses high-priority techniques.
- `focus_tactic` (enum, optional) - Focus comparison on a specific MITRE ATT&CK tactic
- `include_quality_analysis` (boolean, optional) - Include analysis of detection quality indicators (default: true)
- `session_id` (string, optional) - Optional session ID to group related comparisons

**Output:** Comprehensive source comparison with coverage differences, quality analysis, and recommendations

**Example:**
```json
{
  "techniques_to_compare": ["T1059.001", "T1003.001"],
  "focus_tactic": "execution",
  "include_quality_analysis": true,
  "session_id": "session_123"
}
```

**Related Tools:** `compare_sources`, `auto_gap_report`, `analyze_coverage`

**Notes:** Automated comprehensive comparison. Stores results and logs decision reasoning. Use to understand source strengths/weaknesses.

---

### COMPARISON TOOLS (4 tools)

#### compare_sources
**Description:** Compare detection coverage between sources (Sigma vs Splunk vs Elastic vs KQL) for a topic. Returns a clean breakdown with counts and names per source.

**Input Parameters:**
- `topic` (string, required) - Topic to compare (e.g., "powershell", "credential dumping", "ransomware")
- `limit_per_source` (number, optional) - Max detections to show per source (default: 50)

**Output:** Comparison object with detection counts and names per source

**Example:**
```json
{
  "topic": "powershell",
  "limit_per_source": 50
}
```

**Related Tools:** `count_by_source`, `smart_compare`, `auto_compare_sources`

**Notes:** Quick source comparison. Use for topic-based source analysis.

---

#### count_by_source
**Description:** Get quick counts of detections by source for a topic. Returns just the numbers, no detection details.

**Input Parameters:**
- `topic` (string, required) - Topic to count (e.g., "powershell", "lateral movement")

**Output:** Count object with detection counts per source

**Example:**
```json
{
  "topic": "powershell"
}
```

**Related Tools:** `compare_sources`, `smart_compare`, `get_stats`

**Notes:** Lightweight counting tool. Use for quick source comparisons without full details.

---

#### get_detection_list
**Description:** Get a lightweight list of detection names and IDs matching a search query. Returns ONLY name, id, source, mitre_ids - no queries or raw yaml. Use this when you need a simple list.

**Input Parameters:**
- `query` (string, required) - Search query (e.g., "powershell", "credential", "T1059")
- `source_type` (enum, optional) - Filter by source type: "sigma", "splunk_escu", "elastic", "kql"
- `limit` (number, optional) - Max results (default: 100)

**Output:** Array of lightweight detection objects (name, id, source, mitre_ids only)

**Example:**
```json
{
  "query": "powershell",
  "source_type": "splunk_escu",
  "limit": 50
}
```

**Related Tools:** `search`, `list_by_name_pattern`, `list_all`

**Notes:** Lightweight alternative to `search`. Use when you only need basic detection info.

---

#### smart_compare
**Description:** Compare detections across sources, tactics, or techniques for a given topic. Returns breakdown by source, tactic, and severity.

**Input Parameters:**
- `topic` (string, required) - Topic to compare (e.g., "powershell", "credential dumping", "T1059", "ransomware")

**Output:** Smart comparison object with breakdowns by source, tactic, and severity

**Example:**
```json
{
  "topic": "powershell"
}
```

**Related Tools:** `compare_sources`, `count_by_source`, `analyze_coverage`

**Notes:** Multi-dimensional comparison. Use for comprehensive topic analysis.

---

## Tool Combinations

### Common Workflows

#### Finding PowerShell Detection Gaps
1. `identify_gaps(threat_profile="ransomware")` - Find gaps
2. `suggest_detections(technique_id="T1059.001")` - Get detection ideas for PowerShell technique
3. `get_query_patterns(technique_id="T1059.001")` - Learn query patterns
4. `find_similar_detections(description="PowerShell encoded commands")` - Find reference implementations
5. `suggest_detection_template(technique_id="T1059.001", description="...")` - Generate template
6. `log_decision(...)` - Record why this detection was prioritized

#### Comprehensive Coverage Analysis
1. `get_stats()` - Get overview
2. `analyze_coverage(source_type="splunk_escu")` - Detailed coverage
3. `auto_analyze_coverage(threat_profiles=["ransomware", "apt"])` - Automated analysis with storage
4. `query_table(table_name="gap_analyses", where={...})` - Retrieve stored gaps
5. `get_relevant_decisions(context_query="ransomware gaps")` - Find past decisions

#### Source Comparison Workflow
1. `count_by_source(topic="powershell")` - Quick counts
2. `compare_sources(topic="powershell")` - Detailed comparison
3. `auto_compare_sources(focus_tactic="execution")` - Comprehensive automated comparison
4. `log_decision(...)` - Record source selection reasoning

#### Knowledge Graph Building
1. `create_entity(name="APT29", entity_type="threat_actor")` - Create threat actor
2. `create_entity(name="T1059.001", entity_type="technique")` - Create technique
3. `create_relation(from_entity="APT29", to_entity="T1059.001", relation_type="uses", reasoning="...")` - Link them
4. `add_observation(entity_name="APT29", observation="...")` - Add facts
5. `search_knowledge(query="APT29 PowerShell")` - Query knowledge
6. `get_relevant_decisions(context_query="APT29")` - Find related decisions

#### Detection Engineering Workflow
1. `get_query_patterns(technique_id="T1059.001")` - Learn patterns
2. `get_field_reference(data_model="Endpoint.Processes")` - Understand fields
3. `get_macro_reference(filter="security_content")` - Learn macros
4. `find_similar_detections(description="...")` - Find examples
5. `suggest_detection_template(...)` - Generate template
6. `generate_rba_structure(...)` - Generate RBA
7. `learn_from_feedback(...)` - Store improvements

---

## MCP Resources

The Security Detections MCP provides read-only resources for quick access to common data:

### detection://stats
**Description:** Overall detection statistics including counts by source, severity, MITRE tactic, detection type, and story categories.

**Usage:** Access via MCP resource fetch. Returns JSON with:
- Total detection counts
- Counts by source (sigma, splunk_escu, elastic, kql)
- Counts by severity
- Counts by MITRE tactic
- Counts by detection type
- Story counts and categories

---

### detection://coverage-summary
**Description:** Lightweight coverage summary with tactic percentages. Updated automatically.

**Usage:** Access via MCP resource fetch. Returns JSON with coverage percentages per MITRE tactic.

---

### detection://gaps/ransomware
**Description:** Pre-computed ransomware detection gaps with prioritized recommendations.

**Usage:** Access via MCP resource fetch. Returns JSON with gap analysis for ransomware threat profile.

---

### detection://gaps/apt
**Description:** Pre-computed APT detection gaps with prioritized recommendations.

**Usage:** Access via MCP resource fetch. Returns JSON with gap analysis for APT threat profile.

---

### detection://top-techniques
**Description:** Top covered MITRE techniques across all detections.

**Usage:** Access via MCP resource fetch. Returns JSON with most-covered techniques.

---

## Quick Reference

| Tool Name | Category | Purpose |
|-----------|----------|---------|
| `search` | Detection Search | Full-text search across all detections |
| `get_by_id` | Detection Search | Get detection by ID |
| `list_all` | Detection Search | List all detections |
| `list_by_source` | Detection Search | Filter by source type |
| `list_by_mitre` | Detection Search | Filter by MITRE technique |
| `list_by_severity` | Detection Search | Filter by severity |
| `get_raw_yaml` | Detection Search | Get original YAML |
| `get_stats` | Detection Search | Get statistics |
| `search_stories` | Story Tools | Search analytic stories |
| `get_story` | Story Tools | Get story details |
| `list_stories` | Story Tools | List all stories |
| `list_stories_by_category` | Story Tools | Filter stories by category |
| `list_by_mitre_tactic` | Classification Filters | Filter by MITRE tactic |
| `list_by_cve` | Classification Filters | Filter by CVE |
| `list_by_process_name` | Classification Filters | Filter by process name |
| `list_by_data_source` | Classification Filters | Filter by data source |
| `list_by_logsource` | Classification Filters | Filter by Sigma logsource |
| `list_by_detection_type` | Classification Filters | Filter by detection type |
| `list_by_analytic_story` | Classification Filters | Filter by analytic story |
| `list_by_kql_category` | Classification Filters | Filter KQL by category |
| `list_by_kql_tag` | Classification Filters | Filter KQL by tag |
| `list_by_kql_datasource` | Classification Filters | Filter KQL by data source |
| `list_by_name_pattern` | Classification Filters | Filter by name pattern |
| `analyze_coverage` | Coverage & Analysis | Comprehensive coverage analysis |
| `identify_gaps` | Coverage & Analysis | Identify detection gaps |
| `suggest_detections` | Coverage & Analysis | Get detection suggestions |
| `get_technique_ids` | Coverage & Analysis | Get technique IDs (lightweight) |
| `get_coverage_summary` | Coverage & Analysis | Quick coverage summary |
| `get_top_gaps` | Coverage & Analysis | Top 5 gaps (quick) |
| `get_technique_count` | Coverage & Analysis | Technique detection count |
| `get_query_patterns` | Engineering Intelligence | Get query patterns for technique |
| `get_field_reference` | Engineering Intelligence | Get data model fields |
| `get_macro_reference` | Engineering Intelligence | Get macro patterns |
| `find_similar_detections` | Engineering Intelligence | Find similar detections |
| `suggest_detection_template` | Engineering Intelligence | Generate detection template |
| `generate_rba_structure` | Engineering Intelligence | Generate RBA config |
| `extract_patterns` | Engineering Intelligence | Extract patterns from detections |
| `learn_from_feedback` | Engineering Intelligence | Store user feedback |
| `create_entity` | Knowledge Graph | Create knowledge entity |
| `create_relation` | Knowledge Graph | Create entity relationship |
| `add_observation` | Knowledge Graph | Add entity observation |
| `delete_entity` | Knowledge Graph | Delete entity |
| `delete_observation` | Knowledge Graph | Delete observation |
| `search_knowledge` | Knowledge Graph | Search knowledge graph |
| `read_graph` | Knowledge Graph | Read knowledge graph |
| `open_entity` | Knowledge Graph | Get entity details |
| `log_decision` | Knowledge Graph | Record decision |
| `add_learning` | Knowledge Graph | Store learning |
| `get_relevant_decisions` | Knowledge Graph | Find past decisions |
| `get_learnings` | Knowledge Graph | Find past learnings |
| `create_table` | Dynamic Tables | Create custom table |
| `insert_row` | Dynamic Tables | Insert table row |
| `query_table` | Dynamic Tables | Query table data |
| `list_tables` | Dynamic Tables | List all tables |
| `drop_table` | Dynamic Tables | Delete table |
| `describe_table` | Dynamic Tables | Get table schema |
| `save_query` | Cache & Templates | Save query result |
| `get_saved_query` | Cache & Templates | Retrieve saved query |
| `list_saved_queries` | Cache & Templates | List saved queries |
| `save_template` | Cache & Templates | Save query template |
| `run_template` | Cache & Templates | Execute template |
| `list_templates` | Cache & Templates | List templates |
| `get_template` | Cache & Templates | Get template details |
| `delete_template` | Cache & Templates | Delete template |
| `auto_analyze_coverage` | Autonomous Analysis | Automated coverage analysis |
| `auto_gap_report` | Autonomous Analysis | Generate gap report |
| `auto_compare_sources` | Autonomous Analysis | Compare sources automatically |
| `compare_sources` | Comparison Tools | Compare sources for topic |
| `count_by_source` | Comparison Tools | Count detections by source |
| `get_detection_list` | Comparison Tools | Get lightweight detection list |
| `smart_compare` | Comparison Tools | Multi-dimensional comparison |

---

## Notes

- **Tool Count:** This reference documents 69 tools across 10 categories
- **Source Types:** Most tools support filtering by source: "sigma", "splunk_escu", "elastic", "kql"
- **Pagination:** List tools support `limit` and `offset` for pagination
- **Lightweight Tools:** Use `get_coverage_summary`, `get_top_gaps`, `get_technique_count`, `get_detection_list` for quick checks
- **Comprehensive Tools:** Use `analyze_coverage`, `auto_analyze_coverage`, `auto_gap_report` for detailed analysis
- **Knowledge Graph:** Build tribal knowledge with `create_entity`, `create_relation`, `log_decision`, `add_learning`
- **Dynamic Tables:** Store analysis results in custom tables for persistence across sessions
- **Templates:** Save reusable query patterns with `save_template` and execute with `run_template`

---

*Last Updated: January 2025*
