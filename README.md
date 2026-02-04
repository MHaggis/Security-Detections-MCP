# Security Detections MCP

An MCP (Model Context Protocol) server that lets LLMs query a unified database of **Sigma**, **Splunk ESCU**, **Elastic**, and **KQL** security detection rules.

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=security-detections&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsInNlY3VyaXR5LWRldGVjdGlvbnMtbWNwIl0sImVudiI6eyJTSUdNQV9QQVRIUyI6Ii9wYXRoL3RvL3NpZ21hL3J1bGVzLC9wYXRoL3RvL3NpZ21hL3J1bGVzLXRocmVhdC1odW50aW5nIiwiU1BMVU5LX1BBVEhTIjoiL3BhdGgvdG8vc2VjdXJpdHlfY29udGVudC9kZXRlY3Rpb25zIiwiU1RPUllfUEFUSFMiOiIvcGF0aC90by9zZWN1cml0eV9jb250ZW50L3N0b3JpZXMiLCJFTEFTVElDX1BBVEhTIjoiL3BhdGgvdG8vZGV0ZWN0aW9uLXJ1bGVzL3J1bGVzIiwiS1FMX1BBVEhTIjoiL3BhdGgvdG8va3FsLXJ1bGVzIn19)

## 🚀 Version 2.1 Features

**Security Detections MCP v2.1** introduces powerful new capabilities for detection engineering intelligence, analytical memory, autonomous analysis, and advanced MCP protocol features:

### What's New in v2.1
- **Elicitation Support** - Server can request user confirmation for destructive operations (when client supports it)
- **Sampling Integration** - LLM-enhanced analysis via MCP sampling (when client supports it)
- **Resource Subscriptions** - Subscribe to resource changes for live updates
- **Enhanced Error Handling** - Safe JSON parsing and comprehensive error wrapping
- **Dynamic Pattern Extraction** - Improved field/function extraction without hardcoded limitations
- **71+ Tools** - Extended tool suite with 2 new sampling-related tools

### Detection Engineering Intelligence (8 Tools)
- **Pattern Learning** - Automatically extracts and learns patterns from 4 detection formats (SPL, Sigma, KQL, Elastic)
- **Template Generation** - Creates reusable detection templates from learned patterns
- **Field & Macro References** - Tracks commonly used fields, macros, and functions across detections
- **Feedback Learning** - Learns from user corrections and improvements to enhance future suggestions

### Knowledge Graph / Tribal Knowledge (12 Tools)
- **Analytical Memory** - Persistent knowledge graph that remembers WHY decisions were made, not just WHAT was detected
- **Entity Management** - Create and relate entities (threats, techniques, detections, data sources)
- **Decision Logging** - Record analytical reasoning and decision-making context for future reference
- **Learning Capture** - Store insights, patterns, and lessons learned that help future agents understand context

### Dynamic Tables (6 Tools)
- **Custom Analysis Storage** - Create tables on-the-fly for storing analysis results, gap assessments, or custom data
- **Flexible Schema** - Define your own table structure for any analysis workflow
- **Query Interface** - Query stored analysis data with SQL-like operations
- **Persistent Storage** - Tables persist across sessions for long-term analysis tracking

### Comprehensive Pattern Extraction
- **Multi-Format Support** - Extracts patterns from Sigma, Splunk SPL, KQL, and Elastic queries
- **10,235+ Indexed Patterns** - Comprehensive pattern library covering 528+ MITRE techniques
- **Cross-Format Insights** - Learn how different platforms detect the same techniques

### Expanded Tool Suite
- **71+ Total Tools** (vs ~40 in v1.0)
- **Engineering Tools** (8) - Pattern learning, template generation, field analysis
- **Knowledge Tools** (12) - Knowledge graph, entity relations, decision logging
- **Dynamic Tools** (6) - Custom table creation and querying
- **Autonomous Tools** (5) - Self-directed analysis, LLM-enhanced analysis, sampling status
- **Meta/Template Tools** (5) - Query templates and workflow shortcuts
- **Cache Tools** (4) - Index management, saved queries

## 🆕 MCP Prompts - Expert Detection Workflows

This server includes **11 pre-built MCP Prompts** that provide structured, expert-level workflows for common security detection tasks. Instead of figuring out which tools to use and in what order, just ask for a prompt by name and get a comprehensive, professional analysis.

### How to Use Prompts in Cursor

Simply ask Claude to use a prompt by name:

```
You: "Use the ransomware-readiness-assessment prompt"
You: "Run apt-threat-emulation for APT29"  
You: "Execute the executive-security-briefing prompt for our CISO"
You: "Use detection-engineering-sprint with capacity 5 and focus on ransomware"
```

### Available Prompts

| Prompt | Description | Arguments |
|--------|-------------|-----------|
| `ransomware-readiness-assessment` | Comprehensive kill-chain analysis with risk scoring and remediation roadmap | `priority_focus`: prevention/detection/response/all |
| `apt-threat-emulation` | Assess coverage against specific threat actors (APT29, Lazarus, Volt Typhoon, etc.) | `threat_actor` (required), `include_test_plan` |
| `purple-team-exercise` | Generate complete test plans with procedures and expected detections | `scope` (tactic or technique), `environment` |
| `soc-investigation-assist` | Investigation helper with triage guidance, hunting queries, and escalation criteria | `indicator` (required), `context` |
| `detection-engineering-sprint` | Prioritized detection backlog with user stories and acceptance criteria | `sprint_capacity`, `threat_focus` |
| `executive-security-briefing` | C-level report with business risk language and investment recommendations | `audience`: board/ciso/cto, `include_benchmarks` |
| `cve-response-assessment` | Rapid assessment for emerging CVEs and threats | `cve_or_threat` (required) |
| `data-source-gap-analysis` | Analyze telemetry requirements for improved detection coverage | `target_coverage` |
| `detection-quality-review` | Deep-dive quality analysis of detections for a specific technique | `technique_id` (required) |
| `threat-landscape-sync` | Align detection priorities with current threat landscape | `industry` |
| `detection-coverage-diff` | Compare coverage against threat actors or baseline | `compare_against` (required) |

### Example: Ransomware Assessment

```
You: "Use the ransomware-readiness-assessment prompt"

Claude will automatically:
1. Get baseline stats with get_stats
2. Analyze ransomware-specific gaps with identify_gaps
3. Review coverage by tactic with analyze_coverage  
4. Map gaps to the ransomware kill chain
5. Generate prioritized remediation roadmap
6. Output a professional report with risk scores
```

### Example: APT Threat Assessment

```
You: "Run apt-threat-emulation for Volt Typhoon"

Claude will:
1. Research Volt Typhoon using MITRE ATT&CK data
2. Get all 81 techniques attributed to the group
3. Check your detection coverage for each technique
4. Calculate coverage percentage and identify blind spots
5. Generate a purple team test plan (optional)
6. Provide prioritized detection recommendations
```

## Features

- **🆕 MCP Prompts** - 11 pre-built expert workflows for ransomware assessment, APT emulation, purple team exercises, executive briefings, and more
- **🆕 MCP Resources** - Readable context for LLMs (stats, coverage summary, gaps) without tool calls
- **🆕 Argument Completions** - Autocomplete for technique IDs, CVEs, process names as you type
- **🆕 Server Instructions** - Built-in usage guide with examples for better LLM understanding
- **🆕 Structured Errors** - Helpful error messages with suggestions and similar items
- **🆕 Interactive Tools** - Gap prioritization and sprint planning with form-based input (Cursor 0.42+)
- **Unified Search** - Query Sigma, Splunk ESCU, Elastic, and KQL detections from a single interface
- **Full-Text Search** - SQLite FTS5 powered search across names, descriptions, queries, MITRE tactics, CVEs, process names, and more
- **MITRE ATT&CK Mapping** - Filter detections by technique ID or tactic
- **CVE Coverage** - Find detections for specific CVE vulnerabilities
- **Process Name Search** - Find detections that reference specific processes (e.g., powershell.exe, w3wp.exe)
- **Analytic Stories** - Query by Splunk analytic story (optional - enhances context)
- **KQL Categories** - Filter KQL queries by category (Defender For Endpoint, Azure AD, Threat Hunting, etc.)
- **Auto-Indexing** - Automatically indexes detections on startup from configured paths
- **Multi-Format Support** - YAML (Sigma, Splunk), TOML (Elastic), Markdown (KQL)
- **Logsource Filtering** - Filter Sigma rules by category, product, or service
- **Severity Filtering** - Filter by criticality level

## Quick Start

### Option 1: npx (Recommended)

No installation required - just configure and run:

```bash
npx -y security-detections-mcp
```

### Option 2: Clone and Build

```bash
git clone https://github.com/MHaggis/Security-Detections-MCP.git
cd Security-Detections-MCP
npm install
npm run build
```

## Configuration

### Cursor IDE

Add to your MCP config (`~/.cursor/mcp.json` or `.cursor/mcp.json` in your project):

```json
{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS": "/path/to/sigma/rules,/path/to/sigma/rules-threat-hunting",
        "SPLUNK_PATHS": "/path/to/security_content/detections",
        "ELASTIC_PATHS": "/path/to/detection-rules/rules",
        "STORY_PATHS": "/path/to/security_content/stories",
        "KQL_PATHS": "/path/to/Hunting-Queries-Detection-Rules"
      }
    }
  }
}
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS": "/Users/you/sigma/rules,/Users/you/sigma/rules-threat-hunting",
        "SPLUNK_PATHS": "/Users/you/security_content/detections",
        "ELASTIC_PATHS": "/Users/you/detection-rules/rules",
        "STORY_PATHS": "/Users/you/security_content/stories",
        "KQL_PATHS": "/Users/you/Hunting-Queries-Detection-Rules"
      }
    }
  }
}
```
### Visual Studio Code

Add to `~/.vscode/mcp.json`:

```json
{
  "servers":  {
    "security-detections": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS":  "/Users/you/sigma/rules,/Users/you/sigma/rules-threat-hunting",
        "SPLUNK_PATHS": "/Users/you/security_content/detections",
        "ELASTIC_PATHS": "/Users/you/detection-rules/rules",
        "KQL_PATHS": "/Users/you/kql-bertjanp,/Users/you/kql-jkerai1",
        "STORY_PATHS": "/Users/you/security_content/stories"
      }
    }
  }
```

### WSL & Visual Studio Code

Add to `~/.vscode/mcp.json`:

```json
{
  "servers":  {
    "security-detections": {
      "type": "stdio",
      "command": "wsl",
      "args": ["npx", "-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS":  "/Users/you/sigma/rules,/Users/you/sigma/rules-threat-hunting",
        "SPLUNK_PATHS": "/Users/you/security_content/detections",
        "ELASTIC_PATHS": "/Users/you/detection-rules/rules",
        "KQL_PATHS": "/Users/you/kql-bertjanp,/Users/you/kql-jkerai1",
        "STORY_PATHS": "/Users/you/security_content/stories"
      }
    }
  }
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SIGMA_PATHS` | Comma-separated paths to Sigma rule directories | At least one source required |
| `SPLUNK_PATHS` | Comma-separated paths to Splunk ESCU detection directories | At least one source required |
| `ELASTIC_PATHS` | Comma-separated paths to Elastic detection rule directories | At least one source required |
| `KQL_PATHS` | Comma-separated paths to KQL hunting query directories | At least one source required |
| `STORY_PATHS` | Comma-separated paths to Splunk analytic story directories | No (enhances context) |

## Getting Detection Content

### Quick Start: Download All Rules (Copy & Paste)

Create a `detections` folder and download all sources with sparse checkout (only downloads the rules, not full repos):

```bash
# Create detections directory
mkdir -p detections && cd detections

# Download Sigma rules (~3,000+ rules)
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git
cd sigma && git sparse-checkout set rules rules-threat-hunting && cd ..

# Download Splunk ESCU detections + stories (~2,000+ detections, ~330 stories)
git clone --depth 1 --filter=blob:none --sparse https://github.com/splunk/security_content.git
cd security_content && git sparse-checkout set detections stories && cd ..

# Download Elastic detection rules (~1,500+ rules)
git clone --depth 1 --filter=blob:none --sparse https://github.com/elastic/detection-rules.git
cd detection-rules && git sparse-checkout set rules && cd ..

# Download KQL hunting queries (~400+ queries from 2 repos)
git clone --depth 1 https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules.git kql-bertjanp
git clone --depth 1 https://github.com/jkerai1/KQL-Queries.git kql-jkerai1

echo "Done! Configure your MCP with these paths:"
echo "  SIGMA_PATHS: $(pwd)/sigma/rules,$(pwd)/sigma/rules-threat-hunting"
echo "  SPLUNK_PATHS: $(pwd)/security_content/detections"
echo "  ELASTIC_PATHS: $(pwd)/detection-rules/rules"
echo "  KQL_PATHS: $(pwd)/kql-bertjanp,$(pwd)/kql-jkerai1"
echo "  STORY_PATHS: $(pwd)/security_content/stories"
```

### Alternative: Full Clone

If you prefer full git history:

```bash
# Sigma Rules
git clone https://github.com/SigmaHQ/sigma.git
# Use rules/ and rules-threat-hunting/ directories

# Splunk ESCU
git clone https://github.com/splunk/security_content.git
# Use detections/ and stories/ directories

# Elastic Detection Rules
git clone https://github.com/elastic/detection-rules.git
# Use rules/ directory

# KQL Hunting Queries (multiple sources supported)
git clone https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules.git
git clone https://github.com/jkerai1/KQL-Queries.git
# Use entire repos, combine paths with comma
```

## 🆕 MCP Resources - Readable Context

MCP Resources let LLMs read context directly without tool calls. Perfect for understanding the current state before making decisions.

### Available Resources

| Resource URI | Description |
|-------------|-------------|
| `detection://stats` | Current inventory statistics |
| `detection://coverage-summary` | Tactic-by-tactic coverage percentages |
| `detection://gaps/ransomware` | Current ransomware detection gaps |
| `detection://gaps/apt` | Current APT detection gaps |
| `detection://top-techniques` | Top 20 techniques with most coverage |

Resources are automatically available in Cursor's context when needed.

## 🆕 Argument Completions

The server provides **autocomplete suggestions** as you type argument values:

| Argument | Completions From |
|----------|-----------------|
| `technique_id` | Your indexed MITRE technique IDs (T1059.001, etc.) |
| `cve_id` | Your indexed CVE IDs (CVE-2024-27198, etc.) |
| `process_name` | Process names in your detections (powershell.exe, etc.) |
| `tactic` | All 14 MITRE tactics |
| `severity` | informational, low, medium, high, critical |
| `source_type` | sigma, splunk_escu, elastic, kql |
| `threat_profile` | ransomware, apt, initial-access, persistence, etc. |

This prevents typos and helps discover what values are available in your detection corpus.

## 🆕 Structured Errors & Suggestions

When errors occur or no results are found, the server returns **helpful JSON responses** instead of plain strings:

```json
// Missing required argument
{
  "error": true,
  "code": "MISSING_REQUIRED_ARG",
  "message": "technique_id is required",
  "examples": ["T1059.001", "T1547.001", "T1003.001"],
  "hint": "Use format T####.### (e.g., T1059.001 for PowerShell)"
}

// No results found
{
  "results": [],
  "technique_id": "T1234.999",
  "suggestions": {
    "message": "No detections found for this technique",
    "similar_techniques": ["T1234.001", "T1234.002"],
    "try_search": "search(\"T1234\") for broader results",
    "tip": "Parent techniques (T1234) may catch sub-techniques"
  }
}
```

This helps LLMs self-correct and suggest alternatives without getting stuck.

## 🆕 Interactive Tools (Cursor 0.42+)

These tools use **MCP Elicitation** to present forms for interactive configuration:

| Tool | Description |
|------|-------------|
| `prioritize_gaps` | Analyze gaps and get prioritized recommendations |
| `plan_detection_sprint` | Interactive sprint configuration with capacity/focus/data source options |

Example:
```
You: "Help me prioritize which ransomware gaps to fix first"
Tool: prioritize_gaps(threat_profile="ransomware")
→ Returns P0/P1/P2 prioritized gaps with selection guidance
```

## MCP Tools

### Core Detection Tools

| Tool | Description |
|------|-------------|
| `search(query, limit)` | Full-text search across all detection fields (names, descriptions, queries, CVEs, process names, etc.) |
| `get_by_id(id)` | Get a single detection by its ID |
| `list_all(limit, offset)` | Paginated list of all detections |
| `list_by_source(source_type)` | Filter by `sigma`, `splunk_escu`, `elastic`, or `kql` |
| `get_raw_yaml(id)` | Get the original YAML/TOML/Markdown content |
| `get_stats()` | Get index statistics |
| `rebuild_index()` | Force re-index from configured paths |

### MITRE ATT&CK Filters

| Tool | Description |
|------|-------------|
| `list_by_mitre(technique_id)` | Filter by MITRE ATT&CK technique ID (e.g., T1059.001) |
| `list_by_mitre_tactic(tactic)` | Filter by tactic (execution, persistence, credential-access, etc.) |

### Vulnerability & Process Filters

| Tool | Description |
|------|-------------|
| `list_by_cve(cve_id)` | Find detections for a specific CVE (e.g., CVE-2024-27198) |
| `list_by_process_name(process_name)` | Find detections referencing a process (e.g., powershell.exe, w3wp.exe) |
| `list_by_data_source(data_source)` | Filter by data source (e.g., Sysmon, Windows Security) |

### Classification Filters

| Tool | Description |
|------|-------------|
| `list_by_logsource(category, product, service)` | Filter Sigma rules by logsource |
| `list_by_severity(level)` | Filter by severity (informational/low/medium/high/critical) |
| `list_by_detection_type(type)` | Filter by type (TTP, Anomaly, Hunting, Correlation) |
| `list_by_analytic_story(story)` | Filter by Splunk analytic story |

### KQL-Specific Filters

| Tool | Description |
|------|-------------|
| `list_by_kql_category(category)` | Filter KQL by category (e.g., "Defender For Endpoint", "Azure Active Directory", "Threat Hunting") |
| `list_by_kql_tag(tag)` | Filter KQL by tag (e.g., "ransomware", "hunting", "ti-feed", "dfir") |
| `list_by_kql_datasource(data_source)` | Filter KQL by Microsoft data source (e.g., "DeviceProcessEvents", "SigninLogs") |

### Story Tools (Optional)

| Tool | Description |
|------|-------------|
| `search_stories(query, limit)` | Search analytic stories by narrative and description |
| `get_story(name)` | Get detailed story information |
| `list_stories(limit, offset)` | List all analytic stories |
| `list_stories_by_category(category)` | Filter stories by category (Malware, Adversary Tactics, etc.) |

### Efficient Analysis Tools (Token-Optimized)

These tools do heavy processing server-side and return minimal, actionable data:

| Tool | Description | Output Size |
|------|-------------|-------------|
| `analyze_coverage(source_type?)` | Get coverage stats by tactic, top techniques, weak spots | ~2KB |
| `identify_gaps(threat_profile, source_type?)` | Find gaps for ransomware, apt, persistence, etc. | ~500B |
| `suggest_detections(technique_id, source_type?)` | Get detection ideas for a technique | ~2KB |
| `get_technique_ids(source_type?, tactic?, severity?)` | Get only technique IDs (no full objects) | ~200B |
| `get_coverage_summary(source_type?)` | Just tactic percentages (~200 bytes) | ~200B |
| `get_top_gaps(threat_profile)` | Just top 5 gap technique IDs (~300 bytes) | ~300B |
| `get_technique_count(technique_id)` | Just the count for one technique (~50 bytes) | ~50B |

**Why use these?** Traditional tools return full detection objects (~50KB+ per query). These return only what you need, saving 25x+ tokens.

### Interactive Tools

| Tool | Description |
|------|-------------|
| `prioritize_gaps(threat_profile, source_type?)` | Analyze gaps with P0/P1/P2 prioritization and selection guidance |
| `plan_detection_sprint()` | Generate sprint configuration options with recommended backlog |

### Engineering Tools (8)

Detection engineering intelligence tools for pattern learning and template generation:

| Tool | Description |
|------|-------------|
| `extract_patterns(technique_id, source_type?)` | Extract detection patterns for a technique from all sources |
| `learn_pattern(technique_id, pattern, format)` | Teach the system a new pattern for a technique |
| `get_patterns(technique_id, format?)` | Retrieve learned patterns for a technique |
| `generate_template(technique_id, format, data_source)` | Generate detection template from learned patterns |
| `analyze_fields(technique_id)` | Analyze commonly used fields/macros for a technique |
| `get_field_references(field_name)` | Find all detections using a specific field or macro |
| `suggest_improvements(detection_id)` | Get AI suggestions for improving a detection based on patterns |
| `compare_patterns(technique_id)` | Compare patterns across different detection formats |

### Knowledge Tools (12)

Knowledge graph and tribal knowledge tools for analytical memory:

| Tool | Description |
|------|-------------|
| `create_entity(name, type, properties)` | Create an entity in the knowledge graph (threat, technique, detection, etc.) |
| `create_relation(source_entity, relation_type, target_entity, reasoning)` | Create a relationship between entities with reasoning |
| `search_knowledge(query, entity_type?)` | Search the knowledge graph for entities and relations |
| `get_entity(name)` | Get full details of an entity including all relations |
| `log_decision(context, decision, reasoning, tags)` | Log an analytical decision with full context for future reference |
| `get_relevant_decisions(context, tags?)` | Retrieve relevant past decisions for current context |
| `add_learning(insight, category, tags)` | Store a learning or insight for future agents |
| `get_learnings(category?, tags?)` | Retrieve stored learnings by category or tags |
| `link_detection_to_entity(detection_id, entity_name, relation_type)` | Link a detection to a knowledge graph entity |
| `get_entity_detections(entity_name)` | Get all detections related to an entity |
| `update_entity(name, properties)` | Update entity properties in the knowledge graph |
| `delete_entity(name)` | Remove an entity from the knowledge graph |

### Dynamic Tools (6)

Custom table creation and querying for flexible analysis storage:

| Tool | Description |
|------|-------------|
| `create_table(table_name, schema)` | Create a custom table with defined schema for analysis storage |
| `insert_row(table_name, row_data)` | Insert a row of data into a custom table |
| `query_table(table_name, query, limit?)` | Query a custom table with SQL-like syntax |
| `list_tables()` | List all custom tables you've created |
| `get_table_schema(table_name)` | Get the schema of a custom table |
| `delete_table(table_name)` | Delete a custom table |

### Autonomous Tools (5)

Self-directed analysis tools that work independently:

| Tool | Description |
|------|-------------|
| `auto_analyze_coverage(threat_profiles?, store_results?)` | Comprehensive coverage analysis across threat profiles |
| `auto_gap_report(report_name?, compare_sources?)` | Generate executive-level gap reports with prioritized recommendations |
| `auto_compare_sources(techniques?, focus_tactic?)` | Compare detection coverage across all sources with reasoning |
| `llm_enhanced_analysis(analysis_type, threat_profile?)` | LLM-enhanced analysis via MCP sampling (when supported) |
| `check_sampling_status()` | Check if MCP sampling is available for LLM-enhanced analysis |

### Meta/Template Tools (5)

Query templates and workflow shortcuts:

| Tool | Description |
|------|-------------|
| `save_template(name, tool_calls, description)` | Save a sequence of tool calls as a reusable template |
| `run_template(template_name, variables?)` | Execute a saved template with optional variable substitution |
| `list_templates()` | List all saved templates |
| `get_template(template_name)` | Get details of a saved template |
| `delete_template(template_name)` | Delete a saved template |

## MCP Prompts - Detailed Reference

MCP Prompts are pre-built, expert-level workflows that guide Claude through complex analysis tasks. They ensure consistent, comprehensive results by defining exactly which tools to use and in what order.

### Why Use Prompts Instead of Ad-Hoc Questions?

| Ad-Hoc Question | With MCP Prompt |
|-----------------|-----------------|
| "Check my ransomware coverage" | "Use ransomware-readiness-assessment" |
| Claude might check 2-3 things | Claude executes 15+ step workflow |
| Inconsistent output format | Professional report with risk scores |
| May miss important aspects | Comprehensive kill-chain analysis |
| Varies each time | Repeatable, auditable results |

### Prompt Categories

#### 🎯 Threat Assessment Prompts

**`ransomware-readiness-assessment`**
- Full ransomware kill-chain analysis
- Risk scoring per attack phase
- Prioritized remediation roadmap
- Executive-ready reporting

```
Use ransomware-readiness-assessment with priority_focus "detection"
```

**`apt-threat-emulation`**
- Coverage analysis against specific threat actors
- Technique-by-technique gap identification  
- Optional purple team test plan generation
- Supports all MITRE ATT&CK groups (APT29, Lazarus, Volt Typhoon, Scattered Spider, etc.)

```
Run apt-threat-emulation for "Scattered Spider" with include_test_plan true
```

**`threat-landscape-sync`**
- Align detections with current threats
- Industry-specific threat prioritization
- Top actor coverage analysis
- Strategic roadmap generation

```
Use threat-landscape-sync for the finance industry
```

#### 🔬 Purple Team & Validation Prompts

**`purple-team-exercise`**
- Complete exercise planning for a tactic or technique
- Test case development with procedures
- Expected detection mapping
- Safety controls and rollback plans

```
Run purple-team-exercise for "persistence" in a "windows" environment
```

**`detection-quality-review`**
- Deep-dive analysis of detection effectiveness
- Bypass and evasion analysis
- Quality scoring and improvement recommendations
- Enhanced detection logic suggestions

```
Use detection-quality-review for T1059.001
```

#### 📊 Planning & Reporting Prompts

**`detection-engineering-sprint`**
- Threat-informed backlog prioritization
- User stories with acceptance criteria
- Effort estimation and capacity planning
- Focus areas: ransomware, apt, insider, cloud, balanced

```
Run detection-engineering-sprint with sprint_capacity 5 and threat_focus "apt"
```

**`executive-security-briefing`**
- Business-risk translation
- Coverage metrics and trends
- Investment recommendations with ROI
- Audience-specific formatting (board, CISO, CTO)

```
Use executive-security-briefing for audience "board" with include_benchmarks true
```

#### 🚨 Incident Response Prompts

**`soc-investigation-assist`**
- Alert triage guidance
- MITRE ATT&CK context
- Related detections and hunting queries
- Escalation decision trees

```
Use soc-investigation-assist for "suspicious PowerShell execution" with context "domain controller, after hours"
```

**`cve-response-assessment`**
- Rapid threat assessment
- Existing coverage check
- Immediate action recommendations
- Hunting query generation

```
Run cve-response-assessment for CVE-2024-27198
```

#### 🔧 Gap Analysis Prompts

**`data-source-gap-analysis`**
- Telemetry requirements analysis
- Data source prioritization by ROI
- Implementation roadmap
- Cost-benefit analysis

```
Use data-source-gap-analysis for target_coverage "credential-access"
```

**`detection-coverage-diff`**
- Compare against threat actors or baselines
- Progress tracking
- Path-to-parity planning
- Effort estimation

```
Run detection-coverage-diff comparing against "APT29"
```

### Best With: MITRE ATT&CK MCP

These prompts work even better when paired with [mitre-attack-mcp](https://github.com/MHaggis/mitre-attack-mcp). The prompts will automatically leverage MITRE ATT&CK tools for:
- Threat actor technique lookups
- Technique details and detection guidance
- Mitigation recommendations

## Claude Code Skills

This repo includes [Claude Code Skills](https://code.claude.com/docs/en/skills) in `.claude/skills/` that teach Claude efficient workflows:

| Skill | Purpose |
|-------|---------|
| `coverage-analysis` | Efficient coverage analysis using the token-optimized tools |

**Why skills?** Instead of figuring out methodology each time (wasting tokens), skills teach Claude once.

You can also install personal skills to `~/.claude/skills/` for cross-project use.

### Example: Efficient Coverage Analysis

```
You: "What's my Elastic coverage against ransomware?"

AI uses skills + efficient tools:
1. analyze_coverage(source_type="elastic")     → Stats by tactic
2. identify_gaps(threat_profile="ransomware")  → Prioritized gaps
3. suggest_detections(technique_id="T1486")    → Fix top gap

Total: ~5KB of data vs ~500KB with traditional tools
```

## Example Workflows

### Using MCP Prompts (Recommended for Complex Tasks)

```
# Comprehensive ransomware assessment
You: "Use the ransomware-readiness-assessment prompt"
→ Full kill-chain analysis with risk scoring and remediation roadmap

# Assess coverage against a specific APT
You: "Run apt-threat-emulation for Volt Typhoon"
→ Technique-by-technique coverage analysis with test plan

# Generate a sprint backlog
You: "Use detection-engineering-sprint with capacity 5 focusing on apt threats"
→ Prioritized user stories with acceptance criteria

# Executive reporting
You: "Run executive-security-briefing for the board"
→ Business-risk language with investment recommendations
```

### Using Tools Directly (Quick Queries)

#### Find PowerShell Detections

```
LLM: "Find me PowerShell detections related to base64 encoding"
Tool: search(query="powershell base64", limit=5)
```

#### Check CVE Coverage

```
LLM: "Do we have detections for CVE-2024-27198?"
Tool: list_by_cve(cve_id="CVE-2024-27198")
```

#### Compare Coverage Across Sources

```
LLM: "What detections do we have for credential dumping?"
Tool: search(query="credential dumping", limit=10)
→ Returns results from Sigma, Splunk, Elastic, AND KQL
```

#### Find Web Server Attack Detections

```
LLM: "What detections cover IIS web server attacks?"
Tool: list_by_process_name(process_name="w3wp.exe")
```

#### Explore a Threat Campaign

```
LLM: "Tell me about ransomware detections"
Tool: search_stories(query="ransomware")
Tool: list_by_analytic_story(story="Ransomware")
```

#### Find KQL Hunting Queries for Defender

```
LLM: "What KQL queries do we have for Defender For Endpoint?"
Tool: list_by_kql_category(category="Defender For Endpoint")
```

#### Search for BloodHound Detections

```
LLM: "Find detections for BloodHound usage"
Tool: search(query="bloodhound", limit=10)
→ Returns KQL hunting queries and other source detections
```

## Unified Schema

All detection sources (Sigma, Splunk, Elastic, KQL) are normalized to a common schema:

### Core Fields

| Field | Description |
|-------|-------------|
| `id` | Unique identifier |
| `name` | Detection name/title |
| `description` | What the detection looks for |
| `query` | Detection logic (Sigma YAML, Splunk SPL, Elastic EQL, or KQL) |
| `source_type` | `sigma`, `splunk_escu`, `elastic`, or `kql` |
| `severity` | Detection severity level |
| `status` | Rule status (stable, test, experimental, production, etc.) |
| `author` | Rule author |
| `file_path` | Original file path |
| `raw_yaml` | Original YAML/TOML/Markdown content |

### Enhanced Fields (for Semantic Search)

| Field | Description |
|-------|-------------|
| `mitre_ids` | Mapped MITRE ATT&CK technique IDs |
| `mitre_tactics` | Extracted MITRE tactics (execution, persistence, etc.) |
| `cves` | CVE identifiers (e.g., CVE-2024-27198) |
| `analytic_stories` | Splunk analytic story names |
| `process_names` | Process names referenced in detection |
| `file_paths` | Interesting file paths referenced |
| `registry_paths` | Registry paths referenced |
| `data_sources` | Required data sources (Sysmon, DeviceProcessEvents, etc.) |
| `detection_type` | TTP, Anomaly, Hunting, or Correlation |
| `asset_type` | Endpoint, Web Server, Cloud, Network |
| `security_domain` | endpoint, network, cloud, access |

### KQL-Specific Fields

| Field | Description |
|-------|-------------|
| `kql_category` | Category derived from folder path (e.g., "Defender For Endpoint") |
| `kql_tags` | Extracted tags (e.g., "ransomware", "hunting", "ti-feed") |
| `kql_keywords` | Security keywords extracted for search |
| `platforms` | Platforms (windows, azure-ad, office-365, etc.) |

## Database

The index is stored at `~/.cache/security-detections-mcp/detections.sqlite`.

- Auto-created on first run
- Auto-indexed when paths are configured
- Use `rebuild_index()` to refresh after updating detection repos

## Supported Detection Formats

### Sigma Rules (YAML)

Based on the [official Sigma specification](https://github.com/SigmaHQ/sigma-specification):
- All required fields: `title`, `logsource`, `detection`
- All optional fields: `id`, `status`, `description`, `author`, `date`, `modified`, `references`, `tags`, `level`, `falsepositives`, etc.
- CVE tags extracted from `tags` field (e.g., `cve.2021-1675`)

### Splunk ESCU (YAML)

From [Splunk Security Content](https://github.com/splunk/security_content):
- Required: `name`, `id`, `search`
- Optional: `description`, `author`, `date`, `status`, `references`, `tags` (including `mitre_attack_id`, `analytic_story`, `cve`)

### Splunk Analytic Stories (YAML - Optional)

From [Splunk Security Content stories](https://github.com/splunk/security_content/tree/develop/stories):
- Provides rich narrative context for threat campaigns
- Enhances semantic search with detailed descriptions
- Links detections to broader threat context

### Elastic Detection Rules (TOML)

From [Elastic Detection Rules](https://github.com/elastic/detection-rules):
- Required: `rule.name`, `rule.rule_id`
- Optional: `rule.description`, `rule.query`, `rule.severity`, `rule.tags`, `rule.threat` (MITRE mappings)
- Supports EQL, KQL, Lucene, and ESQL query languages

### KQL Hunting Queries (Markdown & Raw .kql)

Supports multiple KQL repositories:

**[Bert-JanP/Hunting-Queries-Detection-Rules](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)** (~290 queries)
- Microsoft Defender XDR and Azure Sentinel hunting queries in Markdown format
- Extracts title from markdown heading, KQL from fenced code blocks
- Extracts MITRE technique IDs from tables
- Categories: Defender For Endpoint, Azure AD, Threat Hunting, DFIR, etc.

**[jkerai1/KQL-Queries](https://github.com/jkerai1/KQL-Queries)** (~130 queries)
- Raw `.kql` files for Defender, Entra, Azure, Office 365
- Title derived from filename
- Lightweight queries for kqlsearch.com

## ⚠️ Limitations & Transparency

We believe in being honest about what this tool can and cannot do. Here are the current limitations:

### Pattern Extraction Limitations

The Detection Engineering Intelligence features extract patterns **dynamically** from your detection corpus, but have some inherent limitations:

| Format | Field Extraction | Notes |
|--------|-----------------|-------|
| **Splunk SPL** | ✅ Excellent | Extracts from data models, `by` clauses, `stats` commands, `where` filters |
| **Sigma** | ✅ Excellent | Full YAML parsing of detection logic |
| **KQL** | ⚠️ Good | Dynamic extraction from `project`, `extend`, `where`, `summarize by`, `join on` |
| **Elastic** | ⚠️ Good | Dynamic extraction from `field:value` patterns, EQL `where` clauses |

**What this means:**
- **SPL and Sigma**: Highly accurate pattern extraction from full detection corpus
- **KQL and Elastic**: Uses regex-based dynamic extraction that catches most patterns, but may miss:
  - Unusual field naming conventions
  - Complex nested expressions
  - Custom functions or operators

### Coverage Analysis Limitations

- **MITRE mappings depend on source data** - If a detection doesn't have MITRE tags, we can't map it
- **Gap analysis is relative** - "Gaps" are based on threat profiles, not absolute coverage requirements
- **Cross-platform comparisons** - Different platforms have different capabilities; raw counts don't tell the whole story

### Client Feature Availability

Some v2.1 features depend on **client support**:

| Feature | Requires | Fallback |
|---------|----------|----------|
| **Elicitation** | Client MCP elicitation support | Parameter-based confirmation (`confirm: true`) |
| **Sampling** | Client MCP sampling support | Direct analysis without LLM enhancement |
| **Resource Subscriptions** | Client subscription support | Poll resources manually |

**Note**: As of January 2025, Cursor may not fully support elicitation and sampling. The MCP gracefully falls back to alternative methods when these features aren't available.

### Reporting Issues

Found a limitation or inaccuracy? Please [open an issue](https://github.com/MHaggis/Security-Detections-MCP/issues) with:
1. The detection format (Sigma, Splunk, Elastic, KQL)
2. An example query that wasn't extracted correctly
3. Expected vs actual behavior

We continuously improve the pattern extraction based on community feedback.

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Lint (TypeScript strict mode)
npm run lint

# Run with paths
SIGMA_PATHS="./detections/sigma/rules" \
SPLUNK_PATHS="./detections/splunk/detections" \
ELASTIC_PATHS="./detections/elastic/rules" \
KQL_PATHS="./detections/kql" \
STORY_PATHS="./detections/splunk/stories" \
npm start
```

## Stats (with full content)

When fully indexed with all sources:

| Source | Count |
|--------|-------|
| Sigma Rules | ~3,200+ |
| Splunk ESCU | ~2,000+ |
| Elastic Rules | ~1,500+ |
| KQL Queries | ~420+ |
| Analytic Stories | ~330 |
| **Total Detections** | **~7,200+** |
| **Indexed Patterns** | **10,235+** |
| **Techniques with Patterns** | **528+** |
| **Detection Formats** | **4** (Sigma, Splunk, Elastic, KQL) |
| **Total Tools** | **71+** |
| **MCP Prompts** | **11** |
| **MCP Resources** | **9 static + 5 templates** |

## 🧠 Tribal Knowledge

**Tribal Knowledge** is the analytical memory system that helps future agents understand WHY decisions were made, not just WHAT was detected. It's like having a senior analyst's notebook that persists across sessions.

### What is Tribal Knowledge?

Traditional detection systems store facts: "We have 5 detections for T1059.001." Tribal Knowledge stores reasoning: "We prioritized T1059.001 because it's used in 80% of ransomware attacks, and our current detections miss base64-encoded PowerShell, which is why we added detection X."

### Knowledge Graph Tables

The knowledge graph consists of four interconnected tables:

1. **Entities** - Things you care about (threats, techniques, detections, data sources, campaigns)
2. **Relations** - How entities connect ("APT29 uses T1059.001", "Detection X covers T1059.001")
3. **Decisions** - Analytical reasoning and decision-making context
4. **Learnings** - Insights, patterns, and lessons learned

### How It Helps Future Agents

When you log a decision like:
```json
log_decision(
  context: "Ransomware gap analysis",
  decision: "Prioritize T1486 (Data Encrypted for Impact)",
  reasoning: "This is the final stage of ransomware attacks. Without detection here, we can't prevent data loss.",
  tags: ["ransomware", "priority", "data-protection"]
)
```

Future agents can retrieve this context when analyzing ransomware coverage, understanding not just that T1486 is important, but WHY it was prioritized.

### Example Workflow

```
1. Analyze ransomware gaps → identify_gaps("ransomware")
2. Log decision → log_decision("Prioritized T1486 because...")
3. Create entity → create_entity("Ransomware Campaign 2024", "threat")
4. Link detection → link_detection_to_entity("det_123", "Ransomware Campaign 2024", "detects")
5. Future agent → get_relevant_decisions("ransomware") → understands context
```

## 🔬 Detection Engineering Intelligence

**Detection Engineering Intelligence** learns patterns from your detection corpus and helps you create better detections faster.

### Pattern Learning from 4 Sources

The system automatically extracts patterns from:
- **Sigma rules** - YAML-based detection logic
- **Splunk SPL** - Search Processing Language queries
- **KQL queries** - Microsoft Kusto Query Language
- **Elastic queries** - Elastic Detection Rules (EQL, KQL, Lucene)

### Automatic Template Generation

When you need a detection for T1059.001 (PowerShell), the system:
1. Analyzes all existing T1059.001 detections across formats
2. Extracts common patterns (process names, command-line arguments, base64 encoding)
3. Generates a template with placeholders for your specific environment
4. Suggests improvements based on learned patterns

### Field and Macro References

The system tracks:
- Which fields/macros are commonly used for each technique
- Cross-platform field mappings (e.g., `process_name` in Splunk vs `ProcessName` in KQL)
- Best practices for field usage in different contexts

### Learning from User Feedback

When you improve a detection or correct a pattern:
- The system learns from your changes
- Future template generation incorporates your improvements
- Field suggestions become more accurate over time

### Example Workflow

```
1. Extract patterns → extract_patterns("T1059.001")
2. Review patterns → get_patterns("T1059.001", "splunk")
3. Generate template → generate_template("T1059.001", "splunk", "Sysmon")
4. Customize template → (edit generated detection)
5. System learns → (automatically improves future templates)
```

## 📚 Documentation

For detailed information on v2.1 features:

- **[Architecture](docs/wiki/Architecture.md)** - System architecture and design decisions
- **[Knowledge Graph](docs/wiki/Knowledge-Graph.md)** - Deep dive into tribal knowledge and knowledge graph usage
- **[Engineering Intelligence](docs/wiki/Engineering-Intelligence.md)** - Pattern learning and template generation guide
- **[Tools Reference](docs/wiki/Tools-Reference.md)** - Complete reference for all 71+ tools

## 🔗 Using with MITRE ATT&CK MCP

**This MCP pairs perfectly with [mitre-attack-mcp](https://github.com/MHaggis/mitre-attack-mcp)** for complete threat coverage analysis:

| MCP | Purpose |
|-----|---------|
| **security-detections-mcp** | Query 7,200+ detection rules + 11 expert workflow prompts |
| **mitre-attack-mcp** | ATT&CK framework data, threat groups, Navigator layers |

### With MCP Prompts (Easiest)

The prompts automatically leverage both MCPs for comprehensive analysis:

```
You: "Run apt-threat-emulation for APT29"

The prompt automatically:
1. Uses mitre-attack-mcp to get APT29's profile and techniques
2. Uses security-detections-mcp to check coverage for each technique
3. Calculates coverage percentage and identifies gaps
4. Generates purple team test plan
5. Outputs professional report with recommendations
```

```
You: "Use threat-landscape-sync for the finance industry"

The prompt automatically:
1. Gets top threat actors from mitre-attack-mcp
2. Filters by industry relevance
3. Analyzes your coverage against each actor
4. Prioritizes detection investments
5. Creates strategic roadmap
```

### With Tools Directly (More Control)

```
You: "What's my coverage against APT29?"

LLM workflow (3 calls, ~10KB total):
1. mitre-attack-mcp → get_group_techniques("G0016")     # APT29's TTPs
2. detections-mcp → analyze_coverage(source_type="elastic")  # Your coverage
3. mitre-attack-mcp → find_group_gaps("G0016", your_coverage) # The gaps

Result: Prioritized gap list, not 500KB of raw data
```

### Generate Navigator Layer

```
You: "Generate a Navigator layer for my initial access coverage"

LLM workflow:
1. detections-mcp → get_technique_ids(tactic="initial-access")  # Get covered technique IDs
2. mitre-attack-mcp → generate_coverage_layer(covered_ids, "Initial Access Coverage")

→ Returns ready-to-import Navigator JSON
```

### Install Both Together (Recommended)

```json
{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS": "/path/to/sigma/rules",
        "SPLUNK_PATHS": "/path/to/security_content/detections",
        "ELASTIC_PATHS": "/path/to/detection-rules/rules",
        "KQL_PATHS": "/path/to/kql-hunting-queries"
      }
    },
    "mitre-attack": {
      "command": "npx",
      "args": ["-y", "mitre-attack-mcp"],
      "env": {
        "ATTACK_DOMAIN": "enterprise-attack"
      }
    }
  }
}
```

## License

Apache 2.0
