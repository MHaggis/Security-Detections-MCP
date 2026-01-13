# Security Detections MCP

An MCP (Model Context Protocol) server that lets LLMs query a unified database of **Sigma** and **Splunk ESCU** security detection rules.

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/install-mcp?name=security-detections&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsInNlY3VyaXR5LWRldGVjdGlvbnMtbWNwIl0sImVudiI6eyJTSUdNQV9QQVRIUyI6Ii9wYXRoL3RvL3NpZ21hL3J1bGVzLC9wYXRoL3RvL3NpZ21hL3J1bGVzLXRocmVhdC1odW50aW5nIiwiU1BMVU5LX1BBVEhTIjoiL3BhdGgvdG8vc2VjdXJpdHlfY29udGVudC9kZXRlY3Rpb25zIn19)

## Features

- **Unified Search** - Query both Sigma and Splunk ESCU detections from a single interface
- **Full-Text Search** - SQLite FTS5 powered search across names, descriptions, queries, and tags
- **MITRE ATT&CK Mapping** - Filter detections by technique ID (e.g., T1059.001)
- **Auto-Indexing** - Automatically indexes detections on startup from configured paths
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
        "SPLUNK_PATHS": "/path/to/security_content/detections"
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
        "SPLUNK_PATHS": "/Users/you/security_content/detections"
      }
    }
  }
}
```

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SIGMA_PATHS` | Comma-separated paths to Sigma rule directories | `/path/to/sigma/rules,/path/to/sigma/rules-threat-hunting` |
| `SPLUNK_PATHS` | Comma-separated paths to Splunk ESCU detection directories | `/path/to/security_content/detections` |

## Getting Detection Content

### Sigma Rules

```bash
git clone https://github.com/SigmaHQ/sigma.git
# Use rules/ and rules-threat-hunting/ directories
```

### Splunk ESCU

```bash
git clone https://github.com/splunk/security_content.git
# Use detections/ directory
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `search(query, limit)` | Full-text search across all detection fields |
| `get_by_id(id)` | Get a single detection by its ID |
| `list_all(limit, offset)` | Paginated list of all detections |
| `list_by_source(source_type)` | Filter by `sigma` or `splunk_escu` |
| `list_by_mitre(technique_id)` | Filter by MITRE ATT&CK technique ID |
| `list_by_logsource(category, product, service)` | Filter Sigma rules by logsource |
| `list_by_severity(level)` | Filter by severity (informational/low/medium/high/critical) |
| `get_stats()` | Get index statistics |
| `rebuild_index()` | Force re-index from configured paths |
| `get_raw_yaml(id)` | Get the original YAML content |

## Example Workflow

1. **Ask the LLM**: "Find me PowerShell detections related to base64 encoding"

2. **LLM calls**: `search(query="powershell base64", limit=5)`

3. **LLM receives**: Top 5 detections with names, descriptions, and detection logic

4. **LLM explores**: Uses `get_by_id` to get full details on interesting detections

5. **LLM filters by MITRE**: `list_by_mitre(technique_id="T1059.001")` to find all PowerShell execution detections

## Unified Schema

Both Sigma and Splunk ESCU detections are normalized to a common schema:

| Field | Description |
|-------|-------------|
| `id` | Unique identifier (UUID for Sigma, ID field for Splunk) |
| `name` | Detection name/title |
| `description` | What the detection looks for |
| `query` | Detection logic (Sigma YAML or Splunk SPL) |
| `source_type` | `sigma` or `splunk_escu` |
| `mitre_ids` | Mapped MITRE ATT&CK technique IDs |
| `logsource_category` | Sigma logsource category |
| `logsource_product` | Sigma logsource product (windows, linux, etc.) |
| `logsource_service` | Sigma logsource service |
| `severity` | Detection severity level |
| `status` | Rule status (stable, test, experimental, etc.) |
| `author` | Rule author |
| `date_created` | Creation date |
| `date_modified` | Last modification date |
| `references` | External references |
| `falsepositives` | Known false positive scenarios |
| `tags` | All tags (MITRE, analytic stories, etc.) |
| `file_path` | Original file path |
| `raw_yaml` | Original YAML content |

## Database

The index is stored at `~/.cache/security-detections-mcp/detections.sqlite`.

- Auto-created on first run
- Auto-indexed when paths are configured
- Use `rebuild_index()` to refresh after updating detection repos

## Supported Detection Formats

### Sigma Rules

Based on the [official Sigma specification](https://github.com/SigmaHQ/sigma-specification):
- All required fields: `title`, `logsource`, `detection`
- All optional fields: `id`, `status`, `description`, `author`, `date`, `modified`, `references`, `tags`, `level`, `falsepositives`, etc.

### Splunk ESCU

From [Splunk Security Content](https://github.com/splunk/security_content):
- Required: `name`, `id`, `search`
- Optional: `description`, `author`, `date`, `status`, `references`, `tags` (including `mitre_attack_id`, `analytic_story`)

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run with paths
SIGMA_PATHS="./detections/sigma/rules" SPLUNK_PATHS="./detections/splunk/detections" npm start
```

## License

Apache 2.0
