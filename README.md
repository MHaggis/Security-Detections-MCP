# Security Detections MCP

An MCP (Model Context Protocol) server that lets LLMs query a unified database of **Sigma**, **Splunk ESCU**, **Elastic**, **KQL**, **Sublime**, and **CrowdStrike CQL** security detection rules.

> **New here? Start with the [Setup Guide](./SETUP.md)** -- covers macOS, Windows (WSL & native), and Linux step by step.
>
> **Want it hosted? Skip the install entirely: [Hosted MCP Setup Guide](./docs/HOSTED_MCP.md)**

## Two Ways to Run It

**Local (full power)** — the npm package you're looking at. Runs on your machine, indexes your own detection repos, exposes all 81 tools. You need Node.js and ~10 minutes.

**Hosted (zero setup)** — a Streamable HTTP server at [`detect.michaelhaag.org/api/mcp/mcp`](https://detect.michaelhaag.org/mcp). Sign up, generate a token, paste one URL into your MCP client. ~25 read-only tools, always in sync with the latest content, 200 calls/day free. Read on for quick-install buttons.

### Install — Local

[![Install Local MCP in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=security-detections&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsInNlY3VyaXR5LWRldGVjdGlvbnMtbWNwIl0sImVudiI6eyJTSUdNQV9QQVRIUyI6Ii9wYXRoL3RvL3NpZ21hL3J1bGVzLC9wYXRoL3RvL3NpZ21hL3J1bGVzLXRocmVhdC1odW50aW5nIiwiU1BMVU5LX1BBVEhTIjoiL3BhdGgvdG8vc2VjdXJpdHlfY29udGVudC9kZXRlY3Rpb25zIiwiU1RPUllfUEFUSFMiOiIvcGF0aC90by9zZWN1cml0eV9jb250ZW50L3N0b3JpZXMiLCJFTEFTVElDX1BBVEhTIjoiL3BhdGgvdG8vZGV0ZWN0aW9uLXJ1bGVzL3J1bGVzIiwiS1FMX1BBVEhTIjoiL3BhdGgvdG8va3FsLXJ1bGVzIiwiU1VCTElNRV9QQVRIUyI6Ii9wYXRoL3RvL3N1YmxpbWUtcnVsZXMvZGV0ZWN0aW9uLXJ1bGVzIiwiQ1FMX0hVQl9QQVRIUyI6Ii9wYXRoL3RvL2NxbC1odWIvcXVlcmllcyJ9fQ==)
[![Install Local MCP in VS Code](https://img.shields.io/badge/VS_Code-Install_Local_MCP-0078d4?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?name=security-detections&config=%7B%22type%22%3A%22stdio%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22security-detections-mcp%22%5D%7D)
[![Install Local MCP in VS Code Insiders](https://img.shields.io/badge/VS_Code_Insiders-Install_Local_MCP-24bfa5?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect?url=vscode-insiders:mcp/install?name=security-detections&config=%7B%22type%22%3A%22stdio%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22security-detections-mcp%22%5D%7D)

**Claude Code** (CLI one-liner):

```bash
claude mcp add security-detections -- npx -y security-detections-mcp
```

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": ["-y", "security-detections-mcp"]
    }
  }
}
```

**OpenAI Codex** (CLI):

```bash
codex mcp add security-detections -- npx -y security-detections-mcp
```

> After install, configure env vars (`SIGMA_PATHS`, `SPLUNK_PATHS`, etc.) to point at your detection repos. See the [Setup Guide](./SETUP.md) for full details.

### Install — Hosted (no setup, token required)

1. **Create a token** at [detect.michaelhaag.org/account/tokens](https://detect.michaelhaag.org/account/tokens). Free tier: 200 calls/day, all read-only tools.
2. **Click the button for your client** — replace `sdmcp_YOUR_TOKEN_HERE` in the resulting config with the token you just generated.

[![Install Hosted MCP in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=security-detections-hosted&config=eyJ1cmwiOiJodHRwczovL2RldGVjdC5taWNoYWVsaGFhZy5vcmcvYXBpL21jcC9tY3AiLCJoZWFkZXJzIjp7IkF1dGhvcml6YXRpb24iOiJCZWFyZXIgc2RtY3BfWU9VUl9UT0tFTl9IRVJFIn19)
[![Install Hosted MCP in VS Code](https://img.shields.io/badge/VS_Code-Install_Hosted_MCP-0078d4?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?name=security-detections&config=%7B%22type%22%3A%22http%22%2C%22url%22%3A%22https%3A%2F%2Fdetect.michaelhaag.org%2Fapi%2Fmcp%2Fmcp%22%2C%22headers%22%3A%7B%22Authorization%22%3A%22Bearer%20sdmcp_YOUR_TOKEN_HERE%22%7D%7D)
[![Install Hosted MCP in VS Code Insiders](https://img.shields.io/badge/VS_Code_Insiders-Install_Hosted_MCP-24bfa5?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect?url=vscode-insiders:mcp/install?name=security-detections&config=%7B%22type%22%3A%22http%22%2C%22url%22%3A%22https%3A%2F%2Fdetect.michaelhaag.org%2Fapi%2Fmcp%2Fmcp%22%2C%22headers%22%3A%7B%22Authorization%22%3A%22Bearer%20sdmcp_YOUR_TOKEN_HERE%22%7D%7D)

**Claude Code** (CLI one-liner):

```bash
claude mcp add --transport http security-detections \
  https://detect.michaelhaag.org/api/mcp/mcp \
  --header "Authorization: Bearer sdmcp_YOUR_TOKEN_HERE"
```

**Claude Desktop** (via [`mcp-remote`](https://github.com/geelen/mcp-remote) — Desktop doesn't speak remote HTTP natively yet):

```json
{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://detect.michaelhaag.org/api/mcp/mcp",
        "--header",
        "Authorization: Bearer sdmcp_YOUR_TOKEN_HERE"
      ]
    }
  }
}
```

**OpenAI Codex** (CLI):

```bash
# Set your token as an env var first: export SDMCP_TOKEN="sdmcp_YOUR_TOKEN_HERE"
codex mcp add security-detections \
  --url https://detect.michaelhaag.org/api/mcp/mcp \
  --bearer-token-env-var SDMCP_TOKEN
```

See the [Hosted MCP Setup Guide](./docs/HOSTED_MCP.md) for the full table of clients, the complete tool inventory, and troubleshooting tips.

## Features

- **8,200+ detections** across 6 formats — Sigma, Splunk ESCU, Elastic, KQL, Sublime, CrowdStrike CQL
- **MITRE ATT&CK STIX** — 172 threat actors, 784 software, 4,362 actor-technique relationships
- **Procedure-level coverage** — auto-extracted behavioral clusters from every detection rule
- **ATT&CK Navigator layers** — export coverage/gap JSON, filterable by source/tactic/severity/actor
- **Autonomous pipeline** — CTI ingestion → gap analysis → detection generation → Atomic testing → DRAFT PR (see [Autonomous docs](./docs/AUTONOMOUS.md))
- **81 local tools / ~25 hosted tools** — unified search, MITRE mapping, coverage analysis, knowledge graph, pattern learning, sprint planning
- **11 MCP Prompts** — ransomware assessment, APT emulation, purple team, executive briefing, and more
- **MCP Resources & Completions** — readable context, autocomplete for technique IDs, CVEs, process names

## Quick Start

```bash
npx -y security-detections-mcp
```

Or clone and build: `git clone https://github.com/MHaggis/Security-Detections-MCP.git && cd Security-Detections-MCP && npm install && npm run build`

Configure env vars to point at your detection repos:

| Variable | Description |
|----------|-------------|
| `SIGMA_PATHS` | Sigma rule directories |
| `SPLUNK_PATHS` | Splunk ESCU detection directories |
| `ELASTIC_PATHS` | Elastic detection rule directories |
| `KQL_PATHS` | KQL hunting query directories |
| `SUBLIME_PATHS` | Sublime Security rule directories |
| `CQL_HUB_PATHS` | CQL Hub (CrowdStrike) query directories |
| `STORY_PATHS` | Splunk analytic story directories (optional) |
| `ATTACK_STIX_PATH` | Path to `enterprise-attack.json` for threat actor data (optional) |

See the [Setup Guide](./SETUP.md) for full per-client config examples (Cursor, VS Code, Claude Desktop, WSL).

## Getting Detection Content

Download all sources with sparse checkout (rules only, not full repos):

```bash
mkdir -p detections && cd detections
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git && cd sigma && git sparse-checkout set rules rules-threat-hunting && cd ..
git clone --depth 1 --filter=blob:none --sparse https://github.com/splunk/security_content.git && cd security_content && git sparse-checkout set detections stories && cd ..
git clone --depth 1 --filter=blob:none --sparse https://github.com/elastic/detection-rules.git && cd detection-rules && git sparse-checkout set rules && cd ..
git clone --depth 1 https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules.git kql-bertjanp
git clone --depth 1 https://github.com/jkerai1/KQL-Queries.git kql-jkerai1
git clone --depth 1 --filter=blob:none --sparse https://github.com/sublime-security/sublime-rules.git && cd sublime-rules && git sparse-checkout set detection-rules && cd ..
git clone --depth 1 https://github.com/ByteRay-Labs/Query-Hub.git cql-hub
```

## MCP Tools

### Core Detection Tools

| Tool | Description |
|------|-------------|
| `search(query, limit)` | Full-text search across all detection fields |
| `get_by_id(id)` | Get a single detection by ID |
| `list_all(limit, offset)` | Paginated list of all detections |
| `list_by_source(source_type)` | Filter by source (`sigma`, `splunk_escu`, `elastic`, `kql`, `sublime`, `crowdstrike_cql`) |
| `get_stats()` | Index statistics |
| `rebuild_index()` | Force re-index from configured paths |

### MITRE ATT&CK & Filtering

| Tool | Description |
|------|-------------|
| `list_by_mitre(technique_id)` | Filter by technique ID (e.g., T1059.001) |
| `list_by_mitre_tactic(tactic)` | Filter by tactic (execution, persistence, etc.) |
| `list_by_cve(cve_id)` | Find detections for a CVE |
| `list_by_process_name(process_name)` | Find detections referencing a process |
| `list_by_severity(level)` | Filter by severity level |
| `list_by_data_source(data_source)` | Filter by data source |

### Coverage & Analysis (Token-Optimized)

| Tool | Description |
|------|-------------|
| `analyze_coverage(source_type?)` | Coverage stats by tactic, top techniques, weak spots (~2KB) |
| `identify_gaps(threat_profile)` | Find gaps for ransomware, apt, persistence, etc. (~500B) |
| `suggest_detections(technique_id)` | Detection ideas for a technique (~2KB) |
| `get_coverage_summary(source_type?)` | Tactic percentages (~200B) |
| `analyze_actor_coverage(actor)` | Coverage against a specific threat actor |
| `compare_actor_coverage(actors)` | Compare coverage across multiple actors |
| `analyze_procedure_coverage(technique_id)` | Behavioral procedure breakdown |
| `generate_navigator_layer(...)` | Export ATT&CK Navigator JSON layers |

### Engineering, Knowledge Graph & More

81 tools total including pattern learning, template generation, knowledge graph, dynamic tables, and autonomous analysis. See the [Tools Reference](docs/wiki/Tools-Reference.md) for the complete list.

## MCP Prompts

11 pre-built expert workflows. Just ask by name:

| Prompt | Description |
|--------|-------------|
| `ransomware-readiness-assessment` | Full kill-chain analysis with risk scoring |
| `apt-threat-emulation` | Coverage against specific threat actors (APT29, Lazarus, etc.) |
| `purple-team-exercise` | Complete test plans with procedures and expected detections |
| `soc-investigation-assist` | Triage guidance, hunting queries, escalation criteria |
| `detection-engineering-sprint` | Prioritized backlog with user stories |
| `executive-security-briefing` | C-level report with business risk language |
| `cve-response-assessment` | Rapid assessment for emerging CVEs |
| `data-source-gap-analysis` | Telemetry requirements analysis |
| `detection-quality-review` | Deep-dive quality analysis for a technique |
| `threat-landscape-sync` | Align priorities with current threats |
| `detection-coverage-diff` | Compare coverage against actors or baseline |

```
You: "Run apt-threat-emulation for APT29"
→ Technique-by-technique coverage, gaps, and purple team test plan
```

## Using with MITRE ATT&CK MCP

Pairs with [mitre-attack-mcp](https://github.com/MHaggis/mitre-attack-mcp) for complete threat coverage analysis. Install both:

```json
{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": { "SIGMA_PATHS": "/path/to/sigma/rules" }
    },
    "mitre-attack": {
      "command": "npx",
      "args": ["-y", "mitre-attack-mcp"],
      "env": { "ATTACK_DOMAIN": "enterprise-attack" }
    }
  }
}
```

## Stats

| Source | Count |
|--------|-------|
| Sigma Rules | ~3,200+ |
| Splunk ESCU | ~2,000+ |
| Elastic Rules | ~1,500+ |
| KQL Queries | ~420+ |
| Sublime Rules | ~900+ |
| CrowdStrike CQL | ~139+ |
| **Total** | **~8,200+** |

## Development

```bash
npm install && npm run build && npm test
```

## Documentation

- **[Setup Guide](./SETUP.md)** — Full install walkthrough for all platforms
- **[Hosted MCP Guide](./docs/HOSTED_MCP.md)** — Hosted setup, token management, tool inventory
- **[Autonomous Platform](./docs/AUTONOMOUS.md)** — CTI-to-detection pipeline
- **[E2E Testing Guide](./docs/E2E-TESTING-GUIDE.md)** — Per-SIEM setup (Splunk, Sentinel, Elastic, Sigma)
- **[Architecture](docs/wiki/Architecture.md)** — System design decisions
- **[Knowledge Graph](docs/wiki/Knowledge-Graph.md)** — Tribal knowledge and analytical memory
- **[Engineering Intelligence](docs/wiki/Engineering-Intelligence.md)** — Pattern learning and templates
- **[Tools Reference](docs/wiki/Tools-Reference.md)** — Complete reference for all 81 tools

## License

Apache 2.0
