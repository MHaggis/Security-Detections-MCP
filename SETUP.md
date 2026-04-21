# Setup Guide - Detections MCP v3.1

Get the autonomous detection engineering platform running on your machine.

**Time estimate**: ~10 minutes for the MCP server, ~15 minutes for the full autonomous pipeline.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Clone the Repo](#step-1-clone-the-repo)
- [Step 2: Install the MCP Server](#step-2-install-the-mcp-server)
- [Step 3: Download Detection Content](#step-3-download-detection-content)
- [Step 4: Configure Your IDE](#step-4-configure-your-ide)
- [Step 5: Verify It Works](#step-5-verify-it-works)
- [Step 6 (Optional): Set Up the Autonomous Pipeline](#step-6-optional-set-up-the-autonomous-pipeline)
- [Platform Notes](#platform-notes)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Version | Check |
|-------------|---------|-------|
| **Node.js** | 20+ (agents require 20+, MCP server needs 18+) | `node --version` |
| **npm** | 9+ | `npm --version` |
| **git** | Any recent | `git --version` |
| **Python** | 3.10+ (only for validation tools like contentctl, pySigma) | `python3 --version` |

### Install Node.js

**macOS** (Homebrew):
```bash
brew install node@20
```

**macOS/Linux** (nvm -- recommended):
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
nvm install 20
nvm use 20
```

**Windows (WSL)**:
```bash
# Inside WSL (Ubuntu):
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
source ~/.bashrc
nvm install 20
nvm use 20
```

**Windows (native)**: Download from [nodejs.org](https://nodejs.org/) (LTS 20.x). You'll also need the "Tools for Native Modules" option checked during install for `better-sqlite3` to compile.

### Build Tools for `better-sqlite3`

This project uses `better-sqlite3`, which compiles a native C module during `npm install`. If it fails, you're missing build tools.

**macOS**:
```bash
xcode-select --install
```

**Ubuntu / WSL**:
```bash
sudo apt update && sudo apt install -y build-essential python3
```

**Windows (native)**: Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the "Desktop development with C++" workload, or run:
```powershell
npm install --global windows-build-tools
```

---

## Step 1: Clone the Repo

```bash
git clone https://github.com/MHaggis/Security-Detections-MCP.git
cd Security-Detections-MCP
```

---

## Step 2: Install the MCP Server

```bash
npm install
npm run build
```

That's it. The MCP server is ready.

**Quick test** (should print version info and exit):
```bash
npm start 2>&1 | head -5
# You'll see JSON output on stderr -- that's the MCP handshake. Ctrl+C to stop.
```

### Alternative: Use npx (No Clone Required)

If you just want the MCP server without cloning:
```bash
npx -y security-detections-mcp
```

This downloads and runs the published npm package directly. Configure paths via environment variables (see Step 4).

---

## Step 3: Download Detection Content

The MCP server indexes rules from community detection repos. Download as many or as few as you want:

```bash
mkdir -p detections && cd detections

# Sigma rules (~3,000+ rules) - recommended, SIEM-agnostic
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git
cd sigma && git sparse-checkout set rules rules-threat-hunting && cd ..

# Splunk ESCU (~2,000+ detections, ~330 stories)
git clone --depth 1 --filter=blob:none --sparse https://github.com/splunk/security_content.git
cd security_content && git sparse-checkout set detections stories && cd ..

# Elastic detection rules (~1,500+ rules)
git clone --depth 1 --filter=blob:none --sparse https://github.com/elastic/detection-rules.git
cd detection-rules && git sparse-checkout set rules && cd ..

# KQL hunting queries (~400+ queries)
git clone --depth 1 https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules.git kql-bertjanp
git clone --depth 1 https://github.com/jkerai1/KQL-Queries.git kql-jkerai1

# Sublime Security rules (~900+ email security rules)
git clone --depth 1 --filter=blob:none --sparse https://github.com/sublime-security/sublime-rules.git
cd sublime-rules && git sparse-checkout set detection-rules && cd ..

# CrowdStrike CQL Hub (~139+ queries)
git clone --depth 1 https://github.com/ByteRay-Labs/Query-Hub.git cql-hub

# MITRE ATT&CK STIX data (172 actors, 691 techniques, 784 software)
git clone --depth 1 https://github.com/mitre-attack/attack-stix-data.git

cd ..
```

> **Tip**: You don't need all of them. Start with Sigma if you're unsure -- it's the most portable. Sublime is great for email-based threat detections, and CQL Hub covers CrowdStrike-specific queries.

---

## Step 4: Configure Your IDE

Pick your IDE and add the MCP server configuration.

### Cursor IDE

Add to `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project):

```json
{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS": "/absolute/path/to/detections/sigma/rules,/absolute/path/to/detections/sigma/rules-threat-hunting",
        "SPLUNK_PATHS": "/absolute/path/to/detections/security_content/detections",
        "ELASTIC_PATHS": "/absolute/path/to/detections/detection-rules/rules",
        "KQL_PATHS": "/absolute/path/to/detections/kql-bertjanp,/absolute/path/to/detections/kql-jkerai1",
        "STORY_PATHS": "/absolute/path/to/detections/security_content/stories",
        "SUBLIME_PATHS": "/absolute/path/to/detections/sublime-rules/detection-rules",
        "CQL_HUB_PATHS": "/absolute/path/to/detections/cql-hub/queries",
        "JAMF_PROTECT_PATHS": "/absolute/path/to/detections/jamfprotect/custom_analytic_detections",
        "ATTACK_STIX_PATH": "/absolute/path/to/attack-stix-data/enterprise-attack/enterprise-attack.json"
      }
    }
  }
}
```

Replace `/absolute/path/to/detections/...` with your actual paths. Only include the sources you downloaded.

### VS Code

Add to `~/.vscode/mcp.json`:

```json
{
  "servers": {
    "security-detections": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS": "/absolute/path/to/detections/sigma/rules,/absolute/path/to/detections/sigma/rules-threat-hunting",
        "SPLUNK_PATHS": "/absolute/path/to/detections/security_content/detections",
        "ELASTIC_PATHS": "/absolute/path/to/detections/detection-rules/rules",
        "KQL_PATHS": "/absolute/path/to/detections/kql-bertjanp,/absolute/path/to/detections/kql-jkerai1",
        "STORY_PATHS": "/absolute/path/to/detections/security_content/stories",
        "SUBLIME_PATHS": "/absolute/path/to/detections/sublime-rules/detection-rules",
        "CQL_HUB_PATHS": "/absolute/path/to/detections/cql-hub/queries",
        "JAMF_PROTECT_PATHS": "/absolute/path/to/detections/jamfprotect/custom_analytic_detections",
        "ATTACK_STIX_PATH": "/absolute/path/to/attack-stix-data/enterprise-attack/enterprise-attack.json"
      }
    }
  }
}
```

### VS Code + WSL

If you're running VS Code on Windows but your files are inside WSL:

```json
{
  "servers": {
    "security-detections": {
      "type": "stdio",
      "command": "wsl",
      "args": ["npx", "-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS": "/home/youruser/detections/sigma/rules",
        "SPLUNK_PATHS": "/home/youruser/detections/security_content/detections",
        "ELASTIC_PATHS": "/home/youruser/detections/detection-rules/rules",
        "KQL_PATHS": "/home/youruser/detections/kql-bertjanp",
        "STORY_PATHS": "/home/youruser/detections/security_content/stories",
        "SUBLIME_PATHS": "/home/youruser/detections/sublime-rules/detection-rules",
        "CQL_HUB_PATHS": "/home/youruser/detections/cql-hub/queries",
        "JAMF_PROTECT_PATHS": "/home/youruser/detections/jamfprotect/custom_analytic_detections"
      }
    }
  }
}
```

Use Linux paths (not `/mnt/c/...`). Keep detection files inside the WSL filesystem for performance.

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "security-detections": {
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS": "/absolute/path/to/detections/sigma/rules",
        "SPLUNK_PATHS": "/absolute/path/to/detections/security_content/detections",
        "SUBLIME_PATHS": "/absolute/path/to/detections/sublime-rules/detection-rules",
        "CQL_HUB_PATHS": "/absolute/path/to/detections/cql-hub/queries",
        "JAMF_PROTECT_PATHS": "/absolute/path/to/detections/jamfprotect/custom_analytic_detections",
        "ATTACK_STIX_PATH": "/absolute/path/to/attack-stix-data/enterprise-attack/enterprise-attack.json"
      }
    }
  }
}
```

---

## Step 5: Verify It Works

After configuring your IDE, restart it and try these queries:

```
"How many detections do we have?" → Should call get_stats and show counts
"Find PowerShell detections" → Should return results from your indexed rules
"What's our coverage for credential access?" → Should show tactic coverage
```

If you see detection counts and search results, you're good. The MCP server auto-indexes all configured paths on startup.

The SQLite database is stored at `~/.cache/security-detections-mcp/detections.sqlite` and rebuilds automatically.

---

## Step 6 (Optional): Set Up the Autonomous Pipeline

This is the v3.1 LangGraph pipeline that goes from threat intel to validated detections. It requires an LLM API key and optionally a lab environment.

### Install the Agents Package

```bash
cd agents
npm install --registry https://registry.npmjs.org/
```

### Configure Environment

```bash
cp .env.example .env
```

Edit `agents/.env` with at minimum:

```bash
# Required: pick your SIEM
SIEM_PLATFORM=splunk  # or sentinel, elastic, sigma

# Required: LLM API key
ANTHROPIC_API_KEY=sk-ant-your-key-here

# Required: path to your detection content repo
SECURITY_CONTENT_PATH=/path/to/security_content
```

See `agents/.env.example` for the full list of options with detailed comments. Each SIEM platform has its own section -- only fill in what applies to you.

### Run the Pipeline

```bash
# Dry run first (no external calls, good for first test)
DRY_RUN=true npm run orchestrate -- --type technique --input "T1566.004 Spearphishing Voice"

# Analyze a specific technique (creates real detections)
npm run orchestrate -- --type technique --input "T1566.004 Spearphishing Voice"

# Process a CISA alert
npm run orchestrate -- --type cisa_alert --url https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a

# Analyze a threat report
npm run orchestrate -- --type threat_report --file ./report.md

# Manual input
npm run orchestrate -- --type manual --input "PowerShell encoded commands observed..."
```

> **First time?** Start with `DRY_RUN=true` to see the pipeline flow without needing a lab environment.
>
> **Note:** The pipeline is coverage-aware. If a technique already has detections (e.g., T1003.001 has 100+), it will correctly skip detection creation. Use a technique with no coverage (like T1566.004) to see the full pipeline.

### Per-SIEM Lab Setup

For full end-to-end validation (running atomics, validating detections fire), see the [E2E Testing Guide](./docs/E2E-TESTING-GUIDE.md). Quick overview:

| SIEM | Lab Option | Cost | Setup Time |
|------|-----------|------|------------|
| Splunk | Attack Range (AWS) | ~$5-15/day | ~30 min |
| Sentinel | Azure VM + Sentinel workspace | Free tier available | ~1 hour |
| Elastic | Docker Elastic Stack | Free | ~20 min |
| Sigma | No lab needed (rule authoring only) | Free | ~5 min |

---

## Platform Notes

### macOS

- **Apple Silicon (M1/M2/M3/M4)**: `better-sqlite3` compiles natively -- no issues.
- **Attack Range on macOS**: If using Attack Range with Ansible, you need:
  ```bash
  export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
  ```
  Add this to your `~/.zshrc` to make it permanent.
- **Homebrew Node.js**: If you installed Node via Homebrew and get permission errors with `npx`, try `nvm` instead.

### Windows (WSL) -- Recommended Approach

Running inside WSL2 (Ubuntu) is the smoothest experience on Windows.

1. **Install WSL2**: Open PowerShell as admin:
   ```powershell
   wsl --install -d Ubuntu
   ```
2. **Inside WSL, install Node.js**:
   ```bash
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
   source ~/.bashrc
   nvm install 20
   ```
3. **Clone and install inside WSL** (not on `/mnt/c/`):
   ```bash
   cd ~
   git clone https://github.com/MHaggis/Security-Detections-MCP.git
   cd Security-Detections-MCP
   npm install && npm run build
   ```
4. **Keep everything on the Linux filesystem**. `/mnt/c/` paths are slow and cause file-watching issues.

### Windows (Native)

Native Windows works for the MCP server (v2.1.1 fixed the EBUSY SQLite bug). Key notes:

- Install Node.js 20 LTS from [nodejs.org](https://nodejs.org/) -- check "Tools for Native Modules" during install.
- Use `cmd` or PowerShell, not Git Bash, for `npm install` (avoids path issues with native modules).
- Paths use backslashes in env vars: `"SIGMA_PATHS": "C:\\Users\\you\\detections\\sigma\\rules"`.

### Linux

No special notes. Install Node.js 20+ via your package manager or nvm. Make sure `build-essential` (or equivalent) is installed for `better-sqlite3`.

---

## Troubleshooting

### `npm install` fails with `better-sqlite3` compilation error

This is the most common issue. `better-sqlite3` compiles a native SQLite binary.

**Fix**: Install build tools for your platform (see [Prerequisites](#prerequisites)).

**Alternative**: If you still can't compile, try:
```bash
npm install --build-from-source=false
```

### `npm ERR! code ERESOLVE` or dependency conflicts

Force the npm registry and clean cache:
```bash
npm cache clean --force
npm install --registry https://registry.npmjs.org/
```

### `npx -y security-detections-mcp` hangs or fails

npm may be trying to use a corporate registry. Force public:
```bash
npx --registry https://registry.npmjs.org/ -y security-detections-mcp
```

### MCP server starts but indexes 0 detections

- Check your paths are absolute and correct.
- The paths should point to the **directories** containing the rules, not individual files.
- Restart your IDE after changing MCP config -- most editors cache the config.

### `EBUSY: resource busy or locked` (Windows)

This was fixed in v2.1.1. Make sure you're on the latest version:
```bash
npx -y security-detections-mcp@latest
```

### `OBJC_DISABLE_INITIALIZE_FORK_SAFETY` error (macOS + Attack Range)

The Ansible subprocess crashes on macOS due to an Objective-C fork safety check:
```bash
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

### `agents/` pipeline errors: "Cannot find module"

Build the agents package first:
```bash
cd agents
npm run build
```

If that fails with TypeScript errors:
```bash
npm run typecheck  # see what's wrong
```

### Node version too old

The `agents/` package requires Node 20+. Check with:
```bash
node --version
```

If you're on an older version:
```bash
nvm install 20
nvm use 20
```

---

## What's Next?

Once you're set up:

- **Explore detections**: Ask your AI assistant "What's our coverage for ransomware?" or "Find detections for T1059.001"
- **Run the pipeline**: Try `npm run orchestrate -- --type technique --input "T1566.004 Spearphishing Voice"` in the agents directory
- **Read the docs**:
  - [E2E Testing Guide](./docs/E2E-TESTING-GUIDE.md) -- Full lab setup per SIEM
  - [Autonomous Platform](./docs/AUTONOMOUS.md) -- Feed-driven continuous detection engineering
  - [Model Configuration](./docs/MODELS.md) -- Swap LLM providers
  - [Main README](./README.md) -- Full tool reference, prompts, and features

---

## Architecture at a Glance

```
┌──────────────────────────────────────────────────────────────────┐
│                    Security Detections MCP v3.1                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  MCP Server (root)              Autonomous Pipeline (agents/)    │
│  ┌─────────────────────┐       ┌────────────────────────────┐   │
│  │ 71+ tools            │       │ LangGraph workflow          │   │
│  │ 11 prompts           │       │ CTI → Coverage → Detect →  │   │
│  │ 8,200+ detections    │◄─────►│ Atomic → Validate → PR     │   │
│  │ SQLite FTS5 index    │       │                            │   │
│  └─────────────────────┘       └────────────────────────────┘   │
│           │                              │                       │
│           ▼                              ▼                       │
│  Cursor / VS Code / Claude      Lab (Attack Range, Azure,       │
│  Desktop (any MCP client)       Docker Elastic, or none)        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```
