# Security-Detections-MCP — Docker Setup

Runs [MHaggis/Security-Detections-MCP](https://github.com/MHaggis/Security-Detections-MCP) in a Docker container — an MCP server that lets LLMs query a unified database of Sigma, Splunk ESCU, and Elastic security detection rules.

## Prerequisites

- Docker + Docker Compose
- ~2–4 GB disk space for detection repos

---

## Quick Start

```bash
# 1. Make the setup script executable
chmod +x setup.sh

# 2. Run it — downloads all detection repos and starts the container
./setup.sh
```

This will:
1. Clone Sigma rules (~3,000+), Splunk ESCU detections (~2,000+), and Elastic rules (~1,500+) into `./detections/`
2. Build the Docker image
3. Start the container with the rules mounted as read-only volumes

---

## Connecting to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent path on your OS:

```json
{
  "mcpServers": {
    "security-detections": {
      "command": "docker",
      "args": [
        "exec", "-i", "security-detections-mcp",
        "node", "dist/index.js"
      ]
    }
  }
}
```

## Connecting to Cursor

Add to `~/.cursor/mcp.json` or `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "security-detections": {
      "command": "docker",
      "args": [
        "exec", "-i", "security-detections-mcp",
        "node", "dist/index.js"
      ]
    }
  }
}
```

---

## Manual Docker Commands

```bash
# Build
docker build -t security-detections-mcp .

# Run (with detection repos already cloned into ./detections/)
docker run -it \
  -v "$(pwd)/detections/sigma:/detections/sigma:ro" \
  -v "$(pwd)/detections/security_content:/detections/security_content:ro" \
  -v "$(pwd)/detections/detection-rules:/detections/detection-rules:ro" \
  -e SIGMA_PATHS="/detections/sigma/rules,/detections/sigma/rules-threat-hunting" \
  -e SPLUNK_PATHS="/detections/security_content/detections" \
  -e ELASTIC_PATHS="/detections/detection-rules/rules" \
  -e STORY_PATHS="/detections/security_content/stories" \
  security-detections-mcp
```

---

## Updating Detection Rules

```bash
cd detections/sigma && git pull
cd detections/security_content && git pull
cd detections/detection-rules && git pull

# Then force re-index inside the running container by calling rebuild_index() via your MCP client,
# or restart the container:
docker compose restart
```

---

## File Layout

```
.
├── Dockerfile
├── docker-compose.yml
├── setup.sh
└── detections/           ← created by setup.sh
    ├── sigma/
    │   ├── rules/
    │   └── rules-threat-hunting/
    ├── security_content/
    │   ├── detections/
    │   └── stories/
    └── detection-rules/
        └── rules/
```

---

## Notes

- The MCP server communicates over **stdio** — no port is exposed.
- The SQLite detection index is persisted in the `mcp-cache` Docker volume so it survives container restarts.
- Detection repos are mounted **read-only** into the container.
