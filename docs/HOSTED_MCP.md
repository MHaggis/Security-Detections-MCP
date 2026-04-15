# Hosted MCP Setup Guide

A fully managed, public-facing Security Detections MCP server at **[`https://detect.michaelhaag.org/api/mcp/mcp`](https://detect.michaelhaag.org/api/mcp/mcp)**. No install, no indexing, always in sync with the latest detection content — just generate a token and point your AI client at the URL.

> **Prefer local?** The npm package is still the full-power option (81 tools, offline, unlimited). See the main [README](../README.md) and [SETUP.md](../SETUP.md). The hosted endpoint is additive — everything in the local package is untouched.

## Table of contents

- [How it works](#how-it-works)
- [Step 1 — Create a token](#step-1--create-a-token)
- [Step 2 — Install in your MCP client](#step-2--install-in-your-mcp-client)
  - [Cursor](#cursor)
  - [VS Code / VS Code Insiders](#vs-code--vs-code-insiders)
  - [Claude Code CLI](#claude-code-cli)
  - [Claude Desktop (via `mcp-remote`)](#claude-desktop-via-mcp-remote)
  - [OpenAI Codex](#openai-codex)
  - [Any other MCP client](#any-other-mcp-client)
- [Verify it works](#verify-it-works)
- [Tool inventory](#tool-inventory)
- [Rate limits and quotas](#rate-limits-and-quotas)
- [Authentication details (RFC 9728 / MCP 2025-11-25)](#authentication-details-rfc-9728--mcp-2025-11-25)
- [Troubleshooting](#troubleshooting)
- [What the hosted version does NOT include](#what-the-hosted-version-does-not-include)

## How it works

```
Your MCP client
     │
     │ HTTPS — Authorization: Bearer sdmcp_xxx
     ▼
/api/mcp/mcp  (Next.js route on Vercel, Streamable HTTP, stateless)
     │
     │ token hash → atomic rate-limit RPC
     ▼
Supabase Postgres (~8,000 detections, full MITRE ATT&CK graph)
```

- **Transport:** MCP Streamable HTTP (spec **2025-11-25**, the latest), stateless mode — every request is independent, no `Mcp-Session-Id`, no server-sent events, no Redis.
- **Auth:** Bearer token in the `Authorization` header. Tokens are minted from the web UI, stored server-side as SHA-256 hashes, and validated by a single atomic Postgres RPC that also enforces the per-tier daily quota.
- **Data:** Supabase-backed. Same ~8,000 detections, 14 tactics, 172 threat actors that power [detect.michaelhaag.org](https://detect.michaelhaag.org). Nightly sync.
- **Spec compliance:** The server exposes `/.well-known/oauth-protected-resource` (RFC 9728 Protected Resource Metadata) and returns a spec-compliant `WWW-Authenticate: Bearer resource_metadata="..."` header on 401 so MCP clients can auto-discover auth requirements.

## Step 1 — Create a token

1. Visit **[detect.michaelhaag.org/account/tokens](https://detect.michaelhaag.org/account/tokens)** and sign in (email or GitHub via Supabase Auth).
2. Give your token a name — something like `"Claude Desktop — laptop"` or `"Cursor — work"`.
3. Click **Generate**.
4. **Copy the token immediately.** It's shown exactly once. Format: `sdmcp_<32 characters>`.

The full token is never stored in our database — we only keep the SHA-256 hash. If you lose it, revoke it and create a new one.

You can create up to **10 active tokens per account**. Revoke any you no longer need from the same page.

## Step 2 — Install in your MCP client

### Cursor

One-click install (opens Cursor):

**[Install Hosted MCP in Cursor →](https://cursor.com/en/install-mcp?name=security-detections-hosted&config=eyJ1cmwiOiJodHRwczovL2RldGVjdC5taWNoYWVsaGFhZy5vcmcvYXBpL21jcC9tY3AiLCJoZWFkZXJzIjp7IkF1dGhvcml6YXRpb24iOiJCZWFyZXIgc2RtY3BfWU9VUl9UT0tFTl9IRVJFIn19)**

After clicking, edit the installed server in **Cursor → Settings → MCP** and replace `sdmcp_YOUR_TOKEN_HERE` with your real token. Or edit `~/.cursor/mcp.json` directly:

```json
{
  "mcpServers": {
    "security-detections": {
      "url": "https://detect.michaelhaag.org/api/mcp/mcp",
      "headers": {
        "Authorization": "Bearer sdmcp_YOUR_TOKEN_HERE"
      }
    }
  }
}
```

### VS Code / VS Code Insiders

One-click install (opens VS Code):

- **[Install in VS Code →](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22security-detections%22%2C%22type%22%3A%22http%22%2C%22url%22%3A%22https%3A//detect.michaelhaag.org/api/mcp/mcp%22%2C%22headers%22%3A%7B%22Authorization%22%3A%22Bearer%20sdmcp_YOUR_TOKEN_HERE%22%7D%7D)**
- **[Install in VS Code Insiders →](https://insiders.vscode.dev/redirect?url=vscode-insiders:mcp/install?%7B%22name%22%3A%22security-detections%22%2C%22type%22%3A%22http%22%2C%22url%22%3A%22https%3A//detect.michaelhaag.org/api/mcp/mcp%22%2C%22headers%22%3A%7B%22Authorization%22%3A%22Bearer%20sdmcp_YOUR_TOKEN_HERE%22%7D%7D)**

After clicking, edit the installed server in VS Code and replace the placeholder token. Or edit your MCP config directly:

```json
{
  "servers": {
    "security-detections": {
      "type": "http",
      "url": "https://detect.michaelhaag.org/api/mcp/mcp",
      "headers": {
        "Authorization": "Bearer sdmcp_YOUR_TOKEN_HERE"
      }
    }
  }
}
```

### Claude Code CLI

```bash
claude mcp add --transport http security-detections \
  https://detect.michaelhaag.org/api/mcp/mcp \
  --header "Authorization: Bearer sdmcp_YOUR_TOKEN_HERE"
```

Verify with `claude mcp list`, then start Claude Code — the tools will be available. `.mcp.json` equivalent:

```json
{
  "mcpServers": {
    "security-detections": {
      "type": "http",
      "url": "https://detect.michaelhaag.org/api/mcp/mcp",
      "headers": {
        "Authorization": "Bearer sdmcp_YOUR_TOKEN_HERE"
      }
    }
  }
}
```

### Claude Desktop (via `mcp-remote`)

Claude Desktop (the Mac/Windows app) only speaks **stdio** MCP natively, not remote HTTP. Bridge the gap with [`mcp-remote`](https://github.com/geelen/mcp-remote):

**macOS** — edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

**Windows** — edit `%APPDATA%\Claude\claude_desktop_config.json`:

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

Quit and relaunch Claude Desktop. You should see the detections tools appear in the chat interface.

### OpenAI Codex

Codex CLI and IDE extension support Streamable HTTP remote servers natively.

**CLI one-liner:**

```bash
codex mcp add security-detections \
  --transport http https://detect.michaelhaag.org/api/mcp/mcp \
  --header "Authorization: Bearer sdmcp_YOUR_TOKEN_HERE"
```

**Config file** — `~/.codex/config.toml`:

```toml
[mcp_servers.security-detections]
type = "http"
url = "https://detect.michaelhaag.org/api/mcp/mcp"
headers = { Authorization = "Bearer sdmcp_YOUR_TOKEN_HERE" }
```

### Any other MCP client

Any client that speaks MCP Streamable HTTP (2025-03-26 spec or newer) will work. Give it:

- **URL:** `https://detect.michaelhaag.org/api/mcp/mcp`
- **Header:** `Authorization: Bearer sdmcp_YOUR_TOKEN_HERE`
- **Transport:** Streamable HTTP, stateless (no `Mcp-Session-Id` required)
- **Protocol version:** The server negotiates up to `2025-11-25`; it accepts `2025-03-26`, `2025-06-18`, `2025-11-25`.

## Verify it works

Before wiring up a client, smoke-test the endpoint with `curl`:

```bash
# List tools (should return ~25 tools)
curl -X POST https://detect.michaelhaag.org/api/mcp/mcp \
  -H "Authorization: Bearer sdmcp_YOUR_TOKEN_HERE" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Call a tool
curl -X POST https://detect.michaelhaag.org/api/mcp/mcp \
  -H "Authorization: Bearer sdmcp_YOUR_TOKEN_HERE" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_coverage_summary","arguments":{}}}'
```

A successful response is JSON-RPC 2.0 with a `result` field. A 401 means your token is missing, wrong, or revoked.

## Tool inventory

The hosted endpoint exposes **~25 read-only tools** — the same schemas as the local npm package, but filtered to the read-only subset (no knowledge graph, no dynamic tables, no autonomous analysis).

| Category | Tools |
|---|---|
| **Search & retrieval** | `search`, `get_by_id`, `get_raw_yaml`, `list_all` |
| **Stats & coverage** | `get_stats`, `get_coverage_summary`, `analyze_coverage`, `identify_gaps`, `get_technique_intelligence`, `get_technique_full`, `compare_sources`, `generate_navigator_layer` |
| **Filters** | `list_by_source`, `list_by_severity`, `list_by_detection_type`, `list_by_mitre`, `list_by_mitre_tactic`, `list_by_cve`, `list_by_process_name`, `list_by_data_source`, `list_by_analytic_story` |
| **Threat actors** | `list_actors`, `get_actor_profile`, `analyze_actor_coverage`, `compare_actor_coverage` |

All tools are registered with the modern `server.registerTool()` API and carry spec-compliant annotations:

- `readOnlyHint: true` — no state is mutated, Claude Code won't nag you for permission
- `destructiveHint: false`
- `idempotentHint: true`
- `openWorldHint: false` — closed-world detection corpus

Each tool also includes a `title` (human-readable display name) and a `_meta` block. MCP clients that surface these (Claude Code, Cursor) will show the friendly names in permission prompts and tool pickers.

## Rate limits and quotas

| Tier | Daily calls | How to get it |
|---|---|---|
| **Free** | 200 | Default for all new accounts |
| **Pro** | 5,000 | (Coming soon — Stripe billing not yet live) |
| **Admin** | 100,000 | Maintainer only |

- Quotas reset at **00:00 UTC**.
- Rate limiting is **per token**, not per account, so you can segment usage across multiple clients.
- The current usage is visible on [`/account/tokens`](https://detect.michaelhaag.org/account/tokens) with a live progress bar.
- Exceeding quota returns JSON-RPC error code `-32003` with a message. Clients will typically surface this as a tool error.

## Authentication details (RFC 9728 / MCP 2025-11-25)

The hosted endpoint is compliant with the current MCP authorization spec:

- **Discovery:** `GET https://detect.michaelhaag.org/.well-known/oauth-protected-resource` returns RFC 9728 Protected Resource Metadata advertising `bearer_methods_supported: ["header"]` and pointing at `/account/tokens` as the token endpoint.
- **Challenge:** On 401, the server emits `WWW-Authenticate: Bearer realm="mcp", resource_metadata="https://detect.michaelhaag.org/.well-known/oauth-protected-resource"`.
- **Bearer format:** `Authorization: Bearer sdmcp_<32chars>`. The `Bearer` scheme prefix is recommended but not required — the server also accepts the raw token in the header.
- **Storage:** Tokens are SHA-256 hashed before storage. The plaintext value exists in the database exactly zero times.
- **Revocation:** Immediate. Revoke a token via `/account/tokens`, and the next request with it returns `-32001 Token has been revoked`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `401 Missing or invalid bearer token` | Header missing / malformed / no `sdmcp_` prefix | Check your client config actually sends `Authorization: Bearer sdmcp_...` |
| `401 Token has been revoked` | Token was revoked via the UI | Generate a new token at `/account/tokens` |
| `429 Daily quota exceeded` | Over 200 calls today on that token | Wait until 00:00 UTC, or use a different token, or upgrade to Pro |
| `403 Account blocked` | Account tier is `blocked` | Contact the maintainer |
| Claude Desktop doesn't see the server | Desktop needs the `mcp-remote` proxy | Use the `mcp-remote` config shown above, not a plain `url` config |
| Cursor button does nothing | `cursor://` deeplink requires Cursor to be installed | Install Cursor first, then click the button again |
| VS Code button does nothing | `vscode:` deeplink requires VS Code (or Insiders) open | Make sure the app is running before clicking |
| Tools appear but all fail | Supabase outage (rare) | Check [status page](https://detect.michaelhaag.org) and retry |

## What the hosted version does NOT include

These tools are **local-only** because they either need per-user state, write to disk, or are destructive:

- Knowledge graph tools (`create_entity`, `create_relation`, `log_decision`, `search_knowledge`, `add_learning`, `get_relevant_decisions`, `get_learnings`)
- Dynamic tables (`create_table`, `insert_row`, `query_table`, `list_tables`)
- Query templates (`save_template`, `run_template`, `list_templates`)
- Autonomous analysis (`auto_analyze_coverage`, `auto_gap_report`, `auto_compare_sources`)
- Resource subscriptions and elicitation flows
- Raw YAML / repo write operations

If you need these, run the local npm package — see [SETUP.md](../SETUP.md).

---

## Something broken?

File an issue at [github.com/MHaggis/Security-Detections-MCP/issues](https://github.com/MHaggis/Security-Detections-MCP/issues). Include:

1. Your MCP client (Claude Desktop / Cursor / VS Code / Claude Code / Codex / other)
2. The JSON-RPC error code you saw (`-32001`, `-32003`, etc.)
3. The first 8 characters of your token prefix (`sdmcp_ab12cd` — **not** the full token)
