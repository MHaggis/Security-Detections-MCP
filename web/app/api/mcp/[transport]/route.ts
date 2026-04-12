/**
 * Hosted MCP endpoint — Streamable HTTP, stateless.
 *
 * Exposes the read-only detection tools over the MCP Streamable HTTP
 * transport at /api/mcp/[transport]. Authenticated via bearer tokens
 * stored in the `mcp_tokens` table (see migration 014_mcp_tokens.sql and
 * lib/mcp/auth.ts).
 *
 * Stateless mode fits Vercel serverless: every request is independent,
 * no session store, no Redis.
 */

import { createMcpHandler } from 'mcp-handler';
import { registerHostedTools } from '@/lib/mcp/tools';
import { authenticateMcpRequest } from '@/lib/mcp/auth';

// Vercel serverless function configuration.
// Edge runtime is not compatible with node:crypto + the MCP SDK.
export const runtime = 'nodejs';
export const maxDuration = 60;
export const dynamic = 'force-dynamic';

const handler = createMcpHandler(
  (server) => {
    registerHostedTools(server);
  },
  {
    serverInfo: {
      name: 'security-detections-hosted',
      version: '1.0.0',
    },
    instructions:
      'Hosted Security Detections MCP. Read-only access to ~8,000 detections from Sigma, Splunk ESCU, Elastic, KQL, Sublime, and CrowdStrike CQL. Start with get_stats() and get_coverage_summary(), then drill down with search, list_by_mitre, or analyze_actor_coverage.',
  },
  {
    basePath: '/api/mcp',
    maxDuration: 60,
    verboseLogs: false,
    // Explicit stateless mode per MCP 2025-11-25 Streamable HTTP:
    // no session cookies, no Mcp-Session-Id emitted, every request
    // independent. Fits Vercel serverless natively — no Redis needed.
    sessionIdGenerator: undefined,
    disableSse: true,
  },
);

async function withAuth(request: Request): Promise<Response> {
  const auth = await authenticateMcpRequest(request);
  if (auth.response) return auth.response;
  // The MCP SDK handler validates and dispatches. We don't need to
  // propagate auth context into tools because all hosted tools are
  // read-only over shared public data.
  return handler(request);
}

export { withAuth as GET, withAuth as POST, withAuth as DELETE };
