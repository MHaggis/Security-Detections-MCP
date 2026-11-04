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
      'Hosted Security Detections MCP. Read-only access to ~8,000 detections from Sigma, Splunk ESCU, Elastic, KQL, Sublime, CrowdStrike CQL, and Jamf Protect (macOS). Start with get_stats() and get_coverage_summary(), then drill down with search, list_by_mitre, or analyze_actor_coverage.',
    verboseLogs: false,
    // SDK v2 is stateless and supports 2025 Streamable HTTP clients too.
    // Hosted tools do not offer subscription streams.
    maxSubscriptions: 0,
  },
);

async function withAuth(request: Request): Promise<Response> {
  const auth = await authenticateMcpRequest(request);
  if (auth.response) return auth.response;
  // The MCP SDK handler validates and dispatches. We don't need to
  // propagate auth context into tools because all hosted tools are
  // read-only over shared public data.
  // Handler v2 delegates URL routing to the host framework. Preserve the
  // published transport URL instead of serving MCP at arbitrary suffixes.
  if (new URL(request.url).pathname !== '/api/mcp/mcp') {
    return new Response('Not found', { status: 404 });
  }
  return handler(request);
}

export { withAuth as GET, withAuth as POST, withAuth as DELETE };
