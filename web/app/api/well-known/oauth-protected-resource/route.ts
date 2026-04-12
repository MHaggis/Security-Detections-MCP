/**
 * RFC 9728 — OAuth 2.0 Protected Resource Metadata.
 *
 * Required by MCP specification 2025-11-25 for token-protected servers.
 * When /api/mcp returns 401, the WWW-Authenticate header points MCP
 * clients at https://detect.michaelhaag.org/.well-known/oauth-protected-resource
 * which is rewritten to this route handler via next.config.ts.
 *
 * We don't operate our own OAuth authorization server — tokens are
 * minted via the web UI and validated directly against Supabase — so
 * we advertise bearer-in-header as the only supported method and
 * direct users at our token-generation page.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9728
 * @see https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
 */

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function baseUrl(request: Request): string {
  const forwardedHost = request.headers.get('x-forwarded-host');
  const forwardedProto = request.headers.get('x-forwarded-proto');
  if (forwardedHost) {
    return `${forwardedProto ?? 'https'}://${forwardedHost}`;
  }
  return new URL(request.url).origin;
}

export async function GET(request: Request): Promise<Response> {
  const origin = baseUrl(request);
  const metadata = {
    resource: `${origin}/api/mcp/http`,
    authorization_servers: [] as string[],
    bearer_methods_supported: ['header'],
    resource_name: 'Security Detections MCP',
    resource_documentation: `${origin}/mcp`,
    // MCP-specific hint: non-OAuth clients should send users here to mint a token.
    token_endpoint: `${origin}/account/tokens`,
  };

  return new Response(JSON.stringify(metadata, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=3600',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, MCP-Protocol-Version',
    },
  });
}

export async function OPTIONS(): Promise<Response> {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, MCP-Protocol-Version',
    },
  });
}
