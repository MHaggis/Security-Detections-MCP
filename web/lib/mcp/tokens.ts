/**
 * MCP token generation, hashing, and prefix helpers.
 *
 * Tokens look like `sdmcp_<base62>` where the payload is 32 random bytes.
 * Only the sha256(token) is stored server-side; the plaintext is returned
 * to the user exactly once at creation time.
 */

import { createHash, randomBytes } from 'crypto';

export const TOKEN_PREFIX = 'sdmcp_';
const RAW_BYTES = 32;

// URL-safe base62-ish alphabet (no padding, no ambiguous chars).
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';

function encodeBytes(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) {
    out += ALPHABET[byte % ALPHABET.length];
  }
  return out;
}

export function generateToken(): { token: string; hash: string; prefix: string } {
  const bytes = randomBytes(RAW_BYTES);
  const token = TOKEN_PREFIX + encodeBytes(bytes);
  const hash = hashToken(token);
  const prefix = token.slice(0, TOKEN_PREFIX.length + 6); // e.g. "sdmcp_aB3xYz"
  return { token, hash, prefix };
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Extract a bearer token from an Authorization header.
 * Accepts "Bearer <token>" or plain "<token>" (some MCP clients omit the scheme).
 */
export function extractBearer(authHeader: string | null | undefined): string | null {
  if (!authHeader) return null;
  const trimmed = authHeader.trim();
  if (!trimmed) return null;
  const match = trimmed.match(/^Bearer\s+(.+)$/i);
  const raw = match ? match[1] : trimmed;
  if (!raw.startsWith(TOKEN_PREFIX)) return null;
  return raw;
}
