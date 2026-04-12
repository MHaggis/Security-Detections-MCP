import { type NextRequest } from 'next/server';
import { updateSession } from '@/lib/supabase/middleware';

export async function middleware(request: NextRequest) {
  return await updateSession(request);
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public files (images, etc.)
     * - api/mcp (hosted MCP endpoint — uses bearer token auth, not cookies)
     * - api routes that don't need auth (search, coverage are public)
     */
    '/((?!_next/static|_next/image|favicon.ico|api/mcp|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};
