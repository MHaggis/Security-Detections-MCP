import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // Allow images from Supabase storage and GitHub avatars
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '*.supabase.co',
      },
      {
        protocol: 'https',
        hostname: 'avatars.githubusercontent.com',
      },
    ],
  },
  // Turbopack is default in dev via --turbopack flag

  // RFC 9728 Protected Resource Metadata — MCP clients fetch this URL
  // after a 401 to discover auth. Next.js disallows `.well-known` in the
  // app/ directory because of the leading dot, so we rewrite to an
  // api/ route handler.
  async rewrites() {
    return [
      {
        source: '/.well-known/oauth-protected-resource',
        destination: '/api/well-known/oauth-protected-resource',
      },
      {
        source: '/.well-known/oauth-protected-resource/:path*',
        destination: '/api/well-known/oauth-protected-resource',
      },
    ];
  },
};

export default nextConfig;
