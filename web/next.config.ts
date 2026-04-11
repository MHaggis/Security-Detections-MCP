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
};

export default nextConfig;
