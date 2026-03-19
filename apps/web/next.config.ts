import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { NextConfig } from 'next';

const workspaceRoot = fileURLToPath(new URL('../..', import.meta.url));

export const approvalConsoleSecurityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: "base-uri 'self'; frame-ancestors 'none'; object-src 'none';",
  },
  {
    key: 'Referrer-Policy',
    value: 'no-referrer',
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  {
    key: 'X-Frame-Options',
    value: 'DENY',
  },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), payment=()',
  },
];

export const approvalConsoleNoStoreHeaders = [
  {
    key: 'Cache-Control',
    value: 'private, no-store, max-age=0',
  },
  {
    key: 'Pragma',
    value: 'no-cache',
  },
  {
    key: 'Expires',
    value: '0',
  },
];

const nextConfig: NextConfig = {
  reactStrictMode: true,
  typedRoutes: true,
  turbopack: {
    root: path.join(workspaceRoot),
  },
  async headers() {
    return [
      {
        source: '/approvals/:path*',
        headers: approvalConsoleNoStoreHeaders,
      },
      {
        source: '/daemons/:path*',
        headers: approvalConsoleNoStoreHeaders,
      },
      {
        source: '/:path*',
        headers: approvalConsoleSecurityHeaders,
      },
    ];
  },
};

export default nextConfig;
