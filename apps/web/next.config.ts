import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Static export — this app is 100% client-side (zero-knowledge)
  output: "export",

  // Disable image optimization for static export
  images: { unoptimized: true },

  // Security headers
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              // API calls to external security services
              "connect-src 'self' https://www.virustotal.com https://urlscan.io https://haveibeenpwned.com https://api.pwnedpasswords.com https://safebrowsing.googleapis.com https://checkurl.phishtank.com",
              "script-src 'self' 'unsafe-inline'", // Required for Next.js
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
              "font-src 'self' https://fonts.gstatic.com",
              "img-src 'self' data: https:",
              "object-src 'none'",
              "base-uri 'self'",
              "frame-ancestors 'none'",
              "form-action 'self'",
            ].join("; "),
          },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=()",
          },
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains; preload",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
