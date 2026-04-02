import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Static export — this app is 100% client-side (zero-knowledge)
  output: "export",

  // Disable image optimization for static export
  images: { unoptimized: true },

  // Transpile the workspace TypeScript package (shipped as .ts source)
  transpilePackages: ["@ramz/core"],

  // next.config `headers`/`rewrites`/`redirects` are NOT supported with `output: "export"`.
  // Apply CSP, HSTS, X-Frame-Options, etc. at the static host, CDN, or Tauri server config.
};

export default nextConfig;
