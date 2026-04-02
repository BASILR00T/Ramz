import type { Metadata, Viewport } from "next";
import { Tajawal, Space_Mono } from "next/font/google";
import "./globals.css";

// Self-hosted via next/font — no external font requests at runtime
const tajawal = Tajawal({
  subsets: ["arabic", "latin"],
  weight: ["300", "400", "500", "700", "900"],
  variable: "--font-tajawal",
  display: "swap",
});

const spaceMono = Space_Mono({
  subsets: ["latin"],
  weight: ["400", "700"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "رَمز | Ramz — منظومة الأمان",
  description:
    "رَمز | Ramz — منظومة أمان صفر-معرفة: خزينة مشفرة، فحص الفيروسات، كشف التسريبات. بدون خادم · بدون سحابة · لا بيانات تغادر جهازك.",
  keywords: ["security", "privacy", "password manager", "vault", "phishing", "virustotal", "hibp"],
  authors: [{ name: "رَمز | Ramz" }],
  robots: "noindex, nofollow", // Security tool — don't index
  icons: { icon: "/favicon.ico" },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    // Font variables on <html> so Tailwind v4 @theme can resolve them at parse time
    <html
      lang="ar"
      dir="rtl"
      className={`${tajawal.variable} ${spaceMono.variable}`}
    >
      {process.env.NODE_ENV === "production" && (
        <head>
          <meta
            httpEquiv="Content-Security-Policy"
            content={[
              "default-src 'self'",
              // API calls to external security services
              "connect-src 'self' https://www.virustotal.com https://urlscan.io https://haveibeenpwned.com https://api.pwnedpasswords.com https://safebrowsing.googleapis.com https://checkurl.phishtank.com",
              "script-src 'self' 'unsafe-inline'",
              "style-src 'self' 'unsafe-inline'",
              "font-src 'self' data:",
              "img-src 'self' data: https:",
              "object-src 'none'",
              "base-uri 'self'",
              "frame-ancestors 'none'",
              "form-action 'self'",
            ].join("; ")}
          />
        </head>
      )}
      <body className="antialiased">{children}</body>
    </html>
  );
}
