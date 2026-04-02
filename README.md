# رَمز | Ramz — منظومة الأمان الصفري المعرفة

> **Zero-Knowledge Security Suite** — Encrypted vault, threat scanner, breach detection.
> No server. No cloud. No data leaves your device.

---

## Features

| Module | Description |
|--------|-------------|
| 🔒 **Encrypted Vault** | AES-256-GCM encrypted credential store with PBKDF2-600k master password |
| 🛡️ **Threat Scanner** | Scan URLs & files via VirusTotal, urlscan.io, Google Safe Browsing + offline heuristics |
| 👁️ **Breach Detection** | Check emails against Have I Been Pwned; check passwords with k-Anonymity |
| 🔑 **API Key Manager** | Securely store your scan API keys locally |
| 📋 **History Log** | Persistent local scan history |
| 🧩 **Browser Extension** | Coming soon — live link scanning from your browser |

---

## Platforms

| Platform | Stack | Status |
|----------|-------|--------|
| 🌐 Web | Next.js 16, static export | ✅ Ready |
| 🖥️ Desktop | Tauri 2 (Windows / macOS / Linux) | ✅ Ready |
| 📱 Mobile | Expo 52 (iOS / Android) | ✅ Ready |

---

## Security Model

- **PBKDF2-SHA256** at 600,000 iterations (OWASP 2024 recommendation)
- **AES-256-GCM** authenticated encryption for the vault
- **HMAC-SHA256** integrity verification before every decrypt
- **k-Anonymity** for password breach checks — only 5 SHA-1 chars sent
- **Auto-lock** after 5 minutes idle
- **Brute-force protection** — 15-minute lockout after 5 failed attempts
- **Clipboard auto-clear** after 30 seconds
- All crypto via **Web Crypto API** (`crypto.subtle`) — no third-party libs
- `noindex, nofollow` — not indexed by search engines

---

## Quick Start

### Prerequisites

- Node.js ≥ 20
- pnpm ≥ 9
- Rust + Cargo (for desktop build)
- Xcode / Android Studio (for mobile build)

### Install

```bash
git clone https://github.com/BASILR00T/Ramz.git
cd Ramz
pnpm install
```

### Run Web

```bash
pnpm --filter web dev
# Opens http://localhost:3000
```

### Run Desktop

```bash
pnpm --filter web build    # build static web first
pnpm --filter desktop dev  # launch Tauri window
```

### Run Mobile

```bash
pnpm --filter mobile start
# Scan QR with Expo Go, or press a/i for simulator
```

### Build for Production

```bash
pnpm build   # builds all platforms via Turborepo
```

---

## API Keys (Optional)

The app works offline with heuristic analysis. For cloud-powered scanning, add keys in the **مفاتيح API** tab:

| Service | Free Tier | Get Key |
|---------|-----------|---------|
| VirusTotal | 4 req/min | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| Have I Been Pwned | Paid | [haveibeenpwned.com](https://haveibeenpwned.com/API/Key) |
| urlscan.io | 5000/month | [urlscan.io](https://urlscan.io/user/signup) |
| Google Safe Browsing | Free quota | [developers.google.com](https://developers.google.com/safe-browsing/v4/get-started) |

All keys are stored **locally only** — never transmitted anywhere.

---

## Project Structure

```
Ramz/
├── apps/
│   ├── web/                    Next.js 16 web dashboard
│   │   ├── app/                App Router (layout, page, globals.css)
│   │   ├── components/
│   │   │   ├── Shell.tsx       Main app shell + lock screen
│   │   │   ├── ui/Icons.tsx    SVG icon system
│   │   │   └── modules/        Feature modules
│   │   └── lib/storage.ts      localStorage wrapper
│   ├── desktop/
│   │   └── src-tauri/          Tauri 2 Rust backend
│   └── mobile/
│       ├── app/                Expo Router screens
│       └── lib/storage.ts      SecureStore wrapper
└── packages/
    └── core/
        └── src/
            ├── types.ts        Zod schemas + TypeScript types
            ├── crypto.ts       PBKDF2, AES-GCM, HMAC, password gen
            ├── heuristics.ts   Offline phishing detector (10 rules)
            └── api.ts          VT, HIBP, urlscan, GSB clients
```

---

## License

MIT © BASILR00T

---

> **Privacy Guarantee**: رَمز is designed so that no data — passwords, emails, scan results, API keys — ever leaves your device. The source code is open for audit.
