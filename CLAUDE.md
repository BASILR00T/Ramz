# CLAUDE.md — رَمز | Ramz

## Project Overview

**رَمز (Ramz)** is a zero-knowledge security suite with three platforms:
- **Web** (`apps/web`) — Next.js 16 static export, Arabic RTL
- **Desktop** (`apps/desktop`) — Tauri 2 wrapping the web build
- **Mobile** (`apps/mobile`) — Expo 52 React Native

All cryptographic operations happen **client-side only**. No data ever leaves the device.

---

## Monorepo Structure

```
Ramz/
├── apps/
│   ├── web/          Next.js 16 (output: export)
│   ├── desktop/      Tauri 2 (wraps web/out)
│   └── mobile/       Expo 52 React Native
├── packages/
│   └── core/         Shared crypto + API + types (zero runtime deps)
├── turbo.json
└── package.json
```

## Key Commands

```bash
pnpm install          # install all workspaces
pnpm dev              # dev all (web on :3000)
pnpm build            # build all
pnpm --filter @ramz/web dev     # web only
pnpm --filter desktop dev       # Tauri dev (requires web running)
pnpm --filter mobile start      # Expo start
```

---

## Architecture Rules

### 1. Zero-knowledge contract
- No analytics, no telemetry, no external calls except the explicitly configured scan APIs
- Web build uses `output: 'export'` — no server, no API routes
- Never add `@vercel/analytics`, Sentry, or any tracking

### 2. Cryptography (`packages/core/src/crypto.ts`)
- PBKDF2-SHA256 **600,000 iterations** (OWASP 2024) — do NOT reduce
- AES-256-GCM for vault encryption — do NOT switch to CBC/CTR
- HMAC-SHA256 for vault integrity — always verify before decryption
- All crypto via `crypto.subtle` (Web Crypto API) — no third-party libs

### 3. Vault storage
- Web: `localStorage` (ramz_vault_v2)
- Mobile: `expo-secure-store` (hardware-backed on supported devices)
- Desktop: Tauri WebView uses same localStorage as the web build

### 4. Auto-lock
- 5 minutes idle → lock (`AUTO_LOCK_MS` in `Shell.tsx`)
- 5 failed attempts → 15-minute brute-force lockout
- Clipboard cleared 30 seconds after copy

### 5. Imports
- Always import from `@ramz/core` — never duplicate crypto/API logic
- Mobile storage (`apps/mobile/lib/storage.ts`) mirrors web storage API but uses SecureStore

### 6. RTL / Styling
- `<html lang="ar" dir="rtl">` — do not remove
- No shadcn/ui — custom Arabic RTL design system in `globals.css`
- Font: Tajawal (Arabic + Latin) + Space Mono (code/monospace)
- All font loading via `next/font/google` — no Google Fonts CDN

### 7. Type safety
- All vault entries validated through Zod (`packages/core/src/types.ts`)
- Use `@ramz/core` types — `VaultEntry`, `ApiKeys`, `HistoryEntry`, `EncryptedVault`
- TypeScript strict mode — no `any` except justified with a comment

---

## API Integrations

| Service | Key field | Notes |
|---------|-----------|-------|
| VirusTotal v3 | `apiKeys.vt` | Rate limit: 4 req/min (free) |
| HIBP | `apiKeys.hibp` | Requires paid key for breach lookup |
| urlscan.io | `apiKeys.urlscan` | Optional |
| Google Safe Browsing v4 | `apiKeys.gsb` | Free within quota |
| HIBP Pwned Passwords | none | k-Anonymity, always available |

All keys stored in localStorage (web) / SecureStore (mobile). Never hardcode.

---

## What NOT to change

- `deriveKey` iterations (600k) — security critical
- `hmacIntegrity` / `verifyIntegrity` — vault corruption guard
- `output: 'export'` in `next.config.ts` — static build required for Tauri
- `robots: "noindex, nofollow"` in `layout.tsx` — security tool, must not index
- `AUTO_LOCK_MS` below 300000ms (5 min) without user config
- CSP (prod-only `<meta http-equiv="Content-Security-Policy">` in `apps/web/app/layout.tsx` and `apps/desktop/src-tauri/tauri.conf.json`)

---

## Adding a New Module

1. Create `apps/web/components/modules/YourModule.tsx`
2. Add tab entry to `TABS` array in `Shell.tsx`
3. Add icon to `IC` in `components/ui/Icons.tsx` if needed
4. Add any new types to `packages/core/src/types.ts`
5. Mirror mobile screen in `apps/mobile/app/(tabs)/your-screen.tsx`
