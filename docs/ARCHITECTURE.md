# Architecture — رَمز | Ramz

## Overview

رَمز is a Turborepo monorepo with three platform apps sharing a single `packages/core` library. All cryptographic and API logic lives in core; platform apps handle UI and storage only.

```
┌─────────────────────────────────────────────────────────┐
│                     User Interface                       │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│   │  Web (Next)  │  │Desktop(Tauri)│  │Mobile (Expo) │  │
│   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│          │                 │                  │          │
│   ┌──────▼─────────────────▼──────────────────▼───────┐  │
│   │              packages/core                        │  │
│   │  crypto.ts  |  api.ts  |  heuristics.ts  | types  │  │
│   └───────────────────────────────────────────────────┘  │
│                                                          │
│   ┌───────────────┐        ┌──────────────────────────┐  │
│   │  localStorage │        │    expo-secure-store     │  │
│   │  (web/desktop)│        │       (mobile)           │  │
│   └───────────────┘        └──────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                     ↕ (optional, user-initiated)
             External Scan APIs (VT, HIBP, urlscan, GSB)
```

---

## packages/core

The shared library has **zero runtime dependencies** — only Zod for validation.

### `types.ts`
Zod schemas for all five vault entry types (login, card, note, identity, key) and all scan/result types. Single source of truth for the data model.

### `crypto.ts`
| Function | Description |
|----------|-------------|
| `deriveKey(password, salt)` | PBKDF2-SHA256, 600k iterations → CryptoKey |
| `encryptVault(entries, key)` | AES-256-GCM, random IV per call → `{ ciphertext, iv }` |
| `decryptVault(vault, key)` | AES-256-GCM decrypt + JSON.parse |
| `hmacIntegrity(password, salt)` | HMAC-SHA256 of `password:salt` → base64 |
| `verifyIntegrity(password, salt, stored)` | Constant-time compare via `crypto.subtle.verify` |
| `generateSalt()` | 16 random bytes → base64 |
| `generatePassword(length, opts)` | Rejection-sampling CSPRNG |

### `api.ts`
| Function | API Used |
|----------|----------|
| `scanUrl(url, key)` | VirusTotal v3 |
| `scanUrl(url, key, 'urlscan')` | urlscan.io submit + poll |
| `scanFile(file, key)` | VirusTotal v3 file upload |
| `checkHIBP(email, key)` | HIBP v3 breachedaccount |
| `checkGoogleSafeBrowsing(url, key)` | GSB v4 |

### `heuristics.ts`
Offline phishing detection (no network). Scores 0–10 across 10 rules:
1. IP address as hostname
2. Excessive subdomains (>3)
3. Suspicious TLD (.tk, .ml, .ga, .cf, .gq, .xyz)
4. URL length > 100 chars
5. @ symbol in URL path
6. Homograph / punycode (xn--)
7. Brand keywords in subdomain (paypal, apple, google, amazon, bank...)
8. Double slash in path (non-standard)
9. Query string > 200 chars
10. Non-HTTPS scheme

---

## Web App (`apps/web`)

Next.js 16 with `output: 'export'` — fully static, no server.

```
app/
├── layout.tsx          HTML shell, fonts (Tajawal + Space Mono)
├── page.tsx            Re-exports Shell
└── globals.css         Full Arabic RTL design system

components/
├── Shell.tsx           Lock screen + app shell + auto-lock logic
├── ui/Icons.tsx        SVG icon component library
└── modules/
    ├── VaultModule.tsx       Credential vault CRUD
    ├── ScannerModule.tsx     URL + file threat scanning
    ├── IdentityModule.tsx    Email breach + password k-anon check
    ├── ExtensionModule.tsx   Browser extension guide
    ├── ApiKeysModule.tsx     API key storage management
    └── HistoryModule.tsx     Scan history log

lib/
└── storage.ts          localStorage wrappers (vault, keys, history, lock)
```

### Lock Screen Flow

```
Mount → loadEncryptedVault()
  ├── null → isNewVault = true → show "Create vault" form
  └── exists → isNewVault = false → show "Unlock" form

Submit password →
  ├── New: generateSalt → deriveKey → encryptVault([]) → saveEncryptedVault
  └── Existing: verifyIntegrity (HMAC) → deriveKey → decryptVault
       ├── success → setCryptoKey, setVault, setUnlocked(true)
       └── failure → increment attempts → brute-force lockout check
```

---

## Desktop App (`apps/desktop`)

Tauri 2 with minimal Rust backend. The frontend is the Next.js static build (`apps/web/out`).

- `tauri.conf.json` — points `frontendDist` to `../../web/out`
- `src-tauri/src/lib.rs` — minimal: just focuses the window on startup
- CSP in `tauri.conf.json` — restricts network to known scan API domains
- No custom Tauri commands needed — all logic runs in the WebView

### Build Flow
```
pnpm --filter @ramz/web build     →  apps/web/out/  (static files)
pnpm --filter desktop build →  bundles out/ + Rust binary → .exe/.app/.deb
```

---

## Mobile App (`apps/mobile`)

Expo 52 with Expo Router (file-based routing).

```
app/
├── _layout.tsx         Root layout (StatusBar, SafeAreaProvider, Stack)
├── index.tsx           Lock screen (mirrors web Shell lock logic)
└── (tabs)/
    ├── _layout.tsx     Bottom tab bar
    ├── vault.tsx       Vault viewer (read-only on mobile)
    ├── scanner.tsx     URL scan with heuristics + optional VT
    ├── identity.tsx    Email breach check
    ├── apikeys.tsx     API key management
    └── history.tsx     Scan history

lib/
└── storage.ts          expo-secure-store wrappers (async, mirrors web API)
```

**Key difference from web**: Mobile uses `expo-secure-store` instead of `localStorage`. This provides hardware-backed encryption on supported iOS/Android devices. The API is async (all functions return Promises).

---

## Data Flow — Vault Unlock

```
User enters password
       │
       ▼
verifyIntegrity(password, vault.salt, vault.hmac)
  [HMAC-SHA256 constant-time compare]
       │
    ✓  │  ✗ → increment failCount → lockout?
       ▼
deriveKey(password, vault.salt)
  [PBKDF2-SHA256, 600,000 iterations]
       │
       ▼
decryptVault(vault, cryptoKey)
  [AES-256-GCM authenticated decrypt]
       │
       ▼
VaultEntry[] → React state (in-memory only)
       │
       ▼
On any change: encryptVault(entries, cryptoKey) → saveEncryptedVault
  [new random IV every save]
```

---

## Data Flow — URL Scan

```
User submits URL
       │
       ├──► checkPhishing(url)           [always, offline, 0ms]
       │     └── score + flags
       │
       ├──► scanUrl(url, keys.vt)        [if VT key set]
       │     └── positives/total
       │
       ├──► checkGoogleSafeBrowsing(url) [if GSB key set]
       │     └── matches[]
       │
       └──► scanUrl(url, keys.urlscan)   [if urlscan key set]
             └── verdict

Results → display ResultCards → addHistory(entry)
```

---

## Security Boundaries

| Trust Boundary | Mechanism |
|----------------|-----------|
| Vault at rest | AES-256-GCM + PBKDF2-600k |
| Vault integrity | HMAC-SHA256 before decrypt |
| Master password in memory | Stored only as `CryptoKey` (non-extractable) |
| Clipboard | Auto-clear after 30s |
| Brute force | 5 attempts → 15-min lockout |
| Idle lock | 5-min timeout on mouse/keyboard/touch |
| API keys | localStorage (web) / SecureStore (mobile) |
| Network | CSP restricts to known scan API domains |
| Indexing | `noindex, nofollow` in robots meta |
