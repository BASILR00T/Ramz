# Security Documentation — رَمز | Ramz

## Threat Model

رَمز protects against the following threats:

| Threat | Mitigation |
|--------|-----------|
| Vault stolen from disk/localStorage | AES-256-GCM encryption, PBKDF2-600k KDF |
| Weak master password | Strength indicator, minimum 8 chars |
| Brute-force of master password | 5-attempt limit + 15-min lockout |
| HMAC bypass / vault tampering | HMAC-SHA256 verified before every decrypt |
| Idle session hijack | 5-minute auto-lock |
| Clipboard sniffing | Clipboard cleared after 30 seconds |
| Malicious URLs | VirusTotal + GSB + heuristic detection |
| Credential breach exposure | HIBP email check + k-Anonymity password check |
| Password reuse | Unique password generator (CSPRNG) |
| Search engine indexing | `noindex, nofollow` robots directive |
| XSS via HIBP descriptions | HTML stripped via `stripHtml()` — plain text only |
| CSP bypass | Strict CSP in next.config.ts + Tauri tauri.conf.json |

**Out of scope:**
- Compromised OS / keylogger
- Physical device seizure with unlocked session
- Malicious browser extensions with full page access

---

## Cryptographic Specifications

### Key Derivation

```
Algorithm : PBKDF2
Hash      : SHA-256
Iterations: 600,000  (OWASP 2024 minimum recommendation)
Salt      : 128 bits (16 bytes, crypto.getRandomValues)
Output    : 256-bit AES-GCM key (non-extractable CryptoKey)
```

**Why 600k?** OWASP 2024 recommends at least 600,000 iterations for PBKDF2-SHA256. This makes offline dictionary attacks computationally expensive (~600ms on modern hardware per attempt).

### Vault Encryption

```
Algorithm : AES-256-GCM
Key size  : 256 bits
IV        : 96 bits (12 bytes, crypto.getRandomValues, fresh per save)
Auth tag  : 128 bits (GCM default)
Plaintext : JSON.stringify(VaultEntry[])
```

AES-GCM provides both **confidentiality** (encryption) and **integrity** (authentication tag). Any bit flip in the ciphertext causes decryption to fail, preventing silent corruption attacks.

### Vault Integrity (HMAC)

```
Algorithm : HMAC-SHA256
Key       : derived from password + salt
Input     : password + ":" + base64(salt)
Purpose   : Fast pre-check before expensive PBKDF2 KDF
```

The HMAC serves as a "wrong password" detector. Comparison is done via `crypto.subtle.verify` which performs constant-time comparison, preventing timing attacks.

### Password Generator

```
Charset   : Configurable (uppercase A-Z, digits 0-9, symbols)
Algorithm : Rejection sampling over crypto.getRandomValues
Output    : Cryptographically uniform random selection
```

Rejection sampling ensures uniform distribution — no modulo bias that would skew character frequency.

### k-Anonymity (Password Breach Check)

```
1. SHA-1 hash the password locally
2. Send ONLY the first 5 hex chars (prefix) to HIBP
3. HIBP returns all hashes with that prefix
4. Match locally — password never transmitted
```

The full password and its complete SHA-1 hash never leave the device.

---

## Storage Security

### Web / Desktop
- Vault stored in `localStorage` as `ramz_vault_v2`
- Plaintext never written to disk — only ciphertext
- API keys stored in `localStorage` (acceptable risk for API keys vs credential data)
- Lock state (brute-force counter) stored in `localStorage`

### Mobile
- All keys stored in `expo-secure-store`
- iOS: backed by the iOS Keychain (hardware-backed on devices with Secure Enclave)
- Android: backed by Android Keystore (hardware-backed on API 23+)

---

## Content Security Policy

Web app CSP (production only, via `apps/web/app/layout.tsx` `<meta http-equiv="Content-Security-Policy">`):

```
default-src 'self'
script-src 'self'
style-src 'self' 'unsafe-inline'
img-src 'self' data: https:
connect-src 'self'
  https://www.virustotal.com
  https://haveibeenpwned.com
  https://urlscan.io
  https://safebrowsing.googleapis.com
  https://api.pwnedpasswords.com
  https://checkurl.phishtank.com
font-src 'self'
frame-ancestors 'none'
```

Notes:
- Next.js `output: "export"` does not support `headers()` in `next.config.ts`, so CSP must be set by the host/CDN or injected via HTML.
- The desktop app has an additional CSP in `apps/desktop/src-tauri/tauri.conf.json` enforced at the WebView level (dev CSP is relaxed to allow dev tooling).

---

## XSS Prevention

1. All user content rendered via React (auto-escaping via JSX)
2. HIBP breach descriptions: HTML tags stripped via `stripHtml()` before render
3. URL inputs validated as `type="url"` in forms
4. No dynamic code execution, no direct innerHTML assignment, no dynamic script injection

---

## Brute-Force Protection

```
On failed unlock:
  attempts++
  if attempts >= 5:
    lockedUntil = Date.now() + 15 * 60 * 1000  (15 minutes)
    saveLockState({ attempts, lockedUntil })

On successful unlock:
  clearLockState()

On lock screen render:
  if lockedUntil && Date.now() < lockedUntil:
    show countdown, disable form
```

Lock state persists across page reloads (stored in localStorage/SecureStore).

---

## Auto-Lock

```
Events that reset the idle timer:
  mousedown, keydown, touchstart, scroll

AUTO_LOCK_MS = 5 * 60 * 1000  (5 minutes)

On timeout:
  setCryptoKey(null)   — key cleared from memory
  setVault([])         — decrypted entries cleared
  setUnlocked(false)   — shows lock screen
```

The `CryptoKey` object is non-extractable — it cannot be read from JS memory, only used for encrypt/decrypt operations via `crypto.subtle`.

---

## Dependency Security

`packages/core` has **zero runtime dependencies** except Zod (validation only). All crypto is built on the browser's native `crypto.subtle` API — no third-party cryptography libraries.

Web dependencies:
- `next` — framework, well-audited
- `react` — framework, well-audited
- `zod` — validation only, no network or crypto

Mobile adds:
- `expo-secure-store` — hardware-backed storage
- `expo-crypto` — native crypto bridge

---

## Responsible Disclosure

If you discover a security vulnerability, please report it via GitHub Security Advisories:
`https://github.com/BASILR00T/Ramz/security/advisories/new`

Do **not** open a public issue for security vulnerabilities.
