import { z } from "zod";

// ── Vault Entry ───────────────────────────────────────────────────────────────

export const VaultEntryTypeSchema = z.enum([
  "login",
  "card",
  "note",
  "identity",
  "key",
]);
export type VaultEntryType = z.infer<typeof VaultEntryTypeSchema>;

export const VaultEntrySchema = z.object({
  id:        z.string(),
  type:      VaultEntryTypeSchema,
  title:     z.string().min(1).max(200),
  username:  z.string().max(200).optional().default(""),
  password:  z.string().max(5000).optional().default(""),
  url:       z.string().max(2000).optional().default(""),
  notes:     z.string().max(50000).optional().default(""),
  tags:      z.array(z.string().max(50)).default([]),
  favorite:  z.boolean().default(false),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type VaultEntry = z.infer<typeof VaultEntrySchema>;

// ── Encrypted Vault (localStorage shape) ─────────────────────────────────────

export interface EncryptedVault {
  /** AES-256-GCM ciphertext — base64 */
  ciphertext: string;
  /** GCM IV — base64 */
  iv:         string;
  /** PBKDF2 salt for encryption key — base64 */
  salt:       string;
  /** HMAC-SHA256 integrity tag — base64 */
  hmac:       string;
}

// ── API Keys ──────────────────────────────────────────────────────────────────

export interface ApiKeys {
  vt:      string;
  hibp:    string;
  urlscan: string;
  gsb:     string;
}

// ── History ───────────────────────────────────────────────────────────────────

export interface HistoryEntry {
  id:        string;
  type:      "url" | "file" | "email";
  target:    string;
  timestamp: string;
  verdict:   "clean" | "suspicious" | "malicious" | "unknown";
  sources:   string[];
}

// ── Lock State ────────────────────────────────────────────────────────────────

export interface LockState {
  attempts:    number;
  lockedUntil: number | null;
}

// ── Scan Result ───────────────────────────────────────────────────────────────

export interface ScanResult {
  positives?: number;
  total?:     number;
  error?:     string;
}

// ── HIBP ──────────────────────────────────────────────────────────────────────

export interface HibpBreach {
  Name:         string;
  Domain:       string;
  BreachDate:   string;
  Description:  string;
  DataClasses:  string[];
  PwnCount:     number;
  IsVerified:   boolean;
}
