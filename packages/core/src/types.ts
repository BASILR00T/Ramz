import { z } from "zod";

// ── Vault Types ──────────────────────────────────────────────────────────────

export const VaultEntryTypeSchema = z.enum([
  "password",
  "secret",
  "note",
  "file",
  "card",
]);
export type VaultEntryType = z.infer<typeof VaultEntryTypeSchema>;

export const VaultPasswordEntrySchema = z.object({
  id: z.number(),
  type: z.literal("password"),
  title: z.string().min(1).max(200),
  username: z.string().max(200).optional(),
  url: z
    .string()
    .max(2000)
    .optional()
    .refine(
      (v) => !v || v.startsWith("https://") || v.startsWith("http://"),
      "Invalid URL"
    ),
  password: z.string().min(1).max(1000),
  note: z.string().max(5000).optional(),
  category: z.string().max(50).optional(),
  tags: z.array(z.string().max(30)).max(10).optional(),
  createdAt: z.number(),
  updatedAt: z.number().optional(),
  lastUsed: z.number().optional(),
});

export const VaultSecretEntrySchema = z.object({
  id: z.number(),
  type: z.literal("secret"),
  title: z.string().min(1).max(200),
  secretType: z.string().max(50).optional(),
  service: z.string().max(200).optional(),
  secret: z.string().min(1).max(10000),
  note: z.string().max(5000).optional(),
  category: z.string().max(50).optional(),
  tags: z.array(z.string().max(30)).max(10).optional(),
  createdAt: z.number(),
  updatedAt: z.number().optional(),
});

export const VaultNoteEntrySchema = z.object({
  id: z.number(),
  type: z.literal("note"),
  title: z.string().min(1).max(200),
  note: z.string().min(1).max(50000),
  category: z.string().max(50).optional(),
  tags: z.array(z.string().max(30)).max(10).optional(),
  createdAt: z.number(),
  updatedAt: z.number().optional(),
});

export const VaultFileEntrySchema = z.object({
  id: z.number(),
  type: z.literal("file"),
  title: z.string().min(1).max(200),
  note: z.string().max(5000).optional(),
  file: z
    .object({
      name: z.string().max(255),
      size: z.number().max(5 * 1024 * 1024),
      mime: z.string().max(100),
      data: z.string(), // base64
    })
    .optional(),
  category: z.string().max(50).optional(),
  tags: z.array(z.string().max(30)).max(10).optional(),
  createdAt: z.number(),
  updatedAt: z.number().optional(),
});

export const VaultCardEntrySchema = z.object({
  id: z.number(),
  type: z.literal("card"),
  title: z.string().min(1).max(200),
  cardNumber: z
    .string()
    .max(20)
    .regex(/^\d[\d\s-]{10,18}\d$/, "Invalid card number"),
  cardHolder: z.string().max(100).optional(),
  expiry: z
    .string()
    .max(7)
    .regex(/^(0[1-9]|1[0-2])\/\d{2,4}$/, "Invalid expiry MM/YY")
    .optional(),
  cvv: z.string().max(4).optional(),
  bank: z.string().max(100).optional(),
  note: z.string().max(5000).optional(),
  category: z.string().max(50).optional(),
  tags: z.array(z.string().max(30)).max(10).optional(),
  createdAt: z.number(),
  updatedAt: z.number().optional(),
});

export const VaultEntrySchema = z.discriminatedUnion("type", [
  VaultPasswordEntrySchema,
  VaultSecretEntrySchema,
  VaultNoteEntrySchema,
  VaultFileEntrySchema,
  VaultCardEntrySchema,
]);
export type VaultEntry = z.infer<typeof VaultEntrySchema>;

// ── Encrypted Vault Storage ──────────────────────────────────────────────────

export interface EncryptedVault {
  version: number;
  salt: number[];
  iv: number[];
  hmacSalt: number[];
  hmac: number[];
  data: number[];
}

// ── Scan Result Types ────────────────────────────────────────────────────────

export interface VtAnalysisStats {
  malicious: number;
  suspicious: number;
  undetected: number;
  harmless: number;
  timeout?: number;
}

export interface VtEngineResult {
  name: string;
  result: string | null;
  category: string;
}

export interface FileScanResult {
  hash: string;
  name: string;
  size: number;
  vtDetections: number;
  vtTotal: number;
  vtEngines: VtEngineResult[];
  vtData: unknown;
  pwnCount: number;
  error?: string;
}

export interface UrlScanSource {
  safe: boolean | null;
  label: string;
  notes?: string;
  error?: string;
  pending?: boolean;
  uuid?: string;
  scanUrl?: string;
  vtData?: unknown;
}

export interface UrlScanResult {
  url: string;
  sources: Record<string, UrlScanSource>;
  verdict: string;
  dangerous: boolean;
  error?: string;
}

export interface PhishingResult {
  score: number;
  indicators: string[];
  extResult: {
    url: string;
    detections: number;
    total: number;
  } | null;
  urlsFound: number;
  error?: string;
}

export interface LeakResult {
  email: string;
  breached: boolean;
  breaches: HibpBreach[];
  source: "HIBP" | "demo";
  error?: string;
}

export interface HibpBreach {
  Name: string;
  BreachDate: string;
  Description?: string;
  PwnCount?: number;
  DataClasses?: string[];
}

// ── API Keys ─────────────────────────────────────────────────────────────────

export interface ApiKeys {
  vt: string;
  hibp: string;
  urlscan: string;
  gsb: string;
}

// ── History ──────────────────────────────────────────────────────────────────

export interface HistoryEntry {
  type: "vault" | "file" | "url" | "phishing" | "leak" | "pwned";
  value: string;
  time: number;
}

// ── Vault Lock State ─────────────────────────────────────────────────────────

export interface LockState {
  attempts: number;
  lockedUntil: number | null;
}
