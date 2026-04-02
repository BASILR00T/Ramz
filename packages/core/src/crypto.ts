/**
 * @ramz/core — Cryptographic utilities
 *
 * Security hardening vs original:
 * - PBKDF2 iterations: 600,000 (was 100,000) — NIST SP 800-63B & OWASP 2024
 * - HMAC-SHA256 integrity check on vault ciphertext (authenticate-then-encrypt)
 * - Separate PBKDF2 derivation for HMAC key to avoid key reuse
 * - Explicit error messages that do not leak timing or plaintext
 * - Password generator uses full Unicode-safe charset via crypto.getRandomValues
 */

import type { EncryptedVault } from "./types.js";

// ── Constants ────────────────────────────────────────────────────────────────

const PBKDF2_ITERATIONS = 600_000; // OWASP 2024 minimum for SHA-256
const PBKDF2_HASH = "SHA-256";
const AES_KEY_LENGTH = 256;
const IV_LENGTH = 12; // AES-GCM recommended
const SALT_LENGTH = 16;
const VAULT_VERSION = 2;

const PASSWORD_CHARSET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";

// ── Password Generator ───────────────────────────────────────────────────────

/**
 * Cryptographically secure password generator.
 * Uses rejection sampling to eliminate modular bias.
 */
export function generatePassword(length = 24): string {
  const charset = PASSWORD_CHARSET;
  const array = new Uint32Array(length * 2); // oversample for rejection
  crypto.getRandomValues(array);
  const result: string[] = [];
  const max = Math.floor(0xffffffff / charset.length) * charset.length;
  for (let i = 0; i < array.length && result.length < length; i++) {
    const val = array[i];
    if (val !== undefined && val < max) {
      result.push(charset[val % charset.length]!);
    }
  }
  // Fallback: if rejection sampling didn't yield enough chars (very unlikely)
  while (result.length < length) {
    const extra = new Uint32Array(1);
    crypto.getRandomValues(extra);
    result.push(charset[extra[0]! % charset.length]!);
  }
  return result.join("");
}

// ── Hashing ──────────────────────────────────────────────────────────────────

export async function sha256File(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return hexEncode(new Uint8Array(hash));
}

export async function sha1Hash(str: string): Promise<string> {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-1", buf);
  return hexEncode(new Uint8Array(hash)).toUpperCase();
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Entropy & Strength ───────────────────────────────────────────────────────

export function calcEntropy(password: string): number {
  const poolSizes = [
    [/[a-z]/, 26],
    [/[A-Z]/, 26],
    [/[0-9]/, 10],
    [/[^a-zA-Z0-9]/, 32],
  ] as const;
  const pool = poolSizes.reduce(
    (acc, [regex, size]) => acc + (regex.test(password) ? size : 0),
    0
  );
  return password.length * Math.log2(pool || 1);
}

export function timeToCrack(entropy: number): string {
  const seconds = Math.pow(2, entropy) / 1e12; // 1 trillion guesses/sec
  if (seconds < 1) return "أقل من ثانية";
  if (seconds < 60) return `${Math.floor(seconds)} ثانية`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} دقيقة`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} ساعة`;
  if (seconds < 31_536_000) return `${Math.floor(seconds / 86400)} يوم`;
  if (seconds < 3.15e9) return `${Math.floor(seconds / 31_536_000)} سنة`;
  return "مليارات السنين";
}

// ── Key Derivation ───────────────────────────────────────────────────────────

async function deriveKey(
  password: string,
  salt: Uint8Array,
  usage: KeyUsage[]
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_HASH,
    },
    keyMaterial,
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    false,
    usage
  );
}

async function deriveHmacKey(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_HASH,
    },
    keyMaterial,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign", "verify"]
  );
}

// ── Vault Encryption ─────────────────────────────────────────────────────────

/**
 * Encrypts vault data with AES-256-GCM and authenticates with HMAC-SHA256.
 * Uses separate salts for encryption key and HMAC key to prevent key reuse.
 */
export async function encryptVault(
  data: unknown,
  password: string
): Promise<EncryptedVault> {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const hmacSalt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const [encKey, hmacKey] = await Promise.all([
    deriveKey(password, salt, ["encrypt"]),
    deriveHmacKey(password, hmacSalt),
  ]);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encKey,
    enc.encode(JSON.stringify(data))
  );

  const ciphertextBytes = new Uint8Array(ciphertext);

  // HMAC over: version || salt || hmacSalt || iv || ciphertext
  const hmacPayload = buildHmacPayload(
    VAULT_VERSION,
    salt,
    hmacSalt,
    iv,
    ciphertextBytes
  );
  const hmacBytes = new Uint8Array(
    await crypto.subtle.sign("HMAC", hmacKey, hmacPayload)
  );

  return {
    version: VAULT_VERSION,
    salt: Array.from(salt),
    iv: Array.from(iv),
    hmacSalt: Array.from(hmacSalt),
    hmac: Array.from(hmacBytes),
    data: Array.from(ciphertextBytes),
  };
}

/**
 * Decrypts vault data. Verifies HMAC before decryption to prevent
 * padding oracle attacks and detect tampered ciphertext.
 *
 * Throws a generic error on failure — does not indicate whether
 * the password was wrong vs data was tampered.
 */
export async function decryptVault(
  encData: EncryptedVault,
  password: string
): Promise<unknown> {
  const salt = new Uint8Array(encData.salt);
  const iv = new Uint8Array(encData.iv);
  const hmacSalt = new Uint8Array(encData.hmacSalt);
  const hmacBytes = new Uint8Array(encData.hmac);
  const ciphertextBytes = new Uint8Array(encData.data);

  const [decKey, hmacKey] = await Promise.all([
    deriveKey(password, salt, ["decrypt"]),
    deriveHmacKey(password, hmacSalt),
  ]);

  // Verify HMAC first (authenticate-then-decrypt)
  const hmacPayload = buildHmacPayload(
    encData.version ?? VAULT_VERSION,
    salt,
    hmacSalt,
    iv,
    ciphertextBytes
  );
  const valid = await crypto.subtle.verify(
    "HMAC",
    hmacKey,
    hmacBytes,
    hmacPayload
  );

  if (!valid) {
    throw new Error("INTEGRITY_FAIL");
  }

  let decrypted: ArrayBuffer;
  try {
    decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      decKey,
      ciphertextBytes
    );
  } catch {
    throw new Error("DECRYPTION_FAIL");
  }

  return JSON.parse(new TextDecoder().decode(decrypted));
}

// ── Internal Helpers ─────────────────────────────────────────────────────────

function buildHmacPayload(
  version: number,
  salt: Uint8Array,
  hmacSalt: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array {
  const verBuf = new Uint8Array([version]);
  const total =
    verBuf.length +
    salt.length +
    hmacSalt.length +
    iv.length +
    ciphertext.length;
  const payload = new Uint8Array(total);
  let offset = 0;
  for (const part of [verBuf, salt, hmacSalt, iv, ciphertext]) {
    payload.set(part, offset);
    offset += part.length;
  }
  return payload;
}
