"use client";

import type { ApiKeys, EncryptedVault, HistoryEntry, LockState } from "@ramz/core";

const KEYS = {
  VAULT: "ramz_vault_v2",
  API_KEYS: "ramz_api_keys",
  HISTORY: "ramz_history",
  LOCK_STATE: "ramz_lock_state",
} as const;

function safeGet<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v ? (JSON.parse(v) as T) : fallback;
  } catch {
    return fallback;
  }
}

function safeSet(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* quota exceeded — swallow */
  }
}

// ── Vault ────────────────────────────────────────────────────────────────────

export function loadEncryptedVault(): EncryptedVault | null {
  return safeGet<EncryptedVault | null>(KEYS.VAULT, null);
}

export function saveEncryptedVault(vault: EncryptedVault): void {
  safeSet(KEYS.VAULT, vault);
}

export function clearVault(): void {
  localStorage.removeItem(KEYS.VAULT);
}

// ── API Keys ─────────────────────────────────────────────────────────────────

const DEFAULT_KEYS: ApiKeys = { vt: "", hibp: "", urlscan: "", gsb: "" };

export function loadApiKeys(): ApiKeys {
  return safeGet<ApiKeys>(KEYS.API_KEYS, DEFAULT_KEYS);
}

export function saveApiKeys(keys: ApiKeys): void {
  safeSet(KEYS.API_KEYS, keys);
}

// ── History ──────────────────────────────────────────────────────────────────

const MAX_HISTORY = 200;

export function loadHistory(): HistoryEntry[] {
  return safeGet<HistoryEntry[]>(KEYS.HISTORY, []);
}

export function saveHistory(history: HistoryEntry[]): void {
  // Keep only the last MAX_HISTORY entries
  const trimmed = history.slice(-MAX_HISTORY);
  safeSet(KEYS.HISTORY, trimmed);
}

// ── Lock State (brute-force protection) ──────────────────────────────────────

export function loadLockState(): LockState {
  return safeGet<LockState>(KEYS.LOCK_STATE, { attempts: 0, lockedUntil: null });
}

export function saveLockState(state: LockState): void {
  safeSet(KEYS.LOCK_STATE, state);
}

export function clearLockState(): void {
  localStorage.removeItem(KEYS.LOCK_STATE);
}
