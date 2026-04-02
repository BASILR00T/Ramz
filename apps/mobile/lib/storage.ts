import * as SecureStore from "expo-secure-store";
import type { EncryptedVault, ApiKeys, HistoryEntry, LockState } from "@ramz/core";

const KEYS = {
  VAULT:      "ramz_vault_v2",
  API_KEYS:   "ramz_api_keys",
  HISTORY:    "ramz_history",
  LOCK_STATE: "ramz_lock_state",
} as const;

async function safeGet<T>(key: string, fallback: T): Promise<T> {
  try {
    const v = await SecureStore.getItemAsync(key);
    return v ? (JSON.parse(v) as T) : fallback;
  } catch {
    return fallback;
  }
}

async function safeSet(key: string, value: unknown): Promise<void> {
  try {
    await SecureStore.setItemAsync(key, JSON.stringify(value));
  } catch {
    /* SecureStore quota / unavailable */
  }
}

// ── Vault ────────────────────────────────────────────────────────────────────

export async function loadEncryptedVault(): Promise<EncryptedVault | null> {
  return safeGet<EncryptedVault | null>(KEYS.VAULT, null);
}

export async function saveEncryptedVault(vault: EncryptedVault): Promise<void> {
  await safeSet(KEYS.VAULT, vault);
}

export async function clearVault(): Promise<void> {
  await SecureStore.deleteItemAsync(KEYS.VAULT);
}

// ── API Keys ─────────────────────────────────────────────────────────────────

const DEFAULT_KEYS: ApiKeys = { vt: "", hibp: "", urlscan: "", gsb: "" };

export async function loadApiKeys(): Promise<ApiKeys> {
  return safeGet<ApiKeys>(KEYS.API_KEYS, DEFAULT_KEYS);
}

export async function saveApiKeys(keys: ApiKeys): Promise<void> {
  await safeSet(KEYS.API_KEYS, keys);
}

// ── History ──────────────────────────────────────────────────────────────────

const MAX_HISTORY = 200;

export async function loadHistory(): Promise<HistoryEntry[]> {
  return safeGet<HistoryEntry[]>(KEYS.HISTORY, []);
}

export async function saveHistory(history: HistoryEntry[]): Promise<void> {
  const trimmed = history.slice(-MAX_HISTORY);
  await safeSet(KEYS.HISTORY, trimmed);
}

// ── Lock State ────────────────────────────────────────────────────────────────

export async function loadLockState(): Promise<LockState> {
  return safeGet<LockState>(KEYS.LOCK_STATE, { attempts: 0, lockedUntil: null });
}

export async function saveLockState(state: LockState): Promise<void> {
  await safeSet(KEYS.LOCK_STATE, state);
}

export async function clearLockState(): Promise<void> {
  await SecureStore.deleteItemAsync(KEYS.LOCK_STATE);
}
