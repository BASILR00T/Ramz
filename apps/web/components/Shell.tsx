"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import { IC } from "./ui/Icons";
import VaultModule from "./modules/VaultModule";
import ScannerModule from "./modules/ScannerModule";
import IdentityModule from "./modules/IdentityModule";
import ExtensionModule from "./modules/ExtensionModule";
import ApiKeysModule from "./modules/ApiKeysModule";
import HistoryModule from "./modules/HistoryModule";
import {
  loadEncryptedVault,
  saveEncryptedVault,
  loadApiKeys,
  loadHistory,
  saveHistory,
  loadLockState,
  saveLockState,
  clearLockState,
} from "../lib/storage";
import {
  deriveKey,
  encryptVault,
  decryptVault,
  generateSalt,
  hmacIntegrity,
  verifyIntegrity,
  generatePassword,
} from "@ramz/core";
import type { VaultEntry, ApiKeys, HistoryEntry } from "@ramz/core";

// ── Constants ────────────────────────────────────────────────────────────────

const AUTO_LOCK_MS = 5 * 60 * 1000; // 5 minutes idle
const MAX_ATTEMPTS = 5;
const LOCK_DURATION_MS = 15 * 60 * 1000; // 15 minutes brute-force lockout

const TABS = [
  { id: "vault",     label: "الخزينة",    Icon: IC.Lock },
  { id: "scanner",   label: "الفاحص",     Icon: IC.Shield },
  { id: "identity",  label: "الهوية",     Icon: IC.Eye },
  { id: "extension", label: "الإضافة",    Icon: IC.Puzzle },
  { id: "apikeys",   label: "مفاتيح API", Icon: IC.Key },
  { id: "history",   label: "السجل",      Icon: IC.History },
] as const;

type TabId = (typeof TABS)[number]["id"];

// ── Lock Screen ──────────────────────────────────────────────────────────────

interface LockScreenProps {
  isNewVault: boolean;
  onUnlock: (password: string) => void;
  lockState: { attempts: number; lockedUntil: number | null };
}

function LockScreen({ isNewVault, onUnlock, lockState }: LockScreenProps) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm]   = useState("");
  const [showPw, setShowPw]     = useState(false);
  const [error, setError]       = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const lockedUntil = lockState.lockedUntil;
  const [remaining, setRemaining] = useState(0);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    if (!lockedUntil) return;
    const tick = () => setRemaining(Math.max(0, lockedUntil - Date.now()));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [lockedUntil]);

  const isLocked = !!lockedUntil && Date.now() < lockedUntil;

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (isLocked) return;
    if (isNewVault && password !== confirm) {
      setError("كلمات المرور غير متطابقة");
      return;
    }
    if (password.length < 8) {
      setError("يجب أن تتكوّن كلمة المرور من 8 أحرف على الأقل");
      return;
    }
    onUnlock(password);
  }

  const remainingMin = Math.ceil(remaining / 60000);

  return (
    <div className="lock-screen">
      <div className="lock-card">
        <div className="lock-icon">
          <IC.Shield />
        </div>
        <h1 className="lock-title">رَمز</h1>
        <p className="lock-subtitle">منظومة الأمان الصفري المعرفة</p>

        {isLocked ? (
          <div className="lock-alert">
            <IC.AlertTriangle />
            <span>
              الحساب مقفل لـ {remainingMin} دقيقة بسبب محاولات فاشلة متعددة
            </span>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="lock-form">
            {isNewVault && (
              <p className="lock-hint">
                أوّل مرة؟ أنشئ كلمة مرور رئيسية لحماية خزينتك.
              </p>
            )}

            {!isNewVault && lockState.attempts > 0 && (
              <div className="lock-attempts">
                {MAX_ATTEMPTS - lockState.attempts} محاولة متبقية
              </div>
            )}

            <div className="input-group">
              <IC.Lock />
              <input
                ref={inputRef}
                type={showPw ? "text" : "password"}
                value={password}
                onChange={(e) => { setPassword(e.target.value); setError(""); }}
                placeholder="كلمة المرور الرئيسية"
                autoComplete={isNewVault ? "new-password" : "current-password"}
                className="pw-input"
              />
              <button
                type="button"
                onClick={() => setShowPw((v) => !v)}
                className="show-pw-btn"
                aria-label={showPw ? "إخفاء" : "إظهار"}
              >
                {showPw ? <IC.EyeOff /> : <IC.Eye />}
              </button>
            </div>

            {isNewVault && (
              <div className="input-group">
                <IC.Lock />
                <input
                  type={showPw ? "text" : "password"}
                  value={confirm}
                  onChange={(e) => { setConfirm(e.target.value); setError(""); }}
                  placeholder="تأكيد كلمة المرور"
                  autoComplete="new-password"
                  className="pw-input"
                />
              </div>
            )}

            {error && (
              <div className="lock-error">
                <IC.AlertTriangle />
                <span>{error}</span>
              </div>
            )}

            <button type="submit" className="btn btn-primary btn-full">
              {isNewVault ? "إنشاء الخزينة" : "فتح الخزينة"}
            </button>
          </form>
        )}

        <p className="lock-footer">
          بدون خادم · بدون سحابة · لا بيانات تغادر جهازك
        </p>
      </div>
    </div>
  );
}

// ── Shell ────────────────────────────────────────────────────────────────────

export default function Shell() {
  const [tab, setTab]           = useState<TabId>("vault");
  const [unlocked, setUnlocked] = useState(false);
  const [cryptoKey, setCryptoKey]   = useState<CryptoKey | null>(null);
  const [vault, setVault]       = useState<VaultEntry[]>([]);
  const [apiKeys, setApiKeys]   = useState<ApiKeys>({ vt: "", hibp: "", urlscan: "", gsb: "" });
  const [history, setHistory]   = useState<HistoryEntry[]>([]);
  const [lockState, setLockState] = useState(loadLockState);
  const [isNewVault, setIsNewVault] = useState(false);
  const [unlockError, setUnlockError] = useState("");
  const idleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Check if new vault on mount
  useEffect(() => {
    const existing = loadEncryptedVault();
    setIsNewVault(!existing);
    setApiKeys(loadApiKeys());
    setHistory(loadHistory());
  }, []);

  // Auto-lock on idle
  const resetIdleTimer = useCallback(() => {
    if (idleTimer.current) clearTimeout(idleTimer.current);
    idleTimer.current = setTimeout(() => {
      lock();
    }, AUTO_LOCK_MS);
  }, []);

  useEffect(() => {
    if (!unlocked) return;
    const events = ["mousedown", "keydown", "touchstart", "scroll"] as const;
    events.forEach((e) => window.addEventListener(e, resetIdleTimer));
    resetIdleTimer();
    return () => {
      events.forEach((e) => window.removeEventListener(e, resetIdleTimer));
      if (idleTimer.current) clearTimeout(idleTimer.current);
    };
  }, [unlocked, resetIdleTimer]);

  function lock() {
    setCryptoKey(null);
    setVault([]);
    setUnlocked(false);
    if (idleTimer.current) clearTimeout(idleTimer.current);
  }

  async function handleUnlock(password: string) {
    // Check brute-force lockout
    const ls = loadLockState();
    if (ls.lockedUntil && Date.now() < ls.lockedUntil) return;

    const existing = loadEncryptedVault();

    if (!existing) {
      // New vault — create
      const salt = generateSalt();
      const key  = await deriveKey(password, salt);
      const hmac = await hmacIntegrity(password, salt);
      const encrypted = await encryptVault([], key);
      saveEncryptedVault({ ...encrypted, salt, hmac });
      clearLockState();
      setLockState({ attempts: 0, lockedUntil: null });
      setCryptoKey(key);
      setVault([]);
      setUnlocked(true);
      setIsNewVault(false);
      return;
    }

    // Existing vault — verify HMAC then decrypt
    try {
      const valid = await verifyIntegrity(password, existing.salt, existing.hmac);
      if (!valid) throw new Error("wrong password");

      const key     = await deriveKey(password, existing.salt);
      const entries = await decryptVault(existing, key);
      clearLockState();
      setLockState({ attempts: 0, lockedUntil: null });
      setCryptoKey(key);
      setVault(entries);
      setUnlocked(true);
    } catch {
      const attempts = ls.attempts + 1;
      const lockedUntil = attempts >= MAX_ATTEMPTS ? Date.now() + LOCK_DURATION_MS : null;
      const next = { attempts, lockedUntil };
      saveLockState(next);
      setLockState(next);
      setUnlockError("كلمة المرور غير صحيحة");
    }
  }

  async function persistVault(entries: VaultEntry[]) {
    if (!cryptoKey) return;
    const existing = loadEncryptedVault();
    if (!existing) return;
    const encrypted = await encryptVault(entries, cryptoKey);
    saveEncryptedVault({ ...encrypted, salt: existing.salt, hmac: existing.hmac });
    setVault(entries);
  }

  function addHistory(entry: HistoryEntry) {
    const next = [...history, entry];
    saveHistory(next);
    setHistory(next);
  }

  if (!unlocked) {
    return (
      <LockScreen
        isNewVault={isNewVault}
        onUnlock={handleUnlock}
        lockState={lockState}
      />
    );
  }

  return (
    <div className="shell">
      {/* ── Header ── */}
      <header className="shell-header">
        <div className="header-brand">
          <IC.Shield />
          <span className="brand-name">رَمز</span>
          <span className="brand-tag">منظومة الأمان</span>
        </div>
        <button
          onClick={lock}
          className="btn btn-ghost btn-sm"
          title="قفل الخزينة"
          aria-label="قفل"
        >
          <IC.Lock />
          <span>قفل</span>
        </button>
      </header>

      {/* ── Nav ── */}
      <nav className="shell-nav" role="tablist" aria-label="أقسام التطبيق">
        {TABS.map(({ id, label, Icon }) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
            className={`nav-tab ${tab === id ? "active" : ""}`}
          >
            <Icon />
            <span>{label}</span>
          </button>
        ))}
      </nav>

      {/* ── Content ── */}
      <main className="shell-main" role="tabpanel">
        {tab === "vault"     && (
          <VaultModule
            vault={vault}
            onSave={persistVault}
          />
        )}
        {tab === "scanner"   && (
          <ScannerModule
            apiKeys={apiKeys}
            onHistory={addHistory}
          />
        )}
        {tab === "identity"  && (
          <IdentityModule
            apiKeys={apiKeys}
            onHistory={addHistory}
          />
        )}
        {tab === "extension" && <ExtensionModule />}
        {tab === "apikeys"   && (
          <ApiKeysModule
            apiKeys={apiKeys}
            onSave={setApiKeys}
          />
        )}
        {tab === "history"   && (
          <HistoryModule
            history={history}
            onClear={() => { saveHistory([]); setHistory([]); }}
          />
        )}
      </main>
    </div>
  );
}
