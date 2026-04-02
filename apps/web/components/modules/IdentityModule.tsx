"use client";

import React, { useState } from "react";
import { IC } from "../ui/Icons";
import { checkHIBP } from "@ramz/core";
import type { ApiKeys, HistoryEntry } from "@ramz/core";

interface Breach {
  Name: string;
  Domain: string;
  BreachDate: string;
  Description: string;
  DataClasses: string[];
  PwnCount: number;
  IsVerified: boolean;
}

interface IdentityModuleProps {
  apiKeys: ApiKeys;
  onHistory: (entry: HistoryEntry) => void;
}

/** Strip HTML tags — HIBP descriptions contain anchor tags; render as plain text */
function stripHtml(html: string): string {
  return html.replace(/<[^>]+>/g, "");
}

export default function IdentityModule({ apiKeys, onHistory }: IdentityModuleProps) {
  const [email, setEmail]       = useState("");
  const [checking, setChecking] = useState(false);
  const [breaches, setBreaches] = useState<Breach[] | null>(null);
  const [error, setError]       = useState("");
  const [pwInput, setPwInput]   = useState("");
  const [pwResult, setPwResult] = useState<{ pwned: boolean; count: number } | null>(null);
  const [pwChecking, setPwChecking] = useState(false);

  const hasHIBP = !!apiKeys.hibp;

  async function handleEmailCheck(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim()) return;
    setChecking(true);
    setBreaches(null);
    setError("");

    try {
      const result = await checkHIBP(email.trim(), apiKeys.hibp);
      setBreaches(result.breaches as Breach[]);
      onHistory({
        id:        crypto.randomUUID(),
        type:      "email",
        target:    email.trim(),
        timestamp: new Date().toISOString(),
        verdict:   result.breaches.length > 0 ? "malicious" : "clean",
        sources:   ["HIBP"],
      });
    } catch (err) {
      setError(String(err));
    } finally {
      setChecking(false);
    }
  }

  async function handlePasswordCheck(e: React.FormEvent) {
    e.preventDefault();
    if (!pwInput) return;
    setPwChecking(true);
    setPwResult(null);

    try {
      // k-Anonymity: only send first 5 chars of SHA-1 hash — password never leaves device
      const encoder = new TextEncoder();
      const data    = encoder.encode(pwInput);
      const buffer  = await crypto.subtle.digest("SHA-1", data);
      const hex     = Array.from(new Uint8Array(buffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();

      const prefix = hex.slice(0, 5);
      const suffix = hex.slice(5);

      const res  = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { "Add-Padding": "true" },
      });
      const text = await res.text();
      const lines = text.split("\n");
      const match = lines.find((l) => l.startsWith(suffix));
      const count = match ? parseInt(match.split(":")[1], 10) : 0;

      setPwResult({ pwned: count > 0, count });
    } catch (err) {
      setError(String(err));
    } finally {
      setPwChecking(false);
    }
  }

  return (
    <section className="module">
      <div className="module-header">
        <h2 className="module-title">
          <IC.Eye /> كشف التسريبات
        </h2>
      </div>

      {/* Email breach check */}
      <div className="card">
        <h3 className="card-title">
          <IC.Mail /> فحص تسريبات البريد الإلكتروني
        </h3>
        <p className="card-desc">
          تحقق إذا ظهر بريدك في قواعد بيانات التسريبات عبر{" "}
          <strong>Have I Been Pwned</strong>.
          {!hasHIBP && (
            <span className="warn-inline"> (يتطلب مفتاح HIBP API)</span>
          )}
        </p>

        <form onSubmit={handleEmailCheck} className="scan-form">
          <div className="input-group">
            <IC.Mail />
            <input
              type="email"
              className="form-input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@example.com"
              required
            />
          </div>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={checking || !hasHIBP}
            title={!hasHIBP ? "أضف مفتاح HIBP أولاً" : undefined}
          >
            {checking ? <><IC.Refresh /> جاري الفحص...</> : <><IC.Search /> فحص</>}
          </button>
        </form>

        {error && (
          <div className="result-card malicious">
            <IC.AlertTriangle /> {error}
          </div>
        )}

        {breaches !== null && (
          <div className="breaches-wrap">
            {breaches.length === 0 ? (
              <div className="result-card clean">
                <div className="result-header">
                  <IC.Check />
                  <span className="result-badge clean">آمن</span>
                  <span>لم يُعثر على تسريبات لهذا البريد.</span>
                </div>
              </div>
            ) : (
              <>
                <div className="result-card malicious">
                  <div className="result-header">
                    <IC.AlertTriangle />
                    <span className="result-badge malicious">مُسرَّب</span>
                    <span>
                      ظهر بريدك في <strong>{breaches.length}</strong> تسريب.
                      غيّر كلمات مرورك فوراً.
                    </span>
                  </div>
                </div>

                <div className="breach-list">
                  {breaches.map((b) => (
                    <div key={b.Name} className="breach-card">
                      <div className="breach-header">
                        <span className="breach-name">{b.Name}</span>
                        {b.Domain && (
                          <span className="breach-domain">{b.Domain}</span>
                        )}
                        <span className="breach-date">{b.BreachDate}</span>
                        {!b.IsVerified && (
                          <span className="tag warn">غير مؤكد</span>
                        )}
                      </div>
                      {/* Strip HTML from HIBP description to prevent XSS */}
                      <p className="breach-desc">{stripHtml(b.Description)}</p>
                      <div className="breach-meta">
                        <span className="breach-count">
                          {b.PwnCount.toLocaleString("ar-SA")} حساب مخترق
                        </span>
                        <div className="breach-classes">
                          {b.DataClasses.map((cls) => (
                            <span key={cls} className="tag">{cls}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {/* Password k-Anonymity check */}
      <div className="card" style={{ marginTop: "var(--sp-4)" }}>
        <h3 className="card-title">
          <IC.Key /> فحص كلمة المرور (بدون إرسالها)
        </h3>
        <p className="card-desc">
          نستخدم k-Anonymity: يُرسَل أول 5 أحرف فقط من بصمة SHA-1.
          كلمة مرورك الكاملة لا تغادر جهازك أبداً.
        </p>

        <form onSubmit={handlePasswordCheck} className="scan-form">
          <div className="input-group">
            <IC.Lock />
            <input
              type="password"
              className="form-input"
              value={pwInput}
              onChange={(e) => setPwInput(e.target.value)}
              placeholder="أدخل كلمة المرور للفحص"
              autoComplete="off"
              required
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={pwChecking}>
            {pwChecking ? <><IC.Refresh /> جاري الفحص...</> : <><IC.Search /> فحص</>}
          </button>
        </form>

        {pwResult && (
          <div className={`result-card ${pwResult.pwned ? "malicious" : "clean"}`}>
            <div className="result-header">
              {pwResult.pwned ? <IC.AlertTriangle /> : <IC.Check />}
              <span className={`result-badge ${pwResult.pwned ? "malicious" : "clean"}`}>
                {pwResult.pwned ? "مُسرَّبة" : "آمنة"}
              </span>
              <span>
                {pwResult.pwned
                  ? `ظهرت هذه الكلمة ${pwResult.count.toLocaleString("ar-SA")} مرة في تسريبات سابقة. لا تستخدمها.`
                  : "لم تُعثر على هذه الكلمة في قواعد بيانات التسريبات."}
              </span>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
