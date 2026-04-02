"use client";

import React, { useState, useRef } from "react";
import { IC } from "../ui/Icons";
import {
  scanUrl,
  scanFile,
  checkPhishing,
  checkGoogleSafeBrowsing,
} from "@ramz/core";
import type { ApiKeys, ScanResult, HistoryEntry } from "@ramz/core";

// ── Types ─────────────────────────────────────────────────────────────────────

type ScanMode = "url" | "file";

interface Verdict {
  level: "clean" | "suspicious" | "malicious" | "unknown";
  label: string;
  detail: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function verdictFromResult(result: ScanResult): Verdict {
  if (result.error) return { level: "unknown", label: "خطأ", detail: result.error };
  const pos = result.positives ?? 0;
  const tot = result.total ?? 0;
  if (pos === 0 && tot > 0) return { level: "clean",     label: "آمن",     detail: `0 / ${tot} محرك` };
  if (pos <= 3)             return { level: "suspicious", label: "مشبوه",   detail: `${pos} / ${tot} محرك` };
  return                         { level: "malicious",  label: "خطير",    detail: `${pos} / ${tot} محرك` };
}

function levelIcon(level: Verdict["level"]) {
  switch (level) {
    case "clean":      return <IC.Check />;
    case "suspicious": return <IC.AlertTriangle />;
    case "malicious":  return <IC.X />;
    default:           return <IC.Radar />;
  }
}

// ── Result Card ───────────────────────────────────────────────────────────────

interface ResultCardProps {
  label: string;
  verdict: Verdict;
  raw?: Record<string, unknown> | null;
}

function ResultCard({ label, verdict, raw }: ResultCardProps) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className={`result-card ${verdict.level}`}>
      <div className="result-header">
        <span className="result-source">{label}</span>
        <span className={`result-badge ${verdict.level}`}>
          {levelIcon(verdict.level)}
          {verdict.label}
        </span>
        <span className="result-detail">{verdict.detail}</span>
        {raw && (
          <button
            className="btn btn-ghost btn-xs"
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? <IC.EyeOff /> : <IC.Eye />}
          </button>
        )}
      </div>
      {expanded && raw && (
        <pre className="result-raw">
          {JSON.stringify(raw, null, 2)}
        </pre>
      )}
    </div>
  );
}

// ── Heuristics Panel ──────────────────────────────────────────────────────────

interface HeuristicsProps {
  url: string;
}

function HeuristicsPanel({ url }: HeuristicsProps) {
  const result = checkPhishing(url);
  const level  = result.score >= 3 ? "malicious" : result.score >= 1 ? "suspicious" : "clean";
  return (
    <ResultCard
      label="تحليل هيورستيكي (بدون إنترنت)"
      verdict={{
        level,
        label:  level === "clean" ? "آمن" : level === "suspicious" ? "مشبوه" : "خطير",
        detail: result.flags.length > 0 ? result.flags.join(" · ") : "لا علامات مشبوهة",
      }}
      raw={result as unknown as Record<string, unknown>}
    />
  );
}

// ── ScannerModule ─────────────────────────────────────────────────────────────

interface ScannerModuleProps {
  apiKeys: ApiKeys;
  onHistory: (entry: HistoryEntry) => void;
}

export default function ScannerModule({ apiKeys, onHistory }: ScannerModuleProps) {
  const [mode, setMode]       = useState<ScanMode>("url");
  const [urlInput, setUrlInput] = useState("");
  const [file, setFile]       = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<Array<{ label: string; verdict: Verdict; raw?: Record<string, unknown> | null }> | null>(null);
  const [heuristicsUrl, setHeuristicsUrl] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const hasVT   = !!apiKeys.vt;
  const hasGSB  = !!apiKeys.gsb;
  const hasUS   = !!apiKeys.urlscan;
  const hasAny  = hasVT || hasGSB || hasUS;

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    if (scanning) return;

    setScanning(true);
    setResults(null);
    setHeuristicsUrl(null);

    const cards: Array<{ label: string; verdict: Verdict; raw?: Record<string, unknown> | null }> = [];

    if (mode === "url") {
      const url = urlInput.trim();
      if (!url) { setScanning(false); return; }

      // Always run heuristics
      setHeuristicsUrl(url);

      // VirusTotal
      if (hasVT) {
        try {
          const vtRes = await scanUrl(url, apiKeys.vt);
          cards.push({ label: "VirusTotal", verdict: verdictFromResult(vtRes), raw: vtRes as unknown as Record<string, unknown> });
        } catch (err) {
          cards.push({ label: "VirusTotal", verdict: { level: "unknown", label: "خطأ", detail: String(err) } });
        }
      }

      // Google Safe Browsing
      if (hasGSB) {
        try {
          const gsbRes = await checkGoogleSafeBrowsing(url, apiKeys.gsb);
          const isSafe = gsbRes.matches.length === 0;
          cards.push({
            label: "Google Safe Browsing",
            verdict: isSafe
              ? { level: "clean",     label: "آمن",  detail: "لا تطابق في القوائم السوداء" }
              : { level: "malicious", label: "خطير", detail: gsbRes.matches.map((m: { threatType: string }) => m.threatType).join(", ") },
            raw: gsbRes as unknown as Record<string, unknown>,
          });
        } catch (err) {
          cards.push({ label: "Google Safe Browsing", verdict: { level: "unknown", label: "خطأ", detail: String(err) } });
        }
      }

      // urlscan.io
      if (hasUS) {
        try {
          const usRes = await scanUrl(url, apiKeys.urlscan, "urlscan");
          cards.push({ label: "urlscan.io", verdict: verdictFromResult(usRes), raw: usRes as unknown as Record<string, unknown> });
        } catch (err) {
          cards.push({ label: "urlscan.io", verdict: { level: "unknown", label: "خطأ", detail: String(err) } });
        }
      }

      const overallLevel = cards.some((c) => c.verdict.level === "malicious")
        ? "malicious"
        : cards.some((c) => c.verdict.level === "suspicious")
        ? "suspicious"
        : "clean";

      onHistory({
        id: crypto.randomUUID(),
        type: "url",
        target: url,
        timestamp: new Date().toISOString(),
        verdict: overallLevel,
        sources: cards.map((c) => c.label),
      });
    }

    if (mode === "file" && file) {
      if (hasVT) {
        try {
          const vtRes = await scanFile(file, apiKeys.vt);
          cards.push({ label: "VirusTotal", verdict: verdictFromResult(vtRes), raw: vtRes as unknown as Record<string, unknown> });
        } catch (err) {
          cards.push({ label: "VirusTotal", verdict: { level: "unknown", label: "خطأ", detail: String(err) } });
        }
      } else {
        cards.push({ label: "VirusTotal", verdict: { level: "unknown", label: "مفتاح مطلوب", detail: "أضف مفتاح VirusTotal في قسم مفاتيح API" } });
      }

      const overallLevel = cards.some((c) => c.verdict.level === "malicious")
        ? "malicious"
        : cards.some((c) => c.verdict.level === "suspicious")
        ? "suspicious"
        : "clean";

      onHistory({
        id: crypto.randomUUID(),
        type: "file",
        target: file.name,
        timestamp: new Date().toISOString(),
        verdict: overallLevel,
        sources: cards.map((c) => c.label),
      });
    }

    setResults(cards);
    setScanning(false);
  }

  return (
    <section className="module">
      <div className="module-header">
        <h2 className="module-title">
          <IC.Shield /> فاحص التهديدات
        </h2>
      </div>

      {/* Mode toggle */}
      <div className="mode-tabs">
        <button
          className={`mode-tab ${mode === "url" ? "active" : ""}`}
          onClick={() => { setMode("url"); setResults(null); }}
        >
          <IC.Link /> رابط URL
        </button>
        <button
          className={`mode-tab ${mode === "file" ? "active" : ""}`}
          onClick={() => { setMode("file"); setResults(null); }}
        >
          <IC.File /> ملف
        </button>
      </div>

      {!hasAny && (
        <div className="info-banner">
          <IC.Key />
          <span className="bidi">
            أضف مفاتيح <bdi dir="ltr" className="code">API</bdi> في قسم «مفاتيح{" "}
            <bdi dir="ltr" className="code">API</bdi>» لتفعيل الفحص السحابي. الفحص
            الهيورستيكي للروابط متاح دائماً بدون مفاتيح.
          </span>
        </div>
      )}

      <form onSubmit={handleScan} className="scan-form">
        {mode === "url" ? (
          <div className="input-group">
            <IC.Link />
            <input
              type="url"
              className="form-input"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="https://example.com/path?query=value"
              required
            />
          </div>
        ) : (
          <div className="file-drop" onClick={() => fileRef.current?.click()}>
            <IC.Upload />
            <span>{file ? file.name : "انقر لاختيار ملف أو اسحب هنا"}</span>
            {file && (
              <span className="file-size">
                {(file.size / 1024).toFixed(1)} KB
              </span>
            )}
            <input
              ref={fileRef}
              type="file"
              className="hidden"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </div>
        )}

        <button
          type="submit"
          className="btn btn-primary"
          disabled={scanning || (mode === "file" && !file)}
        >
          {scanning ? (
            <><IC.Refresh /> جاري الفحص...</>
          ) : (
            <><IC.Radar /> فحص الآن</>
          )}
        </button>
      </form>

      {/* Results */}
      {(results || heuristicsUrl) && (
        <div className="results-section">
          <h3 className="results-title">نتائج الفحص</h3>

          {heuristicsUrl && <HeuristicsPanel url={heuristicsUrl} />}

          {results?.map((r, i) => (
            <ResultCard key={i} label={r.label} verdict={r.verdict} raw={r.raw ?? null} />
          ))}

          {results?.length === 0 && !heuristicsUrl && (
            <p className="muted bidi">
              لم يُجرَ أي فحص. أضف مفاتيح <bdi dir="ltr" className="code">API</bdi>{" "}
              أو أدخل رابطاً.
            </p>
          )}
        </div>
      )}
    </section>
  );
}
