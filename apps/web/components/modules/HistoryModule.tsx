"use client";

import React, { useState } from "react";
import { IC } from "../ui/Icons";
import type { HistoryEntry } from "@ramz/core";

interface HistoryModuleProps {
  history: HistoryEntry[];
  onClear: () => void;
}

const TYPE_LABELS: Record<string, string> = {
  url:   "رابط",
  file:  "ملف",
  email: "بريد",
};

const VERDICT_LABELS: Record<string, { label: string; cls: string }> = {
  clean:      { label: "آمن",    cls: "clean" },
  suspicious: { label: "مشبوه", cls: "suspicious" },
  malicious:  { label: "خطير",  cls: "malicious" },
  unknown:    { label: "غير معروف", cls: "unknown" },
};

function VerdictBadge({ verdict }: { verdict: string }) {
  const v = VERDICT_LABELS[verdict] ?? VERDICT_LABELS.unknown;
  return <span className={`result-badge ${v.cls}`}>{v.label}</span>;
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString("ar-SA", {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

export default function HistoryModule({ history, onClear }: HistoryModuleProps) {
  const [filter, setFilter]   = useState<"all" | "url" | "file" | "email">("all");
  const [search, setSearch]   = useState("");
  const [confirmClear, setConfirmClear] = useState(false);

  const filtered = history
    .filter((e) => filter === "all" || e.type === filter)
    .filter((e) => {
      const q = search.toLowerCase();
      return !q || e.target.toLowerCase().includes(q);
    })
    .slice()
    .reverse(); // newest first

  function handleClear() {
    onClear();
    setConfirmClear(false);
  }

  return (
    <section className="module">
      <div className="module-header">
        <h2 className="module-title">
          <IC.History /> سجل العمليات
        </h2>
        {history.length > 0 && (
          !confirmClear ? (
            <button
              onClick={() => setConfirmClear(true)}
              className="btn btn-danger btn-sm"
            >
              <IC.Trash /> مسح
            </button>
          ) : (
            <div className="confirm-row">
              <span>هل أنت متأكد؟</span>
              <button onClick={() => setConfirmClear(false)} className="btn btn-ghost btn-sm">إلغاء</button>
              <button onClick={handleClear} className="btn btn-danger btn-sm">
                <IC.Trash /> نعم، امسح
              </button>
            </div>
          )
        )}
      </div>

      {history.length === 0 ? (
        <div className="empty-state">
          <IC.History />
          <p>لم تُجرَ أي عمليات فحص بعد.</p>
        </div>
      ) : (
        <>
          {/* Controls */}
          <div className="vault-controls">
            <div className="input-group search-group">
              <IC.Search />
              <input
                className="form-input"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="بحث في السجل..."
              />
            </div>
            <div className="filter-chips">
              {(["all", "url", "file", "email"] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setFilter(t)}
                  className={`type-chip ${filter === t ? "active" : ""}`}
                >
                  {t === "all" ? "الكل" : TYPE_LABELS[t]}
                </button>
              ))}
            </div>
          </div>

          <div className="vault-stats">
            {history.length} عملية · يُعرض {filtered.length}
          </div>

          <div className="entry-list">
            {filtered.length === 0 ? (
              <p className="muted">لا نتائج تطابق الفلتر.</p>
            ) : (
              filtered.map((entry) => (
                <div key={entry.id} className={`history-card ${entry.verdict}`}>
                  <div className="history-row">
                    <span className="history-type tag">
                      {TYPE_LABELS[entry.type] ?? entry.type}
                    </span>
                    <VerdictBadge verdict={entry.verdict} />
                    <span className="history-target monospace" title={entry.target}>
                      {entry.target.length > 60
                        ? entry.target.slice(0, 60) + "…"
                        : entry.target}
                    </span>
                  </div>
                  <div className="history-meta">
                    <span className="history-date">{formatDate(entry.timestamp)}</span>
                    {entry.sources.length > 0 && (
                      <span className="history-sources muted">
                        {entry.sources.join(" · ")}
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </>
      )}
    </section>
  );
}
