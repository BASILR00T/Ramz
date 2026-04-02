"use client";

import React, { useState, useRef } from "react";
import { IC } from "../ui/Icons";
import { generatePassword } from "@ramz/core";
import type { VaultEntry } from "@ramz/core";

// ── Types ─────────────────────────────────────────────────────────────────────

type EntryType = VaultEntry["type"];

const TYPE_LABELS: Record<EntryType, string> = {
  login:    "حساب",
  card:     "بطاقة",
  note:     "ملاحظة",
  identity: "هوية",
  key:      "مفتاح API",
};

const TYPE_ICONS: Record<EntryType, React.FC> = {
  login:    IC.Key,
  card:     IC.CreditCard,
  note:     IC.Note,
  identity: IC.Shield,
  key:      IC.Zap,
};

const EMPTY_ENTRY = (): Omit<VaultEntry, "id" | "createdAt" | "updatedAt"> => ({
  type:     "login",
  title:    "",
  username: "",
  password: "",
  url:      "",
  notes:    "",
  tags:     [],
  favorite: false,
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function newId() {
  return crypto.randomUUID();
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString("ar-SA", {
    year: "numeric", month: "short", day: "numeric",
  });
}

// ── Password Strength ─────────────────────────────────────────────────────────

function passwordStrength(pw: string): { score: number; label: string } {
  if (!pw) return { score: 0, label: "" };
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const labels = ["ضعيفة جداً", "ضعيفة", "متوسطة", "جيدة", "قوية", "ممتازة"];
  const idx = Math.min(score, 5);
  return { score, label: labels[idx] ?? labels[0] ?? "" };
}

// ── Entry Form ────────────────────────────────────────────────────────────────

interface EntryFormProps {
  initial?: VaultEntry;
  onSave: (e: VaultEntry) => void;
  onCancel: () => void;
}

function EntryForm({ initial, onSave, onCancel }: EntryFormProps) {
  const [form, setForm] = useState<Omit<VaultEntry, "id" | "createdAt" | "updatedAt">>(
    initial
      ? { type: initial.type, title: initial.title, username: initial.username ?? "",
          password: initial.password ?? "", url: initial.url ?? "", notes: initial.notes ?? "",
          tags: initial.tags ?? [], favorite: initial.favorite ?? false }
      : EMPTY_ENTRY()
  );
  const [showPw, setShowPw]   = useState(false);
  const [copied, setCopied]   = useState(false);
  const [tagInput, setTagInput] = useState("");

  function set<K extends keyof typeof form>(k: K, v: (typeof form)[K]) {
    setForm((f) => ({ ...f, [k]: v }));
  }

  function handleGenerate() {
    const pw = generatePassword(20, { upper: true, digits: true, symbols: true });
    set("password", pw);
  }

  function handleCopyPw() {
    if (!form.password) return;
    navigator.clipboard.writeText(form.password).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      // Clear clipboard after 30s
      setTimeout(() => navigator.clipboard.writeText(""), 30000);
    });
  }

  function addTag() {
    const t = tagInput.trim();
    if (t && !form.tags.includes(t)) {
      set("tags", [...form.tags, t]);
      setTagInput("");
    }
  }

  function removeTag(t: string) {
    set("tags", form.tags.filter((x) => x !== t));
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!form.title.trim()) return;
    const now = new Date().toISOString();
    onSave({
      ...form,
      id:        initial?.id ?? newId(),
      createdAt: initial?.createdAt ?? now,
      updatedAt: now,
    });
  }

  const pw = form.password ?? "";
  const strength = passwordStrength(pw);

  return (
    <form onSubmit={handleSubmit} className="entry-form">
      {/* Type selector */}
      <div className="form-row type-selector">
        {(Object.keys(TYPE_LABELS) as EntryType[]).map((t) => {
          const Icon = TYPE_ICONS[t];
          return (
            <button
              key={t}
              type="button"
              className={`type-chip ${form.type === t ? "active" : ""}`}
              onClick={() => set("type", t)}
            >
              <Icon />
              {TYPE_LABELS[t]}
            </button>
          );
        })}
      </div>

      {/* Title */}
      <label className="form-label">
        الاسم
        <input
          required
          className="form-input"
          value={form.title}
          onChange={(e) => set("title", e.target.value)}
          placeholder="اسم الحساب أو البطاقة..."
        />
      </label>

      {/* Username */}
      {form.type !== "note" && form.type !== "key" && (
        <label className="form-label">
          اسم المستخدم / البريد
          <div className="input-group">
            <IC.Mail />
            <input
              className="form-input"
              value={form.username}
              onChange={(e) => set("username", e.target.value)}
              placeholder="user@example.com"
              autoComplete="off"
            />
          </div>
        </label>
      )}

      {/* Password / Secret */}
      {(form.type === "login" || form.type === "key") && (
        <label className="form-label">
          {form.type === "key" ? "قيمة المفتاح" : "كلمة المرور"}
          <div className="input-group">
            <IC.Lock />
            <input
              type={showPw ? "text" : "password"}
              className="form-input"
              value={pw}
              onChange={(e) => set("password", e.target.value)}
              placeholder="••••••••••••"
              autoComplete="new-password"
            />
            <button type="button" onClick={() => setShowPw((v) => !v)} className="show-pw-btn" title="إظهار / إخفاء">
              {showPw ? <IC.EyeOff /> : <IC.Eye />}
            </button>
            <button type="button" onClick={handleCopyPw} className="copy-btn" title={copied ? "تم النسخ!" : "نسخ"}>
              {copied ? <IC.Check /> : <IC.Copy />}
            </button>
            {form.type === "login" && (
              <button type="button" onClick={handleGenerate} className="gen-btn" title="توليد كلمة مرور">
                <IC.Zap />
              </button>
            )}
          </div>

          {/* Strength bar */}
          {pw && (
            <div className="strength-bar-wrap">
              <div className="strength-bar">
                {[1,2,3,4,5].map((i) => (
                  <div
                    key={i}
                    className={`strength-seg ${i <= strength.score ? `s${strength.score}` : ""}`}
                  />
                ))}
              </div>
              <span className="strength-label">{strength.label}</span>
            </div>
          )}
        </label>
      )}

      {/* URL */}
      {(form.type === "login" || form.type === "card") && (
        <label className="form-label">
          الرابط
          <div className="input-group">
            <IC.Link />
            <input
              type="url"
              className="form-input"
              value={form.url}
              onChange={(e) => set("url", e.target.value)}
              placeholder="https://example.com"
            />
          </div>
        </label>
      )}

      {/* Notes */}
      <label className="form-label">
        ملاحظات
        <textarea
          className="form-input form-textarea"
          value={form.notes}
          onChange={(e) => set("notes", e.target.value)}
          placeholder="ملاحظات إضافية..."
          rows={3}
        />
      </label>

      {/* Tags */}
      <div className="form-label">
        الوسوم
        <div className="tag-input-row">
          <input
            className="form-input tag-input"
            value={tagInput}
            onChange={(e) => setTagInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addTag(); } }}
            placeholder="أضف وسماً..."
          />
          <button type="button" onClick={addTag} className="btn btn-ghost btn-sm">
            <IC.Plus />
          </button>
        </div>
        <div className="tags-row">
          {form.tags.map((t) => (
            <span key={t} className="tag">
              {t}
              <button type="button" onClick={() => removeTag(t)} className="tag-remove">
                <IC.X />
              </button>
            </span>
          ))}
        </div>
      </div>

      {/* Actions */}
      <div className="form-actions">
        <button type="button" onClick={onCancel} className="btn btn-ghost">
          إلغاء
        </button>
        <button type="submit" className="btn btn-primary">
          <IC.Check />
          حفظ
        </button>
      </div>
    </form>
  );
}

// ── Entry Card ────────────────────────────────────────────────────────────────

interface EntryCardProps {
  entry: VaultEntry;
  onEdit: () => void;
  onDelete: () => void;
}

function EntryCard({ entry, onEdit, onDelete }: EntryCardProps) {
  const [showPw, setShowPw]   = useState(false);
  const [copied, setCopied]   = useState<"user" | "pw" | null>(null);

  function copy(text: string, field: "user" | "pw") {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(field);
      setTimeout(() => setCopied(null), 2000);
      setTimeout(() => navigator.clipboard.writeText(""), 30000);
    });
  }

  const Icon = TYPE_ICONS[entry.type];

  return (
    <div className="entry-card">
      <div className="entry-header">
        <div className="entry-icon">
          <Icon />
        </div>
        <div className="entry-meta">
          <span className="entry-title">{entry.title}</span>
          {entry.username && (
            <span className="entry-sub">{entry.username}</span>
          )}
        </div>
        <div className="entry-actions">
          <button onClick={onEdit} className="btn btn-ghost btn-xs" title="تعديل">
            <IC.Edit />
          </button>
          <button onClick={onDelete} className="btn btn-danger btn-xs" title="حذف">
            <IC.Trash />
          </button>
        </div>
      </div>

      {entry.username && (
        <div className="entry-field">
          <span className="field-label">المستخدم</span>
          <div className="field-value-row">
            <span className="field-value">{entry.username}</span>
            <button
              onClick={() => copy(entry.username!, "user")}
              className="copy-btn-sm"
              title={copied === "user" ? "تم!" : "نسخ"}
            >
              {copied === "user" ? <IC.Check /> : <IC.Copy />}
            </button>
          </div>
        </div>
      )}

      {entry.password && (
        <div className="entry-field">
          <span className="field-label">كلمة المرور</span>
          <div className="field-value-row">
            <span className="field-value monospace">
              {showPw ? entry.password : "••••••••••••"}
            </span>
            <button onClick={() => setShowPw((v) => !v)} className="copy-btn-sm" title="إظهار">
              {showPw ? <IC.EyeOff /> : <IC.Eye />}
            </button>
            <button
              onClick={() => copy(entry.password!, "pw")}
              className="copy-btn-sm"
              title={copied === "pw" ? "تم!" : "نسخ"}
            >
              {copied === "pw" ? <IC.Check /> : <IC.Copy />}
            </button>
          </div>
        </div>
      )}

      {entry.url && (
        <div className="entry-field">
          <span className="field-label">الرابط</span>
          <a href={entry.url} className="field-link" target="_blank" rel="noopener noreferrer">
            {entry.url}
          </a>
        </div>
      )}

      {entry.notes && (
        <div className="entry-field">
          <span className="field-label">ملاحظات</span>
          <span className="field-value notes">{entry.notes}</span>
        </div>
      )}

      {entry.tags.length > 0 && (
        <div className="entry-tags">
          {entry.tags.map((t) => (
            <span key={t} className="tag">{t}</span>
          ))}
        </div>
      )}

      <div className="entry-date">
        آخر تعديل: {formatDate(entry.updatedAt)}
      </div>
    </div>
  );
}

// ── VaultModule ───────────────────────────────────────────────────────────────

interface VaultModuleProps {
  vault: VaultEntry[];
  onSave: (entries: VaultEntry[]) => void;
}

export default function VaultModule({ vault, onSave }: VaultModuleProps) {
  const [mode, setMode]     = useState<"list" | "add" | "edit">("list");
  const [editing, setEditing] = useState<VaultEntry | null>(null);
  const [search, setSearch]   = useState("");
  const [filter, setFilter]   = useState<EntryType | "all">("all");
  const [deleting, setDeleting] = useState<string | null>(null);

  function startAdd()  { setEditing(null); setMode("add"); }
  function startEdit(e: VaultEntry) { setEditing(e); setMode("edit"); }
  function cancel()    { setMode("list"); setEditing(null); }

  function handleSave(entry: VaultEntry) {
    let next: VaultEntry[];
    if (editing) {
      next = vault.map((v) => (v.id === entry.id ? entry : v));
    } else {
      next = [...vault, entry];
    }
    onSave(next);
    cancel();
  }

  function handleDelete(id: string) {
    onSave(vault.filter((v) => v.id !== id));
    setDeleting(null);
  }

  const filtered = vault
    .filter((v) => filter === "all" || v.type === filter)
    .filter((v) => {
      const q = search.toLowerCase();
      return !q || v.title.toLowerCase().includes(q) || (v.username ?? "").toLowerCase().includes(q);
    });

  if (mode === "add" || mode === "edit") {
    return (
      <section className="module">
        <div className="module-header">
          <h2>{mode === "add" ? "إضافة سجل جديد" : "تعديل السجل"}</h2>
        </div>
        {editing ? (
          <EntryForm initial={editing} onSave={handleSave} onCancel={cancel} />
        ) : (
          <EntryForm onSave={handleSave} onCancel={cancel} />
        )}
      </section>
    );
  }

  return (
    <section className="module">
      <div className="module-header">
        <h2 className="module-title">
          <IC.Lock /> الخزينة المشفرة
        </h2>
        <button onClick={startAdd} className="btn btn-primary btn-sm">
          <IC.Plus /> إضافة
        </button>
      </div>

      {/* Search + filter */}
      <div className="vault-controls">
        <div className="input-group search-group">
          <IC.Search />
          <input
            className="form-input"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="بحث في الخزينة..."
          />
        </div>

        <div className="filter-chips">
          {(["all", "login", "card", "note", "identity", "key"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setFilter(t)}
              className={`type-chip ${filter === t ? "active" : ""}`}
            >
              {t === "all" ? "الكل" : TYPE_LABELS[t as EntryType]}
            </button>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="vault-stats">
        <span>{vault.length} سجل محمي</span>
        {search && <span>· {filtered.length} نتيجة</span>}
      </div>

      {/* List */}
      {filtered.length === 0 ? (
        <div className="empty-state">
          <IC.Lock />
          <p>
            {vault.length === 0
              ? "خزينتك فارغة. أضف أول سجل الآن."
              : "لا توجد نتائج تطابق بحثك."}
          </p>
        </div>
      ) : (
        <div className="entry-list">
          {filtered.map((entry) => (
            deleting === entry.id ? (
              <div key={entry.id} className="delete-confirm">
                <p>حذف «{entry.title}»؟ لا يمكن التراجع.</p>
                <div className="form-actions">
                  <button onClick={() => setDeleting(null)} className="btn btn-ghost btn-sm">إلغاء</button>
                  <button onClick={() => handleDelete(entry.id)} className="btn btn-danger btn-sm">
                    <IC.Trash /> حذف
                  </button>
                </div>
              </div>
            ) : (
              <EntryCard
                key={entry.id}
                entry={entry}
                onEdit={() => startEdit(entry)}
                onDelete={() => setDeleting(entry.id)}
              />
            )
          ))}
        </div>
      )}
    </section>
  );
}
