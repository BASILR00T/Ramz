"use client";

import React, { useState } from "react";
import { IC } from "../ui/Icons";
import { saveApiKeys } from "../../lib/storage";
import type { ApiKeys } from "@ramz/core";

interface ApiKeyFieldProps {
  label: string;
  description: string;
  docUrl: string;
  value: string;
  onChange: (v: string) => void;
  required?: boolean;
}

function ApiKeyField({ label, description, docUrl, value, onChange, required }: ApiKeyFieldProps) {
  const [show, setShow] = useState(false);

  return (
    <div className="api-field">
      <div className="api-field-header">
        <span className="api-label">
          {label}
          {required && <span className="tag warn" style={{ marginRight: "var(--sp-2)" }}>مطلوب</span>}
        </span>
        <a
          href={docUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="btn btn-ghost btn-xs"
        >
          <IC.Link /> احصل على مفتاح
        </a>
      </div>
      <p className="api-desc">{description}</p>
      <div className="input-group">
        <IC.Key />
        <input
          type={show ? "text" : "password"}
          className="form-input"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={`أدخل ${label}...`}
          autoComplete="off"
          spellCheck={false}
        />
        <button
          type="button"
          onClick={() => setShow((v) => !v)}
          className="show-pw-btn"
          aria-label={show ? "إخفاء" : "إظهار"}
        >
          {show ? <IC.EyeOff /> : <IC.Eye />}
        </button>
        {value && (
          <button
            type="button"
            onClick={() => onChange("")}
            className="copy-btn"
            title="مسح"
          >
            <IC.X />
          </button>
        )}
      </div>
      <div className={`api-status ${value ? "set" : "unset"}`}>
        {value ? <><IC.Check /> مُعيَّن</> : <><IC.AlertTriangle /> غير مُعيَّن</>}
      </div>
    </div>
  );
}

interface ApiKeysModuleProps {
  apiKeys: ApiKeys;
  onSave: (keys: ApiKeys) => void;
}

export default function ApiKeysModule({ apiKeys, onSave }: ApiKeysModuleProps) {
  const [draft, setDraft] = useState<ApiKeys>(apiKeys);
  const [saved, setSaved] = useState(false);

  function set(field: keyof ApiKeys, value: string) {
    setDraft((d) => ({ ...d, [field]: value }));
    setSaved(false);
  }

  function handleSave(e: React.FormEvent) {
    e.preventDefault();
    saveApiKeys(draft);
    onSave(draft);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  }

  const fields: Array<{
    field: keyof ApiKeys;
    label: string;
    desc: string;
    doc: string;
    required?: boolean;
  }> = [
    {
      field: "vt",
      label: "VirusTotal API Key",
      desc: "لفحص الروابط والملفات عبر 70+ محرك مكافح للفيروسات. الخطة المجانية: 4 طلبات/دقيقة.",
      doc: "https://www.virustotal.com/gui/my-apikey",
      required: true,
    },
    {
      field: "hibp",
      label: "Have I Been Pwned API Key",
      desc: "للتحقق من تسريبات البريد الإلكتروني في أكبر قواعد بيانات التسريبات.",
      doc: "https://haveibeenpwned.com/API/Key",
    },
    {
      field: "urlscan",
      label: "urlscan.io API Key",
      desc: "لفحص الروابط وتحليل سلوك المواقع. الخطة المجانية: 5000 فحص/شهر.",
      doc: "https://urlscan.io/user/signup",
    },
    {
      field: "gsb",
      label: "Google Safe Browsing API Key",
      desc: "للتحقق من القوائم السوداء لـ Google. الاستخدام مجاني ضمن الحصص المعقولة.",
      doc: "https://developers.google.com/safe-browsing/v4/get-started",
    },
  ];

  const setCount = Object.values(draft).filter(Boolean).length;

  return (
    <section className="module">
      <div className="module-header">
        <h2 className="module-title">
          <IC.Key /> مفاتيح API
        </h2>
      </div>

      <div className="info-banner">
        <IC.Lock />
        <span>
          تُحفظ المفاتيح في تخزين المتصفح المحلي فقط. لا تُرسَل لأي خادم.
          {setCount > 0 && ` ${setCount} / ${fields.length} مفتاح مُعيَّن.`}
        </span>
      </div>

      <form onSubmit={handleSave} className="api-form">
        {fields.map(({ field, label, desc, doc, required }) => (
          <ApiKeyField
            key={field}
            label={label}
            description={desc}
            docUrl={doc}
            value={draft[field]}
            onChange={(v) => set(field, v)}
            required={required ?? false}
          />
        ))}

        <div className="form-actions">
          <button type="submit" className="btn btn-primary">
            {saved ? <><IC.Check /> تم الحفظ</> : <><IC.Download /> حفظ المفاتيح</>}
          </button>
        </div>
      </form>

      <div className="card" style={{ marginTop: "var(--sp-4)" }}>
        <h3 className="card-title">
          <IC.Shield /> ملاحظات الأمان
        </h3>
        <ul className="privacy-list">
          <li>المفاتيح تُخزَّن في <code>localStorage</code> على جهازك فقط.</li>
          <li>لا يُشفَّر localStorage، لذا أوصي باستخدام متصفح موثوق وبدون إضافات مشبوهة.</li>
          <li>لا تشارك هذه المفاتيح مع أحد ولا تُدخلها في مواقع أخرى.</li>
          <li>يمكنك مسح المفاتيح في أي وقت بالضغط على زر X بجانب كل حقل.</li>
        </ul>
      </div>
    </section>
  );
}
