"use client";

import React from "react";
import { IC } from "../ui/Icons";

const STEPS = [
  {
    n: 1,
    title: "فتح مدير الإضافات في المتصفح",
    chrome: 'اذهب إلى chrome://extensions أو من القائمة: أدوات ← إضافات',
    firefox: 'اذهب إلى about:addons أو من القائمة: الإضافات والتسجيلات',
  },
  {
    n: 2,
    title: "تفعيل وضع المطوّر",
    chrome: 'فعّل "وضع المطوّر" في أعلى اليمين',
    firefox: 'لا يلزم. اختر "تثبيت الإضافة من الملف"',
  },
  {
    n: 3,
    title: 'النقر على "تحميل غير مضغوط"',
    chrome: 'انقر "تحميل الإضافة غير المضغوطة" ثم اختر مجلد إضافة رَمز',
    firefox: 'انقر "تثبيت الإضافة من الملف" واختر manifest.json',
  },
  {
    n: 4,
    title: "تثبيت الإضافة والتحقق",
    chrome: 'ستظهر أيقونة رَمز في شريط الأدوات، انقر عليها للبدء',
    firefox: 'تأكد من ظهور الإضافة في قائمة الإضافات المثبتة',
  },
];

const FEATURES = [
  { Icon: IC.Shield,   text: "فحص الروابط تلقائياً عند الضغط عليها" },
  { Icon: IC.Lock,     text: "ملء كلمات المرور من الخزينة مباشرةً" },
  { Icon: IC.AlertTriangle, text: "تحذير فوري عند زيارة مواقع مشبوهة" },
  { Icon: IC.Key,      text: "توليد كلمات مرور قوية في أي حقل" },
  { Icon: IC.Eye,      text: "كشف الصفحات الاحتيالية بالتحليل الهيورستيكي" },
  { Icon: IC.History,  text: "تسجيل جميع الروابط التي تم فحصها" },
];

export default function ExtensionModule() {
  return (
    <section className="module">
      <div className="module-header">
        <h2 className="module-title">
          <IC.Puzzle /> إضافة المتصفح
        </h2>
      </div>

      {/* Status banner */}
      <div className="info-banner">
        <IC.Zap />
        <span>
          إضافة المتصفح قيد التطوير وستتوفر قريباً. في الوقت الحالي يمكنك استخدام
          التطبيق المستقل لفحص الروابط والملفات.
        </span>
      </div>

      {/* Features preview */}
      <div className="card">
        <h3 className="card-title">ما ستتيحه الإضافة</h3>
        <div className="feature-grid">
          {FEATURES.map(({ Icon, text }, i) => (
            <div key={i} className="feature-item">
              <Icon />
              <span>{text}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Installation guide */}
      <div className="card" style={{ marginTop: "var(--sp-4)" }}>
        <h3 className="card-title">دليل التثبيت (بعد الإصدار)</h3>

        <div className="steps-list">
          {STEPS.map((step) => (
            <div key={step.n} className="step-item">
              <div className="step-num">{step.n}</div>
              <div className="step-body">
                <strong>{step.title}</strong>
                <div className="step-browsers">
                  <div className="step-browser">
                    <IC.Globe />
                    <span className="bidi">
                      <strong className="ltr">Chrome/Edge</strong>{" "}
                      {step.n === 1 ? (
                        <>
                          اذهب إلى <bdi dir="ltr" className="code">chrome://extensions</bdi>{" "}
                          أو من القائمة: أدوات ← إضافات
                        </>
                      ) : (
                        step.chrome
                      )}
                    </span>
                  </div>
                  <div className="step-browser">
                    <IC.Globe />
                    <span className="bidi">
                      <strong className="ltr">Firefox</strong>{" "}
                      {step.n === 1 ? (
                        <>
                          اذهب إلى <bdi dir="ltr" className="code">about:addons</bdi>{" "}
                          أو من القائمة: الإضافات والتسجيلات
                        </>
                      ) : step.n === 3 ? (
                        <>
                          انقر &quot;تثبيت الإضافة من الملف&quot; واختر{" "}
                          <bdi dir="ltr" className="code">manifest.json</bdi>
                        </>
                      ) : (
                        step.firefox
                      )}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Privacy note */}
      <div className="card" style={{ marginTop: "var(--sp-4)" }}>
        <h3 className="card-title">
          <IC.Shield /> الخصوصية والأمان
        </h3>
        <ul className="privacy-list">
          <li>الإضافة لا ترسل أي بيانات لخوادم خارجية.</li>
          <li>تواصل الإضافة مع التطبيق يتم محلياً فقط (localhost).</li>
          <li>جميع المفاتيح والبيانات تبقى في تخزين المتصفح المشفر.</li>
          <li>الكود مفتوح المصدر وقابل للتدقيق في أي وقت.</li>
        </ul>
      </div>
    </section>
  );
}
