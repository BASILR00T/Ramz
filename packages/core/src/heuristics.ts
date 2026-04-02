/**
 * Offline phishing / suspicious-content heuristics.
 * Runs entirely in-browser with no external network calls.
 */

interface HeuristicRule {
  pattern: RegExp;
  label: string;
  weight: number;
}

const PHISHING_RULES: HeuristicRule[] = [
  {
    pattern:
      /اضغط هنا|انقر الآن|عاجل|فوري|تحقق الآن|act now|click here|urgent/i,
    label: "طلب عاجل",
    weight: 20,
  },
  {
    pattern:
      /كلمة المرور|password|بيانات|حساب|تسجيل الدخول|معلومات شخصية|verify your account/i,
    label: "طلب بيانات حساسة",
    weight: 25,
  },
  {
    pattern:
      /مجاني|جائزة|ربحت|تهانينا|you won|free prize|congratulations/i,
    label: "عرض مغري مشبوه",
    weight: 15,
  },
  {
    pattern: /http:\/\/|bit\.ly|tinyurl|ow\.ly|goo\.gl|t\.co\/[a-z]/i,
    label: "رابط مختصر أو غير مشفر",
    weight: 30,
  },
  {
    pattern:
      /تحقق من هويتك|تأكيد الحساب|تجميد الحساب|account suspended|verify identity/i,
    label: "تهديد بتعطيل الخدمة",
    weight: 25,
  },
  {
    pattern:
      /بنك|ماستر كارد|فيزا|باي بال|paypal|mastercard|visa|bank/i,
    label: "انتحال هوية مالية",
    weight: 20,
  },
  {
    pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    label: "رابط يحتوي على IP مباشر",
    weight: 35,
  },
  {
    pattern: /login[-.]|signin[-.]|secure[-.]|verify[-.]|account[-.]update/i,
    label: "نطاق مشابه لخدمة رسمية",
    weight: 30,
  },
  {
    pattern:
      /limited time|offer expires|expire soon|ستنتهي صلاحيتك|انتهى الوقت/i,
    label: "ضغط زمني مصطنع",
    weight: 15,
  },
  {
    pattern: /confirm.{0,20}(details?|account|payment)/i,
    label: "طلب تأكيد مشبوه",
    weight: 20,
  },
];

export interface PhishingAnalysis {
  score: number;
  indicators: string[];
}

export function heuristicPhishing(text: string): PhishingAnalysis {
  if (!text || text.length > 50_000) {
    return { score: 0, indicators: [] };
  }
  const matched = PHISHING_RULES.filter((r) => r.pattern.test(text));
  return {
    score: Math.min(100, matched.reduce((acc, r) => acc + r.weight, 0)),
    indicators: matched.map((r) => r.label),
  };
}

export function extractUrls(text: string): string[] {
  const matches = text.match(/https?:\/\/[^\s<>"']+/g) ?? [];
  // Deduplicate and limit
  return [...new Set(matches)].slice(0, 10);
}

// ── Module-facing wrapper ─────────────────────────────────────────────────────

/**
 * Check a URL or text for phishing indicators.
 * Returns { score (0–100), flags: string[] }.
 */
export function checkPhishing(urlOrText: string): { score: number; flags: string[] } {
  const result = heuristicPhishing(urlOrText);
  return { score: result.score, flags: result.indicators };
}
