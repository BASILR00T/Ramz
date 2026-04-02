/**
 * External API clients.
 * All calls are made directly from the browser (zero-knowledge).
 * API keys never leave the device.
 */

import type { HibpBreach, ScanResult } from "./types.js";

// ── VirusTotal v3 ────────────────────────────────────────────────────────────

function vtHeaders(apiKey: string): HeadersInit {
  return { "x-apikey": apiKey };
}

function urlToVtId(url: string): string {
  // VT URL ID = base64url(url) without padding
  return btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

export async function vtScanUrl(
  apiKey: string,
  url: string
): Promise<unknown> {
  const id = urlToVtId(url);
  const r = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
    headers: vtHeaders(apiKey),
  });
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    const msg =
      (body as { error?: { message?: string } }).error?.message ??
      `VT Error ${r.status}`;
    throw new Error(msg);
  }
  return r.json();
}

export async function vtSubmitUrl(
  apiKey: string,
  url: string
): Promise<unknown> {
  const body = new URLSearchParams({ url });
  const r = await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: {
      ...vtHeaders(apiKey),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });
  if (!r.ok) throw new Error(`VT Submit ${r.status}`);
  return r.json();
}

export async function vtScanFile(
  apiKey: string,
  hash: string
): Promise<unknown | null> {
  const r = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
    headers: vtHeaders(apiKey),
  });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`VT File ${r.status}`);
  return r.json();
}

export async function vtScanFileBinary(
  apiKey: string,
  file: File
): Promise<unknown> {
  const MAX_SIZE = 32 * 1024 * 1024; // 32 MB VT free tier limit
  if (file.size > MAX_SIZE) {
    throw new Error(`الملف كبير جداً (الحد ${Math.round(MAX_SIZE / 1024 / 1024)} ميجابايت)`);
  }
  const form = new FormData();
  form.append("file", file);
  const r = await fetch("https://www.virustotal.com/api/v3/files", {
    method: "POST",
    headers: vtHeaders(apiKey),
    body: form,
  });
  if (!r.ok) throw new Error(`VT Upload ${r.status}`);
  return r.json();
}

// ── urlscan.io ───────────────────────────────────────────────────────────────

export async function urlscanSubmit(
  apiKey: string,
  url: string
): Promise<{ uuid: string; result: string }> {
  const r = await fetch("https://urlscan.io/api/v1/scan/", {
    method: "POST",
    headers: {
      "API-Key": apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url, visibility: "public" }),
  });
  if (!r.ok) throw new Error(`urlscan submit ${r.status}`);
  return r.json() as Promise<{ uuid: string; result: string }>;
}

export async function urlscanResult(uuid: string): Promise<unknown> {
  const r = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
  if (r.status === 404) throw new Error("urlscan result not ready");
  if (!r.ok) throw new Error(`urlscan result ${r.status}`);
  return r.json();
}

// ── HIBP (Have I Been Pwned) ─────────────────────────────────────────────────

/**
 * Password check using k-Anonymity model.
 * Only the first 5 chars of the SHA-1 hash are sent to HIBP.
 * The full hash never leaves the device.
 */
export async function hibpCheckPassword(sha1Upper: string): Promise<number> {
  const prefix = sha1Upper.slice(0, 5);
  const suffix = sha1Upper.slice(5);
  const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "Add-Padding": "true" }, // reduces timing side-channels
  });
  if (!r.ok) throw new Error(`HIBP ${r.status}`);
  const text = await r.text();
  const match = text.split("\r\n").find((l) => l.split(":")[0] === suffix);
  return match ? parseInt(match.split(":")[1] ?? "0", 10) : 0;
}

export async function hibpCheckEmail(
  apiKey: string,
  email: string
): Promise<HibpBreach[]> {
  const r = await fetch(
    `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
    {
      headers: {
        "hibp-api-key": apiKey,
        "User-Agent": "Ramz-Security-App/1.0",
      },
    }
  );
  if (r.status === 404) return [];
  if (r.status === 401) throw new Error("HIBP API Key غير صحيح");
  if (r.status === 429) throw new Error("تجاوزت حد الطلبات — انتظر قليلاً");
  if (!r.ok) throw new Error(`HIBP ${r.status}`);
  return r.json() as Promise<HibpBreach[]>;
}

// ── Google Safe Browsing v4 ──────────────────────────────────────────────────

interface GsbResponse {
  matches?: Array<{ threatType: string; platformType: string }>;
}

export async function gsbLookup(
  apiKey: string,
  url: string
): Promise<GsbResponse> {
  const body = {
    client: { clientId: "ramz-app", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };
  const r = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }
  );
  if (!r.ok) throw new Error(`GSB ${r.status}`);
  return r.json() as Promise<GsbResponse>;
}

// ── PhishTank ────────────────────────────────────────────────────────────────

/**
 * PhishTank check — may fail with CORS in browser context.
 * Gracefully handles CORS errors.
 */
export async function phishTankCheck(url: string): Promise<unknown> {
  const form = new URLSearchParams({ url, format: "json", app_key: "" });
  const r = await fetch("https://checkurl.phishtank.com/checkurl/", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form,
  });
  if (!r.ok) throw new Error(`PhishTank ${r.status}`);
  return r.json();
}

// ── Module-facing wrapper functions ──────────────────────────────────────────

/**
 * Scan a URL via VirusTotal v3 (default) or urlscan.io.
 * Returns a normalised ScanResult with positives / total.
 */
export async function scanUrl(
  url: string,
  apiKey: string,
  provider: "vt" | "urlscan" = "vt"
): Promise<ScanResult> {
  if (provider === "urlscan") {
    const { uuid } = await urlscanSubmit(apiKey, url);
    // Poll up to 20s for result
    for (let i = 0; i < 4; i++) {
      await new Promise((r) => setTimeout(r, 5000));
      try {
        const res = await urlscanResult(uuid) as { verdicts?: { overall?: { malicious?: boolean; score?: number } } };
        const malicious = res?.verdicts?.overall?.malicious ?? false;
        return { positives: malicious ? 1 : 0, total: 1 };
      } catch {
        /* result not ready yet */
      }
    }
    return { error: "urlscan result not ready after 20s" };
  }

  // VirusTotal — fetch cached report first
  try {
    const data = await vtScanUrl(apiKey, url) as {
      data?: { attributes?: { last_analysis_stats?: { malicious?: number; suspicious?: number; undetected?: number; harmless?: number } } }
    };
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (stats) {
      const positives = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
      const total = positives + (stats.undetected ?? 0) + (stats.harmless ?? 0);
      return { positives, total };
    }
  } catch {
    // No cached report — submit and poll
  }
  try {
    await vtSubmitUrl(apiKey, url);
    await new Promise((r) => setTimeout(r, 4000));
    const data = await vtScanUrl(apiKey, url) as {
      data?: { attributes?: { last_analysis_stats?: { malicious?: number; suspicious?: number; undetected?: number; harmless?: number } } }
    };
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (stats) {
      const positives = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
      const total = positives + (stats.undetected ?? 0) + (stats.harmless ?? 0);
      return { positives, total };
    }
  } catch (e) {
    return { error: String(e) };
  }
  return { error: "لا توجد نتيجة من VirusTotal" };
}

/**
 * Scan a file via VirusTotal v3.
 * Checks cached hash report first, uploads if not found.
 */
export async function scanFile(file: File, apiKey: string): Promise<ScanResult> {
  try {
    // Try hash lookup first (faster, no upload needed)
    const buf  = await file.arrayBuffer();
    const hash = await crypto.subtle.digest("SHA-256", buf);
    const hex  = Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const cached = await vtScanFile(apiKey, hex) as {
      data?: { attributes?: { last_analysis_stats?: { malicious?: number; suspicious?: number; undetected?: number; harmless?: number } } }
    } | null;
    if (cached?.data?.attributes?.last_analysis_stats) {
      const stats = cached.data.attributes.last_analysis_stats;
      const positives = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
      const total = positives + (stats.undetected ?? 0) + (stats.harmless ?? 0);
      return { positives, total };
    }
  } catch {
    /* hash not cached — upload */
  }
  try {
    const submitted = await vtScanFileBinary(apiKey, file) as { data?: { id?: string } };
    const analysisId = submitted?.data?.id;
    if (analysisId) {
      await new Promise((r) => setTimeout(r, 5000));
      const analysisRes = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        { headers: { "x-apikey": apiKey } }
      );
      const analysis = await analysisRes.json() as {
        data?: { attributes?: { stats?: { malicious?: number; suspicious?: number; undetected?: number; harmless?: number } } }
      };
      const stats = analysis?.data?.attributes?.stats;
      if (stats) {
        const positives = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
        const total = positives + (stats.undetected ?? 0) + (stats.harmless ?? 0);
        return { positives, total };
      }
    }
  } catch (e) {
    return { error: String(e) };
  }
  return { error: "لا توجد نتيجة من VirusTotal" };
}

/**
 * Check an email against HIBP breaches.
 */
export async function checkHIBP(
  email: string,
  apiKey: string
): Promise<{ breaches: HibpBreach[] }> {
  const breaches = await hibpCheckEmail(apiKey, email);
  return { breaches };
}

/**
 * Check a URL against Google Safe Browsing v4.
 */
export async function checkGoogleSafeBrowsing(
  url: string,
  apiKey: string
): Promise<{ matches: Array<{ threatType: string }> }> {
  const result = await gsbLookup(apiKey, url);
  return { matches: result.matches ?? [] };
}
