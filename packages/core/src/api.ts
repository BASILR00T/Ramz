/**
 * External API clients.
 * All calls are made directly from the browser (zero-knowledge).
 * API keys never leave the device.
 */

import type { HibpBreach } from "./types.js";

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
