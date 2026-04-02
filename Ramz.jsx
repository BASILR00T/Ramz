import { useState, useEffect, useCallback, useRef } from "react";

// ══════════════════════════════════════════════════════════════════════════════
//  UTILITIES
// ══════════════════════════════════════════════════════════════════════════════

const generatePassword = (length = 24) => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
  const arr = new Uint32Array(length);
  window.crypto.getRandomValues(arr);
  return Array.from(arr, (x) => chars[x % chars.length]).join("");
};

const sha256File = async (file) => {
  const buf = await file.arrayBuffer();
  const hash = await window.crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
};

const sha1Hash = async (str) => {
  const buf = new TextEncoder().encode(str);
  const hash = await window.crypto.subtle.digest("SHA-1", buf);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
};

const calcEntropy = (p) => {
  const pools = [/[a-z]/,/[A-Z]/,/[0-9]/,/[^a-zA-Z0-9]/].reduce((a,r,i)=>a+([26,26,10,32][i]*(r.test(p)?1:0)),0);
  return p.length * Math.log2(pools || 1);
};

const timeToCrack = (e) => {
  const s = Math.pow(2, e) / 1e12;
  if (s < 1) return "أقل من ثانية";
  if (s < 60) return `${~~s} ثانية`;
  if (s < 3600) return `${~~(s/60)} دقيقة`;
  if (s < 86400) return `${~~(s/3600)} ساعة`;
  if (s < 31536000) return `${~~(s/86400)} يوم`;
  if (s < 3.15e9) return `${~~(s/31536000)} سنة`;
  return "مليارات السنين";
};

const encryptVault = async (data, pwd) => {
  const enc = new TextEncoder();
  const km = await window.crypto.subtle.importKey("raw", enc.encode(pwd), "PBKDF2", false, ["deriveKey"]);
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const key = await window.crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},km,{name:"AES-GCM",length:256},false,["encrypt"]);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt({name:"AES-GCM",iv},key,enc.encode(JSON.stringify(data)));
  return {salt:Array.from(salt),iv:Array.from(iv),data:Array.from(new Uint8Array(encrypted))};
};

const decryptVault = async (enc_data, pwd) => {
  const enc = new TextEncoder();
  const km = await window.crypto.subtle.importKey("raw", enc.encode(pwd), "PBKDF2", false, ["deriveKey"]);
  const key = await window.crypto.subtle.deriveKey({name:"PBKDF2",salt:new Uint8Array(enc_data.salt),iterations:100000,hash:"SHA-256"},km,{name:"AES-GCM",length:256},false,["decrypt"]);
  const dec = await window.crypto.subtle.decrypt({name:"AES-GCM",iv:new Uint8Array(enc_data.iv)},key,new Uint8Array(enc_data.data));
  return JSON.parse(new TextDecoder().decode(dec));
};

const ls = {
  get: (k, d=null) => { try { const v=localStorage.getItem(k); return v?JSON.parse(v):d; } catch { return d; } },
  set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
};

// ── Local heuristic phishing (runs offline) ──────────────────────────────────
const heuristicPhishing = (text) => {
  const rules = [
    { p:/اضغط هنا|انقر الآن|عاجل|فوري|تحقق الآن|act now|click here|urgent/i, l:"طلب عاجل", w:20 },
    { p:/كلمة المرور|password|بيانات|حساب|تسجيل الدخول|معلومات شخصية|verify your account/i, l:"طلب بيانات حساسة", w:25 },
    { p:/مجاني|جائزة|ربحت|تهانينا|you won|free prize|congratulations/i, l:"عرض مغري مشبوه", w:15 },
    { p:/http:\/\/|bit\.ly|tinyurl|ow\.ly|goo\.gl|t\.co\/[a-z]/i, l:"رابط مختصر أو غير مشفر", w:30 },
    { p:/تحقق من هويتك|تأكيد الحساب|تجميد الحساب|account suspended|verify identity/i, l:"تهديد بتعطيل الخدمة", w:25 },
    { p:/بنك|ماستر كارد|فيزا|باي بال|paypal|mastercard|visa|bank/i, l:"انتحال هوية مالية", w:20 },
    { p:/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, l:"رابط يحتوي على IP مباشر", w:35 },
    { p:/login[-.]|signin[-.]|secure[-.]|verify[-.]|account[-.]update/i, l:"نطاق مشابه لخدمة رسمية", w:30 },
  ];
  const found = rules.filter(r => r.p.test(text));
  return { score: Math.min(100, found.reduce((a,b)=>a+b.w,0)), indicators: found.map(f=>f.l) };
};

// ══════════════════════════════════════════════════════════════════════════════
//  API CLIENTS  (all calls go through CORS proxies or official endpoints)
// ══════════════════════════════════════════════════════════════════════════════

// VirusTotal v3
const vtScanUrl = async (apiKey, url) => {
  const encoded = btoa(url).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  const r = await fetch(`https://www.virustotal.com/api/v3/urls/${encoded}`,{headers:{"x-apikey":apiKey}});
  if (!r.ok) { const rr=await r.json(); throw new Error(rr.error?.message||`VT Error ${r.status}`); }
  return r.json();
};

const vtSubmitUrl = async (apiKey, url) => {
  const body = new URLSearchParams({url});
  const r = await fetch("https://www.virustotal.com/api/v3/urls",{method:"POST",headers:{"x-apikey":apiKey,"Content-Type":"application/x-www-form-urlencoded"},body});
  if (!r.ok) throw new Error(`VT Submit ${r.status}`);
  return r.json();
};

const vtScanFile = async (apiKey, hash) => {
  const r = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`,{headers:{"x-apikey":apiKey}});
  if (r.status===404) return null; // not in VT database
  if (!r.ok) throw new Error(`VT File ${r.status}`);
  return r.json();
};

const vtScanFileBinary = async (apiKey, file) => {
  const form = new FormData();
  form.append("file", file);
  const r = await fetch("https://www.virustotal.com/api/v3/files",{method:"POST",headers:{"x-apikey":apiKey},body:form});
  if (!r.ok) throw new Error(`VT Upload ${r.status}`);
  return r.json();
};

// urlscan.io
const urlscanSubmit = async (apiKey, url) => {
  const r = await fetch("https://urlscan.io/api/v1/scan/",{
    method:"POST",
    headers:{"API-Key":apiKey,"Content-Type":"application/json"},
    body:JSON.stringify({url,visibility:"public"})
  });
  if (!r.ok) throw new Error(`urlscan submit ${r.status}`);
  return r.json();
};

const urlscanResult = async (uuid) => {
  const r = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
  if (!r.ok) throw new Error("urlscan result not ready");
  return r.json();
};

const urlscanSearch = async (query) => {
  const r = await fetch(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(query)}&size=5`);
  if (!r.ok) throw new Error(`urlscan search ${r.status}`);
  return r.json();
};

// HIBP (Have I Been Pwned) — k-Anonymity model for passwords, plain for emails via proxy
const hibpCheckPassword = async (password) => {
  const hash = await sha1Hash(password);
  const prefix = hash.slice(0,5);
  const suffix = hash.slice(5);
  const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  if (!r.ok) throw new Error("HIBP Error");
  const text = await r.text();
  const lines = text.split("\n");
  const match = lines.find(l => l.split(":")[0] === suffix);
  return match ? parseInt(match.split(":")[1]) : 0;
};

const hibpCheckEmail = async (apiKey, email) => {
  const r = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,{
    headers:{"hibp-api-key":apiKey,"User-Agent":"ScanForMe-App"}
  });
  if (r.status===404) return [];
  if (r.status===401) throw new Error("HIBP API Key غير صحيح");
  if (!r.ok) throw new Error(`HIBP ${r.status}`);
  return r.json();
};

// Google Safe Browsing
const gsbLookup = async (apiKey, url) => {
  const body = {
    client:{clientId:"scanforme",clientVersion:"1.0"},
    threatInfo:{
      threatTypes:["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes:["ANY_PLATFORM"],
      threatEntryTypes:["URL"],
      threatEntries:[{url}]
    }
  };
  const r = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,{
    method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)
  });
  if (!r.ok) throw new Error(`GSB ${r.status}`);
  return r.json();
};

// PhishTank (public API, no key needed for basic)
const phishTankCheck = async (url) => {
  const form = new URLSearchParams({url, format:"json", app_key:""});
  const r = await fetch("https://checkurl.phishtank.com/checkurl/",{
    method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:form
  });
  if (!r.ok) throw new Error(`PhishTank ${r.status}`);
  return r.json();
};

// ══════════════════════════════════════════════════════════════════════════════
//  ICONS
// ══════════════════════════════════════════════════════════════════════════════

const Icon = ({ d, size=20 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    {Array.isArray(d) ? d.map((p,i)=><path key={i} d={p}/>) : <path d={d}/>}
  </svg>
);

const IC = {
  Shield:  ()=><Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>,
  Lock:    ()=><Icon d={["M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2z","M7 11V7a5 5 0 0 1 10 0v4"]}/>,
  File:    ()=><Icon d={["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z","M14 2v6h6","M12 18v-6","M9 15h6"]}/>,
  Link:    ()=><Icon d={["M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71","M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"]}/>,
  Mail:    ()=><Icon d={["M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z","M22 6l-10 7L2 6"]}/>,
  Eye:     ()=><Icon d={["M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z","M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"]}/>,
  EyeOff:  ()=><Icon d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24M1 1l22 22"/>,
  Key:     ()=><Icon d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>,
  Plus:    ()=><Icon d="M12 5v14M5 12h14"/>,
  Trash:   ()=><Icon d={["M3 6h18","M19 6l-1 14H6L5 6","M8 6V4h8v2"]}/>,
  Copy:    ()=><Icon d={["M8 4H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-4-4H8z","M14 2v6h6","M12 11v6","M9 14h6"]}/>,
  History: ()=><Icon d={["M12 8v4l3 3","M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z"]}/>,
  Radar:   ()=><Icon d={["M12 12m-2 0a2 2 0 1 0 4 0 2 2 0 1 0-4 0","M12 2a10 10 0 0 1 0 20A10 10 0 0 1 12 2","M12 7a5 5 0 0 1 0 10","M17 12h4"]}/>,
  Refresh: ()=><Icon d={["M23 4v6h-6","M1 20v-6h6","M3.51 9a9 9 0 0 1 14.85-3.36L23 10","M1 14l4.64 4.36A9 9 0 0 0 20.49 15"]}/>,
  Check:   ()=><Icon d="M20 6L9 17l-5-5"/>,
  X:       ()=><Icon d="M18 6L6 18M6 6l12 12"/>,
  Zap:     ()=><Icon d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>,
  Settings:()=><Icon d={["M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z","M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"]}/>,
  Puzzle:  ()=><Icon d="M20.24 12.24a6 6 0 0 0-8.49-8.49L5 10.5V19h8.5l6.74-6.76zm-7.49.75l-5.74 5.75H9v-3.5l5.75-5.74 1.5 1.49zM16 5l3 3"/>,
  Globe:   ()=><Icon d={["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z","M2 12h20","M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"]}/>,
  AlertTriangle: ()=><Icon d={["M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z","M12 9v4","M12 17h.01"]}/>,
  Download:()=><Icon d={["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4","M7 10l5 5 5-5","M12 15V3"]}/>,
  Bug:     ()=><Icon d={["M8 2l1.88 1.88","M14.12 3.88L16 2","M9 7.13v-1a3.003 3.003 0 1 1 6 0v1","M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6z","M12 20v-9","M6.53 9C4.6 8.8 3 7.1 3 5","M6 13H2","M3 21c0-2.1 1.7-3.9 3.8-4","M20.97 5c0 2.1-1.6 3.8-3.5 4","M22 13h-4","M17.2 17c2.1.1 3.8 1.9 3.8 4"]}/>,
  FileText:()=><Icon d={["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z","M14 2v6h6","M16 13H8","M16 17H8","M10 9H8"]}/>,
  Image:   ()=><Icon d={["M19 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2z","M8.5 10a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3z","M21 15l-5-5L5 21"]}/>,
  Code:    ()=><Icon d="M16 18l6-6-6-6M8 6l-6 6 6 6"/>,
  Note:    ()=><Icon d={["M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7","M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"]}/>,
  CreditCard:()=><Icon d={["M21 4H3a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h18a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2z","M1 10h22"]}/>,
  Search:  ()=><Icon d={["M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z","M21 21l-4.35-4.35"]}/>,
  Filter:  ()=><Icon d="M22 3H2l8 9.46V19l4 2v-8.54L22 3"/>,
  Upload:  ()=><Icon d={["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4","M17 8l-5-5-5 5","M12 3v12"]}/>,
  Tag:     ()=><Icon d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82zM7 7h.01"/>,
  Edit:    ()=><Icon d={["M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7","M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"]}/>,
};

// ══════════════════════════════════════════════════════════════════════════════
//  STYLES
// ══════════════════════════════════════════════════════════════════════════════

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Tajawal:wght@300;400;500;700;900&family=Space+Mono:wght@400;700&display=swap');
*{box-sizing:border-box;margin:0;padding:0;}
:root{
  --black:#000;--white:#fff;
  --g400:#888;--g600:#444;--g800:#1a1a1a;--g900:#0d0d0d;
  --glow:0 0 20px rgba(255,255,255,.12),0 0 40px rgba(255,255,255,.05);
  --glow-sm:0 0 12px rgba(255,255,255,.1);
  --glass:rgba(255,255,255,.04);--gb:rgba(255,255,255,.08);
  --danger:#ff4444;--warn:#ffaa00;--ok:#44ff88;--info:#4488ff;--purple:#aa66ff;
}
html,body,#root{height:100%;background:#000;}
.app{min-height:100vh;background:#000;color:#fff;font-family:'Tajawal',sans-serif;direction:rtl;overflow-x:hidden;}
::-webkit-scrollbar{width:3px;}::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:2px;}
.app::before{content:'';position:fixed;inset:0;z-index:0;
  background-image:linear-gradient(rgba(255,255,255,.012) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.012) 1px,transparent 1px);
  background-size:44px 44px;pointer-events:none;}
.orb{position:fixed;top:-300px;left:50%;transform:translateX(-50%);width:700px;height:700px;
  background:radial-gradient(circle,rgba(255,255,255,.035) 0%,transparent 70%);pointer-events:none;z-index:0;}
.z1{position:relative;z-index:1;}

/* HEADER */
.hdr{padding:16px 24px;border-bottom:1px solid var(--gb);background:rgba(0,0,0,.85);
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;}
.logo{display:flex;align-items:center;gap:10px;font-family:'Space Mono',monospace;font-size:13px;letter-spacing:2px;}
.logo-ico{width:34px;height:34px;border:1px solid rgba(255,255,255,.18);border-radius:9px;
  display:flex;align-items:center;justify-content:center;box-shadow:var(--glow-sm);background:var(--glass);}
.logo-sub{font-size:9px;color:var(--g400);letter-spacing:3px;display:block;}
.hdr-right{display:flex;align-items:center;gap:10px;}
.hdr-badge{font-size:9px;font-family:'Space Mono',monospace;color:var(--g400);letter-spacing:1px;
  border:1px solid var(--gb);padding:4px 10px;border-radius:20px;background:var(--glass);}

/* NAV */
.nav{display:flex;gap:3px;padding:10px 24px;overflow-x:auto;border-bottom:1px solid var(--gb);
  background:rgba(0,0,0,.6);scrollbar-width:none;}
.nav::-webkit-scrollbar{display:none;}
.nbtn{display:flex;align-items:center;gap:7px;padding:8px 13px;border-radius:8px;border:1px solid transparent;
  background:transparent;color:var(--g400);font-family:'Tajawal',sans-serif;font-size:13px;
  cursor:pointer;white-space:nowrap;transition:all .2s;}
.nbtn:hover{color:#fff;background:var(--glass);border-color:var(--gb);}
.nbtn.on{color:#fff;background:rgba(255,255,255,.07);border-color:rgba(255,255,255,.15);box-shadow:var(--glow-sm);}
.badge-cnt{font-size:9px;background:rgba(255,255,255,.12);padding:1px 6px;border-radius:10px;}

/* MAIN */
.main{padding:24px;max-width:960px;margin:0 auto;}
@media(max-width:500px){.main{padding:16px 14px;}}

/* PANEL */
.panel{background:var(--glass);border:1px solid var(--gb);border-radius:16px;
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);overflow:hidden;animation:fs .3s ease;}
@keyframes fs{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.ph{padding:18px 22px;border-bottom:1px solid var(--gb);display:flex;align-items:center;justify-content:space-between;}
.ptitle{font-size:15px;font-weight:600;display:flex;align-items:center;gap:10px;}
.pico{width:30px;height:30px;border:1px solid var(--gb);border-radius:7px;display:flex;align-items:center;justify-content:center;background:rgba(255,255,255,.05);}
.pb{padding:22px;}

/* INPUTS */
.ig{margin-bottom:14px;}
.lbl{font-size:11px;color:var(--g400);margin-bottom:6px;display:block;letter-spacing:.5px;}
.inp,.txta,.sel{width:100%;padding:10px 13px;background:rgba(255,255,255,.04);border:1px solid var(--gb);
  border-radius:9px;color:#fff;font-family:'Tajawal',sans-serif;font-size:14px;
  outline:none;transition:border .2s,box-shadow .2s;direction:rtl;}
.inp:focus,.txta:focus,.sel:focus{border-color:rgba(255,255,255,.22);box-shadow:0 0 0 3px rgba(255,255,255,.04);}
.inp::placeholder,.txta::placeholder{color:var(--g600);}
.txta{resize:vertical;min-height:90px;}
.sel option{background:#111;}
.irow{display:flex;gap:8px;align-items:center;}
.irow .inp{flex:1;}
.pw-inp{padding-left:40px!important;}

/* BUTTONS */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:9px 16px;
  border-radius:9px;border:1px solid var(--gb);background:rgba(255,255,255,.07);color:#fff;
  font-family:'Tajawal',sans-serif;font-size:13px;font-weight:500;cursor:pointer;transition:all .2s;white-space:nowrap;}
.btn:hover{background:rgba(255,255,255,.12);border-color:rgba(255,255,255,.2);box-shadow:var(--glow-sm);}
.btn:active{transform:scale(.97);}
.btn:disabled{opacity:.4;cursor:not-allowed;transform:none;}
.btn-p{background:#fff;color:#000;border-color:#fff;font-weight:700;}
.btn-p:hover{background:rgba(255,255,255,.9);box-shadow:0 0 20px rgba(255,255,255,.2);}
.btn-d{border-color:rgba(255,68,68,.3);color:var(--danger);}
.btn-d:hover{background:rgba(255,68,68,.1);}
.btn-sm{padding:6px 11px;font-size:12px;border-radius:7px;}
.btn-ico{padding:7px;}
.w100{width:100%;}

/* RESULTS */
.rc{padding:15px 18px;border-radius:11px;border:1px solid var(--gb);background:rgba(255,255,255,.025);margin-top:14px;animation:fs .3s ease;}
.rc-ok{border-color:rgba(68,255,136,.25);background:rgba(68,255,136,.04);}
.rc-bad{border-color:rgba(255,68,68,.25);background:rgba(255,68,68,.04);}
.rc-warn{border-color:rgba(255,170,0,.25);background:rgba(255,170,0,.04);}
.rc-info{border-color:rgba(68,136,255,.25);background:rgba(68,136,255,.04);}
.rbadge{display:inline-flex;align-items:center;gap:5px;font-size:10px;font-weight:700;letter-spacing:1px;
  padding:3px 9px;border-radius:5px;margin-bottom:9px;text-transform:uppercase;}
.rb-ok{background:rgba(68,255,136,.15);color:var(--ok);}
.rb-bad{background:rgba(255,68,68,.15);color:var(--danger);}
.rb-warn{background:rgba(255,170,0,.15);color:var(--warn);}
.rb-info{background:rgba(68,136,255,.15);color:var(--info);}
.hash-box{font-family:'Space Mono',monospace;font-size:9px;color:var(--g400);word-break:break-all;
  margin-top:8px;padding:7px 10px;border-radius:6px;background:rgba(255,255,255,.03);border:1px solid var(--gb);}

/* ENGINE GRID */
.engines{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:8px;margin-top:12px;}
.engine-card{padding:10px 12px;border-radius:8px;border:1px solid var(--gb);background:rgba(255,255,255,.02);}
.engine-name{font-size:10px;color:var(--g400);font-family:'Space Mono',monospace;letter-spacing:.5px;margin-bottom:5px;}
.engine-status{font-size:12px;font-weight:600;display:flex;align-items:center;gap:5px;}

/* SCORE BAR */
.sb-wrap{margin:10px 0;}
.sb-labels{display:flex;justify-content:space-between;font-size:10px;color:var(--g400);margin-bottom:5px;}
.sb-track{height:3px;border-radius:2px;background:rgba(255,255,255,.07);overflow:hidden;}
.sb-fill{height:100%;border-radius:2px;transition:width .6s ease;}

/* VAULT */
.vi{display:flex;align-items:center;justify-content:space-between;padding:13px 15px;border-radius:9px;
  border:1px solid var(--gb);background:rgba(255,255,255,.02);margin-bottom:7px;transition:border-color .2s;}
.vi:hover{border-color:rgba(255,255,255,.12);}
.vi-title{font-size:14px;font-weight:500;margin-bottom:2px;}
.vi-meta{font-size:10px;color:var(--g400);font-family:'Space Mono',monospace;}
.tag{display:inline-block;font-size:9px;padding:2px 7px;border-radius:4px;border:1px solid var(--gb);
  background:var(--glass);color:var(--g400);margin-left:5px;}

/* HISTORY */
.hi{display:flex;align-items:flex-start;justify-content:space-between;padding:11px 14px;
  border-radius:9px;border:1px solid var(--gb);background:rgba(255,255,255,.02);margin-bottom:5px;}
.hi-type{font-size:9px;font-family:'Space Mono',monospace;letter-spacing:1px;text-transform:uppercase;}
.hi-val{font-size:11px;margin-top:2px;color:rgba(255,255,255,.7);word-break:break-all;}
.hi-time{font-size:9px;color:var(--g600);white-space:nowrap;margin-right:10px;flex-shrink:0;}

/* SUBNAV */
.snav{display:flex;gap:4px;margin-bottom:18px;flex-wrap:wrap;}
.snbtn{padding:5px 11px;border-radius:6px;font-size:11px;border:1px solid transparent;
  background:transparent;color:var(--g400);cursor:pointer;font-family:'Tajawal',sans-serif;transition:all .2s;}
.snbtn:hover{color:#fff;background:var(--glass);border-color:var(--gb);}
.snbtn.on{color:#fff;background:var(--glass);border-color:rgba(255,255,255,.15);}

/* DROPZONE */
.dz{border:2px dashed var(--gb);border-radius:11px;padding:36px 20px;text-align:center;cursor:pointer;transition:all .2s;}
.dz:hover,.dz.drag{border-color:rgba(255,255,255,.28);background:rgba(255,255,255,.025);}
.dz-text{color:var(--g400);font-size:12px;margin-top:8px;}

/* MODAL */
.mbg{position:fixed;inset:0;z-index:999;background:rgba(0,0,0,.88);backdrop-filter:blur(12px);
  display:flex;align-items:center;justify-content:center;padding:20px;animation:fadeIn .2s ease;}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
.modal{width:100%;max-width:430px;background:#0d0d0d;border:1px solid rgba(255,255,255,.12);
  border-radius:16px;overflow:hidden;box-shadow:0 0 60px rgba(255,255,255,.04);animation:fs .25s ease;}
.mhdr{padding:18px 22px;border-bottom:1px solid var(--gb);display:flex;justify-content:space-between;align-items:center;}
.mtitle{font-size:14px;font-weight:600;}
.mbdy{padding:22px;}
.mftr{padding:14px 22px;border-top:1px solid var(--gb);display:flex;gap:9px;justify-content:flex-end;}

/* PWD STRENGTH */
.sm{display:flex;gap:3px;margin:7px 0;}
.sb{height:3px;flex:1;border-radius:2px;transition:background .3s;}

/* SETTINGS CARD */
.sk{background:rgba(255,255,255,.025);border:1px solid var(--gb);border-radius:10px;padding:16px;margin-bottom:12px;}
.sk-title{font-size:12px;font-weight:600;margin-bottom:12px;display:flex;align-items:center;gap:7px;color:rgba(255,255,255,.8);}
.sk-note{font-size:10px;color:var(--g400);margin-top:6px;line-height:1.5;}
.sk-link{color:rgba(68,136,255,.8);text-decoration:none;}
.sk-link:hover{color:var(--info);}

/* DIVIDER */
.div{height:1px;background:var(--gb);margin:16px 0;}

/* LOADING SPINNER */
.spin{width:14px;height:14px;border:2px solid rgba(255,255,255,.2);border-top-color:#fff;
  border-radius:50%;animation:sp .6s linear infinite;display:inline-block;}
@keyframes sp{to{transform:rotate(360deg)}}

/* INDICATOR */
.ind{display:flex;align-items:center;gap:7px;font-size:12px;padding:4px 0;color:var(--warn);}
.ind-dot{width:5px;height:5px;border-radius:50%;background:var(--warn);flex-shrink:0;}

/* SOURCE ROWS */
.src-row{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.05);}
.src-row:last-child{border:none;}
.src-name{font-size:12px;color:rgba(255,255,255,.7);}
.src-status{font-size:11px;font-weight:600;}

/* GRID 2 */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
@media(max-width:500px){.g2{grid-template-columns:1fr;}}

/* EMPTY */
.empty{text-align:center;padding:44px 20px;color:var(--g600);}
.empty-ico{margin:0 auto 10px;opacity:.25;}

/* EXTENSION GUIDE */
.ext-step{display:flex;gap:12px;margin-bottom:18px;align-items:flex-start;}
.ext-num{width:26px;height:26px;border-radius:50%;border:1px solid rgba(255,255,255,.15);
  display:flex;align-items:center;justify-content:center;font-size:11px;font-family:'Space Mono',monospace;
  flex-shrink:0;color:rgba(255,255,255,.6);}
.ext-desc{font-size:13px;color:rgba(255,255,255,.75);line-height:1.6;}
.ext-code{font-family:'Space Mono',monospace;font-size:10px;background:rgba(255,255,255,.06);
  border:1px solid var(--gb);padding:8px 12px;border-radius:7px;margin-top:8px;white-space:pre;overflow-x:auto;color:rgba(255,255,255,.7);}
.api-status{display:flex;align-items:center;gap:6px;font-size:11px;}
.dot{width:7px;height:7px;border-radius:50%;}

/* VAULT v2 */
.vault-tabs{display:flex;gap:3px;padding:14px 22px 0;border-bottom:1px solid var(--gb);background:rgba(255,255,255,.015);overflow-x:auto;scrollbar-width:none;}
.vault-tabs::-webkit-scrollbar{display:none;}
.vtab{display:flex;align-items:center;gap:6px;padding:8px 14px;border-radius:8px 8px 0 0;border:1px solid transparent;border-bottom:none;
  background:transparent;color:var(--g400);font-family:'Tajawal',sans-serif;font-size:12px;cursor:pointer;white-space:nowrap;transition:all .2s;position:relative;bottom:-1px;}
.vtab:hover{color:#fff;background:var(--glass);}
.vtab.on{color:#fff;background:rgba(255,255,255,.06);border-color:var(--gb);border-bottom-color:transparent;}
.vtab-count{font-size:9px;background:rgba(255,255,255,.12);padding:1px 5px;border-radius:8px;}

.vault-search{display:flex;align-items:center;gap:8px;padding:14px 22px;border-bottom:1px solid var(--gb);}
.vault-search .inp{flex:1;padding:8px 12px;font-size:13px;}
.vault-filter{display:flex;gap:4px;padding:10px 22px;border-bottom:1px solid var(--gb);overflow-x:auto;scrollbar-width:none;flex-wrap:wrap;}
.vf-chip{padding:3px 10px;border-radius:20px;font-size:10px;border:1px solid var(--gb);background:transparent;
  color:var(--g400);cursor:pointer;font-family:'Tajawal',sans-serif;transition:all .15s;white-space:nowrap;}
.vf-chip:hover{border-color:rgba(255,255,255,.2);color:#fff;}
.vf-chip.on{background:rgba(255,255,255,.1);border-color:rgba(255,255,255,.2);color:#fff;}

.vi2{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;padding:14px 16px;border-radius:10px;
  border:1px solid var(--gb);background:rgba(255,255,255,.02);margin-bottom:8px;transition:border-color .2s,background .2s;cursor:pointer;}
.vi2:hover{border-color:rgba(255,255,255,.14);background:rgba(255,255,255,.03);}
.vi2-icon{width:34px;height:34px;border-radius:8px;border:1px solid var(--gb);display:flex;align-items:center;
  justify-content:center;flex-shrink:0;background:rgba(255,255,255,.04);}
.vi2-body{flex:1;min-width:0;}
.vi2-title{font-size:13px;font-weight:600;margin-bottom:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.vi2-sub{font-size:11px;color:var(--g400);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.vi2-meta{display:flex;align-items:center;gap:6px;margin-top:5px;}
.vi2-type{font-size:9px;font-family:'Space Mono',monospace;letter-spacing:.5px;padding:2px 6px;border-radius:3px;text-transform:uppercase;}
.vi2-actions{display:flex;gap:4px;flex-shrink:0;}

.type-password .vi2-icon{border-color:rgba(68,136,255,.3);color:var(--info);}
.type-secret .vi2-icon{border-color:rgba(170,102,255,.3);color:var(--purple);}
.type-note .vi2-icon{border-color:rgba(255,170,0,.3);color:var(--warn);}
.type-file .vi2-icon{border-color:rgba(68,255,136,.3);color:var(--ok);}
.type-card .vi2-icon{border-color:rgba(255,68,68,.3);color:var(--danger);}

.badge-password{background:rgba(68,136,255,.15);color:var(--info);}
.badge-secret{background:rgba(170,102,255,.15);color:var(--purple);}
.badge-note{background:rgba(255,170,0,.15);color:var(--warn);}
.badge-file{background:rgba(68,255,136,.15);color:var(--ok);}
.badge-card{background:rgba(255,68,68,.15);color:var(--danger);}

.detail-modal{width:100%;max-width:500px;background:#0a0a0a;border:1px solid rgba(255,255,255,.12);
  border-radius:16px;overflow:hidden;box-shadow:0 0 80px rgba(255,255,255,.04);animation:fs .25s ease;max-height:90vh;display:flex;flex-direction:column;}
.detail-body{padding:22px;overflow-y:auto;flex:1;}
.detail-field{margin-bottom:14px;}
.detail-label{font-size:10px;color:var(--g400);letter-spacing:.5px;margin-bottom:5px;text-transform:uppercase;}
.detail-val{font-size:13px;padding:10px 13px;background:rgba(255,255,255,.04);border:1px solid var(--gb);
  border-radius:8px;font-family:'Space Mono',monospace;word-break:break-all;line-height:1.5;white-space:pre-wrap;}
.detail-val.blur{filter:blur(5px);transition:filter .2s;cursor:pointer;}
.detail-val.blur:hover{filter:blur(0);}
.file-thumb{width:100%;max-height:200px;object-fit:contain;border-radius:8px;border:1px solid var(--gb);margin-top:6px;}
.file-preview-box{padding:14px;background:rgba(255,255,255,.03);border:1px solid var(--gb);border-radius:8px;margin-top:6px;
  font-family:'Space Mono',monospace;font-size:11px;color:var(--g400);white-space:pre-wrap;max-height:160px;overflow-y:auto;line-height:1.5;}
.add-type-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px;}
.add-type-btn{display:flex;flex-direction:column;align-items:center;gap:7px;padding:16px 12px;border-radius:10px;
  border:1px solid var(--gb);background:transparent;color:var(--g400);cursor:pointer;transition:all .2s;font-family:'Tajawal',sans-serif;font-size:12px;}
.add-type-btn:hover,.add-type-btn.on{background:rgba(255,255,255,.07);border-color:rgba(255,255,255,.2);color:#fff;}
.file-dz{border:2px dashed var(--gb);border-radius:10px;padding:28px 16px;text-align:center;cursor:pointer;transition:all .2s;}
.file-dz:hover{border-color:rgba(255,255,255,.25);background:rgba(255,255,255,.02);}
.vault-empty{text-align:center;padding:56px 24px;color:var(--g600);}

/* STATS ROW */
.vault-stats{display:flex;gap:10px;padding:14px 22px;border-bottom:1px solid var(--gb);flex-wrap:wrap;}
.stat-pill{display:flex;align-items:center;gap:6px;font-size:11px;padding:5px 12px;border-radius:20px;
  border:1px solid var(--gb);background:rgba(255,255,255,.025);}
.stat-dot{width:6px;height:6px;border-radius:50%;}
`;

// ══════════════════════════════════════════════════════════════════════════════
//  SUB-COMPONENTS
// ══════════════════════════════════════════════════════════════════════════════

const PH = ({ icon: I, title, action }) => (
  <div className="ph">
    <div className="ptitle"><div className="pico"><I/></div>{title}</div>
    {action}
  </div>
);

const PasswordStrength = ({ password }) => {
  if (!password) return null;
  const e = calcEntropy(password);
  const score = Math.min(4, Math.floor(e / 25));
  const colors = ["#ff4444","#ff8844","#ffaa00","#88dd44","#44ff88"];
  const labels = ["ضعيف جداً","ضعيف","متوسط","قوي","ممتاز"];
  return (
    <div style={{marginTop:10}}>
      <div className="sm">{[0,1,2,3].map(i=><div key={i} className="sb" style={{background:i<=score?colors[score]:"rgba(255,255,255,.07)"}}/>)}</div>
      <div style={{display:"flex",justifyContent:"space-between"}}>
        <span style={{fontSize:10,color:colors[score]}}>{labels[score]}</span>
        <span style={{fontSize:10,color:"var(--g400)"}}>{Math.round(e)} بت · {timeToCrack(e)}</span>
      </div>
    </div>
  );
};

const ApiStatus = ({ keys }) => {
  const apis = [
    { name:"VirusTotal", key: keys.vt },
    { name:"HIBP", key: keys.hibp },
    { name:"urlscan", key: keys.urlscan },
    { name:"Google SB", key: keys.gsb },
  ];
  return (
    <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
      {apis.map(a=>(
        <div key={a.name} className="api-status">
          <div className="dot" style={{background:a.key?"var(--ok)":"var(--g600)"}}/>
          <span style={{fontSize:10,color:a.key?"rgba(255,255,255,.6)":"var(--g600)"}}>{a.name}</span>
        </div>
      ))}
    </div>
  );
};

// ── Spinner ──────────────────────────────────────────────────────────────────
const Spinner = () => <span className="spin"/>;

// ══════════════════════════════════════════════════════════════════════════════
//  SETTINGS MODULE
// ══════════════════════════════════════════════════════════════════════════════

const SettingsModule = ({ keys, setKeys }) => {
  const [form, setForm] = useState(keys);
  const [saved, setSaved] = useState(false);

  const save = () => {
    setKeys(form);
    ls.set("api_keys", form);
    setSaved(true);
    setTimeout(()=>setSaved(false), 2000);
  };

  const apiDocs = [
    { id:"vt", name:"VirusTotal API Key", placeholder:"VT API Key — 64 حرف", link:"https://www.virustotal.com/gui/my-apikey", desc:"مجاني · 4 طلبات/دقيقة للمجانية · يتيح فحص الملفات والروابط عبر 70+ محرك" },
    { id:"hibp", name:"Have I Been Pwned API Key", placeholder:"HIBP API Key", link:"https://haveibeenpwned.com/API/Key", desc:"مدفوع رمزي · يتيح كشف تسريبات البريد الإلكتروني بشكل كامل" },
    { id:"urlscan", name:"urlscan.io API Key", placeholder:"urlscan API Key", link:"https://urlscan.io/user/signup", desc:"مجاني جزئياً · فحص مرئي وتحليل متعمق للروابط مع لقطات شاشة" },
    { id:"gsb", name:"Google Safe Browsing API Key", placeholder:"Google API Key", link:"https://developers.google.com/safe-browsing/v4/get-started", desc:"مجاني تماماً · قاعدة بيانات Google لمواقع البرمجيات الخبيثة والتصيد" },
  ];

  return (
    <div className="panel">
      <PH icon={IC.Settings} title="مفاتيح API والإعدادات" />
      <div className="pb">
        <div className="rc rc-info" style={{marginBottom:16,marginTop:0}}>
          <div className="rbadge rb-info"><IC.Lock/>خصوصية تامة</div>
          <p style={{fontSize:12,color:"rgba(255,255,255,.7)"}}>جميع مفاتيح API مخزنة محلياً في متصفحك فقط — لا تُرسل أبداً إلى أي خادم خارجي.</p>
        </div>
        {apiDocs.map(api=>(
          <div key={api.id} className="sk">
            <div className="sk-title">
              <div className="dot" style={{background:form[api.id]?"var(--ok)":"var(--g600)"}}/>
              {api.name}
            </div>
            <div className="irow">
              <input className="inp" type="password" placeholder={api.placeholder}
                value={form[api.id]||""} onChange={e=>setForm({...form,[api.id]:e.target.value})}/>
              {form[api.id] && <button className="btn btn-sm btn-ico btn-d" onClick={()=>setForm({...form,[api.id]:""})}><IC.X/></button>}
            </div>
            <p className="sk-note">{api.desc} · <a className="sk-link" href={api.link} target="_blank" rel="noopener noreferrer">احصل على المفتاح ↗</a></p>
          </div>
        ))}
        <button className="btn btn-p w100" style={{marginTop:8}} onClick={save}>
          {saved ? <><IC.Check/>تم الحفظ</> : "حفظ الإعدادات"}
        </button>
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
//  SCANNER MODULE — VirusTotal + urlscan + GSB + PhishTank
// ══════════════════════════════════════════════════════════════════════════════

const ScannerModule = ({ addHistory, keys }) => {
  const [sub, setSub] = useState("file");
  // File
  const [fileResult, setFileResult] = useState(null);
  const [fileLoading, setFileLoading] = useState(false);
  const [drag, setDrag] = useState(false);
  const [fileProgress, setFileProgress] = useState("");
  const fileRef = useRef();
  // URL
  const [url, setUrl] = useState("");
  const [urlResult, setUrlResult] = useState(null);
  const [urlLoading, setUrlLoading] = useState(false);
  const [urlProgress, setUrlProgress] = useState("");
  // Phish
  const [phishText, setPhishText] = useState("");
  const [phishResult, setPhishResult] = useState(null);
  const [phishLoading, setPhishLoading] = useState(false);

  // ── File Scan ──────────────────────────────────────────────────────────────
  const scanFile = async (file) => {
    if (!file) return;
    setFileLoading(true); setFileResult(null);
    try {
      setFileProgress("جاري حساب SHA-256...");
      const hash = await sha256File(file);
      let vtData = null, vtDetections = 0, vtTotal = 0, vtEngines = [];

      if (keys.vt) {
        setFileProgress("جاري الاستعلام من VirusTotal...");
        try {
          const existing = await vtScanFile(keys.vt, hash);
          if (existing) {
            const stats = existing.data.attributes.last_analysis_stats;
            vtDetections = stats.malicious + stats.suspicious;
            vtTotal = Object.values(stats).reduce((a,b)=>a+b,0);
            vtData = existing.data;
            const engines = existing.data.attributes.last_analysis_results;
            vtEngines = Object.entries(engines).slice(0,12).map(([name,r])=>({name,result:r.result,category:r.category}));
          } else {
            setFileProgress("الملف غير موجود في VT — جاري الرفع...");
            const uploaded = await vtScanFileBinary(keys.vt, file);
            vtData = uploaded;
          }
        } catch(e) { console.warn("VT error:", e.message); }
      }

      // HIBP password check for .txt files under 100 chars
      let pwnCount = 0;
      if (file.size < 100 && file.name.endsWith(".txt")) {
        const txt = await file.text();
        try { pwnCount = await hibpCheckPassword(txt.trim()); } catch {}
      }

      setFileProgress("");
      const result = { hash, name: file.name, size: file.size, vtDetections, vtTotal, vtEngines, vtData, pwnCount };
      setFileResult(result);
      addHistory({ type:"file", value:`${file.name} — ${vtDetections>0?"مشبوه":"آمن ظاهرياً"}` });
    } catch(e) {
      setFileResult({ error: e.message });
    }
    setFileLoading(false);
  };

  // ── URL Scan ───────────────────────────────────────────────────────────────
  const scanUrl = async () => {
    if (!url.trim()) return;
    setUrlLoading(true); setUrlResult(null);
    const sources = {};

    // Local heuristic (always runs)
    const sus = ["phish","malware","hack","evil","xn--","free-iphone","prize","win-"].some(p=>url.toLowerCase().includes(p));
    const isHttp = url.startsWith("http://");
    sources.local = { safe: !sus && !isHttp, label:"فحص محلي", notes: isHttp?"اتصال غير مشفر":sus?"أنماط مشبوهة":"نظيف" };

    // VirusTotal
    if (keys.vt) {
      setUrlProgress("VirusTotal...");
      try {
        let vtRes;
        try { vtRes = await vtScanUrl(keys.vt, url); }
        catch { const sub = await vtSubmitUrl(keys.vt, url); vtRes = sub; }
        if (vtRes?.data?.attributes?.last_analysis_stats) {
          const s = vtRes.data.attributes.last_analysis_stats;
          const det = s.malicious + s.suspicious;
          sources.vt = { safe: det===0, label:"VirusTotal", notes:`${det}/${Object.values(s).reduce((a,b)=>a+b,0)} محرك`, vtData: vtRes.data };
        }
      } catch(e) { sources.vt = { error: e.message, label:"VirusTotal" }; }
    }

    // Google Safe Browsing
    if (keys.gsb) {
      setUrlProgress("Google Safe Browsing...");
      try {
        const r = await gsbLookup(keys.gsb, url);
        const threat = r.matches && r.matches.length > 0;
        sources.gsb = { safe: !threat, label:"Google Safe Browsing", notes: threat ? r.matches.map(m=>m.threatType).join(", ") : "لا تهديدات" };
      } catch(e) { sources.gsb = { error: e.message, label:"Google Safe Browsing" }; }
    }

    // urlscan.io
    if (keys.urlscan) {
      setUrlProgress("urlscan.io...");
      try {
        const submitted = await urlscanSubmit(keys.urlscan, url);
        sources.urlscan = { safe: null, label:"urlscan.io", uuid: submitted.uuid, scanUrl: submitted.result, notes:"جاري الفحص — سيكتمل خلال 30-60 ثانية", pending: true };
      } catch(e) { sources.urlscan = { error: e.message, label:"urlscan.io" }; }
    }

    setUrlProgress("");
    const anyDangerous = Object.values(sources).some(s=>s.safe===false);
    const verdict = anyDangerous ? "خطر" : "آمن ظاهرياً";
    setUrlResult({ url, sources, verdict, dangerous: anyDangerous });
    addHistory({ type:"url", value:`${url} — ${verdict}` });
    setUrlLoading(false);
  };

  // ── Phishing Text ──────────────────────────────────────────────────────────
  const analyzePhish = async () => {
    if (!phishText.trim()) return;
    setPhishLoading(true);
    const local = heuristicPhishing(phishText);

    // Extract URLs from text and scan first one via VT/urlscan
    const urlsInText = phishText.match(/https?:\/\/[^\s]+/g) || [];
    let extResult = null;
    if (urlsInText.length > 0 && keys.vt) {
      try {
        const vtRes = await vtScanUrl(keys.vt, urlsInText[0]);
        if (vtRes?.data?.attributes?.last_analysis_stats) {
          const s = vtRes.data.attributes.last_analysis_stats;
          const det = s.malicious + s.suspicious;
          extResult = { url: urlsInText[0], detections: det, total: Object.values(s).reduce((a,b)=>a+b,0) };
        }
      } catch {}
    }

    setPhishResult({ ...local, extResult, urlsFound: urlsInText.length });
    addHistory({ type:"phishing", value:`نسبة الخطر: ${local.score}%` });
    setPhishLoading(false);
  };

  const subs = [
    {id:"file", label:"فحص الملفات"},
    {id:"url", label:"فحص الروابط"},
    {id:"phish", label:"تحليل التصيد"},
  ];

  return (
    <div className="panel">
      <PH icon={IC.Shield} title="الفاحص المتكامل"
        action={<div style={{display:"flex",alignItems:"center",gap:8}}><ApiStatus keys={keys}/></div>}/>
      <div className="pb">
        <div className="snav">
          {subs.map(s=><button key={s.id} className={`snbtn ${sub===s.id?"on":""}`} onClick={()=>setSub(s.id)}>{s.label}</button>)}
        </div>

        {/* ── FILE ── */}
        {sub==="file" && (
          <div>
            {!keys.vt && <div className="rc rc-warn" style={{marginBottom:12,marginTop:0}}>
              <p style={{fontSize:12}}>⚠ أضف مفتاح VirusTotal في الإعدادات للحصول على نتائج محركات الفحص الـ70+</p>
            </div>}
            <div className={`dz ${drag?"drag":""}`}
              onDragOver={e=>{e.preventDefault();setDrag(true)}}
              onDragLeave={()=>setDrag(false)}
              onDrop={e=>{e.preventDefault();setDrag(false);scanFile(e.dataTransfer.files[0])}}
              onClick={()=>fileRef.current.click()}>
              <IC.File/>
              <p className="dz-text">اسحب الملف أو انقر للاختيار</p>
              <p style={{fontSize:10,color:"var(--g600)",marginTop:4}}>SHA-256 يُحسب محلياً — لا يُرفع الملف إلا عند طلبك للفحص عبر VirusTotal</p>
            </div>
            <input ref={fileRef} type="file" style={{display:"none"}} onChange={e=>scanFile(e.target.files[0])}/>

            {fileLoading && <div className="rc rc-info"><div style={{display:"flex",alignItems:"center",gap:8}}><Spinner/><span style={{fontSize:13}}>{fileProgress||"جاري الفحص..."}</span></div></div>}

            {fileResult && !fileResult.error && (
              <div className={`rc ${fileResult.vtDetections>0?"rc-bad":fileResult.vtTotal>0?"rc-ok":"rc-info"}`}>
                <div className={`rbadge ${fileResult.vtDetections>0?"rb-bad":fileResult.vtTotal>0?"rb-ok":"rb-info"}`}>
                  {fileResult.vtDetections>0?<IC.X/>:<IC.Check/>}
                  {fileResult.vtDetections>0?"تهديد محتمل":fileResult.vtTotal>0?"آمن":"لم يُفحص بعد"}
                </div>
                <p style={{fontSize:13}}>{fileResult.name} · {(fileResult.size/1024).toFixed(1)} كيلوبايت</p>
                {fileResult.vtTotal>0 && (
                  <p style={{fontSize:12,marginTop:6,color:fileResult.vtDetections>0?"var(--danger)":"var(--ok)"}}>
                    {fileResult.vtDetections} اكتشاف من {fileResult.vtTotal} محرك
                  </p>
                )}
                <div className="hash-box">SHA-256: {fileResult.hash}</div>
                {fileResult.vtEngines.length>0 && (
                  <div className="engines">
                    {fileResult.vtEngines.map((e,i)=>(
                      <div key={i} className="engine-card">
                        <div className="engine-name">{e.name}</div>
                        <div className="engine-status" style={{color:e.category==="malicious"?"var(--danger)":e.category==="undetected"?"var(--g400)":"var(--warn)"}}>
                          {e.category==="malicious"?<IC.X/>:e.category==="undetected"?<IC.Check/>:<IC.AlertTriangle/>}
                          <span style={{fontSize:10}}>{e.result||e.category}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {fileResult?.error && <div className="rc rc-warn"><p style={{fontSize:12,color:"var(--warn)"}}>{fileResult.error}</p></div>}
          </div>
        )}

        {/* ── URL ── */}
        {sub==="url" && (
          <div>
            <div className="ig">
              <label className="lbl">الرابط المراد فحصه</label>
              <div className="irow">
                <input className="inp" placeholder="https://example.com" value={url}
                  onChange={e=>setUrl(e.target.value)} onKeyDown={e=>e.key==="Enter"&&scanUrl()}/>
                <button className="btn btn-p" onClick={scanUrl} disabled={urlLoading||!url.trim()}>
                  {urlLoading?<Spinner/>:"فحص"}
                </button>
              </div>
            </div>
            {urlLoading && urlProgress && <div style={{fontSize:12,color:"var(--g400)",marginBottom:10,display:"flex",gap:7,alignItems:"center"}}><Spinner/>{urlProgress}</div>}
            {urlResult && (
              <div className={`rc ${urlResult.dangerous?"rc-bad":"rc-ok"}`}>
                <div className={`rbadge ${urlResult.dangerous?"rb-bad":"rb-ok"}`}>
                  {urlResult.dangerous?<IC.X/>:<IC.Check/>}
                  {urlResult.verdict}
                </div>
                {Object.values(urlResult.sources).map((src,i)=>(
                  <div key={i} className="src-row">
                    <span className="src-name">{src.label}</span>
                    <div style={{display:"flex",alignItems:"center",gap:6}}>
                      <span className="src-status" style={{color:src.error?"var(--g400)":src.safe===null?"var(--warn)":src.safe?"var(--ok)":"var(--danger)"}}>
                        {src.error?`خطأ: ${src.error}`:src.notes}
                      </span>
                      {src.scanUrl && <a href={src.scanUrl} target="_blank" rel="noopener noreferrer" className="btn btn-sm btn-ico" style={{padding:"4px 8px"}} title="عرض نتائج urlscan"><IC.Globe/></a>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── PHISH ── */}
        {sub==="phish" && (
          <div>
            <div className="ig">
              <label className="lbl">نص الرسالة أو البريد الإلكتروني المشبوه</label>
              <textarea className="txta" placeholder="الصق النص هنا..." value={phishText}
                onChange={e=>setPhishText(e.target.value)} rows={5}/>
            </div>
            <button className="btn btn-p w100" onClick={analyzePhish} disabled={phishLoading||!phishText.trim()}>
              {phishLoading?<><Spinner/>جاري التحليل...</>:"تحليل الرسالة"}
            </button>
            {phishResult && (
              <div className={`rc ${phishResult.score>=60?"rc-bad":phishResult.score>0?"rc-warn":"rc-ok"}`}>
                <div className={`rbadge ${phishResult.score>=60?"rb-bad":phishResult.score>0?"rb-warn":"rb-ok"}`}>
                  {phishResult.score>=60?"خطر مرتفع":phishResult.score>0?"مشبوه":"آمن"}
                </div>
                <div className="sb-wrap">
                  <div className="sb-labels"><span>نسبة خطر التصيد</span><span>{phishResult.score}%</span></div>
                  <div className="sb-track"><div className="sb-fill" style={{width:`${phishResult.score}%`,background:phishResult.score>=60?"var(--danger)":phishResult.score>0?"var(--warn)":"var(--ok)"}}/></div>
                </div>
                {phishResult.indicators.map((ind,i)=>(
                  <div key={i} className="ind"><div className="ind-dot"/>{ind}</div>
                ))}
                {phishResult.urlsFound>0 && (
                  <div style={{marginTop:10,paddingTop:10,borderTop:"1px solid rgba(255,255,255,.06)"}}>
                    <p style={{fontSize:11,color:"var(--g400)",marginBottom:6}}>روابط مكتشفة في النص: {phishResult.urlsFound}</p>
                    {phishResult.extResult && (
                      <p style={{fontSize:12,color:phishResult.extResult.detections>0?"var(--danger)":"var(--ok)"}}>
                        VirusTotal: {phishResult.extResult.detections} اكتشاف من {phishResult.extResult.total} محرك على {phishResult.extResult.url.slice(0,40)}...
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
//  IDENTITY MODULE — HIBP + k-Anonymity password check
// ══════════════════════════════════════════════════════════════════════════════

const IdentityModule = ({ addHistory, keys }) => {
  const [sub, setSub] = useState("leak");
  const [email, setEmail] = useState("");
  const [leakResult, setLeakResult] = useState(null);
  const [leakLoading, setLeakLoading] = useState(false);
  const [password, setPassword] = useState("");
  const [pwnResult, setPwnResult] = useState(null);
  const [pwnLoading, setPwnLoading] = useState(false);
  const [genPwd, setGenPwd] = useState("");
  const [showGen, setShowGen] = useState(false);

  const checkLeak = async () => {
    if (!email.trim()) return;
    setLeakLoading(true); setLeakResult(null);
    try {
      if (keys.hibp) {
        const breaches = await hibpCheckEmail(keys.hibp, email);
        setLeakResult({ email, breached: breaches.length>0, breaches, source:"HIBP" });
        addHistory({ type:"leak", value:`${email} — ${breaches.length>0?`${breaches.length} خرق مكتشف`:"آمن"}` });
      } else {
        // demo mode
        const DEMO = ["test@example.com","user@test.com","demo@hackme.org"];
        const breached = DEMO.includes(email.toLowerCase());
        setLeakResult({ email, breached, breaches: breached?[{Name:"Demo Breach",BreachDate:"2023-01-01",Description:"بيانات تجريبية",PwnCount:50000}]:[], source:"demo" });
        addHistory({ type:"leak", value:`${email} — ${breached?"مُخترق (تجريبي)":"آمن"}` });
      }
    } catch(e) { setLeakResult({ error: e.message }); }
    setLeakLoading(false);
  };

  const checkPwned = async () => {
    if (!password.trim()) return;
    setPwnLoading(true); setPwnResult(null);
    try {
      const count = await hibpCheckPassword(password);
      setPwnResult({ count });
      addHistory({ type:"pwned", value:`كلمة مرور — ${count>0?`${count.toLocaleString()} تسريب`:"لم تُكتشف"}` });
    } catch(e) { setPwnResult({ error: e.message }); }
    setPwnLoading(false);
  };

  const e = calcEntropy(password);
  const score = Math.min(4, Math.floor(e/25));
  const colors = ["#ff4444","#ff8844","#ffaa00","#88dd44","#44ff88"];
  const labels = ["ضعيف جداً","ضعيف","متوسط","قوي","ممتاز"];

  return (
    <div className="panel">
      <PH icon={IC.Radar} title="الهوية والأمان" action={<ApiStatus keys={keys}/>}/>
      <div className="pb">
        <div className="snav">
          <button className={`snbtn ${sub==="leak"?"on":""}`} onClick={()=>setSub("leak")}>كاشف التسريبات</button>
          <button className={`snbtn ${sub==="pwd"?"on":""}`} onClick={()=>setSub("pwd")}>فحص كلمة المرور</button>
          <button className={`snbtn ${sub==="gen"?"on":""}`} onClick={()=>setSub("gen")}>مولّد كلمات المرور</button>
        </div>

        {sub==="leak" && (
          <div>
            {!keys.hibp && <div className="rc rc-warn" style={{marginBottom:12,marginTop:0}}>
              <p style={{fontSize:12}}>⚠ بدون مفتاح HIBP ستعمل بوضع تجريبي — أضف المفتاح في الإعدادات للكشف الحقيقي</p>
            </div>}
            <div className="ig">
              <label className="lbl">البريد الإلكتروني</label>
              <div className="irow">
                <input className="inp" type="email" placeholder="email@example.com" value={email}
                  onChange={e=>setEmail(e.target.value)} onKeyDown={e=>e.key==="Enter"&&checkLeak()}/>
                <button className="btn btn-p" onClick={checkLeak} disabled={leakLoading||!email.trim()}>
                  {leakLoading?<Spinner/>:"فحص"}
                </button>
              </div>
            </div>
            {leakResult?.error && <div className="rc rc-warn"><p style={{fontSize:12}}>{leakResult.error}</p></div>}
            {leakResult && !leakResult.error && (
              <div className={`rc ${leakResult.breached?"rc-bad":"rc-ok"}`}>
                <div className={`rbadge ${leakResult.breached?"rb-bad":"rb-ok"}`}>
                  {leakResult.breached?<IC.X/>:<IC.Check/>}
                  {leakResult.breached?`${leakResult.breaches.length} خرق مكتشف`:"لا توجد تسريبات"}
                  {leakResult.source==="demo" && <span style={{opacity:.6}}> (تجريبي)</span>}
                </div>
                {leakResult.breaches.map((b,i)=>(
                  <div key={i} style={{marginBottom:8,paddingBottom:8,borderBottom:i<leakResult.breaches.length-1?"1px solid rgba(255,255,255,.06)":"none"}}>
                    <p style={{fontSize:13,fontWeight:600}}>{b.Name}</p>
                    <p style={{fontSize:11,color:"var(--g400)"}}>{b.BreachDate} · {b.PwnCount?.toLocaleString?.()} حساب مُسرَّب</p>
                    {b.DataClasses && <p style={{fontSize:10,color:"var(--warn)",marginTop:3}}>{b.DataClasses.join(" · ")}</p>}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {sub==="pwd" && (
          <div>
            <div className="rc rc-info" style={{marginBottom:14,marginTop:0}}>
              <p style={{fontSize:12}}>🔒 يستخدم نموذج k-Anonymity — تُرسل فقط أول 5 أحرف من الهاش إلى HIBP، كلمة مرورك الكاملة لا تغادر جهازك أبداً</p>
            </div>
            <div className="ig">
              <label className="lbl">كلمة المرور للفحص</label>
              <div className="irow">
                <input className="inp" type="text" placeholder="أدخل كلمة المرور" value={password}
                  onChange={e=>setPassword(e.target.value)}/>
                <button className="btn btn-p" onClick={checkPwned} disabled={pwnLoading||!password.trim()}>
                  {pwnLoading?<Spinner/>:"فحص"}
                </button>
              </div>
              <PasswordStrength password={password}/>
            </div>
            {password && (
              <div className="rc" style={{borderColor:`${colors[score]}33`,marginTop:10}}>
                <div className="rbadge" style={{background:`${colors[score]}22`,color:colors[score]}}>{labels[score]}</div>
                <div className="g2">
                  <div><p style={{fontSize:10,color:"var(--g400)"}}>الإنتروبيا</p><p style={{fontSize:13,fontFamily:"Space Mono",marginTop:4}}>{Math.round(e)} بت</p></div>
                  <div><p style={{fontSize:10,color:"var(--g400)"}}>وقت الكسر</p><p style={{fontSize:13,marginTop:4,color:colors[score]}}>{timeToCrack(e)}</p></div>
                  <div><p style={{fontSize:10,color:"var(--g400)"}}>الطول</p><p style={{fontSize:13,fontFamily:"Space Mono",marginTop:4}}>{password.length} حرف</p></div>
                  <div><p style={{fontSize:10,color:"var(--g400)"}}>التعقيد</p><p style={{fontSize:13,marginTop:4}}>
                    {/[A-Z]/.test(password)&&<span style={{color:"var(--ok)"}}>A </span>}
                    {/[a-z]/.test(password)&&<span style={{color:"var(--ok)"}}>a </span>}
                    {/[0-9]/.test(password)&&<span style={{color:"var(--ok)"}}>0 </span>}
                    {/[^a-zA-Z0-9]/.test(password)&&<span style={{color:"var(--ok)"}}>!@# </span>}
                  </p></div>
                </div>
              </div>
            )}
            {pwnResult && !pwnResult.error && (
              <div className={`rc ${pwnResult.count>0?"rc-bad":"rc-ok"}`} style={{marginTop:10}}>
                <div className={`rbadge ${pwnResult.count>0?"rb-bad":"rb-ok"}`}>
                  {pwnResult.count>0?<IC.X/>:<IC.Check/>}
                  {pwnResult.count>0?`ظهرت ${pwnResult.count.toLocaleString()} مرة في تسريبات!`:"لم تُرصد في أي تسريب"}
                </div>
                <p style={{fontSize:12}}>{pwnResult.count>0?"استبدل هذه الكلمة فوراً — تم استخدامها في خروقات بيانات موثقة":"كلمة مرورك لم تظهر في قواعد البيانات المسرَّبة المعروفة"}</p>
              </div>
            )}
            {pwnResult?.error && <div className="rc rc-warn" style={{marginTop:10}}><p style={{fontSize:12,color:"var(--warn)"}}>{pwnResult.error}</p></div>}
          </div>
        )}

        {sub==="gen" && (
          <div>
            <div style={{display:"flex",gap:8,marginBottom:14,flexWrap:"wrap"}}>
              {[{l:"قوي — 24 حرف",n:24},{l:"متوسط — 16 حرف",n:16},{l:"بسيط — 12 حرف",n:12}].map(p=>(
                <button key={p.n} className={`btn btn-sm ${p.n===24?"btn-p":""}`}
                  onClick={()=>setGenPwd(generatePassword(p.n))}>{p.l}</button>
              ))}
            </div>
            <div className="irow">
              <input className="inp" type="text" readOnly value={genPwd}
                placeholder="اختر طولاً أعلاه لتوليد كلمة مرور" style={{fontFamily:"Space Mono",fontSize:11}}/>
              <button className="btn btn-p" onClick={()=>setGenPwd(generatePassword(24))}>
                <IC.Refresh/>توليد
              </button>
              {genPwd&&<button className="btn btn-ico" onClick={()=>navigator.clipboard.writeText(genPwd)}><IC.Copy/></button>}
            </div>
            {genPwd && <PasswordStrength password={genPwd}/>}
            <p style={{fontSize:10,color:"var(--g400)",marginTop:8}}>يتم التوليد عبر <span style={{fontFamily:"Space Mono"}}>window.crypto.getRandomValues</span> — آمن تشفيرياً ومحلي بالكامل</p>
          </div>
        )}
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
//  VAULT MODULE v2 — passwords, secrets, notes, files, cards
// ══════════════════════════════════════════════════════════════════════════════

// Entry types config
const VAULT_TYPES = {
  password: { label:"كلمة مرور", icon:()=><IC.Key/>, color:"var(--info)", badgeClass:"badge-password" },
  secret:   { label:"سر / مفتاح", icon:()=><IC.Code/>, color:"var(--purple)", badgeClass:"badge-secret" },
  note:     { label:"ملاحظة آمنة", icon:()=><IC.Note/>, color:"var(--warn)", badgeClass:"badge-note" },
  file:     { label:"ملف مشفر", icon:()=><IC.File/>, color:"var(--ok)", badgeClass:"badge-file" },
  card:     { label:"بطاقة", icon:()=><IC.CreditCard/>, color:"var(--danger)", badgeClass:"badge-card" },
};

const VAULT_CATEGORIES = ["الكل","عمل","شخصي","بنوك","بريد","شبكات اجتماعية","مفاتيح API","مستندات","أخرى"];

// Read a file as base64 data URL
const fileToBase64 = (file) => new Promise((res, rej) => {
  const reader = new FileReader();
  reader.onload = () => res(reader.result);
  reader.onerror = rej;
  reader.readAsDataURL(file);
});

// Format bytes
const fmtSize = (bytes) => {
  if (!bytes) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes/1024).toFixed(1)} KB`;
  return `${(bytes/1048576).toFixed(1)} MB`;
};

// ── Add Entry Modal ───────────────────────────────────────────────────────────
const AddEntryModal = ({ onClose, onSave }) => {
  const [step, setStep] = useState("type"); // "type" | "form"
  const [type, setType] = useState(null);
  const [form, setForm] = useState({ title:"", category:"عمل", tags:"" });
  const [fileData, setFileData] = useState(null);
  const [showPwd, setShowPwd] = useState(false);
  const fileRef = useRef();

  const handleFile = async (file) => {
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) { alert("الحد الأقصى للملف هو 5 ميجابايت"); return; }
    const b64 = await fileToBase64(file);
    setFileData({ name: file.name, size: file.size, mime: file.type, data: b64 });
    setForm(f => ({ ...f, title: f.title || file.name }));
  };

  const canSave = () => {
    if (!form.title) return false;
    if (type === "password") return !!form.password;
    if (type === "secret") return !!form.secret;
    if (type === "note") return !!form.note;
    if (type === "file") return !!fileData;
    if (type === "card") return !!form.cardNumber;
    return false;
  };

  const save = () => {
    const entry = { id: Date.now(), type, ...form, tags: form.tags ? form.tags.split(",").map(t=>t.trim()).filter(Boolean) : [], createdAt: Date.now() };
    if (type === "file") entry.file = fileData;
    onSave(entry);
  };

  return (
    <div className="mbg" onClick={onClose}>
      <div className="detail-modal" style={{maxWidth:460}} onClick={e=>e.stopPropagation()}>
        <div className="mhdr">
          <span className="mtitle">{step==="type" ? "اختر نوع العنصر" : `إضافة ${VAULT_TYPES[type]?.label}`}</span>
          <div style={{display:"flex",gap:6}}>
            {step==="form" && <button className="btn btn-sm" onClick={()=>setStep("type")}>← رجوع</button>}
            <button className="btn btn-sm btn-ico" onClick={onClose}><IC.X/></button>
          </div>
        </div>

        <div className="detail-body">
          {step==="type" && (
            <div className="add-type-grid">
              {Object.entries(VAULT_TYPES).map(([k,v])=>(
                <button key={k} className={`add-type-btn ${type===k?"on":""}`}
                  onClick={()=>{setType(k);setStep("form");}}>
                  <div style={{color:v.color}}><v.icon/></div>
                  <span>{v.label}</span>
                </button>
              ))}
            </div>
          )}

          {step==="form" && (
            <div>
              {/* Common fields */}
              <div className="ig">
                <label className="lbl">العنوان *</label>
                <input className="inp" placeholder={type==="password"?"مثال: Gmail":"عنوان واصف"} value={form.title}
                  onChange={e=>setForm({...form,title:e.target.value})}/>
              </div>
              <div className="ig">
                <label className="lbl">الفئة</label>
                <select className="sel" value={form.category} onChange={e=>setForm({...form,category:e.target.value})}>
                  {VAULT_CATEGORIES.filter(c=>c!=="الكل").map(c=><option key={c}>{c}</option>)}
                </select>
              </div>

              {/* Password */}
              {type==="password" && (<>
                <div className="ig">
                  <label className="lbl">اسم المستخدم / البريد</label>
                  <input className="inp" placeholder="user@example.com" value={form.username||""}
                    onChange={e=>setForm({...form,username:e.target.value})}/>
                </div>
                <div className="ig">
                  <label className="lbl">الرابط (اختياري)</label>
                  <input className="inp" placeholder="https://example.com" value={form.url||""}
                    onChange={e=>setForm({...form,url:e.target.value})}/>
                </div>
                <div className="ig">
                  <label className="lbl">كلمة المرور *</label>
                  <div className="irow">
                    <input className="inp" type={showPwd?"text":"password"} placeholder="أدخل أو ولّد" value={form.password||""}
                      onChange={e=>setForm({...form,password:e.target.value})}/>
                    <button className="btn btn-sm btn-ico" onClick={()=>setShowPwd(p=>!p)}>{showPwd?<IC.EyeOff/>:<IC.Eye/>}</button>
                    <button className="btn btn-sm" onClick={()=>setForm({...form,password:generatePassword()})}><IC.Zap/></button>
                  </div>
                  <PasswordStrength password={form.password||""}/>
                </div>
                <div className="ig">
                  <label className="lbl">ملاحظة (اختياري)</label>
                  <textarea className="txta" rows={2} placeholder="أي معلومات إضافية..." value={form.note||""}
                    onChange={e=>setForm({...form,note:e.target.value})}/>
                </div>
              </>)}

              {/* Secret / API Key */}
              {type==="secret" && (<>
                <div className="ig">
                  <label className="lbl">النوع</label>
                  <select className="sel" value={form.secretType||"api_key"} onChange={e=>setForm({...form,secretType:e.target.value})}>
                    {["api_key","token","certificate","env_var","ssh_key","other"].map(s=><option key={s} value={s}>{
                      {api_key:"مفتاح API",token:"رمز Token",certificate:"شهادة",env_var:"متغير بيئة",ssh_key:"مفتاح SSH",other:"أخرى"}[s]
                    }</option>)}
                  </select>
                </div>
                <div className="ig">
                  <label className="lbl">القيمة السرية *</label>
                  <div className="irow">
                    <textarea className="txta" rows={3} placeholder="الصق السر هنا..." value={form.secret||""}
                      onChange={e=>setForm({...form,secret:e.target.value})} style={{fontFamily:"Space Mono",fontSize:11}}/>
                  </div>
                </div>
                <div className="ig">
                  <label className="lbl">الخدمة / المصدر</label>
                  <input className="inp" placeholder="مثال: AWS, OpenAI, GitHub..." value={form.service||""}
                    onChange={e=>setForm({...form,service:e.target.value})}/>
                </div>
                <div className="ig">
                  <label className="lbl">تاريخ انتهاء الصلاحية (اختياري)</label>
                  <input className="inp" type="date" value={form.expiresAt||""}
                    onChange={e=>setForm({...form,expiresAt:e.target.value})}/>
                </div>
              </>)}

              {/* Secure Note */}
              {type==="note" && (<>
                <div className="ig">
                  <label className="lbl">محتوى الملاحظة *</label>
                  <textarea className="txta" rows={7} placeholder="اكتب ملاحظتك السرية هنا..." value={form.note||""}
                    onChange={e=>setForm({...form,note:e.target.value})}/>
                </div>
              </>)}

              {/* File */}
              {type==="file" && (<>
                {!fileData ? (
                  <div className="file-dz" onClick={()=>fileRef.current.click()}
                    onDragOver={e=>e.preventDefault()}
                    onDrop={e=>{e.preventDefault();handleFile(e.dataTransfer.files[0]);}}>
                    <IC.Upload/>
                    <p style={{fontSize:12,color:"var(--g400)",marginTop:8}}>اسحب ملفاً أو انقر للاختيار</p>
                    <p style={{fontSize:10,color:"var(--g600)",marginTop:4}}>الحد الأقصى 5 ميجابايت — يُشفَّر محلياً</p>
                    <input ref={fileRef} type="file" style={{display:"none"}} onChange={e=>handleFile(e.target.files[0])}/>
                  </div>
                ) : (
                  <div className="rc rc-ok" style={{marginTop:0}}>
                    <div className="rbadge rb-ok"><IC.Check/>تم الرفع</div>
                    <p style={{fontSize:13}}>{fileData.name}</p>
                    <p style={{fontSize:11,color:"var(--g400)",marginTop:3}}>{fmtSize(fileData.size)} · {fileData.mime||"unknown"}</p>
                    <button className="btn btn-sm btn-d" style={{marginTop:10}} onClick={()=>setFileData(null)}>إزالة الملف</button>
                  </div>
                )}
                <div className="ig" style={{marginTop:12}}>
                  <label className="lbl">وصف الملف (اختياري)</label>
                  <input className="inp" placeholder="وصف مختصر للملف..." value={form.description||""}
                    onChange={e=>setForm({...form,description:e.target.value})}/>
                </div>
              </>)}

              {/* Card */}
              {type==="card" && (<>
                <div className="ig">
                  <label className="lbl">اسم حامل البطاقة</label>
                  <input className="inp" placeholder="الاسم كما هو على البطاقة" value={form.cardHolder||""}
                    onChange={e=>setForm({...form,cardHolder:e.target.value})}/>
                </div>
                <div className="ig">
                  <label className="lbl">رقم البطاقة *</label>
                  <input className="inp" placeholder="XXXX XXXX XXXX XXXX" maxLength={19} value={form.cardNumber||""}
                    onChange={e=>setForm({...form,cardNumber:e.target.value.replace(/\D/g,"").replace(/(.{4})/g,"$1 ").trim()})}
                    style={{fontFamily:"Space Mono",letterSpacing:2}}/>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
                  <div className="ig">
                    <label className="lbl">تاريخ الانتهاء</label>
                    <input className="inp" placeholder="MM/YY" maxLength={5} value={form.cardExp||""}
                      onChange={e=>setForm({...form,cardExp:e.target.value})}/>
                  </div>
                  <div className="ig">
                    <label className="lbl">CVV</label>
                    <input className="inp" placeholder="XXX" maxLength={4} type="password" value={form.cardCvv||""}
                      onChange={e=>setForm({...form,cardCvv:e.target.value})}/>
                  </div>
                </div>
                <div className="ig">
                  <label className="lbl">البنك / المُصدِر</label>
                  <input className="inp" placeholder="مثال: Al Rajhi, SNB..." value={form.bank||""}
                    onChange={e=>setForm({...form,bank:e.target.value})}/>
                </div>
                <div className="ig">
                  <label className="lbl">الرقم السري (PIN) — اختياري</label>
                  <input className="inp" type="password" placeholder="----" maxLength={6} value={form.pin||""}
                    onChange={e=>setForm({...form,pin:e.target.value})}/>
                </div>
              </>)}

              {/* Tags */}
              <div className="ig">
                <label className="lbl">وسوم / Tags (مفصولة بفاصلة)</label>
                <input className="inp" placeholder="عمل, مهم, 2024..." value={form.tags||""}
                  onChange={e=>setForm({...form,tags:e.target.value})}/>
              </div>
            </div>
          )}
        </div>

        {step==="form" && (
          <div className="mftr">
            <button className="btn" onClick={onClose}>إلغاء</button>
            <button className="btn btn-p" onClick={save} disabled={!canSave()}>حفظ مشفراً</button>
          </div>
        )}
      </div>
    </div>
  );
};

// ── Detail View Modal ─────────────────────────────────────────────────────────
const DetailModal = ({ entry, onClose, onDelete }) => {
  const [reveal, setReveal] = useState({});
  const [copied, setCopied] = useState(null);
  const T = VAULT_TYPES[entry.type] || VAULT_TYPES.password;

  const copy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopied(key); setTimeout(()=>setCopied(null), 1500);
  };

  const downloadFile = () => {
    if (!entry.file) return;
    const a = document.createElement("a");
    a.href = entry.file.data;
    a.download = entry.file.name;
    a.click();
  };

  const FieldRow = ({ label, value, secret=false, copyKey, mono=false }) => (
    <div className="detail-field">
      <div className="detail-label">{label}</div>
      <div style={{display:"flex",gap:6,alignItems:"flex-start"}}>
        <div className={`detail-val ${secret&&!reveal[copyKey]?"blur":""}`}
          style={{flex:1,fontFamily:mono?"Space Mono,monospace":"Tajawal,sans-serif",fontSize:mono?11:13}}
          onClick={()=>secret&&setReveal(r=>({...r,[copyKey]:!r[copyKey]}))}>
          {secret&&!reveal[copyKey]?"انقر للكشف":value}
        </div>
        {value && <button className="btn btn-sm btn-ico" style={{color:copied===copyKey?"var(--ok)":undefined,flexShrink:0}}
          onClick={()=>copy(value,copyKey)}>{copied===copyKey?<IC.Check/>:<IC.Copy/>}</button>}
      </div>
    </div>
  );

  return (
    <div className="mbg" onClick={onClose}>
      <div className="detail-modal" onClick={e=>e.stopPropagation()}>
        <div className="mhdr">
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <div style={{color:T.color}}><T.icon/></div>
            <div>
              <div className="mtitle">{entry.title}</div>
              <div style={{fontSize:10,color:"var(--g400)",marginTop:2}}>{entry.category} · {new Date(entry.createdAt).toLocaleDateString("ar-SA")}</div>
            </div>
          </div>
          <button className="btn btn-sm btn-ico" onClick={onClose}><IC.X/></button>
        </div>

        <div className="detail-body">
          {/* PASSWORD */}
          {entry.type==="password" && (<>
            {entry.username && <FieldRow label="اسم المستخدم" value={entry.username} copyKey="username"/>}
            {entry.url && <FieldRow label="الرابط" value={entry.url} copyKey="url"/>}
            <FieldRow label="كلمة المرور" value={entry.password} secret copyKey="password" mono/>
            {entry.password && <PasswordStrength password={entry.password}/>}
            {entry.note && <FieldRow label="ملاحظة" value={entry.note} copyKey="note"/>}
          </>)}

          {/* SECRET */}
          {entry.type==="secret" && (<>
            {entry.service && <FieldRow label="الخدمة" value={entry.service} copyKey="service"/>}
            {entry.secretType && <div className="detail-field"><div className="detail-label">النوع</div>
              <div className="detail-val" style={{fontFamily:"inherit"}}>{
                {api_key:"مفتاح API",token:"رمز Token",certificate:"شهادة",env_var:"متغير بيئة",ssh_key:"مفتاح SSH",other:"أخرى"}[entry.secretType]||entry.secretType
              }</div></div>}
            <FieldRow label="القيمة السرية" value={entry.secret} secret copyKey="secret" mono/>
            {entry.expiresAt && <FieldRow label="تاريخ الانتهاء" value={entry.expiresAt} copyKey="exp"/>}
          </>)}

          {/* NOTE */}
          {entry.type==="note" && (
            <div className="detail-field">
              <div className="detail-label">الملاحظة</div>
              <div className="file-preview-box">{entry.note}</div>
            </div>
          )}

          {/* FILE */}
          {entry.type==="file" && entry.file && (<>
            <div className="detail-field">
              <div className="detail-label">الملف</div>
              <div className="detail-val" style={{fontFamily:"Space Mono,monospace",fontSize:11}}>
                {entry.file.name}{"\n"}{fmtSize(entry.file.size)} · {entry.file.mime}
              </div>
            </div>
            {entry.file.mime?.startsWith("image/") && (
              <img src={entry.file.data} alt={entry.file.name} className="file-thumb"/>
            )}
            {entry.file.mime?.startsWith("text/") && (
              <div className="detail-field">
                <div className="detail-label">المعاينة</div>
                <div className="file-preview-box">{atob(entry.file.data.split(",")[1])}</div>
              </div>
            )}
            {entry.description && <FieldRow label="الوصف" value={entry.description} copyKey="desc"/>}
            <button className="btn btn-p w100" style={{marginTop:10}} onClick={downloadFile}>
              <IC.Download/>تنزيل الملف
            </button>
          </>)}

          {/* CARD */}
          {entry.type==="card" && (<>
            {entry.cardHolder && <FieldRow label="حامل البطاقة" value={entry.cardHolder} copyKey="ch"/>}
            <FieldRow label="رقم البطاقة" value={entry.cardNumber} secret copyKey="cn" mono/>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
              {entry.cardExp && <FieldRow label="الانتهاء" value={entry.cardExp} copyKey="exp"/>}
              {entry.cardCvv && <FieldRow label="CVV" value={entry.cardCvv} secret copyKey="cvv" mono/>}
            </div>
            {entry.bank && <FieldRow label="البنك" value={entry.bank} copyKey="bank"/>}
            {entry.pin && <FieldRow label="الرقم السري" value={entry.pin} secret copyKey="pin" mono/>}
          </>)}

          {/* Tags */}
          {entry.tags?.length>0 && (
            <div style={{marginTop:12,display:"flex",gap:5,flexWrap:"wrap"}}>
              {entry.tags.map((t,i)=><span key={i} className="tag" style={{fontSize:10}}>{t}</span>)}
            </div>
          )}
        </div>

        <div className="mftr">
          <button className="btn btn-d btn-sm" onClick={()=>{onDelete(entry.id);onClose();}}>
            <IC.Trash/>حذف
          </button>
          <button className="btn" onClick={onClose}>إغلاق</button>
        </div>
      </div>
    </div>
  );
};

// ── Main Vault ────────────────────────────────────────────────────────────────
const VaultModule = ({ addHistory }) => {
  const [locked, setLocked] = useState(true);
  const [masterPwd, setMasterPwd] = useState("");
  const [entries, setEntries] = useState([]);
  const [showAdd, setShowAdd] = useState(false);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [activeType, setActiveType] = useState("all");
  const [activeCat, setActiveCat] = useState("الكل");

  const unlock = async () => {
    if (masterPwd.length<6){setError("يجب أن تكون 6 أحرف على الأقل");return;}
    const enc = ls.get("vault_data_v2");
    if (enc) {
      try { setEntries(await decryptVault(enc, masterPwd)); }
      catch { setError("كلمة المرور غير صحيحة"); return; }
    } else { setEntries([]); }
    setLocked(false); setError("");
  };

  const save = async (list) => {
    const encrypted = await encryptVault(list, masterPwd);
    ls.set("vault_data_v2", encrypted);
  };

  const handleAdd = (entry) => {
    const ne = [...entries, entry];
    setEntries(ne); save(ne); setShowAdd(false);
    addHistory({type:"vault", value:`إضافة ${VAULT_TYPES[entry.type]?.label}: ${entry.title}`});
  };

  const handleDelete = (id) => {
    const ne = entries.filter(e=>e.id!==id);
    setEntries(ne); save(ne);
  };

  // Filter
  const filtered = entries.filter(e => {
    const q = search.toLowerCase();
    const matchSearch = !q || e.title?.toLowerCase().includes(q) ||
      e.username?.toLowerCase().includes(q) || e.service?.toLowerCase().includes(q) ||
      e.tags?.some(t=>t.toLowerCase().includes(q));
    const matchType = activeType==="all" || e.type===activeType;
    const matchCat = activeCat==="الكل" || e.category===activeCat;
    return matchSearch && matchType && matchCat;
  });

  // Stats
  const counts = Object.keys(VAULT_TYPES).reduce((acc,k)=>({...acc,[k]:entries.filter(e=>e.type===k).length}),{});

  if (locked) return (
    <div className="panel">
      <PH icon={IC.Lock} title="الخزينة الآمنة"/>
      <div className="pb" style={{textAlign:"center",padding:"52px 24px"}}>
        <div style={{marginBottom:20,opacity:.25,transform:"scale(1.4)"}}><IC.Lock/></div>
        <p style={{fontSize:13,color:"var(--g400)",marginBottom:6}}>خزينة مشفرة بـ AES-256-GCM</p>
        <p style={{fontSize:11,color:"var(--g600)",marginBottom:22}}>كلمات مرور · مفاتيح API · ملاحظات · ملفات · بطاقات</p>
        {error&&<p style={{fontSize:12,color:"var(--danger)",marginBottom:12}}>{error}</p>}
        <div className="irow" style={{maxWidth:340,margin:"0 auto"}}>
          <input className="inp" type="password" placeholder="كلمة المرور الرئيسية"
            value={masterPwd} onChange={e=>setMasterPwd(e.target.value)} onKeyDown={e=>e.key==="Enter"&&unlock()}/>
          <button className="btn btn-p" onClick={unlock}>فتح</button>
        </div>
        <p style={{fontSize:10,color:"var(--g600)",marginTop:14}}>PBKDF2 · 100,000 تكرار · محلي بالكامل</p>
      </div>
    </div>
  );

  return (
    <>
      <div className="panel">
        {/* Header */}
        <PH icon={IC.Lock} title={`الخزينة الآمنة (${entries.length})`} action={
          <div style={{display:"flex",gap:7}}>
            <button className="btn btn-sm btn-d" onClick={()=>{setLocked(true);setMasterPwd("");}}>قفل</button>
            <button className="btn btn-sm btn-p" onClick={()=>setShowAdd(true)}><IC.Plus/>إضافة</button>
          </div>
        }/>

        {/* Stats row */}
        {entries.length>0 && (
          <div className="vault-stats">
            {Object.entries(VAULT_TYPES).map(([k,v])=>counts[k]>0&&(
              <div key={k} className="stat-pill" style={{cursor:"pointer",borderColor:activeType===k?"rgba(255,255,255,.2)":"var(--gb)"}}
                onClick={()=>setActiveType(activeType===k?"all":k)}>
                <div className="stat-dot" style={{background:v.color}}/>
                <span style={{color:activeType===k?"#fff":"var(--g400)"}}>{v.label}</span>
                <span style={{fontSize:10,fontFamily:"Space Mono",color:v.color}}>{counts[k]}</span>
              </div>
            ))}
          </div>
        )}

        {/* Type tabs */}
        <div className="vault-tabs">
          <button className={`vtab ${activeType==="all"?"on":""}`} onClick={()=>setActiveType("all")}>
            الكل <span className="vtab-count">{entries.length}</span>
          </button>
          {Object.entries(VAULT_TYPES).map(([k,v])=>(
            <button key={k} className={`vtab ${activeType===k?"on":""}`} onClick={()=>setActiveType(k)}>
              <span style={{color:activeType===k?v.color:"inherit"}}><v.icon/></span>
              {v.label}
              {counts[k]>0&&<span className="vtab-count">{counts[k]}</span>}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="vault-search">
          <IC.Search/>
          <input className="inp" placeholder="ابحث في الخزينة..." value={search}
            onChange={e=>setSearch(e.target.value)} style={{border:"none",background:"transparent",padding:"4px 0",outline:"none",fontSize:13}}/>
          {search && <button className="btn btn-sm btn-ico" onClick={()=>setSearch("")}><IC.X/></button>}
        </div>

        {/* Category filter */}
        <div className="vault-filter">
          {VAULT_CATEGORIES.map(c=>(
            <button key={c} className={`vf-chip ${activeCat===c?"on":""}`} onClick={()=>setActiveCat(c)}>{c}</button>
          ))}
        </div>

        {/* Entries list */}
        <div className="pb">
          {filtered.length===0 ? (
            <div className="vault-empty">
              <div style={{opacity:.2,marginBottom:12}}><IC.Key/></div>
              <p style={{fontSize:13}}>{entries.length===0?"الخزينة فارغة — أضف أول عنصر":"لا نتائج للبحث"}</p>
            </div>
          ) : filtered.map(e => {
            const T = VAULT_TYPES[e.type] || VAULT_TYPES.password;
            return (
              <div key={e.id} className={`vi2 type-${e.type}`} onClick={()=>setSelected(e)}>
                <div className="vi2-icon"><T.icon/></div>
                <div className="vi2-body">
                  <div className="vi2-title">{e.title}</div>
                  <div className="vi2-sub">
                    {e.type==="password" && (e.username||e.url||"—")}
                    {e.type==="secret" && (e.service ? `${e.service} · ` : "") + ({api_key:"مفتاح API",token:"Token",certificate:"شهادة",env_var:"ENV",ssh_key:"SSH",other:"سر"}[e.secretType]||"")}
                    {e.type==="note" && (e.note||"").slice(0,60)+(e.note?.length>60?"...":"")}
                    {e.type==="file" && e.file && `${e.file.name} · ${fmtSize(e.file.size)}`}
                    {e.type==="card" && e.cardNumber && `**** **** **** ${e.cardNumber.replace(/\s/g,"").slice(-4)}`}
                  </div>
                  <div className="vi2-meta">
                    <span className={`vi2-type ${T.badgeClass}`}>{T.label}</span>
                    {e.category && <span className="tag">{e.category}</span>}
                    {e.tags?.slice(0,2).map((t,i)=><span key={i} className="tag">{t}</span>)}
                    {e.type==="secret"&&e.expiresAt&&new Date(e.expiresAt)<new Date()&&
                      <span style={{fontSize:9,color:"var(--danger)"}}>⚠ منتهي</span>}
                  </div>
                </div>
                <div className="vi2-actions" onClick={ev=>ev.stopPropagation()}>
                  <button className="btn btn-sm btn-ico btn-d" onClick={()=>handleDelete(e.id)}><IC.Trash/></button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {showAdd && <AddEntryModal onClose={()=>setShowAdd(false)} onSave={handleAdd}/>}
      {selected && <DetailModal entry={selected} onClose={()=>setSelected(null)} onDelete={id=>{handleDelete(id);setSelected(null);}}/>}
    </>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
//  EXTENSION MODULE — Download Manifest V3 extension files
// ══════════════════════════════════════════════════════════════════════════════

const ExtensionModule = () => {
  const manifest = JSON.stringify({
    manifest_version: 3,
    name: "افحص لي — Scan For Me",
    version: "1.0.0",
    description: "أداة أمن سيبراني متكاملة: فحص الملفات، الروابط، التصيد، وخزينة كلمات المرور",
    permissions: ["storage", "clipboardWrite", "activeTab"],
    host_permissions: [
      "https://www.virustotal.com/*",
      "https://haveibeenpwned.com/*",
      "https://api.pwnedpasswords.com/*",
      "https://urlscan.io/*",
      "https://safebrowsing.googleapis.com/*"
    ],
    action: {
      default_popup: "popup.html",
      default_icon: { "16": "icon16.png", "48": "icon48.png", "128": "icon128.png" },
      default_title: "افحص لي"
    },
    icons: { "16": "icon16.png", "48": "icon48.png", "128": "icon128.png" },
    content_security_policy: {
      extension_pages: "script-src 'self'; object-src 'self'"
    }
  }, null, 2);

  const popupHtml = `<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>افحص لي</title>
  <style>
    body { width: 400px; min-height: 560px; margin: 0; background: #000; color: #fff; }
  </style>
</head>
<body>
  <div id="root"></div>
  <script type="module" src="./popup.js"></script>
</body>
</html>`;

  const bgScript = `// background.js — Service Worker (Manifest V3)
chrome.runtime.onInstalled.addListener(() => {
  console.log('افحص لي installed');
});

// Handle messages from popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'FETCH_API') {
    fetch(msg.url, msg.options)
      .then(r => r.json())
      .then(data => sendResponse({ ok: true, data }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true; // async
  }
});`;

  const steps = [
    { n:"1", desc:"قم بتنزيل ملف popup.html وملف ScanForMe.jsx وحوّل JSX إلى JavaScript باستخدام Vite أو Create React App", code:`npm create vite@latest scanforme -- --template react
cd scanforme && npm install
# انسخ ScanForMe.jsx إلى src/App.jsx
npm run build` },
    { n:"2", desc:"انسخ ملف manifest.json وbackground.js إلى مجلد dist/ بعد البناء", code:`cp manifest.json dist/
cp background.js dist/
cp popup.html dist/` },
    { n:"3", desc:"افتح Chrome أو Edge وانتقل إلى صفحة الإضافات", code:`chrome://extensions/
# فعّل 'وضع المطور' في أعلى الصفحة` },
    { n:"4", desc:"انقر 'تحميل غير مضغوط' واختر مجلد dist/ — ستظهر الإضافة في شريط الأدوات فوراً", code:`# تأكد من وجود هذه الملفات في dist/:
# ✓ manifest.json
# ✓ popup.html
# ✓ background.js
# ✓ index.js (مُجمَّع من React)
# ✓ index.css` },
  ];

  const downloadFile = (content, filename, type="application/json") => {
    const blob = new Blob([content], {type});
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
  };

  return (
    <div className="panel">
      <PH icon={IC.Puzzle} title="إضافة المتصفح — Chrome / Edge Manifest V3"/>
      <div className="pb">
        <div className="rc rc-info" style={{marginTop:0,marginBottom:18}}>
          <div className="rbadge rb-info"><IC.Globe/>متوافق مع Chrome & Edge</div>
          <p style={{fontSize:12,color:"rgba(255,255,255,.7)"}}>هذا التطبيق مبني ليعمل كإضافة Manifest V3. اتبع الخطوات أدناه لتثبيته محلياً.</p>
        </div>

        <div style={{marginBottom:20}}>
          <p style={{fontSize:13,fontWeight:600,marginBottom:12,color:"rgba(255,255,255,.8)"}}>تنزيل ملفات الإضافة</p>
          <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
            <button className="btn" onClick={()=>downloadFile(manifest,"manifest.json")}><IC.Download/>manifest.json</button>
            <button className="btn" onClick={()=>downloadFile(bgScript,"background.js","text/javascript")}><IC.Download/>background.js</button>
            <button className="btn" onClick={()=>downloadFile(popupHtml,"popup.html","text/html")}><IC.Download/>popup.html</button>
          </div>
        </div>

        <div className="div"/>
        <p style={{fontSize:13,fontWeight:600,marginBottom:16,color:"rgba(255,255,255,.8)"}}>خطوات التثبيت</p>
        {steps.map(s=>(
          <div key={s.n} className="ext-step">
            <div className="ext-num">{s.n}</div>
            <div style={{flex:1}}>
              <p className="ext-desc">{s.desc}</p>
              <pre className="ext-code">{s.code}</pre>
            </div>
          </div>
        ))}

        <div className="div"/>
        <div className="rc rc-warn" style={{marginTop:0}}>
          <div className="rbadge rb-warn"><IC.AlertTriangle/>ملاحظة CORS</div>
          <p style={{fontSize:12,color:"rgba(255,255,255,.7)"}}>
            بعض نقاط API (مثل HIBP) تتطلب طلبات من background.js بدلاً من popup مباشرة بسبب قيود CORS.
            يتعامل background.js المُرفق مع هذا تلقائياً عبر <span style={{fontFamily:"Space Mono",fontSize:10}}>chrome.runtime.sendMessage</span>.
          </p>
        </div>
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
//  HISTORY MODULE
// ══════════════════════════════════════════════════════════════════════════════

const HistoryModule = ({ history, clearHistory }) => {
  const labels = {vault:"خزينة",file:"ملف",url:"رابط",phishing:"تصيد",leak:"تسريب",pwned:"كلمة مرور"};
  const colors = {vault:"var(--info)",file:"var(--ok)",url:"var(--warn)",phishing:"var(--danger)",leak:"var(--warn)",pwned:"var(--purple)"};
  return (
    <div className="panel">
      <PH icon={IC.History} title="سجل الفحوصات"
        action={history.length>0&&<button className="btn btn-sm btn-d" onClick={clearHistory}>مسح السجل</button>}/>
      <div className="pb">
        {history.length===0 ? (
          <div className="empty"><div className="empty-ico"><IC.History/></div><p style={{fontSize:13}}>لا توجد سجلات بعد</p></div>
        ) : [...history].reverse().map((h,i)=>(
          <div key={i} className="hi">
            <div>
              <div className="hi-type" style={{color:colors[h.type]||"var(--g400)"}}>{labels[h.type]||h.type}</div>
              <div className="hi-val">{h.value}</div>
            </div>
            <div className="hi-time">{new Date(h.time).toLocaleTimeString("ar-SA")}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
//  ROOT APP
// ══════════════════════════════════════════════════════════════════════════════

export default function App() {
  const [tab, setTab] = useState("vault");
  const [history, setHistory] = useState(()=>ls.get("scan_history",[]));
  const [keys, setKeys] = useState(()=>ls.get("api_keys",{vt:"",hibp:"",urlscan:"",gsb:""}));

  const addHistory = useCallback((entry) => {
    setHistory(prev => {
      const next = [...prev, {...entry, time:Date.now()}];
      ls.set("scan_history", next);
      return next;
    });
  }, []);

  const clearHistory = () => { setHistory([]); ls.set("scan_history",[]); };

  const activeCount = Object.values(keys).filter(Boolean).length;

  const nav = [
    {id:"vault", label:"الخزينة", icon:IC.Lock},
    {id:"scanner", label:"الفاحص", icon:IC.Shield},
    {id:"identity", label:"الهوية", icon:IC.Radar},
    {id:"extension", label:"الإضافة", icon:IC.Puzzle},
    {id:"settings", label:"API", icon:IC.Settings},
    {id:"history", label:"السجلات", icon:IC.History},
  ];

  return (
    <>
      <style>{CSS}</style>
      <div className="app">
        <div className="orb"/>
        <div className="z1">
          <header className="hdr">
            <div className="logo">
              <div className="logo-ico"><IC.Shield/></div>
              <div>
                <span>افحص لي</span>
                <span className="logo-sub">SCAN FOR ME</span>
              </div>
            </div>
            <div className="hdr-right">
              <div className="hdr-badge" style={{color:activeCount>0?"var(--ok)":undefined}}>
                {activeCount}/4 API
              </div>
              <div className="hdr-badge">ZERO-KNOWLEDGE · v2.0</div>
            </div>
          </header>

          <nav className="nav">
            {nav.map(item=>(
              <button key={item.id} className={`nbtn ${tab===item.id?"on":""}`} onClick={()=>setTab(item.id)}>
                <item.icon/>{item.label}
                {item.id==="history"&&history.length>0&&<span className="badge-cnt">{history.length}</span>}
                {item.id==="settings"&&activeCount>0&&<span className="badge-cnt" style={{color:"var(--ok)"}}>{activeCount}</span>}
              </button>
            ))}
          </nav>

          <main className="main">
            {tab==="vault"     && <VaultModule addHistory={addHistory}/>}
            {tab==="scanner"   && <ScannerModule addHistory={addHistory} keys={keys}/>}
            {tab==="identity"  && <IdentityModule addHistory={addHistory} keys={keys}/>}
            {tab==="extension" && <ExtensionModule/>}
            {tab==="settings"  && <SettingsModule keys={keys} setKeys={setKeys}/>}
            {tab==="history"   && <HistoryModule history={history} clearHistory={clearHistory}/>}
          </main>
        </div>
      </div>
    </>
  );
}
