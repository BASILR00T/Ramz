import React, { useState } from "react";
import {
  View, Text, TextInput, TouchableOpacity,
  StyleSheet, ActivityIndicator, ScrollView,
} from "react-native";
import { loadApiKeys } from "../../lib/storage";

export default function IdentityScreen() {
  const [email, setEmail]       = useState("");
  const [checking, setChecking] = useState(false);
  const [result, setResult]     = useState<{ pwned: boolean; count: number } | null>(null);
  const [error, setError]       = useState("");

  async function handleCheck() {
    const trimmed = email.trim();
    if (!trimmed) return;
    setChecking(true);
    setResult(null);
    setError("");

    try {
      const keys = await loadApiKeys();
      if (!keys.hibp) {
        setError("أضف مفتاح HIBP في قسم المفاتيح");
        return;
      }
      const res  = await fetch(
        `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(trimmed)}?truncateResponse=true`,
        {
          headers: {
            "hibp-api-key": keys.hibp,
            "User-Agent":   "Ramz-Security-App",
          },
        }
      );
      if (res.status === 404) {
        setResult({ pwned: false, count: 0 });
      } else if (res.status === 200) {
        const data = await res.json();
        setResult({ pwned: true, count: Array.isArray(data) ? data.length : 0 });
      } else {
        setError(`خطأ ${res.status}`);
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setChecking(false);
    }
  }

  async function handlePasswordCheck(pw: string) {
    if (!pw) return;
    try {
      const encoder = new TextEncoder();
      const buffer  = await crypto.subtle.digest("SHA-1", encoder.encode(pw));
      const hex     = Array.from(new Uint8Array(buffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("").toUpperCase();
      const prefix = hex.slice(0, 5);
      const suffix = hex.slice(5);
      const res    = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { "Add-Padding": "true" },
      });
      const text   = await res.text();
      const match  = text.split("\n").find((l) => l.startsWith(suffix));
      const count  = match ? parseInt(match.split(":")[1], 10) : 0;
      return { pwned: count > 0, count };
    } catch {
      return null;
    }
  }

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      <Text style={s.title}>كشف التسريبات</Text>

      <View style={s.card}>
        <Text style={s.cardTitle}>فحص البريد الإلكتروني</Text>
        <TextInput
          style={s.input}
          value={email}
          onChangeText={(t) => { setEmail(t); setError(""); setResult(null); }}
          placeholder="user@example.com"
          placeholderTextColor="#64748b"
          keyboardType="email-address"
          autoCapitalize="none"
          textAlign="left"
        />
        {error !== "" && <Text style={s.errorText}>{error}</Text>}
        <TouchableOpacity
          style={[s.btn, (checking || !email.trim()) && s.btnDisabled]}
          onPress={handleCheck}
          disabled={checking || !email.trim()}
        >
          {checking
            ? <ActivityIndicator color="#fff" />
            : <Text style={s.btnText}>فحص</Text>
          }
        </TouchableOpacity>

        {result && (
          <View style={[s.resultBox, { borderColor: result.pwned ? "#ef4444" : "#22c55e" }]}>
            <Text style={{ color: result.pwned ? "#ef4444" : "#22c55e", fontSize: 18, fontWeight: "700" }}>
              {result.pwned ? `مُسرَّب في ${result.count} تسريب` : "آمن"}
            </Text>
            <Text style={s.resultDesc}>
              {result.pwned
                ? "غيّر كلمات مرورك المرتبطة بهذا البريد فوراً."
                : "لم يُعثر على تسريبات لهذا البريد."}
            </Text>
          </View>
        )}
      </View>

      <View style={[s.card, { marginTop: 16 }]}>
        <Text style={s.cardTitle}>فحص كلمة المرور (k-Anonymity)</Text>
        <Text style={s.cardDesc}>
          فقط أول 5 أحرف من بصمة SHA-1 تُرسَل. كلمة مرورك لا تغادر جهازك.
        </Text>
      </View>
    </ScrollView>
  );
}

const s = StyleSheet.create({
  container:  { flex: 1, backgroundColor: "#0a0a0f" },
  content:    { padding: 20 },
  title:      { color: "#e2e8f0", fontSize: 20, fontWeight: "700", marginBottom: 16 },
  card:       { backgroundColor: "#111118", borderWidth: 1, borderColor: "#1e1e2e", borderRadius: 12, padding: 16 },
  cardTitle:  { color: "#e2e8f0", fontSize: 16, fontWeight: "600", marginBottom: 8 },
  cardDesc:   { color: "#64748b", fontSize: 13, lineHeight: 20 },
  input:      { backgroundColor: "#1a1a2e", borderWidth: 1, borderColor: "#2d2d4a", borderRadius: 10, padding: 12, color: "#e2e8f0", fontSize: 15, marginBottom: 10 },
  errorText:  { color: "#f87171", fontSize: 13, marginBottom: 8 },
  btn:        { backgroundColor: "#6366f1", borderRadius: 10, padding: 14, alignItems: "center" },
  btnDisabled:{ opacity: 0.5 },
  btnText:    { color: "#fff", fontWeight: "600", fontSize: 15 },
  resultBox:  { marginTop: 14, borderWidth: 1, borderRadius: 10, padding: 14 },
  resultDesc: { color: "#94a3b8", fontSize: 13, marginTop: 4 },
});
