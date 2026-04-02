import React, { useState } from "react";
import {
  View, Text, TextInput, TouchableOpacity,
  StyleSheet, ActivityIndicator, ScrollView, Alert,
} from "react-native";
import { loadApiKeys, loadHistory, saveHistory } from "../../lib/storage";
import { checkPhishing } from "@ramz/core";

export default function ScannerScreen() {
  const [url, setUrl]         = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult]   = useState<{ level: string; detail: string } | null>(null);

  async function handleScan() {
    const trimmed = url.trim();
    if (!trimmed) return;
    setScanning(true);
    setResult(null);

    try {
      // Offline heuristic always runs
      const heuristic = checkPhishing(trimmed);
      const level = heuristic.score >= 3 ? "malicious" : heuristic.score >= 1 ? "suspicious" : "clean";

      // Try cloud scan if API keys available
      const keys = await loadApiKeys();
      if (keys.vt) {
        const res = await fetch(
          `https://www.virustotal.com/api/v3/urls`,
          {
            method: "POST",
            headers: { "x-apikey": keys.vt, "Content-Type": "application/x-www-form-urlencoded" },
            body: `url=${encodeURIComponent(trimmed)}`,
          }
        );
        const json = await res.json();
        const id   = json?.data?.id;
        if (id) {
          // Poll for result
          await new Promise((r) => setTimeout(r, 3000));
          const analysisRes = await fetch(
            `https://www.virustotal.com/api/v3/analyses/${id}`,
            { headers: { "x-apikey": keys.vt } }
          );
          const analysis = await analysisRes.json();
          const stats = analysis?.data?.attributes?.stats;
          if (stats) {
            const pos = stats.malicious + stats.suspicious;
            const tot = Object.values(stats as Record<string, number>).reduce((a, b) => a + b, 0);
            const vtLevel = pos === 0 ? "clean" : pos <= 3 ? "suspicious" : "malicious";
            setResult({
              level: vtLevel,
              detail: `VirusTotal: ${pos}/${tot} | هيورستيكي: ${heuristic.flags.join(", ") || "لا علامات"}`,
            });
            await saveHistoryEntry(trimmed, vtLevel);
            return;
          }
        }
      }

      setResult({
        level,
        detail: heuristic.flags.length > 0 ? heuristic.flags.join(" · ") : "لا علامات مشبوهة (هيورستيكي فقط)",
      });
      await saveHistoryEntry(trimmed, level);
    } catch (err) {
      setResult({ level: "unknown", detail: `خطأ: ${String(err)}` });
    } finally {
      setScanning(false);
    }
  }

  async function saveHistoryEntry(target: string, verdict: string) {
    const history = await loadHistory();
    const next = [...history, {
      id:        Math.random().toString(36).slice(2),
      type:      "url" as const,
      target,
      timestamp: new Date().toISOString(),
      verdict:   verdict as "clean" | "suspicious" | "malicious" | "unknown",
      sources:   ["Heuristic"],
    }];
    await saveHistory(next);
  }

  const LEVEL_COLORS: Record<string, string> = {
    clean:      "#22c55e",
    suspicious: "#f59e0b",
    malicious:  "#ef4444",
    unknown:    "#64748b",
  };

  const LEVEL_LABELS: Record<string, string> = {
    clean:      "آمن",
    suspicious: "مشبوه",
    malicious:  "خطير",
    unknown:    "غير معروف",
  };

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      <Text style={s.title}>فاحص التهديدات</Text>
      <Text style={s.desc}>
        أدخل رابطاً لفحصه. يعمل الفحص الهيورستيكي بدون إنترنت.
        الفحص السحابي يتطلب مفتاح VirusTotal.
      </Text>

      <TextInput
        style={s.input}
        value={url}
        onChangeText={setUrl}
        placeholder="https://example.com"
        placeholderTextColor="#64748b"
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType="url"
        textAlign="left"
      />

      <TouchableOpacity
        style={[s.btn, (scanning || !url.trim()) && s.btnDisabled]}
        onPress={handleScan}
        disabled={scanning || !url.trim()}
      >
        {scanning
          ? <ActivityIndicator color="#fff" />
          : <Text style={s.btnText}>فحص الآن</Text>
        }
      </TouchableOpacity>

      {result && (
        <View style={[s.resultCard, { borderColor: LEVEL_COLORS[result.level] ?? "#334155" }]}>
          <Text style={[s.resultLevel, { color: LEVEL_COLORS[result.level] ?? "#64748b" }]}>
            {LEVEL_LABELS[result.level] ?? result.level}
          </Text>
          <Text style={s.resultDetail}>{result.detail}</Text>
        </View>
      )}
    </ScrollView>
  );
}

const s = StyleSheet.create({
  container:    { flex: 1, backgroundColor: "#0a0a0f" },
  content:      { padding: 20 },
  title:        { color: "#e2e8f0", fontSize: 20, fontWeight: "700", marginBottom: 8 },
  desc:         { color: "#64748b", fontSize: 13, lineHeight: 20, marginBottom: 20 },
  input:        { backgroundColor: "#111118", borderWidth: 1, borderColor: "#1e1e2e", borderRadius: 10, padding: 14, color: "#e2e8f0", fontSize: 15, marginBottom: 12 },
  btn:          { backgroundColor: "#6366f1", borderRadius: 10, padding: 16, alignItems: "center" },
  btnDisabled:  { opacity: 0.5 },
  btnText:      { color: "#fff", fontWeight: "600", fontSize: 16 },
  resultCard:   { marginTop: 20, backgroundColor: "#111118", borderWidth: 1, borderRadius: 12, padding: 16 },
  resultLevel:  { fontSize: 20, fontWeight: "700", marginBottom: 8 },
  resultDetail: { color: "#94a3b8", fontSize: 13, lineHeight: 20 },
});
