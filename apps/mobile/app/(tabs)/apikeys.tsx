import React, { useEffect, useState } from "react";
import {
  View, Text, TextInput, TouchableOpacity,
  StyleSheet, ScrollView, ActivityIndicator,
} from "react-native";
import { loadApiKeys, saveApiKeys } from "../../lib/storage";
import type { ApiKeys } from "@ramz/core";

const FIELDS: Array<{ key: keyof ApiKeys; label: string; placeholder: string }> = [
  { key: "vt",      label: "VirusTotal API Key",         placeholder: "VT-xxxx..." },
  { key: "hibp",    label: "Have I Been Pwned API Key",  placeholder: "hibp-xxxx..." },
  { key: "urlscan", label: "urlscan.io API Key",         placeholder: "uuid-xxxx..." },
  { key: "gsb",     label: "Google Safe Browsing Key",   placeholder: "AIza-xxxx..." },
];

export default function ApiKeysScreen() {
  const [keys, setKeys]     = useState<ApiKeys>({ vt: "", hibp: "", urlscan: "", gsb: "" });
  const [loading, setLoading] = useState(true);
  const [saved, setSaved]   = useState(false);

  useEffect(() => {
    loadApiKeys().then((k) => { setKeys(k); setLoading(false); });
  }, []);

  async function handleSave() {
    await saveApiKeys(keys);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  }

  if (loading) {
    return <View style={s.center}><ActivityIndicator color="#6366f1" /></View>;
  }

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      <Text style={s.title}>مفاتيح API</Text>
      <Text style={s.desc}>
        تُحفظ المفاتيح في التخزين الآمن للجهاز (Secure Store) فقط.
      </Text>

      {FIELDS.map(({ key, label, placeholder }) => (
        <View key={key} style={s.field}>
          <Text style={s.label}>{label}</Text>
          <View style={s.row}>
            <TextInput
              style={[s.input, { flex: 1 }]}
              value={keys[key]}
              onChangeText={(v) => setKeys((k) => ({ ...k, [key]: v }))}
              placeholder={placeholder}
              placeholderTextColor="#334155"
              secureTextEntry
              autoCapitalize="none"
              autoCorrect={false}
              textAlign="left"
            />
            {keys[key] ? (
              <View style={[s.statusDot, { backgroundColor: "#22c55e" }]} />
            ) : (
              <View style={[s.statusDot, { backgroundColor: "#334155" }]} />
            )}
          </View>
        </View>
      ))}

      <TouchableOpacity style={s.btn} onPress={handleSave}>
        <Text style={s.btnText}>{saved ? "✓ تم الحفظ" : "حفظ المفاتيح"}</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

const s = StyleSheet.create({
  center:    { flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#0a0a0f" },
  container: { flex: 1, backgroundColor: "#0a0a0f" },
  content:   { padding: 20 },
  title:     { color: "#e2e8f0", fontSize: 20, fontWeight: "700", marginBottom: 8 },
  desc:      { color: "#64748b", fontSize: 13, marginBottom: 20, lineHeight: 20 },
  field:     { marginBottom: 16 },
  label:     { color: "#94a3b8", fontSize: 13, marginBottom: 6 },
  row:       { flexDirection: "row", alignItems: "center", gap: 8 },
  input:     { backgroundColor: "#111118", borderWidth: 1, borderColor: "#1e1e2e", borderRadius: 10, padding: 12, color: "#e2e8f0", fontSize: 14 },
  statusDot: { width: 10, height: 10, borderRadius: 5 },
  btn:       { backgroundColor: "#6366f1", borderRadius: 10, padding: 16, alignItems: "center", marginTop: 8 },
  btnText:   { color: "#fff", fontWeight: "600", fontSize: 16 },
});
