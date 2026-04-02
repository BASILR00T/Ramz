import React, { useEffect, useState, useCallback } from "react";
import {
  View, Text, FlatList, TouchableOpacity,
  StyleSheet, ActivityIndicator, RefreshControl,
} from "react-native";
import { useFocusEffect } from "expo-router";
import { loadHistory, saveHistory } from "../../lib/storage";
import type { HistoryEntry } from "@ramz/core";

const VERDICT_COLORS: Record<string, string> = {
  clean:      "#22c55e",
  suspicious: "#f59e0b",
  malicious:  "#ef4444",
  unknown:    "#64748b",
};

const VERDICT_LABELS: Record<string, string> = {
  clean:      "آمن",
  suspicious: "مشبوه",
  malicious:  "خطير",
  unknown:    "غير معروف",
};

const TYPE_LABELS: Record<string, string> = {
  url:   "رابط",
  file:  "ملف",
  email: "بريد",
};

function formatDate(iso: string) {
  return new Date(iso).toLocaleString("ar-SA", {
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

export default function HistoryScreen() {
  const [history, setHistory]     = useState<HistoryEntry[]>([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  async function fetchHistory() {
    const h = await loadHistory();
    setHistory([...h].reverse());
    setLoading(false);
    setRefreshing(false);
  }

  useFocusEffect(useCallback(() => { fetchHistory(); }, []));

  async function handleClear() {
    await saveHistory([]);
    setHistory([]);
  }

  if (loading) {
    return <View style={s.center}><ActivityIndicator color="#6366f1" /></View>;
  }

  return (
    <View style={s.container}>
      <View style={s.header}>
        <Text style={s.title}>سجل العمليات</Text>
        {history.length > 0 && (
          <TouchableOpacity onPress={handleClear} style={s.clearBtn}>
            <Text style={s.clearText}>مسح</Text>
          </TouchableOpacity>
        )}
      </View>

      {history.length === 0 ? (
        <View style={s.empty}>
          <Text style={s.emptyIcon}>📋</Text>
          <Text style={s.emptyTitle}>السجل فارغ</Text>
          <Text style={s.emptyDesc}>ستظهر هنا عمليات الفحص بعد إجرائها.</Text>
        </View>
      ) : (
        <FlatList
          data={history}
          keyExtractor={(item) => item.id}
          refreshControl={
            <RefreshControl
              refreshing={refreshing}
              onRefresh={() => { setRefreshing(true); fetchHistory(); }}
              tintColor="#6366f1"
            />
          }
          renderItem={({ item }) => (
            <View style={[s.card, { borderLeftColor: VERDICT_COLORS[item.verdict] ?? "#334155" }]}>
              <View style={s.cardRow}>
                <Text style={s.typeTag}>
                  {TYPE_LABELS[item.type] ?? item.type}
                </Text>
                <Text style={[s.verdict, { color: VERDICT_COLORS[item.verdict] ?? "#64748b" }]}>
                  {VERDICT_LABELS[item.verdict] ?? item.verdict}
                </Text>
              </View>
              <Text style={s.target} numberOfLines={1}>{item.target}</Text>
              <View style={s.cardMeta}>
                <Text style={s.date}>{formatDate(item.timestamp)}</Text>
                {item.sources.length > 0 && (
                  <Text style={s.sources}>{item.sources.join(" · ")}</Text>
                )}
              </View>
            </View>
          )}
          contentContainerStyle={{ padding: 16 }}
        />
      )}
    </View>
  );
}

const s = StyleSheet.create({
  center:    { flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#0a0a0f" },
  container: { flex: 1, backgroundColor: "#0a0a0f" },
  header:    { flexDirection: "row", justifyContent: "space-between", alignItems: "center", padding: 16, paddingBottom: 0 },
  title:     { color: "#e2e8f0", fontSize: 20, fontWeight: "700" },
  clearBtn:  { backgroundColor: "#3b0000", paddingHorizontal: 12, paddingVertical: 6, borderRadius: 8 },
  clearText: { color: "#f87171", fontSize: 13, fontWeight: "600" },
  empty:     { flex: 1, justifyContent: "center", alignItems: "center", padding: 32 },
  emptyIcon: { fontSize: 48, marginBottom: 12 },
  emptyTitle:{ color: "#e2e8f0", fontSize: 16, fontWeight: "600", marginBottom: 6 },
  emptyDesc: { color: "#64748b", fontSize: 13, textAlign: "center" },
  card:      { backgroundColor: "#111118", borderWidth: 1, borderColor: "#1e1e2e", borderLeftWidth: 3, borderRadius: 10, padding: 12, marginBottom: 10 },
  cardRow:   { flexDirection: "row", justifyContent: "space-between", marginBottom: 4 },
  typeTag:   { color: "#6366f1", fontSize: 12, fontWeight: "600" },
  verdict:   { fontSize: 13, fontWeight: "700" },
  target:    { color: "#94a3b8", fontSize: 13, fontFamily: "monospace", marginBottom: 6 },
  cardMeta:  { flexDirection: "row", justifyContent: "space-between" },
  date:      { color: "#475569", fontSize: 11 },
  sources:   { color: "#475569", fontSize: 11 },
});
