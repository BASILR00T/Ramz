import React, { useEffect, useState } from "react";
import {
  View, Text, FlatList, TouchableOpacity,
  StyleSheet, ActivityIndicator,
} from "react-native";
import { loadEncryptedVault } from "../../lib/storage";

export default function VaultScreen() {
  const [loading, setLoading] = useState(true);
  const [hasVault, setHasVault] = useState(false);

  useEffect(() => {
    loadEncryptedVault().then((v) => {
      setHasVault(!!v);
      setLoading(false);
    });
  }, []);

  if (loading) {
    return (
      <View style={s.center}>
        <ActivityIndicator color="#6366f1" />
      </View>
    );
  }

  return (
    <View style={s.container}>
      <View style={s.header}>
        <Text style={s.title}>الخزينة المشفرة</Text>
        <TouchableOpacity style={s.addBtn}>
          <Text style={s.addBtnText}>+ إضافة</Text>
        </TouchableOpacity>
      </View>

      <View style={s.empty}>
        <Text style={s.emptyIcon}>🔒</Text>
        <Text style={s.emptyTitle}>
          {hasVault ? "الخزينة فارغة" : "خزينة جديدة"}
        </Text>
        <Text style={s.emptyDesc}>
          استخدم التطبيق على الويب أو سطح المكتب لإدارة السجلات.
          تطبيق الجوال يوفر عرضاً للقراءة فقط حالياً.
        </Text>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  center:      { flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#0a0a0f" },
  container:   { flex: 1, backgroundColor: "#0a0a0f", padding: 16 },
  header:      { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 20 },
  title:       { color: "#e2e8f0", fontSize: 20, fontWeight: "700" },
  addBtn:      { backgroundColor: "#6366f1", paddingHorizontal: 16, paddingVertical: 8, borderRadius: 8 },
  addBtnText:  { color: "#fff", fontWeight: "600" },
  empty:       { flex: 1, justifyContent: "center", alignItems: "center", paddingHorizontal: 32 },
  emptyIcon:   { fontSize: 48, marginBottom: 16 },
  emptyTitle:  { color: "#e2e8f0", fontSize: 18, fontWeight: "600", marginBottom: 8, textAlign: "center" },
  emptyDesc:   { color: "#64748b", fontSize: 14, textAlign: "center", lineHeight: 22 },
});
