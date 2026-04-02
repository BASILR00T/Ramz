import React, { useEffect, useState } from "react";
import {
  View, Text, TextInput, TouchableOpacity,
  StyleSheet, ActivityIndicator, Alert,
} from "react-native";
import { router } from "expo-router";
import {
  loadEncryptedVault, saveEncryptedVault,
  loadLockState, saveLockState, clearLockState,
} from "../lib/storage";
import {
  deriveKey, encryptVault, decryptVault,
  generateSalt, hmacIntegrity, verifyIntegrity,
} from "@ramz/core";

const MAX_ATTEMPTS    = 5;
const LOCK_DURATION   = 15 * 60 * 1000;

export default function LockScreen() {
  const [password, setPassword] = useState("");
  const [confirm,  setConfirm]  = useState("");
  const [isNew,    setIsNew]    = useState(false);
  const [loading,  setLoading]  = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [lockState, setLockState]   = useState({ attempts: 0, lockedUntil: null as number | null });
  const [error,    setError]    = useState("");

  useEffect(() => {
    async function init() {
      const vault = await loadEncryptedVault();
      const ls    = await loadLockState();
      setIsNew(!vault);
      setLockState(ls);
      setLoading(false);
    }
    init();
  }, []);

  const isLocked = !!(lockState.lockedUntil && Date.now() < lockState.lockedUntil);
  const remaining = isLocked ? Math.ceil((lockState.lockedUntil! - Date.now()) / 60000) : 0;

  async function handleUnlock() {
    if (submitting || isLocked) return;
    if (isNew && password !== confirm) {
      setError("كلمات المرور غير متطابقة");
      return;
    }
    if (password.length < 8) {
      setError("8 أحرف على الأقل");
      return;
    }

    setSubmitting(true);
    setError("");

    try {
      const existing = await loadEncryptedVault();

      if (!existing) {
        const salt = generateSalt();
        const key  = await deriveKey(password, salt);
        const hmac = await hmacIntegrity(password, salt);
        const enc  = await encryptVault([], key);
        await saveEncryptedVault({ ...enc, salt, hmac });
        await clearLockState();
      } else {
        const valid = await verifyIntegrity(password, existing.salt, existing.hmac);
        if (!valid) throw new Error("wrong");
        await clearLockState();
      }

      // Navigate to main tabs
      router.replace("/(tabs)/vault");
    } catch {
      const ls = await loadLockState();
      const attempts   = ls.attempts + 1;
      const lockedUntil = attempts >= MAX_ATTEMPTS ? Date.now() + LOCK_DURATION : null;
      const next = { attempts, lockedUntil };
      await saveLockState(next);
      setLockState(next);
      setError(lockedUntil ? "تم تجميد الحساب 15 دقيقة" : "كلمة مرور خاطئة");
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color="#6366f1" />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.card}>
        <Text style={styles.brand}>رَمز</Text>
        <Text style={styles.sub}>منظومة الأمان الصفري المعرفة</Text>

        {isLocked ? (
          <View style={styles.alertBox}>
            <Text style={styles.alertText}>
              الحساب مقفل {remaining} دقيقة بسبب محاولات فاشلة
            </Text>
          </View>
        ) : (
          <>
            {isNew && (
              <Text style={styles.hint}>أنشئ كلمة مرور رئيسية لحماية خزينتك.</Text>
            )}

            <TextInput
              style={styles.input}
              value={password}
              onChangeText={(t) => { setPassword(t); setError(""); }}
              placeholder="كلمة المرور الرئيسية"
              placeholderTextColor="#64748b"
              secureTextEntry
              autoComplete={isNew ? "new-password" : "current-password"}
              textAlign="right"
            />

            {isNew && (
              <TextInput
                style={styles.input}
                value={confirm}
                onChangeText={(t) => { setConfirm(t); setError(""); }}
                placeholder="تأكيد كلمة المرور"
                placeholderTextColor="#64748b"
                secureTextEntry
                textAlign="right"
              />
            )}

            {error !== "" && (
              <Text style={styles.errorText}>{error}</Text>
            )}

            <TouchableOpacity
              style={[styles.btn, submitting && styles.btnDisabled]}
              onPress={handleUnlock}
              disabled={submitting}
            >
              {submitting
                ? <ActivityIndicator color="#fff" />
                : <Text style={styles.btnText}>{isNew ? "إنشاء الخزينة" : "فتح الخزينة"}</Text>
              }
            </TouchableOpacity>
          </>
        )}

        <Text style={styles.footer}>
          بدون خادم · بدون سحابة · لا بيانات تغادر جهازك
        </Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  center:       { flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#0a0a0f" },
  container:    { flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#0a0a0f", padding: 24 },
  card:         { width: "100%", maxWidth: 400, backgroundColor: "#111118", borderRadius: 16, padding: 32, borderWidth: 1, borderColor: "#1e1e2e" },
  brand:        { fontSize: 36, fontWeight: "700", color: "#6366f1", textAlign: "center", marginBottom: 4 },
  sub:          { fontSize: 13, color: "#64748b", textAlign: "center", marginBottom: 24 },
  hint:         { fontSize: 13, color: "#94a3b8", textAlign: "center", marginBottom: 16 },
  input:        { backgroundColor: "#1a1a2e", borderWidth: 1, borderColor: "#2d2d4a", borderRadius: 10, padding: 14, color: "#e2e8f0", fontSize: 16, marginBottom: 12 },
  errorText:    { color: "#f87171", textAlign: "center", marginBottom: 12, fontSize: 14 },
  btn:          { backgroundColor: "#6366f1", borderRadius: 10, padding: 16, alignItems: "center", marginTop: 4 },
  btnDisabled:  { opacity: 0.6 },
  btnText:      { color: "#fff", fontSize: 16, fontWeight: "600" },
  alertBox:     { backgroundColor: "#3b0000", borderRadius: 10, padding: 16, marginBottom: 16 },
  alertText:    { color: "#f87171", textAlign: "center", fontSize: 14 },
  footer:       { color: "#334155", textAlign: "center", fontSize: 11, marginTop: 24 },
});
