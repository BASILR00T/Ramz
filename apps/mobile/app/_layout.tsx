import { Stack } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { SafeAreaProvider } from "react-native-safe-area-context";

export default function RootLayout() {
  return (
    <SafeAreaProvider>
      <StatusBar style="light" backgroundColor="#0a0a0f" />
      <Stack
        screenOptions={{
          headerStyle:      { backgroundColor: "#0a0a0f" },
          headerTintColor:  "#e2e8f0",
          headerTitleStyle: { fontWeight: "600" },
          contentStyle:     { backgroundColor: "#0a0a0f" },
        }}
      >
        <Stack.Screen name="index"   options={{ headerShown: false }} />
        <Stack.Screen name="(tabs)"  options={{ headerShown: false }} />
      </Stack>
    </SafeAreaProvider>
  );
}
