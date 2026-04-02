import { Tabs } from "expo-router";
import { Ionicons } from "@expo/vector-icons";

type IoniconsName = React.ComponentProps<typeof Ionicons>["name"];

const TABS: Array<{ name: string; title: string; icon: IoniconsName; iconActive: IoniconsName }> = [
  { name: "vault",     title: "الخزينة",    icon: "lock-closed-outline",  iconActive: "lock-closed" },
  { name: "scanner",   title: "الفاحص",     icon: "shield-outline",       iconActive: "shield" },
  { name: "identity",  title: "الهوية",     icon: "eye-outline",          iconActive: "eye" },
  { name: "apikeys",   title: "المفاتيح",   icon: "key-outline",          iconActive: "key" },
  { name: "history",   title: "السجل",      icon: "time-outline",         iconActive: "time" },
];

export default function TabLayout() {
  return (
    <Tabs
      screenOptions={{
        tabBarActiveTintColor:   "#6366f1",
        tabBarInactiveTintColor: "#64748b",
        tabBarStyle: {
          backgroundColor: "#111118",
          borderTopColor:  "#1e1e2e",
          borderTopWidth:  1,
        },
        tabBarLabelStyle: { fontSize: 10, fontWeight: "500" },
        headerStyle:      { backgroundColor: "#0a0a0f" },
        headerTintColor:  "#e2e8f0",
        headerTitleStyle: { fontWeight: "700" },
        contentStyle:     { backgroundColor: "#0a0a0f" },
      }}
    >
      {TABS.map(({ name, title, icon, iconActive }) => (
        <Tabs.Screen
          key={name}
          name={name}
          options={{
            title,
            headerTitle: `رَمز | ${title}`,
            tabBarIcon: ({ color, focused }) => (
              <Ionicons name={focused ? iconActive : icon} size={22} color={color} />
            ),
          }}
        />
      ))}
    </Tabs>
  );
}
