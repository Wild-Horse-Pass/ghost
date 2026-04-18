"use client";

import { ReactNode, useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ToastProvider } from "@/components/ui/Toast";
import { useKeyboardShortcuts, KeyboardShortcutsHelp } from "@/hooks/useKeyboardShortcuts";
import { SessionRefresh } from "@/components/SessionRefresh";

function KeyboardShortcutsWrapper({ children }: { children: ReactNode }) {
  const { showHelp, setShowHelp } = useKeyboardShortcuts();

  return (
    <>
      {children}
      <KeyboardShortcutsHelp isOpen={showHelp} onClose={() => setShowHelp(false)} />
    </>
  );
}

export function Providers({ children }: { children: ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 30 * 1000,
            retry: 2,
            refetchOnWindowFocus: true,
            refetchOnReconnect: false,
          },
          mutations: {
            retry: 1,
          },
        },
      })
  );

  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <SessionRefresh />
        <KeyboardShortcutsWrapper>{children}</KeyboardShortcutsWrapper>
      </ToastProvider>
    </QueryClientProvider>
  );
}
