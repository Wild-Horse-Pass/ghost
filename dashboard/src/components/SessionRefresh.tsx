"use client";

import { useEffect } from "react";

/**
 * Slides the session cookie while the operator is actively using the dashboard.
 *
 * The server issues tokens with a fixed TTL (DASHBOARD_TOKEN_TTL_SECS, default
 * 1 hour). Without refresh, an operator gets redirected to /login on the first
 * action after expiry. With refresh, the cookie is rotated every 20 minutes so
 * the TTL window is always well ahead of the current time.
 *
 * If the refresh returns 401 the token has already been invalidated — we let
 * the next route navigation trigger the middleware-driven redirect rather than
 * forcing a reload here.
 */
const REFRESH_INTERVAL_MS = 20 * 60 * 1000; // 20 minutes

export function SessionRefresh() {
  useEffect(() => {
    // Skip for the login page and when running on localhost (middleware
    // skips auth there too).
    if (typeof window === "undefined") return;
    if (window.location.pathname.startsWith("/login")) return;

    let cancelled = false;
    const refresh = async () => {
      try {
        await fetch("/api/auth/refresh", { method: "POST", credentials: "same-origin" });
      } catch {
        // Ignore — network blip. Next cycle or next navigation will recover.
      }
    };

    const handle = window.setInterval(() => {
      if (!cancelled) void refresh();
    }, REFRESH_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
  }, []);

  return null;
}
