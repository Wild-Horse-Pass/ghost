"use client";

import { GhostBrand } from "@/components/ui/GhostBrand";
import { ThemeToggle } from "@/components/ui/ThemeToggle";

/**
 * Top header — minimal. Brand on the left, theme toggle + endpoint indicator
 * on the right. All route navigation lives in the left sidebar; the header
 * is just chrome to identify the product and let the operator flip themes.
 *
 * The previous nav had a duplicate menu tree (top dropdowns + sidebar) which
 * created two competing hierarchies. Single nav = one mental model.
 */
export function Navigation() {
  return (
    <nav
      className="sticky top-0 z-40"
      style={{
        borderBottom: "1px solid var(--rule)",
        background: "var(--bg)",
        backdropFilter: "saturate(180%) blur(8px)",
        WebkitBackdropFilter: "saturate(180%) blur(8px)",
      }}
    >
      <div className="px-4 sm:px-6">
        <div className="flex items-center justify-between" style={{ height: "60px" }}>
          <GhostBrand size="md" />

          <div className="flex items-center gap-3">
            <span
              className="hidden sm:inline"
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                color: "var(--fainter)",
              }}
            >
              <code>
                {process.env.NEXT_PUBLIC_API_URL?.replace("http://", "") || "127.0.0.1:8080"}
              </code>
            </span>
            <ThemeToggle />
          </div>
        </div>
      </div>
    </nav>
  );
}
