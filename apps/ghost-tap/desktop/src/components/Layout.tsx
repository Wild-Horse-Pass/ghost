import { NavLink, Outlet } from "react-router-dom";
import StatusBar from "./StatusBar";

const navItems = [
  { path: "/dashboard", label: "Dashboard" },
  { path: "/terminal", label: "Terminal" },
  { path: "/send", label: "Send" },
  { path: "/receive", label: "Receive" },
  { path: "/history", label: "History" },
  { path: "/invoices", label: "Invoices" },
  { path: "/receipts", label: "Receipts" },
  { path: "/export", label: "Export" },
  { path: "/wraith", label: "Wraith Wash" },
  { path: "/glyph", label: "Glyph Designer" },
  { path: "/settings", label: "Settings" },
];

export default function Layout() {
  return (
    <div style={{ display: "flex", height: "100vh", width: "100%" }}>
      <aside
        style={{
          width: "var(--sidebar-width)",
          minWidth: "var(--sidebar-width)",
          background: "var(--bg-secondary)",
          borderRight: "1px solid var(--border)",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div
          style={{
            padding: "20px 16px",
            borderBottom: "1px solid var(--border)",
          }}
        >
          <h1
            style={{
              fontSize: 16,
              fontWeight: 700,
              color: "var(--accent)",
              letterSpacing: 0.5,
            }}
          >
            GhostTap
          </h1>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
            Merchant Terminal
          </div>
        </div>

        <nav style={{ flex: 1, padding: "8px 0", overflowY: "auto" }}>
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              style={({ isActive }) => ({
                display: "block",
                padding: "10px 20px",
                fontSize: 13,
                fontWeight: 500,
                color: isActive ? "var(--accent)" : "var(--text-secondary)",
                background: isActive ? "var(--accent-muted)" : "transparent",
                textDecoration: "none",
                borderLeft: isActive
                  ? "3px solid var(--accent)"
                  : "3px solid transparent",
                transition: "all 0.1s ease",
              })}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <StatusBar />
      </aside>

      <main style={{ flex: 1, overflow: "hidden" }}>
        <Outlet />
      </main>
    </div>
  );
}
