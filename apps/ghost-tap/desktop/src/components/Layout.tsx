import { NavLink, Outlet } from "react-router-dom";
import { useConnection } from "../contexts/ConnectionContext";
import StatusBar from "./StatusBar";

interface NavSection {
  label: string;
  items: { path: string; label: string }[];
  /** If true, only visible in fullnode mode */
  fullnodeOnly?: boolean;
}

const navSections: NavSection[] = [
  {
    label: "Wallet",
    items: [
      { path: "/dashboard", label: "Dashboard" },
      { path: "/send", label: "Send" },
      { path: "/receive", label: "Receive" },
      { path: "/history", label: "History" },
    ],
  },
  {
    label: "L1 Wallet",
    fullnodeOnly: true,
    items: [
      { path: "/address-book", label: "Address Book" },
      { path: "/coin-control", label: "Coin Control" },
      { path: "/psbt", label: "PSBT" },
      { path: "/sign-verify", label: "Sign / Verify" },
    ],
  },
  {
    label: "Ghost Locks",
    fullnodeOnly: true,
    items: [
      { path: "/ghost-locks", label: "Manage Locks" },
      { path: "/create-lock", label: "Create Lock" },
      { path: "/withdraw", label: "Withdraw" },
      { path: "/send-l2", label: "Send L2" },
      { path: "/ghost-id", label: "Ghost ID" },
    ],
  },
  {
    label: "Merchant",
    items: [
      { path: "/terminal", label: "Terminal" },
      { path: "/invoices", label: "Invoices" },
      { path: "/receipts", label: "Receipts" },
      { path: "/export", label: "Export" },
    ],
  },
  {
    label: "Privacy",
    items: [
      { path: "/wraith", label: "Wraith Wash" },
      { path: "/glyph", label: "Glyph Designer" },
    ],
  },
  {
    label: "Settings",
    items: [{ path: "/settings", label: "Settings" }],
  },
];

export default function Layout() {
  const { mode } = useConnection();

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
            {mode === "fullnode" ? "Full Node Wallet" : "Light Wallet"}
          </div>
        </div>

        <nav style={{ flex: 1, padding: "8px 0", overflowY: "auto" }}>
          {navSections
            .filter((section) => !section.fullnodeOnly || mode === "fullnode")
            .map((section) => (
              <div key={section.label}>
                <div
                  style={{
                    padding: "12px 20px 4px",
                    fontSize: 10,
                    fontWeight: 600,
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                    letterSpacing: 0.8,
                  }}
                >
                  {section.label}
                </div>
                {section.items.map((item) => (
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
              </div>
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
