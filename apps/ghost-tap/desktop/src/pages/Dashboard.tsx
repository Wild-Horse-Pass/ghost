import { useEffect, useState } from "react";
import {
  computeDashboard,
  getBalance,
  formatGhost,
  type DashboardSummary,
  type BalanceResponse,
} from "../api/commands";

type Period = "today" | "week" | "month" | "all";

function periodRange(period: Period): [number, number] {
  const now = Math.floor(Date.now() / 1000);
  switch (period) {
    case "today":
      return [now - 86400, now];
    case "week":
      return [now - 86400 * 7, now];
    case "month":
      return [now - 86400 * 30, now];
    case "all":
      return [0, now];
  }
}

export default function Dashboard() {
  const [period, setPeriod] = useState<Period>("month");
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [balance, setBalance] = useState<BalanceResponse | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const [since, until] = periodRange(period);
    computeDashboard(since, until).then(setSummary).catch((e) => setError(String(e)));
    getBalance().then(setBalance).catch(() => {});
  }, [period]);

  return (
    <div className="page">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ marginBottom: 0 }}>Dashboard</h1>
        <div style={{ display: "flex", gap: 6 }}>
          {(["today", "week", "month", "all"] as const).map((p) => (
            <button
              key={p}
              className={period === p ? "btn-primary btn-small" : "btn-secondary btn-small"}
              onClick={() => setPeriod(p)}
            >
              {p.charAt(0).toUpperCase() + p.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {error && <div className="error-text" style={{ marginBottom: 16 }}>{error}</div>}

      {balance && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 4 }}>
            Wallet Balance
          </div>
          <div style={{ fontSize: 32, fontWeight: 700 }}>
            {formatGhost(balance.confirmed)}{" "}
            <span style={{ fontSize: 16, color: "var(--text-muted)" }}>GHOST</span>
          </div>
          {balance.pending > 0 && (
            <div style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: 4 }}>
              +{formatGhost(balance.pending)} pending
            </div>
          )}
        </div>
      )}

      {summary && (
        <div className="grid-stats">
          <div className="stat-card">
            <div className="stat-label">Total Received</div>
            <div className="stat-value incoming">{formatGhost(summary.total_received)}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Total Sent</div>
            <div className="stat-value outgoing">{formatGhost(summary.total_sent)}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Fees Paid</div>
            <div className="stat-value">{formatGhost(summary.total_fees)}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Transactions</div>
            <div className="stat-value">{summary.tx_count}</div>
          </div>
        </div>
      )}
    </div>
  );
}
