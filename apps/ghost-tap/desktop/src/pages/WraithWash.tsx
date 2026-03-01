import { useEffect, useState } from "react";
import {
  getWashQueue,
  getWashStats,
  washPayment,
  startWashProcessor,
  stopWashProcessor,
  retryWash,
  formatGhost,
  formatTimestamp,
  type WashRequestResponse,
  type WashStatsResponse,
} from "../api/commands";

function statusBadge(status: string) {
  const cls =
    status === "Queued"
      ? "badge-queued"
      : status === "In Progress"
        ? "badge-progress"
        : status === "Completed"
          ? "badge-completed"
          : "badge-failed";
  return <span className={`badge ${cls}`}>{status}</span>;
}

export default function WraithWash() {
  const [queue, setQueue] = useState<WashRequestResponse[]>([]);
  const [stats, setStats] = useState<WashStatsResponse | null>(null);
  const [running, setRunning] = useState(false);
  const [txid, setTxid] = useState("");
  const [amount, setAmount] = useState("");
  const [error, setError] = useState("");

  const refresh = async () => {
    try {
      const [q, s] = await Promise.all([getWashQueue(), getWashStats()]);
      setQueue(q);
      setStats(s);
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 10000);
    return () => clearInterval(id);
  }, []);

  const handleQueue = async () => {
    try {
      setError("");
      const amountSats = Math.floor(parseFloat(amount) * 100_000_000);
      await washPayment(txid, amountSats);
      setTxid("");
      setAmount("");
      refresh();
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleToggle = async () => {
    try {
      setError("");
      if (running) {
        await stopWashProcessor();
      } else {
        await startWashProcessor();
      }
      setRunning(!running);
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleRetry = async (washTxid: string) => {
    try {
      await retryWash(washTxid);
      refresh();
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  return (
    <div className="page">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ marginBottom: 0 }}>Wraith Wash</h1>
        <button
          className={running ? "btn-danger" : "btn-primary"}
          onClick={handleToggle}
        >
          {running ? "Stop Processor" : "Start Processor"}
        </button>
      </div>

      {error && <div className="error-text" style={{ marginBottom: 16 }}>{error}</div>}

      {stats && (
        <div className="grid-stats">
          <div className="stat-card">
            <div className="stat-label">Queued</div>
            <div className="stat-value">{stats.queued_count}</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{formatGhost(stats.queued_amount)} GHOST</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">In Progress</div>
            <div className="stat-value" style={{ color: "var(--warning)" }}>{stats.in_progress_count}</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{formatGhost(stats.in_progress_amount)} GHOST</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Completed</div>
            <div className="stat-value incoming">{stats.completed_count}</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{formatGhost(stats.completed_amount)} GHOST</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Failed</div>
            <div className="stat-value outgoing">{stats.failed_count}</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{formatGhost(stats.failed_amount)} GHOST</div>
          </div>
        </div>
      )}

      <div className="card" style={{ maxWidth: 500, marginBottom: 24 }}>
        <h2>Queue Payment for Washing</h2>
        <div className="form-group">
          <label>Transaction ID</label>
          <input value={txid} onChange={(e) => setTxid(e.target.value)} placeholder="txid..." className="mono" />
        </div>
        <div className="form-group">
          <label>Amount (GHOST)</label>
          <input type="number" step="0.00000001" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="0.00000000" />
        </div>
        <button className="btn-primary" onClick={handleQueue} disabled={!txid || !amount} style={{ width: "100%" }}>
          Queue Wash
        </button>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <table>
          <thead>
            <tr>
              <th>TxID</th>
              <th>Amount</th>
              <th>Status</th>
              <th>Updated</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {queue.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                  Wash queue is empty
                </td>
              </tr>
            ) : (
              queue.map((req) => (
                <tr key={req.txid}>
                  <td className="mono truncate" style={{ maxWidth: 120 }}>{req.txid}</td>
                  <td>{formatGhost(req.amount)} GHOST</td>
                  <td>{statusBadge(req.status)}</td>
                  <td style={{ fontSize: 12, color: "var(--text-muted)" }}>{formatTimestamp(req.updated_at)}</td>
                  <td>
                    {req.status === "Failed" && (
                      <button className="btn-secondary btn-small" onClick={() => handleRetry(req.txid)}>
                        Retry
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
