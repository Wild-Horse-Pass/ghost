import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { listLocks, jumpLock, formatGhost, type LockInfo } from "../api/commands";
import { useConnection } from "../contexts/ConnectionContext";
import { useToast } from "../components/ToastProvider";

const REFRESH_INTERVAL = 10_000;

function stateBadgeClass(state: string): string {
  switch (state.toLowerCase()) {
    case "active":
      return "badge-completed";
    case "pending":
      return "badge-queued";
    case "recovered":
      return "badge-progress";
    case "closed":
      return "badge-draft";
    default:
      return "badge-draft";
  }
}

function jumpRiskBadgeClass(risk: string): string {
  switch (risk.toLowerCase()) {
    case "high":
      return "badge-failed";
    case "moderate":
      return "badge-progress";
    case "none":
    case "low":
    default:
      return "badge-draft";
  }
}

export default function GhostLocks() {
  const { mode } = useConnection();
  const { toast } = useToast();
  const navigate = useNavigate();
  const [locks, setLocks] = useState<LockInfo[]>([]);
  const [error, setError] = useState("");
  const [jumpingId, setJumpingId] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const result = await listLocks();
      setLocks(result);
    } catch (e: unknown) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    if (mode !== "fullnode") return;
    refresh();
    const id = setInterval(refresh, REFRESH_INTERVAL);
    return () => clearInterval(id);
  }, [mode, refresh]);

  const totalL2Sats = locks.reduce((sum, l) => sum + l.amount_sats, 0);

  const handleJump = async (lockId: string) => {
    try {
      setJumpingId(lockId);
      setError("");
      await jumpLock(lockId);
      toast("Keys rotated successfully", "success");
      refresh();
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setJumpingId(null);
    }
  };

  if (mode !== "fullnode") {
    return (
      <div className="page">
        <h1>Ghost Locks</h1>
        <div className="card" style={{ maxWidth: 500 }}>
          <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
            Ghost Locks requires a full node connection. Switch to Full Node mode in Settings.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ marginBottom: 0 }}>Ghost Locks</h1>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn-primary btn-small" onClick={() => navigate("/create-lock")}>
            Create Lock
          </button>
          <button className="btn-secondary btn-small" onClick={() => navigate("/ghost-id")}>
            Ghost ID
          </button>
        </div>
      </div>

      {/* L2 Balance */}
      <div className="grid-stats">
        <div className="stat-card">
          <div className="stat-label">Total L2 Balance</div>
          <div className="stat-value">{formatGhost(totalL2Sats)} GHOST</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Active Locks</div>
          <div className="stat-value">{locks.filter((l) => l.state.toLowerCase() === "active").length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Total Locks</div>
          <div className="stat-value">{locks.length}</div>
        </div>
      </div>

      {error && <div className="error-text" style={{ marginBottom: 16 }}>{error}</div>}

      {/* Locks table */}
      <div className="card" style={{ padding: 0 }}>
        <table>
          <thead>
            <tr>
              <th>Denomination</th>
              <th>Amount</th>
              <th>State</th>
              <th>Timelock</th>
              <th>Jump Risk</th>
              <th>Recovery Height</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {locks.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                  No locks found. Create your first lock to get started.
                </td>
              </tr>
            ) : (
              locks.map((lock) => (
                <tr key={lock.id}>
                  <td style={{ fontWeight: 500 }}>{lock.denomination}</td>
                  <td>{formatGhost(lock.amount_sats)} GHOST</td>
                  <td>
                    <span className={`badge ${stateBadgeClass(lock.state)}`}>{lock.state}</span>
                    {lock.needs_jump && (
                      <span
                        style={{
                          marginLeft: 6,
                          color: "var(--warning)",
                          fontSize: 11,
                          fontWeight: 600,
                        }}
                        title="Key rotation needed"
                      >
                        JUMP NEEDED
                      </span>
                    )}
                  </td>
                  <td style={{ fontSize: 12, color: "var(--text-secondary)" }}>{lock.timelock_tier}</td>
                  <td>
                    <span className={`badge ${jumpRiskBadgeClass(lock.jump_risk)}`}>{lock.jump_risk}</span>
                  </td>
                  <td className="mono" style={{ fontSize: 12 }}>{lock.recovery_height.toLocaleString()}</td>
                  <td>
                    <div style={{ display: "flex", gap: 4 }}>
                      <button
                        className="btn-secondary btn-small"
                        onClick={() => navigate(`/ghost-locks?detail=${lock.id}`)}
                        title="View Details"
                      >
                        Details
                      </button>
                      <button
                        className="btn-secondary btn-small"
                        onClick={() => handleJump(lock.id)}
                        disabled={jumpingId === lock.id || lock.state.toLowerCase() !== "active"}
                        title="Rotate Keys"
                      >
                        {jumpingId === lock.id ? "..." : "Jump"}
                      </button>
                      <button
                        className="btn-primary btn-small"
                        onClick={() => navigate(`/withdraw?lockId=${lock.id}`)}
                        disabled={lock.state.toLowerCase() !== "active"}
                        title="Withdraw"
                      >
                        Withdraw
                      </button>
                    </div>
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
