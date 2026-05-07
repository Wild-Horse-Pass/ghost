import { useEffect, useState } from "react";
import { lightHistory, type LightHistoryEntry } from "../lib/tauri";

export function History() {
  const [entries, setEntries] = useState<LightHistoryEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const h = await lightHistory(100, 0);
        if (!alive) return;
        setEntries(h.transactions);
        setTotal(h.total_count);
        setErr(null);
      } catch (e) {
        if (!alive) return;
        setErr((e as Error).message ?? String(e));
      }
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const fmtTime = (unix: number) => new Date(unix * 1000).toLocaleString();
  const fmtAmount = (sats: number) => {
    const sign = sats > 0 ? "+" : "";
    return `${sign}${sats.toLocaleString()}`;
  };

  return (
    <div className="screen">
      <h1>History</h1>
      {err && (
        <div className="card" style={{ borderColor: "var(--fail)" }}>
          {err}
        </div>
      )}
      <div className="card">
        <div className="card-header">
          <h2>{entries.length === 0 ? "No transactions yet" : "Recent activity"}</h2>
          <span className="muted">{total} total</span>
        </div>
        {entries.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>Type</th>
                <th>Amount (sats)</th>
                <th>Memo</th>
                <th>Conf</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.txid + e.timestamp}>
                  <td>{fmtTime(e.timestamp)}</td>
                  <td>
                    <span
                      className={`pill ${
                        e.tx_type === "receive" ? "pass" : "mute"
                      }`}
                    >
                      {e.tx_type}
                    </span>
                  </td>
                  <td
                    style={{
                      color:
                        e.amount_sats > 0
                          ? "var(--pass)"
                          : e.amount_sats < 0
                            ? "var(--fail)"
                            : "var(--fg)",
                    }}
                  >
                    {fmtAmount(e.amount_sats)}
                  </td>
                  <td className="muted">{e.memo ?? "—"}</td>
                  <td>{e.confirmations ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
