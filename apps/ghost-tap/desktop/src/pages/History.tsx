import { useEffect, useState } from "react";
import { getHistory, type HistoryEntry } from "../api/commands";
import TransactionRow from "../components/TransactionRow";

const PAGE_SIZE = 20;

export default function History() {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [error, setError] = useState("");

  const load = async (off: number) => {
    try {
      setError("");
      const result = await getHistory(off, PAGE_SIZE);
      setEntries(result);
      setHasMore(result.length === PAGE_SIZE);
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  useEffect(() => {
    load(offset);
  }, [offset]);

  return (
    <div className="page">
      <h1>Transaction History</h1>
      {error && <div className="error-text" style={{ marginBottom: 16 }}>{error}</div>}

      <div className="card" style={{ padding: 0 }}>
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Amount</th>
              <th>Address</th>
              <th>Status</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                  No transactions yet
                </td>
              </tr>
            ) : (
              entries.map((entry) => (
                <TransactionRow key={entry.txid + entry.timestamp} entry={entry} />
              ))
            )}
          </tbody>
        </table>
      </div>

      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 16 }}>
        <button
          className="btn-secondary btn-small"
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          disabled={offset === 0}
        >
          Previous
        </button>
        <span style={{ fontSize: 12, color: "var(--text-muted)", alignSelf: "center" }}>
          Showing {offset + 1} - {offset + entries.length}
        </span>
        <button
          className="btn-secondary btn-small"
          onClick={() => setOffset(offset + PAGE_SIZE)}
          disabled={!hasMore}
        >
          Next
        </button>
      </div>
    </div>
  );
}
