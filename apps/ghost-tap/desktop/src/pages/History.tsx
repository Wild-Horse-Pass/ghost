import { useEffect, useState, useCallback } from "react";
import { getHistory, type HistoryEntry } from "../api/commands";
import { useToast } from "../components/ToastProvider";
import TransactionRow from "../components/TransactionRow";

const PAGE_SIZE = 20;
const REFRESH_INTERVAL = 15_000; // 15 seconds

export default function History() {
  const { toast } = useToast();
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const load = useCallback(async (off: number) => {
    try {
      const result = await getHistory(off, PAGE_SIZE);
      setEntries(result);
      setHasMore(result.length === PAGE_SIZE);
      setLastUpdated(new Date());
    } catch (e: unknown) {
      toast(String(e), "error");
    }
  }, [toast]);

  useEffect(() => {
    load(offset);
    const id = setInterval(() => load(offset), REFRESH_INTERVAL);
    return () => clearInterval(id);
  }, [offset, load]);

  return (
    <div className="page">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ marginBottom: 0 }}>Transaction History</h1>
        {lastUpdated && (
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
            Updated {lastUpdated.toLocaleTimeString()}
          </span>
        )}
      </div>

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
