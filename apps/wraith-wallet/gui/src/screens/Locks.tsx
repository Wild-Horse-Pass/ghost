import { useEffect, useState } from "react";
import {
  locksList,
  locksPrepare,
  locksConfirm,
  locksRecover,
  type LockEntry,
  type LocksPreparedResponse,
  type LocksRecoveredResult,
} from "../lib/tauri";

export function Locks() {
  const [locks, setLocks] = useState<LockEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [prep, setPrep] = useState<LocksPreparedResponse | null>(null);
  const [recovery, setRecovery] = useState<LocksRecoveredResult | null>(null);

  const refresh = async () => {
    setErr(null);
    try {
      const list = await locksList();
      setLocks(list.locks);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const onPrepare = async () => {
    const raw = prompt(
      "Capacity in sats (must match a Ghost Lock denomination — Tiny=100k, Small=1M, Medium=10M, Large=100M):",
      "100000",
    );
    if (!raw) return;
    const sats = Number(raw);
    if (!Number.isFinite(sats) || sats <= 0) {
      setErr("Capacity must be a positive number.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const result = await locksPrepare(sats);
      setPrep(result);
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onConfirm = async (lock_id: string) => {
    const txid = prompt(`Funding txid for lock ${lock_id.slice(0, 12)}…:`);
    if (!txid) return;
    setBusy(true);
    setErr(null);
    try {
      await locksConfirm(lock_id, txid.trim());
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onRecover = async (lock_id: string) => {
    const dest = prompt(
      `Unilateral exit ${lock_id.slice(0, 12)}…\n\nL1 destination address (where the recovered sats land):`,
    );
    if (!dest) return;
    const feeStr = prompt("Mining fee (sats, subtracted from recovered amount):", "1000");
    const fee = Number(feeStr ?? "");
    if (!Number.isFinite(fee) || fee <= 0) {
      setErr("Fee must be a positive integer.");
      return;
    }
    setBusy(true);
    setErr(null);
    setRecovery(null);
    try {
      const result = await locksRecover(lock_id, dest.trim(), fee);
      setRecovery(result);
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="screen">
      <h1>Ghost Locks</h1>
      {err && (
        <div className="card" style={{ borderColor: "var(--fail)" }}>
          {err}
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h2>{locks.length === 0 ? "No locks yet" : "Your locks"}</h2>
          <button className="primary" onClick={onPrepare} disabled={busy}>
            + Prepare lock
          </button>
        </div>
        {locks.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Capacity</th>
                <th>State</th>
                <th>Recovery height</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {locks.map((l) => (
                <tr key={l.lock_id}>
                  <td className="mono muted">{l.lock_id.slice(0, 18)}…</td>
                  <td>{l.capacity_sats.toLocaleString()} sats</td>
                  <td>
                    <span
                      className={`pill ${
                        l.state === "active"
                          ? "pass"
                          : l.state === "pending"
                            ? "warn"
                            : "mute"
                      }`}
                    >
                      {l.state}
                    </span>
                  </td>
                  <td className="mono muted">
                    {l.recovery_height ?? "—"}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    {l.state === "pending" && (
                      <button
                        className="secondary"
                        onClick={() => onConfirm(l.lock_id)}
                        disabled={busy}
                        style={{ marginRight: 6 }}
                      >
                        Confirm funding
                      </button>
                    )}
                    {l.state === "active" && (
                      <button
                        className="danger"
                        onClick={() => onRecover(l.lock_id)}
                        disabled={busy}
                        title="Unilateral exit — sends a recovery tx straight to bitcoind, no operator cooperation. Only works after the timelock has matured."
                      >
                        Recover
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {recovery && (
        <div className="card" style={{ borderColor: "var(--pass)" }}>
          <h2>Unilateral exit broadcast ✓</h2>
          <p className="muted" style={{ margin: 0 }}>
            Recovery tx hit bitcoind's mempool. Once it confirms, the
            funds land at the destination address.
          </p>
          <div className="kv">
            <div className="k">Lock ID</div>
            <div className="v">{recovery.lock_id}</div>
            <div className="k">Broadcast txid</div>
            <div className="v">{recovery.broadcast_txid}</div>
            <div className="k">Destination</div>
            <div className="v">{recovery.destination}</div>
            <div className="k">Recovered</div>
            <div className="v">{recovery.recovered_sats.toLocaleString()} sats</div>
            <div className="k">Fee</div>
            <div className="v">{recovery.fee_sats.toLocaleString()} sats</div>
          </div>
        </div>
      )}

      {prep && (
        <div className="card">
          <h2>Lock prepared — fund it now</h2>
          <p className="muted" style={{ margin: 0 }}>
            Send <strong>{prep.required_sats.toLocaleString()}</strong> sats
            to the address below from any Bitcoin wallet, then come
            back and click "Confirm funding" with the resulting txid.
          </p>
          <div className="kv">
            <div className="k">Lock ID</div>
            <div className="v">{prep.lock_id}</div>
            <div className="k">Funding address</div>
            <div className="v">{prep.funding_address}</div>
            <div className="k">Required</div>
            <div className="v">{prep.required_sats.toLocaleString()} sats</div>
          </div>
        </div>
      )}
    </div>
  );
}
