import { useEffect, useState, useCallback } from "react";
import {
  listUnspent,
  lockUnspentOutput,
  listLockedOutputs,
  sendWithInputs,
  formatGhost,
} from "../api/commands";
import { useConnection } from "../contexts/ConnectionContext";
import { useToast } from "../components/ToastProvider";

interface Utxo {
  txid: string;
  vout: number;
  address: string;
  amount: number;
  confirmations: number;
  spendable: boolean;
}

const REFRESH_INTERVAL = 30_000;

export default function CoinControl() {
  const { mode } = useConnection();
  const { toast } = useToast();
  const [utxos, setUtxos] = useState<Utxo[]>([]);
  const [lockedOutputs, setLockedOutputs] = useState<{ txid: string; vout: number }[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState("");

  // Send form
  const [showSend, setShowSend] = useState(false);
  const [destAddress, setDestAddress] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [feeRate, setFeeRate] = useState("");
  const [sending, setSending] = useState(false);

  const utxoKey = (txid: string, vout: number) => `${txid}:${vout}`;

  const refresh = useCallback(async () => {
    try {
      const [unspent, locked] = await Promise.all([listUnspent(), listLockedOutputs()]);
      setUtxos(unspent);
      setLockedOutputs(locked);
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

  const toggleSelect = (key: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  const selectAll = () => {
    setSelected(new Set(utxos.map((u) => utxoKey(u.txid, u.vout))));
  };

  const deselectAll = () => {
    setSelected(new Set());
  };

  const isLocked = (txid: string, vout: number) =>
    lockedOutputs.some((o) => o.txid === txid && o.vout === vout);

  const handleLockToggle = async (lock: boolean) => {
    try {
      setError("");
      for (const key of selected) {
        const [txid, voutStr] = key.split(":");
        await lockUnspentOutput(txid, parseInt(voutStr), lock);
      }
      toast(lock ? "Outputs locked" : "Outputs unlocked", "success");
      setSelected(new Set());
      refresh();
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const selectedTotal = utxos
    .filter((u) => selected.has(utxoKey(u.txid, u.vout)))
    .reduce((sum, u) => sum + u.amount, 0);

  const handleSend = async () => {
    try {
      setError("");
      setSending(true);
      const inputs = Array.from(selected).map((key) => {
        const [txid, voutStr] = key.split(":");
        return { txid, vout: parseInt(voutStr) };
      });
      const amountSats = Math.floor(parseFloat(sendAmount) * 100_000_000);
      const rate = feeRate ? parseFloat(feeRate) : undefined;
      const txid = await sendWithInputs(inputs, destAddress, amountSats, rate);
      toast(`Transaction sent: ${txid.substring(0, 16)}...`, "success");
      setShowSend(false);
      setDestAddress("");
      setSendAmount("");
      setFeeRate("");
      setSelected(new Set());
      refresh();
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setSending(false);
    }
  };

  if (mode !== "fullnode") {
    return (
      <div className="page">
        <h1>Coin Control</h1>
        <div className="card" style={{ maxWidth: 500 }}>
          <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
            Coin Control requires a full node connection. Switch to Full Node mode in Settings.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ marginBottom: 0 }}>Coin Control</h1>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {selected.size > 0 && (
            <span style={{ fontSize: 12, color: "var(--text-secondary)", marginRight: 8 }}>
              {selected.size} selected ({formatGhost(Math.round(selectedTotal * 100_000_000))} GHOST)
            </span>
          )}
          <button className="btn-secondary btn-small" onClick={selectAll}>
            Select All
          </button>
          <button className="btn-secondary btn-small" onClick={deselectAll}>
            Deselect
          </button>
        </div>
      </div>

      {error && <div className="error-text" style={{ marginBottom: 16 }}>{error}</div>}

      {/* Action buttons */}
      {selected.size > 0 && (
        <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
          <button className="btn-secondary btn-small" onClick={() => handleLockToggle(true)}>
            Lock Selected
          </button>
          <button className="btn-secondary btn-small" onClick={() => handleLockToggle(false)}>
            Unlock Selected
          </button>
          <button
            className="btn-primary btn-small"
            onClick={() => setShowSend(!showSend)}
          >
            {showSend ? "Cancel Send" : "Send Selected"}
          </button>
        </div>
      )}

      {/* Send form */}
      {showSend && selected.size > 0 && (
        <div className="card" style={{ maxWidth: 500, marginBottom: 24 }}>
          <h2>Send from Selected UTXOs</h2>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 16 }}>
            Sending from {selected.size} inputs ({formatGhost(Math.round(selectedTotal * 100_000_000))} GHOST available)
          </div>
          <div className="form-group">
            <label>Destination Address</label>
            <input
              value={destAddress}
              onChange={(e) => setDestAddress(e.target.value)}
              placeholder="Ghost address..."
              className="mono"
            />
          </div>
          <div className="form-group">
            <label>Amount (GHOST)</label>
            <input
              type="number"
              step="0.00000001"
              value={sendAmount}
              onChange={(e) => setSendAmount(e.target.value)}
              placeholder="0.00000000"
            />
          </div>
          <div className="form-group">
            <label>Fee Rate (sat/vB, optional)</label>
            <input
              type="number"
              step="0.1"
              value={feeRate}
              onChange={(e) => setFeeRate(e.target.value)}
              placeholder="Auto"
            />
          </div>
          <button
            className="btn-primary"
            onClick={handleSend}
            disabled={!destAddress || !sendAmount || sending}
            style={{ width: "100%" }}
          >
            {sending ? "Sending..." : "Confirm & Send"}
          </button>
        </div>
      )}

      {/* UTXO table */}
      <div className="card" style={{ padding: 0 }}>
        <table>
          <thead>
            <tr>
              <th style={{ width: 40 }}></th>
              <th>TxID</th>
              <th>Vout</th>
              <th>Amount</th>
              <th>Confirmations</th>
              <th>Address</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {utxos.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                  No unspent outputs
                </td>
              </tr>
            ) : (
              utxos.map((utxo) => {
                const key = utxoKey(utxo.txid, utxo.vout);
                const locked = isLocked(utxo.txid, utxo.vout);
                return (
                  <tr key={key} style={{ opacity: locked ? 0.5 : 1 }}>
                    <td>
                      <input
                        type="checkbox"
                        checked={selected.has(key)}
                        onChange={() => toggleSelect(key)}
                        style={{ width: "auto", cursor: "pointer" }}
                      />
                    </td>
                    <td className="mono truncate" style={{ maxWidth: 120 }} title={utxo.txid}>
                      {utxo.txid}
                    </td>
                    <td>{utxo.vout}</td>
                    <td>{formatGhost(Math.round(utxo.amount * 100_000_000))} GHOST</td>
                    <td>{utxo.confirmations}</td>
                    <td className="mono truncate" style={{ maxWidth: 120 }} title={utxo.address}>
                      {utxo.address}
                    </td>
                    <td>
                      {locked ? (
                        <span className="badge badge-failed">Locked</span>
                      ) : utxo.spendable ? (
                        <span className="badge badge-completed">Spendable</span>
                      ) : (
                        <span className="badge badge-draft">Unspendable</span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
