import { useEffect, useState } from "react";
import { lightReceive, walletGhostId } from "../lib/tauri";

export function Receive() {
  const [ghostId, setGhostId] = useState<string | null>(null);
  const [address, setAddress] = useState<string | null>(null);
  const [index, setIndex] = useState(0);
  const [err, setErr] = useState<string | null>(null);

  const refresh = async () => {
    setErr(null);
    try {
      const id = await walletGhostId();
      setGhostId(id.ghost_id);
      const recv = await lightReceive(index);
      setAddress(recv.address);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  useEffect(() => {
    refresh();
  }, [index]);

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // best-effort — clipboard may not be available in some webview
      // sandboxes; rely on the user-visible "copied" feedback only
      // when it succeeds.
    }
  };

  return (
    <div className="screen">
      <h1>Receive</h1>
      {err && (
        <div className="card" style={{ borderColor: "var(--fail)" }}>
          {err}
        </div>
      )}

      <div className="card">
        <h2>Ghost ID (for L2 payments)</h2>
        <p className="muted" style={{ margin: 0 }}>
          Share this with senders. They use it to send you L2 instant
          payments — no on-chain transaction, no liquidity setup.
        </p>
        <div className="row" style={{ alignItems: "stretch" }}>
          <input readOnly value={ghostId ?? "—"} className="mono" />
          <button
            className="secondary"
            onClick={() => ghostId && copy(ghostId)}
            disabled={!ghostId}
          >
            Copy
          </button>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Bitcoin receive address (for L1 deposits)</h2>
          <div className="row">
            <label style={{ margin: 0 }}>Index</label>
            <input
              type="number"
              min={0}
              value={index}
              onChange={(e) => setIndex(Number(e.target.value) || 0)}
              style={{ width: 80 }}
            />
          </div>
        </div>
        <p className="muted" style={{ margin: 0 }}>
          A fresh receive address derived at the supplied index.
          Anyone sending to it generates a payment your wallet detects
          via BIP-352 silent payments.
        </p>
        <div className="row" style={{ alignItems: "stretch" }}>
          <input readOnly value={address ?? "—"} className="mono" />
          <button
            className="secondary"
            onClick={() => address && copy(address)}
            disabled={!address}
          >
            Copy
          </button>
        </div>
      </div>
    </div>
  );
}
