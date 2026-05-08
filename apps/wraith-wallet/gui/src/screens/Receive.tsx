import { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { lightReceive, walletGhostId } from "../lib/tauri";

/// Build a BIP-21 URI for the L1 receive address. Same shape the
/// Merchant screen emits, minus the amount param (Receive is a
/// "send anything" address — the sender picks the amount). The
/// `ghost=` extension carries the bech32 ghost-id so Ghost-aware
/// wallets can route via BIP-352 silent payments instead.
function bip21ReceiveUri(address: string, ghost_id: string | null): string {
  if (!ghost_id) return `bitcoin:${address}`;
  const params = new URLSearchParams();
  params.set("ghost", ghost_id);
  return `bitcoin:${address}?${params.toString()}`;
}

export function Receive() {
  const [ghostId, setGhostId] = useState<string | null>(null);
  const [address, setAddress] = useState<string | null>(null);
  const [index, setIndex] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState<"ghost" | "address" | null>(null);

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

  const copy = async (text: string, tag: "ghost" | "address") => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(tag);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard unavailable in some webview sandboxes */
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
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          Share this with senders. They use it to send you L2 instant
          payments — no on-chain transaction, no liquidity setup.
          Receivers using a Ghost-aware wallet pick this up via the
          BIP-352 silent-payment scanner; senders can also paste it
          into the Send screen of any wallet that speaks the Ghost
          protocol.
        </p>
        {ghostId && (
          <div
            style={{
              display: "flex",
              gap: 16,
              alignItems: "flex-start",
              marginTop: 8,
            }}
          >
            <div
              style={{
                padding: 12,
                background: "white",
                borderRadius: 6,
                flexShrink: 0,
              }}
            >
              <QRCodeSVG value={ghostId} size={140} level="M" />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="row" style={{ alignItems: "stretch" }}>
                <input readOnly value={ghostId} className="mono" />
                <button
                  className="secondary"
                  onClick={() => copy(ghostId, "ghost")}
                  style={{ marginLeft: 6 }}
                >
                  {copied === "ghost" ? "copied" : "Copy"}
                </button>
              </div>
            </div>
          </div>
        )}
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
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          A fresh receive address derived at the supplied index. Any
          wallet can send to it directly — Ghost-aware wallets pick
          up the embedded ghost-id and route via BIP-352 silent
          payments instead. The QR encodes a BIP-21 URI with both
          forms so one scan works everywhere.
        </p>
        {address && (
          <div
            style={{
              display: "flex",
              gap: 16,
              alignItems: "flex-start",
              marginTop: 8,
            }}
          >
            <div
              style={{
                padding: 12,
                background: "white",
                borderRadius: 6,
                flexShrink: 0,
              }}
            >
              <QRCodeSVG
                value={bip21ReceiveUri(address, ghostId)}
                size={140}
                level="M"
              />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="row" style={{ alignItems: "stretch" }}>
                <input readOnly value={address} className="mono" />
                <button
                  className="secondary"
                  onClick={() => copy(address, "address")}
                  style={{ marginLeft: 6 }}
                >
                  {copied === "address" ? "copied" : "Copy"}
                </button>
              </div>
              <span
                className="muted"
                style={{ fontSize: 12, marginTop: 4, display: "block" }}
              >
                BIP86 path: m/86'/531'/0'/0/{index}
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
