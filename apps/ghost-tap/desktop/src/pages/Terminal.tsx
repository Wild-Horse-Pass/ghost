import { useState } from "react";
import { createPaymentUri, newReceiveAddress } from "../api/commands";
import QrCode from "../components/QrCode";
import NumericKeypad from "../components/NumericKeypad";

export default function Terminal() {
  const [amountStr, setAmountStr] = useState("");
  const [paymentUri, setPaymentUri] = useState("");
  const [waiting, setWaiting] = useState(false);
  const [error, setError] = useState("");

  const amountSats = Math.floor(parseFloat(amountStr || "0") * 100_000_000);

  const handleGenerate = async () => {
    try {
      setError("");
      const address = await newReceiveAddress();
      const uri = await createPaymentUri(
        address,
        amountSats > 0 ? amountSats : undefined,
        undefined,
        "GhostTap Terminal",
      );
      setPaymentUri(uri);
      setWaiting(true);
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleReset = () => {
    setAmountStr("");
    setPaymentUri("");
    setWaiting(false);
    setError("");
  };

  if (waiting && paymentUri) {
    return (
      <div className="page" style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ textAlign: "center" }}>
          <h2 style={{ marginBottom: 8 }}>Scan to Pay</h2>
          {amountSats > 0 && (
            <div style={{ fontSize: 28, fontWeight: 700, marginBottom: 20 }}>
              {amountStr}{" "}
              <span style={{ fontSize: 14, color: "var(--text-muted)" }}>GHOST</span>
            </div>
          )}
          <QrCode value={paymentUri} size={280} />
          <div
            className="mono"
            style={{
              fontSize: 11,
              color: "var(--text-muted)",
              marginTop: 16,
              maxWidth: 320,
              wordBreak: "break-all",
            }}
          >
            {paymentUri}
          </div>
          <div style={{ marginTop: 24, color: "var(--text-secondary)", fontSize: 13 }}>
            Waiting for payment...
          </div>
          <button className="btn-secondary" onClick={handleReset} style={{ marginTop: 16 }}>
            New Payment
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="page" style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ textAlign: "center" }}>
        <h1 style={{ marginBottom: 8 }}>Payment Terminal</h1>
        <p style={{ color: "var(--text-secondary)", marginBottom: 32, fontSize: 13 }}>
          Enter amount in GHOST
        </p>
        <div style={{ fontSize: 40, fontWeight: 700, marginBottom: 32, minHeight: 52 }}>
          {amountStr || "0"}{" "}
          <span style={{ fontSize: 18, color: "var(--text-muted)" }}>GHOST</span>
        </div>
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 24 }}>
          <NumericKeypad value={amountStr} onChange={setAmountStr} />
        </div>
        {error && <div className="error-text" style={{ marginBottom: 12 }}>{error}</div>}
        <button
          className="btn-primary"
          onClick={handleGenerate}
          style={{ padding: "14px 48px", fontSize: 16 }}
        >
          Generate QR
        </button>
      </div>
    </div>
  );
}
