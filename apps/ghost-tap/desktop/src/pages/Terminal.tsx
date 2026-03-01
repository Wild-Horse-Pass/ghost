import { useState, useEffect, useRef } from "react";
import { createPaymentUri, newReceiveAddress, getBalance, formatGhost } from "../api/commands";
import { useToast } from "../components/ToastProvider";
import QrCode from "../components/QrCode";
import NumericKeypad from "../components/NumericKeypad";

const POLL_INTERVAL = 3_000; // 3 seconds

export default function Terminal() {
  const { toast } = useToast();
  const [amountStr, setAmountStr] = useState("");
  const [paymentUri, setPaymentUri] = useState("");
  const [waiting, setWaiting] = useState(false);
  const [paid, setPaid] = useState(false);
  const [error, setError] = useState("");
  const baseBalanceRef = useRef<number>(0);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const amountSats = Math.floor(parseFloat(amountStr || "0") * 100_000_000);

  // Poll for payment when waiting
  useEffect(() => {
    if (!waiting || paid) return;

    pollRef.current = setInterval(async () => {
      try {
        const bal = await getBalance();
        const total = bal.confirmed + bal.pending;
        if (total > baseBalanceRef.current) {
          const received = total - baseBalanceRef.current;
          setPaid(true);
          setWaiting(false);
          toast(`Payment received: ${formatGhost(received)} GHOST`, "success");
          if (pollRef.current) clearInterval(pollRef.current);
        }
      } catch {
        // Silently retry on next poll
      }
    }, POLL_INTERVAL);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [waiting, paid, toast]);

  const handleGenerate = async () => {
    try {
      setError("");
      // Snapshot current balance before generating QR
      const bal = await getBalance();
      baseBalanceRef.current = bal.confirmed + bal.pending;

      const address = await newReceiveAddress();
      const uri = await createPaymentUri(
        address,
        amountSats > 0 ? amountSats : undefined,
        undefined,
        "GhostTap Terminal",
      );
      setPaymentUri(uri);
      setWaiting(true);
      setPaid(false);
    } catch (e: unknown) {
      setError(String(e));
      toast(String(e), "error");
    }
  };

  const handleReset = () => {
    setAmountStr("");
    setPaymentUri("");
    setWaiting(false);
    setPaid(false);
    setError("");
    if (pollRef.current) clearInterval(pollRef.current);
  };

  if (paid) {
    return (
      <div className="page" style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ textAlign: "center" }}>
          <div
            style={{
              width: 80,
              height: 80,
              borderRadius: "50%",
              background: "rgba(40, 167, 69, 0.15)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              margin: "0 auto 24px",
              fontSize: 40,
              color: "var(--success)",
            }}
          >
            &#10003;
          </div>
          <h2 style={{ color: "var(--success)", marginBottom: 8 }}>Payment Received</h2>
          {amountSats > 0 && (
            <div style={{ fontSize: 28, fontWeight: 700, marginBottom: 24 }}>
              {amountStr}{" "}
              <span style={{ fontSize: 14, color: "var(--text-muted)" }}>GHOST</span>
            </div>
          )}
          <button className="btn-primary" onClick={handleReset} style={{ padding: "14px 48px" }}>
            New Payment
          </button>
        </div>
      </div>
    );
  }

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
          <div style={{ marginTop: 24, display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: "var(--accent)",
                animation: "pulse-dot 1.5s ease infinite",
              }}
            />
            <span style={{ color: "var(--text-secondary)", fontSize: 13 }}>
              Waiting for payment...
            </span>
          </div>
          <button className="btn-secondary" onClick={handleReset} style={{ marginTop: 16 }}>
            Cancel
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
