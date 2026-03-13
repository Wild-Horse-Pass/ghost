import { useState, useEffect, useRef } from "react";
import { createPaymentUri, newReceiveAddress, getBalance, formatGhost, executeRpc } from "../api/commands";
import { useConnection } from "../contexts/ConnectionContext";
import { useToast } from "../components/ToastProvider";
import QrCode from "../components/QrCode";
import NumericKeypad from "../components/NumericKeypad";

interface RpcHistoryItem {
  method: string;
  params: string;
  result: string;
  error: boolean;
  timestamp: number;
}

const POLL_INTERVAL = 3_000; // 3 seconds

function RpcConsole() {
  const [method, setMethod] = useState("");
  const [params, setParams] = useState("");
  const [result, setResult] = useState("");
  const [rpcError, setRpcError] = useState("");
  const [executing, setExecuting] = useState(false);
  const [history, setHistory] = useState<RpcHistoryItem[]>([]);

  const handleExecute = async () => {
    try {
      setRpcError("");
      setResult("");
      setExecuting(true);
      const res = await executeRpc(method, params || "[]");
      const formatted = JSON.stringify(res, null, 2);
      setResult(formatted);
      setHistory((prev) => [
        { method, params: params || "[]", result: formatted, error: false, timestamp: Date.now() },
        ...prev,
      ]);
    } catch (e: unknown) {
      const errStr = String(e);
      setRpcError(errStr);
      setHistory((prev) => [
        { method, params: params || "[]", result: errStr, error: true, timestamp: Date.now() },
        ...prev,
      ]);
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div>
      <div className="card" style={{ maxWidth: 700, marginBottom: 24 }}>
        <h2>RPC Console</h2>
        <div className="form-group">
          <label>Method</label>
          <input
            value={method}
            onChange={(e) => setMethod(e.target.value)}
            placeholder="getblockchaininfo, getnetworkinfo, etc."
            className="mono"
            onKeyDown={(e) => {
              if (e.key === "Enter" && method) handleExecute();
            }}
          />
        </div>
        <div className="form-group">
          <label>Parameters (JSON array)</label>
          <textarea
            value={params}
            onChange={(e) => setParams(e.target.value)}
            placeholder='[]  or  ["param1", 2, true]'
            rows={3}
            className="mono"
            style={{ resize: "vertical", fontSize: 12 }}
          />
        </div>
        <button
          className="btn-primary"
          onClick={handleExecute}
          disabled={!method || executing}
          style={{ width: "100%" }}
        >
          {executing ? "Executing..." : "Execute"}
        </button>
      </div>

      {(result || rpcError) && (
        <div className="card" style={{ maxWidth: 700, marginBottom: 24 }}>
          <label>{rpcError ? "Error" : "Result"}</label>
          <pre
            className="mono"
            style={{
              fontSize: 11,
              background: "var(--bg-tertiary)",
              padding: 12,
              borderRadius: 6,
              border: `1px solid ${rpcError ? "var(--danger)" : "var(--border)"}`,
              maxHeight: 400,
              overflow: "auto",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              color: rpcError ? "var(--danger)" : "var(--text-primary)",
            }}
          >
            {rpcError || result}
          </pre>
        </div>
      )}

      {history.length > 0 && (
        <div className="card" style={{ maxWidth: 700, padding: 0 }}>
          <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
            <span style={{ fontSize: 13, fontWeight: 600 }}>Command History</span>
          </div>
          {history.map((item, i) => (
            <div
              key={item.timestamp + "-" + i}
              style={{
                padding: "10px 16px",
                borderBottom: "1px solid rgba(42, 42, 62, 0.5)",
                cursor: "pointer",
              }}
              onClick={() => {
                setMethod(item.method);
                setParams(item.params);
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span className="mono" style={{ fontSize: 12, color: "var(--accent)" }}>
                  {item.method}
                </span>
                <span style={{ fontSize: 10, color: "var(--text-muted)" }}>
                  {new Date(item.timestamp).toLocaleTimeString()}
                </span>
              </div>
              {item.params !== "[]" && (
                <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                  {item.params}
                </div>
              )}
              <div
                className="mono truncate"
                style={{
                  fontSize: 11,
                  marginTop: 4,
                  color: item.error ? "var(--danger)" : "var(--text-secondary)",
                  maxWidth: 600,
                }}
              >
                {item.result.split("\n")[0]}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Terminal() {
  const { toast } = useToast();
  const { mode } = useConnection();
  const [terminalTab, setTerminalTab] = useState<"payment" | "rpc">("payment");
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

  // RPC Console tab (fullnode only)
  if (mode === "fullnode" && terminalTab === "rpc") {
    return (
      <div className="page">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
          <h1 style={{ marginBottom: 0 }}>Terminal</h1>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              className="btn-secondary btn-small"
              onClick={() => setTerminalTab("payment")}
            >
              Payment
            </button>
            <button className="btn-primary btn-small">
              RPC Console
            </button>
          </div>
        </div>
        <RpcConsole />
      </div>
    );
  }

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
    <div className="page" style={{ display: "flex", alignItems: "center", justifyContent: "center", position: "relative" }}>
      {mode === "fullnode" && (
        <div style={{ position: "absolute", top: 32, right: 32, display: "flex", gap: 8 }}>
          <button className="btn-primary btn-small">
            Payment
          </button>
          <button
            className="btn-secondary btn-small"
            onClick={() => setTerminalTab("rpc")}
          >
            RPC Console
          </button>
        </div>
      )}
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
