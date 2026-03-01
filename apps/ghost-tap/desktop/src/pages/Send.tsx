import { useState } from "react";
import { buildTransaction, signAndBroadcast, formatGhost } from "../api/commands";

export default function Send() {
  const [address, setAddress] = useState("");
  const [amount, setAmount] = useState("");
  const [feePriority, setFeePriority] = useState(1);
  const [step, setStep] = useState<"input" | "confirm" | "done">("input");
  const [txJson, setTxJson] = useState("");
  const [fee, setFee] = useState(0);
  const [txid, setTxid] = useState("");
  const [error, setError] = useState("");

  const amountSats = Math.floor(parseFloat(amount || "0") * 100_000_000);

  const handleBuild = async () => {
    try {
      setError("");
      const result = await buildTransaction(address, amountSats, feePriority);
      setTxJson(result.tx_json);
      setFee(result.fee);
      setStep("confirm");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleSend = async () => {
    try {
      setError("");
      const result = await signAndBroadcast(txJson);
      setTxid(result.txid);
      setStep("done");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleReset = () => {
    setAddress("");
    setAmount("");
    setTxJson("");
    setFee(0);
    setTxid("");
    setError("");
    setStep("input");
  };

  if (step === "done") {
    return (
      <div className="page">
        <h1>Payment Sent</h1>
        <div className="card" style={{ maxWidth: 500 }}>
          <div style={{ fontSize: 13, color: "var(--success)", marginBottom: 12 }}>
            Transaction broadcast successfully
          </div>
          <div className="form-group">
            <label>Transaction ID</label>
            <div className="mono" style={{ fontSize: 12, wordBreak: "break-all" }}>
              {txid}
            </div>
          </div>
          <button className="btn-primary" onClick={handleReset}>
            Send Another
          </button>
        </div>
      </div>
    );
  }

  if (step === "confirm") {
    return (
      <div className="page">
        <h1>Confirm Transaction</h1>
        <div className="card" style={{ maxWidth: 500 }}>
          <div className="form-group">
            <label>To</label>
            <div className="mono" style={{ fontSize: 12, wordBreak: "break-all" }}>
              {address}
            </div>
          </div>
          <div className="form-group">
            <label>Amount</label>
            <div style={{ fontSize: 24, fontWeight: 700 }}>
              {amount} <span style={{ fontSize: 14, color: "var(--text-muted)" }}>GHOST</span>
            </div>
          </div>
          <div className="form-group">
            <label>Network Fee</label>
            <div>{formatGhost(fee)} GHOST</div>
          </div>
          <div className="form-group">
            <label>Total</label>
            <div style={{ fontSize: 18, fontWeight: 700 }}>
              {formatGhost(amountSats + fee)} GHOST
            </div>
          </div>
          {error && <div className="error-text" style={{ marginBottom: 12 }}>{error}</div>}
          <div style={{ display: "flex", gap: 12 }}>
            <button className="btn-secondary" onClick={() => setStep("input")}>
              Back
            </button>
            <button className="btn-primary" onClick={handleSend} style={{ flex: 1 }}>
              Confirm & Send
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <h1>Send Payment</h1>
      <div className="card" style={{ maxWidth: 500 }}>
        <div className="form-group">
          <label>Recipient Address</label>
          <input
            placeholder="Ghost address..."
            value={address}
            onChange={(e) => setAddress(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label>Amount (GHOST)</label>
          <input
            type="number"
            step="0.00000001"
            placeholder="0.00000000"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label>Fee Priority</label>
          <div style={{ display: "flex", gap: 8 }}>
            {[
              { val: 0, label: "Low" },
              { val: 1, label: "Medium" },
              { val: 2, label: "High" },
            ].map((opt) => (
              <button
                key={opt.val}
                className={feePriority === opt.val ? "btn-primary btn-small" : "btn-secondary btn-small"}
                onClick={() => setFeePriority(opt.val)}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
        {error && <div className="error-text" style={{ marginBottom: 12 }}>{error}</div>}
        <button
          className="btn-primary"
          onClick={handleBuild}
          disabled={!address || !amount || amountSats <= 0}
          style={{ width: "100%" }}
        >
          Preview Transaction
        </button>
      </div>
    </div>
  );
}
