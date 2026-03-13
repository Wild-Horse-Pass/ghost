import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { sendL2Payment, l2Balance, formatGhost } from "../api/commands";
import { useConnection } from "../contexts/ConnectionContext";
import WizardStepper from "../components/WizardStepper";

const STEPS = ["Recipient", "Amount", "Memo", "Confirm"];
const MEMO_MAX_LENGTH = 59;

export default function SendL2() {
  const navigate = useNavigate();
  const { mode } = useConnection();
  const [step, setStep] = useState(0);
  const [recipient, setRecipient] = useState("");
  const [amountStr, setAmountStr] = useState("");
  const [memo, setMemo] = useState("");
  const [availableBalance, setAvailableBalance] = useState(0);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");
  const [sending, setSending] = useState(false);

  const fetchBalance = useCallback(async () => {
    try {
      const bal = await l2Balance();
      setAvailableBalance(bal.confirmed);
    } catch {
      // L2 balance may not be available
    }
  }, []);

  useEffect(() => {
    if (mode === "fullnode") fetchBalance();
  }, [mode, fetchBalance]);

  const amountSats = Math.floor(parseFloat(amountStr || "0"));

  const handleSend = async () => {
    try {
      setError("");
      setSending(true);
      const res = await sendL2Payment(recipient, amountSats, memo || undefined);
      setResult(res);
      setStep(4); // done state
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setSending(false);
    }
  };

  if (mode !== "fullnode") {
    return (
      <div className="page">
        <h1>Send L2</h1>
        <div className="card" style={{ maxWidth: 500 }}>
          <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
            L2 payments require a full node connection. Switch to Full Node mode in Settings.
          </p>
        </div>
      </div>
    );
  }

  // Done state (after step 3 confirm)
  if (step === 4) {
    return (
      <div className="page">
        <h1>Send L2</h1>
        <WizardStepper steps={STEPS} currentStep={3} />
        <div className="card" style={{ maxWidth: 560, margin: "0 auto" }}>
          <div style={{ fontSize: 13, color: "var(--success)", marginBottom: 16 }}>
            L2 payment sent successfully
          </div>
          <div className="form-group">
            <label>Recipient</label>
            <div className="mono" style={{ fontSize: 12, wordBreak: "break-all" }}>
              {recipient}
            </div>
          </div>
          <div className="form-group">
            <label>Amount</label>
            <div style={{ fontSize: 18, fontWeight: 700 }}>
              {amountSats.toLocaleString()} sats
            </div>
          </div>
          {memo && (
            <div className="form-group">
              <label>Memo</label>
              <div style={{ fontSize: 13 }}>{memo}</div>
            </div>
          )}
          {result?.status && (
            <div className="form-group">
              <label>Status</label>
              <div><span className="badge badge-completed">{result.status}</span></div>
            </div>
          )}
          <button className="btn-primary" onClick={() => navigate("/ghost-locks")} style={{ width: "100%" }}>
            Back to Locks
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <h1>Send L2</h1>
      <WizardStepper steps={STEPS} currentStep={step} />

      <div className="card" style={{ maxWidth: 560, margin: "0 auto" }}>
        {/* Step 0: Recipient */}
        {step === 0 && (
          <>
            <h2>Recipient</h2>
            <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 20 }}>
              Enter the Ghost ID of the recipient.
            </p>
            <div className="form-group">
              <label>Ghost ID</label>
              <input
                value={recipient}
                onChange={(e) => setRecipient(e.target.value)}
                placeholder="Enter Ghost ID..."
                className="mono"
              />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 24, gap: 8 }}>
              <button className="btn-secondary" onClick={() => navigate("/ghost-locks")}>
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={() => setStep(1)}
                disabled={!recipient.trim()}
              >
                Next
              </button>
            </div>
          </>
        )}

        {/* Step 1: Amount */}
        {step === 1 && (
          <>
            <h2>Amount</h2>
            <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 20 }}>
              Enter the amount to send in satoshis.
            </p>
            {availableBalance > 0 && (
              <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 16 }}>
                Available L2 balance:{" "}
                <span className="mono" style={{ fontWeight: 600 }}>
                  {formatGhost(availableBalance)} GHOST
                </span>
                <span style={{ color: "var(--text-muted)", marginLeft: 4 }}>
                  ({availableBalance.toLocaleString()} sats)
                </span>
              </div>
            )}
            <div className="form-group">
              <label>Amount (sats)</label>
              <input
                type="number"
                value={amountStr}
                onChange={(e) => setAmountStr(e.target.value)}
                placeholder="0"
                min="1"
              />
              {amountSats > availableBalance && availableBalance > 0 && (
                <div className="error-text">Amount exceeds available balance</div>
              )}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 24, gap: 8 }}>
              <button className="btn-secondary" onClick={() => setStep(0)}>
                Back
              </button>
              <button
                className="btn-primary"
                onClick={() => setStep(2)}
                disabled={amountSats <= 0}
              >
                Next
              </button>
            </div>
          </>
        )}

        {/* Step 2: Memo */}
        {step === 2 && (
          <>
            <h2>Memo (Optional)</h2>
            <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 20 }}>
              Add an optional memo to this payment.
            </p>
            <div className="form-group">
              <label>Memo</label>
              <input
                value={memo}
                onChange={(e) => {
                  if (e.target.value.length <= MEMO_MAX_LENGTH) {
                    setMemo(e.target.value);
                  }
                }}
                placeholder="Optional message..."
                maxLength={MEMO_MAX_LENGTH}
              />
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4, textAlign: "right" }}>
                {memo.length}/{MEMO_MAX_LENGTH}
              </div>
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 24, gap: 8 }}>
              <button className="btn-secondary" onClick={() => setStep(1)}>
                Back
              </button>
              <button className="btn-primary" onClick={() => setStep(3)}>
                Next
              </button>
            </div>
          </>
        )}

        {/* Step 3: Confirm */}
        {step === 3 && (
          <>
            <h2>Confirm Payment</h2>
            <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 20 }}>
              Review and confirm the L2 payment.
            </p>
            <div style={{ display: "grid", gap: 12, marginBottom: 20 }}>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>Recipient</label>
                <div className="mono" style={{ fontSize: 12, wordBreak: "break-all" }}>
                  {recipient}
                </div>
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>Amount</label>
                <div style={{ fontSize: 20, fontWeight: 700 }}>
                  {amountSats.toLocaleString()}{" "}
                  <span style={{ fontSize: 13, color: "var(--text-muted)" }}>sats</span>
                </div>
                <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                  {formatGhost(amountSats)} GHOST
                </div>
              </div>
              {memo && (
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label>Memo</label>
                  <div style={{ fontSize: 13 }}>{memo}</div>
                </div>
              )}
            </div>
            {error && <div className="error-text" style={{ marginBottom: 12 }}>{error}</div>}
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <button className="btn-secondary" onClick={() => setStep(2)}>
                Back
              </button>
              <button
                className="btn-primary"
                onClick={handleSend}
                disabled={sending}
              >
                {sending ? "Sending..." : "Send Payment"}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
