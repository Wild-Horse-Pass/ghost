import { useEffect, useState, useCallback } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { listLocks, reconcileLock, formatGhost, type LockInfo } from "../api/commands";
import { useConnection } from "../contexts/ConnectionContext";
import WizardStepper from "../components/WizardStepper";

const STEPS = ["Select Lock", "Destination", "Confirm", "Complete"];

export default function WithdrawWizard() {
  const navigate = useNavigate();
  const { mode } = useConnection();
  const [searchParams] = useSearchParams();
  const preselectedLockId = searchParams.get("lockId");

  const [step, setStep] = useState(0);
  const [locks, setLocks] = useState<LockInfo[]>([]);
  const [selectedLockId, setSelectedLockId] = useState<string>(preselectedLockId || "");
  const [destination, setDestination] = useState("");
  const [settlementClass, setSettlementClass] = useState<"standard" | "batched">("standard");
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const fetchLocks = useCallback(async () => {
    try {
      const all = await listLocks();
      setLocks(all.filter((l) => l.state.toLowerCase() === "active"));
    } catch (e: unknown) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    if (mode === "fullnode") fetchLocks();
  }, [mode, fetchLocks]);

  const selectedLock = locks.find((l) => l.id === selectedLockId) || null;

  const handleWithdraw = async () => {
    if (!selectedLock) return;
    try {
      setError("");
      setSubmitting(true);
      const res = await reconcileLock(selectedLock.id, destination, settlementClass);
      setResult(res);
      setStep(3);
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  const isValidAddress = destination.length >= 26;

  if (mode !== "fullnode") {
    return (
      <div className="page">
        <h1>Withdraw</h1>
        <div className="card" style={{ maxWidth: 500 }}>
          <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
            Withdraw requires a full node connection. Switch to Full Node mode in Settings.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <h1>Withdraw</h1>
      <WizardStepper steps={STEPS} currentStep={step} />

      <div className="card" style={{ maxWidth: 560, margin: "0 auto" }}>
        {/* Step 0: Select Lock */}
        {step === 0 && (
          <>
            <h2>Select Lock</h2>
            <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 20 }}>
              Choose which lock to withdraw from.
            </p>
            {locks.length === 0 ? (
              <div style={{ textAlign: "center", padding: 24, color: "var(--text-muted)" }}>
                No active locks available for withdrawal.
              </div>
            ) : (
              <div style={{ display: "grid", gap: 10 }}>
                {locks.map((lock) => (
                  <div
                    key={lock.id}
                    onClick={() => setSelectedLockId(lock.id)}
                    style={{
                      padding: "14px 18px",
                      borderRadius: 8,
                      border: selectedLockId === lock.id
                        ? "2px solid var(--accent)"
                        : "1px solid var(--border)",
                      background: selectedLockId === lock.id ? "var(--accent-muted)" : "var(--bg-tertiary)",
                      cursor: "pointer",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      transition: "all 0.15s ease",
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 14 }}>{lock.denomination}</div>
                      <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                        {lock.id.substring(0, 16)}...
                      </div>
                    </div>
                    <div className="mono" style={{ fontSize: 14, fontWeight: 600 }}>
                      {formatGhost(lock.amount_sats)} GHOST
                    </div>
                  </div>
                ))}
              </div>
            )}
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 24, gap: 8 }}>
              <button className="btn-secondary" onClick={() => navigate("/ghost-locks")}>
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={() => setStep(1)}
                disabled={!selectedLockId}
              >
                Next
              </button>
            </div>
          </>
        )}

        {/* Step 1: Destination */}
        {step === 1 && (
          <>
            <h2>Destination Address</h2>
            <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 20 }}>
              Enter the L1 Bitcoin address to receive the withdrawn funds.
            </p>
            <div className="form-group">
              <label>Bitcoin Address</label>
              <input
                value={destination}
                onChange={(e) => setDestination(e.target.value)}
                placeholder="Ghost address..."
                className="mono"
              />
              {destination && !isValidAddress && (
                <div className="error-text">Address appears too short</div>
              )}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 24, gap: 8 }}>
              <button className="btn-secondary" onClick={() => setStep(0)}>
                Back
              </button>
              <button
                className="btn-primary"
                onClick={() => setStep(2)}
                disabled={!isValidAddress}
              >
                Next
              </button>
            </div>
          </>
        )}

        {/* Step 2: Confirm */}
        {step === 2 && selectedLock && (
          <>
            <h2>Confirm Withdrawal</h2>
            <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 20 }}>
              Review the withdrawal details.
            </p>
            <div style={{ display: "grid", gap: 12, marginBottom: 20 }}>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>Lock</label>
                <div style={{ fontSize: 14, fontWeight: 600 }}>
                  {selectedLock.denomination}
                  <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: 8 }}>
                    {selectedLock.id.substring(0, 16)}...
                  </span>
                </div>
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>Amount</label>
                <div style={{ fontSize: 20, fontWeight: 700 }}>
                  {formatGhost(selectedLock.amount_sats)}{" "}
                  <span style={{ fontSize: 13, color: "var(--text-muted)" }}>GHOST</span>
                </div>
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>Destination</label>
                <div className="mono" style={{ fontSize: 12, wordBreak: "break-all" }}>
                  {destination}
                </div>
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>Settlement Class</label>
                <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                  <button
                    className={settlementClass === "standard" ? "btn-primary btn-small" : "btn-secondary btn-small"}
                    onClick={() => setSettlementClass("standard")}
                  >
                    Standard
                  </button>
                  <button
                    className={settlementClass === "batched" ? "btn-primary btn-small" : "btn-secondary btn-small"}
                    onClick={() => setSettlementClass("batched")}
                  >
                    Batched
                  </button>
                </div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                  {settlementClass === "standard"
                    ? "Standard settlement — individual on-chain transaction"
                    : "Batched settlement — grouped with other withdrawals for lower fees"}
                </div>
              </div>
            </div>
            {error && <div className="error-text" style={{ marginBottom: 12 }}>{error}</div>}
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <button className="btn-secondary" onClick={() => setStep(1)}>
                Back
              </button>
              <button
                className="btn-primary"
                onClick={handleWithdraw}
                disabled={submitting}
              >
                {submitting ? "Withdrawing..." : "Confirm Withdrawal"}
              </button>
            </div>
          </>
        )}

        {/* Step 3: Complete */}
        {step === 3 && (
          <>
            <div style={{ fontSize: 13, color: "var(--success)", marginBottom: 16 }}>
              Withdrawal submitted successfully
            </div>
            {selectedLock && (
              <div className="form-group">
                <label>Amount</label>
                <div style={{ fontSize: 18, fontWeight: 700 }}>
                  {formatGhost(selectedLock.amount_sats)} GHOST
                </div>
              </div>
            )}
            <div className="form-group">
              <label>Destination</label>
              <div className="mono" style={{ fontSize: 12, wordBreak: "break-all" }}>
                {destination}
              </div>
            </div>
            <div className="form-group">
              <label>Settlement</label>
              <div style={{ fontSize: 13 }}>{settlementClass === "standard" ? "Standard" : "Batched"}</div>
            </div>
            {result?.txid && (
              <div className="form-group">
                <label>Transaction ID</label>
                <div
                  className="mono"
                  style={{
                    fontSize: 12,
                    wordBreak: "break-all",
                    background: "var(--bg-tertiary)",
                    padding: 10,
                    borderRadius: 6,
                    border: "1px solid var(--border)",
                    cursor: "pointer",
                  }}
                  onClick={() => navigator.clipboard.writeText(result.txid)}
                  title="Click to copy"
                >
                  {result.txid}
                </div>
              </div>
            )}
            {result?.status && (
              <div className="form-group">
                <label>Status</label>
                <div><span className="badge badge-queued">{result.status}</span></div>
              </div>
            )}
            <button className="btn-primary" onClick={() => navigate("/ghost-locks")} style={{ width: "100%" }}>
              Back to Locks
            </button>
          </>
        )}
      </div>
    </div>
  );
}
