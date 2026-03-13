import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { createLock } from "../api/commands";
import WizardStepper from "../components/WizardStepper";

const STEPS = ["Denomination", "Timelock", "Confirm", "Complete"];

const DENOMINATIONS = [
  { label: "Micro", sats: 10_000, desc: "0.00010000 GHOST" },
  { label: "Small", sats: 50_000, desc: "0.00050000 GHOST" },
  { label: "Medium", sats: 100_000, desc: "0.00100000 GHOST" },
  { label: "Large", sats: 500_000, desc: "0.00500000 GHOST" },
  { label: "Jumbo", sats: 1_000_000, desc: "0.01000000 GHOST" },
];

const TIMELOCK_TIERS = [
  { id: "short", label: "Short", desc: "~3 months (~13,000 blocks)" },
  { id: "medium", label: "Medium", desc: "~6 months (~26,000 blocks)" },
  { id: "long", label: "Long", desc: "~1 year (~52,000 blocks)" },
];

export default function CreateLock() {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [selectedDenom, setSelectedDenom] = useState<number | null>(null);
  const [selectedTier, setSelectedTier] = useState<string | null>(null);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);

  const denom = selectedDenom !== null ? DENOMINATIONS[selectedDenom] : null;
  const tier = selectedTier ? TIMELOCK_TIERS.find((t) => t.id === selectedTier) : null;

  const handleCreate = async () => {
    if (!denom || !selectedTier) return;
    try {
      setError("");
      setCreating(true);
      const res = await createLock(denom.sats, selectedTier);
      setResult(res);
      setStep(3);
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="page">
      <h1>Create Lock</h1>
      <WizardStepper steps={STEPS} currentStep={step} />

      <div className="card" style={{ maxWidth: 560, margin: "0 auto" }}>
        {/* Step 0: Denomination */}
        {step === 0 && (
          <>
            <h2>Select Denomination</h2>
            <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 20 }}>
              Choose the amount to lock in the L2 network.
            </p>
            <div style={{ display: "grid", gap: 10 }}>
              {DENOMINATIONS.map((d, i) => (
                <div
                  key={d.label}
                  onClick={() => setSelectedDenom(i)}
                  style={{
                    padding: "16px 20px",
                    borderRadius: 8,
                    border: selectedDenom === i
                      ? "2px solid var(--accent)"
                      : "1px solid var(--border)",
                    background: selectedDenom === i ? "var(--accent-muted)" : "var(--bg-tertiary)",
                    cursor: "pointer",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    transition: "all 0.15s ease",
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 14 }}>{d.label}</div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
                      {d.sats.toLocaleString()} sats
                    </div>
                  </div>
                  <div className="mono" style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                    {d.desc}
                  </div>
                </div>
              ))}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 24, gap: 8 }}>
              <button className="btn-secondary" onClick={() => navigate("/ghost-locks")}>
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={() => setStep(1)}
                disabled={selectedDenom === null}
              >
                Next
              </button>
            </div>
          </>
        )}

        {/* Step 1: Timelock */}
        {step === 1 && (
          <>
            <h2>Select Timelock Tier</h2>
            <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 20 }}>
              Choose how long the lock is timelocked before recovery is possible.
            </p>
            <div style={{ display: "grid", gap: 10 }}>
              {TIMELOCK_TIERS.map((t) => (
                <div
                  key={t.id}
                  onClick={() => setSelectedTier(t.id)}
                  style={{
                    padding: "16px 20px",
                    borderRadius: 8,
                    border: selectedTier === t.id
                      ? "2px solid var(--accent)"
                      : "1px solid var(--border)",
                    background: selectedTier === t.id ? "var(--accent-muted)" : "var(--bg-tertiary)",
                    cursor: "pointer",
                    transition: "all 0.15s ease",
                  }}
                >
                  <div style={{ fontWeight: 600, fontSize: 14 }}>{t.label}</div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>
                    {t.desc}
                  </div>
                </div>
              ))}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 24, gap: 8 }}>
              <button className="btn-secondary" onClick={() => setStep(0)}>
                Back
              </button>
              <button
                className="btn-primary"
                onClick={() => setStep(2)}
                disabled={selectedTier === null}
              >
                Next
              </button>
            </div>
          </>
        )}

        {/* Step 2: Confirm */}
        {step === 2 && denom && tier && (
          <>
            <h2>Confirm Lock</h2>
            <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 20 }}>
              Review the details below before creating your lock.
            </p>
            <div style={{ display: "grid", gap: 12, marginBottom: 20 }}>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>Denomination</label>
                <div style={{ fontSize: 15, fontWeight: 600 }}>{denom.label}</div>
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>Amount</label>
                <div style={{ fontSize: 20, fontWeight: 700 }}>
                  {denom.desc}{" "}
                  <span style={{ fontSize: 13, color: "var(--text-muted)" }}>
                    ({denom.sats.toLocaleString()} sats)
                  </span>
                </div>
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>Timelock Tier</label>
                <div style={{ fontSize: 15, fontWeight: 600 }}>{tier.label}</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>{tier.desc}</div>
              </div>
            </div>
            {error && <div className="error-text" style={{ marginBottom: 12 }}>{error}</div>}
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <button className="btn-secondary" onClick={() => setStep(1)}>
                Back
              </button>
              <button
                className="btn-primary"
                onClick={handleCreate}
                disabled={creating}
              >
                {creating ? "Creating..." : "Create Lock"}
              </button>
            </div>
          </>
        )}

        {/* Step 3: Complete */}
        {step === 3 && result && (
          <>
            <div style={{ fontSize: 13, color: "var(--success)", marginBottom: 16 }}>
              Lock created successfully
            </div>
            <div className="form-group">
              <label>Lock ID</label>
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
                onClick={() => navigator.clipboard.writeText(result.id || JSON.stringify(result))}
                title="Click to copy"
              >
                {result.id || JSON.stringify(result)}
              </div>
            </div>
            {result.address && (
              <div className="form-group">
                <label>Lock Address</label>
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
                  onClick={() => navigator.clipboard.writeText(result.address)}
                  title="Click to copy"
                >
                  {result.address}
                </div>
              </div>
            )}
            {result.state && (
              <div className="form-group">
                <label>Status</label>
                <div><span className="badge badge-queued">{result.state}</span></div>
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
