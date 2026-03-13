import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { getGhostId, generateGhostId, type GhostIdInfo } from "../api/commands";
import { useConnection } from "../contexts/ConnectionContext";
import WizardStepper from "../components/WizardStepper";

const STEPS = ["Welcome", "Generate", "Complete"];

export default function GhostIdWizard() {
  const navigate = useNavigate();
  const { mode } = useConnection();
  const [step, setStep] = useState(0);
  const [existingId, setExistingId] = useState<GhostIdInfo | null>(null);
  const [generatedId, setGeneratedId] = useState<GhostIdInfo | null>(null);
  const [error, setError] = useState("");
  const [generating, setGenerating] = useState(false);
  const [loading, setLoading] = useState(true);

  const checkExisting = useCallback(async () => {
    try {
      const info = await getGhostId();
      if (info && info.ghost_id) {
        setExistingId(info);
      }
    } catch {
      // No Ghost ID exists yet
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (mode === "fullnode") checkExisting();
  }, [mode, checkExisting]);

  const handleGenerate = async () => {
    try {
      setError("");
      setGenerating(true);
      await generateGhostId();
      const info = await getGhostId();
      setGeneratedId(info);
      setStep(2);
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setGenerating(false);
    }
  };

  const displayId = generatedId || existingId;

  const copyField = (value: string) => {
    navigator.clipboard.writeText(value);
  };

  if (mode !== "fullnode") {
    return (
      <div className="page">
        <h1>Ghost ID</h1>
        <div className="card" style={{ maxWidth: 500 }}>
          <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
            Ghost ID requires a full node connection. Switch to Full Node mode in Settings.
          </p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="page">
        <h1>Ghost ID</h1>
        <div className="card" style={{ maxWidth: 500 }}>
          <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <h1>Ghost ID</h1>
      <WizardStepper steps={STEPS} currentStep={step} />

      <div className="card" style={{ maxWidth: 560, margin: "0 auto" }}>
        {/* Step 0: Welcome */}
        {step === 0 && (
          <>
            <h2>{existingId ? "Your Ghost ID" : "What is a Ghost ID?"}</h2>

            {existingId ? (
              <>
                <p style={{ color: "var(--text-secondary)", fontSize: 13, marginBottom: 20 }}>
                  You already have a Ghost ID. This is your identity for receiving L2 payments.
                </p>
                <div className="form-group">
                  <label>Ghost ID</label>
                  <div
                    className="mono"
                    style={{
                      fontSize: 12,
                      wordBreak: "break-all",
                      background: "var(--bg-tertiary)",
                      padding: 12,
                      borderRadius: 6,
                      border: "1px solid var(--border)",
                      cursor: "pointer",
                    }}
                    onClick={() => copyField(existingId.ghost_id)}
                    title="Click to copy"
                  >
                    {existingId.ghost_id}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 24 }}>
                  <button className="btn-secondary" onClick={() => navigate("/ghost-locks")}>
                    Back to Locks
                  </button>
                  <button className="btn-primary" onClick={() => setStep(2)} style={{ flex: 1 }}>
                    View Details
                  </button>
                </div>
              </>
            ) : (
              <>
                <p style={{ color: "var(--text-secondary)", fontSize: 13, marginBottom: 12 }}>
                  A Ghost ID is your unique identity on the L2 network. It allows other users to
                  send you private L2 payments without knowing your on-chain addresses.
                </p>
                <p style={{ color: "var(--text-secondary)", fontSize: 13, marginBottom: 12 }}>
                  Your Ghost ID is derived from two keypairs: a scan key (for detecting incoming
                  payments) and a spend key (for claiming them). Both are generated from your
                  wallet seed.
                </p>
                <p style={{ color: "var(--text-muted)", fontSize: 12, marginBottom: 20 }}>
                  You only need one Ghost ID. It can be shared publicly without compromising privacy.
                </p>
                <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                  <button className="btn-secondary" onClick={() => navigate("/ghost-locks")}>
                    Cancel
                  </button>
                  <button className="btn-primary" onClick={() => setStep(1)}>
                    Next
                  </button>
                </div>
              </>
            )}
          </>
        )}

        {/* Step 1: Generate */}
        {step === 1 && (
          <>
            <h2>Generate Ghost ID</h2>
            <p style={{ color: "var(--text-secondary)", fontSize: 13, marginBottom: 20 }}>
              Click below to generate your Ghost ID. This will derive your scan and spend
              keypairs from your wallet.
            </p>
            {error && <div className="error-text" style={{ marginBottom: 12 }}>{error}</div>}
            <button
              className="btn-primary"
              onClick={handleGenerate}
              disabled={generating}
              style={{ width: "100%", padding: "14px 20px", fontSize: 15 }}
            >
              {generating ? "Generating..." : "Generate Ghost ID"}
            </button>
            <div style={{ display: "flex", justifyContent: "flex-start", marginTop: 16 }}>
              <button className="btn-secondary" onClick={() => setStep(0)}>
                Back
              </button>
            </div>
          </>
        )}

        {/* Step 2: Complete */}
        {step === 2 && displayId && (
          <>
            <div style={{ fontSize: 13, color: "var(--success)", marginBottom: 16 }}>
              {generatedId ? "Ghost ID generated successfully" : "Your Ghost ID details"}
            </div>
            <div className="form-group">
              <label>Ghost ID</label>
              <div
                className="mono"
                style={{
                  fontSize: 12,
                  wordBreak: "break-all",
                  background: "var(--bg-tertiary)",
                  padding: 12,
                  borderRadius: 6,
                  border: "1px solid var(--border)",
                  cursor: "pointer",
                }}
                onClick={() => copyField(displayId.ghost_id)}
                title="Click to copy"
              >
                {displayId.ghost_id}
              </div>
            </div>
            <div className="form-group">
              <label>Scan Public Key</label>
              <div
                className="mono"
                style={{
                  fontSize: 11,
                  wordBreak: "break-all",
                  background: "var(--bg-tertiary)",
                  padding: 12,
                  borderRadius: 6,
                  border: "1px solid var(--border)",
                  cursor: "pointer",
                }}
                onClick={() => copyField(displayId.scan_pubkey)}
                title="Click to copy"
              >
                {displayId.scan_pubkey}
              </div>
            </div>
            <div className="form-group">
              <label>Spend Public Key</label>
              <div
                className="mono"
                style={{
                  fontSize: 11,
                  wordBreak: "break-all",
                  background: "var(--bg-tertiary)",
                  padding: 12,
                  borderRadius: 6,
                  border: "1px solid var(--border)",
                  cursor: "pointer",
                }}
                onClick={() => copyField(displayId.spend_pubkey)}
                title="Click to copy"
              >
                {displayId.spend_pubkey}
              </div>
            </div>
            <div
              style={{
                padding: 12,
                borderRadius: 6,
                background: "rgba(255, 193, 7, 0.1)",
                border: "1px solid rgba(255, 193, 7, 0.3)",
                marginBottom: 20,
              }}
            >
              <div style={{ fontSize: 12, color: "var(--warning)", fontWeight: 600, marginBottom: 4 }}>
                Important
              </div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                Your Ghost ID is derived from your wallet seed. As long as you have your seed
                backup, you can always recover your Ghost ID. Share your Ghost ID freely — it
                does not reveal your on-chain activity.
              </div>
            </div>
            <button className="btn-primary" onClick={() => navigate("/ghost-locks")} style={{ width: "100%" }}>
              Back to Locks
            </button>
          </>
        )}
      </div>
    </div>
  );
}
