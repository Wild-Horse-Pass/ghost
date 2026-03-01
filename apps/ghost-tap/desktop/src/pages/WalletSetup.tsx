import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { createWallet, restoreWallet } from "../api/commands";

export default function WalletSetup() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"choose" | "create" | "restore">("choose");
  const [mnemonic, setMnemonic] = useState("");
  const [restoreInput, setRestoreInput] = useState("");
  const [wordCount, setWordCount] = useState(12);
  const [error, setError] = useState("");
  const [confirmed, setConfirmed] = useState(false);

  const handleCreate = async () => {
    try {
      setError("");
      const words = await createWallet(wordCount);
      setMnemonic(words);
      setMode("create");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleRestore = async () => {
    try {
      setError("");
      await restoreWallet(restoreInput.trim());
      navigate("/dashboard");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleConfirm = () => {
    navigate("/dashboard");
  };

  if (mode === "choose") {
    return (
      <div className="page" style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ maxWidth: 440, textAlign: "center" }}>
          <h1 style={{ color: "var(--accent)", fontSize: 28, marginBottom: 8 }}>
            GhostTap
          </h1>
          <p style={{ color: "var(--text-secondary)", marginBottom: 40 }}>
            Merchant Terminal
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <button className="btn-primary" style={{ padding: "14px 0" }} onClick={handleCreate}>
              Create New Wallet
            </button>
            <button
              className="btn-secondary"
              style={{ padding: "14px 0" }}
              onClick={() => setMode("restore")}
            >
              Restore from Mnemonic
            </button>
          </div>
          <div style={{ marginTop: 20 }}>
            <label>Word count</label>
            <select
              value={wordCount}
              onChange={(e) => setWordCount(Number(e.target.value))}
              style={{ maxWidth: 120, margin: "0 auto" }}
            >
              <option value={12}>12 words</option>
              <option value={24}>24 words</option>
            </select>
          </div>
        </div>
      </div>
    );
  }

  if (mode === "create") {
    return (
      <div className="page" style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ maxWidth: 520 }}>
          <h1>Your Recovery Phrase</h1>
          <p style={{ color: "var(--text-secondary)", marginBottom: 20, fontSize: 13 }}>
            Write these words down and store them safely. They are the only way
            to recover your wallet.
          </p>
          <div
            className="card"
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(3, 1fr)",
              gap: 8,
              marginBottom: 24,
            }}
          >
            {mnemonic.split(" ").map((word, i) => (
              <div
                key={i}
                style={{
                  padding: "8px 12px",
                  background: "var(--bg-tertiary)",
                  borderRadius: 6,
                  fontSize: 13,
                }}
              >
                <span style={{ color: "var(--text-muted)", marginRight: 6, fontSize: 11 }}>
                  {i + 1}.
                </span>
                {word}
              </div>
            ))}
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            I have written down my recovery phrase
          </label>
          <button
            className="btn-primary"
            disabled={!confirmed}
            onClick={handleConfirm}
            style={{ marginTop: 16, width: "100%" }}
          >
            Continue to Dashboard
          </button>
        </div>
      </div>
    );
  }

  // Restore mode
  return (
    <div className="page" style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ maxWidth: 520 }}>
        <h1>Restore Wallet</h1>
        <p style={{ color: "var(--text-secondary)", marginBottom: 20, fontSize: 13 }}>
          Enter your 12 or 24 word recovery phrase.
        </p>
        <div className="form-group">
          <textarea
            rows={4}
            placeholder="Enter mnemonic words separated by spaces..."
            value={restoreInput}
            onChange={(e) => setRestoreInput(e.target.value)}
            style={{ resize: "vertical" }}
          />
        </div>
        {error && <div className="error-text">{error}</div>}
        <div style={{ display: "flex", gap: 12 }}>
          <button className="btn-secondary" onClick={() => setMode("choose")}>
            Back
          </button>
          <button
            className="btn-primary"
            onClick={handleRestore}
            disabled={!restoreInput.trim()}
            style={{ flex: 1 }}
          >
            Restore
          </button>
        </div>
      </div>
    </div>
  );
}
