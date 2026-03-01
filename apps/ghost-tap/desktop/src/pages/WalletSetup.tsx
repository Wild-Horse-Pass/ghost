import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { createWallet, restoreWallet, setPin } from "../api/commands";
import PinEntry from "../components/PinEntry";
import { useToast } from "../components/ToastProvider";

interface Props {
  onComplete: () => void;
}

export default function WalletSetup({ onComplete }: Props) {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [mode, setMode] = useState<"choose" | "create" | "restore" | "pin" | "pin-confirm">("choose");
  const [mnemonic, setMnemonic] = useState("");
  const [restoreInput, setRestoreInput] = useState("");
  const [wordCount, setWordCount] = useState(12);
  const [error, setError] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [pinFirst, setPinFirst] = useState("");

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
      setMode("pin");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleConfirmMnemonic = () => {
    setMode("pin");
  };

  const handlePinFirst = (pin: string) => {
    setPinFirst(pin);
    setMode("pin-confirm");
  };

  const handlePinConfirm = async (pin: string) => {
    if (pin !== pinFirst) {
      setError("PINs do not match");
      setMode("pin");
      setPinFirst("");
      return;
    }
    try {
      setError("");
      await setPin(pin);
      toast("Wallet created and secured with PIN", "success");
      onComplete();
      navigate("/dashboard");
    } catch (e: unknown) {
      setError(String(e));
      setMode("pin");
      setPinFirst("");
    }
  };

  const handleSkipPin = () => {
    toast("Wallet created (no PIN set)", "info");
    onComplete();
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
            onClick={handleConfirmMnemonic}
            style={{ marginTop: 16, width: "100%" }}
          >
            Continue
          </button>
        </div>
      </div>
    );
  }

  if (mode === "pin") {
    return (
      <div className="page" style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ textAlign: "center" }}>
          <h1>Set a PIN</h1>
          <p style={{ color: "var(--text-secondary)", marginBottom: 32, fontSize: 13 }}>
            Choose a 6-digit PIN to protect your wallet.
          </p>
          {error && <div className="error-text" style={{ marginBottom: 16 }}>{error}</div>}
          <PinEntry onSubmit={handlePinFirst} label="Enter new PIN" />
          <button
            className="btn-secondary"
            onClick={handleSkipPin}
            style={{ marginTop: 24, fontSize: 12 }}
          >
            Skip for now
          </button>
        </div>
      </div>
    );
  }

  if (mode === "pin-confirm") {
    return (
      <div className="page" style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ textAlign: "center" }}>
          <h1>Confirm PIN</h1>
          <p style={{ color: "var(--text-secondary)", marginBottom: 32, fontSize: 13 }}>
            Enter the same PIN again to confirm.
          </p>
          <PinEntry onSubmit={handlePinConfirm} label="Confirm PIN" />
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
