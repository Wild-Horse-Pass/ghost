import { useState } from "react";
import { signMessage, verifyMessage } from "../api/commands";
import { useConnection } from "../contexts/ConnectionContext";

type Tab = "sign" | "verify";

export default function SignVerify() {
  const { mode } = useConnection();
  const [tab, setTab] = useState<Tab>("sign");

  // Sign state
  const [signAddress, setSignAddress] = useState("");
  const [signMsg, setSignMsg] = useState("");
  const [signature, setSignature] = useState("");
  const [signError, setSignError] = useState("");

  // Verify state
  const [verifyAddress, setVerifyAddress] = useState("");
  const [verifySig, setVerifySig] = useState("");
  const [verifyMsg, setVerifyMsg] = useState("");
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);
  const [verifyError, setVerifyError] = useState("");

  const handleSign = async () => {
    try {
      setSignError("");
      setSignature("");
      const sig = await signMessage(signAddress, signMsg);
      setSignature(sig);
    } catch (e: unknown) {
      setSignError(String(e));
    }
  };

  const handleVerify = async () => {
    try {
      setVerifyError("");
      setVerifyResult(null);
      const valid = await verifyMessage(verifyAddress, verifySig, verifyMsg);
      setVerifyResult(valid);
    } catch (e: unknown) {
      setVerifyError(String(e));
    }
  };

  if (mode !== "fullnode") {
    return (
      <div className="page">
        <h1>Sign / Verify</h1>
        <div className="card" style={{ maxWidth: 500 }}>
          <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
            Message signing and verification requires a full node connection. Switch to Full Node mode in Settings.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ marginBottom: 0 }}>Sign / Verify</h1>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            className={tab === "sign" ? "btn-primary btn-small" : "btn-secondary btn-small"}
            onClick={() => setTab("sign")}
          >
            Sign
          </button>
          <button
            className={tab === "verify" ? "btn-primary btn-small" : "btn-secondary btn-small"}
            onClick={() => setTab("verify")}
          >
            Verify
          </button>
        </div>
      </div>

      {tab === "sign" && (
        <div className="card" style={{ maxWidth: 500 }}>
          <h2>Sign Message</h2>
          <div className="form-group">
            <label>Address</label>
            <input
              value={signAddress}
              onChange={(e) => setSignAddress(e.target.value)}
              placeholder="Ghost address to sign with..."
              className="mono"
            />
          </div>
          <div className="form-group">
            <label>Message</label>
            <textarea
              value={signMsg}
              onChange={(e) => setSignMsg(e.target.value)}
              placeholder="Message to sign..."
              rows={4}
              style={{ resize: "vertical" }}
            />
          </div>
          {signError && <div className="error-text" style={{ marginBottom: 12 }}>{signError}</div>}
          <button
            className="btn-primary"
            onClick={handleSign}
            disabled={!signAddress || !signMsg}
            style={{ width: "100%", marginBottom: signature ? 16 : 0 }}
          >
            Sign Message
          </button>
          {signature && (
            <div style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid var(--border)" }}>
              <label>Signature</label>
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
                onClick={() => navigator.clipboard.writeText(signature)}
                title="Click to copy"
              >
                {signature}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                Click to copy signature
              </div>
            </div>
          )}
        </div>
      )}

      {tab === "verify" && (
        <div className="card" style={{ maxWidth: 500 }}>
          <h2>Verify Message</h2>
          <div className="form-group">
            <label>Address</label>
            <input
              value={verifyAddress}
              onChange={(e) => setVerifyAddress(e.target.value)}
              placeholder="Signer's Ghost address..."
              className="mono"
            />
          </div>
          <div className="form-group">
            <label>Signature</label>
            <input
              value={verifySig}
              onChange={(e) => setVerifySig(e.target.value)}
              placeholder="Base64 signature..."
              className="mono"
            />
          </div>
          <div className="form-group">
            <label>Message</label>
            <textarea
              value={verifyMsg}
              onChange={(e) => setVerifyMsg(e.target.value)}
              placeholder="Original message..."
              rows={4}
              style={{ resize: "vertical" }}
            />
          </div>
          {verifyError && <div className="error-text" style={{ marginBottom: 12 }}>{verifyError}</div>}
          <button
            className="btn-primary"
            onClick={handleVerify}
            disabled={!verifyAddress || !verifySig || !verifyMsg}
            style={{ width: "100%" }}
          >
            Verify Message
          </button>
          {verifyResult !== null && (
            <div
              style={{
                marginTop: 16,
                padding: 12,
                borderRadius: 6,
                textAlign: "center",
                fontSize: 14,
                fontWeight: 600,
                background: verifyResult
                  ? "rgba(40, 167, 69, 0.15)"
                  : "rgba(220, 53, 69, 0.15)",
                color: verifyResult ? "var(--success)" : "var(--danger)",
              }}
            >
              {verifyResult ? "Valid Signature" : "Invalid Signature"}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
