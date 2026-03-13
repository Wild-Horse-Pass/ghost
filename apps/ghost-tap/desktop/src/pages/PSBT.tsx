import { useState } from "react";
import {
  decodePsbt,
  analyzePsbt,
  signPsbt,
  combinePsbts,
  finalizePsbt,
  broadcastPsbt,
} from "../api/commands";
import { useConnection } from "../contexts/ConnectionContext";

type Step = "load" | "inspect" | "sign" | "combine" | "finalize" | "broadcast" | "done";

export default function PSBT() {
  const { mode } = useConnection();
  const [psbtInput, setPsbtInput] = useState("");
  const [step, setStep] = useState<Step>("load");
  const [decoded, setDecoded] = useState<string>("");
  const [analysis, setAnalysis] = useState<string>("");
  const [signedPsbt, setSignedPsbt] = useState("");
  const [finalizedPsbt, setFinalizedPsbt] = useState("");
  const [txid, setTxid] = useState("");
  const [error, setError] = useState("");

  // Combine mode
  const [combineMode, setCombineMode] = useState(false);
  const [psbtA, setPsbtA] = useState("");
  const [psbtB, setPsbtB] = useState("");
  const [combinedResult, setCombinedResult] = useState("");

  const handleDecode = async () => {
    try {
      setError("");
      const result = await decodePsbt(psbtInput);
      setDecoded(JSON.stringify(result, null, 2));
      setStep("inspect");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleAnalyze = async () => {
    try {
      setError("");
      const result = await analyzePsbt(psbtInput);
      setAnalysis(JSON.stringify(result, null, 2));
      setStep("inspect");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleSign = async () => {
    try {
      setError("");
      const result = await signPsbt(psbtInput);
      const signed = typeof result === "string" ? result : result.psbt || JSON.stringify(result);
      setSignedPsbt(signed);
      setPsbtInput(signed);
      setStep("sign");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleCombine = async () => {
    try {
      setError("");
      const result = await combinePsbts([psbtA, psbtB]);
      setCombinedResult(result);
      setPsbtInput(result);
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleFinalize = async () => {
    try {
      setError("");
      const result = await finalizePsbt(psbtInput);
      const hex = typeof result === "string" ? result : result.hex || JSON.stringify(result);
      setFinalizedPsbt(hex);
      setStep("finalize");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleBroadcast = async () => {
    try {
      setError("");
      const result = await broadcastPsbt(finalizedPsbt || psbtInput);
      setTxid(result);
      setStep("done");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleReset = () => {
    setPsbtInput("");
    setStep("load");
    setDecoded("");
    setAnalysis("");
    setSignedPsbt("");
    setFinalizedPsbt("");
    setTxid("");
    setError("");
    setCombineMode(false);
    setPsbtA("");
    setPsbtB("");
    setCombinedResult("");
  };

  if (mode !== "fullnode") {
    return (
      <div className="page">
        <h1>PSBT</h1>
        <div className="card" style={{ maxWidth: 500 }}>
          <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
            PSBT operations require a full node connection. Switch to Full Node mode in Settings.
          </p>
        </div>
      </div>
    );
  }

  if (step === "done") {
    return (
      <div className="page">
        <h1>Transaction Broadcast</h1>
        <div className="card" style={{ maxWidth: 600 }}>
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
            New PSBT
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ marginBottom: 0 }}>PSBT</h1>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            className={!combineMode ? "btn-primary btn-small" : "btn-secondary btn-small"}
            onClick={() => setCombineMode(false)}
          >
            Single
          </button>
          <button
            className={combineMode ? "btn-primary btn-small" : "btn-secondary btn-small"}
            onClick={() => setCombineMode(true)}
          >
            Combine
          </button>
          {step !== "load" && (
            <button className="btn-secondary btn-small" onClick={handleReset}>
              Reset
            </button>
          )}
        </div>
      </div>

      {error && <div className="error-text" style={{ marginBottom: 16 }}>{error}</div>}

      {combineMode ? (
        <div className="card" style={{ maxWidth: 600, marginBottom: 24 }}>
          <h2>Combine PSBTs</h2>
          <div className="form-group">
            <label>PSBT A (base64)</label>
            <textarea
              value={psbtA}
              onChange={(e) => setPsbtA(e.target.value)}
              placeholder="First PSBT..."
              rows={4}
              className="mono"
              style={{ resize: "vertical", fontSize: 12 }}
            />
          </div>
          <div className="form-group">
            <label>PSBT B (base64)</label>
            <textarea
              value={psbtB}
              onChange={(e) => setPsbtB(e.target.value)}
              placeholder="Second PSBT..."
              rows={4}
              className="mono"
              style={{ resize: "vertical", fontSize: 12 }}
            />
          </div>
          <button
            className="btn-primary"
            onClick={handleCombine}
            disabled={!psbtA || !psbtB}
            style={{ width: "100%" }}
          >
            Combine
          </button>
          {combinedResult && (
            <div style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid var(--border)" }}>
              <label>Combined PSBT</label>
              <div
                className="mono"
                style={{
                  fontSize: 11,
                  wordBreak: "break-all",
                  background: "var(--bg-tertiary)",
                  padding: 12,
                  borderRadius: 6,
                  border: "1px solid var(--border)",
                  maxHeight: 200,
                  overflow: "auto",
                  cursor: "pointer",
                }}
                onClick={() => navigator.clipboard.writeText(combinedResult)}
                title="Click to copy"
              >
                {combinedResult}
              </div>
            </div>
          )}
        </div>
      ) : (
        <>
          {/* Load PSBT */}
          <div className="card" style={{ maxWidth: 600, marginBottom: 24 }}>
            <h2>Load PSBT</h2>
            <div className="form-group">
              <label>PSBT (base64)</label>
              <textarea
                value={psbtInput}
                onChange={(e) => setPsbtInput(e.target.value)}
                placeholder="Paste base64-encoded PSBT..."
                rows={6}
                className="mono"
                style={{ resize: "vertical", fontSize: 12 }}
              />
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="btn-secondary"
                onClick={handleDecode}
                disabled={!psbtInput}
                style={{ flex: 1 }}
              >
                Decode
              </button>
              <button
                className="btn-secondary"
                onClick={handleAnalyze}
                disabled={!psbtInput}
                style={{ flex: 1 }}
              >
                Analyze
              </button>
              <button
                className="btn-primary"
                onClick={handleSign}
                disabled={!psbtInput}
                style={{ flex: 1 }}
              >
                Sign
              </button>
            </div>
          </div>

          {/* Decoded / Analysis output */}
          {(decoded || analysis) && (
            <div className="card" style={{ maxWidth: 600, marginBottom: 24 }}>
              {decoded && (
                <div className="form-group">
                  <label>Decoded</label>
                  <pre
                    className="mono"
                    style={{
                      fontSize: 11,
                      background: "var(--bg-tertiary)",
                      padding: 12,
                      borderRadius: 6,
                      border: "1px solid var(--border)",
                      maxHeight: 300,
                      overflow: "auto",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                    }}
                  >
                    {decoded}
                  </pre>
                </div>
              )}
              {analysis && (
                <div className="form-group">
                  <label>Analysis</label>
                  <pre
                    className="mono"
                    style={{
                      fontSize: 11,
                      background: "var(--bg-tertiary)",
                      padding: 12,
                      borderRadius: 6,
                      border: "1px solid var(--border)",
                      maxHeight: 300,
                      overflow: "auto",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                    }}
                  >
                    {analysis}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* Signed result */}
          {signedPsbt && (
            <div className="card" style={{ maxWidth: 600, marginBottom: 24 }}>
              <h2>Signed PSBT</h2>
              <div
                className="mono"
                style={{
                  fontSize: 11,
                  wordBreak: "break-all",
                  background: "var(--bg-tertiary)",
                  padding: 12,
                  borderRadius: 6,
                  border: "1px solid var(--border)",
                  maxHeight: 200,
                  overflow: "auto",
                  marginBottom: 16,
                  cursor: "pointer",
                }}
                onClick={() => navigator.clipboard.writeText(signedPsbt)}
                title="Click to copy"
              >
                {signedPsbt}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn-primary" onClick={handleFinalize} style={{ flex: 1 }}>
                  Finalize
                </button>
              </div>
            </div>
          )}

          {/* Finalized — Broadcast */}
          {finalizedPsbt && (
            <div className="card" style={{ maxWidth: 600, marginBottom: 24 }}>
              <h2>Finalized Transaction</h2>
              <div
                className="mono"
                style={{
                  fontSize: 11,
                  wordBreak: "break-all",
                  background: "var(--bg-tertiary)",
                  padding: 12,
                  borderRadius: 6,
                  border: "1px solid var(--border)",
                  maxHeight: 200,
                  overflow: "auto",
                  marginBottom: 16,
                }}
              >
                {finalizedPsbt}
              </div>
              <button className="btn-primary" onClick={handleBroadcast} style={{ width: "100%" }}>
                Broadcast Transaction
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
