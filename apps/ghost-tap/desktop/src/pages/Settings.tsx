import { useEffect, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import {
  getConnectionStatus,
  setConnectionMode,
  setRpcConfig,
  setGhostPayConfig,
  testConnection,
  lockWallet,
  unlockWallet,
  isLocked,
  syncConnection,
  hasPin,
  setPin,
  verifyPin,
  getMnemonic,
  getNodeWalletInfo,
  nodeEncryptWallet,
  nodeUnlockWallet,
  nodeLockWallet,
  nodeChangePassphrase,
  type ConnectionStatus,
  type ConnectionTestResult,
} from "../api/commands";
import { useConnection } from "../contexts/ConnectionContext";
import { useToast } from "../components/ToastProvider";
import PinEntry from "../components/PinEntry";

export default function Settings() {
  const { toast } = useToast();
  const { refresh: refreshConnection } = useConnection();
  const [status, setStatus] = useState<ConnectionStatus>({ mode: "", connected: false });
  const [mode, setMode] = useState("rpc");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("18232");
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");

  // ghost-pay config
  const [payHost, setPayHost] = useState("127.0.0.1");
  const [payPort, setPayPort] = useState("8800");
  const [paySecret, setPaySecret] = useState("");

  // Connection test
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [testing, setTesting] = useState(false);

  // Wallet security
  const [locked, setLocked] = useState(false);
  const [pinSet, setPinSet] = useState(false);
  const [pinMode, setPinMode] = useState<"none" | "verify" | "new" | "confirm">("none");
  const [pendingPin, setPendingPin] = useState("");
  const [pinError, setPinError] = useState("");

  // Node wallet encryption
  const [nodeWalletInfo, setNodeWalletInfo] = useState<any>(null);
  const [nodeAction, setNodeAction] = useState<"none" | "encrypt" | "unlock" | "change">("none");
  const [nodePass1, setNodePass1] = useState("");
  const [nodePass2, setNodePass2] = useState("");
  const [nodeTimeout, setNodeTimeout] = useState("600");
  const [nodeError, setNodeError] = useState("");

  const refreshNodeWallet = () => {
    if (connectionMode === "fullnode") {
      getNodeWalletInfo()
        .then(setNodeWalletInfo)
        .catch(() => setNodeWalletInfo(null));
    }
  };

  const connectionMode = useConnection().mode;

  useEffect(() => {
    getConnectionStatus().then((s) => {
      setStatus(s);
      setMode(s.mode.includes("GSP") ? "gsp" : "rpc");
    });
    isLocked().then(setLocked);
    hasPin().then(setPinSet);
    refreshNodeWallet();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSaveConnection = async () => {
    try {
      await setConnectionMode(mode);
      if (mode === "rpc") {
        await setRpcConfig(host, parseInt(port), user || undefined, pass || undefined);
        await setGhostPayConfig(payHost, parseInt(payPort), paySecret || undefined);
      }
      await syncConnection();
      const s = await getConnectionStatus();
      setStatus(s);
      refreshConnection();
      toast("Connection settings saved", "success");
    } catch (e: unknown) {
      toast(String(e), "error");
    }
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      // Apply config first so test uses latest values
      if (mode === "rpc") {
        await setConnectionMode("rpc");
        await setRpcConfig(host, parseInt(port), user || undefined, pass || undefined);
        await setGhostPayConfig(payHost, parseInt(payPort), paySecret || undefined);
      }
      const result = await testConnection();
      setTestResult(result);
      refreshConnection();
    } catch (e: unknown) {
      toast(String(e), "error");
    } finally {
      setTesting(false);
    }
  };

  const handleToggleLock = async () => {
    try {
      if (locked) {
        await unlockWallet();
        toast("Wallet unlocked", "info");
      } else {
        await lockWallet();
        toast("Wallet locked", "info");
      }
      setLocked(!locked);
    } catch (e: unknown) {
      toast(String(e), "error");
    }
  };

  const handleChangePinStart = () => {
    setPinError("");
    if (pinSet) {
      setPinMode("verify");
    } else {
      setPinMode("new");
    }
  };

  const handleVerifyOldPin = async (pin: string) => {
    const valid = await verifyPin(pin);
    if (!valid) {
      setPinError("Incorrect PIN");
      return;
    }
    setPinError("");
    setPinMode("new");
  };

  const handleNewPin = (pin: string) => {
    setPendingPin(pin);
    setPinError("");
    setPinMode("confirm");
  };

  const handleConfirmPin = async (pin: string) => {
    if (pin !== pendingPin) {
      setPinError("PINs do not match");
      setPinMode("new");
      setPendingPin("");
      return;
    }
    try {
      await setPin(pin);
      setPinSet(true);
      setPinMode("none");
      setPendingPin("");
      toast("PIN updated", "success");
    } catch (e: unknown) {
      setPinError(String(e));
      setPinMode("new");
      setPendingPin("");
    }
  };

  const handleBackup = async () => {
    try {
      const mnemonic = await getMnemonic();
      const path = await save({
        defaultPath: "ghosttap-backup.txt",
        filters: [{ name: "Text", extensions: ["txt"] }],
      });
      if (path) {
        const content = [
          "GhostTap Wallet Backup",
          "======================",
          "",
          "Recovery Phrase:",
          mnemonic,
          "",
          "WARNING: Anyone with these words can access your funds.",
          "Store this file securely and delete it after writing down the words.",
          "",
          `Backup Date: ${new Date().toISOString()}`,
        ].join("\n");
        await writeTextFile(path, content);
        toast("Wallet backup saved", "success");
      }
    } catch (e: unknown) {
      toast(String(e), "error");
    }
  };

  return (
    <div className="page">
      <h1>Settings</h1>

      {/* Connection Mode */}
      <div className="card" style={{ maxWidth: 500, marginBottom: 24 }}>
        <h2>Connection</h2>
        <div style={{ marginBottom: 16 }}>
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              fontSize: 12,
              color: "var(--text-muted)",
            }}
          >
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: status.connected ? "var(--success)" : "var(--danger)",
              }}
            />
            {status.mode} - {status.connected ? "Connected" : "Disconnected"}
          </span>
        </div>
        <div className="form-group">
          <label>Mode</label>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              className={mode === "rpc" ? "btn-primary btn-small" : "btn-secondary btn-small"}
              onClick={() => setMode("rpc")}
            >
              Full Node
            </button>
            <button
              className={mode === "gsp" ? "btn-primary btn-small" : "btn-secondary btn-small"}
              onClick={() => setMode("gsp")}
            >
              Light (GSP)
            </button>
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
            {mode === "rpc"
              ? "Connect to a local Ghost daemon for full L1 + L2 features."
              : "Connect to a Ghost Service Provider for lightweight L2 access."}
          </div>
        </div>

        {mode === "rpc" && (
          <>
            {/* ghostd RPC */}
            <div style={{ marginBottom: 8, fontSize: 12, fontWeight: 600, color: "var(--text-secondary)" }}>
              Ghost Daemon (ghostd)
            </div>
            <div className="form-group">
              <label>Host</label>
              <input value={host} onChange={(e) => setHost(e.target.value)} />
            </div>
            <div className="form-group">
              <label>Port</label>
              <input value={port} onChange={(e) => setPort(e.target.value)} />
            </div>
            <div className="form-group">
              <label>RPC User</label>
              <input value={user} onChange={(e) => setUser(e.target.value)} placeholder="Optional" />
            </div>
            <div className="form-group">
              <label>RPC Password</label>
              <input
                type="password"
                value={pass}
                onChange={(e) => setPass(e.target.value)}
                placeholder="Optional"
              />
            </div>

            {/* ghost-pay config */}
            <div
              style={{
                marginTop: 20,
                marginBottom: 8,
                paddingTop: 16,
                borderTop: "1px solid var(--border)",
                fontSize: 12,
                fontWeight: 600,
                color: "var(--text-secondary)",
              }}
            >
              Ghost Pay (L2)
            </div>
            <div className="form-group">
              <label>Host</label>
              <input value={payHost} onChange={(e) => setPayHost(e.target.value)} />
            </div>
            <div className="form-group">
              <label>Port</label>
              <input value={payPort} onChange={(e) => setPayPort(e.target.value)} />
            </div>
            <div className="form-group">
              <label>API Secret</label>
              <input
                type="password"
                value={paySecret}
                onChange={(e) => setPaySecret(e.target.value)}
                placeholder="Optional — required for write operations"
              />
            </div>

            {/* Test connection */}
            <button
              className="btn-secondary"
              onClick={handleTestConnection}
              disabled={testing}
              style={{ width: "100%", marginBottom: 8 }}
            >
              {testing ? "Testing..." : "Test Connection"}
            </button>

            {testResult && (
              <div style={{ fontSize: 12, marginBottom: 12 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                  <span
                    style={{
                      width: 6,
                      height: 6,
                      borderRadius: "50%",
                      background: testResult.ghostd_ok ? "var(--success)" : "var(--danger)",
                    }}
                  />
                  <span>ghostd: {testResult.ghostd_ok ? "OK" : testResult.ghostd_error || "Failed"}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span
                    style={{
                      width: 6,
                      height: 6,
                      borderRadius: "50%",
                      background: testResult.ghost_pay_ok ? "var(--success)" : "var(--danger)",
                    }}
                  />
                  <span>Ghost Pay: {testResult.ghost_pay_ok ? "OK" : testResult.ghost_pay_error || "Failed"}</span>
                </div>
              </div>
            )}
          </>
        )}

        <button className="btn-primary" onClick={handleSaveConnection} style={{ width: "100%" }}>
          Save & Connect
        </button>
      </div>

      {/* Wallet Security */}
      <div className="card" style={{ maxWidth: 500, marginBottom: 24 }}>
        <h2>Wallet Security</h2>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <div>
            <div style={{ fontSize: 14 }}>Wallet Lock</div>
            <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
              {locked ? "Wallet is locked" : "Wallet is unlocked"}
            </div>
          </div>
          <button
            className={locked ? "btn-primary" : "btn-danger"}
            onClick={handleToggleLock}
          >
            {locked ? "Unlock" : "Lock"}
          </button>
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div style={{ fontSize: 14 }}>PIN Protection</div>
            <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
              {pinSet ? "PIN is set" : "No PIN set"}
            </div>
          </div>
          {pinMode === "none" ? (
            <button className="btn-secondary" onClick={handleChangePinStart}>
              {pinSet ? "Change PIN" : "Set PIN"}
            </button>
          ) : (
            <button className="btn-secondary" onClick={() => { setPinMode("none"); setPinError(""); }}>
              Cancel
            </button>
          )}
        </div>
        {pinMode !== "none" && (
          <div style={{ marginTop: 20, paddingTop: 16, borderTop: "1px solid var(--border)" }}>
            {pinError && <div className="error-text" style={{ marginBottom: 12, textAlign: "center" }}>{pinError}</div>}
            {pinMode === "verify" && (
              <PinEntry onSubmit={handleVerifyOldPin} label="Enter current PIN" />
            )}
            {pinMode === "new" && (
              <PinEntry onSubmit={handleNewPin} label="Enter new PIN" />
            )}
            {pinMode === "confirm" && (
              <PinEntry onSubmit={handleConfirmPin} label="Confirm new PIN" />
            )}
          </div>
        )}
      </div>

      {/* Node Wallet Encryption — fullnode only */}
      {connectionMode === "fullnode" && (
        <div className="card" style={{ maxWidth: 500, marginBottom: 24 }}>
          <h2>Node Wallet Encryption</h2>
          {nodeWalletInfo ? (
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 16px", fontSize: 13 }}>
                <span style={{ color: "var(--text-muted)" }}>Wallet</span>
                <span className="mono">{nodeWalletInfo.walletname || "default"}</span>
                <span style={{ color: "var(--text-muted)" }}>Keypool Size</span>
                <span>{nodeWalletInfo.keypoolsize ?? "N/A"}</span>
                <span style={{ color: "var(--text-muted)" }}>Encryption</span>
                <span>
                  {nodeWalletInfo.unlocked_until !== undefined
                    ? nodeWalletInfo.unlocked_until === 0
                      ? "Encrypted (Locked)"
                      : `Encrypted (Unlocked until ${new Date(nodeWalletInfo.unlocked_until * 1000).toLocaleString()})`
                    : "Not Encrypted"}
                </span>
              </div>
            </div>
          ) : (
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 16 }}>
              Unable to fetch node wallet info
            </div>
          )}

          {nodeError && <div className="error-text" style={{ marginBottom: 12 }}>{nodeError}</div>}

          {nodeAction === "none" && (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {nodeWalletInfo?.unlocked_until === undefined && (
                <button className="btn-secondary" onClick={() => setNodeAction("encrypt")}>
                  Encrypt Wallet
                </button>
              )}
              {nodeWalletInfo?.unlocked_until !== undefined && nodeWalletInfo.unlocked_until === 0 && (
                <button className="btn-primary" onClick={() => setNodeAction("unlock")}>
                  Unlock
                </button>
              )}
              {nodeWalletInfo?.unlocked_until !== undefined && nodeWalletInfo.unlocked_until > 0 && (
                <button
                  className="btn-danger"
                  onClick={async () => {
                    try {
                      setNodeError("");
                      await nodeLockWallet();
                      toast("Node wallet locked", "success");
                      refreshNodeWallet();
                    } catch (e: unknown) {
                      setNodeError(String(e));
                    }
                  }}
                >
                  Lock
                </button>
              )}
              {nodeWalletInfo?.unlocked_until !== undefined && (
                <button className="btn-secondary" onClick={() => setNodeAction("change")}>
                  Change Passphrase
                </button>
              )}
            </div>
          )}

          {nodeAction === "encrypt" && (
            <div style={{ paddingTop: 16, borderTop: "1px solid var(--border)" }}>
              <div style={{ fontSize: 12, color: "var(--warning)", marginBottom: 12 }}>
                Warning: Encrypting your node wallet will restart the daemon. Make sure you remember the passphrase.
              </div>
              <div className="form-group">
                <label>Passphrase</label>
                <input
                  type="password"
                  value={nodePass1}
                  onChange={(e) => setNodePass1(e.target.value)}
                  placeholder="Enter passphrase..."
                />
              </div>
              <div className="form-group">
                <label>Confirm Passphrase</label>
                <input
                  type="password"
                  value={nodePass2}
                  onChange={(e) => setNodePass2(e.target.value)}
                  placeholder="Confirm passphrase..."
                />
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  className="btn-secondary"
                  onClick={() => { setNodeAction("none"); setNodePass1(""); setNodePass2(""); setNodeError(""); }}
                >
                  Cancel
                </button>
                <button
                  className="btn-primary"
                  disabled={!nodePass1 || nodePass1 !== nodePass2}
                  onClick={async () => {
                    try {
                      setNodeError("");
                      await nodeEncryptWallet(nodePass1);
                      toast("Node wallet encrypted", "success");
                      setNodeAction("none");
                      setNodePass1("");
                      setNodePass2("");
                      refreshNodeWallet();
                    } catch (e: unknown) {
                      setNodeError(String(e));
                    }
                  }}
                  style={{ flex: 1 }}
                >
                  Encrypt
                </button>
              </div>
            </div>
          )}

          {nodeAction === "unlock" && (
            <div style={{ paddingTop: 16, borderTop: "1px solid var(--border)" }}>
              <div className="form-group">
                <label>Passphrase</label>
                <input
                  type="password"
                  value={nodePass1}
                  onChange={(e) => setNodePass1(e.target.value)}
                  placeholder="Enter passphrase..."
                />
              </div>
              <div className="form-group">
                <label>Timeout (seconds)</label>
                <input
                  type="number"
                  value={nodeTimeout}
                  onChange={(e) => setNodeTimeout(e.target.value)}
                  placeholder="600"
                />
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  className="btn-secondary"
                  onClick={() => { setNodeAction("none"); setNodePass1(""); setNodeError(""); }}
                >
                  Cancel
                </button>
                <button
                  className="btn-primary"
                  disabled={!nodePass1}
                  onClick={async () => {
                    try {
                      setNodeError("");
                      await nodeUnlockWallet(nodePass1, parseInt(nodeTimeout) || 600);
                      toast("Node wallet unlocked", "success");
                      setNodeAction("none");
                      setNodePass1("");
                      refreshNodeWallet();
                    } catch (e: unknown) {
                      setNodeError(String(e));
                    }
                  }}
                  style={{ flex: 1 }}
                >
                  Unlock
                </button>
              </div>
            </div>
          )}

          {nodeAction === "change" && (
            <div style={{ paddingTop: 16, borderTop: "1px solid var(--border)" }}>
              <div className="form-group">
                <label>Current Passphrase</label>
                <input
                  type="password"
                  value={nodePass1}
                  onChange={(e) => setNodePass1(e.target.value)}
                  placeholder="Current passphrase..."
                />
              </div>
              <div className="form-group">
                <label>New Passphrase</label>
                <input
                  type="password"
                  value={nodePass2}
                  onChange={(e) => setNodePass2(e.target.value)}
                  placeholder="New passphrase..."
                />
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  className="btn-secondary"
                  onClick={() => { setNodeAction("none"); setNodePass1(""); setNodePass2(""); setNodeError(""); }}
                >
                  Cancel
                </button>
                <button
                  className="btn-primary"
                  disabled={!nodePass1 || !nodePass2}
                  onClick={async () => {
                    try {
                      setNodeError("");
                      await nodeChangePassphrase(nodePass1, nodePass2);
                      toast("Passphrase changed", "success");
                      setNodeAction("none");
                      setNodePass1("");
                      setNodePass2("");
                      refreshNodeWallet();
                    } catch (e: unknown) {
                      setNodeError(String(e));
                    }
                  }}
                  style={{ flex: 1 }}
                >
                  Change Passphrase
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Wallet Backup */}
      <div className="card" style={{ maxWidth: 500 }}>
        <h2>Wallet Backup</h2>
        <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 16 }}>
          Export your recovery phrase to a file. Store it securely — anyone with
          these words can access your funds.
        </p>
        <button className="btn-secondary" onClick={handleBackup} style={{ width: "100%" }}>
          Export Recovery Phrase
        </button>
      </div>
    </div>
  );
}
