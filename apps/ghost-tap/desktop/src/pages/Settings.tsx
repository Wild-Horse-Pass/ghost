import { useEffect, useState } from "react";
import {
  getConnectionStatus,
  setConnectionMode,
  setRpcConfig,
  lockWallet,
  unlockWallet,
  isLocked,
  syncConnection,
  type ConnectionStatus,
} from "../api/commands";

export default function Settings() {
  const [status, setStatus] = useState<ConnectionStatus>({ mode: "", connected: false });
  const [mode, setMode] = useState("rpc");
  const [host, setHost] = useState("127.0.0.1");
  const [port, setPort] = useState("18232");
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [locked, setLocked] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    getConnectionStatus().then((s) => {
      setStatus(s);
      setMode(s.mode.includes("GSP") ? "gsp" : "rpc");
    });
    isLocked().then(setLocked);
  }, []);

  const handleSaveConnection = async () => {
    try {
      setError("");
      setSuccess("");
      await setConnectionMode(mode);
      if (mode === "rpc") {
        await setRpcConfig(host, parseInt(port), user || undefined, pass || undefined);
      }
      await syncConnection();
      const s = await getConnectionStatus();
      setStatus(s);
      setSuccess("Connection settings saved");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleToggleLock = async () => {
    try {
      setError("");
      if (locked) {
        await unlockWallet();
      } else {
        await lockWallet();
      }
      setLocked(!locked);
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  return (
    <div className="page">
      <h1>Settings</h1>

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
              Direct RPC
            </button>
            <button
              className={mode === "gsp" ? "btn-primary btn-small" : "btn-secondary btn-small"}
              onClick={() => setMode("gsp")}
            >
              GSP
            </button>
          </div>
        </div>
        {mode === "rpc" && (
          <>
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
          </>
        )}
        {error && <div className="error-text" style={{ marginBottom: 12 }}>{error}</div>}
        {success && <div className="success-text" style={{ marginBottom: 12 }}>{success}</div>}
        <button className="btn-primary" onClick={handleSaveConnection} style={{ width: "100%" }}>
          Save & Connect
        </button>
      </div>

      <div className="card" style={{ maxWidth: 500 }}>
        <h2>Wallet Security</h2>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
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
      </div>
    </div>
  );
}
