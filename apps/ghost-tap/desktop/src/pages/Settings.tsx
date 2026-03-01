import { useEffect, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import {
  getConnectionStatus,
  setConnectionMode,
  setRpcConfig,
  lockWallet,
  unlockWallet,
  isLocked,
  syncConnection,
  hasPin,
  setPin,
  verifyPin,
  getMnemonic,
  type ConnectionStatus,
} from "../api/commands";
import { useToast } from "../components/ToastProvider";
import PinEntry from "../components/PinEntry";

export default function Settings() {
  const { toast } = useToast();
  const [status, setStatus] = useState<ConnectionStatus>({ mode: "", connected: false });
  const [mode, setMode] = useState("rpc");
  const [host, setHost] = useState("127.0.0.1");
  const [port, setPort] = useState("18232");
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [locked, setLocked] = useState(false);
  const [pinSet, setPinSet] = useState(false);
  const [pinMode, setPinMode] = useState<"none" | "verify" | "new" | "confirm">("none");
  const [pendingPin, setPendingPin] = useState("");
  const [pinError, setPinError] = useState("");

  useEffect(() => {
    getConnectionStatus().then((s) => {
      setStatus(s);
      setMode(s.mode.includes("GSP") ? "gsp" : "rpc");
    });
    isLocked().then(setLocked);
    hasPin().then(setPinSet);
  }, []);

  const handleSaveConnection = async () => {
    try {
      await setConnectionMode(mode);
      if (mode === "rpc") {
        await setRpcConfig(host, parseInt(port), user || undefined, pass || undefined);
      }
      await syncConnection();
      const s = await getConnectionStatus();
      setStatus(s);
      toast("Connection settings saved", "success");
    } catch (e: unknown) {
      toast(String(e), "error");
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
        <button className="btn-primary" onClick={handleSaveConnection} style={{ width: "100%" }}>
          Save & Connect
        </button>
      </div>

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
