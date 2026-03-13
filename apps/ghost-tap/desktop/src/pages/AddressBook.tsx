import { useEffect, useState, useCallback } from "react";
import {
  listReceivedAddresses,
  setAddressLabel,
  formatGhost,
  type AddressEntry,
} from "../api/commands";
import { useConnection } from "../contexts/ConnectionContext";
import { useToast } from "../components/ToastProvider";

type Tab = "receive" | "send";

const REFRESH_INTERVAL = 30_000;

export default function AddressBook() {
  const { mode } = useConnection();
  const { toast } = useToast();
  const [tab, setTab] = useState<Tab>("receive");
  const [entries, setEntries] = useState<AddressEntry[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [newAddress, setNewAddress] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const result = await listReceivedAddresses();
      setEntries(result);
    } catch (e: unknown) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    if (mode !== "fullnode") return;
    refresh();
    const id = setInterval(refresh, REFRESH_INTERVAL);
    return () => clearInterval(id);
  }, [mode, refresh]);

  const handleCopy = (address: string) => {
    navigator.clipboard.writeText(address);
    toast("Address copied to clipboard", "success");
  };

  const handleAddLabel = async () => {
    try {
      setError("");
      await setAddressLabel(newAddress, newLabel);
      setNewAddress("");
      setNewLabel("");
      setShowForm(false);
      refresh();
      toast("Label saved", "success");
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  if (mode !== "fullnode") {
    return (
      <div className="page">
        <h1>Address Book</h1>
        <div className="card" style={{ maxWidth: 500 }}>
          <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
            Address Book requires a full node connection. Switch to Full Node mode in Settings.
          </p>
        </div>
      </div>
    );
  }

  const receiveEntries = entries.filter((e) => e.amount > 0 || e.label);
  const sendEntries = entries.filter((e) => e.label && e.amount === 0);

  const displayEntries = tab === "receive" ? receiveEntries : sendEntries;

  return (
    <div className="page">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ marginBottom: 0 }}>Address Book</h1>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            className={tab === "receive" ? "btn-primary btn-small" : "btn-secondary btn-small"}
            onClick={() => setTab("receive")}
          >
            Receive
          </button>
          <button
            className={tab === "send" ? "btn-primary btn-small" : "btn-secondary btn-small"}
            onClick={() => setTab("send")}
          >
            Send
          </button>
          <button className="btn-secondary btn-small" onClick={() => setShowForm(!showForm)}>
            {showForm ? "Cancel" : "Add Label"}
          </button>
        </div>
      </div>

      {error && <div className="error-text" style={{ marginBottom: 16 }}>{error}</div>}

      {showForm && (
        <div className="card" style={{ maxWidth: 500, marginBottom: 24 }}>
          <h2>Add Address Label</h2>
          <div className="form-group">
            <label>Address</label>
            <input
              value={newAddress}
              onChange={(e) => setNewAddress(e.target.value)}
              placeholder="Ghost address..."
              className="mono"
            />
          </div>
          <div className="form-group">
            <label>Label</label>
            <input
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
              placeholder="Label for this address..."
            />
          </div>
          <button
            className="btn-primary"
            onClick={handleAddLabel}
            disabled={!newAddress || !newLabel}
            style={{ width: "100%" }}
          >
            Save Label
          </button>
        </div>
      )}

      <div className="card" style={{ padding: 0 }}>
        <table>
          <thead>
            <tr>
              <th>Label</th>
              <th>Address</th>
              <th>Amount</th>
              <th>Confirmations</th>
            </tr>
          </thead>
          <tbody>
            {displayEntries.length === 0 ? (
              <tr>
                <td colSpan={4} style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                  No addresses found
                </td>
              </tr>
            ) : (
              displayEntries.map((entry) => (
                <tr key={entry.address}>
                  <td style={{ fontSize: 13 }}>{entry.label || "-"}</td>
                  <td
                    className="mono truncate"
                    style={{ maxWidth: 180, cursor: "pointer", color: "var(--accent)" }}
                    onClick={() => handleCopy(entry.address)}
                    title={entry.address}
                  >
                    {entry.address}
                  </td>
                  <td>{formatGhost(entry.amount)} GHOST</td>
                  <td>{entry.confirmations}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
