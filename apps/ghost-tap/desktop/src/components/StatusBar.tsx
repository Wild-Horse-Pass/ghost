import { useEffect, useState } from "react";
import { getConnectionStatus, type ConnectionStatus } from "../api/commands";

export default function StatusBar() {
  const [status, setStatus] = useState<ConnectionStatus>({
    mode: "Direct RPC",
    connected: false,
  });

  useEffect(() => {
    const poll = () => {
      getConnectionStatus().then(setStatus).catch(() => {});
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => clearInterval(id);
  }, []);

  return (
    <div
      style={{
        padding: "10px 16px",
        borderTop: "1px solid var(--border)",
        fontSize: 11,
        color: "var(--text-muted)",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
      }}
    >
      <span>{status.mode}</span>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
        }}
      >
        <span
          style={{
            width: 6,
            height: 6,
            borderRadius: "50%",
            background: status.connected ? "var(--success)" : "var(--danger)",
          }}
        />
        {status.connected ? "Connected" : "Disconnected"}
      </span>
    </div>
  );
}
