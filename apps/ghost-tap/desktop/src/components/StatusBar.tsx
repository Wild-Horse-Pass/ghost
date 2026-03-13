import { useConnection } from "../contexts/ConnectionContext";

export default function StatusBar() {
  const { mode, nodeInfo, isConnected, isGhostPayConnected } = useConnection();

  const isFullNode = mode === "fullnode";
  const syncing = isFullNode && nodeInfo?.initial_block_download;
  const syncPct = nodeInfo ? Math.floor(nodeInfo.sync_progress * 100) : 0;

  return (
    <div
      style={{
        padding: "10px 16px",
        borderTop: "1px solid var(--border)",
        fontSize: 11,
        color: "var(--text-muted)",
      }}
    >
      {/* Connection mode + status */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <span>{isFullNode ? "Full Node" : "Light (GSP)"}</span>
        <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: isConnected ? "var(--success)" : "var(--danger)",
            }}
          />
          {isConnected ? "Connected" : "Disconnected"}
        </span>
      </div>

      {/* Full node details */}
      {isFullNode && nodeInfo && nodeInfo.ghostd_connected && (
        <div style={{ marginTop: 6, lineHeight: 1.6 }}>
          {/* Block height */}
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span>Block</span>
            <span className="mono">{nodeInfo.block_height.toLocaleString()}</span>
          </div>

          {/* Peers */}
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span>Peers</span>
            <span>{nodeInfo.peer_count}</span>
          </div>

          {/* Network */}
          {nodeInfo.network && (
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span>Network</span>
              <span>{nodeInfo.network}</span>
            </div>
          )}

          {/* Ghost Pay status */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>Ghost Pay</span>
            <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <span
                style={{
                  width: 5,
                  height: 5,
                  borderRadius: "50%",
                  background: isGhostPayConnected ? "var(--success)" : "var(--danger)",
                }}
              />
              {isGhostPayConnected ? "Online" : "Offline"}
            </span>
          </div>

          {/* Sync progress bar during IBD */}
          {syncing && (
            <div style={{ marginTop: 4 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 2 }}>
                <span>Syncing</span>
                <span>{syncPct}%</span>
              </div>
              <div
                style={{
                  height: 3,
                  background: "var(--border)",
                  borderRadius: 2,
                  overflow: "hidden",
                }}
              >
                <div
                  style={{
                    height: "100%",
                    width: `${syncPct}%`,
                    background: "var(--accent)",
                    borderRadius: 2,
                    transition: "width 0.3s ease",
                  }}
                />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
