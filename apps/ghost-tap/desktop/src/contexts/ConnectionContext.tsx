import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { getNodeInfo, type NodeInfo } from "../api/commands";

interface ConnectionContextValue {
  /** "light" (GSP) or "fullnode" (Direct RPC) */
  mode: "light" | "fullnode";
  /** Full node info — only meaningful when mode === "fullnode" */
  nodeInfo: NodeInfo | null;
  /** Whether the primary transport is connected */
  isConnected: boolean;
  /** Whether ghost-pay-node is reachable (fullnode mode only) */
  isGhostPayConnected: boolean;
  /** Force an immediate refresh */
  refresh: () => void;
}

const defaultValue: ConnectionContextValue = {
  mode: "light",
  nodeInfo: null,
  isConnected: false,
  isGhostPayConnected: false,
  refresh: () => {},
};

const ConnectionContext = createContext<ConnectionContextValue>(defaultValue);

export function ConnectionProvider({ children }: { children: ReactNode }) {
  const [nodeInfo, setNodeInfo] = useState<NodeInfo | null>(null);

  const isBrowser = !(window as any).__TAURI_INTERNALS__;

  const poll = () => {
    if (isBrowser) return; // Skip Tauri calls in browser preview
    getNodeInfo()
      .then(setNodeInfo)
      .catch(() => {});
  };

  useEffect(() => {
    if (isBrowser) {
      // Browser preview: fake fullnode mode so all nav sections are visible
      setNodeInfo({
        connection_mode: "fullnode",
        ghostd_connected: false,
        ghost_pay_connected: false,
        block_height: 0,
        header_count: 0,
        sync_progress: 0,
        initial_block_download: false,
        network: "signet",
        peer_count: 0,
        node_version: "preview",
      });
      return;
    }
    poll();
    const id = setInterval(poll, 5000);
    return () => clearInterval(id);
  }, []);

  const mode = nodeInfo?.connection_mode === "fullnode" ? "fullnode" : "light";
  const isConnected =
    mode === "fullnode"
      ? nodeInfo?.ghostd_connected ?? false
      : true; // GSP connectivity tracked elsewhere
  const isGhostPayConnected = nodeInfo?.ghost_pay_connected ?? false;

  return (
    <ConnectionContext.Provider
      value={{ mode, nodeInfo, isConnected, isGhostPayConnected, refresh: poll }}
    >
      {children}
    </ConnectionContext.Provider>
  );
}

export function useConnection() {
  return useContext(ConnectionContext);
}
