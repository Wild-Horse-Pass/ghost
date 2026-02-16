"use client";

import { useWebSocket } from "@/hooks/useWebSocket";

export function ConnectionStatus() {
  const { connectionState, isConnected } = useWebSocket();

  const statusConfig = {
    connected: {
      color: "bg-green-500",
      label: "Live",
    },
    connecting: {
      color: "bg-yellow-500",
      label: "Connecting",
    },
    disconnected: {
      color: "bg-gray-500",
      label: "Offline",
    },
    error: {
      color: "bg-red-500",
      label: "Error",
    },
  };

  const config = statusConfig[connectionState];

  return (
    <div className="flex items-center gap-2">
      <span className="relative flex h-2 w-2">
        {isConnected && (
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
        )}
        <span className={`relative inline-flex rounded-full h-2 w-2 ${config.color}`}></span>
      </span>
      <span className="text-xs text-gray-500 hidden sm:inline">{config.label}</span>
    </div>
  );
}
