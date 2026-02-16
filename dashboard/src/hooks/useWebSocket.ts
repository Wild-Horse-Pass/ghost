"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import type { NodeEvent } from "@/types/api";

// Dynamically compute WebSocket URL from window location
function getWsUrl(): string {
  if (typeof window !== "undefined") {
    const { protocol, hostname } = window.location;
    const wsProtocol = protocol === "https:" ? "wss:" : "ws:";
    return `${wsProtocol}//${hostname}:8080/ws`;
  }
  const base = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";
  return base.replace(/^http/, "ws") + "/ws";
}

type ConnectionState = "connecting" | "connected" | "disconnected" | "error";

interface UseWebSocketOptions {
  onStatusChange?: (data: NodeEvent & { type: "StatusChange" }) => void;
  onConfigChange?: (data: NodeEvent & { type: "ConfigChange" }) => void;
  onSharesUpdate?: (data: NodeEvent & { type: "SharesUpdate" }) => void;
  onHealthChange?: (data: NodeEvent & { type: "HealthChange" }) => void;
  onMessage?: (event: NodeEvent) => void;
  autoReconnect?: boolean;
  reconnectInterval?: number;
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const {
    onStatusChange,
    onConfigChange,
    onSharesUpdate,
    onHealthChange,
    onMessage,
    autoReconnect = true,
    reconnectInterval = 5000,
  } = options;

  const [connectionState, setConnectionState] = useState<ConnectionState>("disconnected");
  const [lastMessage, setLastMessage] = useState<NodeEvent | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    if (typeof window === "undefined") return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    setConnectionState("connecting");

    try {
      const ws = new WebSocket(getWsUrl());
      wsRef.current = ws;

      ws.onopen = () => {
        if (mountedRef.current) {
          setConnectionState("connected");
        }
      };

      ws.onmessage = (event) => {
        if (!mountedRef.current) return;

        try {
          const data = JSON.parse(event.data) as NodeEvent;
          setLastMessage(data);
          onMessage?.(data);

          switch (data.type) {
            case "StatusChange":
              onStatusChange?.(data as NodeEvent & { type: "StatusChange" });
              break;
            case "ConfigChange":
              onConfigChange?.(data as NodeEvent & { type: "ConfigChange" });
              break;
            case "SharesUpdate":
              onSharesUpdate?.(data as NodeEvent & { type: "SharesUpdate" });
              break;
            case "HealthChange":
              onHealthChange?.(data as NodeEvent & { type: "HealthChange" });
              break;
          }
        } catch (err) {
          console.error("Failed to parse WebSocket message:", err);
        }
      };

      ws.onclose = () => {
        if (!mountedRef.current) return;

        setConnectionState("disconnected");
        wsRef.current = null;

        if (autoReconnect) {
          reconnectTimeoutRef.current = setTimeout(() => {
            if (mountedRef.current) {
              // eslint-disable-next-line react-hooks/immutability
              connect();
            }
          }, reconnectInterval);
        }
      };

      ws.onerror = () => {
        if (mountedRef.current) {
          setConnectionState("error");
        }
      };
    } catch {
      setConnectionState("error");
    }
  }, [onStatusChange, onConfigChange, onSharesUpdate, onHealthChange, onMessage, autoReconnect, reconnectInterval]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    setConnectionState("disconnected");
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      disconnect();
    };
  }, [connect, disconnect]);

  return {
    connectionState,
    lastMessage,
    connect,
    disconnect,
    isConnected: connectionState === "connected",
  };
}

// Hook for subscribing to specific event types with automatic state updates
export function useRealtimeStatus<T>(
  selector: (event: NodeEvent) => T | null,
  initialValue: T
): T {
  const [value, setValue] = useState<T>(initialValue);

  useWebSocket({
    onMessage: (event) => {
      const selected = selector(event);
      if (selected !== null) {
        setValue(selected);
      }
    },
  });

  return value;
}
