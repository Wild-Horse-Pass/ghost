"use client";

import { Badge } from "@/components/ui/Badge";
import {
  useNodeStatus,
  useConfig,
  useSetGhostMode,
  useSetArchiveMode,
  useSetBitcoinPure,
  useSetPublicMining,
  useGhostPayStatus,
} from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { SettingsSection, ToggleRow } from "./shared";

export function ModesSection() {
  const { data: status } = useNodeStatus();
  const { data: config } = useConfig();
  const { data: ghostPayStatus } = useGhostPayStatus();

  const setGhostMode = useSetGhostMode();
  const setArchiveMode = useSetArchiveMode();
  const setBitcoinPure = useSetBitcoinPure();
  const setPublicMining = useSetPublicMining();

  const { success, error } = useToast();

  const handleGhostModeToggle = async (enabled: boolean) => {
    try {
      await setGhostMode.mutateAsync(enabled);
      success("Mode Changed", `Ghost Mode ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleArchiveModeToggle = async (enabled: boolean) => {
    try {
      await setArchiveMode.mutateAsync(enabled);
      success("Mode Changed", `Archive Mode ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleGhostReaperToggle = async (enabled: boolean) => {
    try {
      await setBitcoinPure.mutateAsync(enabled);
      success(
        "Mode Changed",
        enabled
          ? "Ghost Reaper enabled — mempool filtering active"
          : "Ghost Reaper disabled — filtering inactive"
      );
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <SettingsSection title="Operating Modes" subtitle="Configure node operation modes">
      <ToggleRow
        label="Ghost Mode"
        description="Enable Ghost protocol features and L2 participation"
        enabled={status?.ghost_mode ?? false}
        onChange={handleGhostModeToggle}
        disabled={setGhostMode.isPending}
        badge={
          status?.ghost_mode ? (
            <Badge variant="success">Active</Badge>
          ) : (
            <Badge variant="default">Inactive</Badge>
          )
        }
      />

      <ToggleRow
        label="Archive Mode"
        description="Store full blockchain history (+5 shares bonus)"
        enabled={status?.archive_mode ?? false}
        onChange={handleArchiveModeToggle}
        disabled={setArchiveMode.isPending}
        badge={
          status?.archive_mode ? (
            <Badge variant="success">+5 Shares</Badge>
          ) : null
        }
      />

      <ToggleRow
        label="Ghost Pay"
        description="Enable L2 payment network participation - requires ghost-pay-node running"
        enabled={ghostPayStatus?.l2_height ? true : false}
        onChange={() => {}}
        disabled
        badge={
          ghostPayStatus?.l2_height ? (
            <Badge variant="success">Active (L2: {ghostPayStatus.l2_height})</Badge>
          ) : (
            <Badge variant="warning">Not Running</Badge>
          )
        }
      />

      <ToggleRow
        label="Public Mining"
        description="Accept mining connections from public miners (+3 shares bonus)"
        enabled={status?.public_mining ?? false}
        onChange={(enabled) => setPublicMining.mutate(enabled)}
        disabled={setPublicMining.isPending}
        badge={
          status?.public_mining ? (
            <Badge variant="success">+3 Shares</Badge>
          ) : null
        }
      />

      <ToggleRow
        label="Ghost Reaper"
        description="Reject transactions with dead code in witness scripts. Filters inscriptions, drop stuffing, and other non-financial data from your mempool. (+2 shares)"
        enabled={config?.bitcoin_pure ?? false}
        onChange={handleGhostReaperToggle}
        disabled={setBitcoinPure.isPending}
        badge={
          config?.bitcoin_pure ? (
            <Badge variant="success">+2 Shares</Badge>
          ) : null
        }
      />
    </SettingsSection>
  );
}
