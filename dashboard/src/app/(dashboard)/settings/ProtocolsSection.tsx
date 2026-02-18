"use client";

import { Badge } from "@/components/ui/Badge";
import {
  useConfig,
  useSetBitcoinPure,
  useGhostPayStatus,
} from "@/hooks/queries";
import { useHazeStatus } from "@/hooks/queries/useHazeQueries";
import { useShroudStatus } from "@/hooks/queries/useShroudQueries";
import { useToast } from "@/components/ui/Toast";
import { SettingsSection, ToggleRow } from "./shared";

function StatusRow({ label, description, badge }: { label: string; description: string; badge: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span className="text-gray-100 font-medium">{label}</span>
          {badge}
        </div>
        <div className="text-sm text-gray-400">{description}</div>
      </div>
    </div>
  );
}

export function ProtocolsSection() {
  const { data: config } = useConfig();
  const { data: ghostPayStatus } = useGhostPayStatus();
  const { data: hazeStatus } = useHazeStatus();
  const { data: shroudStatus } = useShroudStatus();
  const setBitcoinPure = useSetBitcoinPure();
  const { success, error } = useToast();

  const handleGhostReaperToggle = async (enabled: boolean) => {
    try {
      await setBitcoinPure.mutateAsync(enabled);
      success(
        "Protocol Updated",
        enabled
          ? "Ghost Reaper enabled — mempool filtering active"
          : "Ghost Reaper disabled — filtering inactive"
      );
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const hazeMode = hazeStatus?.mode ?? "unknown";
  const hazeModeLabel = hazeMode === "hazed" ? "Hazed" : hazeMode === "full_archive" ? "Full Archive" : hazeMode === "standard" ? "Standard" : "Unknown";

  return (
    <SettingsSection title="Protocol Settings" subtitle="Privacy and filtering protocols running on your node">
      <ToggleRow
        label="Ghost Reaper"
        description="Reject dead code transactions from your mempool. Specifically targets non-financial witness data (inscriptions, drop stuffing, fake pubkeys)."
        enabled={config?.bitcoin_pure ?? false}
        onChange={handleGhostReaperToggle}
        disabled={setBitcoinPure.isPending}
        badge={
          config?.bitcoin_pure ? (
            <Badge variant="success">+2 Shares</Badge>
          ) : null
        }
      />

      <StatusRow
        label="Wraith Protocol"
        description="CoinJoin mixing participation. Requires ghost-pay-node running."
        badge={
          ghostPayStatus?.wraith_enabled ? (
            <Badge variant="success">Active</Badge>
          ) : ghostPayStatus?.l2_height ? (
            <Badge variant="default">Available</Badge>
          ) : (
            <Badge variant="warning">Not Running</Badge>
          )
        }
      />

      <StatusRow
        label="Ghost Haze"
        description="Storage privacy layer — requires Ghost Core with Haze module."
        badge={
          hazeStatus ? (
            <Badge variant={hazeMode === "hazed" ? "success" : hazeMode === "full_archive" ? "info" : "default"}>
              {hazeModeLabel}
            </Badge>
          ) : (
            <Badge variant="default">Unknown</Badge>
          )
        }
      />

      <StatusRow
        label="Ghost Shroud"
        description="Transaction relay privacy — random delays before relaying transactions to peers."
        badge={
          shroudStatus ? (
            <Badge variant={shroudStatus.enabled ? "success" : "default"}>
              {shroudStatus.enabled ? "Enabled" : "Disabled"}
            </Badge>
          ) : (
            <Badge variant="default">Unknown</Badge>
          )
        }
      />
    </SettingsSection>
  );
}
