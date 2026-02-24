"use client";

import { Badge } from "@/components/ui/Badge";
import {
  useNodeStatus,
  useConfig,
  useSetGhostMode,
  useGhostPayStatus,
} from "@/hooks/queries";
import { useHazeStatus } from "@/hooks/queries/useHazeQueries";
import { useShroudStatus } from "@/hooks/queries/useShroudQueries";
import { useToast } from "@/components/ui/Toast";
import { Card, CardHeader } from "@/components/ui/Card";
import { ToggleRow, StatusRow } from "../shared";

export default function PrivacySettingsPage() {
  const { data: status } = useNodeStatus();
  const { data: config } = useConfig();
  const { data: ghostPayStatus } = useGhostPayStatus();
  const { data: hazeStatus } = useHazeStatus();
  const { data: shroudStatus } = useShroudStatus();

  const setGhostMode = useSetGhostMode();
  const { success, error } = useToast();

  const handleGhostModeToggle = async (enabled: boolean) => {
    try {
      await setGhostMode.mutateAsync(enabled);
      success("Mode Changed", `Ghost Mode ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const hazeMode = hazeStatus?.mode ?? "unknown";
  const hazeModeLabel = hazeMode === "hazed" ? "Hazed" : hazeMode === "full_archive" ? "Full Archive" : hazeMode === "standard" ? "Standard" : "Unknown";

  const gpRunning = ghostPayStatus && ghostPayStatus.sync_state !== "disabled" && ghostPayStatus.sync_state !== "unavailable";

  return (
    <Card className="border-red-600/30">
      <CardHeader
        title={<span className="text-red-400">Privacy &amp; Anonymity</span>}
        subtitle="Control your node's privacy features"
      />
      <div className="space-y-4">
        <ToggleRow
          label="Ghost Mode"
          description="Isolates your node — stops relaying transactions and messages to peers (except block propagation)"
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

        <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <span className="text-gray-100 font-medium">Tor Mode</span>
              {status?.tor_mode ? (
                <Badge variant="success">Active</Badge>
              ) : (
                <Badge variant="default">Disabled</Badge>
              )}
            </div>
            <div className="text-sm text-gray-400">
              Routes all P2P connections through the Tor network, hiding your node&apos;s IP address
            </div>
            {status?.tor_mode && status?.onion_address && (
              <div className="mt-2 flex items-center gap-2">
                <code className="text-xs text-orange-400 bg-gray-900/50 px-2 py-1 rounded font-mono">
                  {status.onion_address}
                </code>
                <button
                  className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
                  onClick={() => {
                    navigator.clipboard.writeText(status.onion_address!);
                  }}
                >
                  Copy
                </button>
              </div>
            )}
            {!status?.tor_mode && (
              <div className="text-xs text-gray-600 mt-1">
                Configure via Ghost Core startup flags (-proxy, -torcontrol)
              </div>
            )}
          </div>
        </div>

        <StatusRow
          label="Ghost Shroud"
          description="Random delays before relaying transactions — protects against timing analysis"
          badge={
            shroudStatus ? (
              <Badge variant={shroudStatus.enabled ? "success" : "default"}>
                {shroudStatus.enabled ? "Active" : "Disabled"}
              </Badge>
            ) : (
              <Badge variant="default">Unknown</Badge>
            )
          }
        />

        <StatusRow
          label="Ghost Haze"
          description="Strips privacy-sensitive data (signatures, witness data, inscriptions) from stored blocks"
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
          label="Wraith Protocol"
          description="CoinJoin mixing on the L2 network — breaks transaction linkability"
          badge={
            ghostPayStatus?.wraith_enabled ? (
              <Badge variant="success">Active</Badge>
            ) : gpRunning ? (
              <Badge variant="default">Available</Badge>
            ) : (
              <Badge variant="warning">Not Running</Badge>
            )
          }
        />
      </div>
    </Card>
  );
}
