"use client";

import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { SkeletonCard } from "@/components/ui/Skeleton";
import {
  useFullConfig,
  useNodeStatus,
  useL2PruningStatus,
  useSetPruneProfile,
  useSetOperatorWindow,
  useSetArchiveMode,
  useGhostPayStatus,
} from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import type { PruneProfile } from "@/types/api";

// Preset OW options (in blocks)
const OW_PRESETS = [
  { blocks: 1008, label: "7 days", description: "Minimum recommended" },
  { blocks: 2016, label: "14 days", description: "Default" },
  { blocks: 4032, label: "30 days", description: "Extended retention" },
];

// Prune profile descriptions
const PRUNE_PROFILES: { value: PruneProfile; label: string; keep: string; prune: string }[] = [
  { value: "default", label: "Default", keep: "T0, T1, T2", prune: "T3 only" },
  { value: "strict", label: "Strict", keep: "T0, T1", prune: "T2, T3" },
  { value: "clean", label: "Clean", keep: "T0, T1", prune: "T2, T3" },
  { value: "structured", label: "Structured", keep: "T0, T1, T2", prune: "T3" },
  { value: "archive", label: "Archive", keep: "All (T0-T3)", prune: "None" },
];

function formatDuration(blocks: number): string {
  const days = Math.round(blocks / 144);
  if (days === 1) return "1 day";
  if (days < 7) return `${days} days`;
  if (days === 7) return "1 week";
  if (days < 30) return `${Math.round(days / 7)} weeks`;
  if (days < 60) return "1 month";
  return `${Math.round(days / 30)} months`;
}

function formatTimestamp(ts: number): string {
  if (!ts) return "Never";
  const date = new Date(ts * 1000);
  return date.toLocaleString();
}

function formatTimeAgo(ts: number): string {
  if (!ts) return "Never";
  const now = Math.floor(Date.now() / 1000);
  const diff = now - ts;
  if (diff < 60) return "Just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function StoragePage() {
  const { data: fullConfig, isLoading: configLoading } = useFullConfig();
  const { data: status } = useNodeStatus();
  const { data: l2Pruning, isLoading: l2Loading } = useL2PruningStatus();
  const { data: ghostPayStatus } = useGhostPayStatus();

  const setPruneProfile = useSetPruneProfile();
  const setOperatorWindow = useSetOperatorWindow();
  const setArchiveMode = useSetArchiveMode();

  const { success, error } = useToast();

  const isLoading = configLoading;
  const archiveMode = status?.archive_mode ?? false;
  const ghostPayRunning = !!ghostPayStatus?.l2_height;

  const handlePruneProfileChange = async (profile: PruneProfile) => {
    try {
      await setPruneProfile.mutateAsync(profile);
      success("Profile Updated", `Prune profile set to "${profile}"`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleOperatorWindowChange = async (blocks: number) => {
    try {
      await setOperatorWindow.mutateAsync(blocks);
      success("Window Updated", `Operator window set to ${formatDuration(blocks)}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleArchiveModeToggle = async () => {
    try {
      await setArchiveMode.mutateAsync(!archiveMode);
      success("Mode Changed", `Archive Mode ${!archiveMode ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">Storage & Pruning</h1>
        {archiveMode && <Badge variant="success">+5 Shares (Archive)</Badge>}
      </div>

      {isLoading ? (
        <>
          <SkeletonCard />
          <SkeletonCard />
        </>
      ) : (
        <>
          {/* L1 Pruning - Three Window Model */}
          <Card>
            <CardHeader
              title="L1 Pruning"
              subtitle="Three-window model: VW (consensus safety) -> OW (configurable) -> AW (archive)"
            />
            <div className="space-y-6">
              {/* Archive Mode Toggle */}
              <div className="p-4 bg-gray-800/50 rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-gray-100 font-medium">Archive Mode</span>
                      {archiveMode && <Badge variant="success">+5 Shares</Badge>}
                    </div>
                    <p className="text-sm text-gray-400 mt-1">
                      Store complete blockchain history. Disables all pruning and earns bonus shares.
                    </p>
                  </div>
                  <Button
                    variant={archiveMode ? "primary" : "secondary"}
                    onClick={handleArchiveModeToggle}
                    loading={setArchiveMode.isPending}
                  >
                    {archiveMode ? "Enabled" : "Disabled"}
                  </Button>
                </div>
              </div>

              {/* Window Visualization */}
              <div className="grid grid-cols-3 gap-4">
                {/* Validator Window */}
                <div className="p-4 bg-blue-900/20 border border-blue-800 rounded-lg">
                  <div className="text-blue-400 font-medium mb-2">Validator Window (VW)</div>
                  <div className="text-2xl font-bold text-gray-100">288 blocks</div>
                  <div className="text-sm text-gray-400 mt-1">~2 days</div>
                  <div className="mt-3 text-xs text-blue-300">
                    Fixed - Bitcoin Core minimum for reorg safety
                  </div>
                </div>

                {/* Operator Window */}
                <div className={`p-4 rounded-lg border ${archiveMode ? 'bg-gray-800/30 border-gray-700' : 'bg-purple-900/20 border-purple-800'}`}>
                  <div className={`font-medium mb-2 ${archiveMode ? 'text-gray-500' : 'text-purple-400'}`}>
                    Operator Window (OW)
                  </div>
                  <div className={`text-2xl font-bold ${archiveMode ? 'text-gray-500' : 'text-gray-100'}`}>
                    {fullConfig?.pruning?.ow_blocks ?? 2016} blocks
                  </div>
                  <div className="text-sm text-gray-400 mt-1">
                    ~{formatDuration(fullConfig?.pruning?.ow_blocks ?? 2016)}
                  </div>
                  <div className={`mt-3 text-xs ${archiveMode ? 'text-gray-500' : 'text-purple-300'}`}>
                    {archiveMode ? "Disabled (Archive Mode)" : "BUDS-based pruning applied here"}
                  </div>
                </div>

                {/* Archive Window */}
                <div className={`p-4 rounded-lg border ${archiveMode ? 'bg-green-900/20 border-green-800' : 'bg-gray-800/30 border-gray-700'}`}>
                  <div className={`font-medium mb-2 ${archiveMode ? 'text-green-400' : 'text-gray-500'}`}>
                    Archive Window (AW)
                  </div>
                  <div className={`text-2xl font-bold ${archiveMode ? 'text-gray-100' : 'text-gray-500'}`}>
                    {archiveMode ? "Infinite" : "Pruned"}
                  </div>
                  <div className="text-sm text-gray-400 mt-1">
                    {archiveMode ? "All history retained" : "Data beyond OW is deleted"}
                  </div>
                  <div className={`mt-3 text-xs ${archiveMode ? 'text-green-300' : 'text-gray-500'}`}>
                    {archiveMode ? "Full chain storage enabled" : "Enable Archive Mode for +5 shares"}
                  </div>
                </div>
              </div>

              {/* Operator Window Selection (only if not archive mode) */}
              {!archiveMode && (
                <div className="space-y-3">
                  <label className="text-sm font-medium text-gray-300">Operator Window Size</label>
                  <div className="grid grid-cols-3 gap-3">
                    {OW_PRESETS.map((preset) => (
                      <button
                        key={preset.blocks}
                        onClick={() => handleOperatorWindowChange(preset.blocks)}
                        disabled={setOperatorWindow.isPending}
                        className={`p-3 rounded-lg border transition-colors text-left ${
                          fullConfig?.pruning?.ow_blocks === preset.blocks
                            ? "bg-purple-900/30 border-purple-600 text-purple-300"
                            : "bg-gray-800/50 border-gray-700 text-gray-300 hover:border-gray-500"
                        }`}
                      >
                        <div className="font-medium">{preset.label}</div>
                        <div className="text-xs text-gray-500 mt-1">{preset.blocks} blocks</div>
                        <div className="text-xs text-gray-400 mt-1">{preset.description}</div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Prune Profile Selection (only if not archive mode) */}
              {!archiveMode && (
                <div className="space-y-3">
                  <label className="text-sm font-medium text-gray-300">BUDS Prune Profile</label>
                  <p className="text-xs text-gray-500">
                    Controls which BUDS tiers are retained in the Operator Window
                  </p>
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                    {PRUNE_PROFILES.filter(p => p.value !== "archive").map((profile) => (
                      <button
                        key={profile.value}
                        onClick={() => handlePruneProfileChange(profile.value)}
                        disabled={setPruneProfile.isPending}
                        className={`p-3 rounded-lg border transition-colors text-left ${
                          fullConfig?.pruning?.prune_profile === profile.value
                            ? "bg-purple-900/30 border-purple-600 text-purple-300"
                            : "bg-gray-800/50 border-gray-700 text-gray-300 hover:border-gray-500"
                        }`}
                      >
                        <div className="font-medium capitalize">{profile.label}</div>
                        <div className="text-xs text-green-400 mt-1">Keep: {profile.keep}</div>
                        <div className="text-xs text-red-400">Prune: {profile.prune}</div>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Card>

          {/* L2 Pruning Status */}
          <Card>
            <CardHeader
              title="L2 Pruning (Ghost Pay)"
              subtitle="Automatic pruning of old payments, attestations, and closed locks"
            />
            <div className="space-y-4">
              {!ghostPayRunning ? (
                <div className="p-4 bg-yellow-900/20 border border-yellow-800 rounded-lg">
                  <div className="flex items-center gap-2">
                    <Badge variant="warning">Ghost Pay Not Running</Badge>
                  </div>
                  <p className="text-sm text-yellow-300 mt-2">
                    Start ghost-pay-node to enable L2 functionality and see pruning status.
                  </p>
                </div>
              ) : l2Loading ? (
                <SkeletonCard />
              ) : l2Pruning ? (
                <>
                  {/* L2 Pruning Config */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="p-4 bg-gray-800/50 rounded-lg">
                      <div className="text-sm text-gray-400">Retention Period</div>
                      <div className="text-xl font-bold text-gray-100 mt-1">
                        {l2Pruning.retention_days} days
                      </div>
                    </div>
                    <div className="p-4 bg-gray-800/50 rounded-lg">
                      <div className="text-sm text-gray-400">Auto Prune</div>
                      <div className="mt-1">
                        <Badge variant="success">Always On</Badge>
                      </div>
                      <div className="text-xs text-gray-500 mt-1">
                        Every {l2Pruning.prune_interval_hours}h
                      </div>
                    </div>
                    <div className="p-4 bg-gray-800/50 rounded-lg">
                      <div className="text-sm text-gray-400">Last Prune</div>
                      <div className="text-lg font-medium text-gray-100 mt-1">
                        {formatTimeAgo(l2Pruning.last_prune_timestamp ?? 0)}
                      </div>
                      <div className="text-xs text-gray-500 mt-1">
                        {formatTimestamp(l2Pruning.last_prune_timestamp ?? 0)}
                      </div>
                    </div>
                    <div className="p-4 bg-gray-800/50 rounded-lg">
                      <div className="text-sm text-gray-400">Last Run Stats</div>
                      <div className="text-sm text-gray-300 mt-2 space-y-1">
                        <div>Payments: {l2Pruning.payments_pruned}</div>
                        <div>Attestations: {l2Pruning.attestations_pruned}</div>
                        <div>Locks: {l2Pruning.locks_pruned}</div>
                      </div>
                    </div>
                  </div>

                  {/* L2 Pruning Info - Two Columns */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 bg-red-900/20 border border-red-800 rounded-lg">
                      <h4 className="text-red-300 font-medium mb-3">What Gets Pruned</h4>
                      <ul className="text-sm text-red-200/80 space-y-2">
                        <li className="flex items-start gap-2">
                          <span className="text-red-400 mt-0.5">•</span>
                          <span>Payments (with ZK proofs) older than {l2Pruning.retention_days} days</span>
                        </li>
                        <li className="flex items-start gap-2">
                          <span className="text-red-400 mt-0.5">•</span>
                          <span>Attestations older than {l2Pruning.retention_days} days</span>
                        </li>
                        <li className="flex items-start gap-2">
                          <span className="text-red-400 mt-0.5">•</span>
                          <span>Closed locks (reconciled or jumped) older than {l2Pruning.retention_days} days</span>
                        </li>
                      </ul>
                    </div>
                    <div className="p-4 bg-green-900/20 border border-green-800 rounded-lg">
                      <h4 className="text-green-300 font-medium mb-3">What is Never Pruned</h4>
                      <ul className="text-sm text-green-200/80 space-y-2">
                        <li className="flex items-start gap-2">
                          <span className="text-green-400 mt-0.5">•</span>
                          <span>Active locks (regardless of age)</span>
                        </li>
                        <li className="flex items-start gap-2">
                          <span className="text-green-400 mt-0.5">•</span>
                          <span>L2 block headers (contain state_root commitments)</span>
                        </li>
                      </ul>
                    </div>
                  </div>
                </>
              ) : (
                <div className="p-4 bg-gray-800/50 rounded-lg text-gray-400">
                  Unable to fetch L2 pruning status. Ensure ghost-pay-node API is accessible.
                </div>
              )}
            </div>
          </Card>

          {/* Storage Summary */}
          <Card>
            <CardHeader title="Quick Reference" />
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-400 border-b border-gray-800">
                    <th className="pb-3 font-medium">Layer</th>
                    <th className="pb-3 font-medium">Window</th>
                    <th className="pb-3 font-medium">Duration</th>
                    <th className="pb-3 font-medium">Behavior</th>
                  </tr>
                </thead>
                <tbody className="text-gray-300">
                  <tr className="border-b border-gray-800/50">
                    <td className="py-3">L1</td>
                    <td className="py-3">Validator (VW)</td>
                    <td className="py-3">288 blocks (~2 days)</td>
                    <td className="py-3">Full retention - Bitcoin Core minimum</td>
                  </tr>
                  <tr className="border-b border-gray-800/50">
                    <td className="py-3">L1</td>
                    <td className="py-3">Operator (OW)</td>
                    <td className="py-3">{fullConfig?.pruning?.ow_blocks ?? 2016} blocks (~{formatDuration(fullConfig?.pruning?.ow_blocks ?? 2016)})</td>
                    <td className="py-3">
                      {archiveMode ? "Archive Mode - no pruning" : `BUDS pruning (${fullConfig?.pruning?.prune_profile ?? "default"})`}
                    </td>
                  </tr>
                  <tr className="border-b border-gray-800/50">
                    <td className="py-3">L1</td>
                    <td className="py-3">Archive (AW)</td>
                    <td className="py-3">{archiveMode ? "Infinite" : "N/A"}</td>
                    <td className="py-3">{archiveMode ? "Full chain stored (+5 shares)" : "Data pruned beyond OW"}</td>
                  </tr>
                  <tr>
                    <td className="py-3">L2</td>
                    <td className="py-3">Retention</td>
                    <td className="py-3">{l2Pruning?.retention_days ?? 90} days</td>
                    <td className="py-3">Auto-prune payments, attestations, closed locks</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
