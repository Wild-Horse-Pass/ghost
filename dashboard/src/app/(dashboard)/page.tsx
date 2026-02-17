"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { StatusDot } from "@/components/ui/StatusDot";
import { Tooltip } from "@/components/ui/Tooltip";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useNodeInfo, useNodeStatus, useShares, useNickname } from "@/hooks/queries/useNodeQueries";
import { useWatchdogStatus } from "@/hooks/queries/useWatchdogQueries";
import { useMiningStatus } from "@/hooks/queries/useMiningQueries";
import { useGhostPayStatus } from "@/hooks/queries/useGhostPayQueries";
import { useHazeStatus } from "@/hooks/queries/useHazeQueries";
import { useShroudStatus } from "@/hooks/queries/useShroudQueries";
import { formatHashrate } from "@/components/ui/DataTable";

const TOOLTIPS = {
  block_height: "The current block height of the Bitcoin blockchain your node has synced to.",
  l1_sync: "Whether your node is fully synced with the Bitcoin network.",
  l1_peers: "Number of other Ghost nodes your node is directly connected to.",
  l1_hashrate: "Combined mining power of all miners connected to your node.",
  l2_height: "The current block height of the Ghost Pay L2 network.",
  l2_sync: "Whether your node is synced with the Ghost Pay L2 consensus.",
  l2_peers: "Number of Ghost Pay L2 peers your node is connected to.",
  l2_sessions: "Active Wraith mixing sessions on the L2 network.",
  shares: "Your node's share count determines your portion of the node reward pool. Based on the 5-4-3-2-1 system.",
  health: "Overall health of the services running on your node.",
  privacy_haze: "Ghost Haze strips privacy-sensitive data from stored blocks.",
  privacy_shroud: "Ghost Shroud adds random relay delays to protect transaction origin.",
};

const SHARE_TIERS = [
  { key: "archive_mode", name: "Archive Mode", bonus: 5 },
  { key: "ghost_pay", name: "Ghost Pay", bonus: 4 },
  { key: "public_mining", name: "Public Mining", bonus: 3 },
  { key: "bitcoin_pure", name: "Bitcoin Pure", bonus: 2 },
  { key: "elder", name: "Elder Status", bonus: 1 },
] as const;

function L1Card() {
  const { data: status, isLoading: statusLoading } = useNodeStatus();
  const { data: mining, isLoading: miningLoading } = useMiningStatus();
  const isLoading = statusLoading || miningLoading;

  const syncStatus = status?.is_synced;
  const height = status ? (status.sync_height ?? status.block_height ?? 0) : 0;

  return (
    <Card className="border-orange-600/30">
      <CardHeader
        title={<span className="text-orange-400">L1 &middot; Bitcoin</span>}
        action={
          syncStatus != null && (
            <StatusDot
              status={syncStatus ? "online" : "warning"}
              pulse={syncStatus}
              label={syncStatus ? "Synced" : "Syncing"}
            />
          )
        }
      />
      <div className="grid grid-cols-2 gap-3">
        <Tooltip content={TOOLTIPS.block_height}>
          <div className="p-3 bg-orange-900/10 rounded-lg">
            <div className="text-xs text-gray-500 mb-1">Block Height</div>
            <div className="text-lg font-mono font-semibold text-gray-100">
              {isLoading ? "..." : height.toLocaleString()}
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.l1_peers}>
          <div className="p-3 bg-orange-900/10 rounded-lg">
            <div className="text-xs text-gray-500 mb-1">Peers</div>
            <div className="text-lg font-mono font-semibold text-gray-100">
              {isLoading ? "..." : `${status?.peer_count ?? 0} connected`}
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.l1_hashrate}>
          <div className="p-3 bg-orange-900/10 rounded-lg">
            <div className="text-xs text-gray-500 mb-1">Hashrate</div>
            <div className="text-lg font-mono font-semibold text-gray-100">
              {isLoading ? "..." : mining ? formatHashrate((mining.hashrate_th ?? 0) * 1e12) : "0 H/s"}
            </div>
          </div>
        </Tooltip>
        <div className="p-3 bg-orange-900/10 rounded-lg">
          <div className="text-xs text-gray-500 mb-1">Miners</div>
          <div className="text-lg font-mono font-semibold text-gray-100">
            {isLoading ? "..." : `${mining?.connected_miners ?? 0} connected`}
          </div>
        </div>
      </div>
    </Card>
  );
}

function L2Card() {
  const { data: gp, isLoading } = useGhostPayStatus();

  const isRunning = gp && gp.sync_state !== "disabled" && gp.sync_state !== "unavailable";
  const height = gp ? `${gp.l2_era ?? 1}:${(gp.virtual_block ?? gp.block_height ?? 0).toLocaleString()}` : "--";

  return (
    <Card className="border-cyan-600/30">
      <CardHeader
        title={<span className="text-cyan-400">L2 &middot; Ghost Pay</span>}
        action={
          isRunning != null && (
            <StatusDot
              status={isRunning ? "online" : "offline"}
              pulse={!!isRunning}
              label={isRunning ? (gp?.sync_state === "synced" ? "Synced" : "Syncing") : "Offline"}
            />
          )
        }
      />
      <div className="grid grid-cols-2 gap-3">
        <Tooltip content={TOOLTIPS.l2_height}>
          <div className="p-3 bg-cyan-900/10 rounded-lg">
            <div className="text-xs text-gray-500 mb-1">L2 Height</div>
            <div className="text-lg font-mono font-semibold text-gray-100">
              {isLoading ? "..." : height}
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.l2_peers}>
          <div className="p-3 bg-cyan-900/10 rounded-lg">
            <div className="text-xs text-gray-500 mb-1">Peers</div>
            <div className="text-lg font-mono font-semibold text-gray-100">
              {isLoading ? "..." : `${gp?.peer_count ?? 0} connected`}
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.l2_sessions}>
          <div className="p-3 bg-cyan-900/10 rounded-lg">
            <div className="text-xs text-gray-500 mb-1">Wraith</div>
            <div className="text-lg font-mono font-semibold text-gray-100">
              {isLoading ? "..." : gp?.wraith_enabled ? "Enabled" : "Disabled"}
            </div>
          </div>
        </Tooltip>
        <div className="p-3 bg-cyan-900/10 rounded-lg">
          <div className="text-xs text-gray-500 mb-1">Status</div>
          <div className="text-lg font-mono font-semibold text-gray-100">
            {isLoading ? "..." : isRunning ? "Active" : "Not enabled"}
          </div>
        </div>
      </div>
    </Card>
  );
}

function SharesSection() {
  const { data: shares, isLoading } = useShares();

  if (isLoading) return <SkeletonCard />;
  if (!shares) return null;

  const percent = shares.max_shares > 0 ? (shares.total / shares.max_shares) * 100 : 0;

  return (
    <Card>
      <CardHeader
        title="Your Shares"
        subtitle="5-4-3-2-1 Reward System"
        action={
          <span className="text-2xl font-bold text-gray-100">
            {shares.total}<span className="text-gray-500 text-lg"> / {shares.max_shares}</span>
          </span>
        }
      />

      <ProgressBar
        value={percent}
        color={shares.uptime_qualified ? "orange" : "red"}
        size="lg"
        className="mb-4"
      />

      {/* Uptime gatekeeper */}
      {!shares.uptime_qualified && (
        <div className="mb-4 p-3 rounded-lg bg-red-900/20 border border-red-800">
          <div className="flex items-center gap-2">
            <span className="text-red-400">&#10007;</span>
            <span className="text-sm text-gray-300">Uptime below 95%</span>
            <Badge variant="error">{(shares.uptime_percent ?? 0).toFixed(1)}%</Badge>
          </div>
          <p className="text-xs text-red-400 mt-1">All shares disabled until uptime recovers</p>
        </div>
      )}

      <div className="space-y-1.5">
        {SHARE_TIERS.map((tier) => {
          const isActive = shares[tier.key as keyof typeof shares] as boolean;
          const disabled = !shares.uptime_qualified;
          return (
            <div key={tier.key} className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-gray-800/30">
              <div className="flex items-center gap-2">
                <span className={isActive && !disabled ? "text-green-400" : "text-gray-600"}>
                  {isActive ? "\u2713" : "\u2717"}
                </span>
                <span className={isActive && !disabled ? "text-gray-100 text-sm" : "text-gray-500 text-sm"}>
                  {tier.name}
                </span>
              </div>
              <Badge variant={isActive && !disabled ? "success" : "default"}>+{tier.bonus}</Badge>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

function HealthSection() {
  const { data: watchdog, isLoading } = useWatchdogStatus();

  if (isLoading) return <SkeletonCard />;
  if (!watchdog) return null;

  const overallStatus = watchdog.overall_health ?? "unknown";
  const statusColor = overallStatus === "healthy" ? "online" : overallStatus === "degraded" ? "warning" : "offline";

  return (
    <Card>
      <CardHeader
        title="Health"
        action={
          <StatusDot
            status={statusColor as 'online' | 'warning' | 'offline'}
            pulse={statusColor === 'online'}
            label={overallStatus.charAt(0).toUpperCase() + overallStatus.slice(1)}
          />
        }
      />
      <div className="flex flex-wrap gap-2">
        {(watchdog.services ?? []).map((svc: { name: string; status: string }) => (
          <Badge
            key={svc.name}
            variant={svc.status === "running" ? "success" : svc.status === "stopped" ? "error" : "warning"}
          >
            {svc.name}
          </Badge>
        ))}
      </div>
    </Card>
  );
}

function PrivacySection() {
  const { data: haze } = useHazeStatus();
  const { data: shroud } = useShroudStatus();

  return (
    <Card className="border-purple-600/20">
      <CardHeader title={<span className="text-purple-400">Privacy Status</span>} />
      <div className="grid grid-cols-2 gap-3">
        <div className="p-3 bg-purple-900/10 rounded-lg">
          <div className="text-xs text-gray-500 mb-1">Ghost Haze</div>
          <div className="flex items-center gap-2">
            <StatusDot
              status={haze?.mode === "hazed" || haze?.mode === "full_archive" ? "online" : "offline"}
              size="sm"
            />
            <span className="text-sm text-gray-100 capitalize">{haze?.mode ?? "unknown"}</span>
          </div>
        </div>
        <div className="p-3 bg-purple-900/10 rounded-lg">
          <div className="text-xs text-gray-500 mb-1">Ghost Shroud</div>
          <div className="flex items-center gap-2">
            <StatusDot
              status={shroud?.enabled ? "online" : "offline"}
              size="sm"
            />
            <span className="text-sm text-gray-100">{shroud?.enabled ? "Active" : "Inactive"}</span>
          </div>
        </div>
      </div>
    </Card>
  );
}

export default function OverviewPage() {
  const { data: info } = useNodeInfo();
  const { data: nickname } = useNickname();
  const { data: status } = useNodeStatus();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Overview"
        subtitle={nickname?.nickname ? `${nickname.nickname} \u00b7 v${info?.version ?? ''}` : info?.version ? `v${info.version}` : undefined}
        actions={
          status?.is_synced != null && (
            <Badge variant={status.is_synced ? "success" : "warning"}>
              {status.is_synced ? "Synced" : "Syncing..."}
            </Badge>
          )
        }
      />

      {/* L1 + L2 hero cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SectionErrorBoundary section="L1 Status">
          <L1Card />
        </SectionErrorBoundary>
        <SectionErrorBoundary section="L2 Status">
          <L2Card />
        </SectionErrorBoundary>
      </div>

      {/* Shares */}
      <SectionErrorBoundary section="Shares">
        <SharesSection />
      </SectionErrorBoundary>

      {/* Health + Privacy */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SectionErrorBoundary section="Health">
          <HealthSection />
        </SectionErrorBoundary>
        <SectionErrorBoundary section="Privacy">
          <PrivacySection />
        </SectionErrorBoundary>
      </div>
    </div>
  );
}
