"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { StatusDot } from "@/components/ui/StatusDot";
import { Tooltip } from "@/components/ui/Tooltip";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useNodeInfo, useNodeStatus, useShares, useNickname } from "@/hooks/queries/useNodeQueries";
import { useRewardsCurrent } from "@/hooks/queries/useRewardsQueries";
import { useWatchdogStatus } from "@/hooks/queries/useWatchdogQueries";
import { useTreasury } from "@/hooks/queries/useNetworkQueries";
import { useMiningStatus } from "@/hooks/queries/useMiningQueries";
import { formatHashrate } from "@/components/ui/DataTable";

const SHARE_TIERS = [
  { key: "archive_mode", name: "Archive Mode", bonus: 5 },
  { key: "ghost_pay", name: "Ghost Pay", bonus: 4 },
  { key: "public_mining", name: "Public Mining", bonus: 3 },
  { key: "bitcoin_pure", name: "Bitcoin Pure", bonus: 2 },
  { key: "elder", name: "Elder Status", bonus: 1 },
] as const;

const DECAY_SCHEDULE = [
  { year: 0, treasury: 0.5, nodePool: 0.5 },
  { year: 1, treasury: 0.4, nodePool: 0.6 },
  { year: 2, treasury: 0.3, nodePool: 0.7 },
  { year: 3, treasury: 0.2, nodePool: 0.8 },
  { year: 4, treasury: 0.1, nodePool: 0.9 },
  { year: 5, treasury: 0.0, nodePool: 1.0 },
];

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

function RewardsSection() {
  const { data, isLoading } = useRewardsCurrent();

  if (isLoading) return <SkeletonCard />;

  const formatSats = (sats: number): string => {
    if (sats >= 100_000_000) return `${(sats / 100_000_000).toFixed(4)} BTC`;
    if (sats >= 100_000) return `${(sats / 100_000_000).toFixed(6)} BTC`;
    return `${sats.toLocaleString()} sats`;
  };

  return (
    <Card>
      <CardHeader title="Earnings Summary" />
      <div className="space-y-4">
        <div className="p-4 bg-gradient-to-br from-yellow-900/30 to-orange-900/20 border border-yellow-800/50 rounded-lg">
          <div className="text-xs text-yellow-500 uppercase tracking-wide mb-1">Total Earned</div>
          <div className="text-2xl font-bold text-yellow-400">
            {data?.total_earned_sats != null ? formatSats(data.total_earned_sats) : "--"}
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="p-3 bg-gray-800/50 rounded-lg">
            <div className="text-xs text-gray-500 mb-1">Pending</div>
            <div className="text-sm font-mono text-gray-100">
              {data?.pending_rewards_sats != null ? formatSats(data.pending_rewards_sats) : "--"}
            </div>
          </div>
          <div className="p-3 bg-gray-800/50 rounded-lg">
            <div className="text-xs text-gray-500 mb-1">Est. Reward</div>
            <div className="text-sm font-mono text-gray-100">
              {data?.estimated_reward_btc != null ? `${data.estimated_reward_btc.toFixed(8)} BTC` : "--"}
            </div>
          </div>
        </div>
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

function TreasurySection() {
  const { data: treasury, isLoading } = useTreasury();

  if (isLoading) return <SkeletonCard className="col-span-full" />;
  if (!treasury) return null;

  const phase = treasury.phase ?? "bootstrap";
  const phaseLabel = { bootstrap: "Bootstrap", decay: "Decay", ossified: "Ossified" }[phase] ?? "Unknown";
  const phaseColor = { bootstrap: "text-yellow-400", decay: "text-orange-400", ossified: "text-green-400" }[phase] ?? "text-gray-400";

  return (
    <Card className="col-span-full">
      <CardHeader title="Decentralisation Timeline" />

      <div className="space-y-4">
        <div className="flex justify-between text-sm mb-1">
          <span className="text-gray-400">Treasury Progress</span>
          <span className="text-gray-100">
            {(treasury.accumulated_btc ?? 0).toFixed(2)} / {(treasury.target_btc ?? 21).toFixed(1)} BTC
            <span className="text-gray-500 ml-2">({(treasury.progress_percent ?? 0).toFixed(1)}%)</span>
          </span>
        </div>
        <ProgressBar value={treasury.progress_percent ?? 0} color="orange" size="md" />

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-gray-800/50 rounded-lg">
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide">Phase</div>
            <div className={`text-lg font-semibold ${phaseColor}`}>{phaseLabel}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide">Decay Year</div>
            <div className="text-lg font-semibold text-gray-100">
              {treasury.decay_started && treasury.decay_year !== null ? `Year ${treasury.decay_year}` : "Not started"}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide">Treasury</div>
            <div className="text-lg font-semibold text-gray-100">{(treasury.treasury_percent ?? 50).toFixed(0)}%</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide">Node Pool</div>
            <div className="text-lg font-semibold text-gray-100">{(treasury.node_pool_percent ?? 50).toFixed(0)}%</div>
          </div>
        </div>

        {/* Timeline dots */}
        <div className="flex items-center justify-between">
          {DECAY_SCHEDULE.map((step) => {
            const decayYear = treasury.decay_year ?? 0;
            const isCurrentYear = treasury.decay_started && decayYear === step.year;
            const isPast = treasury.decay_started && treasury.decay_year != null && step.year < decayYear;
            const isOssified = treasury.phase === "ossified";

            let dotColor = "bg-gray-600";
            if (isOssified && step.year === 5) dotColor = "bg-green-500";
            else if (isCurrentYear) dotColor = "bg-orange-500 animate-pulse";
            else if (isPast) dotColor = "bg-orange-400";
            else if (!treasury.decay_started && step.year === 0) dotColor = "bg-yellow-500";

            return (
              <Tooltip key={step.year} content={`Treasury: ${(step.treasury * 100).toFixed(0)}% / Node Pool: ${(step.nodePool * 100).toFixed(0)}%`}>
                <div className="flex flex-col items-center flex-1">
                  <div className={`w-3 h-3 rounded-full ${dotColor}`} />
                  <div className="text-xs text-gray-500 mt-1">
                    {step.year === 0 ? "21 BTC" : `Yr ${step.year}`}
                  </div>
                </div>
              </Tooltip>
            );
          })}
        </div>
      </div>
    </Card>
  );
}

export default function OverviewPage() {
  const { data: info } = useNodeInfo();
  const { data: nickname } = useNickname();
  const { data: status, isLoading: statusLoading } = useNodeStatus();
  const { data: mining, isLoading: miningLoading } = useMiningStatus();

  const isLoading = statusLoading || miningLoading;

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

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Block Height"
          value={status ? (status.sync_height ?? status.block_height ?? 0).toLocaleString() : "--"}
          loading={isLoading}
        />
        <StatCard
          label="Peers"
          value={status?.peer_count ?? "--"}
          sublabel="connected"
          loading={isLoading}
        />
        <StatCard
          label="Hashrate"
          value={mining ? formatHashrate((mining.hashrate_th ?? 0) * 1e12) : "--"}
          loading={isLoading}
        />
        <StatCard
          label="Miners"
          value={mining?.connected_miners ?? 0}
          sublabel="connected"
          loading={isLoading}
        />
      </div>

      {/* Shares + Rewards row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SectionErrorBoundary section="Shares">
          <SharesSection />
        </SectionErrorBoundary>
        <SectionErrorBoundary section="Rewards">
          <RewardsSection />
        </SectionErrorBoundary>
      </div>

      {/* Health */}
      <SectionErrorBoundary section="Health">
        <HealthSection />
      </SectionErrorBoundary>

      {/* Treasury */}
      <SectionErrorBoundary section="Treasury">
        <TreasurySection />
      </SectionErrorBoundary>
    </div>
  );
}
