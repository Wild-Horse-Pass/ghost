"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Toggle } from "@/components/ui/Toggle";
import { CopyButton } from "@/components/ui/CopyButton";
import { EmptyState } from "@/components/ui/EmptyState";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { DataTable, formatHashrate, formatDuration } from "@/components/ui/DataTable";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useMiningStatus, useMiners, useBestHash, useSetPrivateMining, useSetPublicMining } from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import type { MinerInfo, BestHashEntry } from "@/types/api";
import type { ColumnDef } from "@tanstack/react-table";

const minerColumns: ColumnDef<MinerInfo>[] = [
  {
    accessorKey: "worker_name",
    header: "Worker",
    cell: ({ row }) => (
      <div>
        <div className="font-medium">{row.original.worker_name || "Unknown"}</div>
        <div className="text-xs text-gray-500 font-mono">{row.original.ip_address || "N/A"}</div>
      </div>
    ),
  },
  {
    accessorKey: "hashrate_th",
    header: "Hashrate",
    cell: ({ row }) => (
      <span className="font-mono">{formatHashrate((row.original.hashrate_th ?? 0) * 1e12)}</span>
    ),
  },
  {
    id: "shares",
    header: "Shares",
    cell: ({ row }) => (
      <span>
        {(row.original.shares_accepted ?? 0).toLocaleString()} / {(row.original.shares_submitted ?? 0).toLocaleString()}
      </span>
    ),
  },
  {
    id: "accept_rate",
    header: "Accept Rate",
    cell: ({ row }) => {
      const submitted = row.original.shares_submitted ?? 0;
      const accepted = row.original.shares_accepted ?? 0;
      const rate = submitted > 0 ? (accepted / submitted) * 100 : 0;
      return (
        <Badge variant={rate >= 95 ? "success" : rate >= 80 ? "warning" : "error"}>
          {rate.toFixed(1)}%
        </Badge>
      );
    },
  },
  {
    accessorKey: "connected_at",
    header: "Uptime",
    cell: ({ row }) => {
      const uptime = Math.floor(Date.now() / 1000 - (row.original.connected_at ?? 0));
      return <span className="text-gray-400">{formatDuration(uptime)}</span>;
    },
  },
];

function formatTimeAgo(timestamp: number): string {
  if (!timestamp) return "Never";
  const diff = Math.floor(Date.now() / 1000) - timestamp;
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function calculateLeadingZeros(difficulty: number): number {
  if (difficulty <= 0) return 0;
  return Math.floor(8 + Math.log2(difficulty) / 4);
}

function BestHashCard({ title, entry }: { title: string; entry: BestHashEntry | undefined }) {
  const diff = entry?.difficulty ?? 0;
  const hasData = entry && diff > 0;
  return (
    <div className="p-3 bg-gray-800/50 rounded-lg">
      <div className="text-xs text-gray-400 mb-1">{title}</div>
      {hasData ? (
        <>
          <div className="font-mono text-sm text-orange-400 truncate">{entry.hash}</div>
          <div className="text-xs text-gray-500 mt-0.5">{calculateLeadingZeros(diff)} leading zeros</div>
          <div className="flex justify-between items-center mt-1">
            <span className="text-xs text-gray-500">Block #{entry.block_height?.toLocaleString() || "?"}</span>
            <span className="text-xs text-gray-500">{formatTimeAgo(entry.timestamp ?? 0)}</span>
          </div>
        </>
      ) : (
        <div className="text-gray-500 text-sm">No data yet</div>
      )}
    </div>
  );
}

export default function MiningPage() {
  const { data: status, isLoading: statusLoading } = useMiningStatus();
  const { data: minersData, isLoading: minersLoading } = useMiners();
  const { data: bestHashData, isLoading: bestHashLoading } = useBestHash();
  const setPrivateMining = useSetPrivateMining();
  const setPublicMining = useSetPublicMining();
  const { addToast } = useToast();

  const miners = minersData?.miners ?? [];
  const nodeHost = typeof window !== "undefined" ? window.location.hostname : "localhost";

  const handlePrivateMiningToggle = async (enabled: boolean) => {
    try {
      if (enabled) await setPublicMining.mutateAsync(false);
      await setPrivateMining.mutateAsync(enabled);
      addToast({ type: "success", title: `Private mining ${enabled ? "enabled" : "disabled"}` });
    } catch (err) {
      addToast({ type: "error", title: err instanceof Error ? err.message : "Failed to update" });
    }
  };

  const handlePublicMiningToggle = async (enabled: boolean) => {
    try {
      if (enabled) await setPrivateMining.mutateAsync(false);
      await setPublicMining.mutateAsync(enabled);
      addToast({ type: "success", title: `Public mining ${enabled ? "enabled" : "disabled"}` });
    } catch (err) {
      addToast({ type: "error", title: err instanceof Error ? err.message : "Failed to update" });
    }
  };

  const totalSubmitted = status?.shares_submitted ?? 0;
  const totalAccepted = status?.shares_accepted ?? 0;
  const acceptRate = totalSubmitted > 0 ? ((totalAccepted / totalSubmitted) * 100).toFixed(1) : "0";

  return (
    <div className="space-y-6">
      <PageHeader title="Mining" subtitle="Hashrate, miners, and mining configuration" />

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Hashrate"
          value={status ? formatHashrate((status.hashrate_th ?? 0) * 1e12) : "--"}
          loading={statusLoading}
        />
        <StatCard
          label="Connected Miners"
          value={status?.connected_miners ?? 0}
          loading={statusLoading}
        />
        <StatCard
          label="Shares / Round"
          value={(totalAccepted).toLocaleString()}
          sublabel={`${acceptRate}% accept rate`}
          loading={statusLoading}
        />
        <StatCard
          label="Blocks Found"
          value={status?.blocks_found ?? 0}
          sublabel="all time"
          loading={statusLoading}
        />
      </div>

      {/* Mining Mode */}
      <SectionErrorBoundary section="Mining Mode">
        <Card>
          <CardHeader title="Mining Mode" subtitle="Configure mining modes and connection endpoints" />
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Private Mining */}
            <div className={`p-4 rounded-lg border transition-all ${
              status?.private_mining ? "bg-orange-900/20 border-orange-600" : "bg-gray-800/30 border-gray-700"
            }`}>
              <div className="flex items-center justify-between mb-3">
                <div>
                  <div className="text-gray-100 font-medium flex items-center gap-2">
                    Private Mining
                    {status?.private_mining && <Badge variant="success">Active</Badge>}
                  </div>
                  <div className="text-sm text-gray-400">Mine with your own devices</div>
                </div>
                <Toggle
                  enabled={status?.private_mining ?? false}
                  onChange={handlePrivateMiningToggle}
                  label="Private Mining"
                  disabled={setPrivateMining.isPending}
                />
              </div>
              <div className="space-y-2 pt-3 border-t border-gray-700/50">
                <div className="text-xs text-gray-400 mb-2">Connect to:</div>
                <div className="flex items-center justify-between p-2 bg-gray-900/50 rounded">
                  <div>
                    <div className="text-xs text-gray-500">Stratum V1</div>
                    <code className="text-orange-400 text-sm">stratum+tcp://{nodeHost}:{status?.stratum_v1_port || 3333}</code>
                  </div>
                  <CopyButton text={`stratum+tcp://${nodeHost}:${status?.stratum_v1_port || 3333}`} />
                </div>
                <div className="flex items-center justify-between p-2 bg-gray-900/50 rounded">
                  <div>
                    <div className="text-xs text-gray-500">Stratum V2</div>
                    <code className="text-orange-400 text-sm">stratum+tcp://{nodeHost}:{status?.stratum_v2_port || 3334}</code>
                  </div>
                  <CopyButton text={`stratum+tcp://${nodeHost}:${status?.stratum_v2_port || 3334}`} />
                </div>
              </div>
            </div>

            {/* Public Mining */}
            <div className={`p-4 rounded-lg border transition-all ${
              status?.public_mining ? "bg-orange-900/20 border-orange-600" : "bg-gray-800/30 border-gray-700"
            }`}>
              <div className="flex items-center justify-between mb-3">
                <div>
                  <div className="text-gray-100 font-medium flex items-center gap-2">
                    Public Mining
                    {status?.public_mining && <Badge variant="info">Active</Badge>}
                  </div>
                  <div className="text-sm text-gray-400">Accept public miners via P2P</div>
                </div>
                <Toggle
                  enabled={status?.public_mining ?? false}
                  onChange={handlePublicMiningToggle}
                  label="Public Mining"
                  disabled={setPublicMining.isPending}
                />
              </div>
              <div className="space-y-2 pt-3 border-t border-gray-700/50">
                <div className="text-xs text-gray-400 mb-2">Public miners connect via:</div>
                <div className="flex items-center justify-between p-2 bg-gray-900/50 rounded">
                  <div>
                    <div className="text-xs text-gray-500">Stratum V1</div>
                    <code className="text-orange-400 text-sm">stratum+tcp://pool.bitcoinghost.org:3333</code>
                  </div>
                  <CopyButton text="stratum+tcp://pool.bitcoinghost.org:3333" />
                </div>
                <div className="flex items-center justify-between p-2 bg-gray-900/50 rounded">
                  <div>
                    <div className="text-xs text-gray-500">Stratum V2</div>
                    <code className="text-orange-400 text-sm">stratum+tcp://pool.bitcoinghost.org:34265</code>
                  </div>
                  <CopyButton text="stratum+tcp://pool.bitcoinghost.org:34265" />
                </div>
              </div>
            </div>
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Best Hashes */}
      <SectionErrorBoundary section="Best Hashes">
        <Card>
          <CardHeader title="Best Hashes" subtitle="Lowest hash values achieved by connected miners" />
          {bestHashLoading ? (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <SkeletonCard /><SkeletonCard /><SkeletonCard /><SkeletonCard />
            </div>
          ) : (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <BestHashCard title="Last Round" entry={bestHashData?.last_round} />
              <BestHashCard title="Last Hour" entry={bestHashData?.last_hour} />
              <BestHashCard title="Last 24h" entry={bestHashData?.last_24h} />
              <BestHashCard title="All Time" entry={bestHashData?.all_time} />
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* Connected Miners Table */}
      <SectionErrorBoundary section="Connected Miners">
        <Card>
          <CardHeader
            title="Connected Miners"
            subtitle={`${minersData?.total ?? miners.length} miners connected`}
          />
          <DataTable
            columns={minerColumns}
            data={miners}
            loading={minersLoading}
            emptyMessage="No miners connected"
            emptyDescription="Connect a miner using the Stratum endpoints above"
            searchColumn="worker_name"
            searchPlaceholder="Search miners..."
            showPagination={miners.length > 10}
          />
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
