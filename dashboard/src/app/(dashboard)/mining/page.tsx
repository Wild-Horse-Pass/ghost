"use client";

import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Toggle } from "@/components/ui/Toggle";
import { DataTable, formatHashrate, formatDuration } from "@/components/ui/DataTable";
import { SkeletonCard, SkeletonTable } from "@/components/ui/Skeleton";
import { useMiningStatus, useMiners, useBestHash, useSetPrivateMining, useSetPublicMining } from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import type { MinerInfo, BestHashEntry } from "@/types/api";
import type { ColumnDef } from "@tanstack/react-table";

const minerColumns: ColumnDef<MinerInfo>[] = [
  {
    accessorKey: "worker_name",
    header: "Name",
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
        {(row.original.shares_accepted ?? 0).toLocaleString()} /{" "}
        {(row.original.shares_submitted ?? 0).toLocaleString()}
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

// Format a hash for display (truncate middle)
function formatHash(hash: string): string {
  if (!hash || hash.length < 16) return hash || "N/A";
  return `${hash.slice(0, 8)}...${hash.slice(-8)}`;
}

// Format difficulty to human-readable
function formatDifficulty(difficulty: number): string {
  if (difficulty === 0) return "--";
  if (difficulty >= 1e15) return `${(difficulty / 1e15).toFixed(2)}P`;
  if (difficulty >= 1e12) return `${(difficulty / 1e12).toFixed(2)}T`;
  if (difficulty >= 1e9) return `${(difficulty / 1e9).toFixed(2)}G`;
  if (difficulty >= 1e6) return `${(difficulty / 1e6).toFixed(2)}M`;
  if (difficulty >= 1e3) return `${(difficulty / 1e3).toFixed(2)}K`;
  return difficulty.toFixed(2);
}

// Calculate approximate leading zeros from difficulty
// A hash with difficulty D has approximately log2(D)/4 more leading hex zeros than difficulty 1
function calculateLeadingZeros(difficulty: number): number {
  if (difficulty <= 0) return 0;
  // Base is ~8 leading zeros for difficulty 1 (Bitcoin's minimum target has 8 leading hex zeros)
  // Each 16x increase in difficulty adds ~1 leading zero
  return Math.floor(8 + Math.log2(difficulty) / 4);
}

// Format timestamp to relative time
function formatTimeAgo(timestamp: number): string {
  if (!timestamp) return "Never";
  const now = Math.floor(Date.now() / 1000);
  const diff = now - timestamp;
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

// Best hash entry component
function BestHashCard({ title, entry }: { title: string; entry: BestHashEntry | undefined }) {
  const diff = entry?.difficulty ?? 0;
  const hasData = entry && diff > 0;
  const leadingZeros = hasData ? calculateLeadingZeros(diff) : 0;
  return (
    <div className="p-3 bg-gray-800/50 rounded-lg">
      <div className="text-xs text-gray-400 mb-1">{title}</div>
      {hasData ? (
        <>
          <div className="font-mono text-lg text-orange-400">
            {entry.hash}
          </div>
          <div className="text-xs text-gray-500 mt-0.5">
            {leadingZeros} leading zeros
          </div>
          <div className="flex justify-between items-center mt-1">
            <span className="text-xs text-gray-500">Block #{entry.block_height?.toLocaleString() || "?"}</span>
            <span className="text-xs text-gray-500">{formatTimeAgo(entry.timestamp ?? 0)}</span>
          </div>
          {entry.miner_id && (
            <div className="text-xs text-gray-600 mt-1 truncate">Miner: {entry.miner_id}</div>
          )}
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

  // Get the node's hostname/IP for private mining endpoints
  const nodeHost = typeof window !== 'undefined' ? window.location.hostname : 'localhost';

  const handlePrivateMiningToggle = async (enabled: boolean) => {
    try {
      if (enabled) {
        // Disable public mining when enabling private
        await setPublicMining.mutateAsync(false);
      }
      await setPrivateMining.mutateAsync(enabled);
      addToast({ type: "success", title: `Private mining ${enabled ? "enabled" : "disabled"}` });
    } catch (err) {
      addToast({ type: "error", title: err instanceof Error ? err.message : "Failed to update" });
    }
  };

  const handlePublicMiningToggle = async (enabled: boolean) => {
    try {
      if (enabled) {
        // Disable private mining when enabling public
        await setPrivateMining.mutateAsync(false);
      }
      await setPublicMining.mutateAsync(enabled);
      addToast({ type: "success", title: `Public mining ${enabled ? "enabled" : "disabled"}` });
    } catch (err) {
      addToast({ type: "error", title: err instanceof Error ? err.message : "Failed to update" });
    }
  };

  const totalSubmitted = status?.shares_submitted ?? 0;
  const totalAccepted = status?.shares_accepted ?? 0;
  const acceptRate = totalSubmitted > 0
    ? ((totalAccepted / totalSubmitted) * 100).toFixed(1)
    : "0";

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-100">Mining</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
        {statusLoading ? (
          <>
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
          </>
        ) : (
          <>
            <Card>
              <CardHeader title="Block Height" />
              <div className="text-3xl font-bold text-orange-400">
                {status?.block_height?.toLocaleString() ?? "--"}
              </div>
              <p className="text-sm text-gray-400 mt-1">Mining on</p>
            </Card>

            <Card>
              <CardHeader title="Node Hashrate" />
              <div className="text-3xl font-bold text-gray-100">
                {status ? formatHashrate((status.hashrate_th ?? 0) * 1e12) : "--"}
              </div>
              <p className="text-sm text-gray-400 mt-1">All connected miners</p>
            </Card>

            <Card>
              <CardHeader title="Miners" />
              <div className="text-3xl font-bold text-gray-100">{status?.connected_miners ?? 0}</div>
              <p className="text-sm text-gray-400 mt-1">Connected</p>
            </Card>

            <Card>
              <CardHeader title="Shares" />
              <div className="text-3xl font-bold text-gray-100">
                {(status?.shares_accepted ?? 0).toLocaleString()}
              </div>
              <p className="text-sm text-gray-400 mt-1">{acceptRate}% accept rate</p>
            </Card>

            <Card>
              <CardHeader title="Blocks Found" />
              <div className="text-3xl font-bold text-orange-400">
                {status?.blocks_found ?? 0}
              </div>
              <p className="text-sm text-gray-400 mt-1">All time</p>
            </Card>
          </>
        )}
      </div>

      {/* Best Hash Stats */}
      <Card>
        <CardHeader
          title="Best Hash Produced"
          subtitle="Lowest hash values achieved by connected miners"
        />
        {bestHashLoading ? (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
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

      {/* Mining Connection Card */}
      <Card>
        <CardHeader title="Mining Connection" subtitle="Configure mining modes and view connection endpoints" />

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Private Mining */}
          <div className={`p-4 rounded-lg border transition-all ${
            status?.private_mining
              ? "bg-orange-900/20 border-orange-600"
              : "bg-gray-800/30 border-gray-700"
          }`}>
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="text-gray-100 font-medium flex items-center gap-2">
                  Private Mining
                  {status?.private_mining && <Badge variant="success">Active</Badge>}
                </div>
                <div className="text-sm text-gray-400">Mine with your own devices via this node</div>
              </div>
              <Toggle
                enabled={status?.private_mining ?? false}
                onChange={handlePrivateMiningToggle}
                label="Private Mining"
                disabled={setPrivateMining.isPending}
              />
            </div>

            <div className="space-y-2 pt-3 border-t border-gray-700/50">
              <div className="text-xs text-gray-400 mb-2">Connect your miners to:</div>
              <div className="p-2 bg-gray-900/50 rounded">
                <div className="text-xs text-gray-500">Stratum V1</div>
                <code className="text-orange-400 text-sm">stratum+tcp://{nodeHost}:{status?.stratum_v1_port || 3333}</code>
              </div>
              <div className="p-2 bg-gray-900/50 rounded">
                <div className="text-xs text-gray-500">Stratum V2</div>
                <code className="text-orange-400 text-sm">stratum+tcp://{nodeHost}:{status?.stratum_v2_port || 3334}</code>
              </div>
              <p className="text-xs text-orange-300/70 mt-2">
                These endpoints work when either Private or Public mining is enabled.
              </p>
            </div>
          </div>

          {/* Public Mining */}
          <div className={`p-4 rounded-lg border transition-all ${
            status?.public_mining
              ? "bg-orange-900/20 border-orange-600"
              : "bg-gray-800/30 border-gray-700"
          }`}>
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="text-gray-100 font-medium flex items-center gap-2">
                  Public Mining
                  {status?.public_mining && <Badge variant="info">Active</Badge>}
                </div>
                <div className="text-sm text-gray-400">Accept connections from public miners via P2P routing</div>
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
              <div className="p-2 bg-gray-900/50 rounded">
                <div className="text-xs text-gray-500">Stratum V1</div>
                <code className="text-orange-400 text-sm">stratum+tcp://pool.bitcoinghost.org:3333</code>
              </div>
              <div className="p-2 bg-gray-900/50 rounded">
                <div className="text-xs text-gray-500">Stratum V2</div>
                <code className="text-orange-400 text-sm">stratum+tcp://pool.bitcoinghost.org:34265</code>
              </div>
              <p className="text-xs text-orange-300/70 mt-2">
                P2P routing automatically directs miners to this node based on location.
              </p>
            </div>
          </div>
        </div>

        {/* Payout Address Info */}
        <div className="mt-6 pt-6 border-t border-gray-800">
          <p className="text-xs text-gray-500">
            Configure payout addresses in{" "}
            <a href="/settings" className="text-orange-400 hover:text-orange-300 underline">
              Settings
            </a>
          </p>
        </div>
      </Card>

      <Card>
        <CardHeader title="Connected Miners" subtitle={miners.length > 0 ? `${miners.length} miners connected` : `${minersData?.total ?? 0} miners connected`} />
        {minersLoading ? (
          <SkeletonTable rows={5} cols={5} />
        ) : miners.length > 0 ? (
          <DataTable
            columns={minerColumns}
            data={miners}
            emptyMessage="No miners connected"
            showPagination={miners.length > 10}
          />
        ) : minersData && minersData.total > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-gray-800/50 rounded-lg text-center">
              <div className="text-2xl font-bold text-gray-100">{minersData.total}</div>
              <div className="text-sm text-gray-400">Connected Miners</div>
            </div>
            {minersData.total_hashrate_th !== undefined && (
              <div className="p-4 bg-gray-800/50 rounded-lg text-center">
                <div className="text-2xl font-bold text-gray-100">
                  {formatHashrate((minersData.total_hashrate_th ?? 0) * 1e12)}
                </div>
                <div className="text-sm text-gray-400">Total Hashrate</div>
              </div>
            )}
            {minersData.total_shares_accepted !== undefined && (
              <div className="p-4 bg-gray-800/50 rounded-lg text-center">
                <div className="text-2xl font-bold text-gray-100">
                  {(minersData.total_shares_accepted ?? 0).toLocaleString()}
                </div>
                <div className="text-sm text-gray-400">Shares Accepted</div>
              </div>
            )}
          </div>
        ) : (
          <div className="text-center py-8 text-gray-400">No miners connected</div>
        )}
      </Card>
    </div>
  );
}
