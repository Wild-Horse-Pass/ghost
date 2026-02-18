"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { CopyButton } from "@/components/ui/CopyButton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { DataTable, formatHashrate, formatDuration } from "@/components/ui/DataTable";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useMiningStatus, useMiners, useBestHash, useSetPrivateMining, useSetPublicMining } from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { useQueryClient } from "@tanstack/react-query";
import type { MinerInfo, BestHashEntry } from "@/types/api";
import type { ColumnDef } from "@tanstack/react-table";

const TOOLTIPS = {
  hashrate: "Combined hashrate of all miners connected to your node's stratum port. Updated every few seconds from share submissions.",
  connected_miners: "Number of mining devices currently connected to your stratum port and actively submitting shares.",
  shares_round: "Total accepted shares in the current mining round. The accept rate shows valid vs rejected shares.",
  blocks_found: "Total blocks your pool has found since first startup. Each block found triggers a payout distribution.",
  best_hash: "The lowest (best) hash value submitted by miners. More leading zeros means closer to finding a block. Measured by share difficulty.",
};

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

type MiningMode = "private_solo" | "private_pool" | "pool";

function getMiningMode(privateMining?: boolean, publicMining?: boolean): MiningMode {
  if (privateMining && publicMining) return "private_pool";
  if (publicMining) return "pool";
  return "private_solo"; // default: private solo (includes both-off state)
}

const MODES: { key: MiningMode; label: string; desc: string }[] = [
  { key: "private_solo", label: "Private Solo", desc: "Your miners only. Stratum port closed to external connections. All block rewards go to you." },
  { key: "private_pool", label: "Private Pool", desc: "Your miners + accept public miners. You operate a public pool and share rewards with connected miners." },
  { key: "pool", label: "Pool", desc: "Public pool only. No private mining — your node acts as a pool server for external miners." },
];

export default function MiningPage() {
  const { data: status, isLoading: statusLoading } = useMiningStatus();
  const { data: minersData, isLoading: minersLoading } = useMiners();
  const { data: bestHashData, isLoading: bestHashLoading } = useBestHash();
  const setPrivateMining = useSetPrivateMining();
  const setPublicMining = useSetPublicMining();
  const queryClient = useQueryClient();
  const { addToast } = useToast();

  const miners = minersData?.miners ?? [];
  const nodeHost = typeof window !== "undefined" ? window.location.hostname : "localhost";
  const isPending = setPrivateMining.isPending || setPublicMining.isPending;

  const currentMode = getMiningMode(status?.private_mining, status?.public_mining);

  const handleModeChange = async (mode: MiningMode) => {
    if (mode === currentMode || isPending) return;
    try {
      switch (mode) {
        case "private_solo":
          await setPublicMining.mutateAsync(false);
          await setPrivateMining.mutateAsync(true);
          break;
        case "private_pool":
          await setPrivateMining.mutateAsync(true);
          await setPublicMining.mutateAsync(true);
          break;
        case "pool":
          await setPrivateMining.mutateAsync(false);
          await setPublicMining.mutateAsync(true);
          break;
      }
      await queryClient.invalidateQueries({ queryKey: ["mining"] });
      await queryClient.invalidateQueries({ queryKey: ["config"] });
      addToast({ type: "success", title: `Mining mode: ${MODES.find(m => m.key === mode)?.label}` });
    } catch (err: unknown) {
      const message = err instanceof Error
        ? err.message
        : typeof err === "object" && err !== null && "message" in err
          ? String((err as { message: unknown }).message)
          : "Failed to update mining mode";
      addToast({ type: "error", title: message });
    }
  };

  const totalSubmitted = status?.shares_submitted ?? 0;
  const totalAccepted = status?.shares_accepted ?? 0;
  const acceptRate = totalSubmitted > 0 ? ((totalAccepted / totalSubmitted) * 100).toFixed(1) : "0";

  // Show stratum endpoints based on mode
  const showPrivateEndpoints = currentMode === "private_solo" || currentMode === "private_pool";
  const showPublicEndpoints = currentMode === "private_pool" || currentMode === "pool";

  return (
    <div className="space-y-6">
      <PageHeader title="Mining" subtitle="Hashrate, miners, and mining configuration" />

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Hashrate"
          value={status ? formatHashrate((status.hashrate_th ?? 0) * 1e12) : "--"}
          sublabel="pool combined"
          tooltip={TOOLTIPS.hashrate}
          loading={statusLoading}
        />
        <StatCard
          label="Connected Miners"
          value={status?.connected_miners ?? 0}
          sublabel="active workers"
          tooltip={TOOLTIPS.connected_miners}
          loading={statusLoading}
        />
        <StatCard
          label="Shares / Round"
          value={(totalAccepted).toLocaleString()}
          sublabel={`${acceptRate}% accept rate`}
          tooltip={TOOLTIPS.shares_round}
          loading={statusLoading}
        />
        <StatCard
          label="Blocks Found"
          value={status?.blocks_found ?? 0}
          sublabel="all time"
          tooltip={TOOLTIPS.blocks_found}
          loading={statusLoading}
        />
      </div>

      {/* Mining Mode */}
      <SectionErrorBoundary section="Mining Mode">
        <Card>
          <CardHeader title="Mining Mode" subtitle="Select how your node participates in mining" />

          {/* Mode selector - 3 radio-style options */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-6">
            {MODES.map(({ key, label, desc }) => {
              const isActive = currentMode === key;
              return (
                <button
                  key={key}
                  onClick={() => handleModeChange(key)}
                  disabled={isPending}
                  className={`p-4 rounded-lg border text-left transition-all ${
                    isActive
                      ? "bg-orange-900/20 border-orange-600 ring-1 ring-orange-600/50"
                      : "bg-gray-800/30 border-gray-700 hover:border-gray-600"
                  } ${isPending ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <div className={`w-3 h-3 rounded-full border-2 flex items-center justify-center ${
                      isActive ? "border-orange-500" : "border-gray-600"
                    }`}>
                      {isActive && <div className="w-1.5 h-1.5 rounded-full bg-orange-500" />}
                    </div>
                    <span className={`font-medium ${isActive ? "text-orange-400" : "text-gray-300"}`}>{label}</span>
                    {isActive && <Badge variant="success">Active</Badge>}
                  </div>
                  <div className="text-xs text-gray-500 ml-5">{desc}</div>
                </button>
              );
            })}
          </div>

          {/* Connection endpoints */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {showPrivateEndpoints && (
              <div className="p-4 bg-gray-800/30 rounded-lg border border-gray-700">
                <div className="text-sm text-gray-300 font-medium mb-3">Your Stratum Endpoints</div>
                <div className="space-y-2">
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
            )}
            {showPublicEndpoints && (
              <div className="p-4 bg-gray-800/30 rounded-lg border border-gray-700">
                <div className="text-sm text-gray-300 font-medium mb-3">Public Pool Endpoints</div>
                <div className="space-y-2">
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
            )}
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Best Hashes */}
      <SectionErrorBoundary section="Best Hashes">
        <Card>
          <CardHeader
            title="Best Hashes"
            subtitle="Lowest hash values achieved by connected miners — more leading zeros means closer to winning a block"
          />
          {bestHashLoading ? (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <SkeletonCard /><SkeletonCard /><SkeletonCard /><SkeletonCard />
            </div>
          ) : (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <BestHashCard title="Current Round" entry={bestHashData?.current_round} />
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
            subtitle={`${minersData?.total ?? miners.length} miners connected this round`}
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
