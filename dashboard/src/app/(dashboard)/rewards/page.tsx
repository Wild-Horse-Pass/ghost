"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { DataTable } from "@/components/ui/DataTable";
import { SkeletonCard, SkeletonTable } from "@/components/ui/Skeleton";
import { useRewards, useNodeBalances, useShares } from "@/hooks/queries";
import type { NodeBalanceEntry } from "@/lib/api/rewards";
import type { ColumnDef } from "@tanstack/react-table";

const TOOLTIPS = {
  total_earned: "Total rewards earned by this node since first joining the network. Includes node pool rewards, block tx fees, and L2 fees.",
  pending: "Rewards accumulated but not yet paid out. Payouts happen when a block is found and the coinbase matures.",
  pool_share: "Your node's percentage of the total network reward pool, based on your share count vs all nodes combined.",
  network_shares: "Total shares across all active nodes in the network. Your pool share = your shares / network total shares.",
};

const REWARD_SOURCES = [
  {
    name: "Node Reward Pool",
    desc: "Earned via the 5-4-3-2-1 share system. Each block reward allocates a portion to the node reward pool, distributed proportionally by verified shares.",
    color: "bg-green-500",
  },
  {
    name: "Block TX Fees",
    desc: "When your pool finds a block, transaction fees from the block are distributed to the winning node's miners and node operators.",
    color: "bg-orange-500",
  },
  {
    name: "Ghost Pay L2 Fees",
    desc: "Fees collected from L2 payment channel operations (instant payments, channel opens/closes). Earned by nodes running Ghost Pay.",
    color: "bg-purple-500",
  },
  {
    name: "Wraith Mixing Fees",
    desc: "Fees from CoinJoin mixing sessions coordinated through the Wraith protocol. Earned by nodes facilitating privacy mixing rounds.",
    color: "bg-red-500",
  },
];

function formatShortBtc(btc: number): string {
  if (btc >= 1) return `${btc.toFixed(4)} BTC`;
  if (btc >= 0.01) return `${btc.toFixed(6)} BTC`;
  return `${btc.toFixed(8)} BTC`;
}

function formatSats(satoshis: number): string {
  if (satoshis >= 100_000_000) {
    return `${(satoshis / 100_000_000).toFixed(4)} BTC`;
  }
  return `${satoshis.toLocaleString()} sats`;
}

function formatTimestamp(timestamp: number): string {
  if (!timestamp) return "—";
  const date = new Date(timestamp * 1000);
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const nodeBalanceColumns: ColumnDef<NodeBalanceEntry>[] = [
  {
    id: "rank",
    header: "#",
    cell: ({ row }) => (
      <span className="text-gray-500 text-sm">{row.index + 1}</span>
    ),
  },
  {
    accessorKey: "node_id",
    header: "Node",
    cell: ({ row }) => (
      <div className="flex items-center gap-2">
        <span className="font-mono text-sm text-gray-300">
          {row.original.node_id.slice(0, 12)}...
        </span>
        {row.original.is_self && (
          <Badge variant="success">You</Badge>
        )}
      </div>
    ),
  },
  {
    accessorKey: "balance_sats",
    header: "Balance",
    cell: ({ row }) => (
      <span className="font-mono text-green-400">
        {formatSats(row.original.balance_sats)}
      </span>
    ),
  },
  {
    accessorKey: "total_credits_sats",
    header: "Lifetime Earned",
    cell: ({ row }) => (
      <span className="font-mono text-gray-300">
        {formatSats(row.original.total_credits_sats)}
      </span>
    ),
  },
  {
    accessorKey: "total_withdrawals_sats",
    header: "Withdrawn",
    cell: ({ row }) => (
      <span className="font-mono text-gray-400">
        {formatSats(row.original.total_withdrawals_sats)}
      </span>
    ),
  },
  {
    accessorKey: "last_credited_round",
    header: "Last Credit",
    cell: ({ row }) => (
      <span className="text-gray-400 text-sm">
        Round #{row.original.last_credited_round}
      </span>
    ),
  },
  {
    accessorKey: "updated_at",
    header: "Updated",
    cell: ({ row }) => (
      <span className="text-gray-500 text-sm">
        {formatTimestamp(row.original.updated_at)}
      </span>
    ),
  },
];

export default function RewardsPage() {
  const { data, isLoading } = useRewards();
  const { data: sharesData, isLoading: sharesLoading } = useShares();
  const { data: balancesData, isLoading: balancesLoading } = useNodeBalances();

  const summary = data?.summary ?? null;
  const shares = sharesData ?? null;
  const contributions = data?.share_contributions ?? [];
  const networkTotalShares = data?.network_total_shares ?? 0;
  const poolSharePercent = data?.your_share_of_pool_percent ?? 0;

  const nodeBalances = balancesData?.history ?? [];
  // Sort by balance descending (highest balance first)
  const sortedBalances = [...nodeBalances].sort((a, b) => b.balance_sats - a.balance_sats);

  const statsLoading = isLoading || sharesLoading;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="rewards" title="Earnings, shares, balance." subtitle="Earnings, share breakdown, and node balance accounts" />

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Total Earned"
          value={summary?.total_earned_all_time != null ? formatShortBtc(summary.total_earned_all_time) : "--"}
          tooltip={TOOLTIPS.total_earned}
          loading={statsLoading}
        />
        <StatCard
          label="Pending"
          value={summary?.pending_btc != null ? formatShortBtc(summary.pending_btc) : "--"}
          tooltip={TOOLTIPS.pending}
          loading={statsLoading}
        />
        <StatCard
          label="Pool Share"
          value={Number.isFinite(poolSharePercent) ? `${poolSharePercent.toFixed(4)}%` : "--"}
          tooltip={TOOLTIPS.pool_share}
          loading={statsLoading}
        />
        <StatCard
          label="Network Shares"
          value={Number.isFinite(networkTotalShares) ? networkTotalShares.toLocaleString() : "--"}
          tooltip={TOOLTIPS.network_shares}
          loading={statsLoading}
        />
      </div>

      {/* Reward Sources */}
      <SectionErrorBoundary section="Reward Sources">
        <Card>
          <CardHeader title="Where Rewards Come From" subtitle="Nodes earn from multiple revenue streams" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {REWARD_SOURCES.map((source) => (
              <div key={source.name} className="flex items-start gap-3 p-3 bg-gray-800/30 rounded-lg">
                <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${source.color}`} />
                <div>
                  <div className="text-sm font-medium text-gray-200">{source.name}</div>
                  <div className="text-xs text-gray-500 mt-0.5">{source.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Share Contribution Breakdown */}
      <SectionErrorBoundary section="Share Contribution">
        {sharesLoading || isLoading ? (
          <SkeletonCard />
        ) : (
          <Card>
            <CardHeader
              title="Share Contribution"
              subtitle="Which capabilities contribute to your rewards"
              action={
                shares && (
                  <span className="text-lg font-bold text-gray-100">
                    {shares.total}<span className="text-gray-500 text-sm"> / {shares.max_shares}</span>
                  </span>
                )
              }
            />

            {shares && !shares.uptime_qualified && (
              <div className="mb-4 p-3 rounded-lg bg-red-900/20 border border-red-800">
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-red-400">&#10007;</span>
                  <span className="text-gray-300">Uptime below 95%</span>
                  <Badge variant="error">{(shares.uptime_percent ?? 0).toFixed(1)}%</Badge>
                </div>
                <p className="text-xs text-red-400 mt-1">All shares disabled until uptime recovers</p>
              </div>
            )}

            <div className="space-y-3">
              {contributions.map((contrib) => {
                const isActive = contrib.enabled;
                const disabled = shares ? !shares.uptime_qualified : false;
                const percent = (contrib.contribution_percent ?? 0);

                return (
                  <div key={contrib.tier} className="space-y-1">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Badge variant={isActive && !disabled ? "success" : "default"}>+{contrib.bonus}</Badge>
                        <span className={isActive && !disabled ? "text-gray-100 text-sm" : "text-gray-500 text-sm"}>
                          {contrib.tier}
                        </span>
                        {contrib.tier === "Elder Status" && shares?.elder_slot && (
                          <span className="text-xs text-gray-500">#{shares.elder_slot}</span>
                        )}
                      </div>
                      <span className="text-sm text-gray-400">
                        {isActive && Number.isFinite(percent) ? `${percent.toFixed(0)}%` : "--"}
                      </span>
                    </div>
                    <ProgressBar
                      value={isActive && !disabled ? percent : 0}
                      color={isActive && !disabled ? "orange" : "gray"}
                      size="sm"
                    />
                  </div>
                );
              })}
            </div>

            <div className="mt-4 pt-4 border-t border-gray-800 text-sm text-gray-400">
              <div className="flex justify-between">
                <span>Network Total Shares:</span>
                <span className="text-gray-100 font-mono">
                  {Number.isFinite(networkTotalShares) ? networkTotalShares.toLocaleString() : "0"}
                </span>
              </div>
              <div className="flex justify-between mt-1">
                <span>Your Pool Share:</span>
                <span className="text-gray-100 font-mono">
                  {Number.isFinite(poolSharePercent) ? poolSharePercent.toFixed(4) : "0.0000"}%
                </span>
              </div>
            </div>
          </Card>
        )}
      </SectionErrorBoundary>

      {/* Node Balance Accounts */}
      <SectionErrorBoundary section="Node Balance Accounts">
        <Card>
          <CardHeader
            title="Node Balance Accounts"
            subtitle={`${balancesData?.total ?? sortedBalances.length} nodes with reward balances`}
          />
          {balancesLoading ? (
            <SkeletonTable rows={5} cols={6} />
          ) : (
            <DataTable
              columns={nodeBalanceColumns}
              data={sortedBalances}
              emptyMessage="No node balances yet"
              emptyDescription="Balances accumulate as blocks are found and rewards are distributed"
              searchColumn="node_id"
              searchPlaceholder="Search by node ID..."
              showPagination={sortedBalances.length > 20}
            />
          )}
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
