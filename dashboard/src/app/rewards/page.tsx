"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { getRewardsFull } from "@/lib/api";
import type {
  EarningsSummary,
  SharesInfo,
  ShareContribution,
  EarningsProjection,
  PayoutRecord,
  DailyEarning,
} from "@/types/api";

function formatBtc(btc: number): string {
  if (btc >= 0.001) {
    return `${btc.toFixed(8)} BTC`;
  }
  const sats = Math.floor(btc * 100_000_000);
  return `${sats.toLocaleString()} sats`;
}

function formatShortBtc(btc: number): string {
  if (btc >= 1) return `${btc.toFixed(4)} BTC`;
  if (btc >= 0.01) return `${btc.toFixed(6)} BTC`;
  return `${btc.toFixed(8)} BTC`;
}

function formatDate(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatTime(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });
}

// Simple sparkline component using ASCII bars
function EarningsChart({ data }: { data: DailyEarning[] }) {
  if (data.length === 0) {
    return <div className="text-gray-500 text-sm">No data</div>;
  }

  const max = Math.max(...data.map((d) => d.amount_btc));

  return (
    <div className="flex items-end gap-0.5 h-12">
      {data.slice(-30).map((day) => {
        const normalized = max > 0 ? day.amount_btc / max : 0;
        const height = Math.max(4, normalized * 48);
        return (
          <div
            key={day.date}
            className="w-2 bg-gradient-to-t from-blue-500 to-green-500 rounded-t"
            style={{ height: `${height}px` }}
            title={`${day.date}: ${formatShortBtc(day.amount_btc)}`}
          />
        );
      })}
    </div>
  );
}

export default function RewardsPage() {
  const [summary, setSummary] = useState<EarningsSummary | null>(null);
  const [shares, setShares] = useState<SharesInfo | null>(null);
  const [contributions, setContributions] = useState<ShareContribution[]>([]);
  const [networkTotalShares, setNetworkTotalShares] = useState(0);
  const [poolSharePercent, setPoolSharePercent] = useState(0);
  const [projections, setProjections] = useState<EarningsProjection | null>(null);
  const [payouts, setPayouts] = useState<PayoutRecord[]>([]);
  const [dailyEarnings, setDailyEarnings] = useState<DailyEarning[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const data = await getRewardsFull();
      setSummary(data.summary ?? null);
      setShares(data.shares ?? null);
      setContributions(data.share_contributions ?? []);
      setNetworkTotalShares(data.network_total_shares ?? 0);
      setPoolSharePercent(data.your_share_of_pool_percent ?? 0);
      setProjections(data.projections ?? null);
      setPayouts(data.payouts ?? []);
      setDailyEarnings(data.daily_earnings ?? []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 p-8">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-2xl font-bold text-gray-100 mb-6">Rewards</h1>
          <div className="animate-pulse space-y-6">
            <div className="h-48 bg-gray-800 rounded-lg"></div>
            <div className="h-64 bg-gray-800 rounded-lg"></div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-950 p-8">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-2xl font-bold text-gray-100 mb-6">Rewards</h1>
          <Card>
            <p className="text-red-400">Error: {error}</p>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-2xl font-bold text-gray-100 mb-6">Rewards</h1>

        {/* Earnings Summary */}
        <Card className="mb-6">
          <CardHeader title="Earnings Summary" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Total Earned (All Time)</span>
                  <span className="text-2xl font-bold text-yellow-400">
                    {formatShortBtc(summary?.total_earned_all_time ?? 0)}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">This Month</span>
                  <span className="text-lg font-medium text-gray-100">
                    {formatShortBtc(summary?.earned_this_month ?? 0)}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">This Week</span>
                  <span className="text-lg font-medium text-gray-100">
                    {formatShortBtc(summary?.earned_this_week ?? 0)}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Today</span>
                  <span className="text-lg font-medium text-green-400">
                    {formatShortBtc(summary?.earned_today ?? 0)}
                  </span>
                </div>
              </div>
            </div>
            <div>
              <div className="text-sm text-gray-400 mb-2">30-Day Earnings</div>
              <EarningsChart data={dailyEarnings} />
            </div>
          </div>
        </Card>

        {/* Your Shares */}
        <Card className="mb-6">
          <CardHeader title="Your Shares" />
          <div className="mb-4">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-3xl font-bold text-gray-100">
                {shares?.total ?? 0}
              </span>
              <span className="text-gray-400">/ {shares?.max_shares ?? 15} possible</span>
            </div>
            {!shares?.uptime_qualified && (
              <div className="p-2 bg-red-900/20 border border-red-800 rounded text-sm text-red-400">
                Uptime below 95% - shares currently not earning. Current: {shares?.uptime_percent?.toFixed(1)}%
              </div>
            )}
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-gray-400 text-sm border-b border-gray-800">
                  <th className="pb-3 font-medium">Tier</th>
                  <th className="pb-3 font-medium text-center">Bonus</th>
                  <th className="pb-3 font-medium text-center">Status</th>
                  <th className="pb-3 font-medium text-right">Earnings Contribution</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {contributions.map((contrib) => (
                  <tr key={contrib.tier} className="text-gray-100">
                    <td className="py-3">{contrib.tier}</td>
                    <td className="py-3 text-center">
                      <Badge variant={contrib.enabled ? "success" : "default"}>
                        +{contrib.bonus}
                      </Badge>
                    </td>
                    <td className="py-3 text-center">
                      {contrib.enabled ? (
                        contrib.tier === "Elder Status" && shares?.elder_slot ? (
                          <span className="text-green-400">#{shares.elder_slot}</span>
                        ) : (
                          <span className="text-green-400">Enabled</span>
                        )
                      ) : (
                        <span className="text-gray-500">(not enabled)</span>
                      )}
                    </td>
                    <td className="py-3 text-right">
                      {contrib.enabled && contrib.contribution_percent != null ? (
                        <span className="text-gray-100">
                          ~{contrib.contribution_percent.toFixed(0)}% of your rewards
                        </span>
                      ) : (
                        <span className="text-gray-500">-</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-4 pt-4 border-t border-gray-800 text-sm text-gray-400">
            <div className="flex justify-between">
              <span>Network Total Shares:</span>
              <span className="text-gray-100">{networkTotalShares.toLocaleString()}</span>
            </div>
            <div className="flex justify-between mt-1">
              <span>Your Share of Pool:</span>
              <span className="text-gray-100">{poolSharePercent.toFixed(4)}%</span>
            </div>
          </div>
        </Card>

        {/* Earnings Projection */}
        <Card className="mb-6">
          <CardHeader title="Earnings Projection" />
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-green-400">
                {formatShortBtc(projections?.daily ?? 0)}
              </div>
              <div className="text-sm text-gray-400">Daily</div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-green-400">
                {formatShortBtc(projections?.weekly ?? 0)}
              </div>
              <div className="text-sm text-gray-400">Weekly</div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-green-400">
                {formatShortBtc(projections?.monthly ?? 0)}
              </div>
              <div className="text-sm text-gray-400">Monthly</div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-green-400">
                {formatShortBtc(projections?.yearly ?? 0)}
              </div>
              <div className="text-sm text-gray-400">Yearly</div>
            </div>
          </div>

          {projections && (projections.potential_increase_percent ?? 0) > 0 && (
            <div className="p-4 bg-blue-900/20 border border-blue-800 rounded-lg">
              <p className="text-blue-300 text-sm">
                If you enable all share tiers (Public Mining +3, Bitcoin Pure +2):
              </p>
              <p className="text-blue-100 font-medium mt-1">
                Daily: {formatShortBtc(projections.daily_with_all_shares ?? 0)} (+{(projections.potential_increase_percent ?? 0).toFixed(0)}%)
              </p>
            </div>
          )}
        </Card>

        {/* Payout Breakdown by Type */}
        {payouts.length > 0 && (
          <Card className="mb-6">
            <CardHeader title="Network Payout Breakdown" subtitle="Total allocations by type" />
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              {/* Treasury */}
              <div className="text-center p-4 bg-yellow-900/20 border border-yellow-800/50 rounded-lg">
                <div className="text-lg font-bold text-yellow-400">
                  {formatShortBtc(payouts.filter(p => p.payout_type === "treasury").reduce((sum, p) => sum + p.amount_btc, 0))}
                </div>
                <div className="text-sm text-gray-400">Treasury</div>
                <div className="text-xs text-gray-500">{payouts.filter(p => p.payout_type === "treasury").length} payouts</div>
              </div>
              {/* Node Reward Pool */}
              <div className="text-center p-4 bg-green-900/20 border border-green-800/50 rounded-lg">
                <div className="text-lg font-bold text-green-400">
                  {formatShortBtc(payouts.filter(p => p.payout_type === "node_reward").reduce((sum, p) => sum + p.amount_btc, 0))}
                </div>
                <div className="text-sm text-gray-400">Node Reward Pool</div>
                <div className="text-xs text-gray-500">{payouts.filter(p => p.payout_type === "node_reward").length} payouts</div>
              </div>
              {/* Mining Rewards */}
              <div className="text-center p-4 bg-blue-900/20 border border-blue-800/50 rounded-lg">
                <div className="text-lg font-bold text-blue-400">
                  {formatShortBtc(payouts.filter(p => p.payout_type === "mining").reduce((sum, p) => sum + p.amount_btc, 0))}
                </div>
                <div className="text-sm text-gray-400">Mining Rewards</div>
                <div className="text-xs text-gray-500">{payouts.filter(p => p.payout_type === "mining").length} payouts</div>
              </div>
              {/* Pool Fee */}
              <div className="text-center p-4 bg-gray-800/50 border border-gray-700/50 rounded-lg">
                <div className="text-lg font-bold text-gray-300">
                  {formatShortBtc(payouts.filter(p => p.payout_type === "pool_fee").reduce((sum, p) => sum + p.amount_btc, 0))}
                </div>
                <div className="text-sm text-gray-400">Pool Fee</div>
                <div className="text-xs text-gray-500">{payouts.filter(p => p.payout_type === "pool_fee").length} payouts</div>
              </div>
              {/* Block TX Fees */}
              <div className="text-center p-4 bg-purple-900/20 border border-purple-800/50 rounded-lg">
                <div className="text-lg font-bold text-purple-400">
                  {formatShortBtc(payouts.filter(p => p.payout_type === "tx_fee").reduce((sum, p) => sum + p.amount_btc, 0))}
                </div>
                <div className="text-sm text-gray-400">Block TX Fees</div>
                <div className="text-xs text-gray-500">{payouts.filter(p => p.payout_type === "tx_fee").length} payouts</div>
              </div>
            </div>
          </Card>
        )}

        {/* Payout History */}
        <Card>
          <CardHeader
            title="Payout History"
            subtitle={`${payouts.length} payouts received`}
            action={
              <button className="text-sm text-blue-400 hover:text-blue-300">
                Export CSV
              </button>
            }
          />
          {payouts.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-gray-400">No payouts yet</p>
              <p className="text-sm text-gray-500 mt-1">
                Keep mining to earn your first reward!
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-gray-400 text-sm border-b border-gray-800">
                    <th className="pb-3 font-medium">Date</th>
                    <th className="pb-3 font-medium">Block</th>
                    <th className="pb-3 font-medium">Type</th>
                    <th className="pb-3 font-medium text-right">Amount</th>
                    <th className="pb-3 font-medium">TxID</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {payouts.slice(0, 20).map((payout, idx) => (
                    <tr key={payout.txid || idx} className="text-gray-100">
                      <td className="py-3">
                        <div>{formatDate(payout.timestamp)}</div>
                        <div className="text-xs text-gray-500">
                          {formatTime(payout.timestamp)}
                        </div>
                      </td>
                      <td className="py-3 font-mono text-gray-400">
                        {(payout.block_height ?? 0).toLocaleString()}
                      </td>
                      <td className="py-3">
                        <Badge variant={
                          payout.payout_type === "mining" ? "info" :
                          payout.payout_type === "node_reward" ? "success" :
                          payout.payout_type === "treasury" ? "warning" :
                          payout.payout_type === "pool_fee" ? "default" :
                          payout.payout_type === "tx_fee" ? "info" :
                          "default"
                        }>
                          {payout.payout_type === "mining" ? "Mining Reward" :
                           payout.payout_type === "node_reward" ? "Node Reward" :
                           payout.payout_type === "treasury" ? "Treasury" :
                           payout.payout_type === "pool_fee" ? "Pool Fee" :
                           payout.payout_type === "tx_fee" ? "Block TX Fee" :
                           payout.payout_type}
                        </Badge>
                      </td>
                      <td className="py-3 font-mono text-green-400 text-right">
                        +{formatBtc(payout.amount_btc)}
                      </td>
                      <td className="py-3">
                        <a
                          href={`https://mempool.space/tx/${payout.txid ?? ""}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-mono text-blue-400 hover:text-blue-300 text-sm"
                        >
                          {(payout.txid ?? "").slice(0, 8)}...
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {payouts.length > 20 && (
                <div className="mt-4 text-center">
                  <button className="text-sm text-blue-400 hover:text-blue-300">
                    Load More ({payouts.length - 20} remaining)
                  </button>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
