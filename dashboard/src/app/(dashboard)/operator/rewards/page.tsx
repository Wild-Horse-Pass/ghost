"use client";

import { useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { NodePayoutHistoryCard } from "@/components/PayoutHistoryCard";
import { useRewards, useNodePayoutHistory } from "@/hooks/queries";
import type { PayoutHistoryTimeFilter } from "@/types/api";

function formatShortBtc(btc: number): string {
  if (btc >= 1) return `${btc.toFixed(4)} BTC`;
  if (btc >= 0.01) return `${btc.toFixed(6)} BTC`;
  return `${btc.toFixed(8)} BTC`;
}

export default function RewardsPage() {
  const { data, isLoading } = useRewards();
  const [nodePayoutTimeFilter, setNodePayoutTimeFilter] = useState<PayoutHistoryTimeFilter>("7d");
  const [nodePayoutTypeFilter, setNodePayoutTypeFilter] = useState<string | undefined>(undefined);
  const { data: nodePayoutHistory, isLoading: nodePayoutLoading } = useNodePayoutHistory(nodePayoutTimeFilter, nodePayoutTypeFilter);

  const summary = data?.summary ?? null;
  const shares = data?.shares ?? null;
  const contributions = data?.share_contributions ?? [];
  const networkTotalShares = data?.network_total_shares ?? 0;
  const poolSharePercent = data?.your_share_of_pool_percent ?? 0;

  return (
    <div className="space-y-3">
      <h1 className="text-lg font-bold text-gray-100">Rewards</h1>

      {/* Earnings Summary */}
      {isLoading ? (
        <SkeletonCard />
      ) : (
        <Card className="p-3">
          <CardHeader title="Node Rewards" />
          <div className="p-4 bg-gradient-to-br from-yellow-900/30 to-orange-900/20 border border-yellow-800/50 rounded-lg">
            <div className="text-xs text-yellow-500 uppercase tracking-wide mb-1">
              Lifetime Earnings
            </div>
            <div className="text-2xl font-bold text-yellow-400">
              {formatShortBtc(summary?.total_earned_all_time ?? 0)}
            </div>
            <div className="text-xs text-gray-500 mt-1">
              Node rewards received
            </div>
          </div>
        </Card>
      )}

      {/* Your Shares */}
      {isLoading ? (
        <SkeletonCard />
      ) : (
        <Card className="p-3">
          <CardHeader title="Your Shares" />
          <div className="mb-2">
            <div className="flex items-center gap-2">
              <span className="text-xl font-bold text-gray-100">{shares?.total ?? 0}</span>
              <span className="text-xs text-gray-400">/ {shares?.max_shares ?? 15} possible</span>
            </div>
            {shares && !shares.uptime_qualified && (
              <div className="p-1.5 mt-1 bg-red-900/20 border border-red-800 rounded text-xs text-red-400">
                Uptime below 95% - shares not earning. Current: {shares.uptime_percent?.toFixed(1)}%
              </div>
            )}
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-gray-400 border-b border-gray-800">
                  <th className="pb-1.5 font-medium">Tier</th>
                  <th className="pb-1.5 font-medium text-center">Bonus</th>
                  <th className="pb-1.5 font-medium text-center">Status</th>
                  <th className="pb-1.5 font-medium text-right">Contribution</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {contributions.map((contrib) => (
                  <tr key={contrib.tier} className="text-gray-100">
                    <td className="py-1.5">{contrib.tier}</td>
                    <td className="py-1.5 text-center">
                      <Badge variant={contrib.enabled ? "success" : "default"}>
                        +{contrib.bonus}
                      </Badge>
                    </td>
                    <td className="py-1.5 text-center">
                      {contrib.enabled ? (
                        contrib.tier === "Elder Status" && shares?.elder_slot ? (
                          <span className="text-green-400">#{shares.elder_slot}</span>
                        ) : (
                          <span className="text-green-400">Enabled</span>
                        )
                      ) : (
                        <span className="text-gray-500">-</span>
                      )}
                    </td>
                    <td className="py-1.5 text-right">
                      {contrib.enabled && contrib.contribution_percent != null ? (
                        <span className="text-gray-100">~{contrib.contribution_percent.toFixed(0)}%</span>
                      ) : (
                        <span className="text-gray-500">-</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-2 pt-2 border-t border-gray-800 text-xs text-gray-400">
            <div className="flex justify-between">
              <span>Network Total:</span>
              <span className="text-gray-100">{networkTotalShares.toLocaleString()}</span>
            </div>
            <div className="flex justify-between">
              <span>Your Share:</span>
              <span className="text-gray-100">{poolSharePercent.toFixed(4)}%</span>
            </div>
          </div>
        </Card>
      )}

      {/* Node Payout History (this node only) */}
      <NodePayoutHistoryCard
        entries={nodePayoutHistory ?? []}
        isLoading={nodePayoutLoading}
        timeFilter={nodePayoutTimeFilter}
        onTimeFilterChange={setNodePayoutTimeFilter}
        payoutTypeFilter={nodePayoutTypeFilter}
        onPayoutTypeFilterChange={setNodePayoutTypeFilter}
      />
    </div>
  );
}
