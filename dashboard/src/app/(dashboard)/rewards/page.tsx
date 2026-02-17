"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { NodePayoutHistoryCard } from "@/components/PayoutHistoryCard";
import { useRewards, useNodePayoutHistory, useShares } from "@/hooks/queries";
import type { PayoutHistoryTimeFilter } from "@/types/api";

function formatShortBtc(btc: number): string {
  if (btc >= 1) return `${btc.toFixed(4)} BTC`;
  if (btc >= 0.01) return `${btc.toFixed(6)} BTC`;
  return `${btc.toFixed(8)} BTC`;
}

export default function RewardsPage() {
  const { data, isLoading } = useRewards();
  const { data: sharesData, isLoading: sharesLoading } = useShares();
  const [timeFilter, setTimeFilter] = useState<PayoutHistoryTimeFilter>("7d");
  const [payoutType, setPayoutType] = useState<string | undefined>(undefined);
  const { data: payoutHistory, isLoading: payoutLoading } = useNodePayoutHistory(timeFilter, payoutType);

  const summary = data?.summary ?? null;
  const shares = sharesData ?? null;
  const contributions = data?.share_contributions ?? [];
  const networkTotalShares = data?.network_total_shares ?? 0;
  const poolSharePercent = data?.your_share_of_pool_percent ?? 0;

  const statsLoading = isLoading || sharesLoading;

  return (
    <div className="space-y-6">
      <PageHeader title="Rewards" subtitle="Earnings and share contribution breakdown" />

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Total Earned"
          value={summary?.total_earned_all_time != null ? formatShortBtc(summary.total_earned_all_time) : "--"}
          loading={statsLoading}
        />
        <StatCard
          label="Pending"
          value={summary?.pending_btc != null ? formatShortBtc(summary.pending_btc) : "--"}
          loading={statsLoading}
        />
        <StatCard
          label="Pool Share"
          value={Number.isFinite(poolSharePercent) ? `${poolSharePercent.toFixed(4)}%` : "--"}
          loading={statsLoading}
        />
        <StatCard
          label="Network Shares"
          value={Number.isFinite(networkTotalShares) ? networkTotalShares.toLocaleString() : "--"}
          loading={statsLoading}
        />
      </div>

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

      {/* Payout History */}
      <SectionErrorBoundary section="Payout History">
        <NodePayoutHistoryCard
          entries={payoutHistory ?? []}
          isLoading={payoutLoading}
          timeFilter={timeFilter}
          onTimeFilterChange={setTimeFilter}
          payoutTypeFilter={payoutType}
          onPayoutTypeFilterChange={setPayoutType}
        />
      </SectionErrorBoundary>
    </div>
  );
}
