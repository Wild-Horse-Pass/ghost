"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { NetworkPayoutHistoryCard, GhostPayPayoutHistoryCard } from "@/components/PayoutHistoryCard";
import { useNetworkPayoutHistory, useGhostPayPayoutHistory } from "@/hooks/queries";
import { PageLoader } from "@/components/ui/PageLoader";
import type { PayoutHistoryTimeFilter } from "@/types/api";

function formatSats(satoshis: number): string {
  if (satoshis >= 100_000_000) {
    return `${(satoshis / 100_000_000).toFixed(4)} BTC`;
  }
  return `${satoshis.toLocaleString()} sats`;
}

export default function PayoutsPage() {
  const [networkTimeFilter, setNetworkTimeFilter] = useState<PayoutHistoryTimeFilter>("7d");
  const [gpTimeFilter, setGpTimeFilter] = useState<PayoutHistoryTimeFilter>("7d");

  const { data: payoutHistory, isLoading: payoutLoading } = useNetworkPayoutHistory(networkTimeFilter);
  const { data: gpPayoutHistory, isLoading: gpPayoutLoading } = useGhostPayPayoutHistory(gpTimeFilter);

  const summary = payoutHistory?.summary ?? {
    total_treasury_satoshis: 0,
    total_node_rewards_satoshis: 0,
    total_miner_rewards_satoshis: 0,
    blocks_in_period: 0,
  };

  if (payoutLoading && !payoutHistory) {
    return (
      <div className="space-y-6">
        <PageHeader title="Network Payouts" subtitle="Transparent record of all block reward distributions" />
        <PageLoader message="Loading payout data..." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Network Payouts"
        subtitle="Transparent record of all block reward distributions"
      />

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Treasury"
          value={formatSats(summary.total_treasury_satoshis)}
          sublabel="in period"
        />
        <StatCard
          label="Node Rewards"
          value={formatSats(summary.total_node_rewards_satoshis)}
          sublabel="in period"
        />
        <StatCard
          label="Miner Rewards"
          value={formatSats(summary.total_miner_rewards_satoshis)}
          sublabel="in period"
        />
        <StatCard
          label="Blocks"
          value={summary.blocks_in_period}
          sublabel="in period"
        />
      </div>

      {/* Network Payout History */}
      <SectionErrorBoundary section="Network Payout History">
        <NetworkPayoutHistoryCard
          entries={payoutHistory?.entries ?? []}
          summary={summary}
          isLoading={payoutLoading}
          timeFilter={networkTimeFilter}
          onTimeFilterChange={setNetworkTimeFilter}
        />
      </SectionErrorBoundary>

      {/* GhostPay Fee History */}
      <SectionErrorBoundary section="GhostPay Fee History">
        <GhostPayPayoutHistoryCard
          ghostpayFees={gpPayoutHistory?.ghostpay_fees ?? []}
          wraithFees={gpPayoutHistory?.wraith_fees ?? []}
          summary={gpPayoutHistory?.summary ?? { total_ghostpay_fees_satoshis: 0, total_wraith_fees_satoshis: 0, ghostpay_sessions_count: 0, wraith_sessions_count: 0 }}
          isLoading={gpPayoutLoading}
          timeFilter={gpTimeFilter}
          onTimeFilterChange={setGpTimeFilter}
        />
      </SectionErrorBoundary>
    </div>
  );
}
