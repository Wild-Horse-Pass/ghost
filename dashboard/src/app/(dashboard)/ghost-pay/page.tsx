"use client";

import { useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { GhostPayPayoutHistoryCard } from "@/components/PayoutHistoryCard";
import {
  useGhostPayStatus,
  useWraithStats,
  useSettlementStatus,
  useGhostPayPayoutHistory,
} from "@/hooks/queries";
import type { PayoutHistoryTimeFilter } from "@/types/api";

type HealthStatus = "healthy" | "warning" | "unknown";

function getHealthBadge(status: HealthStatus) {
  const variants: Record<HealthStatus, "success" | "warning" | "default"> = {
    healthy: "success",
    warning: "warning",
    unknown: "default",
  };
  const labels: Record<HealthStatus, string> = {
    healthy: "Healthy",
    warning: "Warning",
    unknown: "Unknown",
  };
  return <Badge variant={variants[status]}>{labels[status]}</Badge>;
}

// Format L2 block with era prefix: "1:45,230" or just "45,230" for era 1
function formatL2Block(era: number, height: number): string {
  if (era <= 1) {
    return height.toLocaleString();
  }
  return `${era}:${height.toLocaleString()}`;
}

// Format epoch with era prefix
function formatEpoch(era: number, epoch: number): string {
  if (era <= 1) {
    return epoch.toLocaleString();
  }
  return `${era}:${epoch.toLocaleString()}`;
}

export default function GhostPayPage() {
  const [payoutTimeFilter, setPayoutTimeFilter] = useState<PayoutHistoryTimeFilter>("7d");

  const { data: status, isLoading: statusLoading } = useGhostPayStatus();
  const { data: wraithStats, isLoading: wraithLoading } = useWraithStats();
  const { data: reconciliation, isLoading: reconciliationLoading } = useSettlementStatus();
  const { data: payoutHistory, isLoading: payoutLoading } = useGhostPayPayoutHistory(payoutTimeFilter);

  const isLoading = statusLoading || wraithLoading || reconciliationLoading;

  const l2Era = status?.l2_era || 1;
  const l2Height = status?.l2_height || status?.block_height || 0;
  const epoch = status?.epoch || 0;

  const consensusHealth: HealthStatus = status?.peer_count !== undefined && status.peer_count > 0 ? "healthy" :
    status?.sync_state === "syncing" ? "warning" : "unknown";
  const l1Health: HealthStatus = reconciliation?.l1_available === true ? "healthy" :
    reconciliation?.l1_available === false ? "warning" : "unknown";
  const wraithHealth: HealthStatus = wraithStats?.active_sessions !== undefined ? "healthy" : "unknown";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">Ghost Pay</h1>
        {status && (
          <div className="flex items-center gap-2 text-sm text-gray-400">
            {l2Era > 1 && <span className="text-cyan-400">Era {l2Era}</span>}
            <span>Epoch {formatEpoch(l2Era, epoch)}</span>
            <span className="text-gray-600">|</span>
            <span>Block {formatL2Block(l2Era, l2Height)}</span>
          </div>
        )}
      </div>

      {/* Health Indicators */}
      {isLoading ? (
        <SkeletonCard />
      ) : (
        <Card>
          <CardHeader title="System Health" />
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-gray-800/50 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-400">L2 Consensus</span>
                {getHealthBadge(consensusHealth)}
              </div>
              <div className="text-xs text-gray-500">
                {status?.sync_state || status?.network || "Unknown"} · {status?.peer_count || 0} peers
              </div>
            </div>
            <div className="p-4 bg-gray-800/50 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-400">L1 Connection</span>
                {getHealthBadge(l1Health)}
              </div>
              <div className="text-xs text-gray-500">
                {reconciliation?.l1_available ? `Block ${reconciliation.l1_height?.toLocaleString()}` : "Awaiting connection"}
              </div>
            </div>
            <div className="p-4 bg-gray-800/50 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-400">Wraith Service</span>
                {getHealthBadge(wraithHealth)}
              </div>
              <div className="text-xs text-gray-500">
                {wraithStats?.active_sessions || 0} active sessions
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Stats Overview */}
      {isLoading ? (
        <SkeletonCard />
      ) : (
        <Card>
          <CardHeader title="Network Stats" />
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-yellow-400">
                {formatL2Block(l2Era, l2Height)}
              </div>
              <div className="text-sm text-gray-400">L2 Block Height</div>
              <div className="text-xs text-gray-500 mt-1">
                Epoch {formatEpoch(l2Era, epoch)}
              </div>
            </div>
            <div className="p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-orange-400">
                {wraithStats?.active_sessions || 0}
              </div>
              <div className="text-sm text-gray-400">Active Mix Sessions</div>
              <div className="text-xs text-gray-500 mt-1">
                {wraithStats?.total_participants || 0} participants
              </div>
            </div>
            <div className="p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-orange-400">
                {reconciliation?.active_count || 0}
              </div>
              <div className="text-sm text-gray-400">Reconciliation Batches</div>
              <div className="text-xs text-gray-500 mt-1">
                {reconciliation?.pending_count || 0} pending
              </div>
            </div>
            <div className="p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-orange-400">
                {reconciliation?.batches_24h || 0}
              </div>
              <div className="text-sm text-gray-400">Confirmed (24h)</div>
              <div className="text-xs text-gray-500 mt-1">
                L1 reconciliations
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Wraith Lifetime Stats */}
      {isLoading ? (
        <SkeletonCard />
      ) : (
        <Card>
          <CardHeader title="Wraith Hosting Stats" />
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-gray-100">
                {wraithStats?.total_sessions?.toLocaleString() || 0}
              </div>
              <div className="text-sm text-gray-400">Sessions Hosted</div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-orange-400">
                {wraithStats?.sessions_completed?.toLocaleString() || 0}
              </div>
              <div className="text-sm text-gray-400">Completed</div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-red-400">
                {wraithStats?.sessions_expired?.toLocaleString() || 0}
              </div>
              <div className="text-sm text-gray-400">Expired</div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-orange-400">
                {wraithStats?.total_participants?.toLocaleString() || 0}
              </div>
              <div className="text-sm text-gray-400">Participants Served</div>
            </div>
          </div>
        </Card>
      )}

      {/* Fee Payout History */}
      <GhostPayPayoutHistoryCard
        ghostpayFees={payoutHistory?.ghostpay_fees ?? []}
        wraithFees={payoutHistory?.wraith_fees ?? []}
        summary={payoutHistory?.summary ?? { total_ghostpay_fees_satoshis: 0, total_wraith_fees_satoshis: 0, ghostpay_sessions_count: 0, wraith_sessions_count: 0 }}
        isLoading={payoutLoading}
        timeFilter={payoutTimeFilter}
        onTimeFilterChange={setPayoutTimeFilter}
      />
    </div>
  );
}
