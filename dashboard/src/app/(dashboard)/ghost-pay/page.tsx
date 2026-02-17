"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { GhostPayPayoutHistoryCard } from "@/components/PayoutHistoryCard";
import {
  useGhostPayStatus,
  useWraithStats,
  useSettlementStatus,
  useGhostPayPayoutHistory,
} from "@/hooks/queries";
import type { PayoutHistoryTimeFilter } from "@/types/api";

const TOOLTIPS = {
  l2_height: "Current block height on the Ghost Pay L2 network. Format: era:block for multi-era chains.",
  active_sessions: "Number of Wraith mixing sessions currently in progress on your node.",
  reconciliation: "Active L1 settlement batches reconciling L2 state back to Bitcoin.",
  confirmed_24h: "L1 reconciliation batches confirmed on-chain in the last 24 hours.",
};

type HealthStatus = "healthy" | "warning" | "unknown";

function getHealthBadge(status: HealthStatus) {
  const variants: Record<HealthStatus, "success" | "warning" | "default"> = {
    healthy: "success", warning: "warning", unknown: "default",
  };
  const labels: Record<HealthStatus, string> = {
    healthy: "Healthy", warning: "Warning", unknown: "Unknown",
  };
  return <Badge variant={variants[status]}>{labels[status]}</Badge>;
}

function formatL2Block(era: number, height: number): string {
  if (era <= 1) return height.toLocaleString();
  return `${era}:${height.toLocaleString()}`;
}

export default function GhostPayPage() {
  const [payoutTimeFilter, setPayoutTimeFilter] = useState<PayoutHistoryTimeFilter>("7d");

  const { data: status, isLoading: statusLoading, error: statusError } = useGhostPayStatus();
  const { data: wraithStats, isLoading: wraithLoading } = useWraithStats();
  const { data: reconciliation, isLoading: reconciliationLoading } = useSettlementStatus();
  const { data: payoutHistory, isLoading: payoutLoading } = useGhostPayPayoutHistory(payoutTimeFilter);

  const isLoading = statusLoading || wraithLoading || reconciliationLoading;

  // If Ghost Pay is not enabled / not reachable
  if (!isLoading && statusError) {
    return (
      <div className="space-y-6">
        <PageHeader title="Ghost Pay" subtitle="L2 instant payments, privacy mixing, and settlement" />
        <Card className="border-cyan-600/30">
          <EmptyState
            icon={
              <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 18.75a60.07 60.07 0 0115.797 2.101c.727.198 1.453-.342 1.453-1.096V18.75M3.75 4.5v.75A.75.75 0 013 6h-.75m0 0v-.375c0-.621.504-1.125 1.125-1.125H20.25M2.25 6v9m18-10.5v.75c0 .414.336.75.75.75h.75m-1.5-1.5h.375c.621 0 1.125.504 1.125 1.125v9.75c0 .621-.504 1.125-1.125 1.125h-.375m1.5-1.5H21a.75.75 0 00-.75.75v.75m0 0H3.75m0 0h-.375a1.125 1.125 0 01-1.125-1.125V15m1.5 1.5v-.75A.75.75 0 003 15h-.75M15 10.5a3 3 0 11-6 0 3 3 0 016 0zm3 0h.008v.008H18V10.5zm-12 0h.008v.008H6V10.5z" />
              </svg>
            }
            title="Ghost Pay is not connected"
            description="Enable Ghost Pay in Settings to access L2 payments, Wraith mixing, and Ghost Locks."
            action={
              <a href="/settings" className="text-sm text-cyan-400 hover:text-cyan-300">
                Go to Settings
              </a>
            }
          />
        </Card>
      </div>
    );
  }

  const l2Era = status?.l2_era || 1;
  const l2Height = status?.l2_height || status?.block_height || 0;

  const consensusHealth: HealthStatus = status?.peer_count !== undefined && status.peer_count > 0 ? "healthy" :
    status?.sync_state === "syncing" ? "warning" : "unknown";
  const l1Health: HealthStatus = reconciliation?.l1_available === true ? "healthy" :
    reconciliation?.l1_available === false ? "warning" : "unknown";
  const wraithHealth: HealthStatus = wraithStats?.active_sessions !== undefined ? "healthy" : "unknown";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Ghost Pay"
        subtitle="L2 instant payments, privacy mixing, and settlement"
        actions={
          status && (
            <span className="text-sm text-gray-400">
              {l2Era > 1 && <span className="text-cyan-400 mr-2">Era {l2Era}</span>}
              Block {formatL2Block(l2Era, l2Height)}
            </span>
          )
        }
      />

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="L2 Height"
          value={status ? formatL2Block(l2Era, l2Height) : "--"}
          sublabel={`Epoch ${status?.epoch ?? 0}`}
          tooltip={TOOLTIPS.l2_height}
          loading={isLoading}
        />
        <StatCard
          label="Active Sessions"
          value={wraithStats?.active_sessions ?? 0}
          sublabel={`${wraithStats?.total_participants ?? 0} participants`}
          tooltip={TOOLTIPS.active_sessions}
          loading={isLoading}
        />
        <StatCard
          label="Reconciliation"
          value={reconciliation?.active_count ?? 0}
          sublabel={`${reconciliation?.pending_count ?? 0} pending`}
          tooltip={TOOLTIPS.reconciliation}
          loading={isLoading}
        />
        <StatCard
          label="Confirmed (24h)"
          value={reconciliation?.batches_24h ?? 0}
          sublabel="L1 reconciliations"
          tooltip={TOOLTIPS.confirmed_24h}
          loading={isLoading}
        />
      </div>

      {/* Health indicators */}
      <SectionErrorBoundary section="System Health">
        {isLoading ? <SkeletonCard /> : (
          <Card className="border-cyan-600/30">
            <CardHeader title={<span className="text-cyan-400">System Health</span>} />
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 bg-cyan-900/10 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-400">L2 Consensus</span>
                  {getHealthBadge(consensusHealth)}
                </div>
                <div className="text-xs text-gray-500">
                  {status?.sync_state || status?.network || "Unknown"} &middot; {status?.peer_count || 0} peers
                </div>
              </div>
              <div className="p-4 bg-cyan-900/10 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-400">L1 Connection</span>
                  {getHealthBadge(l1Health)}
                </div>
                <div className="text-xs text-gray-500">
                  {reconciliation?.l1_available ? `Block ${reconciliation.l1_height?.toLocaleString()}` : "Awaiting connection"}
                </div>
              </div>
              <div className="p-4 bg-cyan-900/10 rounded-lg">
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
      </SectionErrorBoundary>

      {/* Wraith Hosting Stats */}
      <SectionErrorBoundary section="Wraith Stats">
        {isLoading ? <SkeletonCard /> : (
          <Card className="border-cyan-600/30">
            <CardHeader title={<span className="text-cyan-400">Wraith Hosting Stats</span>} />
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-4 bg-cyan-900/10 rounded-lg">
                <div className="text-2xl font-bold text-gray-100">
                  {wraithStats?.total_sessions?.toLocaleString() || 0}
                </div>
                <div className="text-sm text-gray-400">Sessions Hosted</div>
              </div>
              <div className="text-center p-4 bg-cyan-900/10 rounded-lg">
                <div className="text-2xl font-bold text-cyan-400">
                  {wraithStats?.sessions_completed?.toLocaleString() || 0}
                </div>
                <div className="text-sm text-gray-400">Completed</div>
              </div>
              <div className="text-center p-4 bg-cyan-900/10 rounded-lg">
                <div className="text-2xl font-bold text-red-400">
                  {wraithStats?.sessions_expired?.toLocaleString() || 0}
                </div>
                <div className="text-sm text-gray-400">Expired</div>
              </div>
              <div className="text-center p-4 bg-cyan-900/10 rounded-lg">
                <div className="text-2xl font-bold text-cyan-400">
                  {wraithStats?.total_participants?.toLocaleString() || 0}
                </div>
                <div className="text-sm text-gray-400">Participants Served</div>
              </div>
            </div>
          </Card>
        )}
      </SectionErrorBoundary>

      {/* Fee Payout History */}
      <SectionErrorBoundary section="Fee History">
        <GhostPayPayoutHistoryCard
          ghostpayFees={payoutHistory?.ghostpay_fees ?? []}
          wraithFees={payoutHistory?.wraith_fees ?? []}
          summary={payoutHistory?.summary ?? { total_ghostpay_fees_satoshis: 0, total_wraith_fees_satoshis: 0, ghostpay_sessions_count: 0, wraith_sessions_count: 0 }}
          isLoading={payoutLoading}
          timeFilter={payoutTimeFilter}
          onTimeFilterChange={setPayoutTimeFilter}
        />
      </SectionErrorBoundary>
    </div>
  );
}
