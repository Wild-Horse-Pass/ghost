"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { DataTable, formatDuration, truncateId } from "@/components/ui/DataTable";
import { NetworkPayoutHistoryCard } from "@/components/PayoutHistoryCard";
import { usePoolStatus, usePeers, useTreasury, useElderStatus, useNetworkPayoutHistory } from "@/hooks/queries";
import { useMeshStatus } from "@/hooks/queries/useMeshQueries";
import type { PeerInfo, PayoutHistoryTimeFilter } from "@/types/api";
import type { ColumnDef } from "@tanstack/react-table";

function formatBtc(btc: number): string {
  if (btc >= 1) return `${btc.toFixed(4)} BTC`;
  const sats = Math.floor(btc * 100_000_000);
  return `${sats.toLocaleString()} sats`;
}

const peerColumns: ColumnDef<PeerInfo>[] = [
  {
    accessorKey: "node_id",
    header: "Node ID",
    cell: ({ row }) => (
      <span className="font-mono text-sm">{truncateId(row.original.node_id || "N/A", 8)}</span>
    ),
  },
  {
    accessorKey: "version",
    header: "Version",
    cell: ({ row }) => (
      <span className="font-mono text-gray-400">{row.original.version || "N/A"}</span>
    ),
  },
  {
    accessorKey: "latency_ms",
    header: "Latency",
    cell: ({ row }) => {
      const latency = row.original.latency_ms ?? 0;
      return (
        <Badge variant={latency < 100 ? "success" : latency < 500 ? "warning" : "error"}>
          {latency}ms
        </Badge>
      );
    },
  },
  {
    accessorKey: "synced",
    header: "Status",
    cell: ({ row }) => (
      <StatusDot
        status={row.original.synced ? "online" : "warning"}
        label={row.original.synced ? "Synced" : "Syncing"}
        size="sm"
      />
    ),
  },
  {
    accessorKey: "connected_at",
    header: "Connected",
    cell: ({ row }) => {
      const connectedAgo = Math.floor(Date.now() / 1000 - (row.original.connected_at ?? 0));
      return <span className="text-gray-400">{formatDuration(connectedAgo)}</span>;
    },
  },
];

export default function NetworkPage() {
  const [payoutTimeFilter, setPayoutTimeFilter] = useState<PayoutHistoryTimeFilter>("7d");

  const { data: pool, isLoading: poolLoading } = usePoolStatus();
  const { data: peersData, isLoading: peersLoading } = usePeers();
  const { data: treasury, isLoading: treasuryLoading } = useTreasury();
  const { data: elder, isLoading: elderLoading } = useElderStatus();
  const { data: payoutHistory, isLoading: payoutLoading } = useNetworkPayoutHistory(payoutTimeFilter);
  useMeshStatus(); // pre-fetch

  const peers = peersData?.peers ?? [];
  const statsLoading = poolLoading || elderLoading;

  return (
    <div className="space-y-6">
      <PageHeader title="Network" subtitle="Pool-wide view: peers, consensus, elders, and treasury" />

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Active Nodes"
          value={pool?.active_nodes ?? "--"}
          loading={statsLoading}
        />
        <StatCard
          label="Peers"
          value={peers.length}
          sublabel="connected to this node"
          loading={peersLoading}
        />
        <StatCard
          label="Pool Hashrate"
          value={pool ? `${(pool.pool_hashrate_ph ?? 0).toFixed(2)} PH/s` : "--"}
          loading={statsLoading}
        />
        <StatCard
          label="Elder Spots"
          value={elder ? `${elder.active_elders ?? 0} / 101` : "--"}
          sublabel={elder?.is_elder ? `You: #${elder.elder_slot}` : undefined}
          loading={elderLoading}
        />
      </div>

      {/* Peer Table */}
      <SectionErrorBoundary section="Peers">
        <Card>
          <CardHeader title="Connected Peers" subtitle={`${peers.length} peers`} />
          <DataTable
            columns={peerColumns}
            data={peers}
            loading={peersLoading}
            emptyMessage="No peers connected"
            emptyDescription="Your node will discover peers automatically"
            searchColumn="node_id"
            searchPlaceholder="Search by node ID..."
            showPagination={peers.length > 10}
          />
        </Card>
      </SectionErrorBoundary>

      {/* Elder Registry + Treasury row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Elder Registry */}
        <SectionErrorBoundary section="Elder Status">
          <Card>
            <CardHeader
              title="Elder Registry"
              action={
                elder?.is_elder && elder?.elder_slot != null && (
                  <Badge variant="info">You: Slot #{elder.elder_slot}</Badge>
                )
              }
            />
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-400">Status</span>
                <Badge variant={elder?.is_elder ? "success" : "default"}>
                  {elder?.is_elder ? "Elder" : "Not Elder"}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Active Elders</span>
                <span className="font-mono text-gray-100">{elder?.active_elders ?? 0} / 101</span>
              </div>
              <ProgressBar
                value={elder?.active_elders ?? 0}
                max={101}
                color="orange"
                size="sm"
              />
              {elder?.downtime_warning && (
                <div className="p-2 bg-yellow-900/20 border border-yellow-800 rounded">
                  <p className="text-yellow-400 text-sm">
                    Downtime Warning: {elder.consecutive_downtime_days} consecutive days
                  </p>
                </div>
              )}
            </div>
          </Card>
        </SectionErrorBoundary>

        {/* Treasury */}
        <SectionErrorBoundary section="Treasury">
          {treasuryLoading ? <Card><div className="animate-pulse h-48" /></Card> : (
            <Card>
              <CardHeader title="Treasury" />
              <div className="space-y-3">
                <div>
                  <div className="text-2xl font-bold text-yellow-400">
                    {treasury ? formatBtc(treasury.accumulated_btc ?? 0) : "--"}
                  </div>
                  <p className="text-sm text-gray-400">Accumulated</p>
                </div>
                <ProgressBar
                  value={treasury?.progress_percent ?? 0}
                  color="orange"
                  size="sm"
                  sublabel={`${(treasury?.progress_percent ?? 0).toFixed(1)}%`}
                />
                <div className="flex justify-between">
                  <span className="text-gray-400">Phase</span>
                  <Badge variant={treasury?.decay_started ? "warning" : "info"}>
                    {treasury?.phase === "ossified" ? "Ossified" : treasury?.decay_started ? "Decaying" : "Bootstrap"}
                  </Badge>
                </div>
                {treasury?.blocks_until_full != null && treasury.blocks_until_full > 0 && (
                  <div className="flex justify-between">
                    <span className="text-gray-400">Blocks Until Full</span>
                    <span className="font-mono text-gray-100">{treasury.blocks_until_full.toLocaleString()}</span>
                  </div>
                )}
              </div>
            </Card>
          )}
        </SectionErrorBoundary>
      </div>

      {/* Network Payout History */}
      <SectionErrorBoundary section="Payout History">
        <NetworkPayoutHistoryCard
          entries={payoutHistory?.entries ?? []}
          summary={payoutHistory?.summary ?? { total_treasury_satoshis: 0, total_node_rewards_satoshis: 0, total_miner_rewards_satoshis: 0, blocks_in_period: 0 }}
          isLoading={payoutLoading}
          timeFilter={payoutTimeFilter}
          onTimeFilterChange={setPayoutTimeFilter}
        />
      </SectionErrorBoundary>
    </div>
  );
}
