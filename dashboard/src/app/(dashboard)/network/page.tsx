"use client";

import { useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { DataTable, formatDuration, truncateId } from "@/components/ui/DataTable";
import { SkeletonCard, SkeletonTable } from "@/components/ui/Skeleton";
import { NetworkPayoutHistoryCard } from "@/components/PayoutHistoryCard";
import { usePoolStatus, usePeers, useTreasury, useElderStatus, useNetworkPayoutHistory } from "@/hooks/queries";
import type { PeerInfo, PayoutHistoryTimeFilter } from "@/types/api";
import type { ColumnDef } from "@tanstack/react-table";

function formatBtc(btc: number): string {
  if (btc >= 1) {
    return `${btc.toFixed(4)} BTC`;
  }
  const sats = Math.floor(btc * 100_000_000);
  return `${sats.toLocaleString()} sats`;
}

const peerColumns: ColumnDef<PeerInfo>[] = [
  {
    accessorKey: "node_id",
    header: "Peer ID",
    cell: ({ row }) => (
      <span className="font-mono text-sm">
        {truncateId(row.original.node_id || "N/A", 8)}
      </span>
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
        <Badge
          variant={latency < 100 ? "success" : latency < 500 ? "warning" : "error"}
        >
          {latency}ms
        </Badge>
      );
    },
  },
  {
    accessorKey: "synced",
    header: "Status",
    cell: ({ row }) => (
      <Badge variant={row.original.synced ? "success" : "warning"}>
        {row.original.synced ? "Synced" : "Syncing"}
      </Badge>
    ),
  },
  {
    accessorKey: "connected_at",
    header: "Connected",
    cell: ({ row }) => {
      const connectedAgo = Math.floor(Date.now() / 1000 - (row.original.connected_at ?? 0));
      return <span className="text-gray-400">{formatDuration(connectedAgo)} ago</span>;
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

  const peers = peersData?.peers ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-100">Network</h1>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {poolLoading ? (
          <SkeletonCard />
        ) : (
          <Card>
            <CardHeader
              title="Ghost Pool"
              action={
                <Badge variant={pool?.connected ? "success" : "error"}>
                  {pool?.connected ? "Connected" : "Disconnected"}
                </Badge>
              }
            />
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-400">Pool Hashrate</span>
                <span className="font-mono text-gray-100">
                  {pool ? `${(pool.pool_hashrate_ph ?? 0).toFixed(2)} PH/s` : "--"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Active Nodes</span>
                <span className="font-mono text-gray-100">{pool?.active_nodes ?? 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Active Miners</span>
                <span className="font-mono text-gray-100">{pool?.active_miners ?? 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Blocks Found</span>
                <span className="font-mono text-gray-100">{pool?.blocks_found ?? 0}</span>
              </div>
              <div className="pt-2 border-t border-gray-800">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-400">Round Duration</span>
                  <span className="text-gray-300">
                    {pool ? formatDuration(pool.current_round_duration_secs ?? 0) : "--"}
                  </span>
                </div>
                <div className="flex justify-between text-sm mt-1">
                  <span className="text-gray-400">Est. Time to Block</span>
                  <span className="text-gray-300">
                    {pool ? formatDuration(pool.estimated_time_to_block_secs ?? 0) : "--"}
                  </span>
                </div>
              </div>
            </div>
          </Card>
        )}

        {treasuryLoading ? (
          <SkeletonCard />
        ) : (
          <Card>
            <CardHeader title="Treasury" />
            <div className="space-y-3">
              <div>
                <div className="text-2xl font-bold text-yellow-400">
                  {treasury ? formatBtc(treasury.accumulated_btc ?? 0) : "--"}
                </div>
                <p className="text-sm text-gray-400">Accumulated</p>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Decay Status</span>
                <Badge variant={treasury?.decay_started ? "warning" : "info"}>
                  {treasury?.decay_started ? "Decaying" : "Accumulating"}
                </Badge>
              </div>
              {treasury?.decay_rate && (
                <div className="flex justify-between">
                  <span className="text-gray-400">Decay Rate</span>
                  <span className="text-gray-100">{(treasury.decay_rate * 100).toFixed(2)}%</span>
                </div>
              )}
              {treasury?.blocks_until_full && (
                <div className="flex justify-between">
                  <span className="text-gray-400">Blocks Until Full</span>
                  <span className="font-mono text-gray-100">
                    {treasury.blocks_until_full.toLocaleString()}
                  </span>
                </div>
              )}
            </div>
          </Card>
        )}

        {elderLoading ? (
          <SkeletonCard />
        ) : (
          <Card>
            <CardHeader
              title="Elder Status"
              action={
                elder?.is_elder && elder?.elder_slot != null && (
                  <Badge variant="info">Slot #{elder.elder_slot}</Badge>
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
                <span className="font-mono text-gray-100">{elder?.active_elders ?? 0}</span>
              </div>
              {elder?.downtime_warning && (
                <div className="p-2 bg-yellow-900/20 border border-yellow-800 rounded">
                  <p className="text-yellow-400 text-sm">
                    Downtime Warning: {elder.consecutive_downtime_days} consecutive days
                  </p>
                </div>
              )}
            </div>
          </Card>
        )}
      </div>

      <Card>
        <CardHeader title="Connected Peers" subtitle={`${peers.length} peers connected`} />
        {peersLoading ? (
          <SkeletonTable rows={5} cols={5} />
        ) : (
          <DataTable
            columns={peerColumns}
            data={peers}
            emptyMessage="No peers connected"
            showPagination={peers.length > 10}
          />
        )}
      </Card>

      <NetworkPayoutHistoryCard
        entries={payoutHistory?.entries ?? []}
        summary={payoutHistory?.summary ?? { total_treasury_satoshis: 0, total_node_rewards_satoshis: 0, total_miner_rewards_satoshis: 0, blocks_in_period: 0 }}
        isLoading={payoutLoading}
        timeFilter={payoutTimeFilter}
        onTimeFilterChange={setPayoutTimeFilter}
      />
    </div>
  );
}
