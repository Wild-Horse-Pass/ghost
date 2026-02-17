"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { getSettlement } from "@/lib/api";
import type { SettlementBatch, SettlementStats, BatchStatus } from "@/types/api";

function getStatusBadgeVariant(status: BatchStatus): "success" | "warning" | "error" | "info" | "default" {
  switch (status) {
    case "Confirmed":
      return "success";
    case "Ready":
    case "Broadcast":
      return "info";
    case "CollectingSignatures":
    case "Forming":
      return "warning";
    case "Failed":
      return "error";
    default:
      return "default";
  }
}

function getStatusLabel(status: BatchStatus): string {
  switch (status) {
    case "CollectingSignatures":
      return "Collecting Signatures";
    default:
      return status;
  }
}

function truncateId(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 6)}...${id.slice(-6)}`;
}

function formatBtc(sats: number): string {
  return (sats / 100_000_000).toFixed(4);
}

function formatDate(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString();
}

export default function SettlementPage() {
  const [batches, setBatches] = useState<SettlementBatch[]>([]);
  const [stats, setStats] = useState<SettlementStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const data = await getSettlement();
      setBatches(data.batches ?? []);
      setStats(data.stats ?? null);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const yourBatches = batches.filter((b) => b.your_lock_id !== null);
  const activeBatches = batches.filter(
    (b) => b.status !== "Confirmed" && b.status !== "Failed"
  );
  const historyBatches = batches.filter(
    (b) => b.status === "Confirmed" || b.status === "Failed"
  );

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 p-8">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-2xl font-bold text-gray-100 mb-6">Settlement</h1>
          <div className="animate-pulse space-y-6">
            <div className="h-24 bg-gray-800 rounded-lg"></div>
            <div className="h-64 bg-gray-800 rounded-lg"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-2xl font-bold text-gray-100 mb-6">Settlement</h1>

        {error && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-800 rounded-lg">
            <p className="text-red-400">{error}</p>
          </div>
        )}

        {/* L1 Connection Status */}
        <Card className="mb-6">
          <CardHeader title="L1 Connection" />
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span
                className={`w-3 h-3 rounded-full ${
                  stats?.l1_connected ? "bg-green-500" : "bg-red-500"
                }`}
              />
              <span className="text-gray-100">
                {stats?.l1_connected ? "Connected to Ghost Core" : "Disconnected"}
              </span>
            </div>
            <div className="text-gray-400">
              L1 Height: <span className="font-mono text-gray-100">{stats?.l1_height?.toLocaleString() ?? "N/A"}</span>
            </div>
          </div>
        </Card>

        {/* Stats */}
        <Card className="mb-6">
          <CardHeader title="Settlement Stats" />
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <div className="text-center p-3 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-orange-400">
                {stats?.pending_batches ?? 0}
              </div>
              <div className="text-sm text-gray-400">Pending</div>
            </div>
            <div className="text-center p-3 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-orange-400">
                {stats?.active_batches ?? 0}
              </div>
              <div className="text-sm text-gray-400">Active</div>
            </div>
            <div className="text-center p-3 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-green-400">
                {stats?.confirmed_24h ?? 0}
              </div>
              <div className="text-sm text-gray-400">Confirmed (24h)</div>
            </div>
            <div className="text-center p-3 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-yellow-400">
                {formatBtc(stats?.total_settled_24h ?? 0)}
              </div>
              <div className="text-sm text-gray-400">Settled (24h) BTC</div>
            </div>
            <div className="text-center p-3 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-orange-400">
                {stats?.your_settlements ?? 0}
              </div>
              <div className="text-sm text-gray-400">Your Settlements</div>
            </div>
            <div className="text-center p-3 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-gray-100">
                {stats?.current_epoch ?? 0}
              </div>
              <div className="text-sm text-gray-400">Current Epoch</div>
            </div>
          </div>
        </Card>

        {/* Your Pending Settlements */}
        {yourBatches.length > 0 && (
          <Card className="mb-6">
            <CardHeader
              title="Your Pending Settlements"
              subtitle={`${yourBatches.length} batches`}
            />
            <div className="space-y-4">
              {yourBatches.map((batch) => (
                <div
                  key={batch.batch_id}
                  className="p-4 bg-gray-800/50 rounded-lg border border-gray-700"
                >
                  <div className="flex flex-wrap items-start justify-between gap-4 mb-3">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-gray-100">
                          {truncateId(batch.batch_id)}
                        </span>
                        <Badge variant={getStatusBadgeVariant(batch.status)}>
                          {getStatusLabel(batch.status)}
                        </Badge>
                      </div>
                      <div className="text-sm text-gray-400">
                        Class: {batch.settlement_class} | Epoch: {batch.epoch_id}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm text-gray-400">
                        Signatures: {batch.signatures_collected}/{batch.participant_count}
                      </div>
                      <div className="w-32 h-2 bg-gray-700 rounded-full overflow-hidden mt-1">
                        <div
                          className="h-full bg-orange-500"
                          style={{
                            width: `${(batch.signatures_collected / batch.participant_count) * 100}%`,
                          }}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-sm">
                    <div>
                      <span className="text-gray-500">Your Lock:</span>{" "}
                      <span className="font-mono text-gray-100">
                        {truncateId(batch.your_lock_id || "")}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-gray-500">Your Signature:</span>
                      {batch.your_signature_submitted ? (
                        <Badge variant="success">Submitted</Badge>
                      ) : (
                        <Badge variant="warning">Required</Badge>
                      )}
                    </div>
                  </div>

                  {batch.txid && (
                    <div className="mt-3 p-2 bg-green-900/20 border border-green-800 rounded">
                      <span className="text-green-400 text-sm">
                        TxID: {truncateId(batch.txid)} ({batch.confirmations} confirmations)
                      </span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </Card>
        )}

        {/* Active Batches */}
        <Card className="mb-6">
          <CardHeader
            title="Active Batches (Network)"
            subtitle={`${activeBatches.length} batches`}
          />
          {activeBatches.length === 0 ? (
            <p className="text-gray-400">No active batches</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-gray-400 text-sm border-b border-gray-800">
                    <th className="pb-3 font-medium">Batch ID</th>
                    <th className="pb-3 font-medium">Class</th>
                    <th className="pb-3 font-medium">Participants</th>
                    <th className="pb-3 font-medium">Signatures</th>
                    <th className="pb-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {activeBatches.map((batch) => (
                    <tr key={batch.batch_id} className="text-gray-100">
                      <td className="py-3 font-mono text-sm">
                        {truncateId(batch.batch_id)}
                      </td>
                      <td className="py-3">{batch.settlement_class}</td>
                      <td className="py-3">{batch.participant_count}</td>
                      <td className="py-3">
                        {batch.signatures_collected}/{batch.participant_count}
                      </td>
                      <td className="py-3">
                        <Badge variant={getStatusBadgeVariant(batch.status)}>
                          {getStatusLabel(batch.status)}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {/* Settlement History */}
        <Card>
          <CardHeader title="Settlement History" />
          {historyBatches.length === 0 ? (
            <p className="text-gray-400">No settlement history</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-gray-400 text-sm border-b border-gray-800">
                    <th className="pb-3 font-medium">Date</th>
                    <th className="pb-3 font-medium">Batch ID</th>
                    <th className="pb-3 font-medium">L1 TxID</th>
                    <th className="pb-3 font-medium">Participants</th>
                    <th className="pb-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {historyBatches.slice(0, 10).map((batch) => (
                    <tr key={batch.batch_id} className="text-gray-100">
                      <td className="py-3 text-gray-400">
                        {formatDate(batch.created_at ?? 0)}
                      </td>
                      <td className="py-3 font-mono text-sm">
                        {truncateId(batch.batch_id)}
                      </td>
                      <td className="py-3 font-mono text-sm">
                        {batch.txid ? truncateId(batch.txid) : "N/A"}
                      </td>
                      <td className="py-3">{batch.participant_count}</td>
                      <td className="py-3">
                        <Badge variant={getStatusBadgeVariant(batch.status)}>
                          {batch.status === "Confirmed"
                            ? `${batch.confirmations} conf`
                            : batch.status}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
