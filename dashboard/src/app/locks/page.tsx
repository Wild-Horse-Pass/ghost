"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { getGhostLocks } from "@/lib/api";
import type { GhostLock, GhostLockSummary, LockStatus } from "@/types/api";

const DENOMINATION_VALUES: Record<string, number> = {
  Micro: 0.0001,
  Tiny: 0.001,
  Small: 0.01,
  Medium: 0.1,
  Large: 1.0,
};

const TIMELOCK_LABELS: Record<string, string> = {
  Short: "1 day",
  Standard: "1 week",
  Long: "1 month",
};

function getStatusBadgeVariant(status: LockStatus): "success" | "warning" | "error" | "info" | "default" {
  switch (status) {
    case "Active":
      return "success";
    case "PendingSettlement":
      return "warning";
    case "InMixing":
      return "info";
    case "Settled":
      return "default";
    case "Expired":
      return "error";
    default:
      return "default";
  }
}

function getStatusLabel(status: LockStatus): string {
  switch (status) {
    case "PendingSettlement":
      return "Pending Settlement";
    case "InMixing":
      return "In Mixing";
    default:
      return status;
  }
}

function truncateId(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 6)}...${id.slice(-6)}`;
}

function formatBtc(sats: number): string {
  return (sats / 100_000_000).toFixed(8);
}

function formatDate(timestamp: number | null): string {
  if (!timestamp) return "N/A";
  return new Date(timestamp * 1000).toLocaleDateString();
}

export default function LocksPage() {
  const [locks, setLocks] = useState<GhostLock[]>([]);
  const [summary, setSummary] = useState<GhostLockSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const data = await getGhostLocks();
      setLocks(data.locks);
      setSummary(data.summary ?? null);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 p-8">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-2xl font-bold text-gray-100 mb-6">Ghost Locks</h1>
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
        <h1 className="text-2xl font-bold text-gray-100 mb-6">Ghost Locks</h1>

        {error && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-800 rounded-lg">
            <p className="text-red-400">{error}</p>
          </div>
        )}

        {/* Summary */}
        <Card className="mb-6">
          <CardHeader title="Summary" />
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-gray-100">
                {summary?.total_locks ?? 0}
              </div>
              <div className="text-sm text-gray-400">Total Locks</div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-yellow-400">
                {formatBtc(summary?.total_balance ?? 0)}
              </div>
              <div className="text-sm text-gray-400">Total Balance (BTC)</div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-green-400">
                {formatBtc(summary?.available_balance ?? 0)}
              </div>
              <div className="text-sm text-gray-400">Available (BTC)</div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-orange-400">
                {formatBtc(summary?.pending_settlement ?? 0)}
              </div>
              <div className="text-sm text-gray-400">Pending Settlement</div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-2xl font-bold text-purple-400">
                {formatBtc(summary?.in_mixing ?? 0)}
              </div>
              <div className="text-sm text-gray-400">In Mixing</div>
            </div>
          </div>
        </Card>

        {/* Locks List */}
        <Card className="mb-6">
          <CardHeader
            title="Your Locks"
            subtitle={`${locks.length} locks`}
          />
          {locks.length === 0 ? (
            <p className="text-gray-400">No locks found</p>
          ) : (
            <div className="space-y-4">
              {locks.map((lock) => (
                <div
                  key={lock.lock_id}
                  className="p-4 bg-gray-800/50 rounded-lg border border-gray-700"
                >
                  <div className="flex flex-wrap items-start justify-between gap-4 mb-4">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-lg text-gray-100">
                        {truncateId(lock.lock_id)}
                      </span>
                      <Badge variant={getStatusBadgeVariant(lock.status)}>
                        {getStatusLabel(lock.status)}
                      </Badge>
                    </div>
                    <div className="text-right">
                      <div className="text-2xl font-bold text-gray-100">
                        {formatBtc(lock.balance)} BTC
                      </div>
                      <div className="text-sm text-gray-400">
                        {lock.denomination} ({DENOMINATION_VALUES[lock.denomination]} BTC)
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="text-gray-500">Nonce</span>
                      <div className="text-gray-100 font-mono">{lock.nonce}</div>
                    </div>
                    <div>
                      <span className="text-gray-500">Timelock</span>
                      <div className="text-gray-100">
                        {lock.timelock_tier} ({TIMELOCK_LABELS[lock.timelock_tier]})
                      </div>
                    </div>
                    <div>
                      <span className="text-gray-500">Expires</span>
                      <div className="text-gray-100">{formatDate(lock.expires_at)}</div>
                    </div>
                    <div>
                      <span className="text-gray-500">L1 UTXO</span>
                      <div className="text-gray-100 font-mono text-xs">
                        {lock.utxo_txid ? (
                          <>
                            {truncateId(lock.utxo_txid)}:{lock.utxo_vout}
                            {lock.utxo_confirmed ? (
                              <Badge variant="success" className="ml-2">confirmed</Badge>
                            ) : (
                              <Badge variant="warning" className="ml-2">pending</Badge>
                            )}
                          </>
                        ) : (
                          "N/A"
                        )}
                      </div>
                    </div>
                  </div>

                  {lock.status === "PendingSettlement" && lock.batch_id && (
                    <div className="mt-4 p-3 bg-orange-900/20 border border-orange-800 rounded">
                      <div className="flex items-center justify-between">
                        <span className="text-orange-400 text-sm">
                          Batch: {truncateId(lock.batch_id)}
                        </span>
                        {lock.batch_signatures && (
                          <span className="text-orange-300 text-sm">
                            {lock.batch_signatures}
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  <div className="mt-4 flex gap-2">
                    <button className="px-3 py-1 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded text-sm">
                      View History
                    </button>
                    {lock.status === "Active" && (
                      <>
                        <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm">
                          Request Settlement
                        </button>
                        <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white rounded text-sm">
                          Use in Mix
                        </button>
                      </>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Create Lock Info */}
        <Card>
          <CardHeader title="Create New Lock" />
          <div className="p-4 bg-blue-900/20 border border-blue-800 rounded-lg">
            <p className="text-blue-300 text-sm mb-4">
              To create a new Ghost Lock, use the Ghost Wallet app. Locks are created by
              depositing Bitcoin to a special P2WSH address with a recovery path.
            </p>
            <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded">
              Open Ghost Wallet
            </button>
          </div>
        </Card>
      </div>
    </div>
  );
}
