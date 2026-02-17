"use client";

import { useState, useMemo } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { truncateId } from "@/components/ui/DataTable";
import { useMeshStatus } from "@/hooks/queries";
import { useQueryClient } from "@tanstack/react-query";
import { meshKeys } from "@/hooks/queries/useMeshQueries";
import type { ChallengeServiceStats, MeshPeer } from "@/lib/api/mesh";

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  if (days > 0) {
    return `${days}d ${hours}h`;
  }
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  return `${minutes}m`;
}

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

// Order services by share value: +5, +4, +3, +2
const SERVICE_ORDER = ["archive", "ghostpay", "stratum", "policy"];

function getServiceDisplayName(service: string): string {
  const names: Record<string, string> = {
    archive: "Archive Mode (+5)",
    ghostpay: "Ghost Pay (+4)",
    stratum: "Public Mining (+3)",
    policy: "Bitcoin Pure (+2)",
  };
  return names[service] || service;
}

function getServiceDescription(service: string): string {
  const descriptions: Record<string, string> = {
    archive: "Random block retrieval challenges verify full archive storage",
    ghostpay: "L2 block challenges verify Ghost Pay node operation",
    stratum: "Stratum port challenges verify public mining port is open",
    policy: "Policy challenges verify Bitcoin Pure transaction filtering",
  };
  return descriptions[service] || "";
}

const ROWS_PER_PAGE = 20;

export default function MeshPage() {
  const { data: meshData, isLoading } = useMeshStatus();
  const queryClient = useQueryClient();
  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState<"all" | "connected" | "disconnected">("all");

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: meshKeys.all });
  };

  const peers = meshData?.peers ?? [];
  const consensus = meshData?.consensus ?? null;
  const challengeStats = meshData?.challenge_stats ?? [];
  const connectedPeers = peers.filter(p => p.connected).length;

  // Sort challenge stats by share value order
  const sortedChallengeStats = useMemo(() => {
    return [...challengeStats].sort((a, b) => {
      const aIndex = SERVICE_ORDER.indexOf(a.service);
      const bIndex = SERVICE_ORDER.indexOf(b.service);
      return aIndex - bIndex;
    });
  }, [challengeStats]);

  // Filter and paginate peers
  const filteredPeers = useMemo(() => {
    if (filter === "connected") return peers.filter(p => p.connected);
    if (filter === "disconnected") return peers.filter(p => !p.connected);
    return peers;
  }, [peers, filter]);

  const totalPages = Math.ceil(filteredPeers.length / ROWS_PER_PAGE);
  const paginatedPeers = filteredPeers.slice(page * ROWS_PER_PAGE, (page + 1) * ROWS_PER_PAGE);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">Mesh Network</h1>
        <Button variant="secondary" onClick={handleRefresh}>
          Refresh
        </Button>
      </div>

      {/* Overview Stats */}
      {isLoading ? (
        <SkeletonCard />
      ) : (
        <Card>
          <CardHeader
            title="Consensus Status"
            subtitle="BFT mesh network for share verification and payout consensus"
          />
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className={`text-3xl font-bold ${consensus?.active ? "text-green-400" : "text-gray-500"}`}>
                {consensus?.active ? "Active" : "Inactive"}
              </div>
              <div className="text-sm text-gray-400 mt-1">Network Status</div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-3xl font-bold text-orange-400">
                {consensus?.total_nodes ?? (peers.length + 1)}
              </div>
              <div className="text-sm text-gray-400 mt-1">Total Nodes</div>
              <div className="text-xs text-gray-500">(self + {connectedPeers} peers)</div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className={`text-3xl font-bold ${consensus?.quorum_met ? "text-green-400" : "text-yellow-400"}`}>
                {consensus?.quorum_met ? "Yes" : "No"}
              </div>
              <div className="text-sm text-gray-400 mt-1">
                Quorum Met ({consensus?.peers_required ?? 0} required)
              </div>
            </div>
            <div className="text-center p-4 bg-gray-800/50 rounded-lg">
              <div className="text-3xl font-bold text-orange-400">
                {formatUptime(meshData?.uptime_seconds ?? 0)}
              </div>
              <div className="text-sm text-gray-400 mt-1">Node Uptime</div>
            </div>
          </div>

          {/* External Address */}
          {meshData?.external_address && (
            <div className="mt-4 p-3 bg-gray-800/30 rounded-lg">
              <span className="text-xs text-gray-500 uppercase tracking-wide">External Address</span>
              <div className="font-mono text-sm text-gray-300 mt-1">{meshData.external_address}</div>
            </div>
          )}

          {/* Quorum Explanation */}
          <div className="mt-4 p-3 bg-orange-900/20 border border-orange-800/50 rounded-lg">
            <p className="text-sm text-orange-300">
              <span className="font-medium">BFT Consensus:</span> Requires 67% (2/3 + 1) of peers for quorum.
              Share claims are verified through periodic challenges. Payouts require consensus agreement.
            </p>
          </div>
        </Card>
      )}

      {/* Challenge Verification Stats */}
      {isLoading ? (
        <SkeletonCard />
      ) : (
        <Card>
          <CardHeader
            title="Verification Services"
            subtitle="Challenge-response verification for share model features"
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {sortedChallengeStats.map((stats) => (
              <ChallengeStatsCard key={stats.service} stats={stats} />
            ))}
          </div>

          {/* Share Model Reference */}
          <div className="mt-4 p-3 bg-gray-800/30 rounded-lg">
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">5-4-3-2-1 Share Model</p>
            <div className="grid grid-cols-5 gap-2 text-center text-xs">
              <div className="p-2 bg-gray-800 rounded">
                <div className="font-bold text-orange-400">+5</div>
                <div className="text-gray-500">Archive</div>
              </div>
              <div className="p-2 bg-gray-800 rounded">
                <div className="font-bold text-orange-400">+4</div>
                <div className="text-gray-500">GhostPay</div>
              </div>
              <div className="p-2 bg-gray-800 rounded">
                <div className="font-bold text-orange-400">+3</div>
                <div className="text-gray-500">Mining</div>
              </div>
              <div className="p-2 bg-gray-800 rounded">
                <div className="font-bold text-yellow-400">+2</div>
                <div className="text-gray-500">Pure</div>
              </div>
              <div className="p-2 bg-gray-800 rounded">
                <div className="font-bold text-gray-400">+1</div>
                <div className="text-gray-500">Elder</div>
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-2">
              95% uptime required. Features verified through mesh challenges. Max 15 shares per node.
            </p>
          </div>
        </Card>
      )}

      {/* Mesh Peers Table */}
      {isLoading ? (
        <SkeletonCard />
      ) : (
        <Card>
          <CardHeader
            title="Mesh Peers"
            subtitle={`${connectedPeers} connected, ${peers.length - connectedPeers} disconnected`}
          />

          {/* Filter tabs */}
          <div className="flex gap-2 mb-4">
            <button
              onClick={() => { setFilter("all"); setPage(0); }}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                filter === "all" ? "bg-orange-600 text-white" : "bg-gray-800 text-gray-400 hover:bg-gray-700"
              }`}
            >
              All ({peers.length})
            </button>
            <button
              onClick={() => { setFilter("connected"); setPage(0); }}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                filter === "connected" ? "bg-green-600 text-white" : "bg-gray-800 text-gray-400 hover:bg-gray-700"
              }`}
            >
              Connected ({connectedPeers})
            </button>
            <button
              onClick={() => { setFilter("disconnected"); setPage(0); }}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                filter === "disconnected" ? "bg-red-600 text-white" : "bg-gray-800 text-gray-400 hover:bg-gray-700"
              }`}
            >
              Disconnected ({peers.length - connectedPeers})
            </button>
          </div>

          {filteredPeers.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-gray-400 mb-2">No peers in mesh network</p>
              <p className="text-sm text-gray-500">
                Add nodes via the Swarm page to form a mesh network
              </p>
            </div>
          ) : (
            <>
              {/* Compact table */}
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500 border-b border-gray-800">
                      <th className="pb-2 font-medium">Status</th>
                      <th className="pb-2 font-medium">Node ID</th>
                      <th className="pb-2 font-medium text-center">Capabilities</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedPeers.map((peer) => (
                      <PeerTableRow key={peer.node_id} peer={peer} />
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-800">
                  <span className="text-sm text-gray-500">
                    Showing {page * ROWS_PER_PAGE + 1}-{Math.min((page + 1) * ROWS_PER_PAGE, filteredPeers.length)} of {filteredPeers.length}
                  </span>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setPage(p => Math.max(0, p - 1))}
                      disabled={page === 0}
                      className="px-3 py-1.5 text-sm bg-gray-800 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-700"
                    >
                      Previous
                    </button>
                    <button
                      onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                      disabled={page >= totalPages - 1}
                      className="px-3 py-1.5 text-sm bg-gray-800 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-700"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </Card>
      )}

    </div>
  );
}

function PeerTableRow({ peer }: { peer: MeshPeer }) {
  const { capabilities } = peer;

  return (
    <tr className="border-b border-gray-800/50 hover:bg-gray-800/30">
      <td className="py-2">
        <span className={`inline-block w-2 h-2 rounded-full ${peer.connected ? "bg-green-500" : "bg-red-500"}`} />
      </td>
      <td className="py-2">
        <span className="font-mono text-gray-300">{truncateId(peer.node_id, 8)}</span>
      </td>
      <td className="py-2">
        <div className="flex justify-center gap-1 flex-wrap">
          {capabilities.archive_mode && (
            <span className="px-1.5 py-0.5 text-xs bg-orange-900/50 text-orange-300 rounded" title="Archive Mode (+5)">A</span>
          )}
          {capabilities.ghost_pay && (
            <span className="px-1.5 py-0.5 text-xs bg-orange-900/50 text-orange-300 rounded" title="Ghost Pay (+4)">G</span>
          )}
          {capabilities.public_mining && (
            <span className="px-1.5 py-0.5 text-xs bg-orange-900/50 text-orange-300 rounded" title="Public Mining (+3)">M</span>
          )}
          {capabilities.bitcoin_pure && (
            <span className="px-1.5 py-0.5 text-xs bg-yellow-900/50 text-yellow-300 rounded" title="Bitcoin Pure (+2)">P</span>
          )}
          {capabilities.elder_rank !== null && (
            <span className="px-1.5 py-0.5 text-xs bg-gray-700 text-gray-300 rounded" title={`Elder #${capabilities.elder_rank}`}>E{capabilities.elder_rank}</span>
          )}
        </div>
      </td>
    </tr>
  );
}

function ChallengeStatsCard({ stats }: { stats: ChallengeServiceStats }) {
  const passRate = stats.total_challenges > 0
    ? (stats.passed / stats.total_challenges)
    : 0;
  const meetsThreshold = passRate >= stats.threshold;

  return (
    <div className={`p-4 rounded-lg border ${
      stats.qualified
        ? "bg-green-900/10 border-green-800/50"
        : "bg-gray-800/50 border-gray-700"
    }`}>
      <div className="flex items-center justify-between mb-3">
        <div>
          <h4 className="font-medium text-gray-100">{getServiceDisplayName(stats.service)}</h4>
          <p className="text-xs text-gray-500">{getServiceDescription(stats.service)}</p>
        </div>
        <Badge variant={stats.qualified ? "success" : "warning"}>
          {stats.qualified ? "Qualified" : "Not Qualified"}
        </Badge>
      </div>

      <div className="grid grid-cols-4 gap-2 text-center text-xs mb-3">
        <div className="p-2 bg-gray-800/50 rounded">
          <div className="font-bold text-gray-100">{stats.total_challenges}</div>
          <div className="text-gray-500">Total</div>
        </div>
        <div className="p-2 bg-gray-800/50 rounded">
          <div className="font-bold text-green-400">{stats.passed}</div>
          <div className="text-gray-500">Passed</div>
        </div>
        <div className="p-2 bg-gray-800/50 rounded">
          <div className="font-bold text-red-400">{stats.failed}</div>
          <div className="text-gray-500">Failed</div>
        </div>
        <div className="p-2 bg-gray-800/50 rounded">
          <div className="font-bold text-yellow-400">{stats.timeouts}</div>
          <div className="text-gray-500">Timeout</div>
        </div>
      </div>

      <div className="flex items-center justify-between text-xs">
        <span className="text-gray-500">
          Pass Rate: <span className={meetsThreshold ? "text-green-400" : "text-yellow-400"}>
            {formatPercent(passRate)}
          </span> (need {formatPercent(stats.threshold)})
        </span>
        <span className="text-gray-500">
          Min: {stats.min_required} challenges
        </span>
      </div>
    </div>
  );
}
