"use client";

import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { SkeletonCard, SkeletonTable } from "@/components/ui/Skeleton";
import { useBudsMempool, useBudsCapabilities, useConfig } from "@/hooks/queries";
import Link from "next/link";

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatSats(sats: number): string {
  if (sats >= 100_000_000) {
    return `${(sats / 100_000_000).toFixed(4)} BTC`;
  }
  if (sats >= 1_000_000) {
    return `${(sats / 1_000_000).toFixed(2)}M sats`;
  }
  if (sats >= 1_000) {
    return `${(sats / 1_000).toFixed(1)}K sats`;
  }
  return `${sats} sats`;
}

function getTierInfo(tier: string): { name: string; description: string; color: string } {
  switch (tier.toLowerCase()) {
    case "t0":
    case "tier0":
      return {
        name: "T0 - Consensus-Critical",
        description: "Scripts, signatures, tapscript - essential data for transaction validity",
        color: "text-green-400",
      };
    case "t1":
    case "tier1":
      return {
        name: "T1 - Economic Layer",
        description: "L2 anchors, vaults, OP_RETURN ≤100 bytes (batch reconciliation, merkle commits)",
        color: "text-blue-400",
      };
    case "t2":
    case "tier2":
      return {
        name: "T2 - Application Data",
        description: "Inscriptions, tokens, OP_RETURN >100 bytes - non-essential application data",
        color: "text-orange-400",
      };
    case "t3":
    case "tier3":
      return {
        name: "T3 - Unknown",
        description: "Unrecognized formats, obfuscated data - unclassifiable data",
        color: "text-red-400",
      };
    default:
      return {
        name: tier,
        description: "Unknown tier",
        color: "text-gray-400",
      };
  }
}

function CapabilityBadge({ enabled, tier }: { enabled: boolean; tier: string }) {
  const tierInfo = getTierInfo(tier);
  return (
    <div
      className={`p-4 rounded-lg border ${
        enabled
          ? "bg-green-900/20 border-green-700"
          : "bg-gray-800/50 border-gray-700 opacity-60"
      }`}
    >
      <div className="flex items-center gap-2 mb-2">
        <span className={`font-bold ${enabled ? tierInfo.color : "text-gray-500"}`}>
          {tierInfo.name}
        </span>
        <Badge variant={enabled ? "success" : "default"}>
          {enabled ? "Enabled" : "Disabled"}
        </Badge>
      </div>
      <p className="text-sm text-gray-400">{tierInfo.description}</p>
    </div>
  );
}

export default function BudsPage() {
  const { data: mempool, isLoading: mempoolLoading } = useBudsMempool();
  const { data: capabilities, isLoading: capabilitiesLoading } = useBudsCapabilities();
  const { data: config } = useConfig();

  // Only show skeleton on initial load, not on refetch
  const showMempoolSkeleton = mempoolLoading && !mempool;
  const showCapabilitiesSkeleton = capabilitiesLoading && !capabilities;

  const tiers = mempool?.tiers ?? [];
  const totalCount = mempool?.total_count ?? 0;
  const totalSize = mempool?.total_size ?? 0;
  const totalFees = mempool?.total_fees ?? 0;

  // Calculate percentages
  const tierPercentages = tiers.map((t) => ({
    ...t,
    countPercent: totalCount > 0 ? (t.count / totalCount) * 100 : 0,
    sizePercent: totalSize > 0 ? ((t.size_vbytes ?? 0) / totalSize) * 100 : 0,
    feePercent: totalFees > 0 ? ((t.total_fees ?? 0) / totalFees) * 100 : 0,
  }));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">BUDS Classification</h1>
          <p className="text-gray-400 mt-1">Bitcoin Universal Data Specification</p>
        </div>
        <Badge variant="info">
          {config?.mempool_profile ?? "standard"} profile
        </Badge>
      </div>

      {/* Overview Stats */}
      {showMempoolSkeleton ? (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardHeader title="Total Transactions" />
            <div className="text-3xl font-bold text-gray-100">
              {totalCount.toLocaleString()}
            </div>
            <p className="text-sm text-gray-400 mt-1">In mempool</p>
          </Card>
          <Card>
            <CardHeader title="Total Size" />
            <div className="text-3xl font-bold text-blue-400">{formatSize(totalSize)}</div>
            <p className="text-sm text-gray-400 mt-1">Virtual bytes</p>
          </Card>
          <Card>
            <CardHeader title="Total Fees" />
            <div className="text-3xl font-bold text-green-400">{formatSats(totalFees)}</div>
            <p className="text-sm text-gray-400 mt-1">Pending</p>
          </Card>
          <Card>
            <CardHeader title="Avg Fee Rate" />
            <div className="text-3xl font-bold text-purple-400">
              {totalSize > 0 ? (totalFees / totalSize).toFixed(1) : "0"} sat/vB
            </div>
            <p className="text-sm text-gray-400 mt-1">Average</p>
          </Card>
        </div>
      )}

      {/* Mempool by Tier */}
      <Card>
        <CardHeader
          title="Mempool by Tier"
          subtitle="Transaction classification breakdown"
        />
        {showMempoolSkeleton ? (
          <SkeletonTable rows={4} cols={5} />
        ) : tiers.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-gray-400">No transactions in mempool</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="pb-3 text-gray-400 font-medium">Tier</th>
                  <th className="pb-3 text-gray-400 font-medium text-right">Count</th>
                  <th className="pb-3 text-gray-400 font-medium text-right">Size (vB)</th>
                  <th className="pb-3 text-gray-400 font-medium text-right">Fees (sats)</th>
                  <th className="pb-3 text-gray-400 font-medium">Distribution</th>
                </tr>
              </thead>
              <tbody>
                {tierPercentages.map((tier) => {
                  const tierInfo = getTierInfo(tier.tier);
                  return (
                    <tr
                      key={tier.tier}
                      className="border-b border-gray-800/50 hover:bg-gray-800/30"
                    >
                      <td className="py-4">
                        <div className={`font-medium ${tierInfo.color}`}>{tierInfo.name}</div>
                        <div className="text-xs text-gray-500">{tierInfo.description}</div>
                      </td>
                      <td className="py-4 text-right">
                        <div className="text-gray-100">{tier.count.toLocaleString()}</div>
                        <div className="text-xs text-gray-500">
                          {tier.countPercent.toFixed(1)}%
                        </div>
                      </td>
                      <td className="py-4 text-right">
                        <div className="text-gray-100">{formatSize(tier.size_vbytes ?? 0)}</div>
                        <div className="text-xs text-gray-500">
                          {tier.sizePercent.toFixed(1)}%
                        </div>
                      </td>
                      <td className="py-4 text-right">
                        <div className="text-gray-100">{formatSats(tier.total_fees ?? 0)}</div>
                        <div className="text-xs text-gray-500">
                          {tier.feePercent.toFixed(1)}%
                        </div>
                      </td>
                      <td className="py-4">
                        <div className="w-full h-2 bg-gray-700 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              tier.tier.toLowerCase().includes("0")
                                ? "bg-green-500"
                                : tier.tier.toLowerCase().includes("1")
                                ? "bg-blue-500"
                                : tier.tier.toLowerCase().includes("2")
                                ? "bg-orange-500"
                                : "bg-red-500"
                            }`}
                            style={{ width: `${tier.countPercent}%` }}
                          />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Node Capabilities */}
      <Card>
        <CardHeader
          title="Node BUDS Capabilities"
          subtitle="Transaction tiers your node can process"
        />
        {showCapabilitiesSkeleton ? (
          <SkeletonTable rows={4} cols={2} />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <CapabilityBadge enabled={capabilities?.tier0 ?? true} tier="T0" />
            <CapabilityBadge enabled={capabilities?.tier1 ?? false} tier="T1" />
            <CapabilityBadge enabled={capabilities?.tier2 ?? false} tier="T2" />
            <CapabilityBadge enabled={capabilities?.tier3 ?? false} tier="T3" />
          </div>
        )}
      </Card>

      {/* Current Profile Info */}
      <Card>
        <CardHeader
          title="Active Policy Configuration"
          subtitle="Current mempool and template profiles"
        />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 bg-gray-800/50 rounded-lg">
            <div className="text-sm text-gray-400 mb-1">Mempool Profile</div>
            <div className="flex items-center gap-2">
              <span className="text-gray-100 font-medium capitalize">
                {config?.mempool_profile?.replace(/_/g, " ") ?? "Standard"}
              </span>
              <Badge variant="info">{config?.mempool_profile ?? "standard"}</Badge>
            </div>
          </div>
          <div className="p-4 bg-gray-800/50 rounded-lg">
            <div className="text-sm text-gray-400 mb-1">Template Profile</div>
            <div className="flex items-center gap-2">
              <span className="text-gray-100 font-medium capitalize">
                {config?.template_profile?.replace(/_/g, " ") ?? "Standard"}
              </span>
              <Badge variant="info">{config?.template_profile ?? "standard"}</Badge>
            </div>
          </div>
        </div>
        <div className="mt-4 pt-4 border-t border-gray-800">
          <Link
            href="/settings"
            className="text-purple-400 hover:text-purple-300 text-sm"
          >
            Configure profiles in Settings &rarr;
          </Link>
        </div>
      </Card>

      {/* Info Card */}
      <Card>
        <div className="p-4 bg-blue-900/20 border border-blue-800 rounded-lg">
          <h4 className="text-blue-300 font-medium mb-2">About BUDS Classification</h4>
          <p className="text-sm text-blue-300/80 mb-3">
            BUDS (Bitcoin Unified Data Standard) classifies <strong>data within transactions</strong>, not transaction types.
            Each transaction is scored by its worst-tier data (ARBDA score).
          </p>
          <ul className="text-sm space-y-1 list-disc list-inside">
            <li className="text-green-300/80">
              <strong className="text-green-400">T0 (Consensus-Critical)</strong>: Scripts, signatures, tapscript - essential for validity
            </li>
            <li className="text-blue-300/80">
              <strong className="text-blue-400">T1 (Economic Layer)</strong>: L2 anchors, vaults, OP_RETURN ≤100 bytes (batch reconciliation)
            </li>
            <li className="text-orange-300/80">
              <strong className="text-orange-400">T2 (Application Data)</strong>: Inscriptions, tokens, OP_RETURN &gt;100 bytes - non-essential
            </li>
            <li className="text-red-300/80">
              <strong className="text-red-400">T3 (Unknown)</strong>: Unrecognized or obfuscated data - triggers worst-tier score
            </li>
          </ul>
          <p className="text-blue-300/60 text-sm mt-3">
            Nodes can set policy to filter transactions based on their ARBDA score, enabling
            control over mempool composition and block template construction.
          </p>
        </div>
      </Card>
    </div>
  );
}
