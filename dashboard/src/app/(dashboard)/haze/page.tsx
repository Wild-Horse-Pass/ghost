"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useHazeStatus } from "@/hooks/queries/useHazeQueries";

const TOOLTIPS = {
  mode: "How your node stores block data. Hazed nodes strip classified content before storage. Full archive keeps everything. Standard is a normal Bitcoin Core node.",
  blocks: "Total number of blocks your node has processed and stored.",
  storage: "Total disk space used by blockchain data on this node.",
  pruned: "Whether Bitcoin Core is running in pruned mode, discarding old block data to save disk space.",
};

function formatStorageGB(bytes: number): string {
  const gb = bytes / (1024 * 1024 * 1024);
  if (gb >= 1000) return `${(gb / 1024).toFixed(2)} TB`;
  if (gb >= 1) return `${gb.toFixed(2)} GB`;
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(0)} MB`;
}

function getModeLabel(mode: string): string {
  switch (mode) {
    case "hazed":
      return "Hazed";
    case "full_archive":
      return "Full Archive";
    case "standard":
      return "Standard";
    default:
      return "Unknown";
  }
}

function getModeBadgeVariant(mode: string): "success" | "warning" | "info" | "default" {
  switch (mode) {
    case "hazed":
      return "success";
    case "full_archive":
      return "info";
    case "standard":
      return "warning";
    default:
      return "default";
  }
}

function getModeStatus(mode: string): "online" | "warning" | "offline" {
  switch (mode) {
    case "hazed":
      return "online";
    case "full_archive":
      return "online";
    case "standard":
      return "warning";
    default:
      return "offline";
  }
}

export default function HazePage() {
  const { data: haze, isLoading, error } = useHazeStatus();

  const mode = haze?.mode ?? "unknown";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Ghost Haze"
        subtitle="Storage privacy layer for your Bitcoin node"
        actions={
          haze && (
            <Badge variant={getModeBadgeVariant(mode)}>
              {getModeLabel(mode)}
            </Badge>
          )
        }
      />

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Mode"
          value={haze ? getModeLabel(mode) : "--"}
          tooltip={TOOLTIPS.mode}
          loading={isLoading}
        />
        <StatCard
          label="Blocks"
          value={haze ? haze.blocks.toLocaleString() : "--"}
          sublabel={haze?.chain ?? undefined}
          tooltip={TOOLTIPS.blocks}
          loading={isLoading}
        />
        <StatCard
          label="Storage"
          value={haze ? formatStorageGB(haze.size_on_disk) : "--"}
          tooltip={TOOLTIPS.storage}
          loading={isLoading}
        />
        <StatCard
          label="Pruned"
          value={haze ? (haze.pruned ? "Yes" : "No") : "--"}
          tooltip={TOOLTIPS.pruned}
          loading={isLoading}
        />
      </div>

      {/* Hero card */}
      <SectionErrorBoundary section="Ghost Haze Overview">
        {isLoading ? <SkeletonCard /> : (
          <Card className="border-purple-600/30">
            <div className="flex items-start gap-4">
              <div className="w-10 h-10 rounded-lg bg-purple-900/30 border border-purple-600/30 flex items-center justify-center flex-shrink-0">
                <svg className="w-5 h-5 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23.693L5 14.5m14.8.8l1.402 1.402c1.232 1.232.65 3.318-1.067 3.611A48.309 48.309 0 0112 21c-2.773 0-5.491-.235-8.135-.687-1.718-.293-2.3-2.379-1.067-3.61L5 14.5" />
                </svg>
              </div>
              <div>
                <h2 className="text-lg font-semibold text-purple-400 mb-2">What is Ghost Haze?</h2>
                <p className="text-gray-300 text-sm leading-relaxed">
                  Ghost Haze is a storage privacy layer that classifies and strips non-financial data from blocks
                  before writing them to disk. Hazed nodes retain full transaction validity and UTXO integrity
                  while ensuring no arbitrary embedded content is persisted locally. This lets node operators
                  store blockchain data without risk of hosting unwanted content.
                </p>
              </div>
            </div>
          </Card>
        )}
      </SectionErrorBoundary>

      {/* Status detail card */}
      <SectionErrorBoundary section="Haze Status">
        {isLoading ? <SkeletonCard /> : error ? (
          <Card>
            <CardHeader title="Status" />
            <div className="p-4 bg-red-900/20 border border-red-800 rounded-lg">
              <p className="text-red-400 text-sm">
                Unable to fetch Ghost Haze status. Ensure Ghost Core is running and the Haze module is enabled.
              </p>
            </div>
          </Card>
        ) : (
          <Card>
            <CardHeader
              title="Node Status"
              action={
                <StatusDot
                  status={getModeStatus(mode)}
                  label={haze?.hazed ? "Haze Active" : "Haze Inactive"}
                  pulse={haze?.hazed}
                />
              }
            />
            <div className="space-y-3">
              <div className="flex justify-between items-center py-2 border-b border-gray-800">
                <span className="text-gray-400">Storage Mode</span>
                <div className="flex items-center gap-2">
                  <Badge variant={getModeBadgeVariant(mode)}>
                    {getModeLabel(mode)}
                  </Badge>
                </div>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-gray-800">
                <span className="text-gray-400">Blocks Processed</span>
                <span className="font-mono text-gray-100">{haze?.blocks.toLocaleString() ?? 0}</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-gray-800">
                <span className="text-gray-400">Storage on Disk</span>
                <span className="font-mono text-gray-100">{haze ? formatStorageGB(haze.size_on_disk) : "--"}</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-gray-800">
                <span className="text-gray-400">Pruned</span>
                <Badge variant={haze?.pruned ? "warning" : "success"}>
                  {haze?.pruned ? "Yes" : "No"}
                </Badge>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-gray-800">
                <span className="text-gray-400">Archive Mode</span>
                <Badge variant={haze?.archive_mode ? "success" : "default"}>
                  {haze?.archive_mode ? "Enabled" : "Disabled"}
                </Badge>
              </div>
              <div className="flex justify-between items-center py-2">
                <span className="text-gray-400">Chain</span>
                <span className="font-mono text-gray-100">{haze?.chain ?? "--"}</span>
              </div>
              {haze?.error && (
                <div className="mt-3 p-3 bg-red-900/20 border border-red-800 rounded-lg">
                  <p className="text-red-400 text-sm">{haze.error}</p>
                </div>
              )}
            </div>
          </Card>
        )}
      </SectionErrorBoundary>

      {/* Legal compliance card */}
      <SectionErrorBoundary section="Legal Compliance">
        {isLoading ? <SkeletonCard /> : (
          <Card className="border-purple-600/30 bg-purple-900/10">
            <CardHeader title="Legal Compliance" />
            <div className="space-y-4">
              <div className="p-4 bg-gray-800/50 rounded-lg">
                <h4 className="text-purple-400 font-medium mb-2">No Illegal Content Storage</h4>
                <p className="text-gray-300 text-sm leading-relaxed">
                  Hazed nodes use the BUDS classification system to identify and strip non-financial data
                  (OP_RETURN payloads, witness bloat, inscriptions, and other arbitrary content) before
                  blocks are written to disk. This means your node never persists content that could
                  constitute illegal material under local jurisdiction laws.
                </p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-gray-800/50 rounded-lg">
                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-full bg-green-900/30 border border-green-700 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <svg className="w-4 h-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                      </svg>
                    </div>
                    <div>
                      <h5 className="text-gray-100 font-medium text-sm">What is Preserved</h5>
                      <p className="text-gray-400 text-xs mt-1">
                        All financial transaction data, UTXO set integrity, block headers, and consensus-critical
                        information remain intact. Your node can fully validate the chain.
                      </p>
                    </div>
                  </div>
                </div>
                <div className="p-4 bg-gray-800/50 rounded-lg">
                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-full bg-purple-900/30 border border-purple-700 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                      </svg>
                    </div>
                    <div>
                      <h5 className="text-gray-100 font-medium text-sm">What is Stripped</h5>
                      <p className="text-gray-400 text-xs mt-1">
                        Arbitrary data embedded in OP_RETURN outputs, oversized witness data, inscriptions, and
                        other non-financial payloads are removed before storage.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </Card>
        )}
      </SectionErrorBoundary>
    </div>
  );
}
