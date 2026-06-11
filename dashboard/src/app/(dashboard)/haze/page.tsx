"use client";

import { StatusRow } from "@/components/ui/StatusRow";
import { Card, CardHeader } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useHazeStatus } from "@/hooks/queries/useHazeQueries";

// --- Tooltips ---

const TOOLTIPS = {
  mode: "How your node stores block data. Hazed nodes strip classified content before storage. Full archive keeps everything. Standard is a normal Bitcoin Core node.",
  blocks: "Total number of blocks your node has processed and stored.",
  storage: "Total disk space used by blockchain data on this node.",
  pruned: "Whether Bitcoin Core is running in pruned mode, discarding old block data to save disk space.",
};

// --- Helpers ---

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

// --- Page ---

export default function HazePage() {
  const { data: haze, isLoading, error } = useHazeStatus();

  const mode = haze?.mode ?? "unknown";

  return (
    <div className="space-y-6">
      {/* 1. Page Header */}
      <PageHeader
        eyebrow="haze"
        title="Block storage layer."
        subtitle="Storage privacy layer for your Bitcoin node"
        actions={
          haze && (
            <Badge variant={getModeBadgeVariant(mode)}>
              {getModeLabel(mode)}
            </Badge>
          )
        }
      />

      {/* 2. Stat Cards */}
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

      {/* 3. How It Works (collapsible) */}
      <Card collapsible defaultCollapsed>
        <CardHeader
          title="How It Works"
          subtitle="Ghost Haze exorcism pipeline and storage stripping"
        />
        <div className="space-y-5">
          {/* Explanation */}
          <p className="text-gray-300 text-sm leading-relaxed">
            Ghost Haze is a storage privacy layer that classifies and strips non-financial data from blocks
            before writing them to disk. Hazed nodes retain full transaction validity and UTXO integrity
            while ensuring no arbitrary embedded content is persisted locally. This lets node operators
            store blockchain data without risk of hosting unwanted content.
          </p>

          {/* 4-step exorcism pipeline */}
          <div>
            <h4 className="text-gray-200 font-medium text-sm mb-3">The Exorcism Pipeline</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="p-3 bg-gray-800/50 rounded-lg border border-gray-700">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-amber-400 font-mono text-xs font-bold">1</span>
                  <span className="text-gray-100 text-sm font-medium">Field Classification</span>
                </div>
                <p className="text-gray-400 text-xs leading-relaxed">
                  The BUDS system classifies each field in a transaction — witness data, OP_RETURN payloads,
                  script patterns — into financial and non-financial categories.
                </p>
              </div>
              <div className="p-3 bg-gray-800/50 rounded-lg border border-gray-700">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-amber-400 font-mono text-xs font-bold">2</span>
                  <span className="text-gray-100 text-sm font-medium">Block Stripping</span>
                </div>
                <p className="text-gray-400 text-xs leading-relaxed">
                  Non-financial data is stripped from the block at the validation layer, before the block
                  is written to disk. Financial data and consensus-critical fields remain untouched.
                </p>
              </div>
              <div className="p-3 bg-gray-800/50 rounded-lg border border-gray-700">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-amber-400 font-mono text-xs font-bold">3</span>
                  <span className="text-gray-100 text-sm font-medium">GSB Storage</span>
                </div>
                <p className="text-gray-400 text-xs leading-relaxed">
                  Stripped blocks are stored in Ghost Stripped Block (<code className="text-amber-400">.gsb</code>) format —
                  a compact representation that preserves all data needed for chain validation.
                </p>
              </div>
              <div className="p-3 bg-gray-800/50 rounded-lg border border-gray-700">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-amber-400 font-mono text-xs font-bold">4</span>
                  <span className="text-gray-100 text-sm font-medium">UTXO Preservation</span>
                </div>
                <p className="text-gray-400 text-xs leading-relaxed">
                  All financial data and the UTXO set integrity are preserved. Your node can fully validate
                  the chain, spend coins, and participate in consensus without any embedded content on disk.
                </p>
              </div>
            </div>
          </div>

          {/* Exorcist Mode A */}
          <div className="p-3 bg-gray-800/50 rounded-lg border border-gray-700">
            <h4 className="text-gray-200 font-medium text-sm mb-1">The Exorcist</h4>
            <p className="text-gray-400 text-xs leading-relaxed">
              The Exorcist is the core component that performs the actual stripping. It runs inside
              Ghost Core (<code className="text-amber-400">ghostd</code>) at the block acceptance layer,
              intercepting blocks before they are serialized to disk.
            </p>
            <div className="mt-2 p-2 bg-gray-900/50 rounded border border-gray-700">
              <div className="text-xs text-gray-400 leading-relaxed">
                <span className="text-amber-400 font-medium">Mode A (Active Stripping):</span> The Exorcist
                strips classified content before the block is written to disk. This is the default mode for
                hazed nodes — blocks arrive from the network, get stripped in memory, and only the clean
                version is persisted.
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* 4. Primary Content — Node Status */}
      <SectionErrorBoundary section="Haze Status">
        {isLoading ? <SkeletonCard /> : error ? (
          <Card>
            <CardHeader title="Node Status" />
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
            <div className="divide-y divide-gray-800">
              <StatusRow label="Storage Mode">
                <Badge variant={getModeBadgeVariant(mode)}>
                  {getModeLabel(mode)}
                </Badge>
              </StatusRow>
              <StatusRow label="Blocks Processed">
                <span className="font-mono text-sm text-gray-100">
                  {haze?.blocks.toLocaleString() ?? 0}
                </span>
              </StatusRow>
              <StatusRow label="Storage on Disk">
                <span className="font-mono text-sm text-gray-100">
                  {haze ? formatStorageGB(haze.size_on_disk) : "--"}
                </span>
              </StatusRow>
              <StatusRow label="Pruned">
                <Badge variant={haze?.pruned ? "warning" : "success"}>
                  {haze?.pruned ? "Yes" : "No"}
                </Badge>
              </StatusRow>
              <StatusRow label="Archive Mode">
                <Badge variant={haze?.archive_mode ? "success" : "default"}>
                  {haze?.archive_mode ? "Enabled" : "Disabled"}
                </Badge>
              </StatusRow>
              <StatusRow label="Chain">
                <span className="font-mono text-sm text-gray-100">
                  {haze?.chain ?? "--"}
                </span>
              </StatusRow>
            </div>
            {haze?.error && (
              <div className="mt-4 p-3 bg-red-900/20 border border-red-800 rounded-lg">
                <p className="text-red-400 text-sm">{haze.error}</p>
              </div>
            )}
          </Card>
        )}
      </SectionErrorBoundary>

      {/* 5. Technical Details (collapsible) */}
      <Card collapsible defaultCollapsed>
        <CardHeader
          title="Technical Details"
          subtitle="Legal compliance and data classification"
        />
        <div className="space-y-4">
          <div className="p-4 bg-gray-800/50 rounded-lg">
            <h4 className="text-amber-400 font-medium mb-2">No Illegal Content Storage</h4>
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
                <div className="w-8 h-8 rounded-full bg-amber-900/30 border border-amber-700 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <svg className="w-4 h-4 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
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
          <div className="pt-2 border-t border-gray-700">
            <p className="text-gray-400 text-xs mb-3">
              BUDS classification specification and legal framework for operating a hazed node.
            </p>
            <a
              href="/ghost-haze-legal-pack.pdf"
              download
              className="inline-flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white text-sm font-medium rounded-lg transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
              </svg>
              Download Legal Pack
            </a>
          </div>
        </div>
      </Card>
    </div>
  );
}
