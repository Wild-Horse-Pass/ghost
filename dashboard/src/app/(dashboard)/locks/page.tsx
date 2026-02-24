"use client";

import { FlowDiagram } from "@/components/ui/FlowDiagram";
import { Card, CardHeader } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useGhostLocks, useSettlementStatus } from "@/hooks/queries";

// --- Constants ---

const TOOLTIPS = {
  active_locks: "Number of Ghost Lock UTXOs currently held by your node.",
  total_locked: "Total amount of Bitcoin held across all active locks.",
  pending: "Locks waiting for L1 settlement in the current reconciliation batch.",
  in_mixing: "Locks currently participating in a Wraith CoinJoin mix session.",
};

const DENOMINATION_TIERS = [
  { name: "Micro", sats: "10,000", btc: "0.0001", desc: "Tipping, micro-payments" },
  { name: "Tiny", sats: "100,000", btc: "0.001", desc: "Everyday transactions" },
  { name: "Small", sats: "1,000,000", btc: "0.01", desc: "Standard transfers" },
  { name: "Medium", sats: "10,000,000", btc: "0.1", desc: "Significant amounts" },
  { name: "Large", sats: "100,000,000", btc: "1.0", desc: "High-value custody" },
];

const RISK_TIERS = [
  { tier: "Low", threshold: "< 0.1 BTC", interval: "30 days", desc: "Micro and Tiny denominations" },
  { tier: "Medium", threshold: "0.1 – 1 BTC", interval: "14 days", desc: "Small and Medium denominations" },
  { tier: "High", threshold: "> 1 BTC", interval: "7 days", desc: "Large denomination locks" },
];

const SETTLEMENT_CLASSES = [
  { name: "Express", frequency: "Every epoch", participants: "10 min", desc: "Fastest settlement, highest priority" },
  { name: "Standard", frequency: "Every 24h", participants: "25 min", desc: "Default settlement class" },
  { name: "Economy", frequency: "Weekly", participants: "50 min", desc: "Lowest fee, batched settlement" },
];

// --- Types ---

type LockStatus = "Active" | "PendingSettlement" | "InMixing" | "Settled" | "Expired" | string;

// --- Helpers ---

function getStatusBadgeVariant(status: LockStatus): "success" | "warning" | "info" | "default" | "error" {
  switch (status) {
    case "Active": return "success";
    case "PendingSettlement": return "warning";
    case "InMixing": return "info";
    case "Settled": return "default";
    case "Expired": return "error";
    default: return "default";
  }
}

function getStatusLabel(status: LockStatus): string {
  switch (status) {
    case "PendingSettlement": return "Pending";
    case "InMixing": return "Mixing";
    default: return status;
  }
}

function truncateId(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 6)}...${id.slice(-6)}`;
}

function formatBtc(sats: number): string {
  return (sats / 100_000_000).toFixed(8);
}

function formatSats(sats: number): string {
  return sats.toLocaleString();
}

function formatDate(timestamp: number | null): string {
  if (!timestamp) return "--";
  return new Date(timestamp * 1000).toLocaleDateString();
}

// --- Page ---

export default function LocksPage() {
  const { data: locksData, isLoading: locksLoading } = useGhostLocks();
  const { data: reconciliation, isLoading: reconciliationLoading } = useSettlementStatus();

  const isLoading = locksLoading || reconciliationLoading;
  const summary = locksData?.summary;
  const locks = locksData?.locks ?? [];

  return (
    <div className="space-y-6">
      {/* 1. PageHeader */}
      <PageHeader
        title="Ghost Locks"
        subtitle="Timelocked P2TR outputs with automatic key rotation"
      />

      {/* 2. StatCards row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Active Locks"
          value={summary?.total_locks ?? locksData?.active_locks ?? 0}
          tooltip={TOOLTIPS.active_locks}
          loading={isLoading}
        />
        <StatCard
          label="Total Locked"
          value={summary?.total_balance ? `${formatSats(summary.total_balance)} sats` : locksData?.total_locked_sats ? `${formatSats(locksData.total_locked_sats)} sats` : "0 sats"}
          tooltip={TOOLTIPS.total_locked}
          loading={isLoading}
        />
        <StatCard
          label="Pending Settlement"
          value={summary?.pending_settlement ? formatSats(summary.pending_settlement) : "0"}
          sublabel="sats"
          tooltip={TOOLTIPS.pending}
          loading={isLoading}
        />
        <StatCard
          label="In Mixing"
          value={summary?.in_mixing ? formatSats(summary.in_mixing) : "0"}
          sublabel="sats"
          tooltip={TOOLTIPS.in_mixing}
          loading={isLoading}
        />
      </div>

      {/* 3. How It Works — collapsible, NOT wrapped in SectionErrorBoundary */}
      <Card collapsible defaultCollapsed>
        <CardHeader
          title="How It Works"
          subtitle="P2TR outputs with timelocked recovery"
        />
        <div className="space-y-4">
          <p className="text-sm text-gray-300 leading-relaxed">
            Ghost Locks are P2TR (Pay-to-Taproot) UTXOs with two spending paths: a key path for normal
            efficient spending, and a script path with a timelocked recovery clause. They represent the
            on-chain backing of funds held in Ghost Pay, using standard denominations for privacy.
          </p>

          {/* P2TR Structure — Key Path vs Script Path */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-green-900/10 rounded-lg border border-green-600/30">
              <h4 className="text-sm font-medium text-green-400 mb-2 flex items-center gap-2">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
                </svg>
                Key Path (Normal Spending)
              </h4>
              <ul className="space-y-2 text-sm text-gray-300">
                <li className="flex items-start gap-2">
                  <span className="text-green-400 mt-0.5 flex-shrink-0">
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  </span>
                  <span>Single <code className="text-green-400">lock_pubkey</code> signature</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-400 mt-0.5 flex-shrink-0">
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  </span>
                  <span>Most efficient -- looks like any P2TR spend</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-400 mt-0.5 flex-shrink-0">
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  </span>
                  <span>Used for transfers, mixing, and settlement</span>
                </li>
              </ul>
            </div>
            <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700">
              <h4 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-2">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Script Path (Recovery)
              </h4>
              <ul className="space-y-2 text-sm text-gray-300">
                <li className="flex items-start gap-2">
                  <span className="text-gray-500 mt-0.5 flex-shrink-0">
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </span>
                  <span>CLTV timelock + <code className="text-green-400">recovery_pubkey</code></span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-gray-500 mt-0.5 flex-shrink-0">
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </span>
                  <span>Only available after timelock expires</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-gray-500 mt-0.5 flex-shrink-0">
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </span>
                  <span>Emergency fund recovery if lock key is lost</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </Card>

      {/* 4. Primary Content — Active Locks table + Settlement stats */}
      <SectionErrorBoundary section="Active Locks">
        {isLoading ? <SkeletonCard /> : (
          <Card>
            <CardHeader
              title="Your Locks"
              subtitle={`${locks.length} lock${locks.length !== 1 ? "s" : ""}`}
            />
            {locks.length === 0 ? (
              <div className="py-8 text-center">
                <p className="text-gray-400 text-sm">No locks found. Create a lock through Ghost Wallet to get started.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800">
                      <th className="text-left py-2 px-3 text-gray-400 font-medium">Lock ID</th>
                      <th className="text-left py-2 px-3 text-gray-400 font-medium">Denomination</th>
                      <th className="text-right py-2 px-3 text-gray-400 font-medium">Balance</th>
                      <th className="text-left py-2 px-3 text-gray-400 font-medium">Status</th>
                      <th className="text-left py-2 px-3 text-gray-400 font-medium">Timelock</th>
                      <th className="text-left py-2 px-3 text-gray-400 font-medium">Next Jump</th>
                      <th className="text-left py-2 px-3 text-gray-400 font-medium">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {locks.map((lock) => (
                      <tr key={lock.lock_id} className="border-b border-gray-800/50 last:border-b-0 hover:bg-gray-800/30">
                        <td className="py-2.5 px-3 font-mono text-gray-100 text-xs">{truncateId(lock.lock_id)}</td>
                        <td className="py-2.5 px-3 text-gray-300">{lock.denomination}</td>
                        <td className="py-2.5 px-3 text-right font-mono text-green-400">{formatBtc(lock.balance)} BTC</td>
                        <td className="py-2.5 px-3">
                          <Badge variant={getStatusBadgeVariant(lock.status)}>
                            {getStatusLabel(lock.status)}
                          </Badge>
                        </td>
                        <td className="py-2.5 px-3 text-gray-400">{lock.timelock_tier}</td>
                        <td className="py-2.5 px-3 text-gray-400 font-mono text-xs">
                          {lock.next_jump_height ? lock.next_jump_height.toLocaleString() : "--"}
                        </td>
                        <td className="py-2.5 px-3 text-gray-500 text-xs">{formatDate(lock.created_at ?? null)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        )}
      </SectionErrorBoundary>

      <SectionErrorBoundary section="Settlement Status">
        {isLoading ? <SkeletonCard /> : (
          <Card>
            <CardHeader
              title="Settlement Status"
              subtitle="L2 to L1 reconciliation"
            />
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="text-center p-3 bg-gray-800/50 rounded-lg">
                <div className="text-lg font-bold text-gray-100">{reconciliation?.active_count ?? 0}</div>
                <div className="text-xs text-gray-400">Active Batches</div>
              </div>
              <div className="text-center p-3 bg-gray-800/50 rounded-lg">
                <div className="text-lg font-bold text-green-400">{reconciliation?.pending_count ?? 0}</div>
                <div className="text-xs text-gray-400">Pending</div>
              </div>
              <div className="text-center p-3 bg-gray-800/50 rounded-lg">
                <div className="text-lg font-bold text-green-400">{reconciliation?.batches_24h ?? 0}</div>
                <div className="text-xs text-gray-400">Confirmed (24h)</div>
              </div>
              <div className="text-center p-3 bg-gray-800/50 rounded-lg">
                <div className="text-lg font-bold text-gray-100">
                  {reconciliation?.l1_height?.toLocaleString() ?? "--"}
                </div>
                <div className="text-xs text-gray-400">L1 Height</div>
              </div>
            </div>
          </Card>
        )}
      </SectionErrorBoundary>

      {/* 5. Technical Details — collapsible, NOT wrapped in SectionErrorBoundary */}
      <Card collapsible defaultCollapsed>
        <CardHeader
          title="Technical Details"
          subtitle="Denomination tiers, key rotation, and settlement"
        />
        <div className="space-y-6">
          {/* Denomination Tiers */}
          <div>
            <h4 className="text-sm font-medium text-gray-200 mb-3">Denomination Tiers</h4>
            <p className="text-sm text-gray-400 mb-3">
              Standard lock amounts for privacy -- all locks in a mix use the same denomination.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800">
                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Tier</th>
                    <th className="text-right py-2 px-3 text-gray-400 font-medium">Sats</th>
                    <th className="text-right py-2 px-3 text-gray-400 font-medium">BTC</th>
                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Use Case</th>
                  </tr>
                </thead>
                <tbody>
                  {DENOMINATION_TIERS.map((tier) => (
                    <tr key={tier.name} className="border-b border-gray-800/50 last:border-b-0">
                      <td className="py-2.5 px-3 text-gray-100 font-medium">{tier.name}</td>
                      <td className="py-2.5 px-3 text-right font-mono text-green-400">{tier.sats}</td>
                      <td className="py-2.5 px-3 text-right font-mono text-gray-400">{tier.btc}</td>
                      <td className="py-2.5 px-3 text-gray-500">{tier.desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Jump Locks */}
          <div>
            <h4 className="text-sm font-medium text-gray-200 mb-2">Jump Locks -- Automatic Key Rotation</h4>
            <p className="text-sm text-gray-400 mb-3">
              Before the timelock on a lock expires, a Jump transaction atomically moves funds to a new
              lock with fresh keys. Higher-value locks rotate more frequently.
            </p>

            <FlowDiagram
              accentColor="green"
              steps={[
                { label: "GhostLock", sublabel: "old keys" },
                { label: "Jump TX", sublabel: "atomic swap", accent: true },
                { label: "GhostLock", sublabel: "fresh keys" },
              ]}
            />

            <div className="overflow-x-auto mt-4">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800">
                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Risk Tier</th>
                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Value Range</th>
                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Rotation Interval</th>
                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Denominations</th>
                  </tr>
                </thead>
                <tbody>
                  {RISK_TIERS.map((tier) => (
                    <tr key={tier.tier} className="border-b border-gray-800/50 last:border-b-0">
                      <td className="py-2.5 px-3">
                        <Badge variant={tier.tier === "High" ? "error" : tier.tier === "Medium" ? "warning" : "success"}>
                          {tier.tier}
                        </Badge>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-gray-100">{tier.threshold}</td>
                      <td className="py-2.5 px-3 text-green-400">{tier.interval}</td>
                      <td className="py-2.5 px-3 text-gray-500">{tier.desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Settlement Classes */}
          <div>
            <h4 className="text-sm font-medium text-gray-200 mb-2">Settlement Classes</h4>
            <p className="text-sm text-gray-400 mb-3">
              Reconciliation settles Ghost Pay L2 state back to Bitcoin L1 in batches. Each epoch cycle
              processes settlement requests, grouping them by class for efficient on-chain settlement.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800">
                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Class</th>
                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Frequency</th>
                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Min Participants</th>
                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {SETTLEMENT_CLASSES.map((cls) => (
                    <tr key={cls.name} className="border-b border-gray-800/50 last:border-b-0">
                      <td className="py-2.5 px-3 text-gray-100 font-medium">{cls.name}</td>
                      <td className="py-2.5 px-3 font-mono text-green-400">{cls.frequency}</td>
                      <td className="py-2.5 px-3 text-gray-400">{cls.participants}</td>
                      <td className="py-2.5 px-3 text-gray-500">{cls.desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
}
