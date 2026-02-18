"use client";

import Link from "next/link";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import {
  useGhostPayStatus,
  useWraithStats,
  useSettlementStatus,
  useGhostLocks,
} from "@/hooks/queries";

function formatL2Block(era: number, height: number): string {
  if (era <= 1) return height.toLocaleString();
  return `${era}:${height.toLocaleString()}`;
}

function FeatureCard({
  href,
  icon,
  name,
  description,
  statusLabel,
  statusVariant,
  accentColor,
}: {
  href?: string;
  icon: React.ReactNode;
  name: string;
  description: string;
  statusLabel: string;
  statusVariant: "success" | "warning" | "info" | "default";
  accentColor: string;
}) {
  const content = (
    <div className={`p-5 rounded-lg border ${accentColor} bg-gray-800/30 hover:bg-gray-800/50 transition-colors h-full flex flex-col`}>
      <div className="flex items-start justify-between mb-3">
        <div className="w-9 h-9 rounded-lg bg-gray-800/80 border border-gray-700 flex items-center justify-center flex-shrink-0">
          {icon}
        </div>
        <Badge variant={statusVariant}>{statusLabel}</Badge>
      </div>
      <h3 className="text-gray-100 font-semibold text-sm mb-1.5">{name}</h3>
      <p className="text-gray-400 text-xs leading-relaxed flex-1">{description}</p>
      {href && (
        <div className="mt-3 text-cyan-400 text-xs font-medium">
          Learn more &rarr;
        </div>
      )}
    </div>
  );

  if (href) {
    return <Link href={href} className="block">{content}</Link>;
  }
  return content;
}

export default function GhostPayPage() {
  const { data: status, isLoading: statusLoading, error: statusError } = useGhostPayStatus();
  const { data: wraithStats, isLoading: wraithLoading } = useWraithStats();
  const { data: reconciliation, isLoading: reconciliationLoading } = useSettlementStatus();
  const { data: locksData, isLoading: locksLoading } = useGhostLocks();

  const isLoading = statusLoading || wraithLoading || reconciliationLoading || locksLoading;

  // If Ghost Pay is not enabled / not reachable
  if (!isLoading && statusError) {
    return (
      <div className="space-y-6">
        <PageHeader title="Ghost Pay" subtitle="L2 instant payments and privacy toolkit" />
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
  const activeLocks = locksData?.summary?.total_locks ?? locksData?.active_locks ?? 0;
  const activeSessions = wraithStats?.active_sessions ?? 0;
  const pendingSettlement = reconciliation?.pending_count ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Ghost Pay"
        subtitle="L2 instant payments and privacy toolkit"
      />

      {/* Status Banner */}
      <SectionErrorBoundary section="Status Banner">
        {isLoading ? <SkeletonCard /> : (
          <div className="flex items-center gap-6 px-4 py-3 rounded-lg border border-cyan-600/20 bg-cyan-900/10">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              <span className="text-sm text-gray-300">
                L2 Block <span className="font-mono text-cyan-400">{formatL2Block(l2Era, l2Height)}</span>
              </span>
            </div>
            <div className="text-sm text-gray-400">
              Epoch <span className="font-mono text-gray-300">{status?.epoch ?? 0}</span>
            </div>
            <div className="text-sm text-gray-400">
              {status?.peer_count ?? 0} peers
            </div>
            <div className="text-sm text-gray-400">
              {status?.sync_state === "synced" ? (
                <Badge variant="success">Synced</Badge>
              ) : status?.sync_state ? (
                <Badge variant="warning">{status.sync_state}</Badge>
              ) : (
                <Badge variant="default">Unknown</Badge>
              )}
            </div>
          </div>
        )}
      </SectionErrorBoundary>

      {/* Privacy Feature Cards */}
      <SectionErrorBoundary section="Privacy Features">
        {isLoading ? <SkeletonCard /> : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <FeatureCard
              href="/locks"
              icon={
                <svg className="w-4.5 h-4.5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
                </svg>
              }
              name="Ghost Locks"
              description="P2TR UTXOs with timelocked recovery paths for secure fund custody."
              statusLabel={`${activeLocks} lock${activeLocks !== 1 ? "s" : ""}`}
              statusVariant={activeLocks > 0 ? "success" : "default"}
              accentColor="border-cyan-600/20"
            />
            <FeatureCard
              href="/locks"
              icon={
                <svg className="w-4.5 h-4.5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182" />
                </svg>
              }
              name="Jump Locks"
              description="Risk-tiered automatic key rotation for proactive security."
              statusLabel="Built-in"
              statusVariant="info"
              accentColor="border-cyan-600/20"
            />
            <FeatureCard
              href="/wraith"
              icon={
                <svg className="w-4.5 h-4.5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" />
                </svg>
              }
              name="Ghost Wraith"
              description="Two-phase CoinJoin mixing that breaks UTXO history links."
              statusLabel={activeSessions > 0 ? `${activeSessions} active` : "Idle"}
              statusVariant={activeSessions > 0 ? "success" : "default"}
              accentColor="border-red-600/20"
            />
            <FeatureCard
              icon={
                <svg className="w-4.5 h-4.5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
                </svg>
              }
              name="Ghost Keys"
              description="Silent Payment-style addresses — single ID, unlimited unique addresses."
              statusLabel="Built-in"
              statusVariant="info"
              accentColor="border-cyan-600/20"
            />
            <FeatureCard
              href="/locks"
              icon={
                <svg className="w-4.5 h-4.5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 4.5h14.25M3 9h9.75M3 13.5h9.75m4.5-4.5v12m0 0l-3.75-3.75M17.25 21l3.75-3.75" />
                </svg>
              }
              name="Reconciliation"
              description="Batch L1 settlement — Express, Standard, and Economy classes."
              statusLabel={pendingSettlement > 0 ? `${pendingSettlement} pending` : "Idle"}
              statusVariant={pendingSettlement > 0 ? "warning" : "default"}
              accentColor="border-cyan-600/20"
            />
            <FeatureCard
              href="/shroud"
              icon={
                <svg className="w-4.5 h-4.5 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" />
                </svg>
              }
              name="Ghost Shroud"
              description="Transaction relay privacy via random delays — complements Wraith."
              statusLabel="Relay privacy"
              statusVariant="default"
              accentColor="border-purple-600/20"
            />
          </div>
        )}
      </SectionErrorBoundary>

      {/* Fee Structure */}
      <SectionErrorBoundary section="Fee Structure">
        <Card className="border-cyan-600/20">
          <div className="flex items-start gap-4 mb-4">
            <div className="w-9 h-9 rounded-lg bg-cyan-900/30 border border-cyan-600/30 flex items-center justify-center flex-shrink-0">
              <svg className="w-4.5 h-4.5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v12m-3-2.818l.879.659c1.171.879 3.07.879 4.242 0 1.172-.879 1.172-2.303 0-3.182C13.536 12.219 12.768 12 12 12c-.725 0-1.45-.22-2.003-.659-1.106-.879-1.106-2.303 0-3.182s2.9-.879 4.006 0l.415.33M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div>
              <h2 className="text-sm font-semibold text-cyan-400">Fee Structure</h2>
              <p className="text-gray-400 text-xs mt-0.5">Ghost Pay transaction and mixing fees</p>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left py-2 px-3 text-gray-400 font-medium">Service</th>
                  <th className="text-right py-2 px-3 text-gray-400 font-medium">Fee</th>
                  <th className="text-left py-2 px-3 text-gray-400 font-medium">Description</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-b border-gray-800/50">
                  <td className="py-2.5 px-3 text-gray-100 font-medium">L2 Transfer</td>
                  <td className="py-2.5 px-3 text-right font-mono text-cyan-400">10 sats + 0.1%</td>
                  <td className="py-2.5 px-3 text-gray-500">Instant Ghost Pay transfers between wallets</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-3 text-gray-100 font-medium">Wraith Mix</td>
                  <td className="py-2.5 px-3 text-right font-mono text-red-400">1%</td>
                  <td className="py-2.5 px-3 text-gray-500">CoinJoin mixing via Ghost Wraith</td>
                </tr>
              </tbody>
            </table>
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* How Privacy Layers Stack */}
      <SectionErrorBoundary section="Privacy Layers">
        <Card className="border-cyan-600/20 bg-cyan-900/5">
          <div className="flex items-start gap-4">
            <div className="w-9 h-9 rounded-lg bg-cyan-900/30 border border-cyan-600/30 flex items-center justify-center flex-shrink-0">
              <svg className="w-4.5 h-4.5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6.429 9.75L2.25 12l4.179 2.25m0-4.5l5.571 3 5.571-3m-11.142 0L2.25 7.5 12 2.25l9.75 5.25-4.179 2.25m0 0L12 12.75 6.43 9.75m11.142 0l4.179 2.25L12 17.25 2.25 12l4.179-2.25m11.142 0l4.179 2.25L12 22.5 2.25 17.25l4.179-2.25" />
              </svg>
            </div>
            <div>
              <h2 className="text-sm font-semibold text-cyan-400 mb-2">How Privacy Layers Stack</h2>
              <p className="text-gray-300 text-sm leading-relaxed">
                Ghost Pay combines multiple privacy layers. <span className="text-cyan-400">Ghost Keys</span> hide
                your identity with unique addresses per payment. <span className="text-red-400">Ghost Wraith</span> breaks
                transaction links through CoinJoin mixing. <span className="text-purple-400">Ghost Shroud</span> hides
                relay timing to prevent network-level correlation. <span className="text-cyan-400">Ghost Locks</span> secure
                your funds with timelocked P2TR recovery paths and automatic key rotation via Jump Locks.
              </p>
            </div>
          </div>
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
