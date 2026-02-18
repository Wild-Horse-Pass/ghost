"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { Tooltip } from "@/components/ui/Tooltip";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useShroudStatus } from "@/hooks/queries/useShroudQueries";

const TOOLTIPS = {
  enabled: "Whether Ghost Shroud relay delay is currently active on your node.",
  ghost_core: "Connection to Ghost Core (ghostd) is required for Shroud to intercept and delay relays.",
  max_delay: "The maximum random delay applied before relaying a transaction to peers.",
  avg_delay: "The average delay currently being applied across recent transaction relays.",
  timing_analysis: "Adversaries monitor when nodes relay transactions to infer which node originated them.",
  topology_mapping: "Adversaries map the network graph by observing relay timing patterns between nodes.",
};

function StatusRow({ label, tooltip, children }: { label: string; tooltip?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-gray-800 last:border-b-0">
      <div className="flex items-center gap-2">
        {tooltip ? (
          <Tooltip content={tooltip}>
            <span className="text-gray-400 text-sm cursor-help">{label}</span>
          </Tooltip>
        ) : (
          <span className="text-gray-400 text-sm">{label}</span>
        )}
      </div>
      <div>{children}</div>
    </div>
  );
}

function FlowStep({ label, sublabel, accent }: { label: string; sublabel: string; accent?: boolean }) {
  return (
    <div className={`flex-1 text-center px-3 py-4 rounded-lg border ${
      accent
        ? "bg-blue-900/10 border-blue-600/30"
        : "bg-gray-800/50 border-gray-700"
    }`}>
      <div className={`text-sm font-medium ${accent ? "text-blue-400" : "text-gray-100"}`}>
        {label}
      </div>
      <div className="text-xs text-gray-500 mt-1">{sublabel}</div>
    </div>
  );
}

function FlowArrow() {
  return (
    <div className="flex items-center px-1 text-gray-600 flex-shrink-0">
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
      </svg>
    </div>
  );
}

export default function ShroudPage() {
  const { data: status, isLoading } = useShroudStatus({ refetchInterval: 10_000 });

  const showSkeleton = isLoading && !status;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Ghost Shroud"
        subtitle="Transaction relay privacy layer"
        actions={
          status ? (
            <Badge variant={status.enabled ? "success" : "default"}>
              {status.enabled ? "Enabled" : "Disabled"}
            </Badge>
          ) : undefined
        }
      />

      {/* Hero Explanation */}
      <Card className="border-blue-600/30 bg-blue-900/10">
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 rounded-lg bg-blue-900/30 border border-blue-600/30 flex items-center justify-center flex-shrink-0">
            <svg className="w-5 h-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-blue-400 mb-2">Relay Privacy Protection</h3>
            <p className="text-gray-300 text-sm leading-relaxed">
              Ghost Shroud adds random delays before relaying transactions, breaking timing-based
              origin detection. Your transactions enter your mempool instantly — only relay to peers
              is delayed.
            </p>
          </div>
        </div>
      </Card>

      {/* Status Card */}
      <SectionErrorBoundary section="Shroud Status">
        {showSkeleton ? (
          <SkeletonCard />
        ) : status ? (
          <Card>
            <CardHeader
              title="Status"
              subtitle="Current Shroud relay configuration"
            />
            <div className="divide-y divide-gray-800">
              <StatusRow label="Shroud Enabled" tooltip={TOOLTIPS.enabled}>
                <StatusDot
                  status={status.enabled ? "online" : "offline"}
                  label={status.enabled ? "Active" : "Inactive"}
                  pulse={status.enabled}
                />
              </StatusRow>
              <StatusRow label="Ghost Core Connection" tooltip={TOOLTIPS.ghost_core}>
                <StatusDot
                  status={status.ghost_core_connected ? "online" : "offline"}
                  label={status.ghost_core_connected ? "Connected" : "Disconnected"}
                  pulse={status.ghost_core_connected}
                />
              </StatusRow>
              <StatusRow label="Max Delay" tooltip={TOOLTIPS.max_delay}>
                <span className="text-gray-100 font-mono text-sm">
                  {status.max_delay_ms.toLocaleString()} ms
                </span>
              </StatusRow>
              <StatusRow label="Avg Delay" tooltip={TOOLTIPS.avg_delay}>
                <span className="text-blue-400 font-mono text-sm">
                  {status.avg_delay_ms.toLocaleString()} ms
                </span>
              </StatusRow>
            </div>
          </Card>
        ) : null}
      </SectionErrorBoundary>

      {/* How It Works — Flow Diagram */}
      <SectionErrorBoundary section="How It Works">
        <Card>
          <CardHeader
            title="How It Works"
            subtitle="Transaction relay flow with Shroud enabled"
          />
          <div className="flex items-center gap-0 overflow-x-auto pb-2">
            <FlowStep label="TX received" sublabel="From wallet or peer" />
            <FlowArrow />
            <FlowStep label="Mempool" sublabel="Instant" />
            <FlowArrow />
            <FlowStep label="Random delay" sublabel="0-5s" accent />
            <FlowArrow />
            <FlowStep label="Relay to peers" sublabel="Delayed broadcast" />
          </div>
          <div className="mt-4 p-3 bg-gray-800/50 rounded-lg border border-gray-700">
            <p className="text-xs text-gray-400 leading-relaxed">
              When a transaction arrives, it is immediately added to your local mempool for mining
              and validation. Shroud only delays the <span className="text-blue-400">outbound relay</span> to
              other peers, making it impossible for observers to determine whether your node originated
              the transaction or simply forwarded it.
            </p>
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Privacy Properties */}
      <SectionErrorBoundary section="Privacy Properties">
        <Card>
          <CardHeader
            title="Privacy Properties"
            subtitle="What Shroud does and does not protect against"
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Protects Against */}
            <div className="p-4 bg-blue-900/10 rounded-lg border border-blue-600/30">
              <h4 className="text-sm font-medium text-blue-400 mb-3 flex items-center gap-2">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Protects Against
              </h4>
              <ul className="space-y-3">
                <Tooltip content={TOOLTIPS.timing_analysis}>
                  <li className="flex items-start gap-2 cursor-help">
                    <span className="text-green-400 mt-0.5 flex-shrink-0">
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                    </span>
                    <div>
                      <span className="text-gray-200 text-sm font-medium">Timing Analysis</span>
                      <p className="text-gray-500 text-xs mt-0.5">
                        Random delays make it impossible to identify the originating node by relay timing.
                      </p>
                    </div>
                  </li>
                </Tooltip>
                <Tooltip content={TOOLTIPS.topology_mapping}>
                  <li className="flex items-start gap-2 cursor-help">
                    <span className="text-green-400 mt-0.5 flex-shrink-0">
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                    </span>
                    <div>
                      <span className="text-gray-200 text-sm font-medium">Topology Mapping</span>
                      <p className="text-gray-500 text-xs mt-0.5">
                        Obscures the network graph by preventing relay order inference between peers.
                      </p>
                    </div>
                  </li>
                </Tooltip>
              </ul>
            </div>

            {/* Does Not Protect Against */}
            <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700">
              <h4 className="text-sm font-medium text-gray-400 mb-3 flex items-center gap-2">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Does Not Protect Against
              </h4>
              <ul className="space-y-3">
                <li className="flex items-start gap-2">
                  <span className="text-gray-500 mt-0.5 flex-shrink-0">
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </span>
                  <div>
                    <span className="text-gray-300 text-sm font-medium">Content Encryption</span>
                    <p className="text-gray-500 text-xs mt-0.5">
                      Transaction contents are not encrypted. Shroud only affects relay timing, not data.
                    </p>
                  </div>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-gray-500 mt-0.5 flex-shrink-0">
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </span>
                  <div>
                    <span className="text-gray-300 text-sm font-medium">Global Observer</span>
                    <p className="text-gray-500 text-xs mt-0.5">
                      An adversary monitoring all network links simultaneously may still correlate transactions.
                    </p>
                  </div>
                </li>
              </ul>
            </div>
          </div>
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
