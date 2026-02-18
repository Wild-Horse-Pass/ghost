"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";

const DETECTION_VECTORS = [
  {
    name: "Inscription Envelopes",
    desc: "Detects OP_FALSE OP_IF ... OP_ENDIF witness patterns used by Ordinal inscriptions to embed arbitrary data.",
  },
  {
    name: "Drop Stuffing",
    desc: "Identifies unreachable OP_DROP sequences that push and immediately discard data, wasting block space.",
  },
  {
    name: "Unreachable Code",
    desc: "Finds dead code paths in witness scripts that can never execute but bloat transaction size.",
  },
  {
    name: "Fake Pubkeys",
    desc: "Detects invalid or non-functional public keys used as data carriers in multisig outputs.",
  },
  {
    name: "Oversized OP_RETURN",
    desc: "Flags OP_RETURN outputs exceeding standard relay limits, used for embedding large data payloads.",
  },
  {
    name: "Annex Bloat",
    desc: "Identifies taproot annex fields carrying non-consensus data, exploiting the annex discount.",
  },
  {
    name: "Excess Witness Data",
    desc: "Catches witness items far exceeding what the script actually consumes during execution.",
  },
  {
    name: "Legacy ScriptSig Data",
    desc: "Detects data-carrying patterns in legacy scriptSig fields that serve no signing purpose.",
  },
];

export default function ReaperPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Ghost Reaper"
        subtitle="Dead code detection and mempool filtering"
      />

      {/* Stats row — placeholder data */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Mode" value="--" sublabel="coming soon" />
        <StatCard label="Dead TXs Filtered" value="--" sublabel="coming soon" />
        <StatCard label="Dead Bytes Stripped" value="--" sublabel="coming soon" />
        <StatCard label="False Positive Rate" value="--" sublabel="coming soon" />
      </div>

      {/* Hero card */}
      <SectionErrorBoundary section="Ghost Reaper Overview">
        <Card className="border-orange-600/30 bg-orange-900/10">
          <div className="flex items-start gap-4">
            <div className="w-10 h-10 rounded-lg bg-orange-900/30 border border-orange-600/30 flex items-center justify-center flex-shrink-0">
              <svg className="w-5 h-5 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
              </svg>
            </div>
            <div>
              <h2 className="text-lg font-semibold text-orange-400 mb-2">What is Ghost Reaper?</h2>
              <p className="text-gray-300 text-sm leading-relaxed">
                Ghost Reaper detects non-financial data embedded in transaction witnesses — inscriptions,
                drop stuffing, fake pubkeys, and other dead code patterns. When enabled, your mempool rejects
                transactions carrying dead weight, keeping your node focused on real monetary transactions.
              </p>
            </div>
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Detection Vectors */}
      <SectionErrorBoundary section="Detection Vectors">
        <Card>
          <CardHeader
            title="Detection Vectors"
            subtitle="Patterns Ghost Reaper identifies and filters"
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {DETECTION_VECTORS.map((vector) => (
              <div key={vector.name} className="p-3 bg-gray-800/50 rounded-lg border border-gray-700">
                <div className="flex items-start gap-3">
                  <div className="w-6 h-6 rounded-full bg-orange-900/30 border border-orange-600/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <svg className="w-3 h-3 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" />
                    </svg>
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-100">{vector.name}</div>
                    <div className="text-xs text-gray-400 mt-0.5">{vector.desc}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* +2 Shares */}
      <SectionErrorBoundary section="Share Bonus">
        <Card className="border-green-600/30 bg-green-900/10">
          <div className="flex items-start gap-4">
            <div className="w-10 h-10 rounded-lg bg-green-900/30 border border-green-600/30 flex items-center justify-center flex-shrink-0">
              <span className="text-green-400 font-bold text-sm">+2</span>
            </div>
            <div>
              <h2 className="text-lg font-semibold text-green-400 mb-2">Share Bonus</h2>
              <p className="text-gray-300 text-sm leading-relaxed">
                Nodes running Ghost Reaper earn <span className="text-green-400 font-semibold">+2 shares</span> in
                the node reward pool. This is part of the 5-4-3-2-1 capability system: Archive (+5), Ghost Pay (+4),
                Public Mining (+3), <span className="text-orange-400 font-semibold">Ghost Reaper (+2)</span>, Elder (+1).
              </p>
            </div>
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Reaper vs Mempool Policy */}
      <SectionErrorBoundary section="Reaper vs Mempool Policy">
        <Card>
          <CardHeader
            title="Reaper vs Mempool Policy"
            subtitle="Understanding the distinction"
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-orange-900/10 rounded-lg border border-orange-600/30">
              <h4 className="text-sm font-medium text-orange-400 mb-2">Ghost Reaper</h4>
              <ul className="space-y-2 text-xs text-gray-300">
                <li className="flex items-start gap-2">
                  <span className="text-orange-400 mt-0.5 flex-shrink-0">&bull;</span>
                  Specifically targets <span className="text-orange-400 font-medium">dead code</span> in witness scripts
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-orange-400 mt-0.5 flex-shrink-0">&bull;</span>
                  Detects inscriptions, drop stuffing, fake pubkeys, annex bloat
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-orange-400 mt-0.5 flex-shrink-0">&bull;</span>
                  Works at the witness/script level, not transaction-level policy
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-orange-400 mt-0.5 flex-shrink-0">&bull;</span>
                  Can run alongside any mempool policy
                </li>
              </ul>
            </div>
            <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700">
              <h4 className="text-sm font-medium text-gray-400 mb-2">Mempool Policy</h4>
              <ul className="space-y-2 text-xs text-gray-300">
                <li className="flex items-start gap-2">
                  <span className="text-gray-500 mt-0.5 flex-shrink-0">&bull;</span>
                  Controls which transactions your node accepts based on <span className="text-gray-100 font-medium">fee rates, sizes, and standardness</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-gray-500 mt-0.5 flex-shrink-0">&bull;</span>
                  Configurable profiles: standard, strict, clean, custom
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-gray-500 mt-0.5 flex-shrink-0">&bull;</span>
                  Operates at the transaction level (size, fee, output type)
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-gray-500 mt-0.5 flex-shrink-0">&bull;</span>
                  Independent of Ghost Reaper — they complement each other
                </li>
              </ul>
            </div>
          </div>
          <div className="mt-4 p-3 bg-gray-800/50 rounded-lg border border-gray-700">
            <p className="text-xs text-gray-400 leading-relaxed">
              <span className="text-orange-400 font-medium">Key point:</span> Ghost Reaper is NOT a mempool policy.
              You can run Ghost Reaper alongside any mempool policy (standard, strict, clean, etc.). Mempool policies
              filter by economic rules; Ghost Reaper filters by content analysis of witness scripts.
            </p>
          </div>
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
