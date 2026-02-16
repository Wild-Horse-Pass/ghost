"use client";

import { Card, CardHeader } from "@/components/ui/Card";
import { useTreasury } from "@/hooks/useNodeData";

const DECAY_SCHEDULE = [
  { year: 0, treasury: 0.5, nodePool: 0.5 },
  { year: 1, treasury: 0.4, nodePool: 0.6 },
  { year: 2, treasury: 0.3, nodePool: 0.7 },
  { year: 3, treasury: 0.2, nodePool: 0.8 },
  { year: 4, treasury: 0.1, nodePool: 0.9 },
  { year: 5, treasury: 0.0, nodePool: 1.0 },
];

export function DecentralisationCard() {
  const { data: treasury, loading, error } = useTreasury();

  if (loading && !treasury) {
    return (
      <Card className="col-span-full">
        <CardHeader title="Decentralisation Status" />
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-gray-800 rounded w-full"></div>
          <div className="h-20 bg-gray-800 rounded w-full"></div>
        </div>
      </Card>
    );
  }

  if (!treasury) {
    return (
      <Card className="col-span-full">
        <CardHeader title="Decentralisation Status" />
        <p className="text-gray-400">
          {error ? `Error: ${error.message}` : "Unable to load treasury status"}
        </p>
      </Card>
    );
  }

  const phase = treasury.phase ?? "bootstrap";
  const phaseLabel = {
    bootstrap: "BOOTSTRAP",
    decay: "DECAY",
    ossified: "OSSIFIED",
  }[phase] ?? "UNKNOWN";

  const phaseColor = {
    bootstrap: "text-yellow-400",
    decay: "text-blue-400",
    ossified: "text-green-400",
  }[phase] ?? "text-gray-400";

  return (
    <Card className="col-span-full">
      <CardHeader title="Decentralisation Status" />

      <div className="space-y-6">
        {/* Treasury Progress Bar */}
        <div>
          <div className="flex justify-between text-sm mb-2">
            <span className="text-gray-400">Treasury Progress</span>
            <span className="text-gray-100">
              {(treasury.accumulated_btc ?? 0).toFixed(2)} / {(treasury.target_btc ?? 21).toFixed(1)} BTC
              <span className="text-gray-500 ml-2">
                ({(treasury.progress_percent ?? 0).toFixed(1)}%)
              </span>
            </span>
          </div>
          <div className="h-4 bg-gray-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-purple-600 to-purple-400 transition-all duration-500"
              style={{ width: `${Math.min(treasury.progress_percent ?? 0, 100)}%` }}
            />
          </div>
        </div>

        {/* Phase Info */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-gray-800/50 rounded-lg">
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide">Phase</div>
            <div className={`text-lg font-semibold ${phaseColor ?? 'text-gray-400'}`}>{phaseLabel ?? 'Unknown'}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide">Decay Year</div>
            <div className="text-lg font-semibold text-gray-100">
              {treasury.decay_started && treasury.decay_year !== null
                ? `Year ${treasury.decay_year}`
                : "Not started"}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide">Treasury</div>
            <div className="text-lg font-semibold text-gray-100">
              {(treasury.treasury_percent ?? 50).toFixed(2)}% of subsidy
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide">Node Pool</div>
            <div className="text-lg font-semibold text-gray-100">
              {(treasury.node_pool_percent ?? 50).toFixed(2)}% of subsidy
            </div>
          </div>
        </div>

        {/* Ossification Timeline */}
        <div>
          <div className="text-sm text-gray-400 mb-3">Ossification Timeline</div>
          <div className="flex items-center justify-between">
            {DECAY_SCHEDULE.map((step) => {
              const decayYear = treasury.decay_year ?? 0;
              const isCurrentYear = treasury.decay_started && decayYear === step.year;
              const isPast = treasury.decay_started && treasury.decay_year != null && step.year < decayYear;
              const isOssified = treasury.phase === "ossified";

              let dotColor = "bg-gray-600";
              if (isOssified && step.year === 5) dotColor = "bg-green-500";
              else if (isCurrentYear) dotColor = "bg-purple-500 animate-pulse";
              else if (isPast) dotColor = "bg-purple-400";
              else if (!treasury.decay_started && step.year === 0) dotColor = "bg-yellow-500";

              return (
                <div key={step.year} className="flex flex-col items-center flex-1">
                  <div className={`w-3 h-3 rounded-full ${dotColor}`} />
                  <div className="text-xs text-gray-500 mt-1">
                    {step.year === 0 ? "21 BTC" : `Yr ${step.year}`}
                  </div>
                  <div className="text-xs text-gray-600 mt-0.5">
                    {step.treasury}%
                  </div>
                </div>
              );
            })}
          </div>
          <div className="flex justify-between mt-2">
            <span className="text-xs text-gray-500">Bootstrap</span>
            <span className="text-xs text-gray-500">Fully Ossified</span>
          </div>
        </div>
      </div>
    </Card>
  );
}
