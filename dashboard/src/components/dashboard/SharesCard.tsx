"use client";

import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { useShares } from "@/hooks/useNodeData";

const SHARE_TIERS = [
  { key: "archive_mode", name: "Archive Mode", bonus: 5 },
  { key: "ghost_pay", name: "Ghost Pay", bonus: 4 },
  { key: "public_mining", name: "Public Mining", bonus: 3 },
  { key: "reaper", name: "Reaper", bonus: 2 },
  { key: "elder", name: "Elder Status", bonus: 1 },
] as const;

export function SharesCard() {
  const { data: shares, loading, error } = useShares();

  if (loading && !shares) {
    return (
      <Card>
        <CardHeader title="Your Shares" subtitle="5-4-3-2-1 Reward System" />
        <div className="animate-pulse space-y-3">
          <div className="h-12 bg-gray-800 rounded w-1/2 mx-auto"></div>
          <div className="h-4 bg-gray-800 rounded w-3/4"></div>
          <div className="h-4 bg-gray-800 rounded w-3/4"></div>
        </div>
      </Card>
    );
  }

  if (!shares) {
    return (
      <Card>
        <CardHeader title="Your Shares" />
        <p className="text-gray-400">
          {error ? `Error: ${error.message}` : "Unable to load shares"}
        </p>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader
        title="Your Shares"
        subtitle="5-4-3-2-1 Reward System"
        action={
          <span className="text-2xl font-bold text-gray-100">
            {shares.total}
            <span className="text-gray-500 text-lg"> / {shares.max_shares}</span>
          </span>
        }
      />

      {/* Uptime Gatekeeper */}
      <div className={`mb-4 p-3 rounded-lg ${shares.uptime_qualified ? "bg-green-900/20 border border-green-800" : "bg-red-900/20 border border-red-800"}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className={shares.uptime_qualified ? "text-green-400" : "text-red-400"}>
              {shares.uptime_qualified ? "\u2713" : "\u2717"}
            </span>
            <span className="text-sm text-gray-300">Uptime Gatekeeper</span>
          </div>
          <Badge variant={shares.uptime_qualified ? "success" : "error"}>
            {(shares.uptime_percent ?? 0).toFixed(1)}% (min 95%)
          </Badge>
        </div>
        {!shares.uptime_qualified && (
          <p className="text-xs text-red-400 mt-2">
            Below 95% uptime - all shares disabled until uptime recovers
          </p>
        )}
      </div>

      {/* Share Tiers */}
      <div className="space-y-2">
        {SHARE_TIERS.map((tier) => {
          const isActive = shares[tier.key as keyof typeof shares] as boolean;
          const isDisabled = !shares.uptime_qualified;

          return (
            <div
              key={tier.key}
              className={`flex items-center justify-between p-2 rounded ${
                isActive && !isDisabled ? "bg-gray-800/50" : ""
              }`}
            >
              <div className="flex items-center gap-3">
                <span
                  className={`text-lg ${
                    isActive && !isDisabled
                      ? "text-green-400"
                      : isDisabled
                      ? "text-gray-700"
                      : "text-gray-600"
                  }`}
                >
                  {isActive ? "\u2713" : "\u2717"}
                </span>
                <span
                  className={
                    isActive && !isDisabled
                      ? "text-gray-100"
                      : isDisabled
                      ? "text-gray-600"
                      : "text-gray-500"
                  }
                >
                  {tier.name}
                  {tier.key === "elder" && shares.elder && shares.elder_slot && (
                    <span className="text-gray-500 ml-1">#{shares.elder_slot}</span>
                  )}
                </span>
              </div>
              <span
                className={`font-mono text-sm ${
                  isActive && !isDisabled
                    ? "text-green-400"
                    : isDisabled
                    ? "text-gray-700"
                    : "text-gray-600"
                }`}
              >
                +{tier.bonus}
              </span>
            </div>
          );
        })}
      </div>

      {/* Estimated Reward */}
      {shares.estimated_reward_btc != null && (
        <div className="mt-4 pt-4 border-t border-gray-800">
          <div className="flex justify-between items-center">
            <span className="text-sm text-gray-400">Est. Reward / Block</span>
            <span className="font-mono text-gray-100">
              ~{(shares.estimated_reward_btc ?? 0).toFixed(8)} BTC
            </span>
          </div>
        </div>
      )}
    </Card>
  );
}
