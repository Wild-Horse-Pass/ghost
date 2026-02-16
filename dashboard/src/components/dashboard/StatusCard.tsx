"use client";

import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { useNodeStatus } from "@/hooks/useNodeData";

const MODE_CONFIG_PRIMARY = [
  { key: "archive_mode", name: "Archive Mode" },
  { key: "ghost_pay", name: "Ghost Pay" },
  { key: "public_mining", name: "Public Mining" },
  { key: "bitcoin_pure", name: "Bitcoin Pure" },
] as const;

const MODE_CONFIG_SECONDARY = [
  { key: "private_mining", name: "Private Mining" },
  { key: "ghost_mode", name: "Ghost Mode" },
] as const;

export function StatusCard() {
  const { data: status, loading, error } = useNodeStatus();

  if (loading && !status) {
    return (
      <Card>
        <CardHeader title="Node Status" />
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-gray-800 rounded w-3/4"></div>
          <div className="h-4 bg-gray-800 rounded w-1/2"></div>
        </div>
      </Card>
    );
  }

  if (!status) {
    return (
      <Card>
        <CardHeader title="Node Status" />
        <p className="text-gray-400">
          {error ? `Error: ${error.message}` : "Unable to load status"}
        </p>
      </Card>
    );
  }

  const getColorClasses = (active: boolean) => {
    if (active) {
      return { dot: "bg-green-500", badge: "success" as const };
    }
    return { dot: "bg-red-500", badge: "error" as const };
  };

  return (
    <Card>
      <CardHeader
        title="Node Status"
        action={
          <Badge variant={status.is_synced ? "success" : "warning"}>
            {status.is_synced ? "Synced" : "Syncing..."}
          </Badge>
        }
      />

      <div className="space-y-4">
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Block Height</span>
          <span className="font-mono text-gray-100">
            {(status.sync_height ?? status.block_height ?? 0).toLocaleString()}
          </span>
        </div>

        <div className="flex justify-between items-center">
          <span className="text-gray-400">Peers</span>
          <span className="font-mono text-gray-100">{status.peer_count ?? 0}</span>
        </div>

        <div className="flex justify-between items-center">
          <span className="text-gray-400">Mempool Profile</span>
          <span className="font-mono text-gray-100 text-sm capitalize">
            {(status.mempool_profile ?? "standard").replace("_", " ")}
          </span>
        </div>

        <div className="flex justify-between items-center">
          <span className="text-gray-400">Template Profile</span>
          <span className="font-mono text-gray-100 text-sm capitalize">
            {(status.template_profile ?? "standard").replace("_", " ")}
          </span>
        </div>

        <div className="pt-4 border-t border-gray-800 space-y-2">
          {MODE_CONFIG_PRIMARY.map((mode) => {
            const isActive = status[mode.key as keyof typeof status] as boolean;
            const colors = getColorClasses(isActive);

            return (
              <div key={mode.key} className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${colors.dot}`} />
                <span className="text-sm text-gray-300 flex-1">{mode.name}</span>
                <Badge variant={colors.badge}>
                  {isActive ? "Active" : "Off"}
                </Badge>
              </div>
            );
          })}
        </div>

        <div className="pt-3 border-t border-gray-800/50 space-y-2">
          {MODE_CONFIG_SECONDARY.map((mode) => {
            const isActive = status[mode.key as keyof typeof status] as boolean;
            const colors = getColorClasses(isActive);

            return (
              <div key={mode.key} className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${colors.dot}`} />
                <span className="text-sm text-gray-300 flex-1">{mode.name}</span>
                <Badge variant={colors.badge}>
                  {isActive ? "Active" : "Off"}
                </Badge>
              </div>
            );
          })}
        </div>
      </div>
    </Card>
  );
}
