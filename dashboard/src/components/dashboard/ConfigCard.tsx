"use client";

import { useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Toggle } from "@/components/ui/Toggle";
import { useConfig } from "@/hooks/useNodeData";

export function ConfigCard() {
  const { data: config, loading, error, setGhostMode, setArchiveMode } = useConfig();
  const [updating, setUpdating] = useState<string | null>(null);

  const handleGhostMode = async (enabled: boolean) => {
    setUpdating("ghost_mode");
    try {
      await setGhostMode(enabled);
    } finally {
      setUpdating(null);
    }
  };

  const handleArchiveMode = async (enabled: boolean) => {
    setUpdating("archive_mode");
    try {
      await setArchiveMode(enabled);
    } finally {
      setUpdating(null);
    }
  };

  // Show loading skeleton only on initial load (no data yet)
  if (loading && !config) {
    return (
      <Card>
        <CardHeader title="Configuration" />
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-gray-800 rounded w-full"></div>
          <div className="h-6 bg-gray-800 rounded w-full"></div>
        </div>
      </Card>
    );
  }

  if (!config) {
    return (
      <Card>
        <CardHeader title="Configuration" />
        <p className="text-gray-400">
          {error ? `Error: ${error.message}` : "Unable to load configuration"}
        </p>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader title="Configuration" subtitle="Node settings" />

      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-gray-100 font-medium">Ghost Mode</div>
            <div className="text-sm text-gray-400">
              Private blocks-only peer mode
            </div>
          </div>
          <Toggle
            enabled={config.ghost_mode ?? false}
            onChange={handleGhostMode}
            label="Ghost Mode"
            disabled={updating === "ghost_mode"}
          />
        </div>

        <div className="flex items-center justify-between">
          <div>
            <div className="text-gray-100 font-medium">Archive Mode</div>
            <div className="text-sm text-gray-400">
              Full chain storage, no pruning
            </div>
          </div>
          <Toggle
            enabled={config.archive_mode ?? false}
            onChange={handleArchiveMode}
            label="Archive Mode"
            disabled={updating === "archive_mode"}
          />
        </div>

        <div className="pt-4 border-t border-gray-800">
          <div className="flex justify-between mb-2">
            <span className="text-gray-400">Mempool Profile</span>
            <span className="text-gray-100 capitalize">
              {(config.mempool_profile ?? "standard").replace("_", " ")}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">Template Profile</span>
            <span className="text-gray-100 capitalize">
              {(config.template_profile ?? "standard").replace("_", " ")}
            </span>
          </div>
        </div>
      </div>
    </Card>
  );
}
