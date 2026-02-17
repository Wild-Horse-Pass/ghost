"use client";

import { useState, useEffect, useCallback } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Toggle } from "@/components/ui/Toggle";
import * as api from "@/lib/api";
import type { NodeConfig, MempoolProfile, TemplateProfile } from "@/types/api";

const MEMPOOL_PROFILES: { value: MempoolProfile; label: string; description: string }[] = [
  { value: "standard", label: "Standard", description: "Default Bitcoin Core behavior" },
  { value: "strict", label: "Strict", description: "Reject non-standard transactions" },
  { value: "clean", label: "Clean", description: "Minimal metadata, T0/T1 only" },
  { value: "structured", label: "Structured", description: "BUDS-aware classification" },
  { value: "app_friendly", label: "App-Friendly", description: "Accept T2 application data" },
  { value: "ghost", label: "Ghost", description: "Private mempool, no relay" },
];

const TEMPLATE_PROFILES: { value: TemplateProfile; label: string; description: string }[] = [
  { value: "standard", label: "Standard", description: "Default block template" },
  { value: "max_fee", label: "Max Fee", description: "Prioritize highest fee transactions" },
  { value: "strict", label: "Strict", description: "Only standard transactions" },
  { value: "clean_block", label: "Clean Block", description: "T0/T1 only, no metadata" },
  { value: "structured", label: "Structured", description: "BUDS-aware ordering" },
  { value: "app_friendly", label: "App-Friendly", description: "Include T2 application data" },
  { value: "ghost_block", label: "Ghost Block", description: "Private template construction" },
];

export default function ConfigPage() {
  const [config, setConfig] = useState<NodeConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState<string | null>(null);

  const fetchConfig = useCallback(async () => {
    try {
      const data = await api.getConfig();
      setConfig(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch config");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchConfig();
  }, [fetchConfig]);

  const handleToggle = async (key: string, setter: (enabled: boolean) => Promise<NodeConfig>) => {
    if (!config) return;
    setSaving(key);
    try {
      const newValue = !config[key as keyof NodeConfig];
      const updated = await setter(newValue as boolean);
      setConfig(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update");
    } finally {
      setSaving(null);
    }
  };

  const handleMempoolProfile = async (profile: MempoolProfile) => {
    setSaving("mempool");
    try {
      const updated = await api.setMempoolProfile(profile);
      setConfig(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update");
    } finally {
      setSaving(null);
    }
  };

  const handleTemplateProfile = async (profile: TemplateProfile) => {
    setSaving("template");
    try {
      const updated = await api.setTemplateProfile(profile);
      setConfig(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update");
    } finally {
      setSaving(null);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 p-8">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-2xl font-bold text-gray-100 mb-6">Configuration</h1>
          <div className="animate-pulse space-y-6">
            <div className="h-64 bg-gray-800 rounded-lg"></div>
            <div className="h-48 bg-gray-800 rounded-lg"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-2xl font-bold text-gray-100 mb-6">Configuration</h1>

        {error && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-800 rounded-lg">
            <p className="text-red-400">{error}</p>
          </div>
        )}

        {/* Node Modes */}
        <Card className="mb-6">
          <CardHeader
            title="Node Modes"
            subtitle="Enable features to earn shares in the reward pool"
          />

          <div className="space-y-4">
            {/* Ghost Mode */}
            <div className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg">
              <div className="flex-1">
                <div className="flex items-center gap-3">
                  <div className="text-gray-100 font-medium">Ghost Mode</div>
                  <Badge variant="info">Privacy</Badge>
                </div>
                <p className="text-sm text-gray-400 mt-1">
                  Private mempool, no transaction relay, blocks-only connections
                </p>
              </div>
              <Toggle
                enabled={config?.ghost_mode ?? false}
                onChange={() => handleToggle("ghost_mode", api.setGhostMode)}
                label="Ghost Mode"
                disabled={saving === "ghost_mode"}
              />
            </div>

            {/* Archive Mode */}
            <div className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg">
              <div className="flex-1">
                <div className="flex items-center gap-3">
                  <div className="text-gray-100 font-medium">Archive Mode</div>
                  <Badge variant="success">+5 Shares</Badge>
                </div>
                <p className="text-sm text-gray-400 mt-1">
                  Store full blockchain history, serve historical data to network
                </p>
              </div>
              <Toggle
                enabled={config?.archive_mode ?? false}
                onChange={() => handleToggle("archive_mode", api.setArchiveMode)}
                label="Archive Mode"
                disabled={saving === "archive_mode"}
              />
            </div>

            {/* Public Mining */}
            <div className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg">
              <div className="flex-1">
                <div className="flex items-center gap-3">
                  <div className="text-gray-100 font-medium">Public Mining</div>
                  <Badge variant="info">+3 Shares</Badge>
                </div>
                <p className="text-sm text-gray-400 mt-1">
                  Accept mining connections from public miners
                </p>
              </div>
              <Toggle
                enabled={config?.public_mining ?? false}
                onChange={() => handleToggle("public_mining", api.setPublicMiningConfig)}
                label="Public Mining"
                disabled={saving === "public_mining"}
              />
            </div>
          </div>
        </Card>

        {/* Mempool Profile */}
        <Card className="mb-6">
          <CardHeader
            title="Mempool Profile"
            subtitle="Configure transaction acceptance policy"
          />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {MEMPOOL_PROFILES.map((profile) => {
              const isActive = config?.mempool_profile === profile.value;
              return (
                <button
                  key={profile.value}
                  onClick={() => handleMempoolProfile(profile.value)}
                  disabled={saving === "mempool"}
                  className={`p-4 rounded-lg text-left transition-all ${
                    isActive
                      ? "bg-orange-900/30 border-2 border-orange-500"
                      : "bg-gray-800/50 border-2 border-transparent hover:border-gray-700"
                  } ${saving === "mempool" ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  <div className="flex items-center justify-between">
                    <span className={`font-medium ${isActive ? "text-orange-300" : "text-gray-100"}`}>
                      {profile.label}
                    </span>
                    {isActive && (
                      <Badge variant="info">Active</Badge>
                    )}
                  </div>
                  <p className="text-sm text-gray-400 mt-1">{profile.description}</p>
                </button>
              );
            })}
          </div>
        </Card>

        {/* Template Profile */}
        <Card className="mb-6">
          <CardHeader
            title="Block Template Profile"
            subtitle="Configure block construction policy"
          />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {TEMPLATE_PROFILES.map((profile) => {
              const isActive = config?.template_profile === profile.value;
              return (
                <button
                  key={profile.value}
                  onClick={() => handleTemplateProfile(profile.value)}
                  disabled={saving === "template"}
                  className={`p-4 rounded-lg text-left transition-all ${
                    isActive
                      ? "bg-orange-900/30 border-2 border-orange-500"
                      : "bg-gray-800/50 border-2 border-transparent hover:border-gray-700"
                  } ${saving === "template" ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  <div className="flex items-center justify-between">
                    <span className={`font-medium ${isActive ? "text-orange-300" : "text-gray-100"}`}>
                      {profile.label}
                    </span>
                    {isActive && (
                      <Badge variant="info">Active</Badge>
                    )}
                  </div>
                  <p className="text-sm text-gray-400 mt-1">{profile.description}</p>
                </button>
              );
            })}
          </div>
        </Card>

        {/* Bitcoin Pure Info */}
        <Card>
          <CardHeader
            title="Bitcoin Pure Mode"
            subtitle="Spam-free operation (+2 shares)"
          />
          <div className="p-4 bg-yellow-900/20 border border-yellow-800 rounded-lg">
            <p className="text-yellow-300 text-sm">
              Bitcoin Pure mode is automatically enabled when using Clean or Strict profiles
              for both mempool and template. This earns +2 additional shares.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <span className="text-gray-400 text-sm">Current Status:</span>
              <Badge variant={
                (config?.mempool_profile === "clean" || config?.mempool_profile === "strict") &&
                (config?.template_profile === "clean_block" || config?.template_profile === "strict")
                  ? "success"
                  : "default"
              }>
                {(config?.mempool_profile === "clean" || config?.mempool_profile === "strict") &&
                (config?.template_profile === "clean_block" || config?.template_profile === "strict")
                  ? "Active"
                  : "Inactive"}
              </Badge>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
