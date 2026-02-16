"use client";

import { useState, useEffect } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Toggle } from "@/components/ui/Toggle";
import { Dialog } from "@/components/ui/Dialog";
import { SkeletonCard } from "@/components/ui/Skeleton";
import {
  useNodeInfo,
  useNickname,
  useSetNickname,
  useNodeStatus,
  useConfig,
  useFullConfig,
  useSetGhostMode,
  useSetArchiveMode,
  useSetBitcoinPure,
  useSetPublicMining,
  useSetPayoutAddress,
  useSetGhostPayPayoutAddress,
  useGhostPayStatus,
  useMempoolProfiles,
  useSaveMempoolProfile,
  useDeleteMempoolProfile,
  useActivateMempoolProfile,
  useTemplateProfiles,
  useSaveTemplateProfile,
  useDeleteTemplateProfile,
  useActivateTemplateProfile,
  type CustomMempoolProfile,
  type CustomTemplateProfile,
} from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { useUIStore, ACCENT_COLORS, type AccentColorKey } from "@/stores";

// Default values for new profiles
const DEFAULT_MEMPOOL_PROFILE: Omit<CustomMempoolProfile, "name"> = {
  // Core settings
  min_relay_tx_fee: 1,
  max_mempool_size: 300,
  mempool_expiry: 336,
  max_orphan_tx: 100,
  permit_bare_multisig: true,
  datacarrier: true,
  datacarrier_size: 83,
  accept_non_std_outputs: false,
  mempool_full_rbf: true,
  incremental_relay_fee: 1,
  // Ghost Extensions
  dust_limit: 546,
  max_tx_size: 100000,
  prefer_native_segwit: false,
  reject_legacy_p2pkh: false,
  filter_inscriptions: false,
  filter_brc20: false,
  filter_runes: false,
  max_witness_size: 500000,
  prioritize_ln_opens: false,
  prioritize_ln_closes: false,
  prefer_coinjoin: false,
  min_coinjoin_participants: 3,
  max_ancestor_count: 25,
  max_descendant_count: 25,
  max_ancestor_size: 101000,
  // BUDS tiers
  accept_t0: true,
  accept_t1: false,
  accept_t2: false,
  accept_t3: false,
};

const DEFAULT_TEMPLATE_PROFILE: Omit<CustomTemplateProfile, "name"> = {
  // Core settings
  block_max_weight: 4000000,
  block_min_tx_fee: 1,
  prioritise_by_fee: true,
  prioritise_by_age: false,
  // Ghost Extensions
  reserve_weight_for_ln: 0,
  max_sigops_per_block: 80000,
  prefer_small_txs: false,
  filter_inscriptions: false,
  filter_brc20: false,
  filter_runes: false,
  max_witness_item: 500000,
  boost_consolidations: false,
  boost_batched_payments: false,
  enable_package_relay: true,
  max_package_count: 25,
  randomize_tx_order: false,
  fee_band_size: 1,
  include_free_relay: false,
  free_relay_limit: 0,
  // BUDS tiers
  include_t0: true,
  include_t1: false,
  include_t2: false,
  include_t3: false,
  priority_order: ["t0", "t1", "t2", "t3"],
};

function SettingsSection({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader title={title} subtitle={subtitle} />
      <div className="space-y-4">{children}</div>
    </Card>
  );
}

function ToggleRow({
  label,
  description,
  enabled,
  onChange,
  disabled = false,
  badge,
}: {
  label: string;
  description: string;
  enabled: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  badge?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span className="text-gray-100 font-medium">{label}</span>
          {badge}
        </div>
        <div className="text-sm text-gray-400">{description}</div>
      </div>
      <Toggle enabled={enabled} onChange={onChange} label={label} disabled={disabled} />
    </div>
  );
}

function NumberInput({
  label,
  value,
  onChange,
  min,
  max,
  step = 1,
  unit,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
  step?: number;
  unit?: string;
}) {
  return (
    <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
      <span className="text-gray-100">{label}</span>
      <div className="flex items-center gap-2">
        <Input
          type="number"
          value={value}
          onChange={(e) => onChange(Number(e.target.value))}
          min={min}
          max={max}
          step={step}
          className="w-24 text-right"
        />
        {unit && <span className="text-gray-400 text-sm w-12">{unit}</span>}
      </div>
    </div>
  );
}

export default function SettingsPage() {
  const { data: nodeInfo, isLoading: nodeInfoLoading } = useNodeInfo();
  const { data: nicknameData } = useNickname();
  const { data: status, isLoading: statusLoading } = useNodeStatus();
  const { data: config, isLoading: configLoading } = useConfig();
  const { data: fullConfig } = useFullConfig();
  const { data: mempoolProfilesData } = useMempoolProfiles();
  const { data: templateProfilesData } = useTemplateProfiles();

  const { data: ghostPayStatus } = useGhostPayStatus();

  // UI Store for theme settings
  const accentColor = useUIStore((s) => s.accentColor);
  const setAccentColor = useUIStore((s) => s.setAccentColor);

  const setNicknameMutation = useSetNickname();
  const setGhostMode = useSetGhostMode();
  const setArchiveMode = useSetArchiveMode();
  const setBitcoinPure = useSetBitcoinPure();
  const setPublicMining = useSetPublicMining();
  const setPayoutAddressMutation = useSetPayoutAddress();
  const setGhostPayPayoutAddressMutation = useSetGhostPayPayoutAddress();
  const saveMempoolProfile = useSaveMempoolProfile();
  const deleteMempoolProfile = useDeleteMempoolProfile();
  const activateMempoolProfile = useActivateMempoolProfile();
  const saveTemplateProfile = useSaveTemplateProfile();
  const deleteTemplateProfile = useDeleteTemplateProfile();
  const activateTemplateProfile = useActivateTemplateProfile();

  const { success, error } = useToast();

  // Local state for editing
  const [nickname, setNickname] = useState("");
  const [miningPayoutAddress, setMiningPayoutAddress] = useState("");
  const [ghostPayPayoutAddress, setGhostPayPayoutAddress] = useState("");
  const [mempoolDialogOpen, setMempoolDialogOpen] = useState(false);
  const [templateDialogOpen, setTemplateDialogOpen] = useState(false);
  const [editingMempoolProfile, setEditingMempoolProfile] = useState<CustomMempoolProfile | null>(
    null
  );
  const [editingTemplateProfile, setEditingTemplateProfile] =
    useState<CustomTemplateProfile | null>(null);

  // Initialize nickname from data - sync from server data to local state
  useEffect(() => {
    if (nicknameData?.nickname) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setNickname(nicknameData.nickname);
    }
  }, [nicknameData]);

  // Initialize payout addresses from config
  useEffect(() => {
    if (fullConfig?.payout?.address && !miningPayoutAddress) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setMiningPayoutAddress(fullConfig.payout.address);
    }
    if (fullConfig?.payout?.ghostpay_address && !ghostPayPayoutAddress) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setGhostPayPayoutAddress(fullConfig.payout.ghostpay_address);
    }
  }, [fullConfig?.payout?.address, fullConfig?.payout?.ghostpay_address]);

  const mempoolProfiles = mempoolProfilesData?.profiles ?? [];
  const templateProfiles = templateProfilesData?.profiles ?? [];
  const isLoading = nodeInfoLoading || statusLoading || configLoading;
  const budsEnabled = status?.ghost_pay ?? false;

  const handleSaveNickname = async () => {
    try {
      await setNicknameMutation.mutateAsync(nickname);
      success("Nickname Saved", "Node nickname updated successfully");
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleSaveMiningPayoutAddress = async () => {
    try {
      const address = miningPayoutAddress.trim() || null;
      await setPayoutAddressMutation.mutateAsync(address);
      success("Address Saved", "Mining payout address updated successfully");
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleSaveGhostPayPayoutAddress = async () => {
    try {
      const address = ghostPayPayoutAddress.trim() || null;
      await setGhostPayPayoutAddressMutation.mutateAsync(address);
      success("Address Saved", "GhostPay payout address updated successfully");
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleGhostModeToggle = async (enabled: boolean) => {
    try {
      await setGhostMode.mutateAsync(enabled);
      success("Mode Changed", `Ghost Mode ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleArchiveModeToggle = async (enabled: boolean) => {
    try {
      await setArchiveMode.mutateAsync(enabled);
      success("Mode Changed", `Archive Mode ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleBitcoinPureToggle = async (enabled: boolean) => {
    try {
      await setBitcoinPure.mutateAsync(enabled);
      success(
        "Mode Changed",
        enabled
          ? "Bitcoin Pure enabled - profiles locked to bitcoin_pure"
          : "Bitcoin Pure disabled - profiles reset to standard"
      );
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleNewMempoolProfile = () => {
    setEditingMempoolProfile({ name: "", ...DEFAULT_MEMPOOL_PROFILE });
    setMempoolDialogOpen(true);
  };

  const handleEditMempoolProfile = (profile: CustomMempoolProfile) => {
    setEditingMempoolProfile({ ...profile });
    setMempoolDialogOpen(true);
  };

  const handleSaveMempoolProfile = async () => {
    if (!editingMempoolProfile || !editingMempoolProfile.name.trim()) {
      error("Invalid Name", "Profile name is required");
      return;
    }

    try {
      await saveMempoolProfile.mutateAsync(editingMempoolProfile);
      success("Profile Saved", `Mempool profile "${editingMempoolProfile.name}" saved`);
      setMempoolDialogOpen(false);
      setEditingMempoolProfile(null);
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleDeleteMempoolProfile = async (name: string) => {
    try {
      await deleteMempoolProfile.mutateAsync(name);
      success("Profile Deleted", `Mempool profile "${name}" deleted`);
    } catch (err) {
      error("Delete Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleActivateMempoolProfile = async (name: string) => {
    try {
      await activateMempoolProfile.mutateAsync(name);
      success("Profile Activated", `Mempool profile "${name}" is now active`);
    } catch (err) {
      error("Activation Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleNewTemplateProfile = () => {
    setEditingTemplateProfile({ name: "", ...DEFAULT_TEMPLATE_PROFILE });
    setTemplateDialogOpen(true);
  };

  const handleEditTemplateProfile = (profile: CustomTemplateProfile) => {
    setEditingTemplateProfile({ ...profile });
    setTemplateDialogOpen(true);
  };

  const handleSaveTemplateProfile = async () => {
    if (!editingTemplateProfile || !editingTemplateProfile.name.trim()) {
      error("Invalid Name", "Profile name is required");
      return;
    }

    try {
      await saveTemplateProfile.mutateAsync(editingTemplateProfile);
      success("Profile Saved", `Template profile "${editingTemplateProfile.name}" saved`);
      setTemplateDialogOpen(false);
      setEditingTemplateProfile(null);
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleDeleteTemplateProfile = async (name: string) => {
    try {
      await deleteTemplateProfile.mutateAsync(name);
      success("Profile Deleted", `Template profile "${name}" deleted`);
    } catch (err) {
      error("Delete Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleActivateTemplateProfile = async (name: string) => {
    try {
      await activateTemplateProfile.mutateAsync(name);
      success("Profile Activated", `Template profile "${name}" is now active`);
    } catch (err) {
      error("Activation Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-100">Settings</h1>

      {isLoading ? (
        <>
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </>
      ) : (
        <>
          {/* Node Identity */}
          <SettingsSection title="Node Identity" subtitle="Configure your node identification">
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Node Nickname</label>
                <div className="flex gap-3">
                  <Input
                    value={nickname}
                    onChange={(e) => setNickname(e.target.value)}
                    placeholder="Enter a nickname for this node"
                    className="flex-1"
                  />
                  <Button
                    onClick={handleSaveNickname}
                    loading={setNicknameMutation.isPending}
                    disabled={nickname === nicknameData?.nickname}
                  >
                    Save
                  </Button>
                </div>
                <p className="text-xs text-gray-500 mt-1">
                  Useful for identifying nodes in multi-node setups
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <div className="text-sm text-gray-400 mb-1">Node ID</div>
                  <code className="text-gray-100 text-sm break-all">
                    {nodeInfo?.node_id ?? "Loading..."}
                  </code>
                </div>
                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <div className="text-sm text-gray-400 mb-1">Ghost ID (Short)</div>
                  <code className="text-purple-400 text-sm">
                    {nodeInfo?.node_id_short ?? "Loading..."}
                  </code>
                </div>
              </div>

              <div className="p-3 bg-gray-800/50 rounded-lg">
                <div className="flex justify-between items-center">
                  <div className="text-sm text-gray-400">Version</div>
                  <Badge variant="info">{nodeInfo?.version ?? "Unknown"}</Badge>
                </div>
              </div>
            </div>
          </SettingsSection>

          {/* Payout Addresses */}
          <SettingsSection
            title="Payout Addresses"
            subtitle="Configure where your rewards are sent"
          >
            <div className="space-y-4">
              {/* Mining Payout Address */}
              <div>
                <label className="block text-sm text-gray-400 mb-1">Mining Payout Address</label>
                <div className="flex gap-3">
                  <Input
                    value={miningPayoutAddress}
                    onChange={(e) => setMiningPayoutAddress(e.target.value)}
                    placeholder="Enter your Bitcoin address (bc1q...)"
                    className="flex-1 font-mono text-sm"
                  />
                  <Button
                    onClick={handleSaveMiningPayoutAddress}
                    loading={setPayoutAddressMutation.isPending}
                    disabled={miningPayoutAddress === (fullConfig?.payout?.address ?? "")}
                  >
                    Save
                  </Button>
                </div>
                <p className="text-xs text-gray-500 mt-1">
                  Mining block rewards and coinbase fees will be sent to this address
                </p>
              </div>

              {/* GhostPay Payout Address */}
              <div>
                <label className="block text-sm text-gray-400 mb-1">GhostPay Fee Address</label>
                <div className="flex gap-3">
                  <Input
                    value={ghostPayPayoutAddress}
                    onChange={(e) => setGhostPayPayoutAddress(e.target.value)}
                    placeholder="Enter your Bitcoin address (bc1q...)"
                    className="flex-1 font-mono text-sm"
                  />
                  <Button
                    onClick={handleSaveGhostPayPayoutAddress}
                    loading={setGhostPayPayoutAddressMutation.isPending}
                    disabled={ghostPayPayoutAddress === (fullConfig?.payout?.ghostpay_address ?? "")}
                  >
                    Save
                  </Button>
                </div>
                <p className="text-xs text-gray-500 mt-1">
                  GhostPay L2 transaction fee distributions will be sent to this address.
                  Requires Ghost Pay to be enabled.
                </p>
                {!ghostPayStatus?.l2_height && (
                  <p className="text-xs text-yellow-500 mt-1">
                    Ghost Pay is not running - fee distributions require an active ghost-pay-node
                  </p>
                )}
              </div>
            </div>
          </SettingsSection>

          {/* Appearance */}
          <SettingsSection title="Appearance" subtitle="Customize the dashboard theme">
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-3">Accent Color</label>
                <div className="grid grid-cols-4 sm:grid-cols-8 gap-3">
                  {(Object.entries(ACCENT_COLORS) as [AccentColorKey, typeof ACCENT_COLORS[AccentColorKey]][]).map(
                    ([key, color]) => (
                      <button
                        key={key}
                        onClick={() => setAccentColor(key)}
                        className={`
                          relative w-full aspect-square rounded-lg transition-all duration-200
                          ${accentColor === key
                            ? 'ring-2 ring-white ring-offset-2 ring-offset-gray-900 scale-110'
                            : 'hover:scale-105'
                          }
                        `}
                        style={{ backgroundColor: color.hex }}
                        title={color.name}
                      >
                        {accentColor === key && (
                          <div className="absolute inset-0 flex items-center justify-center">
                            <svg className="w-5 h-5 text-white drop-shadow-lg" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                            </svg>
                          </div>
                        )}
                      </button>
                    )
                  )}
                </div>
                <p className="text-xs text-gray-500 mt-3">
                  Current: <span style={{ color: ACCENT_COLORS[accentColor].hex }}>{ACCENT_COLORS[accentColor].name}</span>
                </p>
              </div>
            </div>
          </SettingsSection>

          {/* Operating Modes */}
          <SettingsSection title="Operating Modes" subtitle="Configure node operation modes">
            <ToggleRow
              label="Ghost Mode"
              description="Enable Ghost protocol features and L2 participation"
              enabled={status?.ghost_mode ?? false}
              onChange={handleGhostModeToggle}
              disabled={setGhostMode.isPending}
              badge={
                status?.ghost_mode ? (
                  <Badge variant="success">Active</Badge>
                ) : (
                  <Badge variant="default">Inactive</Badge>
                )
              }
            />

            <ToggleRow
              label="Archive Mode"
              description="Store full blockchain history (+5 shares bonus)"
              enabled={status?.archive_mode ?? false}
              onChange={handleArchiveModeToggle}
              disabled={setArchiveMode.isPending}
              badge={
                status?.archive_mode ? (
                  <Badge variant="success">+5 Shares</Badge>
                ) : null
              }
            />

            <ToggleRow
              label="Ghost Pay"
              description="Enable L2 payment network participation - requires ghost-pay-node running"
              enabled={ghostPayStatus?.l2_height ? true : false}
              onChange={() => {}}
              disabled
              badge={
                ghostPayStatus?.l2_height ? (
                  <Badge variant="success">Active (L2: {ghostPayStatus.l2_height})</Badge>
                ) : (
                  <Badge variant="warning">Not Running</Badge>
                )
              }
            />

            <ToggleRow
              label="Public Mining"
              description="Accept mining connections from public miners (+3 shares bonus)"
              enabled={status?.public_mining ?? false}
              onChange={(enabled) => setPublicMining.mutate(enabled)}
              disabled={setPublicMining.isPending}
              badge={
                status?.public_mining ? (
                  <Badge variant="success">+3 Shares</Badge>
                ) : null
              }
            />

            <ToggleRow
              label="Bitcoin Pure"
              description="Activates bitcoin_pure mempool and block policies. Locks profile selectors when enabled. (+2 shares)"
              enabled={config?.bitcoin_pure ?? false}
              onChange={handleBitcoinPureToggle}
              disabled={setBitcoinPure.isPending}
              badge={
                config?.bitcoin_pure ? (
                  <Badge variant="success">+2 Shares</Badge>
                ) : null
              }
            />
          </SettingsSection>

          {/* Mempool Policy Profiles */}
          <SettingsSection
            title="Mempool Policy Profiles"
            subtitle="Configure which transactions to accept in your mempool"
          >
            {config?.bitcoin_pure && (
              <div className="p-3 bg-yellow-900/30 border border-yellow-700/50 rounded-lg mb-4">
                <div className="text-yellow-400 font-medium">Locked by Bitcoin Pure Mode</div>
                <div className="text-sm text-yellow-500/80">
                  Disable Bitcoin Pure to change mempool profiles
                </div>
              </div>
            )}

            <div className="p-3 bg-gray-800/50 rounded-lg flex justify-between items-center">
              <div>
                <div className="text-gray-100">Current Profile</div>
                <div className="text-sm text-gray-400">
                  {config?.mempool_profile ?? "standard"}
                </div>
              </div>
              <Badge variant="info">{config?.mempool_profile ?? "standard"}</Badge>
            </div>

            {/* Preset profiles */}
            <div className={`grid grid-cols-1 md:grid-cols-2 gap-2 ${config?.bitcoin_pure ? "opacity-50 pointer-events-none" : ""}`}>
              {[
                { name: "standard", desc: "Bitcoin Core defaults - balanced acceptance" },
                { name: "strict", desc: "Higher fees, reject low-value transactions" },
                { name: "clean", desc: "Filter inscriptions, ordinals, and BRC-20" },
                { name: "structured", desc: "Optimized for transaction batching" },
                { name: "app_friendly", desc: "Accept more experimental tx types" },
                { name: "ghost", desc: "Full Ghost protocol support (requires Ghost Mode)" },
              ].map((profile) => (
                <button
                  key={profile.name}
                  className={`p-3 rounded-lg border transition-colors text-left ${
                    config?.mempool_profile === profile.name
                      ? "bg-purple-900/30 border-purple-600 text-purple-300"
                      : "bg-gray-800/50 border-gray-700 text-gray-300 hover:border-gray-500"
                  }`}
                  onClick={() => activateMempoolProfile.mutate(profile.name)}
                  disabled={config?.bitcoin_pure || (profile.name === "ghost" && !status?.ghost_mode)}
                >
                  <div className="font-medium capitalize">{profile.name.replace("_", " ")}</div>
                  <div className="text-xs text-gray-500 mt-1">{profile.desc}</div>
                </button>
              ))}
            </div>

            {/* Custom profiles */}
            {mempoolProfiles.length > 0 && (
              <div className={`space-y-2 ${config?.bitcoin_pure ? "opacity-50 pointer-events-none" : ""}`}>
                <h4 className="text-sm font-medium text-gray-300">Custom Profiles</h4>
                {mempoolProfiles.map((profile) => (
                  <div
                    key={profile.name}
                    className="p-3 bg-gray-800/50 rounded-lg flex justify-between items-center"
                  >
                    <div>
                      <div className="text-gray-100">{profile.name}</div>
                      <div className="text-xs text-gray-500">
                        Fee: {profile.min_relay_tx_fee} sat/vB | Tiers:{" "}
                        {[
                          profile.accept_t0 && "T0",
                          profile.accept_t1 && "T1",
                          profile.accept_t2 && "T2",
                          profile.accept_t3 && "T3",
                        ]
                          .filter(Boolean)
                          .join(", ") || "None"}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => handleEditMempoolProfile(profile)}
                        disabled={config?.bitcoin_pure}
                      >
                        Edit
                      </Button>
                      <Button
                        size="sm"
                        variant="primary"
                        onClick={() => handleActivateMempoolProfile(profile.name)}
                        disabled={config?.bitcoin_pure}
                      >
                        Use
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleDeleteMempoolProfile(profile.name)}
                        disabled={config?.bitcoin_pure}
                      >
                        Delete
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <Button
              onClick={handleNewMempoolProfile}
              variant="secondary"
              className="w-full"
              disabled={config?.bitcoin_pure}
            >
              Create Custom Mempool Profile
            </Button>
          </SettingsSection>

          {/* Block Template Profiles */}
          <SettingsSection
            title="Block Template Profiles"
            subtitle="Configure which transactions to include when mining blocks"
          >
            {config?.bitcoin_pure && (
              <div className="p-3 bg-yellow-900/30 border border-yellow-700/50 rounded-lg mb-4">
                <div className="text-yellow-400 font-medium">Locked by Bitcoin Pure Mode</div>
                <div className="text-sm text-yellow-500/80">
                  Disable Bitcoin Pure to change template profiles
                </div>
              </div>
            )}

            <div className="p-3 bg-gray-800/50 rounded-lg flex justify-between items-center">
              <div>
                <div className="text-gray-100">Current Profile</div>
                <div className="text-sm text-gray-400">
                  {config?.template_profile ?? "standard"}
                </div>
              </div>
              <Badge variant="info">{config?.template_profile ?? "standard"}</Badge>
            </div>

            {/* Preset profiles */}
            <div className={`grid grid-cols-1 md:grid-cols-2 gap-2 ${config?.bitcoin_pure ? "opacity-50 pointer-events-none" : ""}`}>
              {[
                { name: "standard", desc: "Balanced fee optimization" },
                { name: "max_fee", desc: "Maximize fee revenue per block" },
                { name: "strict", desc: "Only high-fee, standard transactions" },
                { name: "clean_block", desc: "Exclude inscriptions and ordinals" },
                { name: "structured", desc: "Prioritize batched payments" },
                { name: "app_friendly", desc: "Include experimental tx types" },
                { name: "ghost_block", desc: "Full Ghost protocol (requires Ghost Mode)" },
              ].map((profile) => (
                <button
                  key={profile.name}
                  className={`p-3 rounded-lg border transition-colors text-left ${
                    config?.template_profile === profile.name
                      ? "bg-purple-900/30 border-purple-600 text-purple-300"
                      : "bg-gray-800/50 border-gray-700 text-gray-300 hover:border-gray-500"
                  }`}
                  onClick={() => activateTemplateProfile.mutate(profile.name)}
                  disabled={config?.bitcoin_pure || (profile.name === "ghost_block" && !status?.ghost_mode)}
                >
                  <div className="font-medium capitalize">{profile.name.replace(/_/g, " ")}</div>
                  <div className="text-xs text-gray-500 mt-1">{profile.desc}</div>
                </button>
              ))}
            </div>

            {/* Custom profiles */}
            {templateProfiles.length > 0 && (
              <div className={`space-y-2 ${config?.bitcoin_pure ? "opacity-50 pointer-events-none" : ""}`}>
                <h4 className="text-sm font-medium text-gray-300">Custom Profiles</h4>
                {templateProfiles.map((profile) => (
                  <div
                    key={profile.name}
                    className="p-3 bg-gray-800/50 rounded-lg flex justify-between items-center"
                  >
                    <div>
                      <div className="text-gray-100">{profile.name}</div>
                      <div className="text-xs text-gray-500">
                        Min Fee: {profile.block_min_tx_fee} sat/vB | Tiers:{" "}
                        {[
                          profile.include_t0 && "T0",
                          profile.include_t1 && "T1",
                          profile.include_t2 && "T2",
                          profile.include_t3 && "T3",
                        ]
                          .filter(Boolean)
                          .join(", ") || "None"}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => handleEditTemplateProfile(profile)}
                        disabled={config?.bitcoin_pure}
                      >
                        Edit
                      </Button>
                      <Button
                        size="sm"
                        variant="primary"
                        onClick={() => handleActivateTemplateProfile(profile.name)}
                        disabled={config?.bitcoin_pure}
                      >
                        Use
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleDeleteTemplateProfile(profile.name)}
                        disabled={config?.bitcoin_pure}
                      >
                        Delete
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <Button
              onClick={handleNewTemplateProfile}
              variant="secondary"
              className="w-full"
              disabled={config?.bitcoin_pure}
            >
              Create Custom Template Profile
            </Button>
          </SettingsSection>

        </>
      )}

      {/* Mempool Profile Editor Dialog */}
      <Dialog
        isOpen={mempoolDialogOpen}
        onClose={() => {
          setMempoolDialogOpen(false);
          setEditingMempoolProfile(null);
        }}
        title={editingMempoolProfile?.name ? `Edit Profile: ${editingMempoolProfile.name}` : "New Mempool Profile"}
      >
        {editingMempoolProfile && (
          <div className="space-y-4 max-h-[70vh] overflow-y-auto">
            {/* Advanced User Warning */}
            <div className="p-4 bg-orange-900/20 border border-orange-700 rounded-lg">
              <div className="flex items-start gap-3">
                <span className="text-orange-400 text-xl">&#9888;</span>
                <div>
                  <h4 className="text-orange-300 font-medium">Advanced Configuration</h4>
                  <p className="text-orange-300/80 text-sm mt-1">
                    Custom mempool profiles are intended for advanced users. Incorrect settings may
                    cause your node to reject valid transactions or accept unwanted ones.
                  </p>
                  <p className="text-orange-300/80 text-sm mt-2">
                    If you&apos;re unsure, use one of the preset profiles instead. For guidance, refer to
                    the <a href="/docs/mempool-profiles" className="text-orange-200 underline hover:text-orange-100">Mempool Profile Guide</a>.
                  </p>
                </div>
              </div>
            </div>

            {/* Profile Name */}
            <div>
              <label className="block text-sm text-gray-400 mb-1">Profile Name</label>
              <Input
                value={editingMempoolProfile.name}
                onChange={(e) =>
                  setEditingMempoolProfile({ ...editingMempoolProfile, name: e.target.value })
                }
                placeholder="My Custom Profile"
              />
            </div>

            {/* Core Mempool Settings */}
            <div>
              <h4 className="text-sm font-medium text-gray-300 mb-3">Core Mempool Settings</h4>
              <div className="space-y-2">
                <NumberInput
                  label="Min Relay Fee"
                  value={editingMempoolProfile.min_relay_tx_fee}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, min_relay_tx_fee: v })
                  }
                  min={0}
                  step={0.1}
                  unit="sat/vB"
                />
                <NumberInput
                  label="Max Mempool Size"
                  value={editingMempoolProfile.max_mempool_size}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, max_mempool_size: v })
                  }
                  min={50}
                  max={1000}
                  unit="MB"
                />
                <NumberInput
                  label="Mempool Expiry"
                  value={editingMempoolProfile.mempool_expiry}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, mempool_expiry: v })
                  }
                  min={1}
                  unit="hours"
                />
                <NumberInput
                  label="Max Orphan Transactions"
                  value={editingMempoolProfile.max_orphan_tx}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, max_orphan_tx: v })
                  }
                  min={0}
                  max={1000}
                  unit=""
                />
              </div>
            </div>

            {/* Transaction Acceptance */}
            <div>
              <h4 className="text-sm font-medium text-gray-300 mb-3">Transaction Acceptance</h4>
              <div className="space-y-2">
                <ToggleRow
                  label="Permit Bare Multisig"
                  description="Allow bare multisig without P2SH wrapper"
                  enabled={editingMempoolProfile.permit_bare_multisig}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, permit_bare_multisig: v })
                  }
                />
                <ToggleRow
                  label="Allow OP_RETURN"
                  description="Accept transactions with OP_RETURN outputs"
                  enabled={editingMempoolProfile.datacarrier}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, datacarrier: v })
                  }
                />
                {editingMempoolProfile.datacarrier && (
                  <NumberInput
                    label="Max OP_RETURN Size"
                    value={editingMempoolProfile.datacarrier_size}
                    onChange={(v) =>
                      setEditingMempoolProfile({ ...editingMempoolProfile, datacarrier_size: v })
                    }
                    min={0}
                    max={10000}
                    unit="bytes"
                  />
                )}
                <ToggleRow
                  label="Accept Non-Standard Outputs"
                  description="Accept outputs that don't match standard templates"
                  enabled={editingMempoolProfile.accept_non_std_outputs}
                  onChange={(v) =>
                    setEditingMempoolProfile({
                      ...editingMempoolProfile,
                      accept_non_std_outputs: v,
                    })
                  }
                />
              </div>
            </div>

            {/* RBF Settings */}
            <div>
              <h4 className="text-sm font-medium text-gray-300 mb-3">Replace-By-Fee (RBF)</h4>
              <div className="space-y-2">
                <ToggleRow
                  label="Full RBF"
                  description="Allow replacement of any unconfirmed transaction"
                  enabled={editingMempoolProfile.mempool_full_rbf}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, mempool_full_rbf: v })
                  }
                />
                <NumberInput
                  label="Incremental Relay Fee"
                  value={editingMempoolProfile.incremental_relay_fee}
                  onChange={(v) =>
                    setEditingMempoolProfile({
                      ...editingMempoolProfile,
                      incremental_relay_fee: v,
                    })
                  }
                  min={0}
                  step={0.1}
                  unit="sat/vB"
                />
              </div>
            </div>

            {/* Ghost Extensions - Spam/Dust Protection */}
            <div>
              <h4 className="text-sm font-medium text-purple-300 mb-3">Spam & Dust Protection</h4>
              <div className="space-y-2">
                <NumberInput
                  label="Dust Limit"
                  value={editingMempoolProfile.dust_limit}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, dust_limit: v })
                  }
                  min={0}
                  unit="sats"
                />
                <NumberInput
                  label="Max Transaction Size"
                  value={editingMempoolProfile.max_tx_size}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, max_tx_size: v })
                  }
                  min={1000}
                  max={400000}
                  unit="vB"
                />
                <NumberInput
                  label="Max Witness Size"
                  value={editingMempoolProfile.max_witness_size}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, max_witness_size: v })
                  }
                  min={0}
                  max={4000000}
                  unit="bytes"
                />
              </div>
            </div>

            {/* Ghost Extensions - Output Preferences */}
            <div>
              <h4 className="text-sm font-medium text-purple-300 mb-3">Output Type Preferences</h4>
              <div className="space-y-2">
                <ToggleRow
                  label="Prefer Native SegWit"
                  description="Prioritize bc1q/bc1p (bech32/bech32m) outputs"
                  enabled={editingMempoolProfile.prefer_native_segwit}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, prefer_native_segwit: v })
                  }
                />
                <ToggleRow
                  label="Reject Legacy P2PKH"
                  description="Reject transactions with legacy 1xxx outputs"
                  enabled={editingMempoolProfile.reject_legacy_p2pkh}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, reject_legacy_p2pkh: v })
                  }
                />
              </div>
            </div>

            {/* Ghost Extensions - Inscription Filtering */}
            <div>
              <h4 className="text-sm font-medium text-purple-300 mb-3">Inscription Filtering</h4>
              <div className="space-y-2">
                <ToggleRow
                  label="Filter Ordinal Inscriptions"
                  description="Reject transactions containing Ordinal inscriptions"
                  enabled={editingMempoolProfile.filter_inscriptions}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, filter_inscriptions: v })
                  }
                />
                <ToggleRow
                  label="Filter BRC-20 Tokens"
                  description="Reject BRC-20 token transfer transactions"
                  enabled={editingMempoolProfile.filter_brc20}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, filter_brc20: v })
                  }
                />
                <ToggleRow
                  label="Filter Runes"
                  description="Reject Rune protocol transactions"
                  enabled={editingMempoolProfile.filter_runes}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, filter_runes: v })
                  }
                />
              </div>
            </div>

            {/* Ghost Extensions - Lightning & Privacy */}
            <div>
              <h4 className="text-sm font-medium text-purple-300 mb-3">Lightning & Privacy</h4>
              <div className="space-y-2">
                <ToggleRow
                  label="Prioritize Lightning Opens"
                  description="Boost priority for Lightning channel opening transactions"
                  enabled={editingMempoolProfile.prioritize_ln_opens}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, prioritize_ln_opens: v })
                  }
                />
                <ToggleRow
                  label="Prioritize Lightning Closes"
                  description="Boost priority for cooperative channel close transactions"
                  enabled={editingMempoolProfile.prioritize_ln_closes}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, prioritize_ln_closes: v })
                  }
                />
                <ToggleRow
                  label="Prefer CoinJoin"
                  description="Boost priority for CoinJoin transactions"
                  enabled={editingMempoolProfile.prefer_coinjoin}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, prefer_coinjoin: v })
                  }
                />
                {editingMempoolProfile.prefer_coinjoin && (
                  <NumberInput
                    label="Min CoinJoin Participants"
                    value={editingMempoolProfile.min_coinjoin_participants}
                    onChange={(v) =>
                      setEditingMempoolProfile({
                        ...editingMempoolProfile,
                        min_coinjoin_participants: v,
                      })
                    }
                    min={2}
                    max={100}
                    unit=""
                  />
                )}
              </div>
            </div>

            {/* Ghost Extensions - Chain Limits */}
            <div>
              <h4 className="text-sm font-medium text-purple-300 mb-3">Chain Limits (CPFP)</h4>
              <div className="space-y-2">
                <NumberInput
                  label="Max Ancestor Count"
                  value={editingMempoolProfile.max_ancestor_count}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, max_ancestor_count: v })
                  }
                  min={1}
                  max={100}
                  unit=""
                />
                <NumberInput
                  label="Max Descendant Count"
                  value={editingMempoolProfile.max_descendant_count}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, max_descendant_count: v })
                  }
                  min={1}
                  max={100}
                  unit=""
                />
                <NumberInput
                  label="Max Ancestor Size"
                  value={editingMempoolProfile.max_ancestor_size}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, max_ancestor_size: v })
                  }
                  min={1000}
                  max={500000}
                  unit="vB"
                />
              </div>
            </div>

            {/* BUDS Tiers */}
            <div>
              <div className="flex items-center gap-2 mb-3">
                <h4 className="text-sm font-medium text-gray-300">BUDS Transaction Tiers</h4>
                {!budsEnabled && (
                  <Badge variant="warning">Requires Ghost Pay</Badge>
                )}
              </div>
              {!budsEnabled && (
                <div className="p-3 bg-yellow-900/20 border border-yellow-800 rounded-lg mb-3">
                  <p className="text-yellow-400 text-sm">
                    Enable Ghost Pay to use BUDS transaction tiers. T1-T3 tiers provide enhanced
                    transaction capabilities.
                  </p>
                </div>
              )}
              <div className="space-y-2">
                <ToggleRow
                  label="T0 - Standard"
                  description="Standard Bitcoin transactions"
                  enabled={editingMempoolProfile.accept_t0}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, accept_t0: v })
                  }
                />
                <ToggleRow
                  label="T1 - Privacy-Enhanced"
                  description="CoinJoin, PayJoin, and privacy-focused transactions"
                  enabled={editingMempoolProfile.accept_t1}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, accept_t1: v })
                  }
                  disabled={!budsEnabled}
                  badge={!budsEnabled ? <Badge variant="default">Locked</Badge> : undefined}
                />
                <ToggleRow
                  label="T2 - Complex"
                  description="Smart contracts, DLCs, and complex scripts"
                  enabled={editingMempoolProfile.accept_t2}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, accept_t2: v })
                  }
                  disabled={!budsEnabled}
                  badge={!budsEnabled ? <Badge variant="default">Locked</Badge> : undefined}
                />
                <ToggleRow
                  label="T3 - Experimental"
                  description="New and experimental transaction types"
                  enabled={editingMempoolProfile.accept_t3}
                  onChange={(v) =>
                    setEditingMempoolProfile({ ...editingMempoolProfile, accept_t3: v })
                  }
                  disabled={!budsEnabled}
                  badge={!budsEnabled ? <Badge variant="default">Locked</Badge> : undefined}
                />
              </div>
            </div>

            {/* Actions */}
            <div className="flex gap-3 pt-4 border-t border-gray-800">
              <Button
                variant="ghost"
                className="flex-1"
                onClick={() => {
                  setMempoolDialogOpen(false);
                  setEditingMempoolProfile(null);
                }}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                className="flex-1"
                onClick={handleSaveMempoolProfile}
                loading={saveMempoolProfile.isPending}
                disabled={!editingMempoolProfile.name.trim()}
              >
                Save Profile
              </Button>
            </div>
          </div>
        )}
      </Dialog>

      {/* Template Profile Editor Dialog */}
      <Dialog
        isOpen={templateDialogOpen}
        onClose={() => {
          setTemplateDialogOpen(false);
          setEditingTemplateProfile(null);
        }}
        title={
          editingTemplateProfile?.name
            ? `Edit Profile: ${editingTemplateProfile.name}`
            : "New Template Profile"
        }
      >
        {editingTemplateProfile && (
          <div className="space-y-4 max-h-[70vh] overflow-y-auto">
            {/* Advanced User Warning */}
            <div className="p-4 bg-orange-900/20 border border-orange-700 rounded-lg">
              <div className="flex items-start gap-3">
                <span className="text-orange-400 text-xl">&#9888;</span>
                <div>
                  <h4 className="text-orange-300 font-medium">Advanced Configuration</h4>
                  <p className="text-orange-300/80 text-sm mt-1">
                    Custom block templates are intended for advanced users. Incorrect settings may
                    affect your mining efficiency or block validity.
                  </p>
                  <p className="text-orange-300/80 text-sm mt-2">
                    If you&apos;re unsure, use one of the preset profiles instead. For guidance, refer to
                    the <a href="/docs/template-profiles" className="text-orange-200 underline hover:text-orange-100">Block Template Guide</a>.
                  </p>
                </div>
              </div>
            </div>

            {/* Profile Name */}
            <div>
              <label className="block text-sm text-gray-400 mb-1">Profile Name</label>
              <Input
                value={editingTemplateProfile.name}
                onChange={(e) =>
                  setEditingTemplateProfile({ ...editingTemplateProfile, name: e.target.value })
                }
                placeholder="My Custom Template"
              />
            </div>

            {/* Core Template Settings */}
            <div>
              <h4 className="text-sm font-medium text-gray-300 mb-3">Core Template Settings</h4>
              <div className="space-y-2">
                <NumberInput
                  label="Block Max Weight"
                  value={editingTemplateProfile.block_max_weight}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, block_max_weight: v })
                  }
                  min={100000}
                  max={4000000}
                  step={100000}
                  unit="WU"
                />
                <NumberInput
                  label="Block Min TX Fee"
                  value={editingTemplateProfile.block_min_tx_fee}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, block_min_tx_fee: v })
                  }
                  min={0}
                  step={0.1}
                  unit="sat/vB"
                />
              </div>
            </div>

            {/* Priority Settings */}
            <div>
              <h4 className="text-sm font-medium text-gray-300 mb-3">Priority Settings</h4>
              <div className="space-y-2">
                <ToggleRow
                  label="Prioritise by Fee"
                  description="Order transactions by fee rate (highest first)"
                  enabled={editingTemplateProfile.prioritise_by_fee}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, prioritise_by_fee: v })
                  }
                />
                <ToggleRow
                  label="Prioritise by Age"
                  description="Factor in transaction age when ordering"
                  enabled={editingTemplateProfile.prioritise_by_age}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, prioritise_by_age: v })
                  }
                />
              </div>
            </div>

            {/* Ghost Extensions - Block Composition */}
            <div>
              <h4 className="text-sm font-medium text-purple-300 mb-3">Block Composition</h4>
              <div className="space-y-2">
                <NumberInput
                  label="Reserve Weight for Lightning"
                  value={editingTemplateProfile.reserve_weight_for_ln}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, reserve_weight_for_ln: v })
                  }
                  min={0}
                  max={1000000}
                  unit="WU"
                />
                <NumberInput
                  label="Max Sigops per Block"
                  value={editingTemplateProfile.max_sigops_per_block}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, max_sigops_per_block: v })
                  }
                  min={1000}
                  max={100000}
                  unit=""
                />
                <ToggleRow
                  label="Prefer Small Transactions"
                  description="Include more smaller txs vs fewer larger ones"
                  enabled={editingTemplateProfile.prefer_small_txs}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, prefer_small_txs: v })
                  }
                />
              </div>
            </div>

            {/* Ghost Extensions - Inscription Filtering */}
            <div>
              <h4 className="text-sm font-medium text-purple-300 mb-3">Inscription Filtering</h4>
              <div className="space-y-2">
                <ToggleRow
                  label="Filter Ordinal Inscriptions"
                  description="Exclude Ordinal inscriptions from blocks you mine"
                  enabled={editingTemplateProfile.filter_inscriptions}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, filter_inscriptions: v })
                  }
                />
                <ToggleRow
                  label="Filter BRC-20 Tokens"
                  description="Exclude BRC-20 transfers from blocks"
                  enabled={editingTemplateProfile.filter_brc20}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, filter_brc20: v })
                  }
                />
                <ToggleRow
                  label="Filter Runes"
                  description="Exclude Rune protocol transactions"
                  enabled={editingTemplateProfile.filter_runes}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, filter_runes: v })
                  }
                />
                <NumberInput
                  label="Max Witness Item Size"
                  value={editingTemplateProfile.max_witness_item}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, max_witness_item: v })
                  }
                  min={0}
                  max={4000000}
                  unit="bytes"
                />
              </div>
            </div>

            {/* Ghost Extensions - Transaction Preferences */}
            <div>
              <h4 className="text-sm font-medium text-purple-300 mb-3">Transaction Preferences</h4>
              <div className="space-y-2">
                <ToggleRow
                  label="Boost Consolidations"
                  description="Prioritize UTXO consolidation transactions"
                  enabled={editingTemplateProfile.boost_consolidations}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, boost_consolidations: v })
                  }
                />
                <ToggleRow
                  label="Boost Batched Payments"
                  description="Prioritize batched payment transactions"
                  enabled={editingTemplateProfile.boost_batched_payments}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, boost_batched_payments: v })
                  }
                />
              </div>
            </div>

            {/* Ghost Extensions - Package Relay */}
            <div>
              <h4 className="text-sm font-medium text-purple-300 mb-3">Package Relay (CPFP)</h4>
              <div className="space-y-2">
                <ToggleRow
                  label="Enable Package Relay"
                  description="Use package-aware transaction selection"
                  enabled={editingTemplateProfile.enable_package_relay}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, enable_package_relay: v })
                  }
                />
                {editingTemplateProfile.enable_package_relay && (
                  <NumberInput
                    label="Max Package Count"
                    value={editingTemplateProfile.max_package_count}
                    onChange={(v) =>
                      setEditingTemplateProfile({ ...editingTemplateProfile, max_package_count: v })
                    }
                    min={2}
                    max={100}
                    unit="txs"
                  />
                )}
              </div>
            </div>

            {/* Ghost Extensions - MEV Protection */}
            <div>
              <h4 className="text-sm font-medium text-purple-300 mb-3">MEV Protection</h4>
              <div className="space-y-2">
                <ToggleRow
                  label="Randomize Transaction Order"
                  description="Randomize tx order within same fee bands"
                  enabled={editingTemplateProfile.randomize_tx_order}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, randomize_tx_order: v })
                  }
                />
                {editingTemplateProfile.randomize_tx_order && (
                  <NumberInput
                    label="Fee Band Size"
                    value={editingTemplateProfile.fee_band_size}
                    onChange={(v) =>
                      setEditingTemplateProfile({ ...editingTemplateProfile, fee_band_size: v })
                    }
                    min={1}
                    max={10}
                    unit="sat/vB"
                  />
                )}
              </div>
            </div>

            {/* Ghost Extensions - Economic Preferences */}
            <div>
              <h4 className="text-sm font-medium text-purple-300 mb-3">Economic Preferences</h4>
              <div className="space-y-2">
                <ToggleRow
                  label="Include Free Relay"
                  description="Altruistically include some 0-fee transactions"
                  enabled={editingTemplateProfile.include_free_relay}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, include_free_relay: v })
                  }
                />
                {editingTemplateProfile.include_free_relay && (
                  <NumberInput
                    label="Free Relay Limit"
                    value={editingTemplateProfile.free_relay_limit}
                    onChange={(v) =>
                      setEditingTemplateProfile({ ...editingTemplateProfile, free_relay_limit: v })
                    }
                    min={0}
                    max={100000}
                    unit="WU"
                  />
                )}
              </div>
            </div>

            {/* BUDS Tiers */}
            <div>
              <div className="flex items-center gap-2 mb-3">
                <h4 className="text-sm font-medium text-gray-300">BUDS Transaction Tiers</h4>
                {!budsEnabled && <Badge variant="warning">Requires Ghost Pay</Badge>}
              </div>
              {!budsEnabled && (
                <div className="p-3 bg-yellow-900/20 border border-yellow-800 rounded-lg mb-3">
                  <p className="text-yellow-400 text-sm">
                    Enable Ghost Pay to use BUDS transaction tiers in block templates.
                  </p>
                </div>
              )}
              <div className="space-y-2">
                <ToggleRow
                  label="Include T0 - Standard"
                  description="Include standard Bitcoin transactions"
                  enabled={editingTemplateProfile.include_t0}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, include_t0: v })
                  }
                />
                <ToggleRow
                  label="Include T1 - Privacy-Enhanced"
                  description="Include privacy-focused transactions"
                  enabled={editingTemplateProfile.include_t1}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, include_t1: v })
                  }
                  disabled={!budsEnabled}
                  badge={!budsEnabled ? <Badge variant="default">Locked</Badge> : undefined}
                />
                <ToggleRow
                  label="Include T2 - Complex"
                  description="Include complex script transactions"
                  enabled={editingTemplateProfile.include_t2}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, include_t2: v })
                  }
                  disabled={!budsEnabled}
                  badge={!budsEnabled ? <Badge variant="default">Locked</Badge> : undefined}
                />
                <ToggleRow
                  label="Include T3 - Experimental"
                  description="Include experimental transaction types"
                  enabled={editingTemplateProfile.include_t3}
                  onChange={(v) =>
                    setEditingTemplateProfile({ ...editingTemplateProfile, include_t3: v })
                  }
                  disabled={!budsEnabled}
                  badge={!budsEnabled ? <Badge variant="default">Locked</Badge> : undefined}
                />
              </div>
            </div>

            {/* Actions */}
            <div className="flex gap-3 pt-4 border-t border-gray-800">
              <Button
                variant="ghost"
                className="flex-1"
                onClick={() => {
                  setTemplateDialogOpen(false);
                  setEditingTemplateProfile(null);
                }}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                className="flex-1"
                onClick={handleSaveTemplateProfile}
                loading={saveTemplateProfile.isPending}
                disabled={!editingTemplateProfile.name.trim()}
              >
                Save Profile
              </Button>
            </div>
          </div>
        )}
      </Dialog>
    </div>
  );
}
