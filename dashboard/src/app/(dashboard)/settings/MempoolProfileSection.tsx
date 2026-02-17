"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import {
  useConfig,
  useNodeStatus,
  useMempoolProfiles,
  useSaveMempoolProfile,
  useDeleteMempoolProfile,
  useActivateMempoolProfile,
  useGhostPayStatus,
  type CustomMempoolProfile,
} from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { SettingsSection } from "./shared";
import { MempoolProfileDialog, DEFAULT_MEMPOOL_PROFILE } from "./MempoolProfileDialog";

export function MempoolProfileSection() {
  const { data: config } = useConfig();
  const { data: status } = useNodeStatus();
  const { data: mempoolProfilesData } = useMempoolProfiles();
  useGhostPayStatus(); // pre-fetch for dialog

  const saveMempoolProfile = useSaveMempoolProfile();
  const deleteMempoolProfile = useDeleteMempoolProfile();
  const activateMempoolProfile = useActivateMempoolProfile();

  const { success, error } = useToast();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingProfile, setEditingProfile] = useState<CustomMempoolProfile | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const mempoolProfiles = mempoolProfilesData?.profiles ?? [];
  const budsEnabled = status?.ghost_pay ?? false;

  const handleNew = () => {
    setEditingProfile({ name: "", ...DEFAULT_MEMPOOL_PROFILE });
    setDialogOpen(true);
  };

  const handleEdit = (profile: CustomMempoolProfile) => {
    setEditingProfile({ ...profile });
    setDialogOpen(true);
  };

  const handleSave = async () => {
    if (!editingProfile || !editingProfile.name.trim()) {
      error("Invalid Name", "Profile name is required");
      return;
    }

    try {
      await saveMempoolProfile.mutateAsync(editingProfile);
      success("Profile Saved", `Mempool profile "${editingProfile.name}" saved`);
      setDialogOpen(false);
      setEditingProfile(null);
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleDelete = async (name: string) => {
    try {
      await deleteMempoolProfile.mutateAsync(name);
      success("Profile Deleted", `Mempool profile "${name}" deleted`);
    } catch (err) {
      error("Delete Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleActivate = async (name: string) => {
    try {
      await activateMempoolProfile.mutateAsync(name);
      success("Profile Activated", `Mempool profile "${name}" is now active`);
    } catch (err) {
      error("Activation Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleDialogClose = () => {
    setDialogOpen(false);
    setEditingProfile(null);
  };

  return (
    <>
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
                  ? "bg-orange-900/30 border-orange-600 text-orange-300"
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

        {/* Show Advanced toggle */}
        <button
          className="flex items-center gap-2 text-sm text-gray-400 hover:text-gray-200 transition-colors"
          onClick={() => setShowAdvanced(!showAdvanced)}
        >
          <svg
            className={`w-4 h-4 transition-transform ${showAdvanced ? "rotate-90" : ""}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
          {showAdvanced ? "Hide Advanced" : "Show Advanced"}
          {mempoolProfiles.length > 0 && !showAdvanced && (
            <span className="text-xs text-gray-600">({mempoolProfiles.length} custom)</span>
          )}
        </button>

        {showAdvanced && (
          <>
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
                        onClick={() => handleEdit(profile)}
                        disabled={config?.bitcoin_pure}
                      >
                        Edit
                      </Button>
                      <Button
                        size="sm"
                        variant="primary"
                        onClick={() => handleActivate(profile.name)}
                        disabled={config?.bitcoin_pure}
                      >
                        Use
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleDelete(profile.name)}
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
              onClick={handleNew}
              variant="secondary"
              className="w-full"
              disabled={config?.bitcoin_pure}
            >
              Create Custom Mempool Profile
            </Button>
          </>
        )}
      </SettingsSection>

      <MempoolProfileDialog
        isOpen={dialogOpen}
        onClose={handleDialogClose}
        profile={editingProfile}
        onProfileChange={setEditingProfile}
        onSave={handleSave}
        saving={saveMempoolProfile.isPending}
        budsEnabled={budsEnabled}
      />
    </>
  );
}
