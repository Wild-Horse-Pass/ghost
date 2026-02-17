"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import {
  useConfig,
  useNodeStatus,
  useTemplateProfiles,
  useSaveTemplateProfile,
  useDeleteTemplateProfile,
  useActivateTemplateProfile,
  useGhostPayStatus,
  type CustomTemplateProfile,
} from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { SettingsSection } from "./shared";
import { TemplateProfileDialog, DEFAULT_TEMPLATE_PROFILE } from "./TemplateProfileDialog";

export function TemplateProfileSection() {
  const { data: config } = useConfig();
  const { data: status } = useNodeStatus();
  const { data: templateProfilesData } = useTemplateProfiles();
  useGhostPayStatus(); // pre-fetch for dialog

  const saveTemplateProfile = useSaveTemplateProfile();
  const deleteTemplateProfile = useDeleteTemplateProfile();
  const activateTemplateProfile = useActivateTemplateProfile();

  const { success, error } = useToast();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingProfile, setEditingProfile] = useState<CustomTemplateProfile | null>(null);

  const templateProfiles = templateProfilesData?.profiles ?? [];
  const budsEnabled = status?.ghost_pay ?? false;

  const handleNew = () => {
    setEditingProfile({ name: "", ...DEFAULT_TEMPLATE_PROFILE });
    setDialogOpen(true);
  };

  const handleEdit = (profile: CustomTemplateProfile) => {
    setEditingProfile({ ...profile });
    setDialogOpen(true);
  };

  const handleSave = async () => {
    if (!editingProfile || !editingProfile.name.trim()) {
      error("Invalid Name", "Profile name is required");
      return;
    }

    try {
      await saveTemplateProfile.mutateAsync(editingProfile);
      success("Profile Saved", `Template profile "${editingProfile.name}" saved`);
      setDialogOpen(false);
      setEditingProfile(null);
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleDelete = async (name: string) => {
    try {
      await deleteTemplateProfile.mutateAsync(name);
      success("Profile Deleted", `Template profile "${name}" deleted`);
    } catch (err) {
      error("Delete Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleActivate = async (name: string) => {
    try {
      await activateTemplateProfile.mutateAsync(name);
      success("Profile Activated", `Template profile "${name}" is now active`);
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
                  ? "bg-orange-900/30 border-orange-600 text-orange-300"
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
          Create Custom Template Profile
        </Button>
      </SettingsSection>

      <TemplateProfileDialog
        isOpen={dialogOpen}
        onClose={handleDialogClose}
        profile={editingProfile}
        onProfileChange={setEditingProfile}
        onSave={handleSave}
        saving={saveTemplateProfile.isPending}
        budsEnabled={budsEnabled}
      />
    </>
  );
}
