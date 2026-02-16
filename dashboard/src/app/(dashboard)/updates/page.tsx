"use client";

import { useState, useEffect } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Dialog } from "@/components/ui/Dialog";
import { SkeletonCard } from "@/components/ui/Skeleton";
import {
  useSystemVersion,
  useCheckForUpdates,
  useUpdateStatus,
  useStartUpdate,
  useRollbackUpdate,
} from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import type { UpdateStatus } from "@/lib/api/system";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function formatDate(dateStr: string): string {
  try {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  } catch {
    return dateStr;
  }
}

function getStatusBadge(status: UpdateStatus["status"]): {
  variant: "success" | "warning" | "error" | "info" | "default";
  label: string;
} {
  switch (status) {
    case "idle":
      return { variant: "default", label: "Ready" };
    case "checking":
      return { variant: "info", label: "Checking..." };
    case "downloading":
      return { variant: "info", label: "Downloading" };
    case "verifying":
      return { variant: "info", label: "Verifying" };
    case "installing":
      return { variant: "warning", label: "Installing" };
    case "complete":
      return { variant: "success", label: "Complete" };
    case "failed":
      return { variant: "error", label: "Failed" };
    default:
      return { variant: "default", label: status };
  }
}

function ProgressBar({ percent }: { percent: number }) {
  return (
    <div className="w-full bg-gray-700 rounded-full h-2.5">
      <div
        className="bg-purple-600 h-2.5 rounded-full transition-all duration-300"
        style={{ width: `${Math.min(100, Math.max(0, percent))}%` }}
      />
    </div>
  );
}

export default function UpdatesPage() {
  const { data: version, isLoading: versionLoading } = useSystemVersion();
  const {
    data: updateCheck,
    isLoading: updateCheckLoading,
    refetch: recheckUpdates,
    isFetching: isChecking,
  } = useCheckForUpdates({ enabled: true });

  const [isUpdating, setIsUpdating] = useState(false);
  const { data: statusData } = useUpdateStatus({
    refetchInterval: isUpdating ? 1000 : false,
    enabled: isUpdating,
  });

  const startUpdate = useStartUpdate();
  const rollback = useRollbackUpdate();
  const { success, error } = useToast();

  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [rollbackDialogOpen, setRollbackDialogOpen] = useState(false);

  const updateStatus = statusData?.update_status;
  const updateInfo = updateCheck?.update_info;
  const hasUpdate = updateCheck?.update_available ?? false;

  // Monitor update status changes - sync completion state from server
  useEffect(() => {
    if (!updateStatus) return;

    if (updateStatus.status === "complete") {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setIsUpdating(false);
      success("Update Complete", "message" in updateStatus ? updateStatus.message : "Node updated successfully. Please restart the node.");
    } else if (updateStatus.status === "failed") {
      setIsUpdating(false);
      error("Update Failed", "error" in updateStatus ? updateStatus.error : "Unknown error occurred");
    }
  }, [updateStatus, success, error]);

  const handleCheckForUpdates = async () => {
    try {
      await recheckUpdates();
      if (!updateCheck?.update_available) {
        success("Up to Date", "You are running the latest version");
      }
    } catch (err) {
      error("Check Failed", err instanceof Error ? err.message : "Failed to check for updates");
    }
  };

  const handleStartUpdate = async () => {
    setConfirmDialogOpen(false);
    setIsUpdating(true);
    try {
      const result = await startUpdate.mutateAsync();
      if (!result.success) {
        setIsUpdating(false);
        error("Update Failed", result.message);
      }
    } catch (err) {
      setIsUpdating(false);
      error("Update Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleRollback = async () => {
    setRollbackDialogOpen(false);
    try {
      const result = await rollback.mutateAsync();
      if (result.success) {
        success("Rollback Started", result.message);
      } else {
        error("Rollback Failed", result.message);
      }
    } catch (err) {
      error("Rollback Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const isLoading = versionLoading || updateCheckLoading;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-100">Software Updates</h1>

      {isLoading ? (
        <>
          <SkeletonCard />
          <SkeletonCard />
        </>
      ) : (
        <>
          {/* Current Version */}
          <Card>
            <CardHeader
              title="Current Version"
              subtitle="Information about your installed Ghost Node software"
            />
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 bg-gray-800/50 rounded-lg">
                  <div className="text-sm text-gray-400 mb-1">Version</div>
                  <div className="text-xl font-bold text-purple-400">
                    {version?.node_version ?? "Unknown"}
                  </div>
                </div>
                <div className="p-4 bg-gray-800/50 rounded-lg">
                  <div className="text-sm text-gray-400 mb-1">Build Date</div>
                  <div className="text-gray-100">
                    {version?.build_time ? formatDate(version.build_time) : "Unknown"}
                  </div>
                </div>
                <div className="p-4 bg-gray-800/50 rounded-lg">
                  <div className="text-sm text-gray-400 mb-1">Git Commit</div>
                  <code className="text-gray-300 text-sm">
                    {version?.git_hash?.substring(0, 8) ?? "Unknown"}
                  </code>
                </div>
              </div>
            </div>
          </Card>

          {/* Update Status */}
          {isUpdating && updateStatus && (
            <Card>
              <CardHeader title="Update Progress" />
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">Status</span>
                  <Badge variant={getStatusBadge(updateStatus.status).variant}>
                    {getStatusBadge(updateStatus.status).label}
                  </Badge>
                </div>

                {"progress" in updateStatus && updateStatus.progress && (
                  <>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-400">{updateStatus.progress.step}</span>
                        <span className="text-gray-400">{updateStatus.progress.progress_percent}%</span>
                      </div>
                      <ProgressBar percent={updateStatus.progress.progress_percent ?? 0} />
                    </div>
                    <p className="text-sm text-gray-500">{updateStatus.progress.message}</p>
                  </>
                )}

                {updateStatus.status === "verifying" && (
                  <div className="flex items-center gap-2">
                    <div className="animate-spin w-4 h-4 border-2 border-purple-500 border-t-transparent rounded-full" />
                    <span className="text-gray-400">Verifying SHA256 checksum...</span>
                  </div>
                )}
              </div>
            </Card>
          )}

          {/* Available Update */}
          <Card>
            <CardHeader
              title="Available Updates"
              subtitle="Check for and install software updates from GitHub releases"
            />
            <div className="space-y-4">
              {hasUpdate && updateInfo ? (
                <>
                  <div className="p-4 bg-purple-900/20 border border-purple-700 rounded-lg">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                          <h3 className="text-lg font-bold text-purple-300">
                            Version {updateInfo.version}
                          </h3>
                          <Badge variant="success">New</Badge>
                        </div>
                        <p className="text-sm text-gray-400">
                          Released {formatDate(updateInfo.release_date ?? "")} &middot;{" "}
                          {formatBytes(updateInfo.size_bytes ?? 0)}
                        </p>
                      </div>
                      <Button
                        onClick={() => setConfirmDialogOpen(true)}
                        disabled={isUpdating || startUpdate.isPending}
                        loading={startUpdate.isPending}
                      >
                        Install Update
                      </Button>
                    </div>
                  </div>

                  {/* Changelog */}
                  {updateInfo.changelog && (
                    <div className="p-4 bg-gray-800/50 rounded-lg">
                      <h4 className="text-sm font-medium text-gray-300 mb-3">Release Notes</h4>
                      <div className="prose prose-sm prose-invert max-w-none">
                        <pre className="text-sm text-gray-400 whitespace-pre-wrap font-sans">
                          {updateInfo.changelog}
                        </pre>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="text-center py-8">
                  <div className="text-4xl mb-3">&#10003;</div>
                  <h3 className="text-lg font-medium text-gray-100 mb-1">
                    You&apos;re up to date!
                  </h3>
                  <p className="text-gray-400 mb-4">
                    Running version {updateCheck?.current_version ?? version?.node_version}
                  </p>
                </div>
              )}

              <Button
                onClick={handleCheckForUpdates}
                variant="secondary"
                className="w-full"
                loading={isChecking}
                disabled={isUpdating}
              >
                Check for Updates
              </Button>
            </div>
          </Card>

          {/* Rollback Section */}
          <Card>
            <CardHeader
              title="Rollback"
              subtitle="Revert to the previous version if an update causes issues"
            />
            <div className="space-y-4">
              <div className="p-4 bg-yellow-900/20 border border-yellow-800 rounded-lg">
                <p className="text-yellow-400 text-sm">
                  Rollback restores the previous version of Ghost Node from backup. Use this if
                  an update causes problems. The node will restart after rollback.
                </p>
              </div>
              <Button
                onClick={() => setRollbackDialogOpen(true)}
                variant="warning"
                disabled={isUpdating || rollback.isPending}
                loading={rollback.isPending}
              >
                Rollback to Previous Version
              </Button>
            </div>
          </Card>

          {/* Info Card */}
          <Card>
            <div className="p-4 bg-blue-900/20 border border-blue-800 rounded-lg">
              <h4 className="text-blue-300 font-medium mb-2">About Updates</h4>
              <ul className="text-sm text-blue-300/80 space-y-1 list-disc list-inside">
                <li>Updates are downloaded from official GitHub releases</li>
                <li>SHA256 checksums are verified before installation</li>
                <li>Current binaries are backed up before updating</li>
                <li>The node will restart automatically after update</li>
                <li>You can rollback to the previous version if needed</li>
              </ul>
            </div>
          </Card>
        </>
      )}

      {/* Install Update Confirmation Dialog */}
      <Dialog
        isOpen={confirmDialogOpen}
        onClose={() => setConfirmDialogOpen(false)}
        title="Install Update"
      >
        <div className="space-y-4">
          <p className="text-gray-300">
            Are you sure you want to update to version{" "}
            <strong className="text-white">{updateInfo?.version}</strong>?
          </p>
          <div className="p-3 bg-purple-900/20 border border-purple-800 rounded">
            <p className="text-sm text-purple-400">
              The node will be stopped during the update and automatically restarted once complete.
              Your current version will be backed up in case you need to rollback.
            </p>
          </div>
          <div className="flex gap-3 pt-4 border-t border-gray-800">
            <Button
              variant="ghost"
              className="flex-1"
              onClick={() => setConfirmDialogOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              className="flex-1"
              onClick={handleStartUpdate}
              loading={startUpdate.isPending}
            >
              Install Update
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Rollback Confirmation Dialog */}
      <Dialog
        isOpen={rollbackDialogOpen}
        onClose={() => setRollbackDialogOpen(false)}
        title="Rollback to Previous Version"
      >
        <div className="space-y-4">
          <p className="text-gray-300">
            Are you sure you want to rollback to the previous version?
          </p>
          <div className="p-3 bg-yellow-900/20 border border-yellow-800 rounded">
            <p className="text-sm text-yellow-400">
              This will restore the backup of your previous Ghost Node version.
              The node will restart after the rollback completes.
            </p>
          </div>
          <div className="flex gap-3 pt-4 border-t border-gray-800">
            <Button
              variant="ghost"
              className="flex-1"
              onClick={() => setRollbackDialogOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant="warning"
              className="flex-1"
              onClick={handleRollback}
              loading={rollback.isPending}
            >
              Rollback
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
