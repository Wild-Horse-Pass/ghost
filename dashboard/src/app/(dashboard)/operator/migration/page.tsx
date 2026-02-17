"use client";

import { useState, useRef } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Dialog } from "@/components/ui/Dialog";
import { Toggle } from "@/components/ui/Toggle";
import { SkeletonTable } from "@/components/ui/Skeleton";
import { useBackupHistory, useCreateBackup, useImportBackup, useVerifyBackup, useDeleteBackup } from "@/hooks/queries";
import { getBackupDownloadUrl } from "@/lib/api/backup";
import { useToast } from "@/components/ui/Toast";
import type { VerifyBackupResponse } from "@/types/api";

function formatDate(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString();
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export default function MigrationPage() {
  const { data: historyData, isLoading } = useBackupHistory();
  const createBackup = useCreateBackup();
  const importBackup = useImportBackup();
  const verifyBackup = useVerifyBackup();
  const deleteBackupMutation = useDeleteBackup();
  const { success, error, warning } = useToast();

  // Export state
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [exportPassword, setExportPassword] = useState("");
  const [exportConfirmPassword, setExportConfirmPassword] = useState("");
  const [exportOptions, setExportOptions] = useState({
    include_identity: true,
    include_wallet_keys: true,
    include_config: true,
    include_ghost_pay_db: true,
    include_block_history: true,
    include_logs: false,
  });

  // Import state
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [importPassword, setImportPassword] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyBackupResponse | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const history = historyData?.backups ?? [];

  const handleDownload = (filename: string) => {
    const url = getBackupDownloadUrl(filename);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleDelete = async (filename: string) => {
    if (!confirm(`Are you sure you want to delete ${filename}?`)) return;

    try {
      const result = await deleteBackupMutation.mutateAsync(filename);
      if (result.success) {
        success("Backup Deleted", `${filename} has been deleted`);
      } else {
        error("Delete Failed", result.error || "Delete failed");
      }
    } catch (err) {
      console.error("Delete error:", err);
      error("Delete Failed", err instanceof Error ? err.message : String(err));
    }
  };

  const handleExport = async () => {
    if (exportPassword !== exportConfirmPassword) {
      error("Password Mismatch", "Passwords do not match");
      return;
    }
    if (exportPassword.length < 8) {
      error("Weak Password", "Password must be at least 8 characters");
      return;
    }

    try {
      const result = await createBackup.mutateAsync({
        options: exportOptions,
        password: exportPassword,
      });

      // Download the backup file using full API URL
      const link = document.createElement("a");
      link.href = getBackupDownloadUrl(result.filename);
      link.download = result.filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      success("Backup Created", `Backup saved as ${result.filename}`);
      setExportDialogOpen(false);
      setExportPassword("");
      setExportConfirmPassword("");
    } catch (err) {
      error("Export Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setSelectedFile(file);
    setVerifyResult(null);
  };

  const handleVerify = async () => {
    if (!selectedFile || !importPassword) return;

    try {
      const result = await verifyBackup.mutateAsync({
        file: selectedFile,
        password: importPassword,
      });
      setVerifyResult(result);

      if (result.valid) {
        success("Backup Verified", "Backup file is valid and can be imported");
      } else {
        warning("Verification Failed", result.error ?? "Backup file is invalid or password is incorrect");
      }
    } catch (err) {
      error("Verification Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleImport = async () => {
    if (!selectedFile || !importPassword || !verifyResult?.valid) return;

    try {
      await importBackup.mutateAsync({
        file: selectedFile,
        password: importPassword,
      });

      success("Import Complete", "Backup restored successfully. The node will restart.");
      setImportDialogOpen(false);
      setSelectedFile(null);
      setImportPassword("");
      setVerifyResult(null);
    } catch (err) {
      error("Import Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-100">Migration</h1>

      {/* Export/Import Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader
            title="Export Backup"
            subtitle="Create an encrypted backup of your node data"
          />
          <p className="text-gray-400 text-sm mb-4">
            Export your node configuration, locks, wallet data, and history to a secure encrypted
            backup file.
          </p>
          <Button variant="primary" onClick={() => setExportDialogOpen(true)}>
            Create Backup
          </Button>
        </Card>

        <Card>
          <CardHeader
            title="Import Backup"
            subtitle="Restore from an encrypted backup file"
          />
          <p className="text-gray-400 text-sm mb-4">
            Restore your node from a previous backup. This will replace current data with the
            backup contents.
          </p>
          <Button variant="secondary" onClick={() => setImportDialogOpen(true)}>
            Restore Backup
          </Button>
        </Card>
      </div>

      {/* Backup History */}
      <Card>
        <CardHeader title="Backup History" subtitle={`${history.length} backups created`} />
        {isLoading ? (
          <SkeletonTable rows={5} cols={4} />
        ) : history.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-gray-400">No backups created yet</p>
            <p className="text-sm text-gray-500 mt-1">
              Create your first backup to protect your node data
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {history.map((backup, idx) => (
              <div
                key={`${backup.filename}-${idx}`}
                className="p-4 bg-gray-800/50 rounded-lg border border-gray-700"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-gray-100 font-medium">{backup.filename}</span>
                      <Badge variant="info">{formatSize(backup.size_bytes ?? 0)}</Badge>
                    </div>
                    <div className="text-sm text-gray-400 mt-1">
                      Created: {formatDate(backup.created_at ?? 0)}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={backup.type === "full" ? "success" : "info"}>
                      {backup.type === "full" ? "Full" : "Partial"}
                    </Badge>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDownload(backup.filename)}
                    >
                      Download
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDelete(backup.filename)}
                      disabled={deleteBackupMutation.isPending}
                    >
                      Delete
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Info Card */}
      <Card>
        <div className="p-4 bg-orange-900/20 border border-orange-800 rounded-lg">
          <h4 className="text-orange-300 font-medium mb-2">Backup Best Practices</h4>
          <ul className="text-sm text-orange-300/80 space-y-1 list-disc list-inside">
            <li>Create regular backups before making configuration changes</li>
            <li>Store backup files in a secure location separate from your node</li>
            <li>Use a strong, unique password and store it safely</li>
            <li>Test your backups periodically by verifying them</li>
            <li>Keep multiple backup copies in different locations</li>
          </ul>
        </div>
      </Card>

      {/* Export Dialog */}
      <Dialog
        isOpen={exportDialogOpen}
        onClose={() => setExportDialogOpen(false)}
        title="Create Backup"
      >
        <div className="space-y-4">
          <div>
            <h4 className="text-sm font-medium text-gray-300 mb-3">Include in Backup</h4>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-gray-100">Node Identity</div>
                  <div className="text-xs text-gray-400">Node ID and keys</div>
                </div>
                <Toggle
                  enabled={exportOptions.include_identity}
                  onChange={(v) => setExportOptions({ ...exportOptions, include_identity: v })}
                  label="Include identity"
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-gray-100">Wallet Keys</div>
                  <div className="text-xs text-gray-400">Private keys and wallet data</div>
                </div>
                <Toggle
                  enabled={exportOptions.include_wallet_keys}
                  onChange={(v) => setExportOptions({ ...exportOptions, include_wallet_keys: v })}
                  label="Include wallet"
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-gray-100">Configuration</div>
                  <div className="text-xs text-gray-400">Node settings and preferences</div>
                </div>
                <Toggle
                  enabled={exportOptions.include_config}
                  onChange={(v) => setExportOptions({ ...exportOptions, include_config: v })}
                  label="Include config"
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-gray-100">Ghost Pay Database</div>
                  <div className="text-xs text-gray-400">L2 locks and payment data</div>
                </div>
                <Toggle
                  enabled={exportOptions.include_ghost_pay_db}
                  onChange={(v) => setExportOptions({ ...exportOptions, include_ghost_pay_db: v })}
                  label="Include ghost pay"
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-gray-100">Block History</div>
                  <div className="text-xs text-gray-400">Historical block data</div>
                </div>
                <Toggle
                  enabled={exportOptions.include_block_history}
                  onChange={(v) => setExportOptions({ ...exportOptions, include_block_history: v })}
                  label="Include history"
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-gray-100">Logs</div>
                  <div className="text-xs text-gray-400">Node log files</div>
                </div>
                <Toggle
                  enabled={exportOptions.include_logs}
                  onChange={(v) => setExportOptions({ ...exportOptions, include_logs: v })}
                  label="Include logs"
                />
              </div>
            </div>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Encryption Password</label>
            <Input
              type="password"
              value={exportPassword}
              onChange={(e) => setExportPassword(e.target.value)}
              placeholder="Enter a strong password"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Confirm Password</label>
            <Input
              type="password"
              value={exportConfirmPassword}
              onChange={(e) => setExportConfirmPassword(e.target.value)}
              placeholder="Confirm password"
            />
          </div>

          <div className="p-3 bg-yellow-900/20 border border-yellow-800 rounded">
            <p className="text-yellow-400 text-sm">
              Store your password securely. You will need it to restore from this backup.
            </p>
          </div>

          <div className="flex gap-3 pt-4 border-t border-gray-800">
            <Button variant="ghost" className="flex-1" onClick={() => setExportDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              className="flex-1"
              onClick={handleExport}
              loading={createBackup.isPending}
              disabled={
                !exportPassword ||
                exportPassword !== exportConfirmPassword ||
                exportPassword.length < 8
              }
            >
              Create Backup
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Import Dialog */}
      <Dialog
        isOpen={importDialogOpen}
        onClose={() => {
          setImportDialogOpen(false);
          setSelectedFile(null);
          setImportPassword("");
          setVerifyResult(null);
        }}
        title="Restore Backup"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Backup File</label>
            <input
              ref={fileInputRef}
              type="file"
              accept=".ghost,.backup"
              onChange={handleFileSelect}
              className="hidden"
            />
            <div className="flex gap-2">
              <Button
                variant="secondary"
                onClick={() => fileInputRef.current?.click()}
                className="flex-1"
              >
                {selectedFile ? selectedFile.name : "Select File"}
              </Button>
              {selectedFile && (
                <Button variant="ghost" onClick={() => setSelectedFile(null)}>
                  Clear
                </Button>
              )}
            </div>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Backup Password</label>
            <Input
              type="password"
              value={importPassword}
              onChange={(e) => setImportPassword(e.target.value)}
              placeholder="Enter backup password"
            />
          </div>

          {!verifyResult && selectedFile && importPassword && (
            <Button
              variant="secondary"
              onClick={handleVerify}
              loading={verifyBackup.isPending}
              className="w-full"
            >
              Verify Backup
            </Button>
          )}

          {verifyResult && (
            <div
              className={`p-4 rounded-lg border ${
                verifyResult.valid
                  ? "bg-green-900/20 border-green-800"
                  : "bg-red-900/20 border-red-800"
              }`}
            >
              <div className="flex items-center gap-2 mb-2">
                <Badge variant={verifyResult.valid ? "success" : "error"}>
                  {verifyResult.valid ? "Valid" : "Invalid"}
                </Badge>
                <span className={verifyResult.valid ? "text-green-400" : "text-red-400"}>
                  {verifyResult.valid ? "Backup verified" : verifyResult.error}
                </span>
              </div>
              {verifyResult.valid && verifyResult.info && (
                <div className="text-sm text-gray-400 space-y-1">
                  <p>Created: {formatDate(verifyResult.info.created_at ?? 0)}</p>
                  <p>Node ID: {(verifyResult.info.node_id ?? "").slice(0, 12)}...</p>
                  <p>Locks: {verifyResult.info.locks_count ?? 0}</p>
                  <div className="flex gap-2 mt-2">
                    {verifyResult.info.config_included && <Badge variant="info">Config</Badge>}
                    {(verifyResult.info.locks_count ?? 0) > 0 && <Badge variant="info">Locks</Badge>}
                    {verifyResult.info.ghost_pay_blocks && <Badge variant="info">Ghost Pay</Badge>}
                  </div>
                </div>
              )}
            </div>
          )}

          {verifyResult?.valid && (
            <div className="p-3 bg-yellow-900/20 border border-yellow-800 rounded">
              <p className="text-yellow-400 text-sm">
                Warning: Importing a backup will replace your current node data. This action cannot
                be undone.
              </p>
            </div>
          )}

          <div className="flex gap-3 pt-4 border-t border-gray-800">
            <Button
              variant="ghost"
              className="flex-1"
              onClick={() => {
                setImportDialogOpen(false);
                setSelectedFile(null);
                setImportPassword("");
                setVerifyResult(null);
              }}
            >
              Cancel
            </Button>
            <Button
              variant="danger"
              className="flex-1"
              onClick={handleImport}
              loading={importBackup.isPending}
              disabled={!verifyResult?.valid}
            >
              Restore Backup
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
