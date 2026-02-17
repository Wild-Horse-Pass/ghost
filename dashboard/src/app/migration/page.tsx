"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { createBackup, verifyBackup, importBackup, getBackupHistory } from "@/lib/api";
import type { BackupOptions, BackupInfo, BackupHistoryEntry } from "@/types/api";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString();
}

function truncateId(id: string): string {
  if (id.length <= 16) return id;
  return `${id.slice(0, 8)}...${id.slice(-8)}`;
}

function getPasswordStrength(password: string): { label: string; percent: number; color: string } {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/[0-9]/.test(password)) score += 1;
  if (/[^a-zA-Z0-9]/.test(password)) score += 1;

  if (score <= 2) return { label: "Weak", percent: 25, color: "bg-red-500" };
  if (score <= 4) return { label: "Moderate", percent: 50, color: "bg-yellow-500" };
  if (score <= 5) return { label: "Strong", percent: 75, color: "bg-green-500" };
  return { label: "Very Strong", percent: 100, color: "bg-green-400" };
}

export default function MigrationPage() {
  // Export state
  const [exportOptions, setExportOptions] = useState<BackupOptions>({
    include_identity: true,
    include_wallet_keys: true,
    include_config: true,
    include_ghost_pay_db: true,
    include_block_history: false,
    include_logs: false,
  });
  const [exportPassword, setExportPassword] = useState("");
  const [exportConfirmPassword, setExportConfirmPassword] = useState("");
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportSuccess, setExportSuccess] = useState<string | null>(null);

  // Import state
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importPassword, setImportPassword] = useState("");
  const [verifiedInfo, setVerifiedInfo] = useState<BackupInfo | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importConfirmed, setImportConfirmed] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importSuccess, setImportSuccess] = useState<string | null>(null);

  // History
  const [history, setHistory] = useState<BackupHistoryEntry[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(true);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchHistory = useCallback(async () => {
    try {
      const data = await getBackupHistory();
      setHistory(data.backups);
    } catch (err) {
      console.error("Failed to fetch backup history:", err);
    } finally {
      setLoadingHistory(false);
    }
  }, []);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const handleExport = async () => {
    if (exportPassword !== exportConfirmPassword) {
      setExportError("Passwords do not match");
      return;
    }
    if (exportPassword.length < 8) {
      setExportError("Password must be at least 8 characters");
      return;
    }

    setExporting(true);
    setExportError(null);
    setExportSuccess(null);

    try {
      const result = await createBackup(exportOptions, exportPassword);
      setExportSuccess(`Backup created: ${result.filename} (${formatBytes(result.size_bytes ?? 0)})`);
      setExportPassword("");
      setExportConfirmPassword("");
      fetchHistory();

      // Trigger download
      if (result.download_url) window.location.href = result.download_url;
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Failed to create backup");
    } finally {
      setExporting(false);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setImportFile(file);
      setVerifiedInfo(null);
      setImportConfirmed(false);
      setImportError(null);
      setImportSuccess(null);
    }
  };

  const handleVerify = async () => {
    if (!importFile || !importPassword) return;

    setVerifying(true);
    setImportError(null);

    try {
      const result = await verifyBackup(importFile, importPassword);
      if (result.valid && result.info) {
        setVerifiedInfo(result.info);
      } else {
        setImportError(result.error || "Invalid backup file");
      }
    } catch (err) {
      setImportError(err instanceof Error ? err.message : "Failed to verify backup");
    } finally {
      setVerifying(false);
    }
  };

  const handleImport = async () => {
    if (!importFile || !importPassword || !importConfirmed) return;

    setImporting(true);
    setImportError(null);

    try {
      await importBackup(importFile, importPassword);
      setImportSuccess("Backup restored successfully. Please restart the node.");
      setImportFile(null);
      setImportPassword("");
      setVerifiedInfo(null);
      setImportConfirmed(false);
    } catch (err) {
      setImportError(err instanceof Error ? err.message : "Failed to import backup");
    } finally {
      setImporting(false);
    }
  };

  const estimatedSize = (() => {
    let size = 0;
    if (exportOptions.include_identity) size += 1;
    if (exportOptions.include_wallet_keys) size += 2;
    if (exportOptions.include_config) size += 0.1;
    if (exportOptions.include_ghost_pay_db) size += 20;
    if (exportOptions.include_block_history) size += 100;
    if (exportOptions.include_logs) size += 50;
    return size;
  })();

  const passwordStrength = getPasswordStrength(exportPassword);

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-2xl font-bold text-gray-100 mb-6">Migration & Backup</h1>

        {/* Safety Warning */}
        <Card className="mb-6">
          <div className="p-4 bg-yellow-900/20 border border-yellow-800 rounded-lg">
            <h3 className="text-yellow-400 font-semibold mb-2">Important Safety Information</h3>
            <ul className="text-yellow-300/80 text-sm space-y-1">
              <li>Your Node ID is your identity in Ghost Pool</li>
              <li>Elder status is tied to your Node ID</li>
              <li>NEVER run the same Node ID on two machines simultaneously</li>
              <li>Backup files contain sensitive keys - store securely</li>
            </ul>
          </div>
        </Card>

        {/* Export */}
        <Card className="mb-6">
          <CardHeader title="Export Node Backup" />

          <div className="space-y-4">
            <div className="text-sm text-gray-400 mb-2">Select data to include:</div>

            <div className="space-y-2">
              <label className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={exportOptions.include_identity}
                  disabled
                  className="w-4 h-4 bg-gray-800 border-gray-700 rounded"
                />
                <span className="text-gray-100">Node Identity (ghostnode.dat)</span>
                <Badge variant="warning">Required</Badge>
              </label>

              <label className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={exportOptions.include_wallet_keys}
                  disabled
                  className="w-4 h-4 bg-gray-800 border-gray-700 rounded"
                />
                <span className="text-gray-100">Wallet & Lock Keys</span>
                <Badge variant="warning">Required</Badge>
              </label>

              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={exportOptions.include_config}
                  onChange={(e) =>
                    setExportOptions({ ...exportOptions, include_config: e.target.checked })
                  }
                  className="w-4 h-4 bg-gray-800 border-gray-700 rounded"
                />
                <span className="text-gray-100">Configuration (config.toml)</span>
                <span className="text-gray-500 text-sm">Recommended</span>
              </label>

              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={exportOptions.include_ghost_pay_db}
                  onChange={(e) =>
                    setExportOptions({ ...exportOptions, include_ghost_pay_db: e.target.checked })
                  }
                  className="w-4 h-4 bg-gray-800 border-gray-700 rounded"
                />
                <span className="text-gray-100">Ghost Pay Database</span>
                <span className="text-gray-500 text-sm">Recommended</span>
              </label>

              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={exportOptions.include_block_history}
                  onChange={(e) =>
                    setExportOptions({ ...exportOptions, include_block_history: e.target.checked })
                  }
                  className="w-4 h-4 bg-gray-800 border-gray-700 rounded"
                />
                <span className="text-gray-100">L2 Block History</span>
                <span className="text-gray-500 text-sm">Optional (large)</span>
              </label>

              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={exportOptions.include_logs}
                  onChange={(e) =>
                    setExportOptions({ ...exportOptions, include_logs: e.target.checked })
                  }
                  className="w-4 h-4 bg-gray-800 border-gray-700 rounded"
                />
                <span className="text-gray-100">Logs</span>
                <span className="text-gray-500 text-sm">Optional</span>
              </label>
            </div>

            <div className="text-sm text-gray-400">
              Estimated size: ~{estimatedSize.toFixed(0)} MB
            </div>

            <div className="pt-4 border-t border-gray-800 space-y-3">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Encryption Password</label>
                <input
                  type="password"
                  value={exportPassword}
                  onChange={(e) => setExportPassword(e.target.value)}
                  placeholder="Enter a strong password"
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-gray-100 focus:outline-none focus:border-orange-500"
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-1">Confirm Password</label>
                <input
                  type="password"
                  value={exportConfirmPassword}
                  onChange={(e) => setExportConfirmPassword(e.target.value)}
                  placeholder="Confirm password"
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-gray-100 focus:outline-none focus:border-orange-500"
                />
              </div>

              {exportPassword && (
                <div className="flex items-center gap-3">
                  <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${passwordStrength.color}`}
                      style={{ width: `${passwordStrength.percent}%` }}
                    />
                  </div>
                  <span className="text-sm text-gray-400">{passwordStrength.label}</span>
                </div>
              )}

              {exportError && (
                <p className="text-red-400 text-sm">{exportError}</p>
              )}

              {exportSuccess && (
                <p className="text-green-400 text-sm">{exportSuccess}</p>
              )}

              <button
                onClick={handleExport}
                disabled={exporting || !exportPassword || exportPassword !== exportConfirmPassword}
                className="w-full px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded disabled:opacity-50"
              >
                {exporting ? "Generating Backup..." : "Generate Encrypted Backup"}
              </button>
            </div>
          </div>
        </Card>

        {/* Import */}
        <Card className="mb-6">
          <CardHeader title="Import Node Backup" />

          <div className="space-y-4">
            <input
              ref={fileInputRef}
              type="file"
              accept=".enc,.tar.gz.enc"
              onChange={handleFileSelect}
              className="hidden"
            />

            <button
              onClick={() => fileInputRef.current?.click()}
              className="w-full px-4 py-8 border-2 border-dashed border-gray-700 rounded-lg text-gray-400 hover:text-gray-200 hover:border-gray-600 transition-colors"
            >
              {importFile ? importFile.name : "Choose Backup File..."}
            </button>

            {importFile && (
              <>
                <div className="p-3 bg-gray-800/50 rounded-lg text-sm">
                  <div className="flex justify-between text-gray-400">
                    <span>Selected: {importFile.name}</span>
                    <span>{formatBytes(importFile.size)}</span>
                  </div>
                </div>

                <div>
                  <label className="block text-sm text-gray-400 mb-1">Decryption Password</label>
                  <input
                    type="password"
                    value={importPassword}
                    onChange={(e) => setImportPassword(e.target.value)}
                    placeholder="Enter backup password"
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-gray-100 focus:outline-none focus:border-orange-500"
                  />
                </div>

                {!verifiedInfo && (
                  <button
                    onClick={handleVerify}
                    disabled={verifying || !importPassword}
                    className="w-full px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded disabled:opacity-50"
                  >
                    {verifying ? "Verifying..." : "Verify Backup"}
                  </button>
                )}

                {verifiedInfo && (
                  <>
                    <div className="p-4 bg-gray-800/50 rounded-lg space-y-2">
                      <h4 className="text-gray-200 font-medium">Backup Contents:</h4>
                      <div className="text-sm space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-green-400">verified</span>
                          <span className="text-gray-400">Node ID:</span>
                          <span className="font-mono text-gray-100">
                            {truncateId(verifiedInfo.node_id ?? "")}
                          </span>
                        </div>
                        {verifiedInfo.elder_status && (
                          <div className="flex items-center gap-2">
                            <span className="text-green-400">verified</span>
                            <span className="text-gray-400">Elder Status:</span>
                            <span className="text-gray-100">#{verifiedInfo.elder_slot}</span>
                          </div>
                        )}
                        {verifiedInfo.config_included && (
                          <div className="flex items-center gap-2">
                            <span className="text-green-400">verified</span>
                            <span className="text-gray-400">Configuration:</span>
                            <span className="text-gray-100">Included</span>
                          </div>
                        )}
                        {verifiedInfo.ghost_pay_blocks && (
                          <div className="flex items-center gap-2">
                            <span className="text-green-400">verified</span>
                            <span className="text-gray-400">Ghost Pay DB:</span>
                            <span className="text-gray-100">
                              {verifiedInfo.ghost_pay_blocks.toLocaleString()} blocks
                            </span>
                          </div>
                        )}
                        {(verifiedInfo.locks_count ?? 0) > 0 && (
                          <div className="flex items-center gap-2">
                            <span className="text-green-400">verified</span>
                            <span className="text-gray-400">Locks:</span>
                            <span className="text-gray-100">
                              {verifiedInfo.locks_count} locks ({(verifiedInfo.locks_balance_btc ?? 0).toFixed(4)} BTC)
                            </span>
                          </div>
                        )}
                        <div className="flex items-center gap-2">
                          <span className="text-green-400">verified</span>
                          <span className="text-gray-400">Checksum:</span>
                          <span className="text-gray-100">Valid</span>
                        </div>
                      </div>
                    </div>

                    <div className="p-3 bg-red-900/20 border border-red-800 rounded-lg">
                      <p className="text-red-400 text-sm">
                        This will REPLACE all current node data.
                        Ensure the OLD node is completely STOPPED.
                      </p>
                    </div>

                    <label className="flex items-center gap-3 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={importConfirmed}
                        onChange={(e) => setImportConfirmed(e.target.checked)}
                        className="w-4 h-4 bg-gray-800 border-gray-700 rounded"
                      />
                      <span className="text-gray-300 text-sm">
                        I confirm the old node is stopped and I understand the risks of running duplicate Node IDs
                      </span>
                    </label>

                    <button
                      onClick={handleImport}
                      disabled={importing || !importConfirmed}
                      className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded disabled:opacity-50"
                    >
                      {importing ? "Restoring..." : "Import & Restore"}
                    </button>
                  </>
                )}

                {importError && (
                  <p className="text-red-400 text-sm">{importError}</p>
                )}

                {importSuccess && (
                  <p className="text-green-400 text-sm">{importSuccess}</p>
                )}
              </>
            )}
          </div>
        </Card>

        {/* Seed Phrase */}
        <Card className="mb-6">
          <CardHeader title="Seed Phrase Backup (Alternative)" />
          <div className="p-4 bg-gray-800/50 rounded-lg">
            <p className="text-gray-400 text-sm mb-4">
              Your seed phrase can regenerate your Node ID and all keys.
              This is a lightweight alternative to full backup.
            </p>
            <div className="flex gap-3">
              <button className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded">
                View Seed Phrase
              </button>
              <button className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded">
                Recover from Seed Phrase
              </button>
            </div>
          </div>
        </Card>

        {/* Backup History */}
        <Card>
          <CardHeader title="Backup History" />
          {loadingHistory ? (
            <div className="animate-pulse h-20 bg-gray-800 rounded"></div>
          ) : history.length === 0 ? (
            <p className="text-gray-400">No backup history</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-gray-400 text-sm border-b border-gray-800">
                    <th className="pb-3 font-medium">Date</th>
                    <th className="pb-3 font-medium">Type</th>
                    <th className="pb-3 font-medium">Size</th>
                    <th className="pb-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {history.map((entry) => (
                    <tr key={entry.filename} className="text-gray-100">
                      <td className="py-3 text-gray-400">
                        {formatDate(entry.created_at ?? 0)}
                      </td>
                      <td className="py-3">{entry.type === "full" ? "Full" : "Partial"}</td>
                      <td className="py-3">{formatBytes(entry.size_bytes ?? 0)}</td>
                      <td className="py-3">
                        <Badge variant={entry.exported ? "success" : "default"}>
                          {entry.exported ? "Exported" : "Pending"}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
