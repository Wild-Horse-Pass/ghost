'use client';

import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Toggle } from '@/components/ui/Toggle';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import {
  useSetPublicMiningConfig,
  useSetMiningPayoutAddress,
} from '@/hooks/queries/useConfigQueries';
import { useNodeStatus } from '@/hooks/queries';

interface PoolSetupData {
  public_mining: boolean;
  payout_address: string;
}

interface PoolSetupWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

function isValidBech32Address(address: string): boolean {
  if (!address) return false;
  const trimmed = address.trim().toLowerCase();
  const validPrefixes = ['bc1', 'tb1', 'bcrt1'];
  const hasValidPrefix = validPrefixes.some((prefix) => trimmed.startsWith(prefix));
  if (!hasValidPrefix) return false;
  // Basic length check: bech32 addresses are typically 42-62 characters for segwit v0,
  // or 62 characters for segwit v1 (taproot). Allow a reasonable range.
  if (trimmed.length < 14 || trimmed.length > 90) return false;
  // Character set: bech32 uses lowercase alphanumeric excluding 1, b, i, o
  const bech32Chars = /^(bc1|tb1|bcrt1)[0-9a-z]{6,87}$/;
  return bech32Chars.test(trimmed);
}

export default function PoolSetupWizard({ isOpen, onClose }: PoolSetupWizardProps) {
  const { data: nodeStatus } = useNodeStatus();
  const setPublicMiningConfig = useSetPublicMiningConfig();
  const setMiningPayoutAddress = useSetMiningPayoutAddress();
  const toast = useToast();

  const steps: WizardStep<PoolSetupData>[] = [
    {
      id: 'mining',
      title: 'Public Mining',
      description: 'Enable or disable public mining connections',
    },
    {
      id: 'payout',
      title: 'Payout Address',
      description: 'Set your mining payout address',
      validate: (data) => {
        if (data.public_mining && !data.payout_address.trim()) {
          return 'Payout address is required when public mining is enabled';
        }
        if (data.payout_address.trim() && !isValidBech32Address(data.payout_address)) {
          return 'Invalid address. Must be a valid bech32 address starting with bc1, tb1, or bcrt1';
        }
        return null;
      },
    },
    {
      id: 'info',
      title: 'Pool Info',
      description: 'Pool configuration details',
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Review and apply changes',
      onSubmit: async (data) => {
        await setPublicMiningConfig.mutateAsync(data.public_mining);
        if (data.payout_address.trim()) {
          await setMiningPayoutAddress.mutateAsync(data.payout_address.trim());
        }
        toast.success(
          'Pool Setup Updated',
          data.public_mining
            ? 'Public mining enabled and payout address configured'
            : 'Pool configuration has been updated'
        );
        onClose();
      },
    },
  ];

  const wizard = useWizard<PoolSetupData>({
    steps,
    initialData: {
      public_mining: nodeStatus?.public_mining ?? false,
      payout_address: '',
    },
  });

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Pool Setup Wizard"
      wizard={wizard}
      size="lg"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 1: Public Mining Toggle */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-gray-100 font-medium">Public Mining</span>
                    <p className="text-sm text-gray-400 mt-1">
                      Accept mining connections from public miners on your Stratum port (3333).
                      Earns +3 shares in the node reward pool.
                    </p>
                  </div>
                  <Toggle
                    enabled={data.public_mining}
                    onChange={(enabled) => setData({ public_mining: enabled })}
                    label="Public Mining"
                  />
                </div>
              </div>
              {data.public_mining && (
                <div className="p-4 rounded-lg bg-green-900/20 border border-green-800">
                  <div className="flex items-center gap-2 mb-2">
                    <Badge variant="success">+3 Shares</Badge>
                    <span className="text-sm text-green-300">Public Mining capability bonus</span>
                  </div>
                  <p className="text-sm text-green-300">
                    Your node will accept external miner connections. Miners connect using
                    the worker name format: address.worker_id
                  </p>
                </div>
              )}
              {!data.public_mining && (
                <div className="p-4 rounded-lg bg-gray-800/50">
                  <p className="text-sm text-gray-400">
                    With public mining disabled, your node will only process blocks from the
                    pool network. External miners will not be able to connect.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Step 2: Payout Address */}
          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <Input
                  label="Mining Payout Address"
                  value={data.payout_address}
                  onChange={(e) => setData({ payout_address: e.target.value })}
                  placeholder="bc1q... / tb1q... / bcrt1q..."
                />
                <p className="text-sm text-gray-400 mt-1">
                  Enter a bech32 Bitcoin address to receive mining payouts. Must start with
                  bc1 (mainnet), tb1 (testnet/signet), or bcrt1 (regtest).
                </p>
              </div>
              {data.payout_address.trim() && (
                <div className="p-4 rounded-lg bg-gray-800/50">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Address Valid</span>
                    {isValidBech32Address(data.payout_address) ? (
                      <Badge variant="success">Valid</Badge>
                    ) : (
                      <Badge variant="error">Invalid</Badge>
                    )}
                  </div>
                  {isValidBech32Address(data.payout_address) && (
                    <div className="mt-2">
                      <span className="text-gray-400 text-sm">Network: </span>
                      <span className="text-orange-300 text-sm">
                        {data.payout_address.trim().toLowerCase().startsWith('bc1')
                          ? 'Mainnet'
                          : data.payout_address.trim().toLowerCase().startsWith('bcrt1')
                          ? 'Regtest'
                          : 'Testnet/Signet'}
                      </span>
                    </div>
                  )}
                </div>
              )}
              {data.public_mining && !data.payout_address.trim() && (
                <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                  <p className="text-sm text-orange-300">
                    A payout address is required when public mining is enabled.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Step 3: Pool Info */}
          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Pool Configuration</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Stratum Port</span>
                    <span className="text-gray-100 font-mono">3333</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Protocol</span>
                    <span className="text-gray-100">Stratum V1</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Variable Difficulty</span>
                    <Badge variant="success">Active</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Target Rate</span>
                    <span className="text-gray-100">4 shares/minute</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Share Cap</span>
                    <span className="text-gray-100">10% per miner</span>
                  </div>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-2">Miner Connection Format</h4>
                <p className="text-sm text-gray-400 mb-2">
                  Miners connect with the following worker name format:
                </p>
                <div className="p-3 rounded bg-gray-900 font-mono text-sm text-orange-300">
                  stratum+tcp://your-node-ip:3333
                </div>
                <p className="text-sm text-gray-400 mt-2">
                  Worker name: <span className="text-orange-300 font-mono">bitcoin_address.worker_id</span>
                </p>
              </div>
            </div>
          )}

          {/* Step 4: Confirm */}
          {wizard.currentStep === 3 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Configuration Summary</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Public Mining</span>
                    <div className="flex items-center gap-2">
                      <Badge variant={nodeStatus?.public_mining ? 'success' : 'default'}>
                        {nodeStatus?.public_mining ? 'Enabled' : 'Disabled'}
                      </Badge>
                      <span className="text-gray-500">-&gt;</span>
                      <Badge variant={data.public_mining ? 'success' : 'default'}>
                        {data.public_mining ? 'Enabled' : 'Disabled'}
                      </Badge>
                    </div>
                  </div>
                  {data.payout_address.trim() && (
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Payout Address</span>
                      <span className="text-gray-100 font-mono text-sm">
                        {data.payout_address.trim().slice(0, 12)}...
                        {data.payout_address.trim().slice(-8)}
                      </span>
                    </div>
                  )}
                </div>
              </div>
              <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                <p className="text-sm text-orange-300">
                  Click Finish to apply pool settings. Changes will take effect immediately.
                  {data.public_mining
                    ? ' Miners will be able to connect to your node on port 3333.'
                    : ''}
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
