'use client';

import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Toggle } from '@/components/ui/Toggle';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { useSetBitcoinPure, useConfig } from '@/hooks/queries';

interface ReaperData {
  bitcoin_pure: boolean;
  filter_inscriptions: boolean;
  filter_brc20: boolean;
  filter_runes: boolean;
  max_witness_size: number;
  dust_limit: number;
}

interface ReaperWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function ReaperWizard({ isOpen, onClose }: ReaperWizardProps) {
  const { data: config } = useConfig();
  const setBitcoinPure = useSetBitcoinPure();
  const toast = useToast();

  const steps: WizardStep<ReaperData>[] = [
    {
      id: 'enable',
      title: 'Enable',
      description: 'Enable or disable Ghost Reaper (Bitcoin Pure mode)',
    },
    {
      id: 'filters',
      title: 'Filters',
      description: 'Configure mempool filtering rules',
      validate: (data) => {
        if (data.bitcoin_pure) {
          if (data.max_witness_size < 100) {
            return 'Maximum witness size must be at least 100 bytes';
          }
          if (data.max_witness_size > 1000000) {
            return 'Maximum witness size cannot exceed 1,000,000 bytes';
          }
          if (data.dust_limit < 330) {
            return 'Dust limit must be at least 330 satoshis';
          }
          if (data.dust_limit > 100000) {
            return 'Dust limit cannot exceed 100,000 satoshis';
          }
        }
        return null;
      },
    },
    {
      id: 'preview',
      title: 'Preview',
      description: 'Review your filtering configuration',
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Apply Ghost Reaper settings',
      onSubmit: async (data) => {
        await setBitcoinPure.mutateAsync(data.bitcoin_pure);
        toast.success(
          'Ghost Reaper Updated',
          data.bitcoin_pure
            ? 'Ghost Reaper enabled -- mempool filtering is now active'
            : 'Ghost Reaper disabled -- filtering is now inactive'
        );
        onClose();
      },
    },
  ];

  const wizard = useWizard<ReaperData>({
    steps,
    initialData: {
      bitcoin_pure: config?.bitcoin_pure ?? false,
      filter_inscriptions: true,
      filter_brc20: true,
      filter_runes: true,
      max_witness_size: 400,
      dust_limit: 546,
    },
  });

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Ghost Reaper Setup"
      wizard={wizard}
      size="lg"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 1: Enable */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-gray-100 font-medium">Bitcoin Pure Mode</span>
                    <p className="text-sm text-gray-400 mt-1">
                      Reject transactions with dead code in witness scripts. Filters inscriptions,
                      drop stuffing, and other non-financial data from your mempool.
                    </p>
                  </div>
                  <Toggle
                    enabled={data.bitcoin_pure}
                    onChange={(enabled) => setData({ bitcoin_pure: enabled })}
                    label="Bitcoin Pure"
                  />
                </div>
              </div>
              {data.bitcoin_pure && (
                <div className="p-4 rounded-lg bg-green-900/20 border border-green-800">
                  <div className="flex items-center gap-2">
                    <Badge variant="success">+2 Shares</Badge>
                    <span className="text-sm text-green-300">
                      Enables Bitcoin Pure capability verification for node rewards
                    </span>
                  </div>
                </div>
              )}
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-2">What Ghost Reaper filters</h4>
                <ul className="space-y-2 text-sm text-gray-400">
                  <li className="flex items-center gap-2">
                    <span className="text-orange-300">--</span>
                    Ordinal inscriptions embedded in witness data
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-orange-300">--</span>
                    BRC-20 token operations (JSON in witness)
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-orange-300">--</span>
                    Runes protocol metadata
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-orange-300">--</span>
                    Oversized witness data (drop stuffing)
                  </li>
                </ul>
              </div>
            </div>
          )}

          {/* Step 2: Filters */}
          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              {!data.bitcoin_pure && (
                <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                  <p className="text-sm text-orange-300">
                    Bitcoin Pure is disabled. These filters will not be active until you enable it.
                  </p>
                </div>
              )}
              <div className="p-4 rounded-lg bg-gray-800/50 space-y-4">
                <h4 className="text-gray-100 font-medium">Transaction Type Filters</h4>
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-gray-100">Filter Inscriptions</span>
                    <p className="text-sm text-gray-400 mt-1">
                      Reject ordinal inscription transactions
                    </p>
                  </div>
                  <Toggle
                    enabled={data.filter_inscriptions}
                    onChange={(v) => setData({ filter_inscriptions: v })}
                    label="Filter Inscriptions"
                    disabled={!data.bitcoin_pure}
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-gray-100">Filter BRC-20</span>
                    <p className="text-sm text-gray-400 mt-1">
                      Reject BRC-20 token operations
                    </p>
                  </div>
                  <Toggle
                    enabled={data.filter_brc20}
                    onChange={(v) => setData({ filter_brc20: v })}
                    label="Filter BRC-20"
                    disabled={!data.bitcoin_pure}
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-gray-100">Filter Runes</span>
                    <p className="text-sm text-gray-400 mt-1">
                      Reject Runes protocol transactions
                    </p>
                  </div>
                  <Toggle
                    enabled={data.filter_runes}
                    onChange={(v) => setData({ filter_runes: v })}
                    label="Filter Runes"
                    disabled={!data.bitcoin_pure}
                  />
                </div>
              </div>
              <div className="p-4 rounded-lg bg-gray-800/50 space-y-4">
                <h4 className="text-gray-100 font-medium">Size Limits</h4>
                <div>
                  <Input
                    label="Max Witness Size (bytes)"
                    type="number"
                    value={data.max_witness_size}
                    onChange={(e) => setData({ max_witness_size: Number(e.target.value) })}
                    disabled={!data.bitcoin_pure}
                  />
                  <p className="text-sm text-gray-400 mt-1">
                    Transactions with witness data exceeding this size will be rejected.
                    Default: 400 bytes.
                  </p>
                </div>
                <div>
                  <Input
                    label="Dust Limit (satoshis)"
                    type="number"
                    value={data.dust_limit}
                    onChange={(e) => setData({ dust_limit: Number(e.target.value) })}
                    disabled={!data.bitcoin_pure}
                  />
                  <p className="text-sm text-gray-400 mt-1">
                    Outputs below this value are considered dust and may be filtered.
                    Default: 546 sats.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Preview */}
          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Configuration Summary</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Bitcoin Pure Mode</span>
                    <Badge variant={data.bitcoin_pure ? 'success' : 'default'}>
                      {data.bitcoin_pure ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                  <div className="border-t border-gray-700 pt-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Inscriptions</span>
                      <Badge variant={data.filter_inscriptions && data.bitcoin_pure ? 'error' : 'default'}>
                        {data.filter_inscriptions && data.bitcoin_pure ? 'Filtered' : 'Allowed'}
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">BRC-20</span>
                      <Badge variant={data.filter_brc20 && data.bitcoin_pure ? 'error' : 'default'}>
                        {data.filter_brc20 && data.bitcoin_pure ? 'Filtered' : 'Allowed'}
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Runes</span>
                      <Badge variant={data.filter_runes && data.bitcoin_pure ? 'error' : 'default'}>
                        {data.filter_runes && data.bitcoin_pure ? 'Filtered' : 'Allowed'}
                      </Badge>
                    </div>
                  </div>
                  <div className="border-t border-gray-700 pt-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Max Witness Size</span>
                      <span className="text-gray-100">{data.max_witness_size.toLocaleString()} bytes</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Dust Limit</span>
                      <span className="text-gray-100">{data.dust_limit.toLocaleString()} sats</span>
                    </div>
                  </div>
                </div>
              </div>
              {data.bitcoin_pure && (
                <div className="p-4 rounded-lg bg-green-900/20 border border-green-800">
                  <p className="text-sm text-green-300">
                    With these settings, your node will actively filter non-financial transactions
                    from its mempool and earn +2 shares in the node reward pool.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Step 4: Confirm */}
          {wizard.currentStep === 3 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Ready to Apply</h4>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Ghost Reaper</span>
                  <div className="flex items-center gap-2">
                    <Badge variant={config?.bitcoin_pure ? 'success' : 'default'}>
                      {config?.bitcoin_pure ? 'Enabled' : 'Disabled'}
                    </Badge>
                    <span className="text-gray-500">-&gt;</span>
                    <Badge variant={data.bitcoin_pure ? 'success' : 'default'}>
                      {data.bitcoin_pure ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                <p className="text-sm text-orange-300">
                  Click Finish to apply the Ghost Reaper configuration.
                  Changes will take effect immediately on your node.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
