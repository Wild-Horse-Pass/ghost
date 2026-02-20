'use client';

import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Toggle } from '@/components/ui/Toggle';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { useConfigureShroud } from '@/hooks/queries/useConfigQueries';
import { useShroudStatus } from '@/hooks/queries/useShroudQueries';

interface ShroudData {
  enabled: boolean;
  dandelion: boolean;
  max_delay_ms: number;
}

interface ShroudWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function ShroudWizard({ isOpen, onClose }: ShroudWizardProps) {
  const { data: shroudStatus } = useShroudStatus();
  const configureShroud = useConfigureShroud();
  const toast = useToast();

  const steps: WizardStep<ShroudData>[] = [
    {
      id: 'status',
      title: 'Status',
      description: 'Current Ghost Shroud configuration',
    },
    {
      id: 'configure',
      title: 'Configure',
      description: 'Set up transaction relay privacy',
      validate: (data) => {
        if (data.enabled) {
          if (data.max_delay_ms < 100) {
            return 'Maximum delay must be at least 100ms';
          }
          if (data.max_delay_ms > 60000) {
            return 'Maximum delay cannot exceed 60,000ms (60 seconds)';
          }
        }
        return null;
      },
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Review and apply changes',
      onSubmit: async (data) => {
        await configureShroud.mutateAsync({
          enabled: data.enabled,
          dandelion: data.dandelion,
          max_delay_ms: data.max_delay_ms,
        });
        toast.success(
          'Ghost Shroud Updated',
          data.enabled
            ? `Shroud enabled with ${data.max_delay_ms}ms max delay`
            : 'Shroud has been disabled'
        );
        onClose();
      },
    },
  ];

  const wizard = useWizard<ShroudData>({
    steps,
    initialData: {
      enabled: shroudStatus?.enabled ?? false,
      dandelion: true,
      max_delay_ms: shroudStatus?.max_delay_ms ?? 5000,
    },
  });

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Ghost Shroud Setup"
      wizard={wizard}
      size="lg"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 1: Current Status */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Current Shroud Status</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Shroud Enabled</span>
                    <Badge variant={shroudStatus?.enabled ? 'success' : 'default'}>
                      {shroudStatus?.enabled ? 'Active' : 'Inactive'}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Ghost Core Connected</span>
                    <Badge variant={shroudStatus?.ghost_core_connected ? 'success' : 'warning'}>
                      {shroudStatus?.ghost_core_connected ? 'Connected' : 'Not Connected'}
                    </Badge>
                  </div>
                  {shroudStatus?.enabled && (
                    <>
                      <div className="flex items-center justify-between">
                        <span className="text-gray-400">Max Delay</span>
                        <span className="text-gray-100">
                          {shroudStatus.max_delay_ms?.toLocaleString() ?? 'N/A'} ms
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-gray-400">Avg Delay</span>
                        <span className="text-gray-100">
                          {shroudStatus.avg_delay_ms?.toLocaleString() ?? 'N/A'} ms
                        </span>
                      </div>
                    </>
                  )}
                </div>
              </div>
              <div className="p-4 rounded-lg bg-gray-800/50">
                <p className="text-sm text-gray-400">
                  Ghost Shroud adds random delays before relaying transactions to peers,
                  making it harder for network observers to determine the origin of a
                  transaction. Combined with Dandelion routing, this provides strong
                  transaction-origin privacy.
                </p>
              </div>
            </div>
          )}

          {/* Step 2: Configure */}
          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-gray-100 font-medium">Enable Shroud</span>
                    <p className="text-sm text-gray-400 mt-1">
                      Add random delays to transaction relay for privacy
                    </p>
                  </div>
                  <Toggle
                    enabled={data.enabled}
                    onChange={(enabled) => setData({ enabled })}
                    label="Enable Shroud"
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-gray-100 font-medium">Dandelion Routing</span>
                    <p className="text-sm text-gray-400 mt-1">
                      Route transactions through a random stem phase before broadcasting
                    </p>
                  </div>
                  <Toggle
                    enabled={data.dandelion}
                    onChange={(v) => setData({ dandelion: v })}
                    label="Dandelion Routing"
                    disabled={!data.enabled}
                  />
                </div>
              </div>
              <div className="p-4 rounded-lg bg-gray-800/50">
                <Input
                  label="Maximum Delay (ms)"
                  type="number"
                  value={data.max_delay_ms}
                  onChange={(e) => setData({ max_delay_ms: Number(e.target.value) })}
                  disabled={!data.enabled}
                />
                <p className="text-sm text-gray-400 mt-1">
                  The maximum random delay added before relaying a transaction.
                  Actual delay is randomized between 0 and this value. Default: 5000ms.
                </p>
              </div>
              {data.enabled && data.max_delay_ms > 15000 && (
                <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                  <p className="text-sm text-orange-300">
                    High delay values may cause slower transaction propagation. Values above
                    15 seconds can impact transaction confirmation times.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Step 3: Confirm */}
          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Change Summary</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Shroud</span>
                    <div className="flex items-center gap-2">
                      <Badge variant={shroudStatus?.enabled ? 'success' : 'default'}>
                        {shroudStatus?.enabled ? 'Active' : 'Inactive'}
                      </Badge>
                      <span className="text-gray-500">-&gt;</span>
                      <Badge variant={data.enabled ? 'success' : 'default'}>
                        {data.enabled ? 'Active' : 'Inactive'}
                      </Badge>
                    </div>
                  </div>
                  {data.enabled && (
                    <>
                      <div className="flex items-center justify-between">
                        <span className="text-gray-400">Dandelion Routing</span>
                        <Badge variant={data.dandelion ? 'success' : 'default'}>
                          {data.dandelion ? 'Enabled' : 'Disabled'}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-gray-400">Max Delay</span>
                        <span className="text-gray-100">{data.max_delay_ms.toLocaleString()} ms</span>
                      </div>
                    </>
                  )}
                </div>
              </div>
              {data.enabled ? (
                <div className="p-4 rounded-lg bg-green-900/20 border border-green-800">
                  <p className="text-sm text-green-300">
                    Shroud will add random delays of up to {data.max_delay_ms.toLocaleString()}ms
                    before relaying transactions.
                    {data.dandelion
                      ? ' Dandelion routing will provide additional origin privacy.'
                      : ''}
                  </p>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                  <p className="text-sm text-orange-300">
                    Shroud will be disabled. Transactions will be relayed immediately to
                    peers without privacy delays.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
