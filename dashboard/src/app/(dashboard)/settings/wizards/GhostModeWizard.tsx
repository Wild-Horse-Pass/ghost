'use client';

import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Toggle } from '@/components/ui/Toggle';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { useSetGhostMode, useConfig } from '@/hooks/queries';

interface GhostModeData {
  enabled: boolean;
}

interface GhostModeWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function GhostModeWizard({ isOpen, onClose }: GhostModeWizardProps) {
  const { data: config } = useConfig();
  const setGhostMode = useSetGhostMode();
  const toast = useToast();

  const steps: WizardStep<GhostModeData>[] = [
    {
      id: 'status',
      title: 'Status',
      description: 'Current Ghost Mode status',
    },
    {
      id: 'toggle',
      title: 'Configure',
      description: 'Enable or disable Ghost Mode',
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Review and apply your changes',
      onSubmit: async (data) => {
        await setGhostMode.mutateAsync(data.enabled);
        toast.success(
          'Ghost Mode Updated',
          `Ghost Mode has been ${data.enabled ? 'enabled' : 'disabled'}`
        );
        onClose();
      },
    },
  ];

  const wizard = useWizard<GhostModeData>({
    steps,
    initialData: {
      enabled: config?.ghost_mode ?? false,
    },
  });

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Ghost Mode Setup"
      wizard={wizard}
      size="md"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <div className="flex items-center justify-between">
                  <span className="text-gray-100 font-medium">Current Status</span>
                  <Badge variant={config?.ghost_mode ? 'success' : 'default'}>
                    {config?.ghost_mode ? 'Active' : 'Inactive'}
                  </Badge>
                </div>
                <p className="text-sm text-gray-400 mt-1">
                  Ghost Mode enables Ghost protocol features including L2 participation,
                  privacy tools, and node reward eligibility.
                </p>
              </div>
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-2">What Ghost Mode enables</h4>
                <ul className="space-y-2 text-sm text-gray-400">
                  <li className="flex items-center gap-2">
                    <span className="text-orange-300">--</span>
                    Ghost Pay L2 payment network participation
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-orange-300">--</span>
                    Node capability verification and share rewards
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-orange-300">--</span>
                    Privacy protocols (Haze, Shroud, Wraith)
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-orange-300">--</span>
                    P2P mesh network participation
                  </li>
                </ul>
              </div>
            </div>
          )}

          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-gray-100 font-medium">Ghost Mode</span>
                    <p className="text-sm text-gray-400 mt-1">
                      Enable Ghost protocol features and L2 participation
                    </p>
                  </div>
                  <Toggle
                    enabled={data.enabled}
                    onChange={(enabled) => setData({ enabled })}
                    label="Ghost Mode"
                  />
                </div>
              </div>
              {data.enabled && (
                <div className="p-4 rounded-lg bg-green-900/20 border border-green-800">
                  <p className="text-sm text-green-300">
                    Your node will join the Ghost network and become eligible for node rewards.
                  </p>
                </div>
              )}
              {!data.enabled && (
                <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                  <p className="text-sm text-orange-300">
                    Disabling Ghost Mode will disconnect your node from the Ghost network.
                    You will no longer earn node rewards or participate in L2 services.
                  </p>
                </div>
              )}
            </div>
          )}

          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Change Summary</h4>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Ghost Mode</span>
                  <div className="flex items-center gap-2">
                    <Badge variant={config?.ghost_mode ? 'success' : 'default'}>
                      {config?.ghost_mode ? 'Active' : 'Inactive'}
                    </Badge>
                    <span className="text-gray-500">-&gt;</span>
                    <Badge variant={data.enabled ? 'success' : 'default'}>
                      {data.enabled ? 'Active' : 'Inactive'}
                    </Badge>
                  </div>
                </div>
              </div>
              {data.enabled !== (config?.ghost_mode ?? false) ? (
                <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                  <p className="text-sm text-orange-300">
                    Click Finish to apply this change. Your node configuration will be updated immediately.
                  </p>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-gray-800/50">
                  <p className="text-sm text-gray-400">
                    No changes detected. The setting matches the current configuration.
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
