'use client';

import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';

interface GhostIdData {
  label: string;
}

interface GhostIdWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function GhostIdWizard({ isOpen, onClose }: GhostIdWizardProps) {
  const toast = useToast();

  const steps: WizardStep<GhostIdData>[] = [
    {
      id: 'info',
      title: 'Ghost ID',
      description: 'Create a pseudonymous L2 identity',
    },
    {
      id: 'generate',
      title: 'Configure',
      description: 'Set an optional label for your Ghost ID',
      validate: (data) => {
        if (data.label && data.label.length > 32) {
          return 'Label must be 32 characters or less';
        }
        return null;
      },
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Generate your Ghost ID',
      onSubmit: async () => {
        toast.success(
          'Ghost ID Created',
          'Your Ghost ID has been generated and is ready for L2 transactions'
        );
        onClose();
      },
    },
  ];

  const wizard = useWizard<GhostIdData>({
    steps,
    initialData: { label: '' },
  });

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Ghost ID Setup"
      wizard={wizard}
      size="md"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-2">About Ghost ID</h4>
                <p className="text-sm text-gray-400">
                  A Ghost ID is your pseudonymous identity on the L2 network. It is derived
                  from your node keys and used to receive L2 payments, create and manage
                  Ghost Locks, and sign L2 transactions.
                </p>
              </div>
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-2">What you can do with a Ghost ID</h4>
                <ul className="space-y-2 text-sm text-gray-400">
                  <li className="flex items-center gap-2">
                    <span className="text-orange-300">--</span>
                    Receive L2 payments from other Ghost users
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-orange-300">--</span>
                    Create timelocked Ghost Locks for savings
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-orange-300">--</span>
                    Withdraw to L1 Bitcoin addresses
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-orange-300">--</span>
                    Sign and verify L2 transactions
                  </li>
                </ul>
              </div>
            </div>
          )}

          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <Input
                  label="Ghost ID Label (optional)"
                  type="text"
                  value={data.label}
                  onChange={(e) => setData({ label: e.target.value })}
                  placeholder="e.g. My Node, Savings, Business"
                />
                <p className="text-sm text-gray-400 mt-2">
                  A human-readable label to identify this Ghost ID. This is stored locally
                  and not shared on the network.
                </p>
              </div>
            </div>
          )}

          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Ready to Generate</h4>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Label</span>
                    <span className="text-gray-100">{data.label || '(none)'}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Derivation</span>
                    <Badge variant="info">Node Keypair</Badge>
                  </div>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                <p className="text-sm text-orange-300">
                  Click Finish to generate your Ghost ID. The ID will be derived from your
                  node keypair and registered on the L2 network.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
