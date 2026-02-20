"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { IdentitySection } from "./IdentitySection";
import { PayoutSection } from "./PayoutSection";
import { AppearanceSection } from "./AppearanceSection";
import { ModesSection } from "./ModesSection";
import { ProtocolsSection } from "./ProtocolsSection";
import { MempoolProfileSection } from "./MempoolProfileSection";
import { TemplateProfileSection } from "./TemplateProfileSection";
import InitialSetupWizard from "./wizards/InitialSetupWizard";
import ChangeSetupWizard from "./wizards/ChangeSetupWizard";
import GhostModeWizard from "./wizards/GhostModeWizard";
import ReaperWizard from "./wizards/ReaperWizard";
import HazeWizard from "./wizards/HazeWizard";
import ShroudWizard from "./wizards/ShroudWizard";
import PoolSetupWizard from "./wizards/PoolSetupWizard";
import MempoolPolicyWizard from "./wizards/MempoolPolicyWizard";
import BuildRunWizard from "./wizards/BuildRunWizard";

export default function SettingsPage() {
  const [initialSetupOpen, setInitialSetupOpen] = useState(false);
  const [changeSetupOpen, setChangeSetupOpen] = useState(false);
  const [ghostModeOpen, setGhostModeOpen] = useState(false);
  const [reaperOpen, setReaperOpen] = useState(false);
  const [hazeOpen, setHazeOpen] = useState(false);
  const [shroudOpen, setShroudOpen] = useState(false);
  const [poolSetupOpen, setPoolSetupOpen] = useState(false);
  const [mempoolPolicyOpen, setMempoolPolicyOpen] = useState(false);
  const [buildRunOpen, setBuildRunOpen] = useState(false);

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" subtitle="Node configuration and preferences" />

      {/* Quick Setup Wizards */}
      <Card>
        <CardHeader title="Quick Setup" subtitle="Guided wizards for common configuration tasks" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <Button variant="primary" size="lg" onClick={() => setInitialSetupOpen(true)} className="w-full">
            Initial Setup
          </Button>
          <Button variant="outline" size="lg" onClick={() => setChangeSetupOpen(true)} className="w-full">
            Change Setup
          </Button>
          <Button variant="primary" size="lg" onClick={() => setBuildRunOpen(true)} className="w-full">
            Build &amp; Run
          </Button>
        </div>
      </Card>

      <SectionErrorBoundary section="Identity"><IdentitySection /></SectionErrorBoundary>
      <SectionErrorBoundary section="Payout"><PayoutSection /></SectionErrorBoundary>
      <SectionErrorBoundary section="Appearance"><AppearanceSection /></SectionErrorBoundary>

      <SectionErrorBoundary section="Modes">
        <ModesSection />
        <div className="flex gap-2 mt-3">
          <Button variant="outline" size="sm" onClick={() => setGhostModeOpen(true)}>
            Ghost Mode Wizard
          </Button>
          <Button variant="outline" size="sm" onClick={() => setPoolSetupOpen(true)}>
            Pool Setup Wizard
          </Button>
        </div>
      </SectionErrorBoundary>

      <SectionErrorBoundary section="Protocols">
        <ProtocolsSection />
        <div className="flex gap-2 mt-3">
          <Button variant="outline" size="sm" onClick={() => setReaperOpen(true)}>
            Reaper Wizard
          </Button>
          <Button variant="outline" size="sm" onClick={() => setHazeOpen(true)}>
            Haze Wizard
          </Button>
          <Button variant="outline" size="sm" onClick={() => setShroudOpen(true)}>
            Shroud Wizard
          </Button>
        </div>
      </SectionErrorBoundary>

      <SectionErrorBoundary section="Mempool Profiles">
        <MempoolProfileSection />
        <div className="mt-3">
          <Button variant="outline" size="sm" onClick={() => setMempoolPolicyOpen(true)}>
            Mempool Policy Wizard
          </Button>
        </div>
      </SectionErrorBoundary>

      <SectionErrorBoundary section="Template Profiles"><TemplateProfileSection /></SectionErrorBoundary>

      {/* Wizard dialogs */}
      <InitialSetupWizard isOpen={initialSetupOpen} onClose={() => setInitialSetupOpen(false)} />
      <ChangeSetupWizard isOpen={changeSetupOpen} onClose={() => setChangeSetupOpen(false)} />
      <BuildRunWizard isOpen={buildRunOpen} onClose={() => setBuildRunOpen(false)} />
      <GhostModeWizard isOpen={ghostModeOpen} onClose={() => setGhostModeOpen(false)} />
      <PoolSetupWizard isOpen={poolSetupOpen} onClose={() => setPoolSetupOpen(false)} />
      <ReaperWizard isOpen={reaperOpen} onClose={() => setReaperOpen(false)} />
      <HazeWizard isOpen={hazeOpen} onClose={() => setHazeOpen(false)} />
      <ShroudWizard isOpen={shroudOpen} onClose={() => setShroudOpen(false)} />
      <MempoolPolicyWizard isOpen={mempoolPolicyOpen} onClose={() => setMempoolPolicyOpen(false)} />
    </div>
  );
}
