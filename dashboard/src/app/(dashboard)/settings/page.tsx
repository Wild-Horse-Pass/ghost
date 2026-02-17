"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { IdentitySection } from "./IdentitySection";
import { PayoutSection } from "./PayoutSection";
import { AppearanceSection } from "./AppearanceSection";
import { ModesSection } from "./ModesSection";
import { MempoolProfileSection } from "./MempoolProfileSection";
import { TemplateProfileSection } from "./TemplateProfileSection";

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <PageHeader title="Settings" subtitle="Node configuration and preferences" />
      <SectionErrorBoundary section="Identity"><IdentitySection /></SectionErrorBoundary>
      <SectionErrorBoundary section="Payout"><PayoutSection /></SectionErrorBoundary>
      <SectionErrorBoundary section="Appearance"><AppearanceSection /></SectionErrorBoundary>
      <SectionErrorBoundary section="Modes"><ModesSection /></SectionErrorBoundary>
      <SectionErrorBoundary section="Mempool Profiles"><MempoolProfileSection /></SectionErrorBoundary>
      <SectionErrorBoundary section="Template Profiles"><TemplateProfileSection /></SectionErrorBoundary>
    </div>
  );
}
