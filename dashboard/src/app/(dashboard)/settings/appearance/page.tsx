"use client";

import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { AppearanceSection } from "../AppearanceSection";

export default function AppearanceSettingsPage() {
  return (
    <SectionErrorBoundary section="Appearance">
      <AppearanceSection />
    </SectionErrorBoundary>
  );
}
