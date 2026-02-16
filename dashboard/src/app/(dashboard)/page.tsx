"use client";

import { NodeHeader } from "@/components/dashboard/NodeHeader";
import { StatsGrid } from "@/components/dashboard/StatsGrid";
import { DecentralisationCard } from "@/components/dashboard/DecentralisationCard";
import { SharesCard } from "@/components/dashboard/SharesCard";
import { StatusCard } from "@/components/dashboard/StatusCard";
import { QuickStatsCard } from "@/components/dashboard/QuickStatsCard";
import { RecentActivityCard } from "@/components/dashboard/RecentActivityCard";

export default function Dashboard() {
  return (
    <div className="space-y-6">
      <NodeHeader />

      {/* Quick Stats Row */}
      <StatsGrid />

      {/* Three Column Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <StatusCard />
        <QuickStatsCard />
        <SharesCard />
      </div>

      {/* Decentralisation Status - Full Width */}
      <DecentralisationCard />

      {/* Recent Activity - Full Width */}
      <RecentActivityCard />
    </div>
  );
}
