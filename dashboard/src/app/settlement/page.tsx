import { redirect } from "next/navigation";

// Legacy free-standing page (no dashboard chrome, manual polling, no React
// Query). Settlement state is now surfaced inside /locks (uses
// useSettlementStatus + useGhostLocks).
export default function Page() {
  redirect("/locks");
}
