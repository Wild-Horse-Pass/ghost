import { redirect } from "next/navigation";

// Legacy free-standing page (no dashboard chrome, manual polling, no React
// Query). Same data is now surfaced inside /ghost-pay's overview cards.
export default function Page() {
  redirect("/ghost-pay");
}
