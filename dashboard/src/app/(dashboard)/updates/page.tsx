import { redirect } from "next/navigation";

// Legacy duplicate of /system's Updates section. Sidebar still links here for
// muscle memory; redirect server-side so any clicks land in one canonical
// place. The route can be deleted once nothing links to /updates externally.
export default function Page() {
  redirect("/system");
}
