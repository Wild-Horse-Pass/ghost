import { redirect } from "next/navigation";

// Legacy free-standing page (outside the dashboard chrome, two inert
// "View Seed Phrase" / "Recover from Seed Phrase" buttons that were never
// wired). Backup/restore is now in /system's Backup section, which uses
// the same APIs but inside the modern dashboard layout.
export default function Page() {
  redirect("/system");
}
