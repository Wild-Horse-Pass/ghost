import { NextRequest, NextResponse } from "next/server";
import { createHmac } from "crypto";

function sessionToken(password: string): string {
  return createHmac("sha256", "ghost-dashboard")
    .update(password)
    .digest("hex")
    .slice(0, 32);
}

export async function POST(request: NextRequest) {
  const { password } = await request.json();
  const dashboardPassword = process.env.DASHBOARD_PASSWORD;

  if (!dashboardPassword) {
    return NextResponse.json({ error: "No password configured" }, { status: 500 });
  }

  if (password !== dashboardPassword) {
    return NextResponse.json({ error: "Invalid password" }, { status: 401 });
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set("ghost-session", sessionToken(dashboardPassword), {
    httpOnly: true,
    secure: request.nextUrl.protocol === "https:",
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 7, // 7 days
  });

  return response;
}
