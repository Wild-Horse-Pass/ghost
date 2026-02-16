import { NextRequest, NextResponse } from "next/server";

function hashPassword(password: string): string {
  let hash = 0;
  for (let i = 0; i < password.length; i++) {
    const char = password.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return `ghost-${Math.abs(hash).toString(36)}`;
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
  response.cookies.set("ghost-session", hashPassword(dashboardPassword), {
    httpOnly: true,
    secure: request.nextUrl.protocol === "https:",
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 7, // 7 days
  });

  return response;
}
