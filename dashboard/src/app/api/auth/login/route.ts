import { NextRequest, NextResponse } from "next/server";
import {
  resolveJwtSecret,
  resolveTtlSecs,
  signSession,
  timingSafeEqualStr,
} from "@/lib/jwt";

export async function POST(request: NextRequest) {
  const { password } = await request.json();
  const dashboardPassword = process.env.DASHBOARD_PASSWORD;

  if (!dashboardPassword) {
    return NextResponse.json({ error: "No password configured" }, { status: 500 });
  }

  if (!timingSafeEqualStr(password ?? "", dashboardPassword)) {
    return NextResponse.json({ error: "Invalid password" }, { status: 401 });
  }

  const secret = await resolveJwtSecret();
  if (!secret) {
    return NextResponse.json({ error: "No signing secret configured" }, { status: 500 });
  }

  const ttl = resolveTtlSecs();
  const token = await signSession("operator", secret, ttl);

  const response = NextResponse.json({ ok: true, expires_in: ttl });
  response.cookies.set("ghost-session", token, {
    httpOnly: true,
    secure: request.nextUrl.protocol === "https:",
    sameSite: "lax",
    path: "/",
    maxAge: ttl,
  });
  return response;
}
