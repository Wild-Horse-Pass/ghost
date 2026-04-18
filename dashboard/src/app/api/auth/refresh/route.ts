import { NextRequest, NextResponse } from "next/server";
import {
  resolveJwtSecret,
  resolveTtlSecs,
  signSession,
  verifySession,
} from "@/lib/jwt";

/**
 * Slide the session cookie. Validates the current JWT (signature + exp) and,
 * if good, issues a fresh one with a new full TTL. Lets the dashboard keep
 * operators logged in while they're active without long-lived tokens.
 *
 * No-op if there's no token or the token is invalid — returns 401 so the
 * client-side refresh loop can stop.
 */
export async function POST(request: NextRequest) {
  const token = request.cookies.get("ghost-session")?.value;
  if (!token) {
    return NextResponse.json({ error: "No session" }, { status: 401 });
  }

  const secret = await resolveJwtSecret();
  if (!secret) {
    return NextResponse.json({ error: "No signing secret configured" }, { status: 500 });
  }

  const payload = await verifySession(token, secret);
  if (!payload) {
    return NextResponse.json({ error: "Invalid or expired session" }, { status: 401 });
  }

  const ttl = resolveTtlSecs();
  const fresh = await signSession(payload.sub, secret, ttl);

  const response = NextResponse.json({ ok: true, expires_in: ttl });
  response.cookies.set("ghost-session", fresh, {
    httpOnly: true,
    secure: request.nextUrl.protocol === "https:",
    sameSite: "lax",
    path: "/",
    maxAge: ttl,
  });
  return response;
}
