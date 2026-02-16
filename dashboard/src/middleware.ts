import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const PUBLIC_PATHS = ["/login", "/api/auth/login", "/api/auth/logout"];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow public paths
  if (PUBLIC_PATHS.some((p) => pathname.startsWith(p))) {
    return NextResponse.next();
  }

  // Allow static files and Next.js internals
  if (
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon") ||
    pathname.endsWith(".svg") ||
    pathname.endsWith(".ico")
  ) {
    return NextResponse.next();
  }

  // Check if request is from localhost — skip auth
  const forwardedFor = request.headers.get("x-forwarded-for");
  const ip = forwardedFor?.split(",")[0]?.trim() || "";
  const isLocalhost =
    ip === "127.0.0.1" ||
    ip === "::1" ||
    ip === "localhost" ||
    ip === "" || // Direct access (no proxy)
    request.headers.get("host")?.startsWith("localhost");

  if (isLocalhost) {
    return NextResponse.next();
  }

  // Check for dashboard password if configured
  const dashboardPassword = process.env.DASHBOARD_PASSWORD;
  if (!dashboardPassword) {
    // No password set — allow all access
    return NextResponse.next();
  }

  // Check session cookie
  const sessionToken = request.cookies.get("ghost-session")?.value;
  if (!sessionToken || sessionToken !== hashPassword(dashboardPassword)) {
    // Redirect to login
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("redirect", pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

function hashPassword(password: string): string {
  // Simple deterministic hash for session token comparison
  // Not cryptographic — just prevents plaintext password in cookie
  let hash = 0;
  for (let i = 0; i < password.length; i++) {
    const char = password.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return `ghost-${Math.abs(hash).toString(36)}`;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
