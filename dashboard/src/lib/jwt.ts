// Minimal HS256 JWT implementation on Web Crypto.
// Runs in both Next.js Edge Runtime (middleware) and Node.js Runtime (API routes).
// Avoids the `jose` dependency — 40 lines beats 50KB.

export interface SessionPayload {
  sub: string;
  iat: number;
  exp: number;
}

const DEFAULT_TTL_SECS = 60 * 60; // 1 hour
const JWT_HEADER_B64U = base64UrlEncode(
  new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })),
);

function base64UrlEncode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(str: string): Uint8Array {
  const pad = (4 - (str.length % 4)) % 4;
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function importKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/**
 * Derive a stable JWT signing secret from the configured dashboard password.
 * Used when DASHBOARD_JWT_SECRET isn't explicitly set — produces a distinct
 * key from the password so a leaked token doesn't equal a leaked password.
 */
export async function deriveJwtSecret(password: string): Promise<string> {
  const key = await importKey(password);
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode("ghost-dashboard-jwt-v1"),
  );
  return base64UrlEncode(new Uint8Array(sig));
}

/** Resolve the signing secret from env, deriving from DASHBOARD_PASSWORD as a fallback. */
export async function resolveJwtSecret(): Promise<string | null> {
  const explicit = process.env.DASHBOARD_JWT_SECRET;
  if (explicit && explicit.length >= 32) return explicit;
  const password = process.env.DASHBOARD_PASSWORD;
  if (!password) return null;
  return deriveJwtSecret(password);
}

export function resolveTtlSecs(): number {
  const raw = process.env.DASHBOARD_TOKEN_TTL_SECS;
  if (!raw) return DEFAULT_TTL_SECS;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TTL_SECS;
}

/** Sign a fresh access token valid for `ttlSecs` seconds. */
export async function signSession(
  sub: string,
  secret: string,
  ttlSecs: number,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: SessionPayload = { sub, iat: now, exp: now + ttlSecs };
  const payloadB64u = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  const signingInput = `${JWT_HEADER_B64U}.${payloadB64u}`;
  const key = await importKey(secret);
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64UrlEncode(new Uint8Array(sig))}`;
}

/**
 * Verify a JWT. Returns the decoded payload if signature + exp check out,
 * else null. Uses crypto.subtle.verify which is constant-time.
 */
export async function verifySession(
  token: string,
  secret: string,
): Promise<SessionPayload | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  if (h !== JWT_HEADER_B64U) return null; // reject non-HS256 or mis-typed
  const signingInput = `${h}.${p}`;
  let sigBytes: Uint8Array;
  try {
    sigBytes = base64UrlDecode(s);
  } catch {
    return null;
  }
  const key = await importKey(secret);
  // Cast: Uint8Array<ArrayBufferLike> is assignable to BufferSource at runtime,
  // but the TS types are strict about ArrayBuffer vs SharedArrayBuffer backing.
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    sigBytes as unknown as BufferSource,
    new TextEncoder().encode(signingInput),
  );
  if (!valid) return null;
  let payload: SessionPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(p)));
  } catch {
    return null;
  }
  if (typeof payload.exp !== "number" || payload.exp < Math.floor(Date.now() / 1000)) {
    return null;
  }
  return payload;
}

/** Constant-time password comparison that survives length-leak attacks. */
export function timingSafeEqualStr(a: string, b: string): boolean {
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);
  if (aBytes.length !== bBytes.length) {
    // Still walk one of them to avoid an early-return length leak on the
    // caller's timing profile. The XOR result is discarded.
    let sink = 0;
    for (let i = 0; i < aBytes.length; i++) sink |= aBytes[i] ^ (bBytes[0] ?? 0);
    void sink;
    return false;
  }
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i] ^ bBytes[i];
  return diff === 0;
}
