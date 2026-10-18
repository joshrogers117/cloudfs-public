// SPDX-License-Identifier: AGPL-3.0-or-later
// cors.ts — cross-origin support for a split-origin web console (audit B9).
//
// The simplest console topology is SAME-ORIGIN (serve the SPA from the Worker via a
// static-assets binding — no CORS, the SameSite=Lax cookie just works). But a deployer
// who hosts the console on Cloudflare Pages (a DIFFERENT origin) needs CORS, and the
// gateway previously had NONE: zero OPTIONS handling and a SameSite=Lax cookie, so a
// Pages-hosted console couldn't call the API at all.
//
// This adds a strict, allow-list-driven CORS layer:
//   • the allowed origins are WEB_BASE_URL (+ an optional CORS_ALLOWED_ORIGINS list);
//   • only an EXACT origin match is reflected into Access-Control-Allow-Origin (never
//     `*` — credentials:include forbids the wildcard and we must not be open-CORS);
//   • credentials are allowed (the session is a cookie) and Vary: Origin is set so a
//     cache never serves one origin's CORS headers to another.
// A request whose Origin isn't allow-listed gets NO CORS headers (the browser blocks
// it) — fail-closed.

export interface CorsEnv {
  WEB_BASE_URL?: string;
  /// Optional extra allowed origins (comma/space-separated), e.g. a staging console.
  CORS_ALLOWED_ORIGINS?: string;
}

const CORS_HEADERS = "authorization, content-type, x-cfs-csrf, x-bootstrap-secret, x-cloudfs-client-id";
const CORS_METHODS = "GET, POST, PUT, PATCH, DELETE, OPTIONS";

/// Normalize an origin string (drop a trailing slash) for exact comparison.
function normOrigin(o: string): string {
  return o.trim().replace(/\/+$/, "");
}

/// The set of allowed origins for this deployment.
export function allowedOrigins(env: CorsEnv): Set<string> {
  const out = new Set<string>();
  if (env.WEB_BASE_URL) out.add(normOrigin(env.WEB_BASE_URL));
  for (const part of (env.CORS_ALLOWED_ORIGINS ?? "").split(/[\s,]+/)) {
    const o = normOrigin(part);
    if (o) out.add(o);
  }
  return out;
}

/// The CORS response headers for a request's Origin, or `{}` if the origin is not
/// allow-listed (so the browser blocks the cross-origin read — fail-closed).
export function corsHeadersFor(req: Request, env: CorsEnv): Record<string, string> {
  const origin = req.headers.get("Origin");
  if (!origin) return {}; // same-origin / non-browser — no CORS needed
  if (!allowedOrigins(env).has(normOrigin(origin))) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": CORS_METHODS,
    "Access-Control-Allow-Headers": CORS_HEADERS,
    "Access-Control-Max-Age": "600",
    "Access-Control-Expose-Headers": "X-CloudFS-Request-ID, X-CloudFS-API-Version, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining",
    Vary: "Origin",
  };
}

/// Handle a CORS preflight (OPTIONS). Returns a 204 with the CORS headers when the
/// origin is allowed, or null when this isn't a preflight to handle here.
export function handleCorsPreflight(req: Request, env: CorsEnv): Response | null {
  if (req.method !== "OPTIONS") return null;
  const headers = corsHeadersFor(req, env);
  // A preflight with no allow-listed origin still returns 204 (no CORS headers), so the
  // browser simply blocks the follow-up — never an error page.
  return new Response(null, { status: 204, headers });
}

/// Copy the CORS headers onto an existing response (mutates a clone's headers). Applied
/// to every response so a cross-origin XHR can read the body + Set-Cookie works.
export function withCors(res: Response, req: Request, env: CorsEnv): Response {
  const cors = corsHeadersFor(req, env);
  if (Object.keys(cors).length === 0) return res;
  const headers = new Headers(res.headers);
  for (const [k, v] of Object.entries(cors)) headers.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}
