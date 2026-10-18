// SPDX-License-Identifier: AGPL-3.0-or-later
// setup.ts — the first-run SETUP WIZARD surface (auth-spec §2.5, §4.4): the human path from a
// fresh deploy to a signed-in admin, replacing the curl-against-/v1/bootstrap dead end.
//
//   GET  /v1/setup/status — public: { needed: true|false }. `needed` is the DirectoryDO
//        setup flag (set by /v1/setup/init AND by a successful legacy /v1/bootstrap), NOT
//        "directory empty". Nothing else is leaked (no org names/counts).
//   POST /v1/setup/init   — public, gated by the deploy BOOTSTRAP_SECRET (same fail-closed
//        posture as /v1/bootstrap: constant-time compare; route disabled when the secret is
//        unset/<16 chars). Creates org + owner + REAL password credential, signs the operator
//        in via the normal browser-session cookie, marks the setup flag (self-disable).
//
// Lives in its own module — NOT in index.ts — because the Worker entry module must never gain a
// non-handler named export (workerd treats entry exports as handlers/DO classes and refuses to
// boot; vitest stays green, deploy breaks). index.ts only routes here.

import type { Env } from "./env";
import { DIRECTORY_DO_NAME } from "./directory-do";
import { authStoresFor } from "./auth-stores";
import {
  hashPassword,
  scryptCostFromEnv,
  PasswordError,
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
} from "./security/auth-password";
import { canonicalEmail, scopesForLogin } from "./security/auth-signup";
import { createBrowserSession, sessionLoginResponse } from "./security/auth-session";
import { qualifyCookie, secureCookies } from "./auth-wiring";

export class SetupError extends Error {
  constructor(readonly code: string, readonly status = 409) { super(code); }
}

/** Shared by browser setup and the legacy API. DirectoryDO serializes the claim across
 *  isolates; the two account authorities resume idempotently after a partial failure. */
export async function provisionFirstOwner(env: Env, input: { orgId: string; email: string; displayName: string; orgName?: string; password?: string }) {
  if (!env.AUTH_SIGNING_SECRET || env.AUTH_SIGNING_SECRET.length < 16) throw new SetupError("auth_signing_secret_unconfigured", 503);
  const directory = directoryStub(env);
  const token = crypto.randomUUID();
  const claim = await directory.acquireSetup(input.orgId, input.email, token);
  if (claim.status !== "acquired") throw new SetupError(claim.status);
  try {
    const existingEmail = await directory.resolve(input.email);
    if (existingEmail && existingEmail.orgId !== input.orgId) {
      await directory.releaseSetup(token, !claim.resumed);
      throw new SetupError("email_taken");
    }
    const org = env.ORG_DO.get(env.ORG_DO.idFromName(input.orgId));
    const admin = await org.provisionSetupOwner({ ...input, resumed: claim.resumed });
    if (!admin) {
      await directory.releaseSetup(token, !claim.resumed);
      throw new SetupError("already_bootstrapped");
    }
    const stores = authStoresFor(env, input.orgId);
    let account = null;
    if (input.password !== undefined) {
      const auth = env.AUTH_DO.get(env.AUTH_DO.idFromName(input.orgId));
      account = await auth.provisionSetupAccount({ ...input, userId: admin.id });
      if (!account) throw new SetupError("bootstrap_credential_failed");
      await directory.claim(input.email, input.orgId, account.id);
      // A retry never replaces an already-created password.
      if (!(await stores.credentials.getPassword(account.id))) {
        const credential = await hashPassword(account.id, input.password, { cost: scryptCostFromEnv(env) });
        await auth.provisionSetupPassword(credential);
      }
    }
    if (input.orgName) await org.setOrgName(input.orgName);
    // Durable closure is required before returning credentials or a browser session.
    await markDeploymentSetupComplete(env);
    return { admin, account, stores };
  } finally {
    await directory.releaseSetup(token);
  }
}

function json(data: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json", ...(extraHeaders ?? {}) },
  });
}

function directoryStub(env: Env) {
  return env.DIRECTORY_DO.get(env.DIRECTORY_DO.idFromName(DIRECTORY_DO_NAME));
}

// ---- constant-time secret compare (double-HMAC, length-blind) --------------
// Mirror of the bootstrap gate's compare in index.ts (which cannot export it — entry-module
// rule above). HMAC both strings under a fresh random key, compare fixed-length digests.
async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw", crypto.getRandomValues(new Uint8Array(32)),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const te = new TextEncoder();
  const ha = new Uint8Array(await crypto.subtle.sign("HMAC", key, te.encode(a)));
  const hb = new Uint8Array(await crypto.subtle.sign("HMAC", key, te.encode(b)));
  let diff = 0;
  for (let i = 0; i < ha.length; i++) diff |= ha[i] ^ hb[i];
  return diff === 0;
}

// ---- per-isolate status cache (auth-spec §2.5: mirror publicAuthConfigCache) ----------------
// The status is read by every SPA boot, so don't let it hammer the global DirectoryDO singleton.
// 10s staleness is invisible; a completed init/bootstrap UPDATES the cache in place so the
// wizard self-disables immediately on this isolate (not after the TTL).
const SETUP_STATUS_TTL_MS = 10_000;
let setupStatusCache: { needed: boolean; expiresAt: number } | null = null;

/// Test-only: drop the per-isolate status cache (isolated-storage tests reset the durable flag
/// between cases; the module cache must not leak a stale answer across them).
export function __resetSetupStatusCacheForTest(): void {
  setupStatusCache = null;
}

/// Mark the deployment set-up (durable flag + cache). Called by /v1/setup/init AND by the legacy
/// /v1/bootstrap success path so the wizard self-disables either way.
export async function markDeploymentSetupComplete(env: Env): Promise<void> {
  await directoryStub(env).markSetupComplete();
  setupStatusCache = { needed: false, expiresAt: Date.now() + SETUP_STATUS_TTL_MS };
}

// ---- GET /v1/setup/status -------------------------------------------------------------------

export async function handleSetupStatus(req: Request, env: Env): Promise<Response> {
  if (req.method !== "GET") return json({ error: "method not allowed" }, 405);
  const nowMs = Date.now();
  if (!setupStatusCache || nowMs >= setupStatusCache.expiresAt) {
    const complete = await directoryStub(env).getSetupComplete();
    setupStatusCache = { needed: !complete, expiresAt: nowMs + SETUP_STATUS_TTL_MS };
  }
  // Nothing but the boolean — no org names, counts, or config (auth-spec §2.5).
  return json({ needed: setupStatusCache.needed });
}

// ---- POST /v1/setup/init --------------------------------------------------------------------

/// Org ids are embedded in org-qualified opaque handles ("<orgId>.<handle>") and DO names, so:
/// lowercase slug, 1–63 chars, no dots (the dot is the handle separator), no leading hyphen.
const ORG_ID_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

interface SetupInitBody {
  secret?: unknown;
  orgId?: unknown;
  orgName?: unknown;
  email?: unknown;
  displayName?: unknown;
  password?: unknown;
}

export async function handleSetupInit(req: Request, env: Env): Promise<Response> {
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  // Fail closed when the deployment has no (or a weak) bootstrap secret — same posture as
  // /v1/bootstrap. The SPA renders the "configure BOOTSTRAP_SECRET and reload" screen on this.
  const configured = env.BOOTSTRAP_SECRET;
  if (!configured || configured.length < 16) {
    return json({ error: "setup_disabled" }, 404);
  }

  let body: SetupInitBody;
  try {
    body = (await req.json()) as SetupInitBody;
  } catch {
    return json({ error: "invalid_body" }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return json({ error: "invalid_body" }, 400);

  // Constant-time secret gate FIRST (before any state reads leak timing/shape).
  if (typeof body.secret !== "string" || !(await timingSafeEqual(body.secret, configured))) {
    return json({ error: "unauthorized" }, 401);
  }

  // Self-disable: once ANY setup completed, the wizard refuses (the secret no longer opens it).
  if (await directoryStub(env).getSetupComplete()) {
    return json({ error: "setup_complete" }, 409);
  }

  // ---- validate the whole body BEFORE provisioning anything (clean retry on any 400) ----
  const orgId = typeof body.orgId === "string" ? body.orgId.trim() : "";
  const orgName = typeof body.orgName === "string" ? body.orgName.trim() : "";
  const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
  const email = typeof body.email === "string" ? canonicalEmail(body.email) : "";
  if (!ORG_ID_RE.test(orgId)) {
    return json({ error: "invalid_body", reason: "orgId must be a short lowercase slug (a-z, 0-9, hyphens; no dots)" }, 400);
  }
  if (!orgName || orgName.length > 100) {
    return json({ error: "invalid_body", reason: "orgName is required (at most 100 chars)" }, 400);
  }
  if (!displayName || displayName.length > 100) {
    return json({ error: "invalid_body", reason: "displayName is required (at most 100 chars)" }, 400);
  }
  if (!email || email.length > 254 || !/^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(email)) {
    return json({ error: "invalid_body", reason: "a valid email is required" }, 400);
  }
  if (typeof body.password !== "string" || body.password.length < MIN_PASSWORD_LENGTH || body.password.length > MAX_PASSWORD_LENGTH) {
    return json({ error: "weak_password", reason: `password must be ${MIN_PASSWORD_LENGTH}–${MAX_PASSWORD_LENGTH} characters` }, 400);
  }

  let provisioned;
  try {
    provisioned = await provisionFirstOwner(env, { orgId, orgName, email, displayName, password: body.password });
  } catch (e) {
    if (e instanceof SetupError) return json({ error: e.code }, e.status);
    if (e instanceof PasswordError) return json({ error: e.code }, e.status ?? 400);
    return json({ error: "bootstrap_credential_failed", detail: String((e as Error)?.message ?? e) }, 409);
  }
  const { admin, account, stores } = provisioned;
  if (!account) return json({ error: "bootstrap_credential_failed" }, 500);

  // ---- sign the operator in: a normal browser session, org-qualified cookie (auth-spec §2.5).
  const session = await createBrowserSession(stores.sessions, {
    accountId: account.id,
    userId: admin.id,
    orgId,
    scopes: scopesForLogin("owner", true),
  });
  const { setCookie, csrf } = sessionLoginResponse(session);

  // ---- self-disable: mark the deployment set-up (also flips the status cache on this isolate).
  return json(
    {
      orgId,
      userId: admin.id,
      csrf,
      account: { email: account.email, displayName: account.displayName, role: account.role },
    },
    201,
    { "set-cookie": qualifyCookie(setCookie, orgId, secureCookies(env, req)) },
  );
}
