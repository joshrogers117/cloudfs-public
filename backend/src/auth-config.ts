// SPDX-License-Identifier: AGPL-3.0-or-later
// auth-config.ts — the PLUGGABLE, deployment-level, UI-managed auth-provider configuration.
//
// WHY: until now the auth provider was fixed at deploy time — the built-in password/2FA/passkey
// lanes, OR an external OIDC IdP wired ONLY via `OIDC_*` env + a `wrangler secret put` redeploy.
// This module lets an owner/admin switch the deployment between the built-in provider and an
// external OIDC IdP (Clerk / Okta / Entra / Auth0 / Google / generic) from the web admin console,
// with NO redeploy. The config is a DEPLOYMENT SINGLETON (one row on the global DirectoryDO), not
// per-org: the sign-in page must resolve it BEFORE any org is known.
//
// It REUSES the existing OIDC flow wholesale (security/oidc.ts handleOidcStart / handleOidcCallback
// / validateIdToken / discover) — this module only supplies the runtime, encrypted OidcConfig the
// flow consumes. For a known preset the operator supplies only `issuer` + `clientId` (+ secret);
// the authorize/token/jwks endpoints are DERIVED from the issuer's `.well-known/openid-configuration`
// via discover(), so they are never stored.
//
// ENCRYPTION: the OAuth client secret is sealed with AES-256-GCM (security/storage-crypto.ts — the
// SAME envelope + `STORAGE_ENC_KEY` as managed storage creds / per-org email config) and stored on
// the DirectoryDO; preset/issuer/clientId/allowedDomains/autoProvision are plaintext for display.
// The secret is NEVER returned by any API after it's saved — it is decrypted ONLY server-side at
// token-exchange time.
//
// RESOLUTION ORDER (oidc-wiring.ts `resolveOidcConfig`): the RUNTIME config is resolved FIRST
// (decrypt → discover → OidcConfig); if there is no row we fall back to the deploy `OIDC_*` env
// (`oidcConfigFromEnv`). So a saved config OVERRIDES the deploy env.

import type { AuthConfigRow, DirectoryDO } from "./directory-do";
import type { OidcConfig, FetchLike } from "./security/oidc";
import { discover } from "./security/oidc";
import { sealSecret, openSecret } from "./security/storage-crypto";

// ---------------------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------------------

/// The known OIDC presets. All are standards-compliant OIDC (Authorization-Code + discovery), so a
/// preset is really just a default human LABEL for the SSO button — the actual endpoints always
/// come from the issuer's discovery doc. `generic` is the escape hatch for any conformant IdP.
export type OidcPreset = "clerk" | "okta" | "entra" | "auth0" | "google" | "generic";

const PRESETS = new Set<OidcPreset>(["clerk", "okta", "entra", "auth0", "google", "generic"]);

/// The auth mode: built-in lanes only, external OIDC only, or both (password OR SSO).
export type AuthMode = "builtin" | "oidc" | "both";
const MODES = new Set<AuthMode>(["builtin", "oidc", "both"]);

/// Default human-facing SSO-button label per preset. The operator may override it (not yet exposed
/// in the PUT body; reserved), but this is the sensible default the sign-in page shows.
const PRESET_LABEL: Record<OidcPreset, string> = {
  clerk: "Clerk",
  okta: "Okta",
  entra: "Microsoft Entra ID",
  auth0: "Auth0",
  google: "Google",
  generic: "Single Sign-On",
};

export function parsePreset(v: unknown): OidcPreset | null {
  return typeof v === "string" && PRESETS.has(v as OidcPreset) ? (v as OidcPreset) : null;
}
export function parseMode(v: unknown): AuthMode | null {
  return typeof v === "string" && MODES.has(v as AuthMode) ? (v as AuthMode) : null;
}

// ---------------------------------------------------------------------------------------
// FROZEN public shapes (the web agent builds against these). The client secret is NEVER part of
// any of them.
// ---------------------------------------------------------------------------------------

/// The owner/admin-facing config. `configured: true` is implied by a present `oidc` block.
export interface AuthConfig {
  mode: AuthMode;
  oidc?: {
    preset: OidcPreset;
    issuer: string;
    clientId: string;
    allowedDomains: string[];
    autoProvision: boolean;
    configured: true;
  };
}

/// The UNAUTHENTICATED sign-in-page shape. Lets the page decide whether to show the password form
/// (`mode !== 'oidc'`) and/or the SSO button (`oidcEnabled`) + its label.
export interface PublicAuthConfig {
  mode: AuthMode;
  oidcEnabled: boolean;
  providerLabel?: string;
}

function parseDomains(json: string | null): string[] {
  if (!json) return [];
  try {
    const arr = JSON.parse(json);
    return Array.isArray(arr) ? arr.filter((d) => typeof d === "string") : [];
  } catch {
    return [];
  }
}

/// Whether a stored row actually carries a usable OIDC config (issuer + clientId present).
function rowHasOidc(row: AuthConfigRow): boolean {
  return (row.mode === "oidc" || row.mode === "both") && !!row.issuer && !!row.clientId;
}

/// Project a stored row to the owner/admin-facing `AuthConfig`. Drops every secret/iv/ciphertext
/// field. A `builtin` row (or an oidc/both row missing issuer/clientId) projects to just `{ mode }`.
export function toAuthConfig(row: AuthConfigRow): AuthConfig {
  if (!rowHasOidc(row)) return { mode: row.mode };
  return {
    mode: row.mode,
    oidc: {
      preset: (parsePreset(row.preset) ?? "generic"),
      issuer: row.issuer!,
      clientId: row.clientId!,
      allowedDomains: parseDomains(row.allowedDomains),
      autoProvision: row.autoProvision,
      configured: true,
    },
  };
}

/// Project a stored row to the unauthenticated sign-in shape.
export function toPublicAuthConfig(row: AuthConfigRow): PublicAuthConfig {
  const oidcEnabled = rowHasOidc(row);
  const out: PublicAuthConfig = { mode: row.mode, oidcEnabled };
  if (oidcEnabled) {
    out.providerLabel = row.providerLabel ?? PRESET_LABEL[parsePreset(row.preset) ?? "generic"];
  }
  return out;
}

// ---------------------------------------------------------------------------------------
// The DirectoryDO slice this module needs (decoupled + testable with an in-memory fake).
// ---------------------------------------------------------------------------------------

export interface AuthConfigStore {
  getAuthConfig(): Promise<AuthConfigRow | null>;
  putAuthConfig(input: {
    mode: AuthMode;
    preset: string | null;
    issuer: string | null;
    clientId: string | null;
    allowedDomains: string | null;
    autoProvision: boolean;
    providerLabel: string | null;
    secretIv: string;
    secretCiphertext: string;
  }): Promise<AuthConfigRow>;
  deleteAuthConfig(): Promise<boolean>;
}

/// Adapt the DirectoryDO stub to the `AuthConfigStore` slice (its RPC already matches).
export function authConfigStoreFor(stub: DurableObjectStub<DirectoryDO>): AuthConfigStore {
  return {
    getAuthConfig: () => stub.getAuthConfig(),
    putAuthConfig: (input) => stub.putAuthConfig(input),
    deleteAuthConfig: () => stub.deleteAuthConfig(),
  };
}

// ---------------------------------------------------------------------------------------
// Runtime OidcConfig resolution — decrypt the stored row + discover the endpoints into the
// OidcConfig the existing security/oidc.ts flow consumes.
// ---------------------------------------------------------------------------------------

export interface ResolveOidcDeps {
  /// AES-256-GCM key for the sealed client secret (STORAGE_ENC_KEY).
  encKey: string | undefined;
  /// `<PUBLIC_BASE_URL>/v1/auth/oidc/callback` — the exact redirect URI registered with the IdP.
  redirectUri: string;
  /// The org logins provision into. Until the org has members, the FIRST OIDC login bootstraps the
  /// owner (auth-wiring), so this is fixed deployment-wide (matches the env OIDC_ORG_ID model).
  orgId: string;
  /// Injected for tests; defaults to global fetch (used by discovery).
  fetchImpl?: FetchLike;
}

/// Build the runtime `OidcConfig` from a stored row: decrypt the client secret, then DISCOVER the
/// authorize/token/jwks endpoints from the issuer (so the operator only supplies issuer+clientId).
/// Returns null when the row doesn't carry a usable OIDC config (mode=builtin, or missing issuer/
/// clientId) so the caller can fall back to the env. Throws on a decryption / discovery failure so
/// the caller surfaces a clear error rather than silently logging the user in with no IdP.
export async function resolveOidcConfigFromRow(
  row: AuthConfigRow,
  deps: ResolveOidcDeps,
): Promise<OidcConfig | null> {
  if (!rowHasOidc(row)) return null;
  if (!row.secretCiphertext) return null; // no secret sealed ⇒ unusable (treat as not configured)
  const clientSecret = await openSecret(deps.encKey, { iv: row.secretIv, ciphertext: row.secretCiphertext });
  const d = await discover(row.issuer!, deps.fetchImpl);
  return {
    issuer: d.issuer,
    authorizationEndpoint: d.authorizationEndpoint,
    tokenEndpoint: d.tokenEndpoint,
    jwksUri: d.jwksUri,
    clientId: row.clientId!,
    clientSecret,
    redirectUri: deps.redirectUri,
    orgId: deps.orgId,
    allowedDomains: parseDomains(row.allowedDomains),
    autoProvision: row.autoProvision,
  };
}

// ---------------------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------------------

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function shortErr(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  return msg.slice(0, 200);
}

export interface AuthConfigDeps {
  store: AuthConfigStore;
  /// AES-256-GCM key (STORAGE_ENC_KEY) for sealing the client secret. Required for an oidc/both PUT
  /// that carries a new secret.
  encKey: string | undefined;
  /// Injected discovery fetch for the /validate route (and any future server-side discovery). Tests
  /// supply a mock so no network is touched.
  fetchImpl?: FetchLike;
}

// ---- GET /v1/auth/config/public (UNAUTHENTICATED) -------------------------------------

/// The unauthenticated public config the sign-in page reads. Built-in default when no row exists.
/// Never throws — a store error falls back to the built-in default (the password form still shows).
export async function handlePublicAuthConfig(
  store: AuthConfigStore,
  envFallback: PublicAuthConfig | null,
): Promise<Response> {
  let row: AuthConfigRow | null = null;
  try {
    row = await store.getAuthConfig();
  } catch {
    row = null;
  }
  if (row) return json(toPublicAuthConfig(row));
  // No runtime row → reflect the deploy env (OIDC_* present ⇒ SSO available) or the built-in default.
  return json(envFallback ?? { mode: "builtin", oidcEnabled: false });
}

// ---- /v1/orgs/:org/auth-config (owner/admin) ------------------------------------------

interface PutBody {
  mode?: unknown;
  oidc?: {
    preset?: unknown;
    issuer?: unknown;
    clientId?: unknown;
    clientSecret?: unknown;
    allowedDomains?: unknown;
    autoProvision?: unknown;
    providerLabel?: unknown;
  };
}

function normalizeDomains(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v
    .filter((d): d is string => typeof d === "string")
    .map((d) => d.trim().toLowerCase().replace(/^@/, ""))
    .filter(Boolean);
}

/// Validate + normalize the PUT body. `existing` lets us RETAIN a previously-sealed secret on a
/// same-config edit that omits `clientSecret`. Returns an error string (for a 400) instead of
/// throwing.
function validatePut(
  b: PutBody,
  existing: AuthConfigRow | null,
):
  | { ok: true; mode: AuthMode; oidc: null }
  | {
      ok: true;
      mode: AuthMode;
      oidc: {
        preset: OidcPreset;
        issuer: string;
        clientId: string;
        clientSecret: string | null; // null ⇒ retain the existing sealed secret
        allowedDomains: string[];
        autoProvision: boolean;
        providerLabel: string | null;
      };
    }
  | { ok: false; error: string } {
  const mode = parseMode(b.mode);
  if (!mode) return { ok: false, error: "mode must be one of builtin|oidc|both" };

  if (mode === "builtin") {
    return { ok: true, mode, oidc: null };
  }

  // oidc / both require an OIDC block.
  const o = b.oidc ?? {};
  const preset = parsePreset(o.preset);
  if (!preset) return { ok: false, error: "oidc.preset must be one of clerk|okta|entra|auth0|google|generic" };
  const issuer = typeof o.issuer === "string" ? o.issuer.trim().replace(/\/+$/, "") : "";
  if (!issuer || !/^https:\/\//.test(issuer)) return { ok: false, error: "oidc.issuer must be an https URL" };
  const clientId = typeof o.clientId === "string" ? o.clientId.trim() : "";
  if (!clientId) return { ok: false, error: "oidc.clientId is required" };

  // Secret: retain the existing sealed one when this is a same-issuer/same-client edit that omits it.
  const secretInBody = typeof o.clientSecret === "string" && o.clientSecret ? o.clientSecret : null;
  const canReuse =
    !!existing && (existing.mode === "oidc" || existing.mode === "both") &&
    existing.issuer === issuer && existing.clientId === clientId && !!existing.secretCiphertext;
  if (!secretInBody && !canReuse) {
    return { ok: false, error: "oidc.clientSecret is required" };
  }

  const providerLabel = typeof o.providerLabel === "string" && o.providerLabel.trim()
    ? o.providerLabel.trim().slice(0, 80)
    : null;

  return {
    ok: true,
    mode,
    oidc: {
      preset,
      issuer,
      clientId,
      clientSecret: secretInBody,
      allowedDomains: normalizeDomains(o.allowedDomains),
      autoProvision: o.autoProvision === true,
      providerLabel,
    },
  };
}

/// Handle the owner/admin auth-config routes under `/v1/orgs/:org`. `rest` is the path AFTER
/// /v1/orgs/:org (e.g. ["auth-config"] or ["auth-config","validate"]). Returns null if not ours.
/// The caller has already authenticated the principal; we enforce the owner/admin role here.
export async function handleAuthConfigRequest(
  req: Request,
  rest: string[],
  isAdmin: boolean,
  deps: AuthConfigDeps,
): Promise<Response | null> {
  if (rest[0] !== "auth-config") return null;
  if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);

  // ---- /v1/orgs/:org/auth-config/validate ----
  if (rest[1] === "validate") {
    if (req.method !== "POST") return json({ error: "method not allowed" }, 405);
    return await handleValidate(req, deps);
  }
  if (rest[1]) return json({ error: "not found" }, 404);

  // ---- /v1/orgs/:org/auth-config ----
  try {
    if (req.method === "GET") {
      const row = await deps.store.getAuthConfig();
      return json({ config: row ? toAuthConfig(row) : null });
    }
    if (req.method === "PUT") {
      return await handlePut(req, deps);
    }
    if (req.method === "DELETE") {
      await deps.store.deleteAuthConfig();
      return new Response(null, { status: 204 });
    }
    return json({ error: "method not allowed" }, 405);
  } catch (e) {
    return json({ error: shortErr(e) }, 500);
  }
}

async function handlePut(req: Request, deps: AuthConfigDeps): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as PutBody;
  const existing = await deps.store.getAuthConfig();
  const v = validatePut(b, existing);
  if (!v.ok) return json({ error: v.error }, 400);

  if (v.oidc === null) {
    // built-in mode — no OIDC fields, no secret.
    const saved = await deps.store.putAuthConfig({
      mode: v.mode,
      preset: null,
      issuer: null,
      clientId: null,
      allowedDomains: null,
      autoProvision: false,
      providerLabel: null,
      secretIv: "",
      secretCiphertext: "",
    });
    return json(toAuthConfig(saved), 200);
  }

  // Audit B11 (SSO lockout): a typo'd / unreachable issuer used to be persisted with
  // mode='oidc' taking effect IMMEDIATELY — once the admin's session lapsed, EVERY user
  // including the admin was locked out with no documented recovery. Run discovery FIRST
  // and REJECT an unreachable issuer (400) so a broken SSO config can never be saved as
  // the live auth mode. (The break-glass AUTH_MODE_FORCE=builtin env override, honored by
  // the resolver, is the recovery path if a deployment ever does get wedged.)
  try {
    await discover(v.oidc.issuer, deps.fetchImpl);
  } catch (e) {
    return json({
      error: "oidc_issuer_unreachable",
      detail: `OIDC discovery failed for ${v.oidc.issuer} — config NOT saved (would lock out every user). ${shortErr(e)}`,
    }, 400);
  }

  // Seal the client secret BEFORE it touches the DO. Retain the prior envelope on a same-config edit
  // that omitted the secret.
  let secretIv = "";
  let secretCiphertext = "";
  if (v.oidc.clientSecret) {
    try {
      const sealed = await sealSecret(deps.encKey, v.oidc.clientSecret);
      secretIv = sealed.iv;
      secretCiphertext = sealed.ciphertext;
    } catch (e) {
      return json({ error: "storage_enc_key_unconfigured", detail: shortErr(e) }, 500);
    }
  } else if (existing && existing.secretCiphertext) {
    secretIv = existing.secretIv;
    secretCiphertext = existing.secretCiphertext;
  }

  const saved = await deps.store.putAuthConfig({
    mode: v.mode,
    preset: v.oidc.preset,
    issuer: v.oidc.issuer,
    clientId: v.oidc.clientId,
    allowedDomains: JSON.stringify(v.oidc.allowedDomains),
    autoProvision: v.oidc.autoProvision,
    providerLabel: v.oidc.providerLabel ?? PRESET_LABEL[v.oidc.preset],
    secretIv,
    secretCiphertext,
  });
  return json(toAuthConfig(saved), 200);
}

/// POST /v1/orgs/:org/auth-config/validate — fetch the issuer's discovery doc and report whether it
/// yields the OIDC endpoints. Never throws — a discovery failure maps to `{ valid:false, error }`.
async function handleValidate(req: Request, deps: AuthConfigDeps): Promise<Response> {
  let b: { issuer?: unknown };
  try {
    b = (await req.json()) as typeof b;
  } catch {
    return json({ valid: false, error: "invalid_body" }, 200);
  }
  const issuer = typeof b.issuer === "string" ? b.issuer.trim().replace(/\/+$/, "") : "";
  if (!issuer || !/^https:\/\//.test(issuer)) {
    return json({ valid: false, error: "issuer must be an https URL" }, 200);
  }
  try {
    const d = await discover(issuer, deps.fetchImpl);
    return json({
      valid: true,
      endpoints: {
        issuer: d.issuer,
        authorizationEndpoint: d.authorizationEndpoint,
        tokenEndpoint: d.tokenEndpoint,
        jwksUri: d.jwksUri,
      },
    }, 200);
  } catch (e) {
    return json({ valid: false, error: shortErr(e) }, 200);
  }
}
