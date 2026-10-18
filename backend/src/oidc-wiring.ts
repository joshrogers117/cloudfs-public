// SPDX-License-Identifier: AGPL-3.0-or-later
/// Tiny adapter wiring `security/oidc.ts` to the gateway's Env + OrgDO.
///
/// `oidc.ts` depends on the `OidcConfig` shape and the `UserDirectory` INTERFACE
/// (not the DO) so it stays unit-testable. This file (owned by the route-mounting
/// agent, per oidc-INTEGRATION.md §3/§4) maps the gateway Env into an OidcConfig
/// and forwards the directory methods to existing OrgDO RPC. It edits no other
/// agent's module — it only consumes oidc.ts and org-do.ts exports.

import { discover, OidcError, type OidcConfig, type UserDirectory, type FetchLike } from "./security/oidc";
import type { Env } from "./env";
import { DIRECTORY_DO_NAME } from "./directory-do";
import {
  authConfigStoreFor,
  resolveOidcConfigFromRow,
  toPublicAuthConfig,
  type AuthMode,
  type PublicAuthConfig,
} from "./auth-config";

/// True when the deployment has the minimum OIDC vars set. The gateway uses this
/// to 404 the OIDC routes when SSO isn't configured (fail closed, never 500).
export function oidcConfigured(env: Env): boolean {
  return !!(env.OIDC_ISSUER && env.OIDC_CLIENT_ID && env.OIDC_CLIENT_SECRET && env.OIDC_REDIRECT_URI && env.OIDC_ORG_ID);
}

function directoryStub(env: Env) {
  return env.DIRECTORY_DO.get(env.DIRECTORY_DO.idFromName(DIRECTORY_DO_NAME));
}

/// The deployment redirect URI registered with the IdP: `<PUBLIC_BASE_URL>/v1/auth/oidc/callback`.
/// Falls back to the request origin when PUBLIC_BASE_URL is unset, matching the rest of the gateway.
function oidcRedirectUri(env: Env, req: Request): string {
  const base = (env.PUBLIC_BASE_URL ?? new URL(req.url).origin).replace(/\/+$/, "");
  return `${base}/v1/auth/oidc/callback`;
}

/// The org logins provision into. The runtime config is a deployment singleton (no per-config org),
/// so we keep the env OIDC_ORG_ID model: a fixed org. The FIRST OIDC login bootstraps its owner.
function oidcOrgId(env: Env): string {
  return env.OIDC_ORG_ID ?? "org1";
}

/// Resolve the EFFECTIVE deployment OidcConfig: the RUNTIME (DirectoryDO, encrypted) config FIRST,
/// then the deploy `OIDC_*` env fallback. Returns null when neither is configured (SSO off → the
/// OIDC routes 404). `fetchImpl` is injected for tests (discovery + token/jwks). A runtime row that
/// can't be decrypted/discovered throws (so the caller surfaces a clear OidcError, not a silent
/// fall-through to env that would log the user into a DIFFERENT IdP than the console shows).
export async function resolveOidcConfig(
  env: Env,
  req: Request,
  fetchImpl?: FetchLike,
): Promise<OidcConfig | null> {
  let row;
  try {
    row = await authConfigStoreFor(directoryStub(env)).getAuthConfig();
  } catch {
    row = null;
  }
  if (row && (row.mode === "oidc" || row.mode === "both")) {
    const cfg = await resolveOidcConfigFromRow(row, {
      encKey: env.STORAGE_ENC_KEY,
      redirectUri: oidcRedirectUri(env, req),
      orgId: oidcOrgId(env),
      fetchImpl,
    });
    if (cfg) return cfg;
    // Row says OIDC but isn't usable (no secret/clientId) — fall through to env below.
  }
  // A built-in runtime row DISABLES the env OIDC fallback (the operator explicitly chose built-in).
  if (row && row.mode === "builtin") return null;
  if (oidcConfigured(env)) return oidcConfigFromEnv(env, fetchImpl);
  return null;
}

/// The EFFECTIVE deployment auth mode: the runtime row's mode if set, else inferred from env
/// (OIDC_* present ⇒ "both" so password login still works alongside SSO; absent ⇒ "builtin").
export async function resolveAuthMode(env: Env): Promise<AuthMode> {
  // Audit B11 break-glass: if a runtime SSO config ever wedges the deployment (e.g. the
  // IdP goes away and every session lapses into mode='oidc'), the operator sets
  // AUTH_MODE_FORCE=builtin and redeploys to FORCE password login back on, overriding the
  // stored row. This is the documented recovery path the lockout finding lacked.
  if ((env.AUTH_MODE_FORCE ?? "").trim().toLowerCase() === "builtin") return "builtin";
  let row;
  try {
    row = await authConfigStoreFor(directoryStub(env)).getAuthConfig();
  } catch {
    row = null;
  }
  if (row) return row.mode;
  return oidcConfigured(env) ? "both" : "builtin";
}

/// The unauthenticated public sign-in config the env implies when there is no runtime row. OIDC_*
/// present ⇒ SSO enabled (mode "both", so the password form still shows); absent ⇒ built-in only.
export function envPublicAuthConfig(env: Env): PublicAuthConfig {
  if (oidcConfigured(env)) return { mode: "both", oidcEnabled: true, providerLabel: "Single Sign-On" };
  return { mode: "builtin", oidcEnabled: false };
}

/// The DirectoryDO-backed public-config resolver the sign-in page reads (runtime row first, then the
/// env-implied default). Exported for the gateway + tests. Reuses `toPublicAuthConfig` for the row.
export async function resolvePublicAuthConfig(env: Env): Promise<PublicAuthConfig> {
  let row;
  try {
    row = await authConfigStoreFor(directoryStub(env)).getAuthConfig();
  } catch {
    row = null;
  }
  return row ? toPublicAuthConfig(row) : envPublicAuthConfig(env);
}

function splitDomains(csv?: string): string[] | undefined {
  if (!csv) return undefined;
  const list = csv.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  return list.length ? list : undefined;
}

/// Build the OidcConfig from env. If the authorize/token/jwks endpoints aren't
/// hard-set, run OIDC discovery against the issuer (cheap, cached by the IdP edge).
/// `fetchImpl` is injectable so tests can supply a mock discovery doc.
export async function oidcConfigFromEnv(env: Env, fetchImpl?: FetchLike): Promise<OidcConfig> {
  if (!oidcConfigured(env)) {
    throw new OidcError("OIDC not configured", 500, "oidc_not_configured");
  }
  let authorizationEndpoint = env.OIDC_AUTHORIZATION_ENDPOINT;
  let tokenEndpoint = env.OIDC_TOKEN_ENDPOINT;
  let jwksUri = env.OIDC_JWKS_URI;
  if (!authorizationEndpoint || !tokenEndpoint || !jwksUri) {
    const d = await discover(env.OIDC_ISSUER!, fetchImpl);
    authorizationEndpoint ??= d.authorizationEndpoint;
    tokenEndpoint ??= d.tokenEndpoint;
    jwksUri ??= d.jwksUri;
  }
  return {
    issuer: env.OIDC_ISSUER!,
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri,
    clientId: env.OIDC_CLIENT_ID!,
    clientSecret: env.OIDC_CLIENT_SECRET!,
    redirectUri: env.OIDC_REDIRECT_URI!,
    orgId: env.OIDC_ORG_ID!,
    allowedDomains: splitDomains(env.OIDC_ALLOWED_DOMAINS),
    autoProvision: env.OIDC_AUTO_PROVISION === "true",
  };
}

/// UserDirectory over OrgDO — forwards to RPC that already exist (no OrgDO edits).
export function orgDirectory(env: Env, orgId: string): UserDirectory {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  return {
    getUserByEmail: (email) => stub.getUserByEmail(email) as any,
    createUser: async (input) => {
      await directoryStub(env).registerOrganization(orgId);
      return stub.createUser(input) as any;
    },
    groupsForUser: (userId) => stub.groupsForUser(userId),
  };
}

/// Decide whether `email` (already lowercased + IdP-verified by `mapIdentityToPrincipal`) is allowed
/// to BOOTSTRAP the first-login OWNER of an empty org (FINDING 4+12). The pre-fix code minted the
/// owner for ANY first verified SSO identity — an account-takeover footgun (the first person to
/// complete an SSO round-trip owns the org). Now it's gated by an EXPLICIT allow-list:
///   - `OIDC_BOOTSTRAP_EMAIL` (exact, case-insensitive) — the single email permitted to bootstrap, OR
///   - the email's DOMAIN appears in the configured `allowedDomains`.
/// If NEITHER is configured (no bootstrap email AND empty allowedDomains), bootstrap is REFUSED
/// (fail closed). Used by `bootstrapOrgDirectory`.
function bootstrapOwnerAllowed(email: string, allowedDomains: string[] | undefined, bootstrapEmail?: string): boolean {
  const e = email.trim().toLowerCase();
  const allowEmail = bootstrapEmail?.trim().toLowerCase();
  if (allowEmail && e === allowEmail) return true;
  const at = e.lastIndexOf("@");
  const domain = at >= 0 ? e.slice(at + 1) : "";
  const domains = (allowedDomains ?? []).map((d) => d.trim().toLowerCase()).filter(Boolean);
  return domain.length > 0 && domains.includes(domain);
}

/// A UserDirectory that BOOTSTRAPS the owner on the first OIDC login of an empty org. The trick:
/// `mapIdentityToPrincipal` (security/oidc.ts) is reused UNCHANGED — it looks the verified identity
/// up via `getUserByEmail`, and an EXISTING active user simply logs in (no domain/autoProvision
/// gate). So when the org has no members, we PROVISION the owner right inside `getUserByEmail`
/// (using the already-verified email from the validated id_token) and return it as "existing". The
/// reused flow then mints that owner's session. There is no chicken-and-egg: the very identity that
/// completes the first SSO round-trip becomes the org owner — BUT ONLY IF it passes the explicit
/// bootstrap allow-list (FINDING 4+12: `OIDC_BOOTSTRAP_EMAIL` or `allowedDomains`); a non-allowed
/// email is REFUSED (fail closed) rather than silently made owner. The empty-org check is
/// `countUsers() === 0` re-read at call time (single-threaded OrgDO ⇒ the second concurrent login
/// sees the owner already there and falls through to the normal per-domain policy via `createUser`).
export function bootstrapOrgDirectory(
  env: Env,
  orgId: string,
  allowedDomains: string[] | undefined,
): UserDirectory {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  return {
    getUserByEmail: async (email) => {
      const existing = (await stub.getUserByEmail(email)) as any;
      if (existing) return existing;
      // Empty org ⇒ this verified identity MAY bootstrap the OWNER. (countUsers is the authoritative,
      // single-threaded check; a non-empty org means someone already bootstrapped, so we return null
      // and let the normal allowedDomains/autoProvision gate decide.)
      const count = await stub.countUsers();
      if (count > 0) return null;
      // GATE: only an allow-listed email may become the bootstrap owner (else fail closed).
      if (!bootstrapOwnerAllowed(email, allowedDomains, env.OIDC_BOOTSTRAP_EMAIL)) {
        throw new OidcError(
          `first-login owner bootstrap refused for ${email}: not on the OIDC bootstrap allow-list`,
          403,
          "bootstrap_denied",
        );
      }
      await directoryStub(env).registerOrganization(orgId);
      return (await stub.createUser({
        orgId,
        email,
        displayName: email,
        role: "owner",
      })) as any;
    },
    createUser: async (input) => {
      await directoryStub(env).registerOrganization(orgId);
      return stub.createUser(input) as any;
    },
    groupsForUser: (userId) => stub.groupsForUser(userId),
  };
}

/// Choose the UserDirectory for an OIDC callback: the BOOTSTRAP directory when the target org has no
/// members yet (first login → owner), else the plain per-org directory (normal per-domain policy).
/// The config is returned UNCHANGED in both cases — bootstrap is handled entirely in the directory.
export async function prepareOidcCallback(
  env: Env,
  config: OidcConfig,
): Promise<{ config: OidcConfig; dir: UserDirectory }> {
  let memberCount = 0;
  try {
    memberCount = await env.ORG_DO.get(env.ORG_DO.idFromName(config.orgId)).countUsers();
  } catch {
    memberCount = 0;
  }
  const dir =
    memberCount === 0
      ? bootstrapOrgDirectory(env, config.orgId, config.allowedDomains)
      : orgDirectory(env, config.orgId);
  return { config, dir };
}
