// SPDX-License-Identifier: AGPL-3.0-or-later
// auth-stores.ts — the REAL DO-backed adapters the auth module lanes depend on.
//
// The lanes (auth-password/session/totp/webauthn/email/service-tokens/signup) are written
// against the abstract store INTERFACES in CONTRACTS-AUTH.md §2 and are unit-tested with
// in-memory fakes. THIS file provides the production adapters that satisfy those same
// interfaces by forwarding to `AuthDO(orgId)` and `DirectoryDO("global")` RPC.
//
// Design:
//   - One adapter set is bound to a single `orgId` (the AuthDO instance). The directory
//     adapter is global. `authStoresFor(env, orgId)` builds the whole bundle.
//   - `AccountStore.resolveEmail` + `createAccount`'s directory claim + `releaseEmail` are the
//     only methods that touch DirectoryDO; everything else is AuthDO(orgId) (CONTRACTS-AUTH.md
//     §1.7 — the directory is off the hot path).
//   - The two `revoked*Jtis()` interface methods return `Set<string>`. DO RPC can't return a
//     Set cleanly, so the DO returns an array and the adapter wraps it in a Set here.

import type { Scope } from "./security/auth";
import type { AuthDO } from "./auth-do";
import type { OrgDO } from "./org-do";
import type { DirectoryDO } from "./directory-do";
import { DIRECTORY_DO_NAME } from "./directory-do";
import type { OrgProvisioner } from "./security/auth-signup";
import type {
  Account,
  AccountRole,
  AccountStatus,
  PasswordCredential,
  TotpCredential,
  WebAuthnCredential,
  BrowserSession,
  ServiceToken,
  EmailTokenRecord,
  EmailTokenPurpose,
  ChallengeRecord,
} from "./security/auth-types";

import type {
  EmailSender,
  EmailEnv,
} from "./security/auth-email";
import {
  cloudflareEmailSender,
  resendEmailSender,
  postmarkEmailSender,
  sesEmailSender,
  ConsoleEmailSender,
  FakeEmailSender,
} from "./security/auth-email";
import type { RateLimitStore, BucketState, RateLimitConfig, RateLimitResult } from "./security/ratelimit";
import type { Env } from "./env";
import { describeRuntimeEmailProvider, runtimeEmailSenderFor } from "./email-config";

// Re-export the lane store interfaces this module implements, for clarity at call sites.
import type { PasswordStore } from "./security/auth-password";
import type { SessionStore } from "./security/auth-session";
import type { TotpCredentialStore } from "./security/auth-totp";
import type { WebAuthnCredentialStore } from "./security/auth-webauthn";
import type { EmailTokenStore } from "./security/auth-email";
import type { ServiceTokenStore } from "./security/auth-service-tokens";
import type {
  DeviceStore,
  DeviceCodeRecord,
  DeviceSessionRecord,
} from "./security/auth-device";

type AuthStub = DurableObjectStub<AuthDO>;
type DirectoryStub = DurableObjectStub<DirectoryDO>;

/// Minimal env the adapters bind against (structural subset, mirroring auth.ts's AuthEnv
/// decoupling). The integration layer passes the real Env.
export interface AuthStoresEnv {
  AUTH_DO: DurableObjectNamespace<AuthDO>;
  DIRECTORY_DO: DurableObjectNamespace<DirectoryDO>;
  ORG_DO: DurableObjectNamespace<OrgDO>;
}

function authStub(env: AuthStoresEnv, orgId: string): AuthStub {
  return env.AUTH_DO.get(env.AUTH_DO.idFromName(orgId));
}

function directoryStub(env: AuthStoresEnv): DirectoryStub {
  return env.DIRECTORY_DO.get(env.DIRECTORY_DO.idFromName(DIRECTORY_DO_NAME));
}

// ---------------------------------------------------------------------------------------
// AccountStore (CONTRACTS-AUTH.md §2) — accounts in AuthDO(orgId) + the global directory.
// ---------------------------------------------------------------------------------------

export class DoAccountStore {
  constructor(
    private readonly env: AuthStoresEnv,
    private readonly orgId: string,
  ) {}

  private stub(): AuthStub {
    return authStub(this.env, this.orgId);
  }

  /// Directory resolution — touches DirectoryDO("global") only. Returns {orgId, accountId}.
  resolveEmail(emailLower: string): Promise<{ orgId: string; accountId: string } | null> {
    return directoryStub(this.env).resolve(emailLower) as Promise<
      { orgId: string; accountId: string } | null
    >;
  }

  /// Create the credential-bearing account. CLAIMS the email globally FIRST (authoritative
  /// dedupe — throws `email_taken` on collision in ANY org), then writes the account row. If
  /// the account write somehow fails after a successful claim, we release the claim so a retry
  /// isn't permanently blocked.
  async createAccount(input: {
    orgId: string;
    userId: string;
    email: string;
    displayName: string;
    role: AccountRole;
    emailVerified?: boolean;
  }): Promise<Account> {
    const email = input.email.trim().toLowerCase();
    const acc = await this.stub().createAccount(input);
    // Claim AFTER the local row exists so the directory points at a real accountId; the local
    // unique-email index already prevents an intra-org dupe, and DirectoryDO.claim is the
    // cross-org authority. claim() is idempotent for the same (org, account).
    try {
      await directoryStub(this.env).claim(email, input.orgId, acc.id);
    } catch (err) {
      // Lost the global race: another org (or a concurrent signup) owns this email. Roll back
      // the just-written local account so it doesn't dangle without a directory entry.
      await this.stub().setStatus(acc.id, "deprovisioned").catch(() => {});
      throw err;
    }
    return acc;
  }

  getAccount(accountId: string): Promise<Account | null> {
    return this.stub().getAccount(accountId) as Promise<Account | null>;
  }

  getAccountByEmail(emailLower: string): Promise<Account | null> {
    return this.stub().getAccountByEmail(emailLower) as Promise<Account | null>;
  }

  getAccountByUserId(userId: string): Promise<Account | null> {
    return this.stub().getAccountByUserId(userId) as Promise<Account | null>;
  }

  setEmailVerified(accountId: string, verified: boolean): Promise<void> {
    return this.stub().setEmailVerified(accountId, verified);
  }

  /// Self-service profile update (displayName/email) on the AuthDO account row. Changing the email
  /// resets emailVerified to false in the DO; the gateway re-claims the global directory entry
  /// separately (see `reclaimEmail`). Throws `email_taken` on an intra-org collision. Returns the
  /// updated account, or null if unknown.
  setAccountProfile(
    accountId: string,
    patch: { displayName?: string; email?: string },
  ): Promise<Account | null> {
    return this.stub().setAccountProfile(accountId, patch) as Promise<Account | null>;
  }

  /// Atomically re-point this account's email in the GLOBAL directory: claim the new address and
  /// release the old. Returns "taken" (no change) if the new address is owned by another account,
  /// else "ok". Touches DirectoryDO("global") only.
  reclaimEmail(
    oldEmailLower: string,
    newEmailLower: string,
    orgId: string,
    accountId: string,
  ): Promise<"ok" | "taken"> {
    return directoryStub(this.env).reclaim(oldEmailLower, newEmailLower, orgId, accountId) as Promise<"ok" | "taken">;
  }

  setStatus(accountId: string, status: AccountStatus): Promise<void> {
    return this.stub().setStatus(accountId, status);
  }

  setRole(accountId: string, role: AccountRole): Promise<void> {
    return this.stub().setRole(accountId, role);
  }

  releaseEmail(emailLower: string): Promise<void> {
    return directoryStub(this.env).release(emailLower);
  }
}

// ---------------------------------------------------------------------------------------
// CredentialStore (passwords + TOTP + WebAuthn + recovery + challenges). One class satisfies
// every lane's narrowed credential interface (PasswordStore, TotpCredentialStore,
// WebAuthnCredentialStore) by structural typing.
// ---------------------------------------------------------------------------------------

export class DoCredentialStore
  implements PasswordStore, TotpCredentialStore, WebAuthnCredentialStore
{
  constructor(
    private readonly env: AuthStoresEnv,
    private readonly orgId: string,
  ) {}

  private stub(): AuthStub {
    return authStub(this.env, this.orgId);
  }

  // password
  putPasswordAtEpoch(cred: PasswordCredential, authEpoch: number): Promise<void> {
    return this.stub().putPasswordAtEpoch(cred, authEpoch);
  }
  getPassword(accountId: string): Promise<PasswordCredential | null> {
    return this.stub().getPassword(accountId) as Promise<PasswordCredential | null>;
  }
  putPassword(cred: PasswordCredential): Promise<void> {
    return this.stub().putPassword(cred);
  }
  deletePassword(accountId: string): Promise<void> {
    return this.stub().deletePassword(accountId);
  }

  // totp
  beginTotpEnrollment(cred: TotpCredential): Promise<boolean> {
    return this.stub().beginTotpEnrollment(cred);
  }
  completeTotpEnrollment(accountId: string, secret: string, confirmedAt: number, step: number,
      expiresAt: number, recoveryHashes: string[]): Promise<boolean> {
    return this.stub().completeTotpEnrollment(accountId, secret, confirmedAt, step, expiresAt, recoveryHashes);
  }
  claimTotpStep(accountId: string, secret: string, step: number, expiresAt: number): Promise<boolean> {
    return this.stub().claimTotpStep(accountId, secret, step, expiresAt);
  }
  getTotp(accountId: string): Promise<TotpCredential | null> {
    return this.stub().getTotp(accountId) as Promise<TotpCredential | null>;
  }
  putTotp(cred: TotpCredential): Promise<void> {
    return this.stub().putTotp(cred);
  }
  confirmTotp(accountId: string, confirmedAt: number): Promise<void> {
    return this.stub().confirmTotp(accountId, confirmedAt);
  }
  deleteTotp(accountId: string): Promise<void> {
    return this.stub().deleteTotp(accountId);
  }
  putRecoveryCodes(accountId: string, codeHashes: string[]): Promise<void> {
    return this.stub().putRecoveryCodes(accountId, codeHashes);
  }
  consumeRecoveryCode(accountId: string, codeHash: string, usedAt: number): Promise<boolean> {
    return this.stub().consumeRecoveryCode(accountId, codeHash, usedAt);
  }

  // webauthn
  listWebAuthn(accountId: string): Promise<WebAuthnCredential[]> {
    return this.stub().listWebAuthn(accountId) as Promise<WebAuthnCredential[]>;
  }
  getWebAuthnByCredentialId(credentialId: string): Promise<WebAuthnCredential | null> {
    return this.stub().getWebAuthnByCredentialId(credentialId) as Promise<WebAuthnCredential | null>;
  }
  putWebAuthn(cred: WebAuthnCredential): Promise<void> {
    return this.stub().putWebAuthn(cred);
  }
  updateWebAuthnSignCount(id: string, signCount: number, lastUsedAt: number): Promise<void> {
    return this.stub().updateWebAuthnSignCount(id, signCount, lastUsedAt);
  }
  deleteWebAuthn(id: string): Promise<void> {
    return this.stub().deleteWebAuthn(id);
  }

  // challenges (single-use)
  putChallenge(c: ChallengeRecord): Promise<void> {
    return this.stub().putChallenge(c);
  }
  takeChallenge(id: string): Promise<Omit<ChallengeRecord, "id"> | null> {
    return this.stub().takeChallenge(id) as Promise<Omit<ChallengeRecord, "id"> | null>;
  }
}

// ---------------------------------------------------------------------------------------
// SessionStore (CONTRACTS-AUTH.md §2)
// ---------------------------------------------------------------------------------------

export class DoSessionStore implements SessionStore {
  constructor(
    private readonly env: AuthStoresEnv,
    private readonly orgId: string,
  ) {}

  private stub(): AuthStub {
    return authStub(this.env, this.orgId);
  }

  createSession(input: {
    authEpoch?: number;
    accountId: string;
    userId: string;
    orgId: string;
    scopes: Scope[];
    csrfToken: string;
    expiresAt: number;
  }): Promise<BrowserSession> {
    return this.stub().createSession(input) as Promise<BrowserSession>;
  }
  getSession(sessionId: string): Promise<BrowserSession | null> {
    return this.stub().getSession(sessionId) as Promise<BrowserSession | null>;
  }
  touchSession(sessionId: string, lastSeenAt: number): Promise<void> {
    return this.stub().touchSession(sessionId, lastSeenAt);
  }
  revokeSession(sessionId: string): Promise<void> {
    return this.stub().revokeSession(sessionId);
  }
  listSessions(accountId: string): Promise<BrowserSession[]> {
    return this.stub().listSessions(accountId) as Promise<BrowserSession[]>;
  }
  /// Upgrade an account's live sessions to a new scope set in place (email-verification gate
  /// upgrade-on-verification). Not part of the frozen `SessionStore` interface — integration-only.
  updateSessionsScopesForAccount(accountId: string, scopes: Scope[]): Promise<void> {
    return this.stub().updateSessionsScopesForAccount(accountId, scopes);
  }
  async revokedSessionJtis(): Promise<Set<string>> {
    // DO returns an array (Sets don't survive RPC); wrap it here to satisfy the interface.
    return new Set(await this.stub().revokedSessionJtis());
  }
}

// ---------------------------------------------------------------------------------------
// ServiceTokenStore (CONTRACTS-AUTH.md §2)
// ---------------------------------------------------------------------------------------

export class DoServiceTokenStore implements ServiceTokenStore {
  constructor(
    private readonly env: AuthStoresEnv,
    private readonly orgId: string,
  ) {}

  private stub(): AuthStub {
    return authStub(this.env, this.orgId);
  }

  createServiceToken(rec: ServiceToken): Promise<void> {
    return this.stub().createServiceToken(rec);
  }
  getServiceToken(id: string): Promise<ServiceToken | null> {
    return this.stub().getServiceToken(id) as Promise<ServiceToken | null>;
  }
  listServiceTokens(orgId: string): Promise<ServiceToken[]> {
    return this.stub().listServiceTokens(orgId) as Promise<ServiceToken[]>;
  }
  touchServiceToken(id: string, lastUsedAt: number): Promise<void> {
    return this.stub().touchServiceToken(id, lastUsedAt);
  }
  revokeServiceToken(id: string): Promise<void> {
    return this.stub().revokeServiceToken(id);
  }
  setServiceTokenExpiry(id: string, expiresAt: number): Promise<void> {
    return this.stub().setServiceTokenExpiry(id, expiresAt);
  }
  async revokedServiceJtis(): Promise<Set<string>> {
    return new Set(await this.stub().revokedServiceJtis());
  }
}

// ---------------------------------------------------------------------------------------
// DeviceStore (auth-spec §4.1) — device codes + device sessions in AuthDO(orgId).
// ---------------------------------------------------------------------------------------

export class DoDeviceStore implements DeviceStore {
  constructor(
    private readonly env: AuthStoresEnv,
    private readonly orgId: string,
  ) {}

  private stub(): AuthStub {
    return authStub(this.env, this.orgId);
  }

  createDeviceCode(rec: DeviceCodeRecord): Promise<void> {
    return this.stub().createDeviceCode(rec);
  }
  consumeDeviceCode(id: string, consumedAt: number): Promise<DeviceCodeRecord | null> {
    return this.stub().consumeDeviceCode(id, consumedAt) as Promise<DeviceCodeRecord | null>;
  }
  createDeviceSession(rec: DeviceSessionRecord): Promise<void> {
    return this.stub().createDeviceSession(rec);
  }
  getDeviceSession(id: string): Promise<DeviceSessionRecord | null> {
    return this.stub().getDeviceSession(id) as Promise<DeviceSessionRecord | null>;
  }
  rotateDeviceSession(
    id: string,
    patch: {
      refreshHash: string;
      prevRefreshHash: string;
      prevGraceUntil: number;
      scopes: Scope[];
      lastSeenAt: number;
      expiresAt: number;
    },
  ): Promise<boolean> {
    return this.stub().rotateDeviceSession(id, patch);
  }
  revokeDeviceSession(id: string, reason: string, revokedAt: number): Promise<void> {
    return this.stub().revokeDeviceSession(id, reason, revokedAt);
  }
  listDeviceSessions(accountId: string): Promise<DeviceSessionRecord[]> {
    return this.stub().listDeviceSessions(accountId) as Promise<DeviceSessionRecord[]>;
  }
}

// ---------------------------------------------------------------------------------------
// EmailTokenStore (CONTRACTS-AUTH.md §2 / §1.7)
// ---------------------------------------------------------------------------------------

export class DoEmailTokenStore implements EmailTokenStore {
  constructor(
    private readonly env: AuthStoresEnv,
    private readonly orgId: string,
  ) {}

  private stub(): AuthStub {
    return authStub(this.env, this.orgId);
  }

  put(rec: EmailTokenRecord): Promise<void> {
    return this.stub().putEmailToken(rec);
  }
  get(id: string): Promise<EmailTokenRecord | null> {
    return this.stub().getEmailToken(id) as Promise<EmailTokenRecord | null>;
  }
  consume(id: string, consumedAt: number): Promise<boolean> {
    return this.stub().consumeEmailToken(id, consumedAt);
  }
  invalidateOutstanding(accountId: string, purpose: EmailTokenPurpose): Promise<void> {
    return this.stub().invalidateOutstandingEmailTokens(accountId, purpose);
  }
}

// ---------------------------------------------------------------------------------------
// EmailSender resolution (CONTRACTS-AUTH.md §3, §4.1; API.md §8).
//
// A deployer picks the provider EXPLICITLY via `EMAIL_PROVIDER` ∈
//   cloudflare | resend | postmark | ses | console
// (with a sensible auto-detect fallback when it's unset). For self-hosters, **Cloudflare Email
// Sending (the `send_email` binding) is the zero-external-account DEFAULT** — no API key, no third
// party — with Resend / Postmark / SES as opt-in deliverability upgrades.
//
// EXPLICIT (`EMAIL_PROVIDER` set): the named provider is used when its required env/secret +
// `EMAIL_FROM` are present; if a named provider is misconfigured we DON'T silently send via a
// different one — we fall through to console/fake so a misconfig is obvious rather than surprising.
//
// AUTO-DETECT (`EMAIL_PROVIDER` unset), first match wins:
//   1. Resend       — `RESEND_API_KEY` + `EMAIL_FROM`.
//   2. Postmark     — `POSTMARK_SERVER_TOKEN` + `EMAIL_FROM`.
//   3. SES          — `SES_ACCESS_KEY_ID` + `SES_SECRET_ACCESS_KEY` + `SES_REGION` + `EMAIL_FROM`.
//   4. Cloudflare   — the `EMAIL` send_email binding + `EMAIL_FROM` (the self-host default path).
//   5. Console dev  — `EMAIL_DEV_CONSOLE=1`: logs recipient/subject/LINK locally.
//   6. Fake         — otherwise: a no-op that records sends (so signup/verify never 500 in a deploy
//                     without email configured, and the vitest suite runs with no network). The
//                     verification link is still issued + retrievable via the resend route.
// Tests can also inject their own Fake/Console sender directly.
// ---------------------------------------------------------------------------------------

export interface EmailSenderEnv extends Partial<EmailEnv> {
  EMAIL?: EmailEnv["EMAIL"];
  EMAIL_FROM?: string;
  EMAIL_FROM_NAME?: string;
  /// Explicit provider selector: cloudflare | resend | postmark | ses | console. Unset => auto-detect.
  EMAIL_PROVIDER?: string;
  /// SECRET — Resend API key. With EMAIL_FROM, selects/enables Resend.
  RESEND_API_KEY?: string;
  /// SECRET — Postmark Server API token (X-Postmark-Server-Token). With EMAIL_FROM, selects Postmark.
  POSTMARK_SERVER_TOKEN?: string;
  /// SECRETS + region — AWS SES v2 SigV4 creds. With EMAIL_FROM, select SES.
  SES_ACCESS_KEY_ID?: string;
  SES_SECRET_ACCESS_KEY?: string;
  SES_REGION?: string;
  /// "1"/"true" selects the console dev sender when no real provider is configured.
  EMAIL_DEV_CONSOLE?: string;
}

function fromName(env: EmailSenderEnv): { EMAIL_FROM_NAME?: string } {
  return env.EMAIL_FROM_NAME ? { EMAIL_FROM_NAME: env.EMAIL_FROM_NAME } : {};
}

/// Build the Resend sender if fully configured, else null.
function resendIfConfigured(env: EmailSenderEnv): EmailSender | null {
  if (env.RESEND_API_KEY && env.EMAIL_FROM) {
    return resendEmailSender({ RESEND_API_KEY: env.RESEND_API_KEY, EMAIL_FROM: env.EMAIL_FROM, ...fromName(env) });
  }
  return null;
}
function postmarkIfConfigured(env: EmailSenderEnv): EmailSender | null {
  if (env.POSTMARK_SERVER_TOKEN && env.EMAIL_FROM) {
    return postmarkEmailSender({ POSTMARK_SERVER_TOKEN: env.POSTMARK_SERVER_TOKEN, EMAIL_FROM: env.EMAIL_FROM, ...fromName(env) });
  }
  return null;
}
function sesIfConfigured(env: EmailSenderEnv): EmailSender | null {
  if (env.SES_ACCESS_KEY_ID && env.SES_SECRET_ACCESS_KEY && env.SES_REGION && env.EMAIL_FROM) {
    return sesEmailSender({
      SES_ACCESS_KEY_ID: env.SES_ACCESS_KEY_ID,
      SES_SECRET_ACCESS_KEY: env.SES_SECRET_ACCESS_KEY,
      SES_REGION: env.SES_REGION,
      EMAIL_FROM: env.EMAIL_FROM,
      ...fromName(env),
    });
  }
  return null;
}
function cloudflareIfConfigured(env: EmailSenderEnv): EmailSender | null {
  if (env.EMAIL && env.EMAIL_FROM) {
    return cloudflareEmailSender({ EMAIL: env.EMAIL, EMAIL_FROM: env.EMAIL_FROM, ...fromName(env) });
  }
  return null;
}

/// Final fallback when no real provider is selected/configured: console dev sender if requested,
/// else the no-op fake (records sends; never fails the request).
function fallbackSender(env: EmailSenderEnv): EmailSender {
  if (env.EMAIL_DEV_CONSOLE === "1" || env.EMAIL_DEV_CONSOLE === "true") {
    return new ConsoleEmailSender();
  }
  return new FakeEmailSender();
}

/// Resolve the per-org RUNTIME email sender, RESOLUTION ORDER:
///   1. RUNTIME — the org's UI-managed, encrypted email config (email-config.ts), decrypted and
///      built into the matching sender. A saved config OVERRIDES the deploy env for that org.
///   2. ENV — the existing `EMAIL_PROVIDER`/auto-detect path (`emailSenderFor`).
///   3. FALLBACK — console/fake (handled inside `emailSenderFor`).
/// The runtime step never throws (an undecryptable/absent config simply falls through to env).
/// `org` is the OrgDO stub (`env.ORG_DO.get(idFromName(orgId))`) bound to the caller's org.
export async function emailSenderForOrg(
  env: EmailSenderEnv & Partial<Pick<Env, "STORAGE_ENC_KEY">> & { ORG_DO: DurableObjectNamespace<OrgDO> },
  orgId: string,
): Promise<EmailSender> {
  const org = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  const runtime = await runtimeEmailSenderFor(
    { STORAGE_ENC_KEY: env.STORAGE_ENC_KEY, EMAIL: env.EMAIL },
    org,
  );
  return runtime ?? emailSenderFor(env);
}

/// Describe the provider actually selected for an org, honoring its saved override before the
/// deployment-wide provider. The org doctor uses the same precedence as real send operations.
export async function describeSelectedEmailProviderForOrg(
  env: EmailSenderEnv & Partial<Pick<Env, "STORAGE_ENC_KEY">> & { ORG_DO: DurableObjectNamespace<OrgDO> },
  orgId: string,
) {
  const org = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  return await describeRuntimeEmailProvider(
    { STORAGE_ENC_KEY: env.STORAGE_ENC_KEY, EMAIL: env.EMAIL },
    org,
  ) ?? describeSelectedEmailProvider(env);
}

export function emailSenderFor(env: EmailSenderEnv): EmailSender {
  // EXPLICIT selection: honour EMAIL_PROVIDER. A misconfigured named provider falls through to the
  // console/fake fallback (never silently to a different provider), so a misconfig is visible.
  const provider = env.EMAIL_PROVIDER?.trim().toLowerCase();
  if (provider) {
    switch (provider) {
      case "resend":
        return resendIfConfigured(env) ?? fallbackSender(env);
      case "postmark":
        return postmarkIfConfigured(env) ?? fallbackSender(env);
      case "ses":
        return sesIfConfigured(env) ?? fallbackSender(env);
      case "cloudflare":
        return cloudflareIfConfigured(env) ?? fallbackSender(env);
      case "console":
        return new ConsoleEmailSender();
      default:
        // Unrecognized value: ignore and auto-detect (fail safe, never crash on a typo).
        break;
    }
  }

  // AUTO-DETECT (no explicit provider): Resend → Postmark → SES → Cloudflare → console → fake.
  return (
    resendIfConfigured(env) ??
    postmarkIfConfigured(env) ??
    sesIfConfigured(env) ??
    cloudflareIfConfigured(env) ??
    fallbackSender(env)
  );
}

/// Audit B8/B11 — name (don't build) the email provider the ENV path would select, so
/// the doctor endpoint + operator logs can report it. Mirrors `emailSenderFor` exactly.
/// A return of `"fake"` means mail is SILENTLY DROPPED (no provider configured) — the
/// single most common "verification never arrives" misconfig.
export function describeSelectedEmailProvider(env: EmailSenderEnv): {
  provider: "resend" | "postmark" | "ses" | "cloudflare" | "console" | "fake";
  delivers: boolean;
  detail: string;
} {
  const explicit = env.EMAIL_PROVIDER?.trim().toLowerCase();
  const has = {
    resend: !!(env.RESEND_API_KEY && env.EMAIL_FROM),
    postmark: !!(env.POSTMARK_SERVER_TOKEN && env.EMAIL_FROM),
    ses: !!(env.SES_ACCESS_KEY_ID && env.SES_SECRET_ACCESS_KEY && env.SES_REGION && env.EMAIL_FROM),
    cloudflare: !!(env.EMAIL && env.EMAIL_FROM),
  };
  const fallback = () =>
    (env.EMAIL_DEV_CONSOLE === "1" || env.EMAIL_DEV_CONSOLE === "true")
      ? { provider: "console" as const, delivers: false, detail: "console dev sender — logs links, does NOT deliver mail" }
      : { provider: "fake" as const, delivers: false, detail: "no-op fake sender — mail is SILENTLY DROPPED (configure an email provider)" };

  if (explicit === "console") return { provider: "console", delivers: false, detail: "console dev sender (EMAIL_PROVIDER=console)" };
  if (explicit === "resend") return has.resend ? { provider: "resend", delivers: true, detail: "Resend" } : fallback();
  if (explicit === "postmark") return has.postmark ? { provider: "postmark", delivers: true, detail: "Postmark" } : fallback();
  if (explicit === "ses") return has.ses ? { provider: "ses", delivers: true, detail: "AWS SES" } : fallback();
  if (explicit === "cloudflare") return has.cloudflare ? { provider: "cloudflare", delivers: true, detail: "Cloudflare Email Sending" } : fallback();

  // Auto-detect order: Resend → Postmark → SES → Cloudflare → console/fake.
  if (has.resend) return { provider: "resend", delivers: true, detail: "Resend (auto-detected)" };
  if (has.postmark) return { provider: "postmark", delivers: true, detail: "Postmark (auto-detected)" };
  if (has.ses) return { provider: "ses", delivers: true, detail: "AWS SES (auto-detected)" };
  if (has.cloudflare) return { provider: "cloudflare", delivers: true, detail: "Cloudflare Email Sending (auto-detected)" };
  return fallback();
}

// ---------------------------------------------------------------------------------------
// DoRateLimitStore — a FLEET-WIDE token-bucket store backed by the global DirectoryDO singleton
// (fix for per-isolate dilution of the pre-auth signup/login limiters). Each of the four buckets
// (signupIp/signupEmail/loginIp/loginEmail) gets its OWN instance with a distinct `bucket` prefix,
// so the persisted `bucket_key` is `"<bucket>|<key>"` and the four buckets stay fully disjoint
// (a prior bug shared them). Reads/writes are point-keyed RPC to the singleton — off the
// authenticated hot path (only pre-auth login/signup touch it).
// ---------------------------------------------------------------------------------------

export class DoRateLimitStore implements RateLimitStore {
  constructor(
    private readonly env: AuthStoresEnv,
    private readonly bucket: string,
  ) {}

  private key(key: string): string {
    return `${this.bucket}|${key}`;
  }

  async get(key: string): Promise<BucketState | null> {
    return directoryStub(this.env).getRateBucket(this.key(key));
  }

  async set(key: string, state: BucketState): Promise<void> {
    await directoryStub(this.env).setRateBucket(this.key(key), state.tokens, state.updatedAt);
  }

  /// ATOMIC check-and-consume in a single DirectoryDO RPC, so two Worker isolates can't each read
  /// the same prior state before either writes (burst-boundary over-admit). `RateLimiter.check`
  /// prefers this over the non-atomic get→compute→set path. Same bucket math (DO calls `consume`).
  async consume(key: string, config: RateLimitConfig, cost: number, now: number): Promise<RateLimitResult> {
    return directoryStub(this.env).consumeRateBucket(this.key(key), config, cost, now);
  }
}

// ---------------------------------------------------------------------------------------
// OrgProvisioner (CONTRACTS-AUTH.md §4.1) — self-serve signup's OrgDO side: a brand-new org
// plus its first `owner` human user. The auth-signup lane owns the credential-bearing Account
// (in AuthDO); the org/user directory is OrgDO's domain, so this adapter is the only place
// signup touches OrgDO.
// ---------------------------------------------------------------------------------------

export class DoOrgProvisioner implements OrgProvisioner {
  constructor(private readonly env: AuthStoresEnv) {}

  /// Mint a fresh org id and create its first owner user. An OrgDO instance "exists" once it
  /// holds a user (same model the bootstrap route uses), so creating the owner is the org
  /// creation. The new org id is namespaced so it can never collide with a human-chosen
  /// `org1`-style id from the bootstrap/OIDC paths.
  async createOrgWithOwner(input: {
    orgName: string;
    ownerEmail: string;
    ownerDisplayName: string;
  }): Promise<{ orgId: string; userId: string }> {
    const orgId = `org-${crypto.randomUUID()}`;
    const stub = this.env.ORG_DO.get(this.env.ORG_DO.idFromName(orgId));
    const user = await stub.createUser({
      orgId,
      email: input.ownerEmail,
      displayName: input.ownerDisplayName,
      role: "owner",
      kind: "human",
    });
    // Persist the submitted org display name so `/v1/auth/me` returns the real `orgName` right
    // after signup (no PATCH /v1/orgs/:org needed). The org's stable slug remains the orgId; this
    // only stores the human-facing name in the OrgDO `org_meta` store (setOrgName).
    await stub.setOrgName(input.orgName);
    return { orgId, userId: user.id };
  }
}

// ---------------------------------------------------------------------------------------
// Bundle factory — build the full adapter set for one org in one call.
// ---------------------------------------------------------------------------------------

export interface AuthStores {
  accounts: DoAccountStore;
  credentials: DoCredentialStore;
  sessions: DoSessionStore;
  serviceTokens: DoServiceTokenStore;
  emailTokens: DoEmailTokenStore;
  devices: DoDeviceStore;
}

export function authStoresFor(env: AuthStoresEnv, orgId: string): AuthStores {
  return {
    accounts: new DoAccountStore(env, orgId),
    credentials: new DoCredentialStore(env, orgId),
    sessions: new DoSessionStore(env, orgId),
    serviceTokens: new DoServiceTokenStore(env, orgId),
    emailTokens: new DoEmailTokenStore(env, orgId),
    devices: new DoDeviceStore(env, orgId),
  };
}
