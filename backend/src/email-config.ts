// SPDX-License-Identifier: AGPL-3.0-or-later
// email-config.ts — per-org, UI-managed, encrypted-at-rest transactional-email provider config
// + a real test-send endpoint (API.md §8).
//
// WHY: until now the email provider was chosen ONLY at deploy time via `EMAIL_PROVIDER` + the
// matching Worker secret (RESEND_API_KEY / POSTMARK_SERVER_TOKEN / SES_* / the `send_email`
// binding). A self-hoster had to `wrangler secret put` + redeploy to change it. This module lets
// an owner/admin configure email through the web admin console: the provider SECRET (Resend API
// key / Postmark server token / SES secret access key) is sealed with AES-256-GCM
// (security/storage-crypto.ts — the SAME envelope + `STORAGE_ENC_KEY` as managed storage creds)
// and stored in the OrgDO; the provider/from/region/sesAccessKeyId are stored plaintext for
// display. The secret is NEVER returned by any API after it is saved — it is decrypted ONLY
// server-side when building the runtime sender.
//
// RESOLUTION ORDER (auth-stores.ts `emailSenderForOrg`): the RUNTIME (per-org) config is resolved
// FIRST (decrypt → build the matching RawEmailSender); if there is no managed row (or it can't be
// decrypted) we fall back to the existing `EMAIL_PROVIDER`/env path (`emailSenderFor`), which
// itself falls back to console/fake. So a saved config OVERRIDES the deploy env for that org.
//
// The test-send endpoint builds a sender from the SAVED config OR from unsaved creds in the body
// (so the web "Test" button works before saving). It sends a real "cloud-fs test email", is
// rate-limited, and NEVER throws — every failure is mapped to `{ sent:false, error }`.

import type { Env } from "./env";
import type { AuthedContext, EmailConfigRow } from "./org-do";
import { sealSecret, openSecret } from "./security/storage-crypto";
import {
  type EmailSender,
  type RawEmailSender,
  MessageEmailSender,
  CloudflareRawEmailSender,
  ResendRawEmailSender,
  PostmarkRawEmailSender,
  SesRawEmailSender,
  type EmailEnv,
} from "./security/auth-email";
import {
  RateLimiter,
  InMemoryRateLimitStore,
  tooManyRequests,
  type RateLimitResult,
} from "./security/ratelimit";

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

/// The four UI-selectable runtime providers. (Console/Fake are deploy-only fallbacks, never a
/// user-chosen runtime config.)
export type EmailProvider = "cloudflare" | "resend" | "postmark" | "ses";

/// FROZEN CONTRACT — the safe, client-facing config shape. The provider secret(s) are NEVER part
/// of this; `configured` is always `true` (a present config is, by definition, configured).
export interface EmailConfig {
  provider: EmailProvider;
  fromAddress: string;
  fromName?: string;
  /// SES region only; omitted for other providers.
  region?: string;
  configured: true;
}

/// Project a stored row to the safe client shape (drops every secret/iv/ciphertext field).
export function toPublicEmailConfig(row: EmailConfigRow): EmailConfig {
  const out: EmailConfig = {
    provider: row.provider,
    fromAddress: row.fromAddress,
    configured: true,
  };
  if (row.fromName) out.fromName = row.fromName;
  if (row.provider === "ses" && row.region) out.region = row.region;
  return out;
}

// ---------------------------------------------------------------------------------------
// The OrgDO slice this module needs (decoupled + testable with an in-memory fake).
// ---------------------------------------------------------------------------------------

export interface EmailConfigOrgStub {
  getEmailConfig(): Promise<EmailConfigRow | null>;
  putEmailConfig(input: {
    orgId: string;
    provider: EmailProvider;
    fromAddress: string;
    fromName: string | null;
    region: string | null;
    secretIv: string;
    secretCiphertext: string;
    sesAccessKeyId: string | null;
  }): Promise<EmailConfigRow>;
  deleteEmailConfig(): Promise<boolean>;
}

// ---------------------------------------------------------------------------------------
// Runtime sender construction — decrypt a stored row (or build from plaintext creds) into the
// rich EmailSender, reusing the providers in security/auth-email.ts. `EMAIL_FROM`/from name come
// from the config (NOT the env), so a per-org from address is honoured.
// ---------------------------------------------------------------------------------------

/// Plaintext, decrypted email config (server-side only). Built either from a stored row (decrypt)
/// or directly from unsaved creds for the test endpoint.
export interface ResolvedEmailConfig {
  provider: EmailProvider;
  fromAddress: string;
  fromName?: string;
  region?: string;
  /// Resend API key OR Postmark server token OR SES secret access key (provider-dependent).
  secret?: string;
  sesAccessKeyId?: string;
}

/// Build the rich `EmailSender` for a resolved (plaintext) config. `cloudflareBinding` is the
/// Workers `send_email` binding from the env — Cloudflare is binding-based (no secret), so the
/// runtime config only carries the from address; the binding still comes from the deploy. Returns
/// null when the provider can't be built (e.g. Cloudflare selected but no binding bound, or a
/// secret-requiring provider with no secret) so the caller can fall back.
export function buildRuntimeSender(
  cfg: ResolvedEmailConfig,
  cloudflareBinding?: EmailEnv["EMAIL"],
): EmailSender | null {
  const fromName = cfg.fromName ? { EMAIL_FROM_NAME: cfg.fromName } : {};
  let raw: RawEmailSender;
  switch (cfg.provider) {
    case "cloudflare": {
      if (!cloudflareBinding) return null; // binding-based; nothing to send through.
      raw = new CloudflareRawEmailSender({ EMAIL: cloudflareBinding, EMAIL_FROM: cfg.fromAddress, ...fromName });
      break;
    }
    case "resend": {
      if (!cfg.secret) return null;
      raw = new ResendRawEmailSender({ RESEND_API_KEY: cfg.secret, EMAIL_FROM: cfg.fromAddress, ...fromName });
      break;
    }
    case "postmark": {
      if (!cfg.secret) return null;
      raw = new PostmarkRawEmailSender({ POSTMARK_SERVER_TOKEN: cfg.secret, EMAIL_FROM: cfg.fromAddress, ...fromName });
      break;
    }
    case "ses": {
      if (!cfg.secret || !cfg.sesAccessKeyId || !cfg.region) return null;
      raw = new SesRawEmailSender({
        SES_ACCESS_KEY_ID: cfg.sesAccessKeyId,
        SES_SECRET_ACCESS_KEY: cfg.secret,
        SES_REGION: cfg.region,
        EMAIL_FROM: cfg.fromAddress,
        ...fromName,
      });
      break;
    }
    default:
      return null;
  }
  return new MessageEmailSender(raw);
}

/// Decrypt a stored row into a `ResolvedEmailConfig`. Throws only if a secret-bearing row can't be
/// decrypted (bad/missing STORAGE_ENC_KEY) — callers treat a throw as "fall back to env".
export async function resolveStoredConfig(
  env: Pick<Env, "STORAGE_ENC_KEY">,
  row: EmailConfigRow,
): Promise<ResolvedEmailConfig> {
  const cfg: ResolvedEmailConfig = { provider: row.provider, fromAddress: row.fromAddress };
  if (row.fromName) cfg.fromName = row.fromName;
  if (row.region) cfg.region = row.region;
  if (row.sesAccessKeyId) cfg.sesAccessKeyId = row.sesAccessKeyId;
  // Cloudflare carries no secret (empty envelope columns). Decrypt only when one was sealed.
  if (row.secretCiphertext) {
    cfg.secret = await openSecret(env.STORAGE_ENC_KEY, { iv: row.secretIv, ciphertext: row.secretCiphertext });
  }
  return cfg;
}

/// Resolve the RUNTIME (per-org) sender from a stored config, or null when there is no usable
/// managed config (no row, undecryptable, or unbuildable) so the caller can fall back to the env
/// path. The Cloudflare `send_email` binding (if any) is taken from the env. Never throws.
export async function runtimeEmailSenderFor(
  env: Pick<Env, "STORAGE_ENC_KEY"> & { EMAIL?: EmailEnv["EMAIL"] },
  org: EmailConfigOrgStub,
): Promise<EmailSender | null> {
  let row: EmailConfigRow | null;
  try {
    row = await org.getEmailConfig();
  } catch {
    return null;
  }
  if (!row) return null;
  try {
    const cfg = await resolveStoredConfig(env, row);
    return buildRuntimeSender(cfg, env.EMAIL);
  } catch {
    // Undecryptable secret (e.g. rotated/missing STORAGE_ENC_KEY) → fall back rather than crash.
    return null;
  }
}

/// Describe a buildable org override using the same config resolution as runtime sends.
/// Returns null when absent, undecryptable, or unbuildable so callers can describe the env
/// fallback instead. Never includes sender addresses or decrypted secrets in the result.
export async function describeRuntimeEmailProvider(
  env: Pick<Env, "STORAGE_ENC_KEY"> & { EMAIL?: EmailEnv["EMAIL"] },
  org: EmailConfigOrgStub,
): Promise<{ provider: EmailProvider; delivers: boolean; detail: string } | null> {
  let row: EmailConfigRow | null;
  try {
    row = await org.getEmailConfig();
  } catch {
    return null;
  }
  if (!row) return null;
  try {
    const cfg = await resolveStoredConfig(env, row);
    const sender = buildRuntimeSender(cfg, env.EMAIL);
    if (!sender) return null;
    const names: Record<EmailProvider, string> = {
      cloudflare: "Cloudflare Email Sending",
      resend: "Resend",
      postmark: "Postmark",
      ses: "AWS SES",
    };
    return { provider: cfg.provider, delivers: sender.delivers !== false, detail: `${names[cfg.provider]} (org override)` };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------------------
// Test-send rate limiter — a real network send, owner/admin-triggered. In-isolate is fine: it's a
// manual "Test" click, not a hot path; the role gate + short bucket are the real protection.
// ---------------------------------------------------------------------------------------
const testSendStore = new InMemoryRateLimitStore();
const testSendLimiter = new RateLimiter(testSendStore, { capacity: 5, refillPerSec: 0.2 });

// ---------------------------------------------------------------------------------------
// The "cloud-fs test email" body.
// ---------------------------------------------------------------------------------------
function renderTestEmail(to: string) {
  return {
    to,
    subject: "cloud-fs test email",
    text:
      "This is a test email from cloud-fs.\n\n" +
      "If you received this, your email provider is configured correctly.\n",
    html:
      "<p>This is a test email from <strong>cloud-fs</strong>.</p>" +
      "<p>If you received this, your email provider is configured correctly.</p>",
  };
}

// ---------------------------------------------------------------------------------------
// HTTP handler — /v1/orgs/:org/email-config[/test]. Mounted by the gateway, which has already
// authenticated the principal + supplied the org role on `ctx`.
// ---------------------------------------------------------------------------------------

export interface EmailConfigDeps {
  org: EmailConfigOrgStub;
  /// Build the sender used by the test-send route from a resolved config. Defaults to
  /// `buildRuntimeSender` (real providers); tests inject a fake so no network is touched.
  buildSender?: (cfg: ResolvedEmailConfig) => EmailSender | null;
  /// Rate-limit key for the test route (default: the principal). Injectable for tests.
  rateKey?: string;
}

const PROVIDERS = new Set<EmailProvider>(["cloudflare", "resend", "postmark", "ses"]);

function parseProvider(v: unknown): EmailProvider | null {
  return typeof v === "string" && PROVIDERS.has(v as EmailProvider) ? (v as EmailProvider) : null;
}

/// Handle the email-config routes. `rest` is the path AFTER /v1/orgs/:org (e.g. ["email-config"]
/// or ["email-config","test"]). Returns null if the path isn't ours.
export async function handleEmailConfigRequest(
  req: Request,
  env: Env,
  ctx: AuthedContext,
  rest: string[],
  orgId: string,
  deps: EmailConfigDeps,
): Promise<Response | null> {
  if (rest[0] !== "email-config") return null;
  const isAdmin = ctx.orgRole === "owner" || ctx.orgRole === "admin";
  if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);

  // ---- /v1/orgs/:org/email-config/test ----
  if (rest[1] === "test") {
    if (req.method !== "POST") return json({ error: "method not allowed" }, 405);
    const rl: RateLimitResult = await testSendLimiter.check(deps.rateKey ?? ctx.principalUserId);
    if (!rl.allowed) return tooManyRequests(rl);
    return await handleTestSend(req, env, orgId, deps);
  }

  if (rest[1]) return json({ error: "not found" }, 404);

  // ---- /v1/orgs/:org/email-config ----
  try {
    if (req.method === "GET") {
      const row = await deps.org.getEmailConfig();
      return json({ config: row ? toPublicEmailConfig(row) : null });
    }
    if (req.method === "PUT") {
      return await handlePut(req, env, orgId, deps);
    }
    if (req.method === "DELETE") {
      await deps.org.deleteEmailConfig();
      return new Response(null, { status: 204 });
    }
    return json({ error: "method not allowed" }, 405);
  } catch (e) {
    return json({ error: shortErr(e) }, 500);
  }
}

interface ConfigBody {
  provider?: unknown;
  fromAddress?: unknown;
  fromName?: unknown;
  secret?: unknown;
  sesAccessKeyId?: unknown;
  sesSecretAccessKey?: unknown;
  sesRegion?: unknown;
}

/// Validate + normalize a PUT/test body into the fields we need. Returns an error string (for a
/// 400 / test failure) instead of throwing. `existing` is the currently-saved row (PUT only), so a
/// secret can be RETAINED on edit when the body omits it (e.g. user changes the from name only).
function validateConfig(
  b: ConfigBody,
  existing: EmailConfigRow | null,
): { ok: true; cfg: { provider: EmailProvider; fromAddress: string; fromName: string | null; region: string | null; secret: string | null; sesAccessKeyId: string | null } } | { ok: false; error: string } {
  const provider = parseProvider(b.provider);
  if (!provider) return { ok: false, error: "provider must be one of cloudflare|resend|postmark|ses" };
  const fromAddress = typeof b.fromAddress === "string" ? b.fromAddress.trim() : "";
  if (!fromAddress) return { ok: false, error: "fromAddress is required" };
  const fromName = typeof b.fromName === "string" && b.fromName.trim() ? b.fromName.trim() : null;

  const reuseSecret = existing && existing.provider === provider;
  const secretInBody = typeof b.secret === "string" && b.secret ? b.secret : null;
  const sesSecretInBody = typeof b.sesSecretAccessKey === "string" && b.sesSecretAccessKey ? b.sesSecretAccessKey : null;

  switch (provider) {
    case "cloudflare":
      // Binding-based: no secret, no region.
      return { ok: true, cfg: { provider, fromAddress, fromName, region: null, secret: null, sesAccessKeyId: null } };
    case "resend":
    case "postmark": {
      const secret = secretInBody ?? null;
      if (!secret && !reuseSecret) return { ok: false, error: "secret is required" };
      return { ok: true, cfg: { provider, fromAddress, fromName, region: null, secret, sesAccessKeyId: null } };
    }
    case "ses": {
      const region = typeof b.sesRegion === "string" && b.sesRegion.trim() ? b.sesRegion.trim() : (reuseSecret ? existing!.region : null);
      const sesAccessKeyId = typeof b.sesAccessKeyId === "string" && b.sesAccessKeyId.trim() ? b.sesAccessKeyId.trim() : (reuseSecret ? existing!.sesAccessKeyId : null);
      const secret = sesSecretInBody ?? null;
      if (!region) return { ok: false, error: "sesRegion is required" };
      if (!sesAccessKeyId) return { ok: false, error: "sesAccessKeyId is required" };
      if (!secret && !reuseSecret) return { ok: false, error: "sesSecretAccessKey is required" };
      return { ok: true, cfg: { provider, fromAddress, fromName, region, secret, sesAccessKeyId } };
    }
  }
}

async function handlePut(req: Request, env: Env, orgId: string, deps: EmailConfigDeps): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as ConfigBody;
  const existing = await deps.org.getEmailConfig();
  const v = validateConfig(b, existing);
  if (!v.ok) return json({ error: v.error }, 400);
  const { provider, fromAddress, fromName, region, secret, sesAccessKeyId } = v.cfg;

  // Seal the secret BEFORE it touches the DO. Cloudflare carries no secret (empty envelope). When
  // editing an existing same-provider config without a new secret, RETAIN the stored envelope.
  let secretIv = "";
  let secretCiphertext = "";
  if (secret) {
    try {
      const sealed = await sealSecret(env.STORAGE_ENC_KEY, secret);
      secretIv = sealed.iv;
      secretCiphertext = sealed.ciphertext;
    } catch (e) {
      return json({ error: "storage_enc_key_unconfigured", detail: shortErr(e) }, 500);
    }
  } else if (existing && existing.provider === provider) {
    secretIv = existing.secretIv;
    secretCiphertext = existing.secretCiphertext;
  }

  const saved = await deps.org.putEmailConfig({
    orgId,
    provider,
    fromAddress,
    fromName,
    region,
    secretIv,
    secretCiphertext,
    sesAccessKeyId,
  });
  return json(toPublicEmailConfig(saved), 200);
}

/// Test-send: build a sender from SAVED config OR unsaved creds in the body, send the test email,
/// and return `{ sent, error? }`. Never throws — failures map to `{ sent:false, error }`.
async function handleTestSend(req: Request, env: Env, orgId: string, deps: EmailConfigDeps): Promise<Response> {
  let b: ConfigBody & { to?: unknown };
  try {
    b = (await req.json()) as typeof b;
  } catch {
    return json({ sent: false, error: "invalid_body" }, 200);
  }
  const to = typeof b.to === "string" ? b.to.trim() : "";
  if (!to) return json({ sent: false, error: "to is required" }, 200);

  const build = deps.buildSender ?? ((cfg: ResolvedEmailConfig) => buildRuntimeSender(cfg, env.EMAIL));

  // Resolve the config to send through: prefer unsaved creds in the body (so "Test" works before
  // saving / for tweaked values), else fall back to the SAVED config.
  let resolved: ResolvedEmailConfig | null = null;
  if (parseProvider(b.provider)) {
    const existing = await deps.org.getEmailConfig().catch(() => null);
    const v = validateConfig(b, existing);
    if (!v.ok) return json({ sent: false, error: v.error }, 200);
    const { provider, fromAddress, fromName, region, secret, sesAccessKeyId } = v.cfg;
    resolved = { provider, fromAddress };
    if (fromName) resolved.fromName = fromName;
    if (region) resolved.region = region;
    if (sesAccessKeyId) resolved.sesAccessKeyId = sesAccessKeyId;
    if (secret) {
      resolved.secret = secret;
    } else if (existing && existing.provider === provider && existing.secretCiphertext) {
      // Reusing the saved secret for a same-provider test where the body omitted it.
      try {
        resolved.secret = await openSecret(env.STORAGE_ENC_KEY, { iv: existing.secretIv, ciphertext: existing.secretCiphertext });
      } catch (e) {
        return json({ sent: false, error: shortErr(e) }, 200);
      }
    }
  } else {
    const row = await deps.org.getEmailConfig().catch(() => null);
    if (!row) return json({ sent: false, error: "no_email_config" }, 200);
    try {
      resolved = await resolveStoredConfig(env, row);
    } catch (e) {
      return json({ sent: false, error: shortErr(e) }, 200);
    }
  }

  const sender = build(resolved);
  if (!sender) return json({ sent: false, error: "provider_not_configured" }, 200);

  try {
    await sender.sendTransactional(renderTestEmail(to));
    return json({ sent: true }, 200);
  } catch (e) {
    return json({ sent: false, error: shortErr(e) }, 200);
  }
}
