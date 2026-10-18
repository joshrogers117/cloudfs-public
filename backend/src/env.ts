// SPDX-License-Identifier: AGPL-3.0-or-later
import type { FilespaceDO } from "./filespace-do";
import type { OrgDO } from "./org-do";
import type { AuthDO } from "./auth-do";
import type { DirectoryDO } from "./directory-do";
import type { SendEmailBinding } from "./security/auth-email";

export interface Env {
  METADATA_WARNING_BYTES?: string;
  METADATA_ADMISSION_BYTES?: string;
  /// Operator-only offline backup/restore. Ordinary traffic fails closed while set.
  BACKUP_MODE?: "export" | "restore";
  /// One Durable Object per (org, space): metadata authority + lock manager.
  /// Addressed via `filespaceDoName(orgId, spaceId)` so two orgs that pick the
  /// same human space id land on DIFFERENT DOs (multi-tenant isolation, F2).
  FILESPACE: DurableObjectNamespace<FilespaceDO>;

  /// Org/account-level tenancy authority: users, groups, memberships, roles,
  /// the filespace registry, and invite rows (multiuser workstream).
  ORG_DO: DurableObjectNamespace<OrgDO>;

  /// Per-org AUTH authority (CONTRACTS-AUTH.md §0): accounts, password/TOTP/WebAuthn
  /// credentials, recovery codes, browser sessions, service tokens, email/reset tokens,
  /// and short-lived challenges. Addressed via `idFromName(orgId)`, mirroring ORG_DO.
  AUTH_DO: DurableObjectNamespace<AuthDO>;

  /// The GLOBAL singleton email -> {orgId, accountId} directory (CONTRACTS-AUTH.md §1.7).
  /// Addressed via `idFromName("global")`. Resolves a bare email+password login before the
  /// org is known and enforces system-wide email uniqueness. Off the authenticated hot path.
  DIRECTORY_DO: DurableObjectNamespace<DirectoryDO>;

  // ---- transactional email (CONTRACTS-AUTH.md §2 EmailSender, §4) ----
  /// Cloudflare Email Sending binding (`send_email`). Optional: if unbound (or EMAIL_FROM
  /// unset) the auth layer uses a no-op sender — verification links are still issued and
  /// re-sendable, but no mail leaves the Worker (safe default for un-onboarded deploys and
  /// for the vitest suite, which uses the fake sender). Onboard a domain with
  /// `wrangler email sending enable <domain>` before binding this in prod.
  EMAIL?: SendEmailBinding;
  /// The verified `from` address for transactional mail (non-secret var). Required for real
  /// sending; absent => no-op sender.
  EMAIL_FROM?: string;
  /// Optional friendly `from` display name.
  EMAIL_FROM_NAME?: string;

  /// SECRET — Resend (https://resend.com) API key. When set together with EMAIL_FROM, Resend is
  /// the DEFAULT real transactional sender (HTTP API via fetch — no binding/onboarding needed
  /// beyond verifying the from-domain in Resend). Provision via `wrangler secret put
  /// RESEND_API_KEY`; never hard-code it. Falls back to the Cloudflare `EMAIL` binding if only
  /// that's configured, else the dev-console / no-op fake sender. See API.md §8.
  RESEND_API_KEY?: string;

  /// Dev-only: set to "1" (or "true") to select the console email sender when no real provider
  /// (Resend/Cloudflare) is configured — it logs the recipient + subject + verification/invite
  /// LINK to the Worker console so signup can be exercised locally with no real email. Never set
  /// in prod. Non-secret var.
  EMAIL_DEV_CONSOLE?: string;

  // ---- WebAuthn / passkeys RP config (CONTRACTS-AUTH.md §1.4, §5) ----
  /// Relying Party ID — the portal's registrable domain ("portal.cloudfs.app"; "localhost"
  /// in dev). Optional: if unset the WebAuthn routes 404 (fail closed, like OIDC).
  WEBAUTHN_RP_ID?: string;
  /// Human-visible RP name shown in the platform passkey UI. Defaults to "cloud-fs".
  WEBAUTHN_RP_NAME?: string;
  /// Expected ceremony origin(s), comma-separated, e.g.
  /// "https://portal.cloudfs.app,http://localhost:5173". Required when WEBAUTHN_RP_ID is set.
  WEBAUTHN_ORIGIN?: string;

  /// Public base URL the SPA/portal is served from, used to build email verification + reset
  /// links ("https://portal.cloudfs.app"). Defaults to the request origin if unset.
  PUBLIC_BASE_URL?: string;
  /// Public origin of the WEB APP (the SPA), e.g. "https://portal.cloudfs.app"; dev default
  /// "http://localhost:5173". Used to build links that a HUMAN clicks in email and must land on a
  /// browser-rendered web page — NOT a Worker API route. The email-verification link points at the
  /// web app's public `/verify-email` page (which POSTs `{token, orgId}` to the POST confirm route),
  /// because the confirm route is POST-only and a GET to it would 401. Defaults to PUBLIC_BASE_URL,
  /// then the request origin, if unset.
  WEB_BASE_URL?: string;
  /// Product name used in email copy + the TOTP otpauth issuer. Defaults to "cloud-fs".
  PRODUCT_NAME?: string;

  /// ONBOARDING.md build step 6: deployment-specific download link for the cloud-fs Mac app,
  /// carried on `GET /v1/auth/config/public` (`appDownloadUrl`) alongside webBaseUrl/productName.
  /// cloud-fs is self-hosted (AGPLv3, BYO Cloudflare account) — there's no single canonical
  /// download URL, so this is unset by default and the web `GetTheAppCard` falls back to the
  /// build-time `VITE_APP_DOWNLOAD_URL`, then honest "ask your admin" copy. Non-secret var.
  APP_DOWNLOAD_URL?: string;

  /// FINDING #3 — session/OIDC cookie hardening transport override. Controls whether the auth
  /// cookies use the hardened `__Host-` name prefix + the `Secure` attribute. When UNSET (the
  /// default), the transport is auto-detected from the request URL: `https:` ⇒ secure cookies
  /// (`__Host-cfs_session` / `__Host-cfs_oidc` + Secure), plain `http`/localhost ⇒ the plain
  /// names with NO Secure (a `__Host-`/Secure cookie is dropped by the browser over http, which
  /// would break the local dev stack + the E2E harness that run over http). Set to "1"/"true" to
  /// FORCE secure cookies (e.g. behind a TLS-terminating proxy that forwards http to the Worker),
  /// or "0"/"false" to force the plain names. Non-secret var.
  COOKIE_SECURE?: string;

  /// SECRET — HMAC signing key for HS256 bearer tokens (verifyRequest).
  /// Provision via `wrangler secret put AUTH_SIGNING_SECRET` in prod; the local
  /// dev/test value lives in `.dev.vars`. Must be >= 16 chars.
  AUTH_SIGNING_SECRET: string;

  // ---- password hardening (src/security/auth-password.ts) ----
  /// Operator-tunable scrypt cost: overrides the default N (CPU/memory cost). MUST be a power of
  /// two (scrypt requires N = 2^k). The default is 2^15 = 32768 (about 32 MiB per derivation).
  /// Test memory and concurrent sign-ins before raising it within Workers limits. A
  /// missing / non-power-of-two / out-of-range value is ignored (falls back to the default). Older
  /// hashes verify with their own stored params and upgrade transparently on the next login.
  /// Non-secret var.
  SCRYPT_COST_N?: string;
  /// Enable the OPTIONAL breached-password check (HaveIBeenPwned k-anonymity range API) at signup
  /// + password change + reset. "1"/"true" turns it ON; default OFF (dev/tests). Privacy-preserving
  /// (only a 5-char SHA-1 prefix leaves the Worker) and FAILS OPEN if HIBP is unreachable. Turn ON
  /// in prod for defence-in-depth. Non-secret var. See API.md §8.
  CHECK_BREACHED_PASSWORDS?: string;

  // ---- email provider selection (src/security/auth-email.ts; see API.md §8) ----
  /// Pick the transactional email provider explicitly: one of
  ///   "cloudflare" — the Workers `send_email` binding (zero external account; the SELF-HOST DEFAULT).
  ///   "resend"     — Resend HTTP API (RESEND_API_KEY).
  ///   "postmark"   — Postmark HTTP API (POSTMARK_SERVER_TOKEN).
  ///   "ses"        — AWS SES v2 SendEmail via SigV4 (SES_* creds + region).
  ///   "console"    — dev console sender (logs the link; never prod).
  /// When UNSET, selection auto-detects from the configured secrets/bindings (Resend → Postmark →
  /// SES → Cloudflare → console → no-op fake). Non-secret var.
  EMAIL_PROVIDER?: string;
  /// SECRET — Postmark Server API token (the `X-Postmark-Server-Token` header). With EMAIL_FROM,
  /// selects Postmark. Provision via `wrangler secret put POSTMARK_SERVER_TOKEN`. See API.md §8.
  POSTMARK_SERVER_TOKEN?: string;
  /// SECRETS — AWS SES v2 SigV4 credentials + region for the SES sender (EMAIL_PROVIDER="ses").
  /// SES_ACCESS_KEY_ID / SES_SECRET_ACCESS_KEY are the IAM creds (ses:SendEmail); SES_REGION is the
  /// SES region (e.g. "us-east-1"). Provision the keys via `wrangler secret put`. With EMAIL_FROM
  /// these select the SES sender. See API.md §8.
  SES_ACCESS_KEY_ID?: string;
  SES_SECRET_ACCESS_KEY?: string;
  SES_REGION?: string;

  /// SECRET — deploy-time bootstrap secret. Presented (constant-time compared) on
  /// `POST /v1/bootstrap` to create the FIRST org + admin and mint an admin token.
  /// This is NOT an open admin endpoint: without this secret the route 401s, and
  /// it is single-use per org (409 once a user exists). Provision via
  /// `wrangler secret put BOOTSTRAP_SECRET`; rotate/revoke after first run.
  /// Optional binding — if unset/weak the bootstrap route is disabled (fails closed).
  BOOTSTRAP_SECRET?: string;

  /// FINDING B — the org permitted to manage the DEPLOYMENT-WIDE auth-config singleton.
  /// The auth-config (`PUT/DELETE /v1/orgs/:org/auth-config`) writes ONE global row on the
  /// DirectoryDO that selects the SSO provider for the WHOLE deployment — yet the route was
  /// gated only on "is the caller owner/admin of the org in the PATH". Under SIGNUP_MODE=
  /// open/domain an attacker could self-sign-up as owner of a throwaway org and rewrite the
  /// deployment's OIDC issuer/clientId/secret, hijacking SSO for the primary org (cross-tenant
  /// confused deputy). We now allow the write ONLY when the caller's org equals this designated
  /// primary org. Set it to the org id that legitimately owns deployment-wide auth (typically
  /// the bootstrap/first org, and the same value as OIDC_ORG_ID when SSO provisions into it).
  /// When UNSET we fall back to OIDC_ORG_ID, and if that is also unset the write/delete is
  /// REFUSED for every org (fail safe — never "any org's admin"). Reads degrade the same way.
  /// Non-secret var. Document the chosen org id in wrangler.jsonc for self-host operators.
  AUTH_CONFIG_ADMIN_ORG?: string;

  /// Audit B23 — operator-tunable per-(org,space) rate-limit caps (token bucket). Match these to
  /// your media workload + block size; defaults suit 4 MB blocks. Non-secret vars.
  RL_PRESIGN_CAPACITY?: string;
  RL_PRESIGN_REFILL?: string;
  RL_MUTATION_CAPACITY?: string;
  RL_MUTATION_REFILL?: string;

  /// Audit B16 (SSRF) — opt-in to allow the storage connection-test probe to target a PRIVATE host
  /// (loopback / RFC-1918), e.g. an on-prem MinIO. "1"/"true" enables it. UNSET ⇒ private/metadata
  /// endpoints are rejected so an admin can't use the probe to reach internal services. Cloud
  /// metadata (169.254.169.254) is ALWAYS blocked regardless. Non-secret var.
  STORAGE_PROBE_ALLOW_PRIVATE?: string;

  /// Audit B24 — seed demo fixtures (Project A / A001.mov / timeline.prproj) into a NEW filespace.
  /// "1"/"true" enables it (dev/test/demos). UNSET ⇒ a real deployment starts EMPTY (no phantom
  /// files an editor never created). Non-secret var.
  SEED_DEMO_ITEMS?: string;

  /// Audit B9 — extra CORS-allowed origins for a split-origin web console (comma/space-
  /// separated), beyond WEB_BASE_URL. Only an EXACT origin match is reflected (never `*`).
  /// Leave unset for a same-origin console. Non-secret var.
  CORS_ALLOWED_ORIGINS?: string;

  /// Audit B11 break-glass. Set to "builtin" to FORCE built-in (password) auth regardless of
  /// any saved runtime SSO config — the documented recovery from an SSO-lockout (a typo'd or
  /// dead IdP that wedged the deployment into mode='oidc'). Set it, redeploy, log back in with
  /// a password, then fix the config and unset it. Non-secret var.
  AUTH_MODE_FORCE?: string;

  // ---- self-serve signup gate (self-host deployment policy; src/signup-mode.ts) ----
  /// Gates `POST /v1/auth/signup` for a self-hosted deployment. One of:
  ///   "closed" — signup disabled entirely (bootstrap/invite-only org creation). 403 signup_disabled.
  ///   "invite" — only with a valid invite token in the signup body (`inviteToken`); checked
  ///              constant-time against SIGNUP_INVITE_TOKENS. 403 signup_disabled when missing/bad.
  ///   "domain" — open, but only emails whose domain is in SIGNUP_ALLOWED_DOMAINS may sign up.
  ///              403 domain_not_allowed otherwise.
  ///   "open"   — anyone may sign up (legacy public-SaaS behaviour).
  /// DEFAULT = "invite" (safe for self-host). An unrecognized value also fails closed to "invite".
  /// Non-secret var.
  SIGNUP_MODE?: string;
  /// Comma/space-separated email domains allowed when SIGNUP_MODE="domain" (e.g.
  /// "acmepost.com, example.org"). Case-insensitive; a leading "@" is tolerated. Non-secret var.
  SIGNUP_ALLOWED_DOMAINS?: string;
  /// SECRET — comma/space/newline-separated set of valid signup invite tokens, used when
  /// SIGNUP_MODE="invite". The signup body's `inviteToken` is compared constant-time against
  /// each. Provision via `wrangler secret put SIGNUP_INVITE_TOKENS` (or `.dev.vars` locally);
  /// never commit real tokens. If unset/empty while mode="invite", ALL signups are blocked
  /// (fail closed).
  SIGNUP_INVITE_TOKENS?: string;
  /// Audit B7 — explicit opt-in to allow SIGNUP_MODE="open" on an https deployment. The dev
  /// config ships "open"; a real (https) deployment under "open" is REFUSED (signup_disabled)
  /// unless this is "1"/"true". Protects a self-hoster who deploys the dev config verbatim from
  /// handing strangers self-serve orgs that presign into their bucket. Non-secret var.
  SIGNUP_OPEN_ON_HTTPS?: string;

  /// DEPLOYMENT-DEFAULT S3-compatible data plane (local: MinIO; prod: Cloudflare R2 via its
  /// S3 endpoint). Used to mint presigned URLs for any filespace that hasn't overridden its
  /// storage backend in the registry. cloud-fs is bring-your-own-storage: a per-filespace
  /// backend (R2 / AWS S3 / Backblaze B2 / MinIO / Wasabi / Ceph) is configured in the OrgDO
  /// `spaces` registry (endpoint/region/bucket/forcePathStyle + a `credentialRef`); a space
  /// with no override falls back to these defaults. See src/storage.ts + API.md §8.
  /// In prod, S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY are Worker SECRETS (`wrangler secret
  /// put`), NOT plaintext vars (F7).
  /// Internal metadata-fixture escape hatch. Production tooling refuses disabling
  /// verification and readiness fails if set to "0". Never configure in a deployment.
  STORAGE_VERIFY_UPLOADS?: string;
  S3_ENDPOINT: string;
  S3_BUCKET: string;
  /// SigV4 region for the DEFAULT backend. Defaults to "auto" (R2) if unset. AWS S3 / B2 /
  /// Wasabi want a real region; MinIO/Ceph ignore it. Non-secret var.
  S3_REGION?: string;
  S3_ACCESS_KEY_ID: string;
  S3_SECRET_ACCESS_KEY: string;
  /// SECRET — optional temporary S3/R2 session token, paired with the default keys.
  /// Rotate all three together before expiry; long-lived credentials omit it.
  S3_SESSION_TOKEN?: string;
  /// Optional native verification for the exact deployment-default R2 bucket.
  /// Both identity vars must describe this binding; other backends use S3 HEAD.
  DATA_BUCKET?: R2Bucket;
  DATA_BUCKET_ENDPOINT?: string;
  DATA_BUCKET_NAME?: string;

  /// SECRET — AES-256-GCM key (32 random bytes, base64) for UI-MANAGED encrypted-at-rest secrets:
  /// object-storage credentials (src/storage-credentials.ts) AND the per-org email-provider config
  /// (src/email-config.ts), both via src/security/storage-crypto.ts. When an owner/admin saves
  /// S3-compatible credentials or an email provider's API key/token through the web UI, the SECRET
  /// is sealed under this key and stored in the OrgDO; it is decrypted ONLY server-side (at presign
  /// time / when building the email sender) and never returned by any API after creation. Generate with
  /// `openssl rand -base64 32` and provision via `wrangler secret put STORAGE_ENC_KEY` (prod) or
  /// `.dev.vars` (local). Optional binding: if unset, creating/using a MANAGED credential fails
  /// closed (the env `S3_*__<REF>` scheme is unaffected). See API.md §8 + §8c.
  STORAGE_ENC_KEY?: string;

  /// SECRETS — per-backend credential pairs for bring-your-own storage. A space whose
  /// registry row sets `storageCredentialRef: "<ref>"` is signed with the secrets
  /// `S3_ACCESS_KEY_ID__<REF>` / `S3_SECRET_ACCESS_KEY__<REF>` (the ref is uppercased and
  /// non-alnum chars become `_`; see storage.ts `credentialEnvSuffix`). Provision via
  /// `wrangler secret put S3_ACCESS_KEY_ID__<REF>` etc. These are matched dynamically by name
  /// (not a fixed field), so they live on the index signature below rather than as named keys.
  [key: `S3_ACCESS_KEY_ID__${string}`]: string | undefined;
  [key: `S3_SECRET_ACCESS_KEY__${string}`]: string | undefined;
  [key: `S3_SESSION_TOKEN__${string}`]: string | undefined;

  /// R2 bucket for AUDIT ARCHIVAL (WS3). The DO keeps only a small recent ring of
  /// audit events in SQLite; older sealed records are flushed here as NDJSON
  /// segments keyed `audit/{filespaceId}/{YYYY-MM-DD}.ndjson`, with a per-space
  /// `audit/{filespaceId}/index.json` manifest that preserves hash-chain
  /// continuity across the DO→R2 boundary (see metadata/audit-archive.ts). This is
  /// a native R2 binding (NOT presigned/S3) — the DO reads/writes it directly.
  /// Optional: if unbound, archival is a no-op and the DO keeps the full chain in
  /// SQLite (back-compat / local dev without R2).
  AUDIT_BUCKET?: R2Bucket;

  // ---- OIDC SSO (security/oidc.ts; see oidc-INTEGRATION.md §2) ----
  // The OIDC login routes (/v1/auth/oidc/start|callback) are disabled unless the
  // required vars below are set (issuer/client/redirect/org). AUTH_SIGNING_SECRET
  // (above) doubles as the HMAC key for the transient login-state cookie.
  /// IdP issuer, e.g. "https://acmepost.okta.com" (non-secret var). Optional —
  /// absence disables OIDC (the routes 404, never 500).
  OIDC_ISSUER?: string;
  OIDC_CLIENT_ID?: string;
  /// SECRET — the OAuth client secret. `wrangler secret put OIDC_CLIENT_SECRET`.
  OIDC_CLIENT_SECRET?: string;
  /// Exact registered callback URL, e.g. "https://gw.example/v1/auth/oidc/callback".
  OIDC_REDIRECT_URI?: string;
  /// Org this IdP provisions logins into (one IdP config per org, simple model).
  OIDC_ORG_ID?: string;
  /// Comma-separated email-domain allow-list, e.g. "acmepost.com" (optional).
  OIDC_ALLOWED_DOMAINS?: string;
  /// FIRST-LOGIN OWNER bootstrap allow-list (FINDING 4+12). The very first verified SSO identity for
  /// an empty org becomes its OWNER — that must NOT be any random verified user. Either set this to
  /// the exact email permitted to bootstrap the owner, OR rely on `OIDC_ALLOWED_DOMAINS` (the email's
  /// domain must be allow-listed). If NEITHER is configured, owner bootstrap is REFUSED (fail closed).
  OIDC_BOOTSTRAP_EMAIL?: string;
  /// "true" to auto-create allowed-domain users; default OFF (fail closed).
  OIDC_AUTO_PROVISION?: string;
  /// Endpoints: hard-set these (vars) to skip discovery, else discover(OIDC_ISSUER).
  OIDC_AUTHORIZATION_ENDPOINT?: string;
  OIDC_TOKEN_ENDPOINT?: string;
  OIDC_JWKS_URI?: string;
}

/// Classification of a config key for the canonical table:
///   - "binding": a wrangler runtime binding (DO namespace / R2 bucket / email) — wired in
///     wrangler.jsonc, NOT a plain env value.
///   - "secret": a secret-class value — `wrangler secret put` in prod, `.dev.vars` locally;
///     NEVER a plaintext `var` in wrangler.jsonc (audit F7).
///   - "var": a NON-secret config string — may live in wrangler.jsonc `vars`.
export type ConfigKind = "binding" | "secret" | "var";

export interface ConfigEntry {
  kind: ConfigKind;
  /// True when the gateway cannot serve its core function without it (a required binding
  /// or the token-signing secret). Optional keys gate an OPTIONAL feature (email/SSO/etc.).
  required: boolean;
  /// One-line purpose (the canonical, human-facing description).
  note: string;
}

/// CANONICAL CONFIG TABLE — the single source of truth for every key the gateway reads.
///
/// This is the documented contract referenced by SELF-HOSTING.md §4/§6/§7 and API.md §8.
/// A `config-drift.test.ts` asserts this manifest is in EXACT bidirectional sync with the
/// `Env` interface above — so a key added to `Env` without documenting it here (or a key
/// removed from `Env` but left documented) fails the suite. Keep them together.
///
/// (Historical note: the `DEV_TOKEN` static-bearer key was RETIRED — the gateway
/// authenticates only via signed tokens; it is intentionally ABSENT from both `Env` and
/// this table. See docs/security.md F1.)
export const CONFIG_MANIFEST = {
  METADATA_WARNING_BYTES: { kind: 'var', required: false, note: 'Filespace SQLite warning threshold in bytes; default 8000000000.' },
  METADATA_ADMISSION_BYTES: { kind: 'var', required: false, note: 'Filespace SQLite growth admission threshold; default 9000000000, preserving maintenance headroom below 10 GB.' },
  BACKUP_MODE: { kind: "var", required: false, note: "Offline maintenance: export or restore. Clear only after the coordinated session finishes." },
  // ---- runtime bindings (wrangler.jsonc) ----
  FILESPACE: { kind: "binding", required: true, note: "Durable Object namespace: per-(org,space) metadata authority + lock manager." },
  ORG_DO: { kind: "binding", required: true, note: "Durable Object namespace: org tenancy — users/groups/roles/filespace registry/invites." },
  AUTH_DO: { kind: "binding", required: true, note: "Durable Object namespace: per-org auth authority (credentials, sessions, tokens)." },
  DIRECTORY_DO: { kind: "binding", required: true, note: "Durable Object namespace: global email→{org,account} directory." },
  EMAIL: { kind: "binding", required: false, note: "Cloudflare Email Sending binding; unbound ⇒ no-op sender." },
  AUDIT_BUCKET: { kind: "binding", required: false, note: "R2 bucket for archived audit-chain segments; unbound ⇒ DO keeps the chain in SQLite." },
  DATA_BUCKET: { kind: "binding", required: false, note: "Optional deployment-default R2 bucket for native object verification; requires exact explicit endpoint/bucket identity mapping." },

  // ---- token signing (required secret) ----
  AUTH_SIGNING_SECRET: { kind: "secret", required: true, note: "HMAC key for HS256 session/service tokens (verifyRequest). ≥16 chars." },

  // ---- deploy-time bootstrap ----
  BOOTSTRAP_SECRET: { kind: "secret", required: false, note: "Deploy-time first-org/admin gate (X-Bootstrap-Secret). ≥16 chars or disabled." },

  // ---- default S3-compatible data plane ----
  STORAGE_VERIFY_UPLOADS: { kind: "var", required: false, note: "Internal metadata-test switch only. Production requires object verification; 0 fails readiness and is refused by deployment tooling." },
  S3_ENDPOINT: { kind: "var", required: true, note: "Default storage endpoint origin (no bucket/key)." },
  S3_BUCKET: { kind: "var", required: true, note: "Default storage bucket name." },
  S3_REGION: { kind: "var", required: false, note: "SigV4 region for the default backend ('auto' for R2)." },
  S3_ACCESS_KEY_ID: { kind: "secret", required: true, note: "Default backend access key id." },
  S3_SECRET_ACCESS_KEY: { kind: "secret", required: true, note: "Default backend secret access key (bucket master credential)." },
  S3_SESSION_TOKEN: { kind: "secret", required: false, note: "Temporary default S3/R2 session token; rotate with its access key pair before expiry." },
  DATA_BUCKET_ENDPOINT: { kind: "var", required: false, note: "Exact R2 S3 endpoint belonging to DATA_BUCKET; must match the deployment default before native verification is used." },
  DATA_BUCKET_NAME: { kind: "var", required: false, note: "Exact R2 bucket name bound as DATA_BUCKET; must match the deployment default before native verification is used." },

  // ---- UI-managed storage credential encryption ----
  STORAGE_ENC_KEY: { kind: "secret", required: false, note: "AES-256-GCM key for web-console-managed storage credentials (required to use that feature)." },
  STORAGE_PROBE_ALLOW_PRIVATE: { kind: "var", required: false, note: "Allow the storage-probe endpoint to reach private/loopback hosts (dev/SSRF override)." },

  // ---- rate limiting (token-bucket; env-tunable) ----
  RL_PRESIGN_CAPACITY: { kind: "var", required: false, note: "Presign rate-limit bucket capacity (burst)." },
  RL_PRESIGN_REFILL: { kind: "var", required: false, note: "Presign rate-limit refill rate (tokens/sec)." },
  RL_MUTATION_CAPACITY: { kind: "var", required: false, note: "Mutation rate-limit bucket capacity (burst)." },
  RL_MUTATION_REFILL: { kind: "var", required: false, note: "Mutation rate-limit refill rate (tokens/sec)." },

  // ---- CORS / web origin ----
  CORS_ALLOWED_ORIGINS: { kind: "var", required: false, note: "Extra allow-listed origins for the split-origin web console." },
  WEB_BASE_URL: { kind: "var", required: false, note: "Public origin of the web app (SPA); used to build human-clickable links + CORS." },
  PUBLIC_BASE_URL: { kind: "var", required: false, note: "Public base URL the portal is served from (email verify/reset links)." },
  PRODUCT_NAME: { kind: "var", required: false, note: "Product name in email copy + TOTP issuer. Default 'cloud-fs'." },
  APP_DOWNLOAD_URL: { kind: "var", required: false, note: "Download link for the cloud-fs Mac app, served on GET /v1/auth/config/public. Unset ⇒ web falls back to VITE_APP_DOWNLOAD_URL, then honest 'ask your admin' copy." },
  COOKIE_SECURE: { kind: "var", required: false, note: "Force/relax __Host- + Secure auth cookies (default: auto-detect from request scheme)." },

  // ---- email providers (optional; one is selected by which keys are set) ----
  EMAIL_FROM: { kind: "var", required: false, note: "Verified from-address for transactional mail; absent ⇒ no-op sender." },
  EMAIL_FROM_NAME: { kind: "var", required: false, note: "Optional from display name." },
  EMAIL_PROVIDER: { kind: "var", required: false, note: "Force a specific email provider (else auto-selected by configured keys)." },
  EMAIL_DEV_CONSOLE: { kind: "var", required: false, note: "Dev-only: log email links to the Worker console instead of sending." },
  RESEND_API_KEY: { kind: "secret", required: false, note: "Resend API key (default real sender when set with EMAIL_FROM)." },
  POSTMARK_SERVER_TOKEN: { kind: "secret", required: false, note: "Postmark server token." },
  SES_ACCESS_KEY_ID: { kind: "secret", required: false, note: "Amazon SES access key id." },
  SES_SECRET_ACCESS_KEY: { kind: "secret", required: false, note: "Amazon SES secret access key." },
  SES_REGION: { kind: "var", required: false, note: "Amazon SES region." },

  // ---- password hardening ----
  SCRYPT_COST_N: { kind: "var", required: false, note: "scrypt cost N override (power of two); default 2^15 (32768)." },
  CHECK_BREACHED_PASSWORDS: { kind: "var", required: false, note: "Enable the HaveIBeenPwned breached-password check at signup." },

  // ---- WebAuthn / passkeys (optional) ----
  WEBAUTHN_RP_ID: { kind: "var", required: false, note: "WebAuthn Relying Party ID (registrable domain); unset ⇒ passkey routes 404." },
  WEBAUTHN_RP_NAME: { kind: "var", required: false, note: "Human RP name in the passkey UI. Default 'cloud-fs'." },
  WEBAUTHN_ORIGIN: { kind: "var", required: false, note: "Expected ceremony origin(s), comma-separated. Required when WEBAUTHN_RP_ID is set." },

  // ---- signup gate ----
  SIGNUP_MODE: { kind: "var", required: false, note: "Self-serve signup policy: closed|invite|domain|open. Default invite." },
  SIGNUP_ALLOWED_DOMAINS: { kind: "var", required: false, note: "Allowed email domains when SIGNUP_MODE=domain." },
  SIGNUP_INVITE_TOKENS: { kind: "secret", required: false, note: "Valid signup invite tokens when SIGNUP_MODE=invite." },
  SIGNUP_OPEN_ON_HTTPS: { kind: "var", required: false, note: "Opt-in tripwire to allow SIGNUP_MODE=open over https (else refused)." },

  // ---- auth break-glass / admin ----
  AUTH_MODE_FORCE: { kind: "var", required: false, note: "Break-glass: force 'builtin' password auth regardless of saved SSO config." },
  AUTH_CONFIG_ADMIN_ORG: { kind: "var", required: false, note: "Org permitted to manage runtime auth config." },
  SEED_DEMO_ITEMS: { kind: "var", required: false, note: "Dev/test: seed demo namespace items in a fresh FilespaceDO." },

  // ---- OIDC SSO (optional; absence disables the routes) ----
  OIDC_ISSUER: { kind: "var", required: false, note: "OIDC IdP issuer; absence disables OIDC (routes 404)." },
  OIDC_CLIENT_ID: { kind: "var", required: false, note: "OIDC client id." },
  OIDC_CLIENT_SECRET: { kind: "secret", required: false, note: "OIDC OAuth client secret." },
  OIDC_REDIRECT_URI: { kind: "var", required: false, note: "Exact registered OIDC callback URL." },
  OIDC_ORG_ID: { kind: "var", required: false, note: "Org this IdP provisions logins into." },
  OIDC_ALLOWED_DOMAINS: { kind: "var", required: false, note: "OIDC email-domain allow-list." },
  OIDC_BOOTSTRAP_EMAIL: { kind: "var", required: false, note: "Exact email permitted to bootstrap the first SSO owner (fail-closed)." },
  OIDC_AUTO_PROVISION: { kind: "var", required: false, note: "'true' to auto-create allowed-domain SSO users; default off." },
  OIDC_AUTHORIZATION_ENDPOINT: { kind: "var", required: false, note: "Hard-set OIDC authorize endpoint (skips discovery)." },
  OIDC_TOKEN_ENDPOINT: { kind: "var", required: false, note: "Hard-set OIDC token endpoint (skips discovery)." },
  OIDC_JWKS_URI: { kind: "var", required: false, note: "Hard-set OIDC JWKS URI (skips discovery)." },
} satisfies Record<string, ConfigEntry>;

/// DYNAMIC (pattern-named) config keys that can't be discrete literals — the per-backend
/// BYO-storage credential pairs. Documented here so the canonical table is complete even
/// though these are matched by name pattern at runtime (storage-credentials.ts), not by a
/// fixed key. The `<REF>` is the uppercased `storageCredentialRef` on a filespace registry row.
export const CONFIG_DYNAMIC_PATTERNS = {
  "S3_ACCESS_KEY_ID__<REF>": { kind: "secret", required: false, note: "Per-backend BYO-storage access key id (names a credential set via storageCredentialRef)." },
  "S3_SECRET_ACCESS_KEY__<REF>": { kind: "secret", required: false, note: "Per-backend BYO-storage secret access key." },
  "S3_SESSION_TOKEN__<REF>": { kind: "secret", required: false, note: "Optional temporary session token for this credential reference only; never inherits the default token." },
} satisfies Record<string, ConfigEntry>;

/// The canonical set of config key names (derived from the manifest).
export const CONFIG_KEYS: ReadonlySet<string> = new Set(Object.keys(CONFIG_MANIFEST));

// ---- COMPILE-TIME drift guard (catches Env↔manifest divergence at `tsc`) ----
// These two type assertions FAIL THE BUILD if the canonical manifest and the `Env`
// interface ever diverge, so neither can silently drift from the other:
//   1. every manifest key is a real `Env` key (no documenting a key the code doesn't read);
//   2. every DISCRETE `Env` key is documented in the manifest (no adding an undocumented key
//      — this is what would have flagged a re-introduced DEV_TOKEN).
// The per-backend BYO-storage credential index signatures (`S3_ACCESS_KEY_ID__${string}` /
// `S3_SECRET_ACCESS_KEY__${string}`) are DYNAMIC patterns, not discrete keys, so they're
// excluded from rule 2 (they're documented as a pattern alongside S3_ACCESS_KEY_ID).
// The discrete (string-literal) `Env` keys: drop the dynamic BYO-storage credential index
// signatures (`*__${string}`) and any non-string key, leaving only the fixed config names.
type _LiteralEnvKeys = Exclude<Extract<keyof Env, string>, `${string}__${string}`>;
type _ManifestKeys = keyof typeof CONFIG_MANIFEST;
// Drift is the SYMMETRIC set difference between the discrete `Env` keys and the manifest
// keys. Each `Exclude` must be empty (`never`). The `[T] extends [never]` tuple wrap is
// the non-distributive emptiness test: when a side is NON-empty the conditional yields
// `false`, and assigning `true` to it is a build error — so the build fails loudly on any
// divergence (a re-introduced DEV_TOKEN, or a documented-but-removed key).
type _EnvKeysMissingFromManifest = Exclude<_LiteralEnvKeys, _ManifestKeys>;
type _ManifestKeysMissingFromEnv = Exclude<_ManifestKeys, keyof Env>;
const _configDriftGuardA: [_EnvKeysMissingFromManifest] extends [never] ? true : false = true;
const _configDriftGuardB: [_ManifestKeysMissingFromEnv] extends [never] ? true : false = true;
void _configDriftGuardA;
void _configDriftGuardB;
