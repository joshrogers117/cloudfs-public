/*
 * API domain types — the shared shapes the screens render against.
 *
 * Mirrors the macOS app's CloudFSKit Models (Filespace, ConnectionState, roles)
 * so the web and Mac product speak the same vocabulary. The Wire phase will
 * implement the same `CloudFsApi` interface against the real Worker/gateway;
 * screens only ever touch this interface, never the concrete client.
 */

export type ConnectionState = 'connected' | 'connecting' | 'paused' | 'disconnected' | 'error'

export type FilespaceRole = 'Filespace Admin' | 'Standard User' | 'Viewer'

export interface Filespace {
  id: string
  name: string
  /** Region label, e.g. "ENAM (us-east)". */
  region: string
  /** Storage backend label, e.g. "Cloudflare R2", "Backblaze B2 + CDN". */
  storageBackend: string
  connection: ConnectionState
  role: FilespaceRole
  /** Total bytes stored in the filespace. */
  usedBytes: number
  memberCount: number
  /** False when the server has not supplied authoritative usage/member counts. */
  usageKnown?: boolean
  memberCountKnown?: boolean
  /** Local mount path (display only on web). */
  mountPath?: string
  storageBucket?: string
  storageEndpoint?: string
}

/**
 * Progress of an IRREVERSIBLE purge sweep (the backend's `GET .../purge` poll). `failed`/`error`
 * report a TERMINAL stall — per-key delete errors the sweep can never get past (object-lock /
 * retention / legal hold / a scoped DeleteObject Deny) — so the UI can show "Purge failed — retry"
 * instead of an endlessly-"purging" spinner.
 */
/** A filespace snapshot schedule (GFS retention). `GET /v1/filespaces/:fs/schedules`. */
export interface SnapshotSchedule {
  id: string
  /** 'daily' | 'weekly' | … */
  tier: string
  intervalMs: number
  /** How many snapshots of this tier are kept. */
  retain: number
  enabled: boolean
  nextRunAt: number
  lastRunAt: number | null
}

export interface PurgeStatus {
  /** The sweep is armed/running. */
  purging: boolean
  /** Objects + metadata are gone (the space is fully purged). */
  done: boolean
  /** The sweep hit a terminal failure and stopped — re-issue the purge to retry. */
  failed: boolean
  /** Objects deleted so far (progress). */
  deleted: number
  /** Operator-readable failure summary (present only when `failed`). */
  error?: string
}

export interface DeploymentStorage {
  configured: boolean
  provider: string
  endpoint: string
  region: string
  bucket: string
  forcePathStyle: boolean
  problems: string[]
}

export interface CreateFilespaceInput {
  storageMode?: 'deployment'

  name: string
  region: string
  storageBackend: string
  /* ----- Per-space S3-compatible storage backend (optional override) -----
   * These round-trip to the backend's secret-free per-filespace storage descriptor
   * (org-do.ts registerSpace: storageEndpoint/Region/Bucket/ForcePathStyle/
   * CredentialRef). Absent fields inherit the deployment-default backend.
   */
  /** S3 endpoint origin, e.g. https://<acct>.r2.cloudflarestorage.com. */
  storageEndpoint?: string
  /** Bucket the presigner addresses. */
  storageBucket?: string
  /** true (default) = path-style; false = virtual-host addressing. */
  storageForcePathStyle?: boolean
  /** Names a SAVED storage credential id (never a secret). */
  credentialId?: string
}

/* ----- Storage credentials + connection verification ----- */

/**
 * A saved storage access key, public projection. The secret (secretAccessKey)
 * is write-only — it is sent once on create and NEVER returned by the API.
 */
export interface StorageCredential {
  id: string
  /** Human label shown in pickers + lists, e.g. "r2-prod-key". */
  label: string
  /** The access key id (safe to display); the secret is never returned. */
  accessKeyId: string
  createdAt: string
}

/** Body for creating a credential — the only place a secret is ever entered. */
export interface CreateStorageCredentialInput {
  label: string
  accessKeyId: string
  secretAccessKey: string
}

/**
 * Storage config to verify. Either reference a saved credential by id, or pass a
 * raw access key id + secret inline (used before the credential is saved).
 */
export interface StorageTestInput {
  endpoint: string
  region: string
  bucket: string
  forcePathStyle?: boolean
  keyPrefix?: string
  credentialId?: string
  accessKeyId?: string
  secretAccessKey?: string
}

/** Result of a connection-verify probe against the storage config. */
export interface StorageTestResult {
  reachable: boolean
  canWrite: boolean
  canRead: boolean
  canDelete: boolean
  /** True when the target bucket/prefix holds no objects (safe to adopt). */
  prefixEmpty: boolean
  /** A few example keys already under the prefix, when non-empty. */
  sampleKeys?: string[]
  /** Human-readable failure reason when the probe could not complete. */
  error?: string
}

/* ----- Email configuration (org-scoped, owner/admin) ----- */

/** Supported transactional-email providers (mirrors the onboarding catalog ids). */
export type EmailProvider = 'cloudflare' | 'resend' | 'postmark' | 'ses'

/**
 * The org's saved email configuration, public projection. Secrets (API key / SES
 * secret access key) are write-only — sent on PUT, NEVER echoed back. `configured`
 * is always true on a returned config; a null config means "using deployment
 * default" (no per-org override saved).
 */
export interface EmailConfig {
  provider: EmailProvider
  fromAddress: string
  fromName?: string
  /** SES region, when provider is 'ses'. */
  region?: string
  configured: true
}

/** Body for PUT email-config. Secrets are optional (omit to keep the saved one). */
export interface EmailConfigInput {
  provider: EmailProvider
  fromAddress: string
  fromName?: string
  /** Resend / Postmark API key (provider secret). */
  secret?: string
  /** SES IAM credentials + region. */
  sesAccessKeyId?: string
  sesSecretAccessKey?: string
  sesRegion?: string
}

/** Body for the send-test probe; may carry unsaved creds to test before saving. */
export interface EmailTestInput {
  to: string
  provider?: EmailProvider
  fromAddress?: string
  fromName?: string
  secret?: string
  sesAccessKeyId?: string
  sesSecretAccessKey?: string
  sesRegion?: string
}

/** Result of a send-test email probe. */
export interface EmailTestResult {
  sent: boolean
  error?: string
}

/* ----- Sign-in & authentication (org-scoped auth provider config) ----- */

/**
 * How the organization signs in.
 *   - `builtin` : cloud-fs built-in auth only (password + TOTP + passkeys).
 *   - `oidc`    : OIDC-only — password sign-in is DISABLED for everyone; members
 *                 must sign in through the configured identity provider.
 *   - `both`    : OIDC is available AND built-in password sign-in still works.
 */
export type AuthMode = 'builtin' | 'oidc' | 'both'

/** OIDC provider presets — mirror the auth onboarding catalog ids. */
export type OidcPreset = 'clerk' | 'okta' | 'entra' | 'auth0' | 'google' | 'generic'

/**
 * The PUBLIC sign-in config, readable WITHOUT a session — the sign-in page reads
 * it to decide whether to show the password form, the SSO button, or both.
 * `GET /v1/auth/config/public` → `{ mode, oidcEnabled, providerLabel?,
 * webBaseUrl?, gatewayBaseUrl?, productName? }` (auth-spec §2.8 added public
 * discovery fields so the Mac app can find the portal and API gateway).
 */
export interface PublicAuthConfig {
  mode: AuthMode
  /** True when an OIDC provider is configured (so a "Sign in with …" button shows). */
  oidcEnabled: boolean
  passkeysEnabled?: boolean
  signupMode?: 'closed' | 'invite' | 'domain' | 'open'
  /** Display label for the SSO button, e.g. "Okta" / "Clerk" / "Google Workspace". */
  providerLabel?: string
  /** Origin serving the web console (device-handoff base; auth-spec §2.8). */
  webBaseUrl?: string
  /** Public API gateway origin used by browser-to-native connect handoff. */
  gatewayBaseUrl?: string
  /** Product display name, e.g. "cloud-fs" (auth-spec §2.8). */
  productName?: string
  /**
   * Deployment-specific download link for the cloud-fs Mac app (ONBOARDING.md build
   * step 6). Server-configured (`APP_DOWNLOAD_URL`) so an operator can set/change it
   * without a web rebuild; `GetTheAppCard` falls back to the build-time
   * `VITE_APP_DOWNLOAD_URL`, then honest "ask your admin" copy, when unset.
   */
  appDownloadUrl?: string
}

/**
 * Minimum password length for every password the web console collects (setup
 * wizard, sign-up, password change). MUST mirror the backend's policy
 * (`backend/src/security/auth-password.ts` MIN_PASSWORD_LENGTH) — a lower
 * client gate lets a password pass the form only to 400 at the server (M-1).
 */
export const MIN_PASSWORD_LENGTH = 10

/* ----- First-run setup wizard (auth-spec §2.5) ----- */

/** `GET /v1/setup/status` → `{ needed }`. Public; nothing else is leaked. */
export interface SetupStatus {
  /** True until someone completes setup (or legacy bootstrap) on this deployment. */
  needed: boolean
}

/**
 * Body for `POST /v1/setup/init` — creates the first organization + admin
 * account and signs the operator in (sets the session cookie). The secret is
 * the deployment's BOOTSTRAP_SECRET: held in page memory only, sent exactly
 * once, never stored or echoed (auth-spec §5.4).
 */
export interface SetupInitInput {
  secret: string
  /** Org slug — short, lowercase, no dots; immutable after setup. */
  orgId: string
  orgName: string
  email: string
  displayName: string
  password: string
}

/** `POST /v1/setup/init` → 201 (cookie set; csrf captured by the client). */
export interface SetupInitResult {
  orgId: string
  userId: string
}

/* ----- Deploy-health doctor (ONBOARDING.md build step 5 "Health check") ----- */

export type DoctorCheckStatus = 'ok' | 'warn' | 'fail'

/** One readiness probe row (backend `backend/src/admin-doctor.ts` `DoctorCheck`). */
export interface DoctorCheck {
  name: string
  status: DoctorCheckStatus
  detail: string
}

/**
 * `GET /v1/orgs/:org/doctor` → 200 (owner/admin session-gated). The same probes
 * `backend/src/admin-doctor.ts` runs for the deploy-time BOOTSTRAP_SECRET-gated
 * `GET /v1/admin/doctor`, reachable here from an already-signed-in wizard/console
 * session (the bootstrap secret is cleared from page memory well before this step).
 */
export interface DoctorReport {
  ok: boolean
  isHttps: boolean
  checks: DoctorCheck[]
}

/* ----- Device sign-in: Mac-app browser handoff (auth-spec §2.2 / §2.6) ----- */

/**
 * Body for `POST /v1/auth/device/approve` (session + CSRF) — mints the one-time
 * device authorization code after the user explicitly approves on the portal.
 * Field values come from the app's /device/authorize query params (§2.1).
 */
export interface DeviceApproveInput {
  /** The app's pending-request state, echoed verbatim on the callback. */
  state: string
  /** base64url(SHA-256(verifier)), 43–128 chars. */
  codeChallenge: string
  /** Literally "S256" — anything else is rejected. */
  codeChallengeMethod: 'S256'
  /** e.g. "Josh's MacBook Pro", ≤64 chars. */
  deviceName: string
  /** e.g. "MacBookPro18,3", ≤32 chars, optional. */
  deviceModel?: string
}

/** `POST /v1/auth/device/approve` → 201 (auth-spec §2.2). */
export interface DeviceApproveResult {
  /** Org-qualified one-time code "<orgId>.dac-<id>.<secret>" — 5 min, single use. */
  code: string
  /** The request's state, echoed verbatim for the cloudfs:// callback. */
  state: string
  expiresInSeconds: number
}

/**
 * A long-lived device session (a Mac signed in through the app), public
 * projection from `GET /v1/auth/devices` (auth-spec §2.6). Refresh-token
 * hashes never leave the server. Recently revoked sessions stay listed
 * (flagged via `revokedAt`) until the server prunes them.
 */
export interface DeviceSession {
  id: string
  name: string
  model?: string
  createdAt: string
  lastSeenAt: string
  expiresAt: string
  /** Set when the session was revoked (reuse detection / settings / offboarding). */
  revokedAt?: string
}

/**
 * The org's saved auth configuration, public projection. The OIDC client secret is
 * write-only — sent on PUT, NEVER echoed back. `configured` is always true on a
 * returned `oidc` block. A null config means "using built-in auth (default)".
 * `GET /v1/orgs/:org/auth-config` → `{ config: AuthConfig | null }`.
 */
export interface AuthConfig {
  mode: AuthMode
  oidc?: {
    preset: OidcPreset
    issuer: string
    clientId: string
    /** Email domains allowed to sign in / be provisioned (may be empty). */
    allowedDomains: string[]
    /** Create accounts on first successful sign-in when the domain is allowed. */
    autoProvision: boolean
    configured: true
  }
}

/** Body for PUT auth-config. The secret is optional (omit to keep the saved one). */
export interface AuthConfigInput {
  mode: AuthMode
  oidc?: {
    preset: OidcPreset
    issuer: string
    clientId: string
    /** Omit to keep the previously-saved secret; required on first configure. */
    clientSecret?: string
    allowedDomains?: string[]
    autoProvision?: boolean
  }
}

/** Body for the validate probe against an issuer's discovery document. */
export interface AuthValidateInput {
  issuer: string
}

/** Result of validating an OIDC issuer (reads /.well-known/openid-configuration). */
export interface AuthValidateResult {
  valid: boolean
  /** Resolved endpoints from the discovery document, when reachable. */
  endpoints?: {
    authorization?: string
    token?: string
    jwks?: string
    userinfo?: string
    issuer?: string
  }
  /** Human-readable failure reason when the issuer could not be validated. */
  error?: string
}

export type OrgRole = 'Owner' | 'Admin' | 'Filespace Admin' | 'Member'

export interface Organization {
  id: string
  /** Short slug used at sign-in, e.g. "acme". */
  slug: string
  name: string
}

export interface User {
  id: string
  name: string
  email: string
  orgId: string
  orgRole: OrgRole
  /** Two-factor (TOTP) enrolled? */
  totpEnabled: boolean
  /** Registered passkeys. */
  passkeys: Passkey[]
}

export interface Passkey {
  id: string
  label: string
  createdAt: string
  lastUsedAt?: string
}

/* ----- Members & invites (B26) ----- */

/** The OrgDO role vocabulary as it travels on the wire (`/v1/orgs/:org/users`). */
export type MemberRole = 'owner' | 'admin' | 'space_admin' | 'standard'
export type MemberStatus = 'active' | 'suspended' | 'deprovisioned'

/** A member of the org (a row from `GET /v1/orgs/:org/users`). */
export interface Member {
  id: string
  email: string
  name: string
  role: MemberRole
  status: MemberStatus
}

/** A pending invite (a row from `GET /v1/orgs/:org/invites`). */
export interface Invite {
  id: string
  email: string
  role: MemberRole
  status: 'pending' | 'accepted' | 'revoked' | 'expired'
  createdAt: string
  expiresAt: string
}

/** Level of filespace access an invite scope grants (mirrors backend `Level`). */
export type FilespaceAccessLevel = 'read' | 'edit' | 'admin'

/** Input for `POST /v1/orgs/:org/invites`. */
export interface CreateInviteInput {
  email: string
  role: MemberRole
  /**
   * Optional filespace access granted on redeem, in addition to the org role — the invite
   * carries an ACL grant on the filespace's root (whole-filespace access; ONBOARDING.md build
   * step 5 "Invite the team"). Omit for an org-role-only invite (today's default behavior).
   */
  scope?: {
    spaceId: string
    level: FilespaceAccessLevel
  }
}

/** Result of creating an invite — the raw token is returned exactly ONCE (admin copies/sends it). */
export interface CreateInviteResult {
  invite: Invite
  /** The single-use raw token (never re-fetchable). Org-scoped (unqualified); rarely needed directly
   *  — prefer `joinToken` / `inviteUrl` for anything a human clicks or pastes. */
  rawToken: string
  /** Org-qualified token (`"<orgId>.inv-<id>.<secret>"`) for the join link (`/join?token=<joinToken>`).
   *  Self-contained: unlike `rawToken`, it needs no separate org id to redeem (ONBOARDING.md build step 1). */
  joinToken: string
  /**
   * Whether the backend actually emailed the invite (a delivering `EmailSender` was configured).
   * `false` means nothing was sent — the console must show the copy-link handoff as the ONLY way the
   * invite reaches the recipient, not a hollow "emailed" claim (ONBOARDING.md step 3 honesty gate).
   */
  emailSent: boolean
  /** A ready-to-share join link built from `joinToken` (`<origin>/join?token=<joinToken>`). */
  inviteUrl: string
}

export interface Session {
  user: User
  org: Organization
  token: string
}

/* ----- Auth request/response shapes ----- */

export interface SignUpInput {
  name: string
  email: string
  password: string
  /** New org name; the slug is derived server-side in the real client. */
  orgName: string
}

/**
 * Input for joining an EXISTING org via an invite token (B26). Distinct from `signup`, which
 * creates a NEW org. The token + org id come from the invite link an admin shared
 * (`/signup?org=<org>&invite=<token>`); `name` is the new member's display name. The backend
 * provisions the member in the existing org (`POST /v1/orgs/:org/invites/redeem`).
 */
export interface RedeemInviteInput {
  org: string
  token: string
  name: string
}

/* ----- Invite-based join (ONBOARDING.md build step 1 / CONTRACTS-AUTH §4.8) -----
 * Distinct from `redeemInvite` above: `redeemInvite` only provisions org membership
 * (the pre-existing B26 path, now dead-ended in the UI) and never creates a credential.
 * The `/join` flow is the real editor path: preview the invite, then atomically create
 * the account + credential + membership + session in one POST.
 */

/** `GET /v1/auth/join/preview?token=…` → 200. Enough for the join page's invitation header. */
export interface JoinPreview {
  /** Null when the org has no name set (grey-out gracefully, never block on it). */
  orgName: string | null
  /** The invited email — NOT editable; join reads it from the invite record, not the form. */
  email: string
  role: MemberRole
  /** Epoch-ms the invite expires, as an ISO string (mirrors `Invite.expiresAt`). */
  expiresAt: string
  /** Null when the inviting member has no display name on record. */
  invitedByName: string | null
}

/** Body for `POST /v1/auth/join` — the org-qualified `joinToken` from the invite link. */
export interface JoinInput {
  token: string
  displayName: string
  password: string
}

export interface LoginInput {
  email: string
  password: string
  /** Org slug, when signing into a specific org. */
  org?: string
  /** TOTP code, required when the account has 2FA enabled. */
  totp?: string
}

/** Which second factors the backend will accept to complete a login challenge. */
export type MfaMethod = 'totp' | 'webauthn'

/**
 * Login may succeed, or signal that a second factor is still required. When MFA is
 * required, `methods` carries the factors the backend offered (CONTRACTS-AUTH §4.2):
 * a user with only a passkey enrolled gets `['webauthn']`, a TOTP-only user gets
 * `['totp']`, and a user with both gets both. The sign-in screen routes on this —
 * a webauthn-only challenge must drive the passkey ceremony, never a dead TOTP form.
 */
export type LoginResult =
  | { kind: 'session'; session: Session }
  | { kind: 'totp-required'; challengeId: string; methods: MfaMethod[] }

export interface TotpEnrollment {
  /** otpauth:// URI for the authenticator app / QR code. */
  otpauthUri: string
  secret: string
}
