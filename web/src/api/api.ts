/*
 * CloudFsApi — the API seam.
 *
 * Every screen talks to THIS interface, never a concrete client. The Wire phase
 * swaps the implementation (MockApi → a real HTTP client against the Worker /
 * gateway) by changing only `getApi()` in index.ts — screens are untouched.
 */
import type {
  AuthConfig,
  AuthConfigInput,
  AuthValidateResult,
  CreateFilespaceInput,
  CreateInviteInput,
  CreateInviteResult,
  CreateStorageCredentialInput,
  DeviceApproveInput,
  DeviceApproveResult,
  DeviceSession,
  DoctorReport,
  DeploymentStorage,
  EmailConfig,
  EmailConfigInput,
  EmailTestInput,
  EmailTestResult,
  Filespace,
  Invite,
  JoinInput,
  JoinPreview,
  LoginInput,
  LoginResult,
  Member,
  MemberRole,
  Organization,
  Passkey,
  PublicAuthConfig,
  PurgeStatus,
  RedeemInviteInput,
  Session,
  SetupInitInput,
  SetupInitResult,
  SetupStatus,
  SignUpInput,
  StorageCredential,
  StorageTestInput,
  StorageTestResult,
  TotpEnrollment,
  User,
  SnapshotSchedule,
} from './types'

export interface CloudFsApi {
  /* ----- Auth ----- */
  signup(input: SignUpInput): Promise<Session>
  /**
   * Join an EXISTING org via an invite token (B26). The token + org come from an admin's invite
   * link (`/signup?org=&invite=`). Provisions the member in the existing org via the public
   * `POST /v1/orgs/:org/invites/redeem` route (the token IS the credential — no prior session).
   */
  redeemInvite(input: RedeemInviteInput): Promise<void>
  /**
   * Preview an invite BEFORE accepting it (PUBLIC — no session). Enough for the /join page's
   * "<invitedByName> invited you to <orgName>" header. `404 not_found` for an unknown/malformed
   * token; `410 expired|revoked|already_used` for a dead one.
   * `GET /v1/auth/join/preview?token=…`
   */
  previewJoin(token: string): Promise<JoinPreview>
  /**
   * Complete an invite-based join (ONBOARDING.md build step 1): atomically creates the
   * credential-bearing Account (the invite token's possession already proved the email),
   * redeems the invite (org membership + any ACL grant it promised), and signs the user in —
   * one POST from an emailed link to a live session, no separate sign-in step. Errors:
   * `400 invalid_token|invalid_display_name|weak_password|password_too_long|password_breached`,
   * `401 token_mismatch`, `403 auth_mode_oidc`, `404 not_found`, `409 already_used|email_taken`,
   * `410 expired|revoked`, `429 rate_limited`, `500 join_incomplete`.
   * `POST /v1/auth/join` → 201, sets the `cfs_session` cookie (same mechanics as signup/login).
   */
  join(input: JoinInput): Promise<Session>
  login(input: LoginInput): Promise<LoginResult>
  /** Resolve a pending TOTP challenge from `login`. */
  verifyTotp(challengeId: string, code: string): Promise<Session>
  /** Resolve a pending login challenge with a single-use recovery code. */
  loginWithRecovery(challengeId: string, recoveryCode: string): Promise<Session>
  /**
   * WebAuthn sign-in. Pass `{ email }` for passwordless login, or `{ challengeId }`
   * to satisfy a passkey second-factor challenge returned by `login`. Runs the real
   * `navigator.credentials.get()` ceremony in the browser and establishes the
   * cookie session on success.
   */
  loginWithPasskey(req: { email?: string; challengeId?: string }): Promise<Session>
  /**
   * Begin organization SSO. On the real backend this NAVIGATES the browser to the
   * gateway's OIDC start URL (a full-page redirect), so it does not return; the IdP
   * round-trips back to the web `/auth/callback` route, which calls `completeSSO()`.
   * The mock simulates success and resolves with a `Session` in-place.
   */
  beginSSO(returnTo?: string): Promise<Session | void>
  /**
   * Finish an SSO round-trip after the backend set the session cookie and redirected
   * back to `/auth/callback`. Reads `me()` and returns the session (or null if the
   * cookie wasn't established).
   */
  completeSSO(): Promise<Session | null>
  logout(): Promise<void>
  /** Current session, or null if signed out. */
  me(): Promise<Session | null>

  /* ----- First-run setup wizard (auth-spec §2.5) ----- */
  /**
   * Whether this deployment still needs first-run setup (PUBLIC; server-cached).
   * The router redirects a fresh deploy to /setup off this; the wizard self-hides
   * once it flips to false. `GET /v1/setup/status` → `{ needed }`.
   */
  getSetupStatus(): Promise<SetupStatus>
  /**
   * Complete first-run setup: bootstrap-secret-gated creation of the first org +
   * admin account. On success the response SETS the session cookie — the operator
   * is signed in (call `me()`/refresh to hydrate). Typed errors: 401 (secret
   * mismatch), 409 `setup_complete`, 400 `weak_password`, 429.
   * `POST /v1/setup/init` → 201.
   */
  setupInit(input: SetupInitInput): Promise<SetupInitResult>
  /**
   * Deploy-health readiness probes (ONBOARDING.md build step 5 "Health check"), reachable from an
   * already-signed-in owner/admin session — unlike `GET /v1/admin/doctor`, this doesn't need the
   * BOOTSTRAP_SECRET (already cleared from page memory by the time the wizard reaches this step).
   * Runs the SAME checks as the deploy-time doctor: transactional email in effect, `STORAGE_ENC_KEY`
   * configured (storage credentials + filespace master keys), and public-URL sanity for the
   * device-handoff. Always resolves 200 with the structured report — never throws on a failing
   * check — so the wizard can render pass/fail rows regardless of overall health.
   * `GET /v1/orgs/:org/doctor`.
   */
  doctor(org: string): Promise<DoctorReport>

  /* ----- Device sign-in: Mac-app browser handoff (auth-spec §2.2 / §2.6) ----- */
  /**
   * Mint the one-time device authorization code after the signed-in user clicks
   * [Approve sign-in] on /device/authorize. Session + CSRF gated. The returned
   * `code` rides BOTH the cloudfs:// redirect and the visible paste-fallback box.
   * `POST /v1/auth/device/approve` → 201 `{ code, state, expiresInSeconds }`.
   */
  approveDevice(input: DeviceApproveInput): Promise<DeviceApproveResult>
  /**
   * List the account's device sessions (Macs signed in through the app) — name,
   * model, created / last-seen / expiry, revoked flag. `GET /v1/auth/devices`.
   */
  listDevices(): Promise<DeviceSession[]>
  /**
   * Revoke a device session: signs the device out (refresh + access tokens die)
   * and CASCADES to its daemon service token, disconnecting the drive.
   * `DELETE /v1/auth/devices/:id` → 204.
   */
  revokeDevice(id: string): Promise<void>

  /* ----- Email verification ----- */
  /** (Re)send the verification email for the signed-in account. */
  sendVerificationEmail(): Promise<void>
  /**
   * Confirm an email from the verification link landing page (PUBLIC / no session).
   * Both `token` and `orgId` ride in the link's query string, so this works for a
   * signed-out visitor clicking the link in their inbox. POSTs `{ token, orgId }` to
   * `/v1/auth/verify-email`. Rejects on an expired/invalid token.
   */
  confirmEmail(token: string, orgId: string): Promise<void>
  requestPasswordReset(email: string): Promise<void>
  resetPassword(token: string, orgId: string, newPassword: string): Promise<void>
  enrollLegacyAccount(token: string, orgId: string, newPassword: string): Promise<void>

  /* ----- Filespaces ----- */
  listFilespaces(): Promise<Filespace[]>
  createFilespace(input: CreateFilespaceInput): Promise<Filespace>
  updateFilespace(id: string, patch: Partial<Filespace>): Promise<Filespace>
  /**
   * REVERSIBLE soft delete (owner-only). Sets the registry tombstone so the space vanishes from
   * `listFilespaces`; objects + metadata are left intact and recoverable. Step 1 of 2 — see
   * `purgeFilespace` for the irreversible step.
   */
  deleteFilespace(id: string): Promise<void>
  /**
   * IRREVERSIBLE purge (owner-only, two-step). PERMANENTLY deletes the soft-deleted space's
   * encrypted objects from storage AND hard-deletes its metadata + registry row. The backend
   * refuses unless the space is ALREADY soft-deleted (409 `must_soft_delete_first`) and requires
   * `confirm` to echo the exact filespace id (400 `confirmation_required` otherwise). Resolves once
   * the async sweep is ACCEPTED (HTTP 202); poll progress is not surfaced in the web flow.
   * `POST /v1/orgs/:org/spaces/:id/purge { confirm: id }`.
   */
  purgeFilespace(id: string): Promise<void>
  /**
   * Poll an IRREVERSIBLE purge's progress (owner-only). Returns the terminal/failed/in-progress
   * state so the UI can surface "Purge failed — retry" instead of spinning forever when the sweep
   * stalls on per-key delete errors (object-lock / legal-hold / Deny).
   * `GET /v1/orgs/:org/spaces/:id/purge`.
   */
  purgeFilespaceStatus(id: string): Promise<PurgeStatus>

  /* ----- Snapshot schedules (owner/admin) ----- */
  /** `GET /v1/filespaces/:fs/schedules`. */
  listSnapshotSchedules(filespaceId: string): Promise<SnapshotSchedule[]>
  /** `PATCH /v1/filespaces/:fs/schedules/:id` with `{ retain?, enabled? }`. */
  updateSnapshotSchedule(
    filespaceId: string,
    scheduleId: string,
    patch: { retain?: number; enabled?: boolean },
  ): Promise<void>

  /* ----- Storage credentials (org-scoped) ----- */
  /** List the org's saved storage access keys (secrets never returned). */
  listStorageCredentials(org: string): Promise<StorageCredential[]>
  /** Save a new access key; the secret is sent once and stored encrypted. */
  createStorageCredential(
    org: string,
    input: CreateStorageCredentialInput,
  ): Promise<StorageCredential>
  /**
   * Delete a saved credential. May reject with `credential_in_use` (HTTP 409)
   * carrying the filespace names still referencing it.
   */
  deleteStorageCredential(org: string, id: string): Promise<void>

  /* ----- Connection verification ----- */
  /** Probe an S3-compatible storage config for reachability + read/write/delete. */
  testStorage(org: string, input: StorageTestInput): Promise<StorageTestResult>
  getDefaultStorage(org: string): Promise<DeploymentStorage>
  validateDefaultStorage(org: string): Promise<StorageTestResult>

  /* ----- Email configuration (org-scoped; owner/admin) ----- */
  /**
   * Read the org's email configuration. Resolves `null` when no per-org override is
   * saved (the deployment default is in effect). The secret is NEVER returned.
   * `GET /v1/orgs/:org/email-config` → `{ config: EmailConfig | null }`.
   */
  getEmailConfig(org: string): Promise<EmailConfig | null>
  /**
   * Save (create or replace) the org's email configuration. The secret(s) ride in
   * the body once and are stored encrypted; the returned config never echoes them.
   * `PUT /v1/orgs/:org/email-config` → `EmailConfig`.
   */
  putEmailConfig(org: string, input: EmailConfigInput): Promise<EmailConfig>
  /** Remove the per-org override and fall back to the deployment default. */
  deleteEmailConfig(org: string): Promise<void>
  /**
   * Send a test email to `to`. May carry unsaved provider creds so the user can
   * verify BEFORE saving. `POST /v1/orgs/:org/email-config/test` → `{ sent, error? }`.
   */
  testEmailConfig(org: string, input: EmailTestInput): Promise<EmailTestResult>

  /* ----- Sign-in & authentication (org-scoped; owner/admin) ----- */
  /**
   * Read the PUBLIC sign-in config — no session required. The sign-in page calls
   * this on load to adapt: `oidc` hides the password form, `both` shows both,
   * `builtin`/null leaves the page unchanged.
   * `GET /v1/auth/config/public` → `{ mode, oidcEnabled, providerLabel? }`.
   */
  getPublicAuthConfig(): Promise<PublicAuthConfig>
  /**
   * Read the org's auth configuration (owner/admin). Resolves `null` when no OIDC
   * override is saved (built-in auth is in effect). The client secret is NEVER
   * returned. `GET /v1/orgs/:org/auth-config` → `{ config: AuthConfig | null }`.
   */
  getAuthConfig(org: string): Promise<AuthConfig | null>
  /**
   * Save (create or replace) the org's auth configuration. The OIDC client secret
   * rides in the body once and is stored encrypted; the returned config never
   * echoes it. `PUT /v1/orgs/:org/auth-config` → `AuthConfig`.
   */
  putAuthConfig(org: string, input: AuthConfigInput): Promise<AuthConfig>
  /** Remove the OIDC override and fall back to built-in auth. */
  deleteAuthConfig(org: string): Promise<void>
  /**
   * Validate an OIDC issuer BEFORE saving — fetches its discovery document and
   * resolves the endpoints. `POST /v1/orgs/:org/auth-config/validate` `{ issuer }`
   * → `{ valid, endpoints?, error? }`.
   */
  validateAuthConfig(org: string, issuer: string): Promise<AuthValidateResult>

  /* ----- Account ----- */
  updateAccount(patch: Partial<Pick<User, 'name' | 'email'>>): Promise<User>
  /** Change the signed-in account's password (revokes the account's other sessions). */
  changePassword(currentPassword: string, newPassword: string): Promise<void>
  /** Rename the caller's organization (owner/admin only). */
  updateOrg(patch: { name: string }): Promise<Organization>
  /** Begin TOTP enrollment — returns the otpauth URI to show as a QR code. */
  beginTotpEnrollment(): Promise<TotpEnrollment>
  /**
   * Confirm enrollment with a code from the authenticator app. Returns the
   * updated user and the one-time recovery codes minted by the server — these
   * are real auth credentials (usable via the recovery sign-in flow) and are
   * only returned once, so they must be surfaced to the user immediately.
   */
  confirmTotpEnrollment(code: string): Promise<{ user: User; recoveryCodes: string[] }>
  disableTotp(): Promise<User>

  /* ----- Passkeys ----- */
  listPasskeys(): Promise<Passkey[]>
  registerPasskey(label: string): Promise<Passkey>
  removePasskey(id: string): Promise<void>

  /* ----- Members & invites (B26; owner/admin) ----- */
  /** List the org's members (`GET /v1/orgs/:org/users`). */
  listMembers(org: string): Promise<Member[]>
  /**
   * Change a member's role (`PATCH /v1/orgs/:org/users/:id {role}`). The backend enforces the
   * role-transition policy (only an owner may assign owner; no last-owner removal; etc.).
   */
  setMemberRole(org: string, userId: string, role: MemberRole): Promise<void>
  /**
   * Deprovision (offboard) a member (`DELETE /v1/orgs/:org/users/:id`). Revokes their sessions +
   * service tokens and releases their email claim. Irreversible from the console.
   */
  removeMember(org: string, userId: string): Promise<void>
  /** List the org's PENDING invites (`GET /v1/orgs/:org/invites`). */
  listInvites(org: string): Promise<Invite[]>
  /**
   * Create an invite (`POST /v1/orgs/:org/invites`). The backend best-effort emails the join link
   * when a delivering `EmailSender` is configured; `CreateInviteResult.emailSent` reports whether it
   * actually went out so the console never claims "emailed" when nothing was configured to send —
   * `joinToken`/`inviteUrl` are always returned (once) so copy-link is always available as a fallback.
   * The invitable role is capped by the caller's role server-side. `input.scope`, when present,
   * additionally grants edit/read/admin access on a filespace's root (whole-filespace) on redeem.
   */
  createInvite(org: string, input: CreateInviteInput): Promise<CreateInviteResult>
  /** Revoke a pending invite (`DELETE /v1/orgs/:org/invites/:id`). */
  revokeInvite(org: string, inviteId: string): Promise<void>
}
