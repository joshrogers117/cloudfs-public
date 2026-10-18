/*
 * HttpApi — the REAL CloudFsApi, talking to the cloud-fs backend gateway.
 *
 * This is the production seam implementation that MockApi stands in for offline.
 * It speaks the wire contract frozen in /CONTRACTS-AUTH.md (§4 route surface) and
 * maps the backend's wire shapes onto the app's domain types (src/api/types.ts),
 * which the screens render against. Screens never see this class — they go through
 * `getApi()`; the mock/real choice is made once in src/api/index.ts.
 *
 * Session model (CONTRACTS-AUTH §4): cookie-based browser session.
 *   - The `cfs_session` cookie is HttpOnly and set/cleared by the server, so JS
 *     never reads it. We send it by setting `credentials: 'include'` on every
 *     request.
 *   - State-changing requests (POST/DELETE) carry the double-submit CSRF value in
 *     the `X-CFS-CSRF` header. The CSRF token is NOT HttpOnly-only data — it is
 *     returned in login/me bodies (`csrf`) and we hold it in memory for the tab's
 *     lifetime, re-hydrating it from `GET /v1/auth/me` on load.
 *
 * The app's domain `token` field (Session.token) is vestigial under cookie auth;
 * we surface the CSRF token there so any screen that reads it has a real value.
 */
import type { CloudFsApi } from './api'
import { CredentialInUseError } from './errors'
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
  MfaMethod,
  Organization,
  Passkey,
  PublicAuthConfig,
  PurgeStatus,
  SnapshotSchedule,
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
} from './types'
import { MIN_PASSWORD_LENGTH } from './types'
import { mapRole, mapOrgRole, type WireSpace, spaceToFilespace } from './wire'

const CSRF_HEADER = 'X-CFS-CSRF'

/** Thrown for any non-2xx response; carries the HTTP status + backend error code. */
export class ApiError extends Error {
  readonly status: number
  /** The backend `{ "error": string }` code, when present. */
  readonly code: string | null
  /** The parsed JSON error body, when present (e.g. 409 carries `spaces[]`). */
  readonly body: unknown

  constructor(status: number, code: string | null, message: string, body?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.body = body
  }
}

/* ----- Wire shapes (CONTRACTS-AUTH §4 response bodies) ----------------------
 * Declared locally so the public domain types (types.ts) stay frozen for the
 * screen lanes; only this file knows the backend's JSON.
 */

/** `GET /v1/auth/me` → 200 (CONTRACTS-AUTH §4.2). */
interface WireMe {
  userId: string
  orgId: string
  email: string
  role: string // OrgRole vocabulary: owner|admin|space_admin|standard
  scopes?: string[]
  emailVerified: boolean
  mfa: { totp: boolean; webauthn: number }
  // Optional enrichment some gateways include; tolerated when present.
  displayName?: string
  orgName?: string
  orgSlug?: string
  // The double-submit CSRF token, so we can re-hydrate it after a page reload
  // (it lives only in memory and is otherwise lost until the next login).
  csrf?: string
}

/** Login / MFA-complete success body (CONTRACTS-AUTH §4.2). */
interface WireLoginSuccess {
  userId: string
  orgId: string
  role: string
  scopes?: string[]
  csrf: string
}

/** Login when MFA is still required (CONTRACTS-AUTH §4.2). */
interface WireMfaRequired {
  mfaRequired: true
  methods: string[]
  challengeId: string
}

type WireLoginResponse = WireLoginSuccess | WireMfaRequired

/** `POST /v1/auth/signup` → 201 (CONTRACTS-AUTH §4.1). */
interface WireSignup {
  orgId: string
  accountId: string
  userId: string
  emailSent: boolean
  csrf?: string
}

/** `GET /v1/auth/join/preview?token=…` → 200 (CONTRACTS-AUTH §4.8). */
interface WireJoinPreview {
  orgName: string | null
  email: string
  role: string
  expiresAt: number
  invitedByName: string | null
}

/** `POST /v1/auth/join` → 201 (CONTRACTS-AUTH §4.8). Full role scopes, never the reduced
 *  UNVERIFIED_SCOPES signup starts with — the invite token already proved the email. */
interface WireJoin {
  orgId: string
  accountId: string
  userId: string
  role: string
  scopes?: string[]
  emailVerified: true
  state: string
  csrf: string
}

/** WebAuthn credential, public projection (CONTRACTS-AUTH §1.4 / §4.4). */
interface WireWebAuthnCredential {
  id: string
  credentialId?: string
  label: string | null
  createdAt: number | string
  lastUsedAt: number | string | null
}

/** Saved storage credential, public projection (secret never returned). */
interface WireStorageCredential {
  id: string
  label: string
  accessKeyId: string
  createdAt: number | string
}

/**
 * `GET /v1/orgs/:org/storage-credentials` → 200 (backend API.md). The list is
 * wrapped in a `{ credentials: [...] }` envelope; a brand-new org returns
 * `{ credentials: [] }` (an empty list, NOT an error). Create returns the single
 * saved credential wrapped the same way.
 */
interface WireStorageCredentialList {
  credentials: WireStorageCredential[]
}

/** 409 body for a credential still referenced by filespaces. */
interface WireCredentialInUse {
  error?: string
  /** Filespaces (spaces) blocking deletion — names and/or ids, tolerated both. */
  spaces?: Array<string | { id?: string; name?: string }>
}

/* ----- HttpApi --------------------------------------------------------------*/

export class HttpApi implements CloudFsApi {
  private readonly base: string
  /** Double-submit CSRF token for the live cookie session (in-memory only). */
  private csrf: string | null = null
  /** Cached org id so space routes (/v1/orgs/:org/spaces) can be addressed. */
  private orgId: string | null = null
  /** Cached me() so list/update don't refetch identity on every space call. */
  private cachedMe: WireMe | null = null

  constructor(base: string) {
    // Normalize: no trailing slash; paths below all start with "/v1/...".
    this.base = base.replace(/\/+$/, '')
  }

  /* ----- transport ----- */

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    opts: { mutating?: boolean } = {},
  ): Promise<T> {
    const headers: Record<string, string> = {}
    const mutating = opts.mutating ?? method !== 'GET'
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (mutating && this.csrf) headers[CSRF_HEADER] = this.csrf

    const res = await fetch(`${this.base}${path}`, {
      method,
      headers,
      // Carry the HttpOnly cfs_session cookie on every call.
      credentials: 'include',
      body: body === undefined ? undefined : JSON.stringify(body),
    })

    if (!res.ok) throw await this.toError(res)

    if (res.status === 204) return undefined as T
    const text = await res.text()
    if (!text) return undefined as T
    return JSON.parse(text) as T
  }

  private async toError(res: Response): Promise<ApiError> {
    let code: string | null = null
    let message = `${res.status} ${res.statusText}`
    let body: unknown
    try {
      const data = (await res.json()) as { error?: string; message?: string }
      body = data
      if (typeof data.error === 'string') {
        code = data.error
        message = data.message ?? humanizeError(data.error)
      } else if (typeof data.message === 'string') {
        message = data.message
      }
    } catch {
      // non-JSON error body; keep the status line.
    }
    return new ApiError(res.status, code, message, body)
  }

  /** Resolve the caller's org id (needed for /v1/orgs/:org/spaces routes). */
  private async requireOrgId(): Promise<string> {
    if (this.orgId) return this.orgId
    const me = await this.fetchMe()
    if (!me) throw new ApiError(401, 'not_authenticated', 'Not signed in.')
    return me.orgId
  }

  private async fetchMe(): Promise<WireMe | null> {
    try {
      const me = await this.request<WireMe>('GET', '/v1/auth/me')
      this.cachedMe = me
      this.orgId = me.orgId
      // Re-hydrate the in-memory CSRF token so mutations work after a reload.
      if (me.csrf) this.csrf = me.csrf
      return me
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        this.clearSessionState()
        return null
      }
      throw err
    }
  }

  private clearSessionState() {
    this.csrf = null
    this.orgId = null
    this.cachedMe = null
  }

  private sessionFromMe(me: WireMe): Session {
    const user: User = {
      id: me.userId,
      name: me.displayName ?? me.email,
      email: me.email,
      orgId: me.orgId,
      orgRole: mapOrgRole(me.role),
      totpEnabled: me.mfa.totp,
      // Passkeys are filled lazily by listPasskeys(); me() only carries a count.
      passkeys: [],
    }
    const org: Organization = {
      id: me.orgId,
      slug: me.orgSlug ?? me.orgId,
      name: me.orgName ?? me.orgSlug ?? me.orgId,
    }
    // Under cookie auth there is no bearer token to surface; expose the CSRF
    // token (vestigial Session.token slot) so it is never an empty string.
    return { user, org, token: this.csrf ?? '' }
  }

  /* ----- Auth (CONTRACTS-AUTH §4.1 / §4.2) ----- */

  async signup(input: SignUpInput): Promise<Session> {
    const res = await this.request<WireSignup>('POST', '/v1/auth/signup', {
      orgName: input.orgName,
      email: input.email,
      password: input.password,
      displayName: input.name,
    })
    if (res.csrf) this.csrf = res.csrf
    this.orgId = res.orgId
    // Signup sets the cfs_session cookie; reflect identity via me() so the
    // returned Session matches what the app expects post-auth.
    const me = await this.fetchMe()
    if (me) return this.sessionFromMe(me)
    // Email-gated deployments may not establish a live session; synthesize a
    // minimal one from the signup response so the caller still gets a Session.
    return {
      user: {
        id: res.userId,
        name: input.name,
        email: input.email,
        orgId: res.orgId,
        orgRole: 'Owner',
        totpEnabled: false,
        passkeys: [],
      },
      org: { id: res.orgId, slug: res.orgId, name: input.orgName },
      token: this.csrf ?? '',
    }
  }

  /* ----- Invite-based join (ONBOARDING.md build step 1 / CONTRACTS-AUTH §4.8) ----- */

  async previewJoin(token: string): Promise<JoinPreview> {
    // PUBLIC — called before any session exists, from the /join page on load.
    const res = await this.request<WireJoinPreview>(
      'GET',
      `/v1/auth/join/preview?token=${encodeURIComponent(token)}`,
      undefined,
      { mutating: false },
    )
    return {
      orgName: res.orgName,
      email: res.email,
      role: res.role as MemberRole,
      expiresAt: new Date(res.expiresAt).toISOString(),
      invitedByName: res.invitedByName,
    }
  }

  async join(input: JoinInput): Promise<Session> {
    // PUBLIC + rate-limited — the invite token IS the credential, no prior session or CSRF needed.
    const res = await this.request<WireJoin>(
      'POST',
      '/v1/auth/join',
      { token: input.token, displayName: input.displayName, password: input.password },
      { mutating: false },
    )
    this.csrf = res.csrf
    this.orgId = res.orgId
    // Join sets the cfs_session cookie; reflect identity via me() so the returned Session
    // matches what the rest of the app expects post-auth (mirrors signup()/completeLogin()).
    const me = await this.fetchMe()
    if (me) return this.sessionFromMe(me)
    return {
      user: {
        id: res.userId,
        name: input.displayName,
        // Not echoed by the join response (the server never accepted it from the client either) —
        // unknown until a me() call succeeds; every real deployment has me() available post-join.
        email: '',
        orgId: res.orgId,
        orgRole: mapOrgRole(res.role),
        totpEnabled: false,
        passkeys: [],
      },
      org: { id: res.orgId, slug: res.orgId, name: '' },
      token: this.csrf ?? '',
    }
  }

  async login(input: LoginInput): Promise<LoginResult> {
    const res = await this.request<WireLoginResponse>('POST', '/v1/auth/login', {
      email: input.email,
      password: input.password,
      // org slug is not part of the frozen login contract (email is globally
      // unique → resolved server-side), so it is intentionally not sent.
    })
    if (isMfaRequired(res)) {
      // Carry the offered factors through (CONTRACTS-AUTH §4.2): the sign-in screen
      // routes a webauthn-only challenge to the passkey ceremony, not a TOTP form.
      return { kind: 'totp-required', challengeId: res.challengeId, methods: mfaMethods(res.methods) }
    }
    return { kind: 'session', session: await this.completeLogin(res) }
  }

  async verifyTotp(challengeId: string, code: string): Promise<Session> {
    const res = await this.request<WireLoginSuccess>('POST', '/v1/auth/login/totp', {
      challengeId,
      code,
    })
    return this.completeLogin(res)
  }

  /** Continue a login challenge with a recovery code (CONTRACTS-AUTH §4.2). */
  async loginWithRecovery(challengeId: string, recoveryCode: string): Promise<Session> {
    const res = await this.request<WireLoginSuccess>('POST', '/v1/auth/login/recovery', {
      challengeId,
      recoveryCode,
    })
    return this.completeLogin(res)
  }

  /** Shared tail of every session-minting flow: capture CSRF, hydrate me(). */
  private async completeLogin(res: WireLoginSuccess): Promise<Session> {
    this.csrf = res.csrf
    this.orgId = res.orgId
    const me = await this.fetchMe()
    return me ? this.sessionFromMe(me) : this.sessionFromMe(loginToMe(res))
  }

  async logout(): Promise<void> {
    try {
      await this.request<void>('POST', '/v1/auth/logout')
    } finally {
      this.clearSessionState()
    }
  }

  async me(): Promise<Session | null> {
    const me = await this.fetchMe()
    return me ? this.sessionFromMe(me) : null
  }

  /* ----- First-run setup wizard (auth-spec §2.5) ----- */

  async getSetupStatus(): Promise<SetupStatus> {
    // PUBLIC — called before any session exists (the router's fresh-deploy gate).
    const res = await this.request<Partial<SetupStatus> | null>(
      'GET',
      '/v1/setup/status',
      undefined,
      { mutating: false },
    )
    return { needed: res?.needed === true }
  }

  async setupInit(input: SetupInitInput): Promise<SetupInitResult> {
    // PUBLIC + bootstrap-secret-gated. A 201 SETS the cfs_session cookie (the
    // operator is signed in); capture csrf/orgId exactly like completeLogin so
    // follow-up mutations (e.g. the wizard's optional TOTP enroll) work.
    const res = await this.request<{
      orgId: string
      userId: string
      csrf?: string
    }>('POST', '/v1/setup/init', {
      secret: input.secret,
      orgId: input.orgId,
      orgName: input.orgName,
      email: input.email,
      displayName: input.displayName,
      password: input.password,
    })
    if (res.csrf) this.csrf = res.csrf
    this.orgId = res.orgId
    return { orgId: res.orgId, userId: res.userId }
  }

  /* ----- Device sign-in: approve / device sessions (auth-spec §2.2 / §2.6) ----- */

  async approveDevice(input: DeviceApproveInput): Promise<DeviceApproveResult> {
    // Session + CSRF gated. Belt-and-braces: re-hydrate the CSRF token if a hard
    // reload landed directly on /device/authorize without any prior me() call.
    if (!this.csrf) await this.fetchMe()
    return this.request<DeviceApproveResult>('POST', '/v1/auth/device/approve', {
      state: input.state,
      codeChallenge: input.codeChallenge,
      codeChallengeMethod: input.codeChallengeMethod,
      deviceName: input.deviceName,
      deviceModel: input.deviceModel,
    })
  }

  async listDevices(): Promise<DeviceSession[]> {
    // Session-gated read (no CSRF). `{ devices: [...] }` envelope per §2.6.
    const res = await this.request<{ devices?: WireDeviceSession[] } | null>(
      'GET',
      '/v1/auth/devices',
    )
    return (res?.devices ?? []).map(toDeviceSession)
  }

  async revokeDevice(id: string): Promise<void> {
    // Session + CSRF. Revokes the device session and cascades to its daemon
    // service token (the drive disconnects). 204 on success.
    await this.request<void>('DELETE', `/v1/auth/devices/${encodeURIComponent(id)}`)
  }

  /* ----- Organization SSO / OIDC (API.md §5: /v1/auth/oidc/*) ----- */

  /**
   * Full-page redirect the browser to the gateway's OIDC start endpoint. The IdP
   * authenticates the user and round-trips back to the gateway callback, which sets
   * the `cfs_session` cookie and redirects to the web `/auth/callback` route (see
   * `completeSSO`). This never returns — it navigates away.
   */
  async beginSSO(returnTo?: string): Promise<void> {
    const url = new URL(`${this.base}/v1/auth/oidc/start`, window.location.origin)
    if (returnTo) url.searchParams.set('returnTo', returnTo)
    window.location.assign(url.toString())
    // Navigation has been requested; resolve so callers can show a spinner. The
    // page unloads before this matters in practice.
  }

  /**
   * After the OIDC callback set the cookie and bounced back to /auth/callback,
   * hydrate the session from me(). Returns null if no cookie was established.
   */
  async completeSSO(): Promise<Session | null> {
    const me = await this.fetchMe()
    return me ? this.sessionFromMe(me) : null
  }

  /* ----- Email verification (CONTRACTS-AUTH §4.5) ----- */

  async sendVerificationEmail(): Promise<void> {
    await this.request<void>('POST', '/v1/auth/verify-email/send')
  }

  async confirmEmail(token: string, orgId: string): Promise<void> {
    // PUBLIC confirm from the email-link landing page: both token and orgId come
    // from the query string, so no session is needed (API.md §5a:
    // `POST /v1/auth/verify-email` { token, orgId } → 200 { verified:true },
    // 400/410 on a bad/expired token). CSRF isn't required for this unauthenticated
    // call, but the header is harmless when we have no session anyway.
    await this.request<{ verified: boolean }>(
      'POST',
      '/v1/auth/verify-email',
      { token, orgId },
      { mutating: false },
    )
  }

  async requestPasswordReset(email: string): Promise<void> {
    await this.request('POST', '/v1/auth/password/forgot', { email }, { mutating: false })
  }

  async enrollLegacyAccount(token: string, orgId: string, newPassword: string): Promise<void> {
    try {
      await this.request('POST', '/v1/auth/password/enroll-legacy', { token, orgId, newPassword }, { mutating: false })
    } catch (error) {
      if (error instanceof ApiError && error.code === 'invalid_enrollment') {
        throw new Error('This sign-in link has expired or was already used. Ask your deployment administrator for a new link.', { cause: error })
      }
      throw error
    }
  }

  async resetPassword(token: string, orgId: string, newPassword: string): Promise<void> {
    try {
      await this.request('POST', '/v1/auth/password/reset', { token, orgId, newPassword }, { mutating: false })
      this.clearSessionState()
    } catch (error) {
      if (error instanceof ApiError && ['invalid_token', 'expired', 'already_used', 'not_found', 'wrong_purpose'].includes(error.code ?? '')) {
        throw new Error('This reset link is invalid, expired, or already used. Request a new link.', { cause: error })
      }
      throw error
    }
  }

  /* ----- Filespaces → backend "spaces" (CONTRACTS / spaces routes) ----- */

  async listFilespaces(): Promise<Filespace[]> {
    const org = await this.requireOrgId()
    const spaces = await this.request<WireSpace[]>('GET', `/v1/orgs/${org}/spaces`)
    const role = mapRole(this.cachedMe?.role)
    return spaces.map((s) => spaceToFilespace(s, role))
  }

  async createFilespace(input: CreateFilespaceInput): Promise<Filespace> {
    const org = await this.requireOrgId()
    const space = await this.request<WireSpace>(
      'POST',
      `/v1/orgs/${org}/spaces`,
      filespaceCreateBody(input),
    )
    return spaceToFilespace(space, mapRole(this.cachedMe?.role))
  }

  async updateFilespace(id: string, patch: Partial<Filespace>): Promise<Filespace> {
    const org = await this.requireOrgId()
    const space = await this.request<WireSpace>(
      'PATCH',
      `/v1/orgs/${org}/spaces/${id}`,
      filespacePatchBody(patch),
      { mutating: true },
    )
    return spaceToFilespace(space, mapRole(this.cachedMe?.role))
  }

  async deleteFilespace(id: string): Promise<void> {
    const org = await this.requireOrgId()
    await this.request<void>('DELETE', `/v1/orgs/${org}/spaces/${id}`)
  }

  async purgeFilespace(id: string): Promise<void> {
    const org = await this.requireOrgId()
    // The backend confirmation token is the EXACT space id (it must match the path :id). The web
    // UI gates the human on typing the filespace NAME; the wire confirm carries the id. A 409
    // (must_soft_delete_first) / 400 (confirmation_required) / 403 (owner) surface as ApiError.
    await this.request<void>(
      'POST',
      `/v1/orgs/${org}/spaces/${id}/purge`,
      { confirm: id },
      { mutating: true },
    )
  }

  async listSnapshotSchedules(filespaceId: string): Promise<SnapshotSchedule[]> {
    const res = await this.request<{ schedules?: SnapshotSchedule[] }>(
      'GET',
      `/v1/filespaces/${encodeURIComponent(filespaceId)}/schedules`,
    )
    return res?.schedules ?? []
  }

  async updateSnapshotSchedule(
    filespaceId: string,
    scheduleId: string,
    patch: { retain?: number; enabled?: boolean },
  ): Promise<void> {
    await this.request(
      'PATCH',
      `/v1/filespaces/${encodeURIComponent(filespaceId)}/schedules/${encodeURIComponent(scheduleId)}`,
      patch,
    )
  }

  async purgeFilespaceStatus(id: string): Promise<PurgeStatus> {
    const org = await this.requireOrgId()
    // Backend GET .../purge → { id, purging, done, failed, deleted, prefix, error? }. We project to
    // the client-facing PurgeStatus (the prefix is operator-only and not surfaced in the web UI).
    const s = await this.request<{
      purging?: boolean
      done?: boolean
      failed?: boolean
      deleted?: number
      error?: string
    }>('GET', `/v1/orgs/${org}/spaces/${id}/purge`)
    return {
      purging: !!s.purging,
      done: !!s.done,
      failed: !!s.failed,
      deleted: s.deleted ?? 0,
      ...(s.error ? { error: s.error } : {}),
    }
  }

  /* ----- Storage credentials (/v1/orgs/:org/storage-credentials) ----- */

  async listStorageCredentials(org: string): Promise<StorageCredential[]> {
    // Backend returns a `{ credentials: [...] }` envelope (API.md §5c). A brand-new
    // org returns `{ credentials: [] }` — an empty list, which must surface as the
    // calm empty state, NOT an error. (Tolerate a bare array too, defensively.)
    const res = await this.request<WireStorageCredentialList | WireStorageCredential[]>(
      'GET',
      `/v1/orgs/${org}/storage-credentials`,
    )
    const creds = Array.isArray(res) ? res : (res?.credentials ?? [])
    return creds.map(toStorageCredential)
  }

  async createStorageCredential(
    org: string,
    input: CreateStorageCredentialInput,
  ): Promise<StorageCredential> {
    const cred = await this.request<WireStorageCredential>(
      'POST',
      `/v1/orgs/${org}/storage-credentials`,
      {
        label: input.label,
        accessKeyId: input.accessKeyId,
        secretAccessKey: input.secretAccessKey,
      },
    )
    return toStorageCredential(cred)
  }

  async deleteStorageCredential(org: string, id: string): Promise<void> {
    try {
      await this.request<void>('DELETE', `/v1/orgs/${org}/storage-credentials/${id}`)
    } catch (err) {
      // Translate the 409 in-use contract into a typed error carrying the
      // blocking filespace names, so the UI can name them.
      if (err instanceof ApiError && err.status === 409) {
        throw new CredentialInUseError(inUseSpaces(err))
      }
      throw err
    }
  }

  /* ----- Connection verification (/v1/orgs/:org/storage/test) ----- */

  async getDefaultStorage(org: string): Promise<DeploymentStorage> {
    return this.request<DeploymentStorage>('GET', `/v1/orgs/${encodeURIComponent(org)}/storage/default`)
  }

  async validateDefaultStorage(org: string): Promise<StorageTestResult> {
    return this.request<StorageTestResult>('POST', `/v1/orgs/${encodeURIComponent(org)}/storage/default/validate`, {})
  }

  async testStorage(org: string, input: StorageTestInput): Promise<StorageTestResult> {
    return this.request<StorageTestResult>('POST', `/v1/orgs/${org}/storage/test`, input)
  }

  /* ----- Email configuration (/v1/orgs/:org/email-config) ----- */

  async getEmailConfig(org: string): Promise<EmailConfig | null> {
    // Contract: `{ config: EmailConfig | null }`. A null config means "using the
    // deployment default" — surface it as the calm unset state, not an error.
    const res = await this.request<{ config: EmailConfig | null }>(
      'GET',
      `/v1/orgs/${org}/email-config`,
    )
    return res?.config ?? null
  }

  async putEmailConfig(org: string, input: EmailConfigInput): Promise<EmailConfig> {
    // Send only the keys the contract names; omit empty secrets so a re-save that
    // leaves the secret blank keeps the previously-stored one server-side.
    const body: Record<string, unknown> = {
      provider: input.provider,
      fromAddress: input.fromAddress,
      fromName: input.fromName || undefined,
      secret: input.secret || undefined,
      sesAccessKeyId: input.sesAccessKeyId || undefined,
      sesSecretAccessKey: input.sesSecretAccessKey || undefined,
      sesRegion: input.sesRegion || undefined,
    }
    return this.request<EmailConfig>('PUT', `/v1/orgs/${org}/email-config`, body)
  }

  async deleteEmailConfig(org: string): Promise<void> {
    await this.request<void>('DELETE', `/v1/orgs/${org}/email-config`)
  }

  async testEmailConfig(org: string, input: EmailTestInput): Promise<EmailTestResult> {
    // `{ to, ...optional unsaved creds }` → `{ sent, error? }`. Omit empty optionals
    // so an already-saved config is tested as-is when only `to` is provided.
    const body: Record<string, unknown> = {
      to: input.to,
      provider: input.provider || undefined,
      fromAddress: input.fromAddress || undefined,
      fromName: input.fromName || undefined,
      secret: input.secret || undefined,
      sesAccessKeyId: input.sesAccessKeyId || undefined,
      sesSecretAccessKey: input.sesSecretAccessKey || undefined,
      sesRegion: input.sesRegion || undefined,
    }
    return this.request<EmailTestResult>('POST', `/v1/orgs/${org}/email-config/test`, body)
  }

  /* ----- Sign-in & authentication (/v1/auth/config, /v1/orgs/:org/auth-config) ----- */

  async getPublicAuthConfig(): Promise<PublicAuthConfig> {
    // PUBLIC — no session needed (the sign-in page calls it signed-out). Tolerate a
    // missing body by defaulting to built-in so the page is never blocked.
    const res = await this.request<Partial<PublicAuthConfig> | null>(
      'GET',
      '/v1/auth/config/public',
      undefined,
      { mutating: false },
    )
    return {
      mode: res?.mode ?? 'builtin',
      oidcEnabled: res?.oidcEnabled ?? false,
      passkeysEnabled: res?.passkeysEnabled ?? false,
      signupMode: res?.signupMode ?? 'closed',
      providerLabel: res?.providerLabel,
      // auth-spec §2.8 additions (tolerated absent on older gateways).
      webBaseUrl: res?.webBaseUrl,
      gatewayBaseUrl: res?.gatewayBaseUrl,
      productName: res?.productName,
      // ONBOARDING.md build step 6 (tolerated absent on a deployment with no APP_DOWNLOAD_URL set).
      appDownloadUrl: res?.appDownloadUrl,
    }
  }

  async getAuthConfig(org: string): Promise<AuthConfig | null> {
    // Contract: `{ config: AuthConfig | null }`. A null config means built-in auth
    // (default) — surface it as the calm unset state, not an error.
    const res = await this.request<{ config: AuthConfig | null }>(
      'GET',
      `/v1/orgs/${org}/auth-config`,
    )
    return res?.config ?? null
  }

  async putAuthConfig(org: string, input: AuthConfigInput): Promise<AuthConfig> {
    // Send only the contract keys; omit an empty secret so a re-save that leaves
    // the secret blank keeps the previously-stored one server-side.
    const body: Record<string, unknown> = { mode: input.mode }
    if (input.oidc) {
      body.oidc = {
        preset: input.oidc.preset,
        issuer: input.oidc.issuer,
        clientId: input.oidc.clientId,
        clientSecret: input.oidc.clientSecret || undefined,
        allowedDomains: input.oidc.allowedDomains,
        autoProvision: input.oidc.autoProvision,
      }
    }
    return this.request<AuthConfig>('PUT', `/v1/orgs/${org}/auth-config`, body)
  }

  async deleteAuthConfig(org: string): Promise<void> {
    await this.request<void>('DELETE', `/v1/orgs/${org}/auth-config`)
  }

  async validateAuthConfig(org: string, issuer: string): Promise<AuthValidateResult> {
    return this.request<AuthValidateResult>(
      'POST',
      `/v1/orgs/${org}/auth-config/validate`,
      { issuer },
    )
  }

  /* ----- Account (CONTRACTS-AUTH §4.2) ----- */

  /**
   * Change the signed-in account's password (CONTRACTS-AUTH §4.2:
   * `POST /v1/auth/password/change`, session + CSRF). Per the contract this revokes
   * the account's OTHER live sessions and keeps the current one.
   */
  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.request<void>('POST', '/v1/auth/password/change', {
      currentPassword,
      newPassword,
    })
  }

  /**
   * Update profile fields (display name / email).
   *
   * PATCH /v1/auth/account updates the account and directory in the gateway.
   */
  async updateAccount(patch: Partial<Pick<User, 'name' | 'email'>>): Promise<User> {
    await this.request<void>('PATCH', '/v1/auth/account', {
      displayName: patch.name,
      email: patch.email,
    })
    const me = await this.fetchMe()
    if (!me) throw new ApiError(401, 'not_authenticated', 'Session expired.')
    return this.sessionFromMe(me).user
  }

  /**
   * Rename the caller's organization.
   *
   * PATCH /v1/orgs/:org is owner/admin gated and persists the workspace name.
   */
  async updateOrg(patch: { name: string }): Promise<Organization> {
    const org = await this.requireOrgId()
    await this.request<void>('PATCH', `/v1/orgs/${org}`, { name: patch.name })
    const me = await this.fetchMe()
    if (!me) throw new ApiError(401, 'not_authenticated', 'Session expired.')
    return this.sessionFromMe(me).org
  }

  /* ----- TOTP (CONTRACTS-AUTH §4.3) ----- */

  async beginTotpEnrollment(): Promise<TotpEnrollment> {
    return this.request<TotpEnrollment>('POST', '/v1/auth/totp/enroll')
  }

  async confirmTotpEnrollment(code: string): Promise<{ user: User; recoveryCodes: string[] }> {
    // The server mints the one-time recovery codes here and returns them exactly
    // once (CONTRACTS-AUTH §4.3). They are real auth credentials consumed by the
    // recovery sign-in flow (`loginWithRecovery`), so they must be returned to the
    // caller and shown to the user — never discarded or fabricated client-side.
    const res = await this.request<{ confirmed: boolean; recoveryCodes: string[] }>(
      'POST',
      '/v1/auth/totp/confirm',
      { code },
    )
    const me = await this.fetchMe()
    if (!me) throw new ApiError(401, 'not_authenticated', 'Session expired.')
    return { user: this.sessionFromMe(me).user, recoveryCodes: res.recoveryCodes ?? [] }
  }

  async disableTotp(): Promise<User> {
    await this.request<void>('DELETE', '/v1/auth/totp')
    const me = await this.fetchMe()
    if (!me) throw new ApiError(401, 'not_authenticated', 'Session expired.')
    return this.sessionFromMe(me).user
  }

  /* ----- Passkeys / WebAuthn (CONTRACTS-AUTH §4.4) ----- */

  async listPasskeys(): Promise<Passkey[]> {
    const creds = await this.request<WireWebAuthnCredential[]>(
      'GET',
      '/v1/auth/webauthn/credentials',
    )
    return creds.map(toPasskey)
  }

  async registerPasskey(label: string): Promise<Passkey> {
    // Two-leg WebAuthn REGISTRATION ceremony (CONTRACTS-AUTH §4.4 / API.md §5a):
    //   1. POST register/options → PublicKeyCredentialCreationOptionsJSON + challengeId
    //   2. navigator.credentials.create() with the parsed options
    //   3. POST register/verify { challengeId, response, label }
    // The challenge in the options is base64url; createCredential parses it to an
    // ArrayBuffer for the browser, and credentialToJSON re-encodes the attestation.
    const opts = await this.request<PublicKeyCredentialCreationOptionsJSON & { challengeId: string }>(
      'POST',
      '/v1/auth/webauthn/register/options',
    )
    const { challengeId, ...options } = opts
    const attestation = await createCredential(options)
    const created = await this.request<{ credentialId: string; label: string | null }>(
      'POST',
      '/v1/auth/webauthn/register/verify',
      { challengeId, response: attestation, label },
    )
    return {
      id: created.credentialId,
      label: created.label ?? label,
      createdAt: new Date().toISOString(),
    }
  }

  async removePasskey(id: string): Promise<void> {
    await this.request<void>('DELETE', `/v1/auth/webauthn/credentials/${id}`)
  }

  /**
   * Passwordless / second-factor WebAuthn sign-in (CONTRACTS-AUTH §4.4 / API.md §5a):
   *   1. POST authenticate/options { email? | challengeId? } → request options + challengeId
   *   2. navigator.credentials.get() with the parsed (base64url→ArrayBuffer) options
   *   3. POST authenticate/verify { challengeId, response } → session cookie + body
   * `{ email }` = passwordless; `{ challengeId }` = a passkey 2nd-factor after a password.
   */
  async loginWithPasskey(req: { email?: string; challengeId?: string }): Promise<Session> {
    const opts = await this.request<PublicKeyCredentialRequestOptionsJSON & { challengeId: string }>(
      'POST',
      '/v1/auth/webauthn/authenticate/options',
      req,
    )
    const { challengeId, ...options } = opts
    const assertion = await getAssertion(options)
    const res = await this.request<WireLoginSuccess>(
      'POST',
      '/v1/auth/webauthn/authenticate/verify',
      { challengeId, response: assertion },
    )
    return this.completeLogin(res)
  }

  /* ----- Members & invites (B26) ----- */

  /**
   * Join an EXISTING org via an invite token. The public redeem route is unauthenticated (the token
   * is the credential), so this needs NO session/CSRF. It provisions the member in the org; the
   * member still signs in afterwards (the redeem doesn't establish a session here).
   */
  async redeemInvite(input: RedeemInviteInput): Promise<void> {
    await this.request<unknown>('POST', `/v1/orgs/${input.org}/invites/redeem`, {
      token: input.token,
      displayName: input.name,
    })
  }

  async listMembers(org: string): Promise<Member[]> {
    const rows = await this.request<WireUser[]>('GET', `/v1/orgs/${org}/users`)
    // Service accounts surface in the same list; the members surface only shows human members.
    return rows
      .filter((u) => !u.email.endsWith(`@svc.${org}`) && !u.email.includes('@svc.'))
      .map(wireUserToMember)
  }

  async setMemberRole(org: string, userId: string, role: MemberRole): Promise<void> {
    await this.request<unknown>('PATCH', `/v1/orgs/${org}/users/${encodeURIComponent(userId)}`, { role })
  }

  async removeMember(org: string, userId: string): Promise<void> {
    await this.request<void>('DELETE', `/v1/orgs/${org}/users/${encodeURIComponent(userId)}`)
  }

  async listInvites(org: string): Promise<Invite[]> {
    const rows = await this.request<WireInvite[]>('GET', `/v1/orgs/${org}/invites`)
    return rows.map(wireInviteToInvite)
  }

  async createInvite(org: string, input: CreateInviteInput): Promise<CreateInviteResult> {
    const res = await this.request<{
      invite: WireInvite
      rawToken: string
      joinToken: string
      emailSent: boolean
    }>('POST', `/v1/orgs/${org}/invites`, {
      email: input.email,
      role: input.role,
      // Optional whole-filespace ACL grant (ONBOARDING.md build step 5 "Invite the team").
      // "root" is the filespace's namespace anchor (backend/src/filespace-do.ts seedIfEmpty) —
      // a grant there inherits down the entire tree, i.e. "access to this filespace".
      scope: input.scope ? { spaceId: input.scope.spaceId, inodeId: 'root', level: input.scope.level } : undefined,
    })
    return {
      invite: wireInviteToInvite(res.invite),
      rawToken: res.rawToken,
      joinToken: res.joinToken,
      emailSent: res.emailSent,
      inviteUrl: buildJoinUrl(res.joinToken),
    }
  }

  async revokeInvite(org: string, inviteId: string): Promise<void> {
    await this.request<unknown>('DELETE', `/v1/orgs/${org}/invites/${encodeURIComponent(inviteId)}`)
  }

  /* ----- Deploy-health doctor (ONBOARDING.md build step 5 "Health check") ----- */

  async doctor(org: string): Promise<DoctorReport> {
    return this.request<DoctorReport>('GET', `/v1/orgs/${org}/doctor`, undefined, { mutating: false })
  }
}

/* ----- Members & invites wire shapes (B26) ----- */

/** `GET /v1/orgs/:org/users` row (org-do.ts `User`). */
interface WireUser {
  id: string
  email: string
  displayName: string
  role: MemberRole
  status: 'active' | 'suspended' | 'deprovisioned'
}

/** `GET /v1/orgs/:org/invites` row (org-do.ts `InviteRecord`; the hash/scope fields are ignored). */
interface WireInvite {
  id: string
  email: string
  role: MemberRole
  status: 'pending' | 'accepted' | 'revoked' | 'expired'
  createdAt: number
  expiresAt: number
}

function wireUserToMember(u: WireUser): Member {
  return { id: u.id, email: u.email, name: u.displayName, role: u.role, status: u.status }
}

function wireInviteToInvite(i: WireInvite): Invite {
  return {
    id: i.id,
    email: i.email,
    role: i.role,
    status: i.status,
    createdAt: new Date(i.createdAt).toISOString(),
    expiresAt: new Date(i.expiresAt).toISOString(),
  }
}

/**
 * Build the shareable join link from the current origin (the SPA is served same-origin per B9).
 * `joinToken` is org-qualified and self-contained (ONBOARDING.md build step 1) — unlike the old
 * `/signup?org=&invite=` shape, `/join?token=` needs no separate org id.
 */
function buildJoinUrl(joinToken: string): string {
  const origin = typeof window !== 'undefined' ? window.location.origin : ''
  return `${origin}/join?token=${encodeURIComponent(joinToken)}`
}

/* ----- pure mappers / helpers (no `this`) ----------------------------------*/

function isMfaRequired(res: WireLoginResponse): res is WireMfaRequired {
  return (res as WireMfaRequired).mfaRequired === true
}

/**
 * Normalize the backend's `methods` array onto the app's `MfaMethod` union, keeping
 * only the factors the sign-in screen knows how to drive. Defaults to `['totp']`
 * when the field is absent/empty so older gateways still surface the TOTP form.
 */
function mfaMethods(methods: string[] | undefined): MfaMethod[] {
  const known = (methods ?? []).filter((m): m is MfaMethod => m === 'totp' || m === 'webauthn')
  return known.length > 0 ? known : ['totp']
}

function loginToMe(res: WireLoginSuccess): WireMe {
  return {
    userId: res.userId,
    orgId: res.orgId,
    email: '',
    role: res.role,
    scopes: res.scopes,
    emailVerified: true,
    mfa: { totp: false, webauthn: 0 },
  }
}

function toPasskey(c: WireWebAuthnCredential): Passkey {
  return {
    id: c.id,
    label: c.label ?? 'Passkey',
    createdAt: toIso(c.createdAt),
    lastUsedAt: c.lastUsedAt == null ? undefined : toIso(c.lastUsedAt),
  }
}

/** `GET /v1/auth/devices` row (auth-spec §2.6) — epoch-ms timestamps. */
interface WireDeviceSession {
  id: string
  name: string
  model?: string | null
  createdAt: number | string
  lastSeenAt: number | string
  expiresAt: number | string
  revokedAt?: number | string | null
}

function toDeviceSession(d: WireDeviceSession): DeviceSession {
  return {
    id: d.id,
    name: d.name,
    model: d.model ?? undefined,
    createdAt: toIso(d.createdAt),
    lastSeenAt: toIso(d.lastSeenAt),
    expiresAt: toIso(d.expiresAt),
    revokedAt: d.revokedAt == null ? undefined : toIso(d.revokedAt),
  }
}

function toStorageCredential(c: WireStorageCredential): StorageCredential {
  return {
    id: c.id,
    label: c.label,
    accessKeyId: c.accessKeyId,
    createdAt: toIso(c.createdAt),
  }
}

/** Best-effort extraction of the blocking filespaces from a 409 in-use body. */
function inUseSpaces(err: ApiError): string[] {
  const spaces = (err.body as WireCredentialInUse | undefined)?.spaces
  if (!Array.isArray(spaces)) return []
  return spaces
    .map((s) => (typeof s === 'string' ? s : (s.name ?? s.id ?? '')))
    .filter((s): s is string => s.length > 0)
}

function toIso(v: number | string): string {
  if (typeof v === 'number') return new Date(v).toISOString()
  // Already ISO, or an epoch-ms string.
  const n = Number(v)
  return Number.isFinite(n) && String(n) === v ? new Date(n).toISOString() : v
}

/** Map the web's display backend label back to the backend provider key. */
const PROVIDER_KEYS: Record<string, string> = {
  'cloudflare r2': 'r2',
  'aws s3': 's3',
  'backblaze b2': 'b2',
  minio: 'minio',
  wasabi: 'wasabi',
}

function providerKey(label: string | undefined): string {
  if (!label) return 'r2'
  return PROVIDER_KEYS[label.trim().toLowerCase()] ?? label.trim().toLowerCase()
}

/**
 * Body for creating a space. The screen projects its rich StorageConfig down to
 * CreateFilespaceInput (storage.ts → toCreateInput); we map that onto the backend's
 * `registerSpace` shape (org-do.ts) so the per-space S3 fields — endpoint, region,
 * bucket, path-style, and the saved-credential ref — round-trip on create and are
 * returned by GET (spaceToFilespace reads them back). `keyPrefix` defaults to the
 * space prefix convention; `bucketName` mirrors the storage bucket for display.
 */
function filespaceCreateBody(input: CreateFilespaceInput): Record<string, unknown> {
  if (input.storageMode === 'deployment') return { name: input.name, storageMode: 'deployment' }
  const provider = providerKey(input.storageBackend)
  return {
    name: input.name,
    // Descriptive registry metadata (org-do.ts requires these).
    bucketProvider: provider,
    bucketName: input.storageBucket ?? '',
    keyPrefix: '',
    // Display label so GET can echo it without re-deriving from the provider.
    storageBackend: input.storageBackend,
    // Secret-free per-space S3 override (presigner reads these). Omit undefineds so
    // an unspecified field inherits the deployment-default backend.
    storageEndpoint: input.storageEndpoint,
    storageRegion: input.region,
    storageBucket: input.storageBucket,
    storageForcePathStyle: input.storageForcePathStyle,
    storageCredentialRef: input.credentialId,
  }
}

/** Patch body: only send the fields the screen actually changed. */
function filespacePatchBody(patch: Partial<Filespace>): Record<string, unknown> {
  const body: Record<string, unknown> = {}
  if (patch.name !== undefined) body.name = patch.name
  if (patch.region !== undefined) body.storageRegion = patch.region
  if (patch.storageBackend !== undefined) body.storageBackend = patch.storageBackend
  return body
}

function humanizeError(code: string): string {
  const map: Record<string, string> = {
    email_taken: 'That email is already in use.',
    invalid_credentials: 'Incorrect email or password.',
    not_authenticated: 'Please sign in to continue.',
    mfa_required: 'A verification code is required.',
    invalid_code: 'That code is incorrect or has expired.',
    rate_limited: 'Too many attempts. Try again shortly.',
    // First-run setup + device-handoff lanes (auth-spec §2.2 / §2.5).
    setup_complete: 'Someone already completed setup on this deployment.',
    weak_password: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`,
    bad_challenge: 'This sign-in link is invalid or incomplete.',
    bad_method: 'This sign-in link is invalid or incomplete.',
    bad_device_name: 'This sign-in link is invalid or incomplete.',
    no_session: 'Please sign in to continue.',
    // Invite-based join (ONBOARDING.md build step 1 / CONTRACTS-AUTH §4.8).
    invalid_token: 'This invite link doesn’t look right.',
    token_mismatch: 'This invite link doesn’t look right.',
    invalid_display_name: 'Enter your name.',
    password_too_long: 'That password is too long.',
    password_breached: 'That password has appeared in a known data breach. Choose a different one.',
    not_found: 'This invitation could not be found.',
    expired: 'This invitation has expired.',
    revoked: 'This invitation was revoked.',
    already_used: 'This invitation was already used.',
    auth_mode_oidc: 'This organization signs in with single sign-on (SSO).',
    join_incomplete: 'We hit a snag finishing your account setup.',
    // Filespace creation (ONBOARDING.md "Key model" — build step 2): the master key is generated
    // server-side at creation time and fails closed without STORAGE_ENC_KEY. The health-check step
    // should catch this earlier, but surface it clearly here too if it's hit directly.
    storage_enc_key_unconfigured:
      'Storage encryption isn’t configured on this deployment yet. An admin needs to set STORAGE_ENC_KEY before a filespace can be created.',
  }
  return map[code] ?? code.replace(/_/g, ' ')
}

/* ----- WebAuthn browser glue (only reached on the real path) ---------------*/

async function createCredential(
  options: PublicKeyCredentialCreationOptionsJSON,
): Promise<Record<string, unknown>> {
  const w = globalThis as unknown as {
    PublicKeyCredential?: { parseCreationOptionsFromJSON?: (o: unknown) => PublicKeyCredentialCreationOptions }
  }
  const publicKey = w.PublicKeyCredential?.parseCreationOptionsFromJSON
    ? w.PublicKeyCredential.parseCreationOptionsFromJSON(options)
    : (decodeCreationOptions(options) as PublicKeyCredentialCreationOptions)
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null
  if (!cred) throw new ApiError(0, 'webauthn_cancelled', 'Passkey registration was cancelled.')
  return credentialToJSON(cred)
}

async function getAssertion(
  options: PublicKeyCredentialRequestOptionsJSON,
): Promise<Record<string, unknown>> {
  const w = globalThis as unknown as {
    PublicKeyCredential?: { parseRequestOptionsFromJSON?: (o: unknown) => PublicKeyCredentialRequestOptions }
  }
  const publicKey = w.PublicKeyCredential?.parseRequestOptionsFromJSON
    ? w.PublicKeyCredential.parseRequestOptionsFromJSON(options)
    : (decodeRequestOptions(options) as PublicKeyCredentialRequestOptions)
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null
  if (!cred) throw new ApiError(0, 'webauthn_cancelled', 'Passkey sign-in was cancelled.')
  return credentialToJSON(cred)
}

/** Serialize a PublicKeyCredential to the JSON the gateway expects. */
function credentialToJSON(cred: PublicKeyCredential): Record<string, unknown> {
  const asJSON = (cred as unknown as { toJSON?: () => unknown }).toJSON
  if (typeof asJSON === 'function') return asJSON.call(cred) as Record<string, unknown>
  // Fallback for browsers without credential.toJSON(): hand-encode.
  const r = cred.response as AuthenticatorResponse & {
    attestationObject?: ArrayBuffer
    authenticatorData?: ArrayBuffer
    signature?: ArrayBuffer
    userHandle?: ArrayBuffer | null
  }
  return {
    id: cred.id,
    rawId: b64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64url(r.clientDataJSON),
      attestationObject: r.attestationObject ? b64url(r.attestationObject) : undefined,
      authenticatorData: r.authenticatorData ? b64url(r.authenticatorData) : undefined,
      signature: r.signature ? b64url(r.signature) : undefined,
      userHandle: r.userHandle ? b64url(r.userHandle) : undefined,
    },
  }
}

function decodeCreationOptions(o: PublicKeyCredentialCreationOptionsJSON): unknown {
  return {
    ...o,
    challenge: ub64url(o.challenge),
    user: { ...o.user, id: ub64url(o.user.id) },
    excludeCredentials: o.excludeCredentials?.map((c) => ({ ...c, id: ub64url(c.id) })),
  }
}

function decodeRequestOptions(o: PublicKeyCredentialRequestOptionsJSON): unknown {
  return {
    ...o,
    challenge: ub64url(o.challenge),
    allowCredentials: o.allowCredentials?.map((c) => ({ ...c, id: ub64url(c.id) })),
  }
}

function b64url(buf: ArrayBuffer): string {
  let s = ''
  const bytes = new Uint8Array(buf)
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function ub64url(s: string): ArrayBuffer {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad)
  const out = new Uint8Array(b.length)
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i)
  return out.buffer
}
