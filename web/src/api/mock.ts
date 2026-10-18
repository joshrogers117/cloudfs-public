/*
 * MockApi — an in-memory CloudFsApi backed by sample data, so every screen
 * renders with NO backend. Sample data mirrors the macOS app's MockFixtures:
 * org "acme", a current user, and two filespaces —
 *   "Studio A — Editorial" (Connected, Cloudflare R2, ENAM, Filespace Admin)
 *   "Archive 2025"         (Paused,    Backblaze B2 + CDN, WNAM, Standard User)
 *
 * Mutations persist for the lifetime of the page (in module state). Calls add a
 * small artificial delay so loading states are exercised. The Wire phase
 * replaces this with a real client implementing the same interface.
 */
import type { CloudFsApi } from './api'
import { CredentialInUseError } from './errors'
import { ApiError } from './http'
import { MIN_PASSWORD_LENGTH } from './types'
import { mapOrgRole } from './wire'
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
  OidcPreset,
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

const GiB = 1024 * 1024 * 1024

function delay<T>(value: T, ms = 280): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms))
}

function uid(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

/** Human label for the SSO button / status chip, from the OIDC preset id. */
function presetLabel(preset: OidcPreset): string {
  const map: Record<OidcPreset, string> = {
    clerk: 'Clerk',
    okta: 'Okta',
    entra: 'Microsoft Entra ID',
    auth0: 'Auth0',
    google: 'Google Workspace',
    generic: 'your organization',
  }
  return map[preset] ?? 'your organization'
}

/** Deep-clone an AuthConfig so callers can't mutate the mock's stored copy. */
function cloneAuthConfig(c: AuthConfig): AuthConfig {
  return c.oidc
    ? { mode: c.mode, oidc: { ...c.oidc, allowedDomains: [...c.oidc.allowedDomains] } }
    : { mode: c.mode }
}

// ----- Seed data ---------------------------------------------------------

const org: Organization = {
  id: 'org-acme',
  slug: 'acme',
  name: 'Acme Post',
}

function seedUser(): User {
  return {
    id: 'user-1',
    name: 'Alex Rivera',
    email: 'alex@acme.example',
    orgId: org.id,
    orgRole: import.meta.env.DEV && import.meta.env.VITE_DEMO_ROLE === 'Member' ? 'Member' : 'Admin',
    totpEnabled: true,
    passkeys: [
      {
        id: 'pk-1',
        label: "Alex's MacBook Pro",
        createdAt: new Date(Date.now() - 30 * 86_400_000).toISOString(),
        lastUsedAt: new Date(Date.now() - 2 * 3600_000).toISOString(),
      },
    ],
  }
}

function seedMembers(): Member[] {
  return [
    { id: 'user-1', email: 'alex@acme.example', name: 'Alex Rivera', role: 'admin', status: 'active' },
    { id: 'user-2', email: 'sam@acme.example', name: 'Sam Okafor', role: 'owner', status: 'active' },
    { id: 'user-3', email: 'jordan@acme.example', name: 'Jordan Lee', role: 'standard', status: 'active' },
  ]
}

function seedFilespaces(): Filespace[] {
  return [
    {
      id: 'fs-studio-a',
      name: 'Studio A — Editorial',
      region: 'ENAM (us-east)',
      storageBackend: 'Cloudflare R2',
      connection: 'connected',
      role: 'Filespace Admin',
      usedBytes: 14 * 1024 * GiB,
      memberCount: 22,
      mountPath: '~/Library/CloudStorage/cloud-fs-Studio A — Editorial',
    },
    {
      id: 'fs-archive',
      name: 'Archive 2025',
      region: 'WNAM (us-west)',
      storageBackend: 'Backblaze B2 + CDN',
      connection: 'paused',
      role: 'Standard User',
      usedBytes: 312 * 1024 * GiB,
      memberCount: 30,
      mountPath: '~/Library/CloudStorage/cloud-fs-Archive 2025',
    },
  ]
}

function seedDevices(): DeviceSession[] {
  return [
    {
      id: 'dev-mbp-alex',
      name: "Alex's MacBook Pro",
      model: 'MacBookPro18,3',
      createdAt: new Date(Date.now() - 12 * 86_400_000).toISOString(),
      lastSeenAt: new Date(Date.now() - 3600_000).toISOString(),
      expiresAt: new Date(Date.now() + 400 * 86_400_000).toISOString(),
    },
  ]
}

/** A plausible base64url secret half for mock device codes. */
function mockSecret(len = 43): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  let out = ''
  for (let i = 0; i < len; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)]
  return out
}

function seedCredentials(): StorageCredential[] {
  return [
    {
      id: 'cred-r2-prod',
      label: 'r2-prod-key',
      accessKeyId: 'a1b2c3d4e5f6a7b8c9d0',
      createdAt: new Date(Date.now() - 42 * 86_400_000).toISOString(),
    },
    {
      id: 'cred-b2-archive',
      label: 'b2-archive-key',
      accessKeyId: '004f2e9a1c7b3d80000000001',
      createdAt: new Date(Date.now() - 9 * 86_400_000).toISOString(),
    },
  ]
}

// ----- MockApi -----------------------------------------------------------

export class MockApi implements CloudFsApi {
  private user: User = seedUser()
  private org: Organization = { ...org }
  private filespaces: Filespace[] = seedFilespaces()
  private credentials: StorageCredential[] = seedCredentials()
  /** Per-org email override. null = "using deployment default". Starts unset. */
  private emailConfig: EmailConfig | null = null
  /** Per-org auth/OIDC override. null = built-in auth (default). Starts unset. */
  private authConfig: AuthConfig | null = null
  private session: Session | null = null
  /** Active TOTP challenges from login(); keyed by challengeId. */
  private challenges = new Map<string, string>()
  /** B26: in-memory members + pending invites (DEMO data; the real client hits OrgDO). */
  private members: Member[] = seedMembers()
  private invites: Invite[] = []
  /** Join-token (ONBOARDING.md build step 1) → invite, so previewJoin/join can resolve a /join link
   *  offline. Keyed by the same self-contained token `createInvite` hands back as `joinToken`. */
  private joinTokens = new Map<string, Invite>()
  /** Device sessions (Macs signed in through the app) for Settings → Devices. */
  private devices: DeviceSession[] = seedDevices()
  /**
   * First-run wizard state. Defaults to "already set up" so the normal mock flow
   * isn't hijacked to /setup; append `?setup-demo` to any URL to exercise the
   * wizard offline (it flips to false once the wizard completes).
   */
  private setupNeeded =
    typeof window !== 'undefined' &&
    new URLSearchParams(window.location.search).has('setup-demo')

  // A dev-only member preview survives page reloads so direct-route guards can
  // be inspected. Production and the real HTTP adapter never read this option.
  constructor() {
    if (import.meta.env.DEV && import.meta.env.VITE_DEMO_ROLE === 'Member') {
      this.filespaces = this.filespaces.map(space => ({ ...space, role: 'Standard User' }))
      this.session = this.newSession()
    }
  }

  private newSession(): Session {
    return { user: this.user, org: this.org, token: uid('tok') }
  }

  /* ----- Auth ----- */

  async signup(input: SignUpInput): Promise<Session> {
    this.user = {
      ...this.user,
      name: input.name,
      email: input.email,
      orgRole: 'Owner',
      totpEnabled: false,
      passkeys: [],
    }
    this.session = this.newSession()
    return delay(this.session)
  }

  async login(input: LoginInput): Promise<LoginResult> {
    // Mirror the backend's `hasTotp || hasWebAuthn` gate: when the account has any
    // second factor enrolled, step up to an MFA challenge (unless a TOTP code was
    // supplied up-front). `methods` advertises the factors the user actually has —
    // a passkey-only user gets `['webauthn']`, so the screen drives the passkey
    // ceremony rather than a dead TOTP form.
    const methods = this.mfaMethods()
    if (methods.length > 0 && !input.totp) {
      const challengeId = uid('chal')
      this.challenges.set(challengeId, input.email)
      return delay<LoginResult>({ kind: 'totp-required', challengeId, methods })
    }
    this.session = this.newSession()
    return delay<LoginResult>({ kind: 'session', session: this.session })
  }

  /** The second factors the seeded user has enrolled, in backend order (totp first). */
  private mfaMethods(): MfaMethod[] {
    const methods: MfaMethod[] = []
    if (this.user.totpEnabled) methods.push('totp')
    if (this.user.passkeys.length > 0) methods.push('webauthn')
    return methods
  }

  async verifyTotp(challengeId: string, code: string): Promise<Session> {
    void code
    this.challenges.delete(challengeId)
    this.session = this.newSession()
    return delay(this.session)
  }

  async loginWithRecovery(challengeId: string, recoveryCode: string): Promise<Session> {
    void recoveryCode
    this.challenges.delete(challengeId)
    this.session = this.newSession()
    return delay(this.session)
  }

  async loginWithPasskey(req: { email?: string; challengeId?: string }): Promise<Session> {
    // No real WebAuthn ceremony offline — a registered passkey asserts a session.
    void req
    this.session = this.newSession()
    return delay(this.session)
  }

  async beginSSO(returnTo?: string): Promise<Session> {
    // Offline: simulate a successful IdP round-trip in-place (no redirect).
    void returnTo
    this.session = this.newSession()
    return delay(this.session)
  }

  async completeSSO(): Promise<Session | null> {
    return delay(this.session)
  }

  async logout(): Promise<void> {
    this.session = null
    return delay(undefined)
  }

  async me(): Promise<Session | null> {
    return delay(this.session)
  }

  /* ----- First-run setup wizard (auth-spec §2.5) ----- */

  async getSetupStatus(): Promise<SetupStatus> {
    return delay({ needed: this.setupNeeded }, 150)
  }

  async setupInit(input: SetupInitInput): Promise<SetupInitResult> {
    await delay(undefined)
    // Typed ApiErrors so the wizard exercises the same error mapping as the
    // real gateway (401 secret mismatch / 409 complete / 400 weak password).
    if (!this.setupNeeded) {
      throw new ApiError(409, 'setup_complete', 'Someone already completed setup on this deployment.')
    }
    if (input.secret.trim().length < 16) {
      throw new ApiError(401, 'unauthorized', 'That setup secret didn’t match.')
    }
    if (input.password.length < MIN_PASSWORD_LENGTH) {
      throw new ApiError(
        400,
        'weak_password',
        `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`,
      )
    }
    this.org = { id: input.orgId, slug: input.orgId, name: input.orgName }
    this.user = {
      id: uid('user'),
      name: input.displayName,
      email: input.email,
      orgId: input.orgId,
      orgRole: 'Owner',
      totpEnabled: false,
      passkeys: [],
    }
    this.members = [
      { id: this.user.id, email: input.email, name: input.displayName, role: 'owner', status: 'active' },
    ]
    this.filespaces = []
    this.devices = []
    // The 201 sets the session cookie — the operator is signed in (spec §1.1.3).
    this.session = this.newSession()
    this.setupNeeded = false
    return { orgId: this.org.id, userId: this.user.id }
  }

  /**
   * Deploy-health readiness probes (ONBOARDING.md build step 5 "Health check"). The mock has no
   * real STORAGE_ENC_KEY/public-URL concept, so those two always report healthy; `email_provider`
   * mirrors `createInvite`'s own `emailSent` gate below (`this.emailConfig != null`) — a fresh mock
   * org starts with no email configured, so the wizard's health-check step demonstrates the red
   * "copy-link only" row exactly as a real fresh deployment would, with no extra demo flags needed.
   */
  async doctor(_org: string): Promise<DoctorReport> {
    void _org
    const emailOk = this.emailConfig != null
    const checks: DoctorReport['checks'] = [
      ...['default_storage_backend', 'storage_integrity', 'upload_verification', 'auth_signing_secret', 'metadata_directory_do', 'metadata_org_do', 'metadata_auth_do', 'metadata_filespace', 'audit_storage_backend'].map(name => ({ name, status: 'ok' as const, detail: 'Ready (demo)' })),
      {
        name: 'email_provider',
        status: emailOk ? 'ok' : 'warn',
        detail: emailOk
          ? `delivering via ${this.emailConfig!.provider} (mock)`
          : 'no email provider configured (mock) — verification/reset/invite mail will NOT reach users.',
      },
      {
        name: 'storage_enc_key',
        status: 'ok',
        detail: 'decodes to 32 bytes and seal→open round-trips (mock)',
      },
      {
        name: 'public_urls',
        status: 'ok',
        detail: 'no localhost-valued public URLs (mock)',
      },
    ]
    return delay({ ok: checks.every((c) => c.status !== 'fail'), isHttps: true, checks }, 200)
  }

  /* ----- Device sign-in: approve / device sessions (auth-spec §2.2 / §2.6) ----- */

  async approveDevice(input: DeviceApproveInput): Promise<DeviceApproveResult> {
    await delay(undefined)
    if (!this.session) throw new ApiError(401, 'no_session', 'Please sign in to continue.')
    // Mirror the backend validation (§2.2) so malformed links fail offline too.
    if (input.codeChallengeMethod !== 'S256') {
      throw new ApiError(400, 'bad_method', 'This sign-in link is invalid or incomplete.')
    }
    if (!/^[A-Za-z0-9_-]{43,128}$/.test(input.codeChallenge)) {
      throw new ApiError(400, 'bad_challenge', 'This sign-in link is invalid or incomplete.')
    }
    const name = input.deviceName.trim()
    if (!name || name.length > 64) {
      throw new ApiError(400, 'bad_device_name', 'This sign-in link is invalid or incomplete.')
    }
    // The approval is what will become a device session once the app exchanges
    // the code — surface it in Settings → Devices so the mock flow feels real.
    const now = Date.now()
    this.devices = [
      {
        id: uid('dev'),
        name,
        model: input.deviceModel?.trim() || undefined,
        createdAt: new Date(now).toISOString(),
        lastSeenAt: new Date(now).toISOString(),
        expiresAt: new Date(now + 400 * 86_400_000).toISOString(),
      },
      ...this.devices,
    ]
    return {
      code: `${this.org.slug}.dac-${uid('').slice(1)}.${mockSecret()}`,
      state: input.state,
      expiresInSeconds: 300,
    }
  }

  async listDevices(): Promise<DeviceSession[]> {
    return delay(this.devices.map((d) => ({ ...d })))
  }

  async revokeDevice(id: string): Promise<void> {
    // Revoked rows stay listed (flagged) for a while, mirroring the server prune.
    this.devices = this.devices.map((d) =>
      d.id === id ? { ...d, revokedAt: new Date().toISOString() } : d,
    )
    return delay(undefined)
  }

  /* ----- Email verification ----- */

  async sendVerificationEmail(): Promise<void> {
    return delay(undefined)
  }

  async confirmEmail(token: string, orgId: string): Promise<void> {
    // Offline: treat a present token+orgId as a successful confirmation. An empty
    // token (e.g. a malformed link) rejects so the failure state can be exercised.
    if (!token || !orgId) {
      return delay(undefined).then(() => {
        throw new Error('This verification link is invalid or has expired.')
      })
    }
    return delay(undefined)
  }

  async requestPasswordReset(_email: string): Promise<void> {
    void _email
    return delay(undefined)
  }

  async enrollLegacyAccount(_token: string, _orgId: string, _newPassword: string): Promise<void> {
    void _token; void _orgId; void _newPassword
    throw new Error('Account migration requires a connected CloudFS deployment.')
  }

  async resetPassword(token: string, orgId: string, newPassword: string): Promise<void> {
    if (!token || !orgId) throw new Error('This reset link is invalid or has expired.')
    if (newPassword.length < MIN_PASSWORD_LENGTH) throw new Error('Choose a longer password.')
    return delay(undefined)
  }

  /* ----- Filespaces ----- */

  async listFilespaces(): Promise<Filespace[]> {
    return delay(this.filespaces.map((f) => ({ ...f })))
  }

  async createFilespace(input: CreateFilespaceInput): Promise<Filespace> {
    const fs: Filespace = {
      id: uid('fs'),
      name: input.name,
      region: input.region,
      storageBackend: input.storageBackend,
      connection: 'connecting',
      role: 'Filespace Admin',
      usedBytes: 0,
      memberCount: 1,
      mountPath: `~/Library/CloudStorage/cloud-fs-${input.name}`,
    }
    this.filespaces = [...this.filespaces, fs]
    return delay({ ...fs })
  }

  async updateFilespace(id: string, patch: Partial<Filespace>): Promise<Filespace> {
    const idx = this.filespaces.findIndex((f) => f.id === id)
    if (idx < 0) throw new Error(`Filespace ${id} not found`)
    this.filespaces[idx] = { ...this.filespaces[idx], ...patch, id }
    return delay({ ...this.filespaces[idx] })
  }

  async deleteFilespace(id: string): Promise<void> {
    this.filespaces = this.filespaces.filter((f) => f.id !== id)
    return delay(undefined)
  }

  async purgeFilespace(id: string): Promise<void> {
    // The mock collapses the two-step model: `deleteFilespace` already removed the row, so the
    // permanent purge is an idempotent no-op here (the real backend runs an async object sweep).
    this.filespaces = this.filespaces.filter((f) => f.id !== id)
    return delay(undefined)
  }

  private schedules: SnapshotSchedule[] = [
    { id: 'default-daily', tier: 'daily', intervalMs: 86_400_000, retain: 7, enabled: true, nextRunAt: Date.now() + 86_400_000, lastRunAt: null },
    { id: 'default-weekly', tier: 'weekly', intervalMs: 604_800_000, retain: 4, enabled: true, nextRunAt: Date.now() + 604_800_000, lastRunAt: null },
  ]

  async listSnapshotSchedules(_filespaceId: string): Promise<SnapshotSchedule[]> {
    void _filespaceId
    return delay(this.schedules.map((s) => ({ ...s })))
  }

  async updateSnapshotSchedule(
    _filespaceId: string,
    scheduleId: string,
    patch: { retain?: number; enabled?: boolean },
  ): Promise<void> {
    void _filespaceId
    this.schedules = this.schedules.map((s) => (s.id === scheduleId ? { ...s, ...patch } : s))
    return delay(undefined)
  }

  async purgeFilespaceStatus(_id: string): Promise<PurgeStatus> {
    // The mock's purge completes synchronously (no real object sweep), so a follow-up poll always
    // reports "done" and never fails. Parity with the real API shape; the UI shows the success path.
    void _id
    return delay({ purging: false, done: true, failed: false, deleted: 0 })
  }

  /* ----- Storage credentials ----- */

  async listStorageCredentials(_org: string): Promise<StorageCredential[]> {
    void _org
    return delay(this.credentials.map((c) => ({ ...c })))
  }

  async createStorageCredential(
    _org: string,
    input: CreateStorageCredentialInput,
  ): Promise<StorageCredential> {
    void _org
    // The secret is accepted but intentionally discarded here — the mock never
    // stores or returns it, mirroring the write-only contract.
    const cred: StorageCredential = {
      id: uid('cred'),
      label: input.label.trim(),
      accessKeyId: input.accessKeyId.trim(),
      createdAt: new Date().toISOString(),
    }
    this.credentials = [...this.credentials, cred]
    return delay({ ...cred })
  }

  async deleteStorageCredential(_org: string, id: string): Promise<void> {
    void _org
    // Demonstrate the 409 in-use path: the seeded archive credential is pinned
    // to the seeded "Archive 2025" filespace so Delete surfaces the named-spaces
    // case in the UI; everything else deletes cleanly.
    if (id === 'cred-b2-archive') {
      return delay(undefined).then(() => {
        throw new CredentialInUseError(['Archive 2025'])
      })
    }
    this.credentials = this.credentials.filter((c) => c.id !== id)
    return delay(undefined)
  }

  /* ----- Connection verification ----- */

  async getDefaultStorage(_org: string): Promise<DeploymentStorage> {
    void _org
    return delay({ configured: true, provider: 'r2', endpoint: 'https://example.r2.cloudflarestorage.com',
      region: 'auto', bucket: 'studio-files', forcePathStyle: true, problems: [] })
  }

  async validateDefaultStorage(_org: string): Promise<StorageTestResult> {
    void _org
    return delay({ reachable: true, canWrite: true, canRead: true, canDelete: true, prefixEmpty: true })
  }

  async testStorage(_org: string, input: StorageTestInput): Promise<StorageTestResult> {
    void _org
    const bucket = input.bucket.trim()
    // A clearly-unreachable host short-circuits to an error result so the UI can
    // exercise the failure path deterministically.
    if (/unreachable|invalid|broken/i.test(input.endpoint) || !bucket) {
      return delay<StorageTestResult>({
        reachable: false,
        canWrite: false,
        canRead: false,
        canDelete: false,
        prefixEmpty: false,
        error: !bucket
          ? 'No bucket specified.'
          : 'Could not reach the storage endpoint. Check the endpoint URL and network access.',
      })
    }
    // Buckets whose name suggests existing data report a NON-empty prefix with a
    // few sample keys; everything else reports an empty, safe-to-adopt prefix.
    const nonEmpty = /archive/i.test(bucket)
    return delay<StorageTestResult>({
      reachable: true,
      canWrite: true,
      canRead: true,
      canDelete: true,
      prefixEmpty: !nonEmpty,
      sampleKeys: nonEmpty
        ? [
            `${input.keyPrefix ?? ''}blocks/3f/3fa9c2b1e0d4.blk`,
            `${input.keyPrefix ?? ''}blocks/a7/a7e10c4488f2.blk`,
            `${input.keyPrefix ?? ''}manifests/0001.json`,
          ]
        : undefined,
    })
  }

  /* ----- Email configuration ----- */

  async getEmailConfig(_org: string): Promise<EmailConfig | null> {
    void _org
    return delay(this.emailConfig ? { ...this.emailConfig } : null)
  }

  async putEmailConfig(_org: string, input: EmailConfigInput): Promise<EmailConfig> {
    void _org
    // Persist a secret-free projection — the mock accepts secrets but never stores
    // or returns them, mirroring the write-only contract.
    this.emailConfig = {
      provider: input.provider,
      fromAddress: input.fromAddress.trim(),
      fromName: input.fromName?.trim() || undefined,
      region: input.provider === 'ses' ? input.sesRegion?.trim() || undefined : undefined,
      configured: true,
    }
    return delay({ ...this.emailConfig })
  }

  async deleteEmailConfig(_org: string): Promise<void> {
    void _org
    this.emailConfig = null
    return delay(undefined)
  }

  async testEmailConfig(_org: string, input: EmailTestInput): Promise<EmailTestResult> {
    void _org
    const to = input.to.trim()
    // A clearly-invalid recipient or an "invalid" key surfaces the failure path so
    // the UI can exercise it deterministically.
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
      return delay<EmailTestResult>({ sent: false, error: 'Enter a valid recipient email address.' })
    }
    if (/invalid|broken/i.test(input.secret ?? input.sesSecretAccessKey ?? '')) {
      return delay<EmailTestResult>({
        sent: false,
        error: 'The provider rejected the credentials. Check your API key / token.',
      })
    }
    return delay<EmailTestResult>({ sent: true })
  }

  /* ----- Sign-in & authentication ----- */

  async getPublicAuthConfig(): Promise<PublicAuthConfig> {
    // §2.8 additions: the app's probe fields (display + portal discovery).
    const webBaseUrl = typeof window !== 'undefined' ? window.location.origin : undefined
    const cfg = this.authConfig
    if (!cfg || cfg.mode === 'builtin') {
      return delay<PublicAuthConfig>({
        mode: 'builtin',
        oidcEnabled: false,
        signupMode: 'open',
        webBaseUrl,
        gatewayBaseUrl: webBaseUrl,
        productName: 'cloud-fs',
        // appDownloadUrl intentionally omitted — the mock has no server config for it, so
        // GetTheAppCard falls back to VITE_APP_DOWNLOAD_URL / honest "ask your admin" copy,
        // same as a real deployment that never set APP_DOWNLOAD_URL.
      })
    }
    return delay<PublicAuthConfig>({
      mode: cfg.mode,
      oidcEnabled: Boolean(cfg.oidc),
      signupMode: 'open',
      providerLabel: cfg.oidc ? presetLabel(cfg.oidc.preset) : undefined,
      webBaseUrl,
      gatewayBaseUrl: webBaseUrl,
      productName: 'cloud-fs',
    })
  }

  async getAuthConfig(_org: string): Promise<AuthConfig | null> {
    void _org
    return delay(this.authConfig ? cloneAuthConfig(this.authConfig) : null)
  }

  async putAuthConfig(_org: string, input: AuthConfigInput): Promise<AuthConfig> {
    void _org
    // Built-in: drop any OIDC override entirely (equivalent to delete, but explicit).
    if (input.mode === 'builtin' || !input.oidc) {
      this.authConfig = { mode: 'builtin' }
      return delay(cloneAuthConfig(this.authConfig))
    }
    // Persist a secret-free projection — the mock accepts the secret but never
    // stores or returns it, mirroring the write-only contract.
    this.authConfig = {
      mode: input.mode,
      oidc: {
        preset: input.oidc.preset,
        issuer: input.oidc.issuer.trim(),
        clientId: input.oidc.clientId.trim(),
        allowedDomains: (input.oidc.allowedDomains ?? [])
          .map((d) => d.trim().toLowerCase())
          .filter(Boolean),
        autoProvision: input.oidc.autoProvision ?? false,
        configured: true,
      },
    }
    return delay(cloneAuthConfig(this.authConfig))
  }

  async deleteAuthConfig(_org: string): Promise<void> {
    void _org
    this.authConfig = null
    return delay(undefined)
  }

  async validateAuthConfig(_org: string, issuer: string): Promise<AuthValidateResult> {
    void _org
    const trimmed = issuer.trim()
    // A clearly-bad issuer surfaces the failure path deterministically.
    if (!/^https:\/\/[^\s]+\.[^\s]+/.test(trimmed) || /invalid|broken|unreachable/i.test(trimmed)) {
      return delay<AuthValidateResult>({
        valid: false,
        error:
          'Could not fetch the OpenID configuration from this issuer. Check the issuer URL — it must be HTTPS and expose /.well-known/openid-configuration.',
      })
    }
    const origin = trimmed.replace(/\/+$/, '')
    return delay<AuthValidateResult>({
      valid: true,
      endpoints: {
        issuer: origin,
        authorization: `${origin}/authorize`,
        token: `${origin}/oauth/token`,
        jwks: `${origin}/.well-known/jwks.json`,
        userinfo: `${origin}/userinfo`,
      },
    })
  }

  /* ----- Account ----- */

  async updateAccount(patch: Partial<Pick<User, 'name' | 'email'>>): Promise<User> {
    this.user = { ...this.user, ...patch }
    return delay({ ...this.user })
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    void currentPassword
    void newPassword
    return delay(undefined)
  }

  async updateOrg(patch: { name: string }): Promise<Organization> {
    this.org = { ...this.org, name: patch.name.trim() }
    if (this.session) this.session = { ...this.session, org: this.org }
    return delay({ ...this.org })
  }

  async beginTotpEnrollment(): Promise<TotpEnrollment> {
    const secret = 'JBSWY3DPEHPK3PXP'
    const label = encodeURIComponent(`cloud-fs:${this.user.email}`)
    return delay({
      secret,
      otpauthUri: `otpauth://totp/${label}?secret=${secret}&issuer=cloud-fs`,
    })
  }

  async confirmTotpEnrollment(code: string): Promise<{ user: User; recoveryCodes: string[] }> {
    void code
    this.user = { ...this.user, totpEnabled: true }
    // Plausible fixed codes so the offline UI exercises the recovery-codes view.
    const recoveryCodes = [
      'A1B2-C3D4',
      'E5F6-G7H8',
      'J9K1-L2M3',
      'N4P5-Q6R7',
      'S8T9-U1V2',
      'W3X4-Y5Z6',
      '7A8B-9C1D',
      '2E3F-4G5H',
    ]
    return delay({ user: { ...this.user }, recoveryCodes })
  }

  async disableTotp(): Promise<User> {
    this.user = { ...this.user, totpEnabled: false }
    return delay({ ...this.user })
  }

  /* ----- Passkeys ----- */

  async listPasskeys(): Promise<Passkey[]> {
    return delay(this.user.passkeys.map((p) => ({ ...p })))
  }

  async registerPasskey(label: string): Promise<Passkey> {
    const pk: Passkey = {
      id: uid('pk'),
      label,
      createdAt: new Date().toISOString(),
    }
    this.user = { ...this.user, passkeys: [...this.user.passkeys, pk] }
    return delay({ ...pk })
  }

  async removePasskey(id: string): Promise<void> {
    this.user = {
      ...this.user,
      passkeys: this.user.passkeys.filter((p) => p.id !== id),
    }
    return delay(undefined)
  }

  /* ----- Members & invites (B26) ----- */

  async redeemInvite(_input: RedeemInviteInput): Promise<void> {
    void _input
    // Mock: pretend the redeem succeeded (the real client provisions in the existing org).
    return delay(undefined)
  }

  /* ----- Invite-based join (ONBOARDING.md build step 1 / CONTRACTS-AUTH §4.8) ----- */

  private lookupJoinInvite(token: string): Invite {
    const invite = this.joinTokens.get(token)
    if (!invite) throw new ApiError(404, 'not_found', 'This invitation could not be found.')
    if (invite.status === 'revoked') throw new ApiError(410, 'revoked', 'This invitation was revoked.')
    if (invite.status === 'accepted') {
      throw new ApiError(410, 'already_used', 'This invitation was already used.')
    }
    if (new Date(invite.expiresAt).getTime() <= Date.now()) {
      throw new ApiError(410, 'expired', 'This invitation has expired.')
    }
    return invite
  }

  async previewJoin(token: string): Promise<JoinPreview> {
    await delay(undefined, 150)
    const invite = this.lookupJoinInvite(token)
    return {
      orgName: this.org.name,
      email: invite.email,
      role: invite.role,
      expiresAt: invite.expiresAt,
      invitedByName: this.user.name,
    }
  }

  async join(input: JoinInput): Promise<Session> {
    await delay(undefined)
    const invite = this.lookupJoinInvite(input.token)
    const displayName = input.displayName.trim()
    if (!displayName) throw new ApiError(400, 'invalid_display_name', 'Enter your name.')
    if (input.password.length < MIN_PASSWORD_LENGTH) {
      throw new ApiError(
        400,
        'weak_password',
        `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`,
      )
    }
    // Single-use: a second join() against the same token now sees `already_used` via lookupJoinInvite.
    invite.status = 'accepted'
    const userId = uid('user')
    this.members = [
      ...this.members,
      { id: userId, email: invite.email, name: displayName, role: invite.role, status: 'active' },
    ]
    this.user = {
      id: userId,
      name: displayName,
      email: invite.email,
      orgId: this.org.id,
      orgRole: mapOrgRole(invite.role),
      totpEnabled: false,
      passkeys: [],
    }
    this.session = this.newSession()
    return delay(this.session)
  }

  async listMembers(_org: string): Promise<Member[]> {
    void _org
    return delay(this.members.map((m) => ({ ...m })))
  }

  async setMemberRole(_org: string, userId: string, role: MemberRole): Promise<void> {
    this.members = this.members.map((m) => (m.id === userId ? { ...m, role } : m))
    return delay(undefined)
  }

  async removeMember(_org: string, userId: string): Promise<void> {
    this.members = this.members.map((m) =>
      m.id === userId ? { ...m, status: 'deprovisioned' as const } : m,
    )
    return delay(undefined)
  }

  async listInvites(_org: string): Promise<Invite[]> {
    void _org
    return delay(this.invites.filter((i) => i.status === 'pending').map((i) => ({ ...i })))
  }

  async createInvite(org: string, input: CreateInviteInput): Promise<CreateInviteResult> {
    // `input.scope` (optional whole-filespace grant) is accepted but not modeled offline — the
    // mock's grant/ACL system isn't wired up; the real backend applies it on redeem (invites.ts).
    const id = uid('inv')
    const rawToken = `${id}.${uid('secret')}`
    const joinToken = `${org}.${rawToken}`
    const now = Date.now()
    const invite: Invite = {
      id,
      email: input.email,
      role: input.role,
      status: 'pending',
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 7 * 86_400_000).toISOString(),
    }
    this.invites = [invite, ...this.invites]
    this.joinTokens.set(joinToken, invite)
    const origin = typeof window !== 'undefined' ? window.location.origin : ''
    // Mirrors the honesty gate (ONBOARDING.md step 3): "emailed" only when the org has an email
    // provider configured — a fresh mock org starts with none, so copy-link is the default demo path.
    const emailSent = this.emailConfig != null
    return delay({
      invite,
      rawToken,
      joinToken,
      emailSent,
      inviteUrl: `${origin}/join?token=${encodeURIComponent(joinToken)}`,
    })
  }

  async revokeInvite(_org: string, inviteId: string): Promise<void> {
    this.invites = this.invites.map((i) =>
      i.id === inviteId ? { ...i, status: 'revoked' as const } : i,
    )
    return delay(undefined)
  }
}
