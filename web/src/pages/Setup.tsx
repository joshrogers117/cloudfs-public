/*
 * Setup — the first-run wizard for a fresh deployment (ONBOARDING.md "Admin journey";
 * auth-spec §1.1 / §2.5, W3; ONBOARDING.md build step 5 extends the original 3 steps).
 *
 * Gated by GET /v1/setup/status: when setup is already complete the page
 * self-hides ("This deployment is already set up. [Go to sign in]"). Steps:
 *
 *   1 of 6 "Unlock setup"  — the BOOTSTRAP_SECRET, held in PAGE MEMORY only and
 *           submitted exactly once with step 2 (no secret-echo round trip, no
 *           storage — auth-spec §5.4). Step 1 → 2 is purely client-side.
 *   2 of 6 "Create your workspace & admin" — org name + immutable slug +
 *           admin email/display name/password (shared strength meter). POSTs
 *           /v1/setup/init; a 201 sets the session cookie — the operator is
 *           SIGNED IN from here on.
 *   3 of 6 "Protect this account" — optional TOTP enrollment via the shared
 *           TotpEnrollFlow (same UI as AccountSettings), with an equally
 *           prominent skip (no dark patterns).
 *   4 of 6 "Health check" (build step 5, new) — runs the SAME readiness probes as
 *           the deploy-time doctor (admin-doctor.ts) inline, from this now-signed-in
 *           session (`GET /v1/orgs/:org/doctor` — the BOOTSTRAP_SECRET is long gone
 *           from page memory by now). Advances silently when all checks pass;
 *           issues show repair steps and retry, required failures block Continue.
 *   5 of 6 "First filespace" (build step 5, new) — embeds the SAME creation form as
 *           /filespaces/new (`FilespaceCreateForm`, refactored out of CreateFilespace.tsx
 *           so it isn't duplicated). Creation auto-generates the filespace's master key
 *           server-side; a missing STORAGE_ENC_KEY fails closed with a clear message
 *           (the health-check step above should have already caught it). Skippable.
 *   6 of 6 "Invite the team" (build step 5, new) — paste emails, pick a role, optionally
 *           grant access to the filespace just created. Creates each invite through the
 *           existing API and reports its own honest per-row outcome ("emailed" vs.
 *           "copy this link") — never a blanket "invites were sent" claim. Skippable.
 *   Finish — "You're in." + a "Get the app" card (shared GetTheAppCard — build step 3)
 *           in place of the old static manual-entry card, plus links to anything skipped.
 *
 * Friendly typed errors: wrong secret (401 → back to step 1), setup already
 * complete (409), weak password (400), rate limit (429), and the fail-closed
 * "no BOOTSTRAP_SECRET configured" server state.
 *
 * Standalone route (own AuthLayout-style chrome): it must render both signed-out
 * (steps 1–2) and signed-in (steps 3+), which neither shared layout allows.
 */
import { useCallback, useEffect, useId, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Banner, BrandMark, Button, Card, Icons, LabeledField, Spinner } from '../design'
import { StatusDot } from '../design/components'
import { ApiError, getApi, MIN_PASSWORD_LENGTH } from '../api'
import type { Filespace, FilespaceAccessLevel, MemberRole } from '../api'
import { useAuth } from '../app/auth'
import { useProductName } from '../app/productName'
import { fetchSetupNeeded, markSetupComplete } from '../app/setupStatus'
import { estimatePassword } from './auth/passwordStrength'
import { HealthCheckPanel } from './HealthCheckPanel'
import { EmailChipsInput } from './EmailChipsInput'
import { mergeUniqueEmails, parseEmailTokens } from './emailChips'
import { TotpEnrollFlow } from './settings/TotpEnrollFlow'
import { FilespaceCreateForm } from './filespaces/FilespaceCreateForm'
import { GetTheAppCard } from './join/GetTheAppCard'
import '../app/shell.css'
import './auth/auth.css'

const TONE_VAR: Record<string, string> = {
  idle: 'var(--cfs-text-tertiary)',
  error: 'var(--cfs-status-error)',
  warn: 'var(--cfs-status-warn)',
  accent: 'var(--cfs-accent)',
  ok: 'var(--cfs-status-ok)',
}

const ROLE_LABEL: Record<MemberRole, string> = {
  owner: 'Owner',
  admin: 'Admin',
  space_admin: 'Space Admin',
  standard: 'Member',
}
const ROLE_OPTIONS: MemberRole[] = ['admin', 'space_admin', 'standard']

type Step =
  | { kind: 'loading' }
  | { kind: 'complete'; reason?: string } // setup already done — self-hide
  | { kind: 'disabled' } // server fail-closed: no usable BOOTSTRAP_SECRET
  | { kind: 'secret' }
  | { kind: 'org' }
  | { kind: 'totp'; enrolling: boolean }
  | { kind: 'health' }
  | { kind: 'filespace' }
  | { kind: 'invite' }
  | { kind: 'done' }

/** Derive a URL/API-safe org slug from the display name (lowercase, no dots). */
function deriveSlug(name: string): string {
  return name
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32)
}

const SLUG_OK = /^[a-z0-9][a-z0-9-]*$/

/* ----- Invite-the-team step: per-invite result row ----- */
interface InviteRowResult {
  email: string
  ok: boolean
  emailSent?: boolean
  inviteUrl?: string
  error?: string
}

function InviteResultRow({ result }: { result: InviteRowResult }) {
  const [copied, setCopied] = useState(false)
  const showCopyLink = result.ok && result.emailSent === false && result.inviteUrl

  return (
    <div className="cfs-doctor-row cfs-invite-result">
      <StatusDot color={result.ok ? 'ok' : 'error'} size={9} />
      <div className="cfs-doctor-row__body">
        <span className="cfs-doctor-row__title">{result.email}</span>
        <span className="cfs-doctor-row__detail">
          {result.ok
            ? result.emailSent
              ? 'Invitation emailed.'
              : 'Email isn’t configured on this deployment — copy this link and send it yourself.'
            : result.error}
        </span>
        {showCopyLink && (
          <div className="cfs-doctor-row__copy">
            <LabeledField label="" value={result.inviteUrl} readOnly onChange={() => {}} />
            <Button
              type="button"
              variant="secondary"
              size="small"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(result.inviteUrl!)
                  setCopied(true)
                  setTimeout(() => setCopied(false), 1500)
                } catch {
                  /* clipboard blocked — the link is still visible to copy manually */
                }
              }}
            >
              {copied ? 'Copied' : 'Copy'}
            </Button>
          </div>
        )}
      </div>
    </div>
  )
}

export function Setup() {
  const productName = useProductName()
  const navigate = useNavigate()
  const { refresh, session } = useAuth()
  const org = session?.org.slug ?? ''

  const [step, setStep] = useState<Step>({ kind: 'loading' })
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  // The setup secret lives in component state (page memory) ONLY — submitted
  // once inside the step-2 POST, never echoed, never persisted (§5.4).
  const [secret, setSecret] = useState('')

  const [orgName, setOrgName] = useState('')
  const [slug, setSlug] = useState('')
  const [slugTouched, setSlugTouched] = useState(false)
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')

  const continueToFilespace = useCallback(() => setStep({ kind: 'filespace' }), [])

  // First-filespace step (build step 5) — the created filespace, if any, feeds the
  // invite step's optional scoping picker and the finish screen's next-step cards.
  const [createdFilespace, setCreatedFilespace] = useState<Filespace | null>(null)

  // Invite-the-team step (build step 5).
  const [inviteEmails, setInviteEmails] = useState<string[]>([])
  const [inviteDraft, setInviteDraft] = useState('')
  const [inviteRole, setInviteRole] = useState<MemberRole>('standard')
  const [inviteScopeLevel, setInviteScopeLevel] = useState<FilespaceAccessLevel | 'none'>('none')
  const [inviteSubmitting, setInviteSubmitting] = useState(false)
  const [inviteError, setInviteError] = useState<string | null>(null)
  const [inviteResults, setInviteResults] = useState<InviteRowResult[] | null>(null)

  const strengthId = useId()
  const strength = useMemo(() => estimatePassword(password), [password])

  // Gate the wizard on the public status probe; self-hide when already set up.
  useEffect(() => {
    let alive = true
    void fetchSetupNeeded().then((needed) => {
      if (!alive) return
      setStep(needed ? { kind: 'secret' } : { kind: 'complete' })
    })
    return () => {
      alive = false
    }
  }, [])

  const effectiveSlug = slugTouched ? slug : deriveSlug(orgName)
  const emailOk = /.+@.+\..+/.test(email.trim())
  const slugOk = SLUG_OK.test(effectiveSlug) && !effectiveSlug.includes('.')
  const canCreate =
    !busy &&
    orgName.trim().length > 0 &&
    slugOk &&
    emailOk &&
    displayName.trim().length > 0 &&
    password.length >= MIN_PASSWORD_LENGTH &&
    password === confirm

  async function onCreate(e: FormEvent) {
    e.preventDefault()
    if (!canCreate) return
    setBusy(true)
    setError(null)
    try {
      await getApi().setupInit({
        secret,
        orgId: effectiveSlug,
        orgName: orgName.trim(),
        email: email.trim(),
        displayName: displayName.trim(),
        password,
      })
      // The 201 set the session cookie — hydrate the app session, stop the
      // root/sign-in gates from redirecting here, and move on to step 3.
      markSetupComplete()
      await refresh()
      setSecret('')
      setStep({ kind: 'totp', enrolling: false })
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) {
          // The single POST carries the secret; a mismatch bounces back to step 1.
          setStep({ kind: 'secret' })
          setError('That setup secret didn’t match.')
          return
        }
        if (err.code === 'setup_complete' || err.code === 'already_bootstrapped') {
          markSetupComplete()
          setStep({
            kind: 'complete',
            reason: 'Someone already completed setup on this deployment.',
          })
          return
        }
        if (err.code === 'weak_password') {
          setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`)
          return
        }
        if (
          err.code === 'bootstrap_disabled' ||
          err.code === 'setup_disabled' ||
          err.code === 'disabled'
        ) {
          setStep({ kind: 'disabled' })
          return
        }
        if (err.status === 429) {
          setError('Too many attempts. Wait a minute and try again.')
          return
        }
      }
      setError(err instanceof Error ? err.message : 'Couldn’t complete setup. Try again.')
    } finally {
      setBusy(false)
    }
  }

  const parsedInviteDraft = useMemo(() => parseEmailTokens(inviteDraft), [inviteDraft])
  const inviteEmailList = useMemo(
    () => mergeUniqueEmails(inviteEmails, parsedInviteDraft.valid),
    [inviteEmails, parsedInviteDraft],
  )
  const invalidInviteDraft = parsedInviteDraft.invalid.length > 0

  async function sendInvites() {
    if (inviteEmailList.length === 0 || inviteSubmitting || invalidInviteDraft) return
    setInviteSubmitting(true)
    setInviteError(null)
    const results: InviteRowResult[] = []
    for (const addr of inviteEmailList) {
      if (!/.+@.+\..+/.test(addr)) {
        results.push({ email: addr, ok: false, error: 'Not a valid email address.' })
        continue
      }
      try {
        const scope =
          inviteScopeLevel !== 'none' && createdFilespace
            ? { spaceId: createdFilespace.id, level: inviteScopeLevel }
            : undefined
        const res = await getApi().createInvite(org, { email: addr, role: inviteRole, scope })
        results.push({ email: addr, ok: true, emailSent: res.emailSent, inviteUrl: res.inviteUrl })
      } catch (err) {
        results.push({
          email: addr,
          ok: false,
          error: err instanceof Error ? err.message : 'Could not create the invitation.',
        })
      }
    }
    setInviteResults(results)
    setInviteSubmitting(false)
  }

  /* ----- Render ----- */

  let body: ReactNode
  let footnote: ReactNode = null

  switch (step.kind) {
    case 'loading':
      body = (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--cfs-space-xxxl)' }}>
          <Spinner size={24} />
        </div>
      )
      break

    case 'complete':
      body = (
        <Card title={`Set up ${productName}`}>
          <div className="cfs-auth-form">
            <Banner
              kind="info"
              title={step.reason ?? 'This deployment is already set up.'}
              detail="Sign in with your account, or ask an admin for an invitation."
            />
            <Button variant="primary" size="large" block onClick={() => navigate('/signin')}>
              Go to sign in
            </Button>
          </div>
        </Card>
      )
      break

    case 'disabled':
      body = (
        <Card title="Setup is disabled">
          <div className="cfs-auth-form">
            <Banner
              kind="warning"
              title="Setup is disabled because no BOOTSTRAP_SECRET (≥ 16 chars) is configured."
              detail="Set one with `wrangler secret put BOOTSTRAP_SECRET` and reload."
            />
          </div>
        </Card>
      )
      break

    case 'secret':
      body = (
        <Card title={`Set up ${productName}`}>
          <form
            className="cfs-auth-form"
            onSubmit={(e) => {
              e.preventDefault()
              if (secret.trim().length >= 16) {
                setError(null)
                setStep({ kind: 'org' })
              }
            }}
            noValidate
          >
            {error && <Banner kind="error" title="Couldn’t unlock setup" detail={error} />}
            <p className="cfs-auth-note" style={{ textAlign: 'left' }}>
              This deployment is brand new. Enter the setup secret to create the first
              organization and admin account.
            </p>
            <LabeledField
              label="Setup secret"
              icon={<Icons.IconLock />}
              type="password"
              autoComplete="off"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              autoFocus
              hint={
                secret.length > 0 && secret.trim().length < 16
                  ? 'The setup secret is at least 16 characters.'
                  : undefined
              }
            />
            <p className="cfs-auth-note" style={{ textAlign: 'left' }}>
              This is the <code>BOOTSTRAP_SECRET</code> you provisioned in{' '}
              your protected deployment secrets during installation.
            </p>
            <Button
              type="submit"
              variant="primary"
              size="large"
              block
              disabled={secret.trim().length < 16}
            >
              Continue
            </Button>
          </form>
        </Card>
      )
      footnote = <p className="cfs-auth-footnote">Step 1 of 6 · Unlock setup</p>
      break

    case 'org':
      body = (
        <Card title="Create your workspace & admin">
          <form className="cfs-auth-form" onSubmit={onCreate} noValidate>
            {error && <Banner kind="error" title="Couldn’t create the account" detail={error} />}
            <div className="cfs-auth-fields">
              <LabeledField
                label="Organization name"
                icon={<Icons.IconBuilding />}
                placeholder="Acme Post"
                autoComplete="organization"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                autoFocus
              />
              <LabeledField
                label="Organization ID"
                icon={<Icons.IconGlobe />}
                placeholder="acme-post"
                autoComplete="off"
                value={effectiveSlug}
                onChange={(e) => {
                  setSlugTouched(true)
                  setSlug(e.target.value.toLowerCase())
                }}
                hint={
                  effectiveSlug && !slugOk
                    ? 'Lowercase letters, numbers and dashes only — no dots.'
                    : undefined
                }
              />
              <p className="cfs-auth-note" style={{ textAlign: 'left' }}>
                Short, lowercase; used in URLs and the API — can’t be changed later. No dots.
              </p>
              <LabeledField
                label="Your email"
                icon={<Icons.IconMail />}
                type="email"
                placeholder="you@acme.example"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
              <LabeledField
                label="Display name"
                icon={<Icons.IconSSO />}
                placeholder="Alex Rivera"
                autoComplete="name"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
              <div className="cfs-strength">
                <LabeledField
                  label="Password"
                  icon={<Icons.IconLock />}
                  type="password"
                  placeholder={`At least ${MIN_PASSWORD_LENGTH} characters`}
                  autoComplete="new-password"
                  aria-describedby={strengthId}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <div className="cfs-strength__bars" aria-hidden="true">
                  {[1, 2, 3, 4].map((i) => (
                    <span
                      key={i}
                      className={`cfs-strength__seg${i <= strength.score ? ' is-on' : ''}`}
                      style={{ ['--_tone' as string]: TONE_VAR[strength.tone] }}
                    />
                  ))}
                </div>
                <span id={strengthId} className="cfs-strength__label" aria-live="polite">
                  {strength.label}
                </span>
              </div>
              <LabeledField
                label="Confirm password"
                icon={<Icons.IconLock />}
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                hint={
                  confirm.length > 0 && confirm !== password ? 'Passwords don’t match.' : undefined
                }
              />
            </div>
            <Button type="submit" variant="primary" size="large" block disabled={!canCreate}>
              {busy ? 'Creating admin account…' : 'Create admin account'}
            </Button>
            <button
              type="button"
              className="cfs-auth-link"
              style={{ alignSelf: 'center' }}
              onClick={() => {
                setError(null)
                setStep({ kind: 'secret' })
              }}
            >
              Back
            </button>
          </form>
        </Card>
      )
      footnote = <p className="cfs-auth-footnote">Step 2 of 6 · Create your organization &amp; admin</p>
      break

    case 'totp':
      body = (
        <Card title="Protect this account">
          <div className="cfs-auth-form">
            {!step.enrolling ? (
              <>
                <p className="cfs-auth-note" style={{ textAlign: 'left' }}>
                  Add two-factor authentication now? You can also do this later in Account
                  Settings.
                </p>
                <Button
                  type="button"
                  variant="primary"
                  size="large"
                  block
                  leading={<Icons.IconLock />}
                  onClick={() => setStep({ kind: 'totp', enrolling: true })}
                >
                  Set up authenticator app
                </Button>
                {/* Equally prominent — do not dark-pattern the skip (§1.1 step 4). */}
                <Button
                  type="button"
                  variant="secondary"
                  size="large"
                  block
                  onClick={() => setStep({ kind: 'health' })}
                >
                  Skip for now
                </Button>
              </>
            ) : (
              <TotpEnrollFlow
                onEnrolled={refresh}
                onDone={() => setStep({ kind: 'health' })}
                onCancel={() => setStep({ kind: 'totp', enrolling: false })}
              />
            )}
          </div>
        </Card>
      )
      footnote = <p className="cfs-auth-footnote">Step 3 of 6 · Optional — you can skip this</p>
      break

    case 'health': {
      body = (
        <Card>
          <div className="cfs-auth-form">
            <HealthCheckPanel org={org} onContinue={continueToFilespace} />
            <Link className="cfs-auth-link" to="/workspace#troubleshooting" target="_blank" rel="noopener noreferrer">
              Open workspace settings ↗
            </Link>
          </div>
        </Card>
      )
      footnote = <p className="cfs-auth-footnote">Step 4 of 6</p>
      break
    }

    case 'filespace':
      body = (
        <>
          <FilespaceCreateForm
            onCreated={(fs) => {
              setCreatedFilespace(fs)
              setStep({ kind: 'invite' })
            }}
            onCancel={() => setStep({ kind: 'invite' })}
            cancelLabel="Skip for now"
          />
        </>
      )
      footnote = <p className="cfs-auth-footnote">Step 5 of 6 · Create a shared drive</p>
      break

    case 'invite': {
      const emailCount = inviteEmailList.length
      body = (
        <Card title="Invite your team">
          <div className="cfs-auth-form">
            {inviteError && <Banner kind="error" title="Couldn’t send invites" detail={inviteError} />}
            {!inviteResults ? (
              <>
                <p className="cfs-auth-note" style={{ textAlign: 'left' }}>
                  Add teammates and choose the access their invitations will grant.
                </p>
                <EmailChipsInput
                  id="setup-invite-emails"
                  label="Email addresses"
                  values={inviteEmails}
                  onChange={setInviteEmails}
                  onDraftChange={setInviteDraft}
                  disabled={inviteSubmitting}
                />
                <div className="cfs-field">
                  <label className="cfs-field__label" htmlFor="setup-invite-role">
                    Role
                  </label>
                  <select
                    id="setup-invite-role"
                    className="cfs-select"
                    value={inviteRole}
                    onChange={(e) => setInviteRole(e.target.value as MemberRole)}
                  >
                    {ROLE_OPTIONS.map((r) => (
                      <option key={r} value={r}>
                        {ROLE_LABEL[r]}
                      </option>
                    ))}
                  </select>
                </div>
                {createdFilespace && (
                  <div className="cfs-field">
                    <label className="cfs-field__label" htmlFor="setup-invite-scope">
                      Filespace access (optional)
                    </label>
                    <select
                      id="setup-invite-scope"
                      className="cfs-select"
                      value={inviteScopeLevel}
                      onChange={(e) => setInviteScopeLevel(e.target.value as FilespaceAccessLevel | 'none')}
                    >
                      <option value="none">No filespace access</option>
                      <option value="read">Read — {createdFilespace.name}</option>
                      <option value="edit">Edit — {createdFilespace.name}</option>
                      <option value="admin">Folder admin — {createdFilespace.name}</option>
                    </select>
                  </div>
                )}
                <Button
                  type="button"
                  variant="primary"
                  size="large"
                  block
                  disabled={emailCount === 0 || inviteSubmitting || invalidInviteDraft}
                  onClick={() => void sendInvites()}
                >
                  {inviteSubmitting
                    ? 'Sending…'
                    : emailCount > 0
                      ? `Send ${emailCount} invite${emailCount === 1 ? '' : 's'}`
                      : 'Send invites'}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  size="large"
                  block
                  disabled={inviteSubmitting}
                  onClick={() => setStep({ kind: 'done' })}
                >
                  Skip for now
                </Button>
              </>
            ) : (
              <>
                <div className="cfs-doctor-rows">
                  {inviteResults.map((r) => (
                    <InviteResultRow key={r.email} result={r} />
                  ))}
                </div>
                <Button variant="primary" size="large" block onClick={() => setStep({ kind: 'done' })}>
                  Continue
                </Button>
              </>
            )}
          </div>
        </Card>
      )
      footnote = <p className="cfs-auth-footnote">Step 6 of 6 · Invite teammates</p>
      break
    }

    case 'done': {
      const orgLabel = session?.org.name ?? orgName.trim()
      body = (
        <Card title="Your workspace is ready">
          <div className="cfs-auth-form">
            <ul className="cfs-setup-checklist">
              <li>
                <Icons.IconCheck /> Workspace <strong>{orgLabel}</strong> created
              </li>
              {createdFilespace && (
                <li>
                  <Icons.IconCheck /> Filespace <strong>{createdFilespace.name}</strong> created
                </li>
              )}
              {inviteResults && inviteResults.some((r) => r.ok) && (
                <li>
                  <Icons.IconCheck /> {inviteResults.filter((r) => r.ok).length} teammate
                  {inviteResults.filter((r) => r.ok).length === 1 ? '' : 's'} invited
                </li>
              )}
            </ul>
            <div className="cfs-setup-next">
              {!createdFilespace && (
                <Link className="cfs-setup-next__card" to="/filespaces/new">
                  <span className="cfs-setup-next__title">Create your first filespace</span>
                  <span className="cfs-setup-next__hint">
                    Point {productName} at your bucket and mount it.
                  </span>
                </Link>
              )}
              {!(inviteResults && inviteResults.some((r) => r.ok)) && (
                <Link className="cfs-setup-next__card" to="/members">
                  <span className="cfs-setup-next__title">Invite your team</span>
                  <span className="cfs-setup-next__hint">
                    Manage members and invitations in your browser.
                  </span>
                </Link>
              )}
              <GetTheAppCard compact />
            </div>
            <Button variant="secondary" size="large" block leading={<Icons.IconGlobe />} onClick={() => navigate('/filespaces')}>
              Open web console
            </Button>
            <p className="cfs-auth-note">Manage filespaces and members in your browser.</p>
          </div>
        </Card>
      )
      break
    }
  }

  return (
    <main className="cfs-auth-layout">
      <div className="cfs-auth-layout__inner">
        <header className="cfs-hero">
          <BrandMark size={72} chrome className="cfs-hero__plate" />
          <span className="cfs-hero__wordmark">{productName}</span>
        </header>
        {body}
        {footnote}
      </div>
    </main>
  )
}
