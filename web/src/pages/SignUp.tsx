/*
 * SignUp — UNAUTH screen lane. Renders inside <AuthLayout/> (centered branded
 * card), mirroring the macOS LoginView: a single primary path (org + email +
 * password → "Create account") plus a passkey alternative below an "or" divider.
 *
 * Cohesion: built ENTIRELY from the frozen design system (Card / LabeledField /
 * Button / Banner / Icons) + tokens, so it reads as the same product as the Mac
 * app. Uses the API seam for signup and reads the public deployment policy before
 * showing self-service account creation.
 *
 * Owned by the Auth screen lane.
 */
import { useEffect, useId, useMemo, useState, type FormEvent } from 'react'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { Banner, Button, Card, Icons, LabeledField } from '../design'
import { getApi, MIN_PASSWORD_LENGTH, type PublicAuthConfig } from '../api'
import { authAvailability } from '../app/authAvailability'
import { estimatePassword } from './auth/passwordStrength'
import './auth/auth.css'

const TONE_VAR: Record<string, string> = {
  idle: 'var(--cfs-text-tertiary)',
  error: 'var(--cfs-status-error)',
  warn: 'var(--cfs-status-warn)',
  accent: 'var(--cfs-accent)',
  ok: 'var(--cfs-status-ok)',
}

/**
 * A strong random password for passkey-first signups (the backend signup contract
 * requires a password). The user signs in with the passkey thereafter; this is a
 * throwaway never shown to them.
 */
function randomPassword(): string {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('') + 'Aa1!'
}

export function SignUp() {
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const [authConfig, setAuthConfig] = useState<PublicAuthConfig | null>(null)
  const [authConfigStatus, setAuthConfigStatus] = useState<'loading' | 'ready' | 'error'>('loading')
  const [authConfigAttempt, setAuthConfigAttempt] = useState(0)

  useEffect(() => {
    let alive = true
    getApi()
      .getPublicAuthConfig()
      .then((config) => {
        if (!alive) return
        setAuthConfig(config)
        setAuthConfigStatus('ready')
      })
      .catch(() => {
        // Keep policy lookup errors distinct from a confirmed closed signup policy.
        if (alive) setAuthConfigStatus('error')
      })
    return () => {
      alive = false
    }
  }, [authConfigAttempt])
  const availability = authAvailability(authConfig)

  // Legacy invite links: `?org=&invite=` (the old B26 redeem-only path — it provisioned org
  // membership but never a credential, dead-ending at "Continue to sign in" with nothing to sign
  // in WITH). ONBOARDING.md build step 1 replaces it with `/join?token=<joinToken>`, which
  // atomically creates the credential too. A legacy link's `invite` is the UNQUALIFIED rawToken;
  // `joinToken` is simply `<org>.<rawToken>` (same qualify scheme auth-wiring.ts uses elsewhere),
  // so we can redirect losslessly rather than dead-ending old links.
  const inviteToken = params.get('invite') ?? ''
  const inviteOrg = params.get('org') ?? ''
  const isLegacyInvite = inviteToken.length > 0 && inviteOrg.length > 0

  const [orgName, setOrgName] = useState('')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  /** Pasted invite link or token (for the "Have an invitation?" card below). */
  const [manualToken, setManualToken] = useState('')

  const [busy, setBusy] = useState(false)
  const [passkeyBusy, setPasskeyBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  /** When set, we've "created" the account and show the verify-email panel. */
  const [pendingEmail, setPendingEmail] = useState<string | null>(null)

  const strengthId = useId()
  const strength = useMemo(() => estimatePassword(password), [password])

  const emailOk = /.+@.+\..+/.test(email.trim())
  const canCreate =
    !busy &&
    orgName.trim().length > 0 &&
    emailOk &&
    password.length >= MIN_PASSWORD_LENGTH &&
    availability.signup
  // A passkey still needs an org + email to bind the new account/identity.
  const canPasskey =
    !passkeyBusy && orgName.trim().length > 0 && emailOk && availability.signup && availability.passkey

  async function createAccount(via: 'password' | 'passkey') {
    // Create the account via the API seam directly — NOT useAuth().signup, which
    // would set the session in context and trip AuthLayout's redirect, hiding the
    // verify-email panel. signup() DOES establish the cookie session though, which
    // the passkey-registration ceremony below needs (it's a session-gated route).
    await getApi().signup({
      orgName: orgName.trim(),
      name: name.trim() || email.trim().split('@')[0],
      email: email.trim(),
      // Passkey signups still set a password (the backend signup requires one); the
      // passkey is then registered as an additional credential below.
      password: via === 'passkey' ? randomPassword() : password,
    })
  }

  async function landOnVerify() {
    // Sign back out so the new session doesn't auto-authenticate the shell; the
    // user must verify their email and then sign in (mirrors production).
    await getApi().logout()
    setPendingEmail(email.trim())
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!canCreate) return
    setBusy(true)
    setError(null)
    try {
      await createAccount('password')
      await landOnVerify()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create your account.')
    } finally {
      setBusy(false)
    }
  }

  async function onPasskey() {
    if (!canPasskey) return
    setPasskeyBusy(true)
    setError(null)
    try {
      // 1) Create the account (establishes the cookie session), then 2) run the
      // REAL WebAuthn registration ceremony (navigator.credentials.create via the
      // session-gated register/options + register/verify routes), then 3) sign out
      // to the verify-email panel.
      await createAccount('passkey')
      await getApi().registerPasskey(`${email.trim()} · passkey`)
      await landOnVerify()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passkey setup was cancelled.')
    } finally {
      setPasskeyBusy(false)
    }
  }

  /* ----- Legacy invite link: redirect to the real join flow ----- */
  if (isLegacyInvite) {
    const joinToken = `${inviteOrg}.${inviteToken}`
    return <Navigate to={`/join?token=${encodeURIComponent(joinToken)}`} replace />
  }

  /* ----- Success: verify-email panel ----- */
  if (pendingEmail) {
    return (
      <>
        <Card title="Account created">
          <div className="cfs-auth-success">
            <span className="cfs-auth-success__glyph">
              <Icons.IconMail size={34} />
            </span>
            <span className="cfs-auth-success__title">Check your email to verify</span>
            <p className="cfs-auth-success__body">
              We sent a verification link to{' '}
              <span className="cfs-auth-success__email">{pendingEmail}</span>. Open it to activate{' '}
              <strong>{orgName.trim()}</strong> and finish setting up your workspace.
            </p>
            <div className="cfs-auth-form" style={{ width: '100%' }}>
              <Button variant="primary" size="large" block onClick={() => navigate('/signin')}>
                Continue to sign in
              </Button>
              <button
                type="button"
                className="cfs-auth-link"
                style={{ alignSelf: 'center' }}
                onClick={() => setPendingEmail(null)}
              >
                Use a different email
              </button>
            </div>
          </div>
        </Card>
        <p className="cfs-auth-footnote">
          Didn’t get it? Check spam, or contact your workspace administrator.
        </p>
      </>
    )
  }

  /* ----- Form ----- */
  return (
    <>
      {authConfigStatus === 'loading' ? (
        <Card title="Checking sign-up availability">
          <p className="cfs-auth-note" role="status">Checking this deployment’s sign-up policy…</p>
        </Card>
      ) : authConfigStatus === 'error' ? (
        <Card title="Could not check sign-up availability">
          <p className="cfs-auth-note" role="alert">
            The deployment’s sign-up policy could not be loaded. Try again before creating an account.
          </p>
          <Button
            type="button"
            variant="secondary"
            size="large"
            block
            onClick={() => {
              setAuthConfigStatus('loading')
              setAuthConfigAttempt((attempt) => attempt + 1)
            }}
          >
            Retry
          </Button>
        </Card>
      ) : availability.signup ? (
        <Card title="Create your account">
          <form className="cfs-auth-form" onSubmit={onSubmit} noValidate>
          {error && <Banner kind="error" title="Couldn’t create account" detail={error} />}

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
              label="Your name"
              icon={<Icons.IconSSO />}
              placeholder="Alex Rivera"
              autoComplete="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <LabeledField
              label="Work email"
              icon={<Icons.IconMail />}
              type="email"
              placeholder="you@acme.example"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
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
          </div>

          <Button type="submit" variant="primary" size="large" block disabled={!canCreate}>
            {busy ? 'Creating account…' : 'Create account'}
          </Button>

          {availability.passkey && (
            <>
              <div className="cfs-auth-divider">or</div>
              <Button
                type="button"
                variant="secondary"
                size="large"
                block
                leading={<Icons.IconKey />}
                disabled={!canPasskey}
                onClick={onPasskey}
              >
                {passkeyBusy ? 'Setting up passkey…' : 'Sign up with a passkey'}
              </Button>
            </>
          )}

          </form>
        </Card>
      ) : (
        <Card title="Sign-up is unavailable">
          <p className="cfs-auth-note">
            {authConfig?.signupMode === 'invite'
              ? 'This deployment accepts new members by invitation. Use the invitation link below to join your workspace.'
              : 'Self-service sign-up is closed for this deployment. Ask an administrator for an invitation.'}
          </p>
        </Card>
      )}

      {/* Have an invite link? Paste it to JOIN an existing org instead of creating a new one — routes
          through /join (ONBOARDING.md build step 1), which handles the credential too. */}
      <details className="cfs-auth-invite" open={authConfigStatus === 'ready' && !availability.signup}>
        <summary>Have an invitation?</summary>
        <div className="cfs-auth-fields">
          <LabeledField
            label="Invite link or token"
            icon={<Icons.IconMail />}
            placeholder="https://…/join?token=…"
            value={manualToken}
            onChange={(e) => setManualToken(e.target.value)}
          />
          <Button
            type="button"
            variant="secondary"
            size="large"
            block
            disabled={manualToken.trim().length === 0}
            onClick={() => {
              const target = parseInviteLink(manualToken.trim())
              if (target) navigate(target)
              else setError('That doesn’t look like a valid invite link.')
            }}
          >
            Accept invitation
          </Button>
        </div>
      </details>

      <p className="cfs-auth-footnote">
        Already have an account? <Link to="/signin">Sign in</Link>
      </p>
    </>
  )
}

/**
 * Parse a pasted invite link (or token) into a local `/join?token=…` path. Accepts:
 *   - a modern join link/token (`?token=…`, or a bare `<orgId>.inv-…` token pasted directly),
 *   - a legacy link (`?org=…&invite=…`) or `org:token` shorthand — qualified into a joinToken
 *     the same way `isLegacyInvite` above does, so old invites keep working.
 * Returns null when none of these shapes are present.
 */
function parseInviteLink(raw: string): string | null {
  try {
    const u = new URL(raw)
    const token = u.searchParams.get('token')
    if (token) return `/join?token=${encodeURIComponent(token)}`
    const org = u.searchParams.get('org')
    const invite = u.searchParams.get('invite')
    if (org && invite) return `/join?token=${encodeURIComponent(`${org}.${invite}`)}`
  } catch {
    // Not a URL — try an `org:token` shorthand, else treat it as a bare (already-qualified) token.
    const idx = raw.indexOf(':')
    if (idx > 0) {
      const org = raw.slice(0, idx).trim()
      const token = raw.slice(idx + 1).trim()
      if (org && token) return `/join?token=${encodeURIComponent(`${org}.${token}`)}`
    } else if (raw.length > 0) {
      return `/join?token=${encodeURIComponent(raw)}`
    }
  }
  return null
}
