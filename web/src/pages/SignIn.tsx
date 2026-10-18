/*
 * SignIn — UNAUTH screen lane. Renders inside <AuthLayout/> (centered branded
 * card), mirroring the macOS LoginView's two-path feel: a primary credentials
 * path ("Sign in") that may step up to a TOTP 2FA challenge, then an "or" divider
 * with the organization SSO and passkey alternatives.
 *
 * Cohesion: built ENTIRELY from the frozen design system (Card / LabeledField /
 * Button / Banner / SegmentedControl-free) + tokens. No backend — uses
 * useAuth().login / verifyTotp + getApi() (MockApi) only.
 *
 * Owned by the Auth screen lane.
 */
import { useEffect, useState, type FormEvent } from 'react'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { Banner, Button, Card, Icons, LabeledField, Spinner } from '../design'
import { getApi, type MfaMethod, type PublicAuthConfig } from '../api'
import { useAuth } from '../app/auth'
import { useProductName } from '../app/productName'
import { sanitizeNext } from '../app/nextParam'
import { authAvailability } from '../app/authAvailability'
import { useSetupNeeded } from '../app/setupStatus'
import './auth/auth.css'

/**
 * The credentials step, or the stepped-up MFA challenge after a password. `methods`
 * carries the factors the backend offered: `webauthn` drives the passkey ceremony,
 * `totp` shows the authenticator/recovery field. A user with only a passkey enrolled
 * gets `['webauthn']` and must never be dead-ended on a 6-digit form they can't satisfy.
 */
type Step =
  | { kind: 'credentials' }
  | { kind: 'totp'; challengeId: string; recovery: boolean; methods: MfaMethod[] }

export function SignIn() {
  const productName = useProductName()
  const { login, verifyTotp, loginWithRecovery, loginWithPasskey, beginSSO } = useAuth()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  // Where to land after auth (W2). AuthLayout performs the actual redirect; the
  // MFA step is in-page, so the URL — and therefore `next` — survives it.
  const next = sanitizeNext(params.get('next'))
  // Fresh-deploy gate (auth-spec §1.1 step 1): a brand-new deployment has no
  // credential that can pass this form — route the operator to /setup instead.
  const setupNeeded = useSetupNeeded()

  const [step, setStep] = useState<Step>({ kind: 'credentials' })
  const [email, setEmail] = useState('')
  const [emailEntered, setEmailEntered] = useState(false)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')

  const [busy, setBusy] = useState(false)
  const [passkeyBusy, setPasskeyBusy] = useState(false)
  const [ssoBusy, setSsoBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Adapt to the deployment's configured auth provider. `null` until the public
  // config (GET /v1/auth/config/public) resolves; falls back to built-in on error
  // so sign-in is never blocked by a config-read failure.
  const [authConfig, setAuthConfig] = useState<PublicAuthConfig | null>(null)
  useEffect(() => {
    let alive = true
    getApi()
      .getPublicAuthConfig()
      .then((c) => alive && setAuthConfig(c))
      .catch(() => alive && setAuthConfig({ mode: 'builtin', oidcEnabled: false }))
    return () => {
      alive = false
    }
  }, [])

  // Derived presentation: oidc-only HIDES the password form; both shows password +
  // SSO; built-in/null leaves the page as it was.
  const availability = authAvailability(authConfig)
  const mode = authConfig?.mode ?? 'builtin'
  const oidcOnly = mode === 'oidc' && (authConfig?.oidcEnabled ?? false)
  const oidcEnabled = authConfig?.oidcEnabled ?? false
  const providerLabel = authConfig?.providerLabel?.trim() || 'your organization'
  const ssoLabel = oidcEnabled
    ? `Sign in with ${providerLabel}`
    : 'Sign in with your organization (SSO)'

  const emailOk = /.+@.+\..+/.test(email.trim())
  const canSignIn = !busy && emailOk && (!emailEntered || password.length > 0)
  // On success, AuthLayout sees isAuthenticated and redirects to /filespaces; no
  // navigate() call needed here.

  async function onSubmitCredentials(e: FormEvent) {
    e.preventDefault()
    if (!canSignIn) return
    if (!emailEntered) { setEmailEntered(true); setError(null); return }
    setBusy(true)
    setError(null)
    try {
      const result = await login({ email: email.trim(), password })
      if (result.kind === 'totp-required') {
        const methods = result.methods
        setStep({ kind: 'totp', challengeId: result.challengeId, recovery: false, methods })
        setCode('')
        // Passkey-only second factor: there is no code to enter, so kick off the
        // WebAuthn assertion immediately rather than showing a dead TOTP form.
        if (methods.includes('webauthn') && !methods.includes('totp')) {
          void completePasskeyChallenge(result.challengeId)
        }
      }
      // kind === 'session' → AuthProvider set the session → redirect happens.
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Check your email and password.')
    } finally {
      setBusy(false)
    }
  }

  async function onSubmitTotp(e: FormEvent) {
    e.preventDefault()
    if (step.kind !== 'totp' || busy) return
    const recovery = step.recovery
    const min = recovery ? 4 : 6
    if (code.trim().length < min) return
    setBusy(true)
    setError(null)
    try {
      // Recovery codes are validated by a DEDICATED route (POST /v1/auth/login/recovery);
      // the TOTP endpoint only accepts the RFC-6238 authenticator code. Routing both to
      // verifyTotp would make saved recovery codes always fail to sign in.
      if (recovery) {
        await loginWithRecovery(step.challengeId, code.trim())
      } else {
        await verifyTotp(step.challengeId, code.trim())
      }
      // Success → redirect via AuthLayout.
    } catch (err) {
      setError(err instanceof Error ? err.message : 'That code didn’t work. Try again.')
    } finally {
      setBusy(false)
    }
  }

  /**
   * Complete a passkey (WebAuthn) second factor for a pending login challenge. Unlike
   * the standalone passwordless button (which passes `{ email }`), this binds the
   * assertion to the MFA `challengeId` the backend issued after the password step.
   */
  async function completePasskeyChallenge(challengeId: string) {
    if (passkeyBusy) return
    setPasskeyBusy(true)
    setError(null)
    try {
      await loginWithPasskey({ challengeId })
      // Success → redirect via AuthLayout.
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passkey sign-in was cancelled.')
    } finally {
      setPasskeyBusy(false)
    }
  }

  async function onPasskey() {
    if (passkeyBusy) return
    setPasskeyBusy(true)
    setError(null)
    try {
      // Real WebAuthn ASSERTION (navigator.credentials.get) via the API seam:
      // passwordless sign-in bound to the entered email (omitted = resident-key /
      // discoverable credential). On success the cookie session is established and
      // AuthLayout redirects to /filespaces.
      await loginWithPasskey({ email: email.trim() || undefined })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passkey sign-in was cancelled.')
    } finally {
      setPasskeyBusy(false)
    }
  }

  async function onSSO() {
    if (ssoBusy) return
    setSsoBusy(true)
    setError(null)
    try {
      // Real backend: navigates the browser to the gateway's OIDC start endpoint
      // (full-page redirect) — this call does not return. The IdP round-trips back
      // to /auth/callback, which finishes the session. Mock resolves a session and
      // AuthLayout redirects. Pass `next` through as returnTo so an SSO sign-in
      // can also resume a device-authorize handoff when the gateway honors it.
      await beginSSO(next ?? undefined)
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Single sign-on is not configured for this deployment.',
      )
      setSsoBusy(false)
    }
  }

  /* ----- Fresh deploy (auth-spec §1.1 step 1): no credential can pass this
   * form — show the "not set up yet" banner and redirect to the one-time setup
   * wizard. While the status probe is still resolving (null) the form renders;
   * a slow/failed probe must never block sign-in on a working deployment. ----- */
  if (setupNeeded) {
    return (
      <>
        <Card title="Sign in">
          <div className="cfs-auth-form">
            <Banner
              kind="warning"
              title="This deployment hasn’t been set up yet."
              detail="Create the first organization and admin account to get started."
              actionTitle="Go to setup"
              onAction={() => navigate('/setup')}
            />
          </div>
        </Card>
        <Navigate to="/setup" replace />
      </>
    )
  }

  /* ----- MFA second-factor step (after a correct password) ----- */
  if (step.kind === 'totp') {
    const recovery = step.recovery
    const offersTotp = step.methods.includes('totp')
    const offersPasskey = step.methods.includes('webauthn')

    // Passkey-ONLY second factor: there is no code to type. The assertion was kicked
    // off on entry (onSubmitCredentials); show its progress with a retry, never a TOTP
    // field the user can't satisfy.
    if (offersPasskey && !offersTotp) {
      return (
        <>
          <Card title="Two-factor authentication">
            <form className="cfs-auth-form" onSubmit={(e) => e.preventDefault()} noValidate>
              {error && <Banner kind="error" title="Verification failed" detail={error} />}
              <Banner
                kind="info"
                title="Confirm with your passkey"
                detail={`Use the passkey you registered for ${productName} to finish signing in. Your browser or device will prompt you.`}
              />
              <Button
                type="button"
                variant="primary"
                size="large"
                block
                leading={<Icons.IconKey />}
                disabled={passkeyBusy}
                onClick={() => completePasskeyChallenge(step.challengeId)}
              >
                {passkeyBusy ? 'Waiting for passkey…' : 'Use your passkey'}
              </Button>
              <button
                type="button"
                className="cfs-auth-link"
                style={{ alignSelf: 'center' }}
                onClick={() => {
                  setStep({ kind: 'credentials' })
                  setCode('')
                  setError(null)
                }}
              >
                Back to sign in
              </button>
            </form>
          </Card>
          <p className="cfs-auth-footnote">Signing in as {email.trim() || 'your account'}.</p>
        </>
      )
    }

    return (
      <>
        <Card title="Two-factor authentication">
          <form className="cfs-auth-form" onSubmit={onSubmitTotp} noValidate>
            {error && <Banner kind="error" title="Verification failed" detail={error} />}
            <Banner
              kind="info"
              title={recovery ? 'Enter a recovery code' : 'Enter your authentication code'}
              detail={
                recovery
                  ? 'Use one of the one-time recovery codes you saved when enabling 2FA.'
                  : `Open your authenticator app and enter the current 6-digit code for ${productName}.`
              }
            />
            <LabeledField
              label={recovery ? 'Recovery code' : 'Authentication code'}
              icon={<Icons.IconLock />}
              className={recovery ? undefined : 'cfs-otp'}
              inputMode={recovery ? 'text' : 'numeric'}
              autoComplete="one-time-code"
              placeholder={recovery ? 'xxxx-xxxx-xxxx' : '••••••'}
              maxLength={recovery ? 19 : 6}
              value={code}
              onChange={(e) =>
                setCode(recovery ? e.target.value : e.target.value.replace(/\D/g, '').slice(0, 6))
              }
              autoFocus
            />
            <div className="cfs-auth-accessory">
              <button
                type="button"
                className="cfs-auth-link"
                onClick={() => {
                  setStep({ ...step, recovery: !recovery })
                  setCode('')
                  setError(null)
                }}
              >
                {recovery ? 'Use an authenticator code' : 'Use a recovery code'}
              </button>
            </div>

            <Button
              type="submit"
              variant="primary"
              size="large"
              block
              disabled={busy || code.trim().length < (recovery ? 4 : 6)}
            >
              {busy ? 'Verifying…' : 'Verify and sign in'}
            </Button>

            {/* Both factors enrolled: let the user fall back to their passkey. */}
            {offersPasskey && (
              <Button
                type="button"
                variant="secondary"
                size="large"
                block
                leading={<Icons.IconKey />}
                disabled={passkeyBusy}
                onClick={() => completePasskeyChallenge(step.challengeId)}
              >
                {passkeyBusy ? 'Waiting for passkey…' : 'Use your passkey instead'}
              </Button>
            )}

            <button
              type="button"
              className="cfs-auth-link"
              style={{ alignSelf: 'center' }}
              onClick={() => {
                setStep({ kind: 'credentials' })
                setCode('')
                setError(null)
              }}
            >
              Back to sign in
            </button>
          </form>
        </Card>
        <p className="cfs-auth-footnote">Signing in as {email.trim() || 'your account'}.</p>
      </>
    )
  }

  /* ----- Loading the public auth config ----- */
  if (authConfig == null) {
    return (
      <Card title="Sign in">
        <div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--cfs-space-xxxl)' }}>
          <Spinner size={22} />
        </div>
      </Card>
    )
  }

  /* ----- OIDC-only: password sign-in is disabled; SSO is the only path ----- */
  if (oidcOnly) {
    return (
      <>
        <Card title="Sign in">
          <form className="cfs-auth-form" onSubmit={(e) => e.preventDefault()} noValidate>
            {error && <Banner kind="error" title="Couldn’t sign in" detail={error} />}
            <Banner
              kind="info"
              title="Single sign-on required"
              detail={`This organization signs in through ${providerLabel}. Continue to your identity provider to sign in.`}
            />
            <Button
              type="button"
              variant="primary"
              size="large"
              block
              leading={<Icons.IconSSO />}
              disabled={ssoBusy}
              onClick={onSSO}
            >
              {ssoBusy ? 'Redirecting…' : ssoLabel}
            </Button>
          </form>
        </Card>
        <p className="cfs-auth-footnote">
          Trouble signing in? Contact your organization’s administrator.
        </p>
      </>
    )
  }

  /* ----- Credentials step (built-in, or "both": password + SSO) ----- */
  return (
    <>
      <Card title={emailEntered ? "Enter your password" : "Log in to your account"}>
        <p className="cfs-login-intro">{emailEntered ? "Welcome back. Use your CloudFS password to continue." : "Enter your email to access your workspace."}</p>
        <form className="cfs-auth-form" onSubmit={onSubmitCredentials} noValidate>
          {error && <Banner kind="error" title="Couldn’t sign in" detail={error} />}

          <div className="cfs-auth-fields">
            <LabeledField
              label="Work email"
              icon={<Icons.IconMail />}
              type="email"
              placeholder="you@acme.example"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoFocus
              readOnly={emailEntered}
            />
            {emailEntered && <LabeledField
              label="Password"
              icon={<Icons.IconLock />}
              type="password"
              placeholder="Your password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
            />}
          </div>
          {emailEntered && <div className="cfs-auth-accessory"><button className="cfs-auth-link" type="button" onClick={() => { setEmailEntered(false); setPassword(''); setError(null) }}>Change email</button><Link className="cfs-auth-link" to="/forgot-password">Forgot password?</Link></div>}

          <Button type="submit" variant="primary" size="large" block disabled={!canSignIn}>
            {busy ? 'Signing in…' : emailEntered ? 'Sign in' : 'Continue'}
          </Button>

          {(availability.sso || availability.passkey) && <div className="cfs-auth-divider">or</div>}

          {availability.sso && <Button
            type="button"
            variant="secondary"
            size="large"
            block
            leading={<Icons.IconSSO />}
            disabled={ssoBusy}
            onClick={onSSO}
          >
            {ssoBusy ? 'Redirecting…' : ssoLabel}
          </Button>}
          {availability.passkey && <Button
            type="button"
            variant="secondary"
            size="large"
            block
            leading={<Icons.IconKey />}
            disabled={passkeyBusy}
            onClick={onPasskey}
          >
            {passkeyBusy ? 'Waiting for passkey…' : 'Use a passkey'}
          </Button>}
        </form>
      </Card>

      <p className="cfs-auth-footnote">
        {availability.signup ? <>New here? <Link to="/signup">Create an account</Link></> : 'Joining a team? Open the invitation link from your workspace admin.'}
      </p>
    </>
  )
}
