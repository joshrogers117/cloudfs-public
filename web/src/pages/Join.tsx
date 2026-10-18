// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Join — the editor's invite-to-Finder entry point (ONBOARDING.md editor journey step 2 / build
 * step 1). Reached from the emailed (or copy-linked) `/join?token=<joinToken>` invite link.
 *
 * Flow:
 *   1. Preview the invite (`GET /v1/auth/join/preview`) — a public read that never provisions
 *      anything, so a dead/expired/mistyped link never touches the account store. Renders the
 *      "<invitedByName> invited you to <orgName>" header (greying out gracefully when either is
 *      null) plus the invited email + role.
 *   2. Display name + password → `POST /v1/auth/join`, which atomically creates the credential,
 *      redeems the invite (membership + ACL grant), and signs the user in — one submit from an
 *      emailed link to a live session (unlike the old `/signup?org=&invite=` path this replaces,
 *      which redeemed membership but dead-ended with no credential; see SignUp.tsx).
 *   3. Optional, skippable passkey enrollment via the existing session-gated
 *      `POST /v1/auth/webauthn/register/*` routes (mirrors SignUp.tsx's post-signup passkey leg).
 *      There is NO passkey-at-join in the atomic call — join is password-first, same as signup.
 *   4. A clean success stub ("You're in — next, set up your Mac") with a placeholder app-download
 *      card (GetTheAppCard) a follow-up build step swaps for the real `cloudfs://connect` page.
 *
 * Every backend error code gets human copy. Dead invites (expired/revoked/already_used/not_found/
 * invalid_token/token_mismatch) replace the whole page with a dead-end — the token is spent, no
 * retry is possible, and the ONLY path forward is a fresh invite from an admin. `email_taken`
 * and `auth_mode_oidc` dead-end with a link to /signin instead. Recoverable form errors
 * (invalid_display_name/weak_password/password_too_long/password_breached/rate_limited) stay on
 * the form so the user can just fix the field and resubmit.
 *
 * Standalone route (own AuthLayout-style chrome, mirroring Setup.tsx): it renders BOTH
 * signed-out (preview + form) and signed-in (passkey offer + success) states, which
 * <AuthLayout/>'s "redirect once authenticated" behavior does not allow.
 */
import { useEffect, useId, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { Banner, BrandMark, Button, Card, Icons, LabeledField, Spinner } from '../design'
import { ApiError, getApi, MIN_PASSWORD_LENGTH, type JoinPreview, type MemberRole } from '../api'
import { useAuth } from '../app/auth'
import { useProductName } from '../app/productName'
import { estimatePassword } from './auth/passwordStrength'
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

/** A whole-page dead end: the token is spent, no retry on this page is possible. */
interface DeadEnd {
  title: string
  detail: string
  action?: { label: string; to: string }
}

const GENERIC_DEAD: DeadEnd = {
  title: 'This invite link doesn’t look right',
  detail: 'Double-check the link, or ask whoever invited you to send a new one.',
}

/** Error codes that mean the invite itself is unusable — the page dead-ends, no retry in place. */
const DEAD_END_CODES = new Set([
  'not_found',
  'invalid_token',
  'token_mismatch',
  'expired',
  'revoked',
  'already_used',
  'email_taken',
  'auth_mode_oidc',
  'join_incomplete',
])

function deadEndFor(err: unknown): DeadEnd {
  const code = err instanceof ApiError ? err.code : null
  switch (code) {
    case 'expired':
      return {
        title: 'This invitation has expired',
        detail: 'Invites are single-use and time-limited. Ask whoever invited you to send a new one.',
      }
    case 'revoked':
      return {
        title: 'This invitation was revoked',
        detail: 'Ask your admin to send a new invite if you still need access.',
      }
    case 'already_used':
      return {
        title: 'This invitation was already used',
        detail: 'If that was you, sign in instead. Otherwise, ask your admin for a new invite.',
        action: { label: 'Go to sign in', to: '/signin' },
      }
    case 'email_taken':
      return {
        title: 'You already have an account',
        detail:
          'An account already exists for this email address. Sign in instead — there’s no need to redeem this invite.',
        action: { label: 'Go to sign in', to: '/signin' },
      }
    case 'auth_mode_oidc':
      return {
        title: 'This organization signs in with SSO',
        detail:
          'Password sign-up is disabled on this deployment. Continue to sign-in and use your organization’s single sign-on.',
        action: { label: 'Go to sign in', to: '/signin' },
      }
    case 'join_incomplete':
      return {
        title: 'We hit a snag finishing your account',
        detail:
          'Your invitation was accepted, but something went wrong finishing setup. Contact your workspace admin — they can help you get in, or send you a fresh invite.',
      }
    case 'not_found':
    case 'invalid_token':
    case 'token_mismatch':
    default:
      return GENERIC_DEAD
  }
}

type Step =
  | { kind: 'loading' }
  | { kind: 'dead'; info: DeadEnd }
  | { kind: 'form'; preview: JoinPreview }
  | { kind: 'passkey'; preview: JoinPreview; enrolling: boolean }
  | { kind: 'done'; preview: JoinPreview }

export function Join() {
  const productName = useProductName()
  const navigate = useNavigate()
  const { refresh } = useAuth()
  const [params] = useSearchParams()
  const token = params.get('token') ?? ''

  // A missing token is known synchronously at first render (mirrors VerifyEmail.tsx) — no need to
  // round-trip through an effect just to discover what we already know from the URL.
  const [step, setStep] = useState<Step>(
    token ? { kind: 'loading' } : { kind: 'dead', info: GENERIC_DEAD },
  )
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [passkeyBusy, setPasskeyBusy] = useState(false)

  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')

  const strengthId = useId()
  const strength = useMemo(() => estimatePassword(password), [password])

  // Preview the invite on load — a public read, never provisions anything (§ above).
  useEffect(() => {
    if (!token) return
    let alive = true
    getApi()
      .previewJoin(token)
      .then((preview) => {
        if (alive) setStep({ kind: 'form', preview })
      })
      .catch((err: unknown) => {
        if (alive) setStep({ kind: 'dead', info: deadEndFor(err) })
      })
    return () => {
      alive = false
    }
  }, [token])

  const canSubmit =
    step.kind === 'form' && !busy && displayName.trim().length > 0 && password.length >= MIN_PASSWORD_LENGTH

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (step.kind !== 'form' || !canSubmit) return
    const preview = step.preview
    setBusy(true)
    setError(null)
    try {
      await getApi().join({ token, displayName: displayName.trim(), password })
      // The 201 set the session cookie — hydrate the app-wide session so the rest of the shell
      // (and the passkey enrollment ceremony below, which is session-gated) sees it immediately.
      await refresh()
      setStep({ kind: 'passkey', preview, enrolling: false })
    } catch (err) {
      if (err instanceof ApiError && DEAD_END_CODES.has(err.code ?? '')) {
        setStep({ kind: 'dead', info: deadEndFor(err) })
        return
      }
      setError(err instanceof Error ? err.message : 'Couldn’t complete your invitation. Try again.')
    } finally {
      setBusy(false)
    }
  }

  async function onAddPasskey() {
    if (step.kind !== 'passkey' || passkeyBusy) return
    const preview = step.preview
    setPasskeyBusy(true)
    setError(null)
    try {
      await getApi().registerPasskey(`${preview.email} · passkey`)
      setStep({ kind: 'done', preview })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passkey setup was cancelled.')
    } finally {
      setPasskeyBusy(false)
    }
  }

  /* ----- Render ----- */

  let body: ReactNode
  let footnote: ReactNode = null

  switch (step.kind) {
    case 'loading':
      body = (
        <Card title={`Join ${productName}`}>
          <div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--cfs-space-xxxl)' }}>
            <Spinner size={24} />
          </div>
        </Card>
      )
      break

    case 'dead': {
      const info = step.info
      body = (
        <Card title="Invitation">
          <div className="cfs-auth-form">
            <Banner kind="error" title={info.title} detail={info.detail} />
            {info.action ? (
              <Button variant="primary" size="large" block onClick={() => navigate(info.action!.to)}>
                {info.action.label}
              </Button>
            ) : (
              <Button variant="secondary" size="large" block onClick={() => navigate('/signin')}>
                Go to sign in
              </Button>
            )}
          </div>
        </Card>
      )
      break
    }

    case 'form': {
      const { preview } = step
      body = (
          <Card title={`Join ${preview.orgName ?? productName}`}>
            <form className="cfs-auth-form" onSubmit={onSubmit} noValidate>
              <p className="cfs-device-lede">
                {preview.invitedByName ? <strong>{preview.invitedByName}</strong> : 'Someone'} invited
                you to{' '}
                {preview.orgName ? (
                  <strong>{preview.orgName}</strong>
                ) : (
                  <span style={{ color: 'var(--cfs-text-tertiary)' }}>a {productName} workspace</span>
                )}
                .
              </p>
              <dl className="cfs-device-facts">
                <dt>Email</dt>
                <dd>{preview.email}</dd>
                <dt>Role</dt>
                <dd>{ROLE_LABEL[preview.role]}</dd>
              </dl>
              {error && <Banner kind="error" title="Couldn’t join" detail={error} />}
              <div className="cfs-auth-fields">
                <LabeledField
                  label="Your name"
                  icon={<Icons.IconSSO />}
                  placeholder="Alex Rivera"
                  autoComplete="name"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  autoFocus
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
              <Button type="submit" variant="primary" size="large" block disabled={!canSubmit}>
                {busy ? 'Joining…' : `Join ${preview.orgName ?? productName}`}
              </Button>
            </form>
          </Card>
      )
      footnote = (
        <p className="cfs-auth-footnote">
          Already have an account? <Link to="/signin">Sign in</Link>
        </p>
      )
      break
    }

    case 'passkey':
      body = (
        <Card title="Protect your account">
          <div className="cfs-auth-form">
            {error && <Banner kind="error" title="Couldn’t add a passkey" detail={error} />}
            <p className="cfs-auth-note" style={{ textAlign: 'left' }}>
              Add a passkey now for faster, phishing-resistant sign-in? You can also do this later
              from Account Settings.
            </p>
            <Button
              type="button"
              variant="primary"
              size="large"
              block
              leading={<Icons.IconKey />}
              disabled={passkeyBusy}
              onClick={onAddPasskey}
            >
              {passkeyBusy ? 'Setting up passkey…' : 'Add a passkey'}
            </Button>
            {/* Equally prominent — do not dark-pattern the skip (mirrors Setup.tsx's TOTP step). */}
            <Button
              type="button"
              variant="secondary"
              size="large"
              block
              disabled={passkeyBusy}
              onClick={() => setStep({ kind: 'done', preview: step.preview })}
            >
              Skip for now
            </Button>
          </div>
        </Card>
      )
      footnote = <p className="cfs-auth-footnote">Optional — you can add or remove passkeys any time.</p>
      break

    case 'done':
      body = (
        <Card title="You’re in">
          <div className="cfs-auth-form">
            <div className="cfs-auth-success">
              <span className="cfs-auth-success__glyph">
                <Icons.IconCheck size={34} />
              </span>
              <span className="cfs-auth-success__title">
                Welcome to {step.preview.orgName ?? productName}
              </span>
              <p className="cfs-auth-success__body">
                Your account is ready. Next, set up your Mac to start working with your files.
              </p>
            </div>
            <div className="cfs-setup-next">
              <GetTheAppCard />
            </div>
            <Button variant="secondary" size="large" block leading={<Icons.IconGlobe />} onClick={() => navigate('/filespaces')}>
              Continue in browser
            </Button>
          </div>
        </Card>
      )
      break
  }

  return (
    <main className="cfs-auth-layout cfs-join-layout">
      <div className="cfs-auth-layout__inner">
        <header className="cfs-hero">
          <BrandMark size={48} chrome className="cfs-hero__plate" />
          <span className="cfs-hero__wordmark">{productName}</span>
        </header>
        {body}
        {footnote}
      </div>
    </main>
  )
}
