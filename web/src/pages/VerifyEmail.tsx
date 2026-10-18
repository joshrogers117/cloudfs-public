/*
 * VerifyEmail — the PUBLIC (no-auth) email-verification landing page.
 *
 * The verification email now links at THIS web app:
 *   ${WEB_BASE_URL}/verify-email?token=<t>&orgId=<o>
 * (dev: http://localhost:5173/verify-email?...). A signed-out visitor clicking the
 * link lands here; we read `token` + `orgId` from the query string and POST them to
 * the confirm endpoint (`POST /v1/auth/verify-email`, via getApi().confirmEmail).
 *
 * Renders inside <AuthLayout/> (centered branded card), reusing the same calm
 * verify-panel design as the signup success step. Shows a success state with a
 * "Continue to sign in" button, or a clear failure state (expired/invalid link)
 * with a hint to request a fresh link.
 *
 * Owned by the Auth screen lane.
 */
import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Button, Card, Icons } from '../design'
import { getApi } from '../api'
import './auth/auth.css'

type Phase = 'verifying' | 'ok' | 'error'

export function VerifyEmail() {
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const token = params.get('token') ?? ''
  const orgId = params.get('orgId') ?? ''

  // A link missing either field is malformed — known at first render, so derive it
  // directly (no round-trip, no synchronous setState in an effect).
  const linkComplete = Boolean(token && orgId)
  const [phase, setPhase] = useState<Phase>(linkComplete ? 'verifying' : 'error')
  const [error, setError] = useState<string | null>(
    linkComplete
      ? null
      : 'This verification link is incomplete. Please use the most recent link from your email.',
  )
  // StrictMode double-invokes effects in dev; guard so we POST the token once.
  const ran = useRef(false)

  useEffect(() => {
    if (ran.current || !linkComplete) return
    ran.current = true

    let alive = true
    getApi()
      .confirmEmail(token, orgId)
      .then(() => alive && setPhase('ok'))
      .catch((err: unknown) => {
        if (!alive) return
        setError(err instanceof Error ? err.message : 'This verification link is invalid or has expired.')
        setPhase('error')
      })
    return () => {
      alive = false
    }
  }, [token, orgId, linkComplete])

  if (phase === 'verifying') {
    return (
      <Card title="Verifying your email">
        <div className="cfs-auth-success">
          <span className="cfs-auth-success__glyph" style={{ color: 'var(--cfs-status-busy)' }}>
            <Icons.IconMail size={34} />
          </span>
          <span className="cfs-auth-success__title">Confirming your link…</span>
          <p className="cfs-auth-success__body">
            One moment while we verify your email and finish setting up your workspace.
          </p>
        </div>
      </Card>
    )
  }

  if (phase === 'ok') {
    return (
      <>
        <Card title="Email verified">
          <div className="cfs-auth-success">
            <span className="cfs-auth-success__glyph">
              <Icons.IconCheck size={34} />
            </span>
            <p className="cfs-auth-success__body">
              Your email is confirmed. Sign in to continue.
            </p>
            <div className="cfs-auth-form" style={{ width: '100%' }}>
              <Button variant="primary" size="large" block onClick={() => navigate('/signin')}>
                Continue to sign in
              </Button>
            </div>
          </div>
        </Card>
        <p className="cfs-auth-footnote">
          Having trouble? Contact your workspace administrator.
        </p>
      </>
    )
  }

  return (
    <>
      <Card title="Verification failed">
        <div className="cfs-auth-success">
          <span className="cfs-auth-success__glyph" style={{ color: 'var(--cfs-status-error)' }}>
            <Icons.IconError size={34} />
          </span>
          <p className="cfs-auth-success__body">
            {error ?? 'This verification link is invalid or has expired.'} Sign in to request a new link.
          </p>
          <div className="cfs-auth-form" style={{ width: '100%' }}>
            <Button variant="primary" size="large" block onClick={() => navigate('/signin')}>
              Go to sign in
            </Button>
          </div>
        </div>
      </Card>
    </>
  )
}
