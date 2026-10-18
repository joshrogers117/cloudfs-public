/*
 * AuthCallback — the SSO landing route (/auth/callback).
 *
 * After "Sign in with your organization (SSO)" navigates the browser to the
 * gateway's OIDC start endpoint, the IdP authenticates the user and round-trips
 * back to the gateway callback, which sets the `cfs_session` cookie and redirects
 * here. We call completeSSO() (→ me()) to hydrate the session, then route into the
 * app (/filespaces) or back to /signin with an error.
 *
 * The backend may signal failure via `?error=<code>` on the redirect (OIDC typed
 * errors per API.md / oidc.ts), which we surface instead of looping.
 */
import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Banner, BrandMark, Button, Spinner } from '../design'
import { StatusDot } from '../design/components'
import { useAuth } from '../app/auth'
import '../app/shell.css'
import './auth/auth.css'

export function AuthCallback() {
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const { completeSSO } = useAuth()
  // The IdP/gateway may redirect back with ?error=<code> (OIDC typed errors). That
  // is known at first render, so derive it directly rather than via an effect.
  const providerError = params.get('error')
  const [error, setError] = useState<string | null>(
    providerError ? humanizeOidcError(providerError) : null,
  )
  const ran = useRef(false)

  useEffect(() => {
    if (ran.current || providerError) return
    ran.current = true

    let alive = true
    completeSSO()
      .then((session) => {
        if (!alive) return
        if (session) navigate('/filespaces', { replace: true })
        else setError('Single sign-on did not establish a session. Please try again.')
      })
      .catch((err: unknown) => {
        if (alive) setError(err instanceof Error ? err.message : 'Single sign-on failed.')
      })
    return () => {
      alive = false
    }
  }, [completeSSO, navigate, providerError])

  return (
    <main className="cfs-auth-layout">
      <div className="cfs-auth-layout__inner">
        <header className="cfs-hero">
          <BrandMark size={72} chrome className="cfs-hero__plate" />
          <span className="cfs-hero__wordmark">cloud-fs</span>
          {!error && (
            <span className="cfs-hero__status">
              <StatusDot color="busy" size={7} />
              Completing single sign-on…
            </span>
          )}
        </header>

        {error ? (
          <>
            <Banner kind="error" title="Couldn’t complete sign-in" detail={error} />
            <Button
              variant="primary"
              size="large"
              block
              onClick={() => navigate('/signin', { replace: true })}
            >
              Back to sign in
            </Button>
          </>
        ) : (
          <div
            style={{
              display: 'flex',
              justifyContent: 'center',
              padding: 'var(--cfs-space-xxxl)',
            }}
          >
            <Spinner size={24} />
          </div>
        )}
      </div>
    </main>
  )
}

function humanizeOidcError(code: string): string {
  const map: Record<string, string> = {
    provider_error: 'Your identity provider rejected the sign-in.',
    state_mismatch: 'The sign-in could not be verified (state mismatch). Please try again.',
    provision_denied: 'Your account is not provisioned for this organization.',
    bad_callback: 'The sign-in response was malformed. Please try again.',
    not_found: 'Single sign-on is not configured for this deployment.',
  }
  return map[code] ?? code.replace(/_/g, ' ')
}
