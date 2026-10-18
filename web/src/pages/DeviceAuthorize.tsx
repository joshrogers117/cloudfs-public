/*
 * DeviceAuthorize — the portal approval screen for the Mac app's browser-handoff
 * sign-in (auth-spec §1.3 / §2.1 / §2.2, W1).
 *
 * The app opens
 *   /device/authorize?state&code_challenge&code_challenge_method=S256
 *                    &device_name&device_model&app_version
 * in the system browser. A signed-out visitor is bounced through
 * `/signin?next=<this url>` and lands back here authenticated. The user then
 * EXPLICITLY approves; we POST /v1/auth/device/approve (cookie + CSRF) and
 * navigate to `cloudfs://auth/callback?code&state` — with an always-visible
 * copyable one-time-code fallback ("App didn't open?") because macOS custom
 * schemes can be silently dropped or prompt-blocked.
 *
 * Malformed / incomplete params (bad code_challenge, absent state, oversize
 * device name) NEVER render an approve button. Deny needs no backend call: the
 * pending request simply never gets a code and the app times out.
 *
 * Standalone route (its own AuthLayout-style chrome) because it needs the
 * inverse of AuthLayout's redirect: it REQUIRES a session.
 */
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Navigate, useLocation, useSearchParams } from 'react-router-dom'
import { Banner, BrandMark, Button, Card, Spinner } from '../design'
import { StatusDot } from '../design/components'
import { ApiError, getApi, type DeviceApproveResult } from '../api'
import { useAuth } from '../app/auth'
import { signinWithNext } from '../app/nextParam'
import { IconCopy } from './settings/icons'
import { displayProductName } from '../app/productName'
import '../app/shell.css'
import './auth/auth.css'

/** The validated authorize request parsed from the app's query params (§2.1). */
interface AuthorizeRequest {
  state: string
  codeChallenge: string
  deviceName: string
  deviceModel?: string
  appVersion?: string
}

const B64URL = /^[A-Za-z0-9_-]+$/

/** Strip control characters (mirrors the backend's deviceName cleaning, §2.2). */
function stripControl(s: string): string {
  let out = ''
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0
    if (cp >= 0x20 && cp !== 0x7f) out += ch
  }
  return out
}

/** Validate the query params; null = malformed (never show an approve button). */
function parseRequest(params: URLSearchParams): AuthorizeRequest | null {
  const state = (params.get('state') ?? '').trim()
  const challenge = params.get('code_challenge') ?? ''
  const method = params.get('code_challenge_method') ?? ''
  const name = stripControl(params.get('device_name') ?? '').trim()
  const model = stripControl(params.get('device_model') ?? '').trim()
  const appVersion = stripControl(params.get('app_version') ?? '').trim()

  if (!state) return null
  if (method !== 'S256') return null // reject anything else (§2.1)
  if (challenge.length < 43 || challenge.length > 128 || !B64URL.test(challenge)) return null
  if (!name || name.length > 64) return null
  if (model.length > 32) return null
  if (appVersion.length > 16) return null

  return {
    state,
    codeChallenge: challenge,
    deviceName: name,
    deviceModel: model || undefined,
    appVersion: appVersion || undefined,
  }
}

type Phase =
  | { kind: 'review' }
  | { kind: 'approving' }
  | { kind: 'approved'; result: DeviceApproveResult }
  | { kind: 'denied' }
  | { kind: 'spoiled' } // the request was consumed/rejected server-side — start over

export function DeviceAuthorize() {
  const { isAuthenticated, loading, session } = useAuth()
  const location = useLocation()
  const [params] = useSearchParams()
  const request = useMemo(() => parseRequest(params), [params])

  const [phase, setPhase] = useState<Phase>({ kind: 'review' })
  const [error, setError] = useState<string | null>(null)
  const [sessionLost, setSessionLost] = useState(false)
  const [copied, setCopied] = useState(false)

  // Product display name from the deployment's public config (auth-spec §2.8) —
  // the only config fetch on this page. Fallback keeps the title rendering if
  // the gateway predates `productName` or the request fails.
  const [productName, setProductName] = useState<string | null>(null)
  useEffect(() => {
    let alive = true
    getApi()
      .getPublicAuthConfig()
      .then((c) => {
        if (alive) setProductName(c.productName?.trim() || null)
      })
      .catch(() => {
        /* keep the fallback name */
      })
    return () => {
      alive = false
    }
  }, [])
  const product = displayProductName(productName)

  // Session evaporated mid-approval (or was never there): authenticate FIRST,
  // then come back and approve (§1.3).
  if (sessionLost || (!loading && !isAuthenticated)) {
    return <Navigate to={signinWithNext(location.pathname, location.search)} replace />
  }

  async function approve() {
    if (!request || phase.kind === 'approving') return
    setPhase({ kind: 'approving' })
    setError(null)
    try {
      const res = await getApi().approveDevice({
        state: request.state,
        codeChallenge: request.codeChallenge,
        codeChallengeMethod: 'S256',
        deviceName: request.deviceName,
        deviceModel: request.deviceModel,
      })
      setPhase({ kind: 'approved', result: res })
      // Hand the one-time code to the app via its custom scheme. The page stays
      // up with the paste fallback below — LaunchServices may prompt or silently
      // drop the URL, and the code must survive that.
      window.location.assign(
        `cloudfs://auth/callback?code=${encodeURIComponent(res.code)}&state=${encodeURIComponent(res.state)}`,
      )
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401 || err.status === 403) {
          setSessionLost(true)
          return
        }
        if (err.status === 400) {
          // bad_challenge / bad_method / bad_device_name — the request itself is
          // bad (or was already consumed); never re-offer Approve for it.
          setPhase({ kind: 'spoiled' })
          return
        }
        if (err.status === 429) {
          setPhase({ kind: 'review' })
          setError('Too many sign-in approvals right now. Wait a minute and try again.')
          return
        }
      }
      setPhase({ kind: 'review' })
      setError(err instanceof Error ? err.message : 'Couldn’t approve the sign-in. Try again.')
    }
  }

  async function copyCode(code: string) {
    try {
      await navigator.clipboard?.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    } catch {
      /* clipboard may be unavailable; the code is visible/selectable to copy */
    }
  }

  /* ----- Page body by state ----- */

  let body: ReactNode
  let footnote: ReactNode = null

  if (loading || !session) {
    body = (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--cfs-space-xxxl)' }}>
        <Spinner size={24} />
      </div>
    )
  } else if (!request || phase.kind === 'spoiled') {
    /* Malformed/missing params, or a request the server refused/already burned. */
    body = (
      <Card title="Sign-in request">
        <div className="cfs-auth-form">
          <Banner
            kind="error"
            title="This sign-in link is invalid or incomplete."
            detail={
              phase.kind === 'spoiled'
                ? `The request may have expired or already been used. Start again from the ${product} app.`
                : `Start again from the ${product} app.`
            }
          />
        </div>
      </Card>
    )
  } else if (phase.kind === 'denied') {
    body = (
      <Card title="Sign-in request denied">
        <div className="cfs-auth-form">
          <Banner
            kind="info"
            title="Sign-in request denied."
            detail="You can close this tab. Nothing was shared with the device."
          />
        </div>
      </Card>
    )
  } else if (phase.kind === 'approved') {
    const { result } = phase
    body = (
      <Card title="Approved">
        <div className="cfs-auth-form">
          <Banner
            kind="success"
            title={`Approved ✓ — Returning you to the ${product} app…`}
            detail="macOS will switch to the app automatically."
          />
          {/* Always visible — there is no dead end on any browser (§1.1 step 5). */}
          <div className="cfs-auth-fields">
            <p className="cfs-device-fallback">
              App didn’t open? Paste this one-time code in the app:
            </p>
            <div className="cfs-code-box">
              <span className="cfs-code-box__code">{result.code}</span>
              <Button
                variant="secondary"
                size="small"
                leading={<IconCopy size={13} />}
                onClick={() => void copyCode(result.code)}
              >
                {copied ? 'Copied' : 'Copy'}
              </Button>
            </div>
            <p className="cfs-auth-note">
              This code works once and expires in {Math.round(result.expiresInSeconds / 60)}{' '}
              minutes.
            </p>
          </div>
        </div>
      </Card>
    )
    footnote = <p className="cfs-auth-footnote">You can close this tab once the app opens.</p>
  } else {
    /* The approval screen proper (§1.3). */
    const device = request.deviceModel
      ? `${request.deviceName} (${request.deviceModel})`
      : request.deviceName
    body = (
      <Card title={`Sign in to ${product} on “${request.deviceName}”?`}>
        <div className="cfs-auth-form">
          {error && <Banner kind="error" title="Couldn’t approve the sign-in" detail={error} />}
          <p className="cfs-device-lede">
            A Mac app on this device is asking to sign in as{' '}
            <strong>{session.user.email}</strong> ({session.org.name}).
          </p>
          <dl className="cfs-device-facts">
            <dt>Device</dt>
            <dd>{device}</dd>
            <dt>Access</dt>
            <dd>Files, locks and snapshots — same as your account</dd>
            {request.appVersion && (
              <>
                <dt>App</dt>
                <dd>{product} {request.appVersion}</dd>
              </>
            )}
          </dl>
          <Button
            type="button"
            variant="primary"
            size="large"
            block
            disabled={phase.kind === 'approving'}
            onClick={() => void approve()}
          >
            {phase.kind === 'approving' ? 'Approving…' : 'Approve sign-in'}
          </Button>
          <Button
            type="button"
            variant="secondary"
            size="large"
            block
            disabled={phase.kind === 'approving'}
            onClick={() => setPhase({ kind: 'denied' })}
          >
            Deny
          </Button>
        </div>
      </Card>
    )
    // The phishing tripwire: name the device, tell the user when to deny (§1.3).
    footnote = (
      <p className="cfs-auth-footnote">
        Didn’t request this from your Mac? Deny, and consider changing your password.
      </p>
    )
  }

  return (
    <main className="cfs-auth-layout">
      <div className="cfs-auth-layout__inner">
        <header className="cfs-hero">
          <BrandMark size={72} chrome className="cfs-hero__plate" />
          <span className="cfs-hero__wordmark">{product}</span>
          <span className="cfs-hero__status">
            <StatusDot color={phase.kind === 'approved' ? 'ok' : 'busy'} size={7} />
            {phase.kind === 'approved' ? 'Approved' : 'Device sign-in request'}
          </span>
        </header>
        {body}
        {footnote}
      </div>
    </main>
  )
}
