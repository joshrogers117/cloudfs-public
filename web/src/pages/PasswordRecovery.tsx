// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState, type FormEvent } from 'react'
import { Link, useSearchParams, useLocation, useNavigate } from 'react-router-dom'
import { Banner, Button, Card, LabeledField } from '../design'
import { getApi, MIN_PASSWORD_LENGTH } from '../api'
import { useAuth } from '../app/auth'
import './auth/auth.css'

/** Password-reset links remain usable even when another browser session exists. */
export function PasswordRecovery({ reset = false, legacy = false }: { reset?: boolean; legacy?: boolean }) {
  const [params, setParams] = useSearchParams()
  const location = useLocation()
  const navigate = useNavigate()
  const { refresh } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const link = location.hash ? new URLSearchParams(location.hash.slice(1)) : params
  const token = link.get('token') ?? ''
  const orgId = link.get('orgId') ?? ''
  const completeLink = Boolean(token && orgId)
  const valid = reset
    ? completeLink && password.length >= MIN_PASSWORD_LENGTH && password === confirmation
    : /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!valid || busy) return
    setBusy(true)
    setError(null)
    try {
      if (reset) {
        if (legacy) await getApi().enrollLegacyAccount(token, orgId, password)
        else await getApi().resetPassword(token, orgId, password)
        setPassword('')
        setConfirmation('')
        // The server revokes sessions; discard the consumed token from this URL.
        if (legacy || location.hash) navigate(legacy ? '/finish-sign-in' : '/reset-password', { replace: true })
        else setParams({}, { replace: true })
        await refresh()
      } else {
        await getApi().requestPasswordReset(email.trim())
      }
      setDone(true)
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Couldn’t complete the request. Try again.')
    } finally {
      setBusy(false)
    }
  }

  return <>
    <Card title={legacy ? 'Finish setting up your sign-in' : reset ? 'Choose a new password' : 'Reset your password'}>
      {done ? <div className="cfs-auth-form">
        <Banner kind="success" title={legacy ? 'Your account is ready' : reset ? 'Password updated' : 'Check your email'} detail={legacy
          ? 'Sign in with your existing email and this password on the web or in the CloudFS app. Your workspace and files are preserved.' : reset
          ? 'Your previous sessions have been signed out. Use your new password to sign in.'
          : 'If an active account matches this address and email delivery is configured, you’ll receive a reset link. Check your spam folder or contact your workspace administrator.'} />
        <Link className="cfs-auth-link" to="/signin">Return to sign in</Link>
      </div> : reset && !completeLink ? <div className="cfs-auth-form">
        <Banner kind="error" title={legacy ? 'This sign-in link is incomplete' : 'This reset link is incomplete'} detail={legacy
          ? 'Open the full account migration link from your deployment administrator.' : 'Open the full link from your email, or request a new one.'} />
        {!legacy && <Link className="cfs-auth-link" to="/forgot-password">Request a new link</Link>}
      </div> : <form className="cfs-auth-form" onSubmit={submit}>
        {legacy && <p>Choose a password for your existing account. You’ll use it to sign in to the web admin and CloudFS app.</p>}
        {error && <Banner kind="error" title={legacy ? 'Couldn’t finish sign-in setup' : 'Couldn’t reset your password'} detail={error} />}
        {reset ? <>
          <LabeledField label="New password" type="password" autoComplete="new-password" value={password}
            onChange={(event) => setPassword(event.target.value)} hint={`Use at least ${MIN_PASSWORD_LENGTH} characters.`} disabled={busy} />
          <LabeledField label="Confirm new password" type="password" autoComplete="new-password" value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)} disabled={busy}
            hint={confirmation && confirmation !== password ? 'The passwords don’t match.' : undefined} />
        </> : <LabeledField label="Work email" type="email" autoComplete="email" value={email}
          onChange={(event) => setEmail(event.target.value)} disabled={busy} />}
        <Button type="submit" variant="primary" block disabled={!valid || busy}>
          {busy ? 'Working…' : legacy ? 'Save password' : reset ? 'Save new password' : 'Send reset link'}
        </Button>
        {reset && !legacy && <Link className="cfs-auth-link" to="/forgot-password">Request a new reset link</Link>}
      </form>}
    </Card>
    {!done && <p className="cfs-auth-footnote"><Link to="/signin">Back to sign in</Link></p>}
  </>
}
