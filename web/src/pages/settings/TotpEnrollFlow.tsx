/*
 * TotpEnrollFlow — the shared TOTP enrollment flow: QR/setup-key + 6-digit
 * confirm, then the ONE-TIME recovery codes with copy/download. Extracted from
 * AccountSettings' TwoFactorSection so the first-run /setup wizard's optional
 * "Protect this account" step reuses the exact same enrollment UI (auth-spec
 * §1.1 step 4 / W3).
 *
 * Owns the whole ceremony through the getApi() seam (begin on mount → confirm →
 * recovery codes → Done); the caller owns the surrounding chrome (SettingsRow vs
 * wizard card) and what happens after Done/Cancel. Recovery codes are REAL
 * single-use credentials minted server-side and returned exactly once — they are
 * always surfaced here, never fabricated or discarded.
 */
import { useEffect, useState } from 'react'
import { Banner, Button, LabeledField, Spinner } from '../../design'
import { getApi } from '../../api'
import type { TotpEnrollment } from '../../api'
import { IconCopy } from './icons'
import { renderTotpQr } from './totpQr'
import './settings.css'

export function TotpEnrollFlow({
  onEnrolled,
  onDone,
  onCancel,
}: {
  /** Fired once the server confirms enrollment (refresh the session/user here). */
  onEnrolled?: () => void | Promise<void>
  /** Fired when the user dismisses the recovery-codes view ("Done"). */
  onDone: () => void
  /** Fired when the user backs out before confirming. */
  onCancel: () => void
}) {
  const [enrollment, setEnrollment] = useState<TotpEnrollment | null>(null)
  const [recovery, setRecovery] = useState<string[] | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [secretCopied, setSecretCopied] = useState(false)
  const [codesCopied, setCodesCopied] = useState(false)
  const [qrUrl, setQrUrl] = useState<string | null>(null)
  const [qrUnavailable, setQrUnavailable] = useState(false)

  // Begin enrollment on mount — the caller renders this component when (and only
  // when) the user chose to enroll.
  useEffect(() => {
    let alive = true
    getApi()
      .beginTotpEnrollment()
      .then(async (e) => {
        if (!alive) return
        setEnrollment(e)
        try {
          const url = await renderTotpQr(e.otpauthUri)
          if (alive) setQrUrl(url)
        } catch {
          if (alive) setQrUnavailable(true)
        }
      })
      .catch(() => alive && setError('Couldn’t start enrollment. Try again.'))
    return () => {
      alive = false
    }
  }, [])

  async function confirm() {
    if (code.trim().length < 6) {
      setError('Enter the 6-digit code from your authenticator app.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const res = await getApi().confirmTotpEnrollment(code.trim())
      // Preserve one-time recovery codes before refreshing account details.
      // A refresh failure must not disguise a successful MFA enrollment.
      setRecovery(res.recoveryCodes)
      setEnrollment(null)
      try { await onEnrolled?.() }
      catch { setError('Two-factor is enabled, but account details could not refresh. Save these recovery codes before reloading.') }
    } catch {
      setError('That code didn’t match. Try again.')
    } finally {
      setBusy(false)
    }
  }

  async function copySecret() {
    if (!enrollment) return
    try {
      if (!navigator.clipboard) return
      await navigator.clipboard.writeText(enrollment.secret)
      setSecretCopied(true)
      setTimeout(() => setSecretCopied(false), 1800)
    } catch {
      /* clipboard may be unavailable; the secret is visible to copy manually */
    }
  }

  async function copyCodes() {
    if (!recovery) return
    try {
      if (!navigator.clipboard) return
      await navigator.clipboard.writeText(recovery.join('\n'))
      setCodesCopied(true)
      setTimeout(() => setCodesCopied(false), 1800)
    } catch {
      /* codes remain visible to copy manually */
    }
  }

  /* ----- Recovery-codes view (after a confirmed enrollment) ----- */
  if (recovery) {
    return (
      <div className="cfs-set-form" style={{ maxWidth: 460 }}>
        <Banner
          kind="success"
          title="Two-factor is on"
          detail="Save these recovery codes somewhere safe. Each can be used once if you lose your authenticator."
        />
        {error && <Banner kind="error" title={error} />}
        <div className="cfs-recovery" aria-label="Recovery codes">
          {recovery.map((c) => (
            <span key={c} className="cfs-recovery__code">
              {c}
            </span>
          ))}
        </div>
        <div className="cfs-set-form__actions">
          <Button
            variant="secondary"
            size="small"
            leading={<IconCopy size={13} />}
            onClick={() => void copyCodes()}
          >
            {codesCopied ? 'Copied' : 'Copy codes'}
          </Button>
          <Button variant="secondary" size="small" onClick={() => downloadCodes(recovery)}>
            Download codes
          </Button>
          <Button variant="subtle" onClick={onDone}>
            Done
          </Button>
        </div>
      </div>
    )
  }

  /* ----- Starting (or failed-to-start) ----- */
  if (!enrollment) {
    return (
      <div className="cfs-set-form">
        {error ? (
          <>
            <Banner kind="error" title={error} />
            <div className="cfs-set-form__actions">
              <Button variant="subtle" onClick={onCancel}>
                Cancel
              </Button>
            </div>
          </>
        ) : (
          <Spinner size={20} />
        )}
      </div>
    )
  }

  /* ----- Enrolling: QR/setup key + 6-digit confirm ----- */
  return (
    <div className="cfs-totp">
      <div className="cfs-totp__qr">
        {qrUrl ? <img src={qrUrl} alt="Scan to add CloudFS to your authenticator app" width={240} height={240} />
          : qrUnavailable ? <span>Use the setup key</span>
          : <Spinner size={20} />}
      </div>
      <div className="cfs-totp__detail">
        <p className="cfs-totp__hint">
          {qrUnavailable
            ? 'The QR code could not be displayed. Enter this setup key manually in your authenticator app, then type the 6-digit code to confirm.'
            : 'Scan the QR code in your authenticator app, or enter this setup key manually, then type the 6-digit code to confirm.'}
        </p>
        <span className="cfs-mono-key" aria-label="TOTP secret">
          {enrollment.secret}
        </span>
        <div className="cfs-set-form__actions">
          <Button
            variant="secondary"
            size="small"
            leading={<IconCopy size={13} />}
            onClick={() => void copySecret()}
          >
            {secretCopied ? 'Copied' : 'Copy key'}
          </Button>
        </div>
        {error && <Banner kind="error" title={error} />}
        <div className="cfs-set-form" style={{ maxWidth: 220 }}>
          <LabeledField
            label="6-digit code"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="000000"
          />
          <div className="cfs-set-form__actions">
            <Button onClick={() => void confirm()} disabled={busy || code.length < 6}>
              {busy ? 'Confirming…' : 'Confirm'}
            </Button>
            <Button variant="subtle" onClick={onCancel} disabled={busy}>
              Cancel
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}

/** Save the one-time recovery codes as a plain-text file. */
function downloadCodes(codes: string[]) {
  const blob = new Blob([codes.join('\n') + '\n'], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'cloud-fs-recovery-codes.txt'
  a.click()
  URL.revokeObjectURL(url)
}
