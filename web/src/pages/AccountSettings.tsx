/*
 * AccountSettings — AUTH screen lane. Renders inside <RootLayout/> content pane
 * at /settings. Owned by the Account-Settings screen agent.
 *
 * Mirrors the macOS app's grouped Preferences / Cache panes: a stack of surface
 * groups, each with an ALL-CAPS section label, a description line, and
 * hairline-separated rows (label + sublabel on the left, control on the right).
 *
 * Sections:
 *   - Profile        display name + email                  → updateAccount
 *   - Password       current + new + confirm
 *   - Two-factor     enroll (otpauth QR + confirm) / recovery codes / disable
 *                                  → beginTotpEnrollment / confirmTotpEnrollment / disableTotp
 *   - Passkeys       list + add + remove                   → listPasskeys / registerPasskey / removePasskey
 *   - Organization   org name (editable by Owner/Admin)    → (mock, in-screen)
 *
 * Everything goes through the MockApi seam (getApi()) and useAuth(); no real
 * backend. After mutations that change the user, refresh() re-reads the session
 * so the rest of the app stays in sync.
 */
import { useEffect, useRef, useState } from 'react'
import { Link, Navigate, useLocation } from 'react-router-dom'
import { permissionsFor } from '../app/permissions'
import { Banner, Button, LabeledField, PaneHeader, Spinner } from '../design'
import { IconCheck, IconError, IconKey, IconMail, IconLock, IconPlus } from '../design/icons'
import { getApi, MIN_PASSWORD_LENGTH } from '../api'
import type { Organization, Passkey, User } from '../api/types'
import { useAuth } from '../app/auth'
import { SettingsGroup, SettingsRow } from './settings/SettingsGroup'
import { StorageCredentialsSection } from './settings/StorageCredentialsSection'
import { EmailSection } from './settings/EmailSection'
import { TroubleshootingSection } from './settings/TroubleshootingSection'
import { AuthProviderSection } from './settings/AuthProviderSection'
import { TotpEnrollFlow } from './settings/TotpEnrollFlow'
import { IconPasskey, IconShield, IconTrash } from './settings/icons'
import './settings/settings.css'
import './filespaces/filespaces.css'

const api = getApi()

export function AccountSettings({ workspace = false }: { workspace?: boolean }) {
  const { user, session, refresh } = useAuth()
  const { hash } = useLocation()
  const sections = ['general', 'signin', 'storage', 'email', 'troubleshooting']
  const requestedSection = sections.includes(hash.slice(1)) ? hash.slice(1) : null
  const [selected, setSelected] = useState(requestedSection ?? 'general')
  if (requestedSection && requestedSection !== selected) setSelected(requestedSection)

  // Local editable org copy, persisted through the authenticated org endpoint.
  // Re-sync to the session's org during render when its identity changes, so we
  // pick up a fresh org without a cascading effect (per React guidance).
  const [org, setOrg] = useState<Organization | null>(session?.org ?? null)
  const [orgSyncId, setOrgSyncId] = useState(session?.org?.id)
  if (session?.org && session.org.id !== orgSyncId) {
    setOrg(session.org)
    setOrgSyncId(session.org.id)
  }

  if (!user || !org) {
    return (
      <>
        <PaneHeader title="Settings" subtitle="Account, security, and passkeys" />
        <div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--cfs-space-xxxl)' }}>
          <Spinner size={24} />
        </div>
      </>
    )
  }

  const canEditOrg = permissionsFor(user.orgRole).manageWorkspace
  if (workspace && !canEditOrg) return <Navigate to="/filespaces" replace />

  return (
    <div key={org.id} className={workspace ? 'cfs-workspace-settings cfs-settings-page' : 'cfs-my-account'}>
      {!workspace && <Link to="/filespaces" className="cfs-account-close cfs-icon-button" aria-label="Close My account">×</Link>}
      <PaneHeader title={workspace ? 'Workspace settings' : 'My account'} subtitle={workspace ? org.name : undefined} />
      {workspace ? <>
        <nav className="cfs-settings-nav" aria-label="Workspace settings sections">
          {sections.map((id, index) => <Link key={id} to={`#${id}`} aria-current={selected === id ? 'page' : undefined}>
            {['General', 'Sign-in', 'Storage', 'Email', 'Troubleshooting'][index]}
          </Link>)}
        </nav>
        <div hidden={selected !== 'general'}><OrgSection org={org} canEdit={canEditOrg} onSaved={setOrg} /></div>
        <div hidden={selected !== 'signin'}><AuthProviderSection org={org.slug} /></div>
        <div hidden={selected !== 'storage'}><StorageCredentialsSection org={org.slug} /></div>
        <div hidden={selected !== 'email'}><EmailSection org={org.slug} /></div>
        <div hidden={selected !== 'troubleshooting'}><TroubleshootingSection key={org.slug} org={org.slug} /></div>
      </> : <>
        <ProfileSection user={user} onSaved={refresh} />
        <PasswordSection />
        <TwoFactorSection user={user} onChanged={refresh} />
        <PasskeysSection />
      </>}
    </div>
  )
}

/* ===== Inline status note (saved / error) =============================== */

function Note({ kind, children }: { kind: 'ok' | 'error'; children: React.ReactNode }) {
  return (
    <span className={`cfs-set-note cfs-set-note--${kind}`} role="status">
      {kind === 'ok' ? <IconCheck /> : <IconError />}
      {children}
    </span>
  )
}

/* ===== Profile ========================================================== */

function ProfileSection({ user, onSaved }: { user: User; onSaved: () => Promise<void> }) {
  const [editing, setEditing] = useState(false)
  const [name, setName] = useState(user.name)
  const [email, setEmail] = useState(user.email)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const dirty = name.trim() !== user.name || email.trim() !== user.email
  const valid = name.trim().length > 0 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())

  async function save() {
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      await api.updateAccount({ name: name.trim(), email: email.trim() })
      await onSaved()
      setSaved(true)
    } catch {
      setError('Couldn’t save profile. Try again.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <SettingsGroup label="Account details">
      <SettingsRow align="top">
        {!editing ? <div className="cfs-account-summary"><LabeledField label="Email" value={user.email} disabled /><Button variant="secondary" onClick={() => setEditing(true)}>Edit account details</Button></div> : <div className="cfs-set-form">
          <LabeledField
            label="Display name"
            value={name}
            onChange={(e) => {
              setName(e.target.value)
              setSaved(false)
            }}
            autoComplete="name"
          />
          <LabeledField
            label="Email"
            type="email"
            icon={<IconMail />}
            value={email}
            onChange={(e) => {
              setEmail(e.target.value)
              setSaved(false)
            }}
            autoComplete="email"
            hint={email && !valid ? 'Enter a valid email address.' : undefined}
          />
          {error && <Banner kind="error" title={error} />}
          <div className="cfs-set-form__actions">
            <Button onClick={() => void save()} disabled={!dirty || !valid || saving}>
              {saving ? 'Saving…' : 'Save changes'}
            </Button>
            {dirty && !saving && (
              <Button
                variant="subtle"
                onClick={() => {
                  setName(user.name)
                  setEmail(user.email)
                  setError(null)
                  setSaved(false)
                }}
              >
                Reset
              </Button>
            )}
            {saved && !dirty && <Note kind="ok">Saved</Note>}
          </div>
          <Button variant="subtle" onClick={() => setEditing(false)} disabled={saving}>Done</Button>
        </div>}
      </SettingsRow>
    </SettingsGroup>
  )
}

/* ===== Password ========================================================= */

function PasswordSection() {
  const [editing, setEditing] = useState(false)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [saving, setSaving] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const tooShort = next.length > 0 && next.length < MIN_PASSWORD_LENGTH
  const mismatch = confirm.length > 0 && next !== confirm
  const valid = current.length > 0 && next.length >= MIN_PASSWORD_LENGTH && next === confirm

  async function change() {
    setSaving(true)
    setError(null)
    setDone(false)
    try {
      await api.changePassword(current, next)
      setCurrent('')
      setNext('')
      setConfirm('')
      setDone(true)
    } catch (err) {
      setError(
        err instanceof Error && err.message
          ? err.message
          : 'Couldn’t update password. Try again.',
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <SettingsGroup
      label="Password"
      description={`Use at least ${MIN_PASSWORD_LENGTH} characters. You’ll stay signed in on this device.`}
    >
      <SettingsRow align="top">
        {!editing ? <Button variant="secondary" onClick={() => setEditing(true)}>Change password</Button> : <div className="cfs-set-form">
          <LabeledField
            label="Current password"
            type="password"
            icon={<IconLock />}
            value={current}
            onChange={(e) => {
              setCurrent(e.target.value)
              setDone(false)
            }}
            autoComplete="current-password"
          />
          <LabeledField
            label="New password"
            type="password"
            icon={<IconLock />}
            value={next}
            onChange={(e) => {
              setNext(e.target.value)
              setDone(false)
            }}
            autoComplete="new-password"
            hint={tooShort ? `Use at least ${MIN_PASSWORD_LENGTH} characters.` : undefined}
          />
          <LabeledField
            label="Confirm new password"
            type="password"
            icon={<IconLock />}
            value={confirm}
            onChange={(e) => {
              setConfirm(e.target.value)
              setDone(false)
            }}
            autoComplete="new-password"
            hint={mismatch ? 'Passwords don’t match.' : undefined}
          />
          {error && <Banner kind="error" title={error} />}
          <div className="cfs-set-form__actions">
            <Button onClick={() => void change()} disabled={!valid || saving}>
              {saving ? 'Updating…' : 'Change password'}
            </Button>
            {done && <Note kind="ok">Password changed</Note>}
          </div>
          <Button variant="subtle" onClick={() => { setEditing(false); setCurrent(''); setNext(''); setConfirm(''); setError(null) }} disabled={saving}>Cancel</Button>
        </div>}
      </SettingsRow>
    </SettingsGroup>
  )
}

/* ===== Two-factor (TOTP) =============================================== */

function TwoFactorSection({ user, onChanged }: { user: User; onChanged: () => Promise<void> }) {
  // The enrollment ceremony itself (QR + confirm + recovery codes) lives in the
  // SHARED TotpEnrollFlow (also used by the /setup wizard's step 3); this
  // section owns only the enable/disable chrome around it.
  const [enrolling, setEnrolling] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function disable() {
    setBusy(true)
    setError(null)
    try {
      await api.disableTotp()
      await onChanged()
      setEnrolling(false)
    } catch {
      setError('Couldn’t disable two-factor. Try again.')
    } finally {
      setBusy(false)
    }
  }

  const statusTrailing = user.totpEnabled ? (
    <>
      <span className="cfs-set-chip cfs-set-chip--accent">
        <IconCheck /> Enabled
      </span>
      <Button variant="destructive" size="small" onClick={() => void disable()} disabled={busy}>
        Disable
      </Button>
    </>
  ) : !enrolling ? (
    <Button
      onClick={() => {
        setError(null)
        setEnrolling(true)
      }}
    >
      Enable
    </Button>
  ) : null

  return (
    <SettingsGroup
      label="Two-factor authentication"
      description="Require a time-based code (TOTP) from an authenticator app at sign-in."
    >
      <SettingsRow
        leading={<IconShield />}
        title="Authenticator app"
        sublabel={
          user.totpEnabled
            ? 'Two-factor is on for this account.'
            : 'Add a second step using Authy, 1Password, or Google Authenticator.'
        }
        trailing={statusTrailing}
      />

      {error && (
        <SettingsRow>
          <Banner kind="error" title={error} />
        </SettingsRow>
      )}

      {enrolling && (
        <SettingsRow align="top">
          <TotpEnrollFlow
            onEnrolled={onChanged}
            onDone={() => setEnrolling(false)}
            onCancel={() => setEnrolling(false)}
          />
        </SettingsRow>
      )}
    </SettingsGroup>
  )
}

/* ===== Passkeys ======================================================== */

function PasskeysSection() {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [passkeys, setPasskeys] = useState<Passkey[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)
  const [removingId, setRemovingId] = useState<string | null>(null)
  const labelRef = useRef<HTMLInputElement>(null)
  const [showAdd, setShowAdd] = useState(false)
  const [label, setLabel] = useState('')

  useEffect(() => {
    let alive = true
    api.getPublicAuthConfig().then(async (config) => {
      if (!alive) return
      setEnabled(config.passkeysEnabled === true)
      if (config.passkeysEnabled) {
        const list = await api.listPasskeys()
        if (alive) setPasskeys(list)
      }
    })
      .catch(() => alive && setError('Couldn’t load passkeys.'))
    return () => {
      alive = false
    }
  }, [])

  async function add() {
    const name = label.trim() || defaultPasskeyName()
    setAdding(true)
    setError(null)
    try {
      const pk = await api.registerPasskey(name)
      setPasskeys((cur) => [...(cur ?? []), pk])
      setLabel('')
      setShowAdd(false)
    } catch {
      setError('Couldn’t register the passkey. Try again.')
    } finally {
      setAdding(false)
    }
  }

  async function remove(id: string) {
    setRemovingId(id)
    setError(null)
    try {
      await api.removePasskey(id)
      setPasskeys((cur) => (cur ?? []).filter((p) => p.id !== id))
    } catch {
      setError('Couldn’t remove the passkey. Try again.')
    } finally {
      setRemovingId(null)
    }
  }

  if (enabled !== true) return <SettingsGroup label="Passkeys" description="Sign in using Touch ID or a security key.">
    <SettingsRow title={enabled === null ? 'Checking availability…' : 'Passkeys are not enabled'}
      sublabel={enabled === false ? 'Your administrator can enable passkeys in the deployment configuration.' : undefined} />
    {error && <SettingsRow><Banner kind="error" title={error} /></SettingsRow>}
  </SettingsGroup>

  return (
    <SettingsGroup
      label="Passkeys"
      description="Sign in without a password using Touch ID, Face ID, or a security key."
    >
      <SettingsRow
        leading={<IconPasskey />}
        title="Registered passkeys"
        sublabel={
          passkeys == null
            ? 'Loading…'
            : passkeys.length === 0
              ? 'No passkeys yet.'
              : `${passkeys.length} passkey${passkeys.length === 1 ? '' : 's'} on this account.`
        }
        trailing={
          !showAdd && (
            <Button
              size="small"
              leading={<IconPlus size={13} />}
              onClick={() => {
                setShowAdd(true)
                setError(null)
                setTimeout(() => labelRef.current?.focus(), 0)
              }}
            >
              Add passkey
            </Button>
          )
        }
      />

      {error && (
        <SettingsRow>
          <Banner kind="error" title={error} />
        </SettingsRow>
      )}

      {showAdd && (
        <SettingsRow align="top">
          <div className="cfs-set-form">
            <LabeledField
              ref={labelRef}
              label="Passkey name"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder={defaultPasskeyName()}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void add()
              }}
            />
            <div className="cfs-set-form__actions">
              <Button onClick={() => void add()} disabled={adding}>
                {adding ? 'Registering…' : 'Register passkey'}
              </Button>
              <Button
                variant="subtle"
                onClick={() => {
                  setShowAdd(false)
                  setLabel('')
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        </SettingsRow>
      )}

      {passkeys != null && passkeys.length > 0 && (
        <SettingsRow>
          <div className="cfs-passkeys">
            {passkeys.map((pk) => (
              <div key={pk.id} className="cfs-passkey">
                <span className="cfs-passkey__icon">
                  <IconKey />
                </span>
                <div className="cfs-passkey__text">
                  <span className="cfs-passkey__label">{pk.label}</span>
                  <span className="cfs-passkey__meta">
                    Added {formatDate(pk.createdAt)}
                    {pk.lastUsedAt ? ` · Last used ${formatRelative(pk.lastUsedAt)}` : ' · Never used'}
                  </span>
                </div>
                <Button
                  className="cfs-passkey__action"
                  variant="destructive"
                  size="small"
                  leading={<IconTrash size={13} />}
                  onClick={() => void remove(pk.id)}
                  disabled={removingId === pk.id}
                >
                  {removingId === pk.id ? 'Removing…' : 'Remove'}
                </Button>
              </div>
            ))}
          </div>
        </SettingsRow>
      )}
    </SettingsGroup>
  )
}

function defaultPasskeyName(): string {
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent : ''
  if (/Mac/.test(ua)) return 'This Mac'
  if (/Windows/.test(ua)) return 'This PC'
  if (/iPhone|iPad/.test(ua)) return 'This iPhone'
  return 'This device'
}

/* ===== Organization ==================================================== */

function OrgSection({
  org,
  canEdit,
  onSaved,
}: {
  org: Organization
  canEdit: boolean
  onSaved: (org: Organization) => void
}) {
  const [name, setName] = useState(org.name)
  const [syncedName, setSyncedName] = useState(org.name)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // When the org name changes from outside (e.g. a fresh session), reset the
  // field during render rather than via an effect (avoids cascading renders).
  if (org.name !== syncedName) {
    setName(org.name)
    setSyncedName(org.name)
  }

  const dirty = name.trim() !== org.name
  const valid = name.trim().length > 0

  async function save() {
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      const updated = await api.updateOrg({ name: name.trim() })
      onSaved(updated)
      setSaved(true)
    } catch (err) {
      setError(
        err instanceof Error && err.message
          ? err.message
          : 'Couldn’t rename the organization. Try again.',
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <SettingsGroup
      label="Workspace"
      description="The name your team sees in CloudFS."
    >
      <SettingsRow
        title="Workspace ID"
        sublabel="Identifies this workspace when signing in. This ID cannot be edited here."
        trailing={<span className="cfs-set-chip">{org.slug}</span>}
      />

      {canEdit ? (
        <SettingsRow align="top">
          <div className="cfs-set-form">
            <LabeledField
              label="Workspace name"
              value={name}
              onChange={(e) => {
                setName(e.target.value)
                setSaved(false)
              }}
            />
            {error && <Banner kind="error" title={error} />}
            <div className="cfs-set-form__actions">
              <Button onClick={() => void save()} disabled={!dirty || !valid || saving}>
                {saving ? 'Saving…' : 'Save name'}
              </Button>
              {saved && !dirty && <Note kind="ok">Saved</Note>}
            </div>
          </div>
        </SettingsRow>
      ) : (
        <SettingsRow
          title="Organization name"
          sublabel="Only an owner or admin can rename the organization."
          trailing={<span className="cfs-set-chip">{org.name}</span>}
        />
      )}
    </SettingsGroup>
  )
}

/* ===== date helpers ==================================================== */

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  } catch {
    return iso
  }
}

function formatRelative(iso: string): string {
  const then = new Date(iso).getTime()
  const diff = Date.now() - then
  const mins = Math.round(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.round(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.round(hours / 24)
  if (days < 30) return `${days}d ago`
  return formatDate(iso)
}
