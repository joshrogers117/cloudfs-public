/*
 * MembersSection — B26 owner/admin member + invite management. Renders inside AccountSettings
 * (admin-only, like StorageCredentialsSection).
 *
 *   - Members list: name + email + role select (change role) + Remove (deprovision, confirmed).
 *   - Pending invites: email + role + Revoke.
 *   - "Invite member": email + role → creates the invite; the single-use redeem link is shown ONCE
 *     with a Copy button (the admin shares it, or the backend also emails it).
 *
 * Everything goes through the getApi() seam (mock offline, HttpApi against the gateway's existing
 * /v1/orgs/:org/users + /invites routes). Owned by the Settings lane.
 */
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Modal } from '../../design/Modal'
import { Banner, Button, LabeledField } from '../../design'
import { IconPlus } from '../../design/icons'
import { getApi, type Invite, type Member, type MemberRole, type Filespace, type FilespaceAccessLevel } from '../../api'
import { useAuth } from '../../app/auth'
import { SettingsGroup, SettingsRow } from './SettingsGroup'
import { IconCopy, IconTrash } from './icons'

const ROLE_LABEL: Record<MemberRole, string> = {
  owner: 'Owner',
  admin: 'Admin',
  space_admin: 'Filespace Admin (all filespaces)',
  standard: 'Member',
}
const ROLE_OPTIONS: MemberRole[] = ['owner', 'admin', 'space_admin', 'standard']

export function MembersSection({ org }: { org: string }) {
  const { user } = useAuth()
  const [filespaces, setFilespaces] = useState<Filespace[]>([])
  const [inviteSpace, setInviteSpace] = useState('')
  const [inviteAccess, setInviteAccess] = useState<FilespaceAccessLevel>('edit')
  const [members, setMembers] = useState<Member[] | null>(null)
  const [invites, setInvites] = useState<Invite[] | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)

  // Invite form
  const [searchParams] = useSearchParams()
  const [showInvite, setShowInvite] = useState(() => searchParams.get("invite") === "1")
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState<MemberRole>('standard')
  const [inviting, setInviting] = useState(false)
  const [inviteError, setInviteError] = useState<string | null>(null)
  /**
   * The last-created invite, shown once with a Copy button. `emailSent` decides the copy: honest
   * "emailed" confirmation when the backend actually delivered it, or a "copy this link yourself"
   * handoff when no email provider is configured on this deployment (ONBOARDING.md step 3 — never
   * claim an invite was emailed when nothing sent it).
   */
  const [lastInvite, setLastInvite] = useState<{ url: string; email: string; emailSent: boolean; grantedSpace?: string } | null>(
    null,
  )
  const [copied, setCopied] = useState(false)

  // Per-row action state.
  const [rowBusyId, setRowBusyId] = useState<string | null>(null)
  const [rowError, setRowError] = useState<{ id: string; message: string } | null>(null)

  useEffect(() => {
    let alive = true
    Promise.all([getApi().listMembers(org), getApi().listInvites(org), getApi().listFilespaces()])
      .then(([m, i, spaces]) => {
        if (!alive) return
        setFilespaces(spaces)
        setMembers(m)
        setInvites(i)
      })
      .catch(() => alive && setLoadError('Couldn’t load members.'))
    return () => {
      alive = false
    }
  }, [org])

  const activeMembers = (members ?? []).filter((m) => m.status !== 'deprovisioned')

  async function changeRole(member: Member, role: MemberRole) {
    setRowError(null)
    setRowBusyId(member.id)
    try {
      await getApi().setMemberRole(org, member.id, role)
      setMembers((cur) => (cur ?? []).map((m) => (m.id === member.id ? { ...m, role } : m)))
    } catch (err) {
      setRowError({ id: member.id, message: err instanceof Error ? err.message : 'Could not change the role.' })
    } finally {
      setRowBusyId(null)
    }
  }

  async function removeMember(member: Member) {
    if (!window.confirm(`Remove ${member.name || member.email} from this organization? Their sessions and tokens are revoked. This cannot be undone from the console.`)) {
      return
    }
    setRowError(null)
    setRowBusyId(member.id)
    try {
      await getApi().removeMember(org, member.id)
      setMembers((cur) => (cur ?? []).map((m) => (m.id === member.id ? { ...m, status: 'deprovisioned' } : m)))
    } catch (err) {
      setRowError({ id: member.id, message: err instanceof Error ? err.message : 'Could not remove the member.' })
    } finally {
      setRowBusyId(null)
    }
  }

  async function revokeInvite(invite: Invite) {
    if (!window.confirm(`Revoke the invitation for ${invite.email}? The link stops working immediately.`)) return
    setRowError(null)
    setRowBusyId(invite.id)
    try {
      await getApi().revokeInvite(org, invite.id)
      setInvites((cur) => (cur ?? []).filter((i) => i.id !== invite.id))
    } catch (err) {
      setRowError({ id: invite.id, message: err instanceof Error ? err.message : 'Could not revoke the invitation.' })
    } finally {
      setRowBusyId(null)
    }
  }

  async function sendInvite() {
    setInviteError(null)
    setInviting(true)
    try {
      const res = await getApi().createInvite(org, { email: inviteEmail.trim(), role: inviteRole, ...(inviteRole === 'standard' && inviteSpace ? { scope: { spaceId: inviteSpace, level: inviteAccess } } : {}) })
      setInvites((cur) => [res.invite, ...(cur ?? [])])
      setLastInvite({ url: res.inviteUrl, email: res.invite.email, emailSent: res.emailSent, grantedSpace: inviteRole === 'standard' && inviteSpace ? filespaces.find((f) => f.id === inviteSpace)?.name ?? inviteSpace : undefined })
      setInviteEmail('')
      setInviteRole('standard')
      setInviteSpace('')
      setShowInvite(false)
    } catch (err) {
      setInviteError(err instanceof Error ? err.message : 'Could not create the invitation.')
    } finally {
      setInviting(false)
    }
  }

  const emailOk = /.+@.+\..+/.test(inviteEmail.trim())

  return (
    <SettingsGroup label="Team members">
      {loadError && <Banner kind="error" title={loadError} />}

      {/* Pending invite link (shown once after creating an invite). Copy is ALWAYS the fallback —
          the sublabel is honest about whether email actually went out (ONBOARDING.md step 3). */}
      {lastInvite && (
        <SettingsRow
          title={lastInvite.emailSent ? 'Invitation sent' : 'Invitation created'}
          sublabel={
            lastInvite.emailSent
              ? `Invite emailed to ${lastInvite.email}. You can also copy the link below.`
              : `Email isn't configured on this deployment — copy this link and send it to ${lastInvite.email} yourself.`
          }
          align="top"
        >
          {lastInvite.grantedSpace && (
            <p className="cfs-field__hint" role="status">
              Access to {lastInvite.grantedSpace} is applied when {lastInvite.email} accepts. Anyone who already has this filespace
              connected in the Mac app must reconnect it before newly granted folders appear.
            </p>
          )}
          <div className="cfs-set-row__body" style={{ display: 'flex', gap: 'var(--cfs-space-md)', alignItems: 'center', width: '100%' }}>
            <LabeledField label="Invite link" value={lastInvite.url} readOnly onChange={() => {}} />
            <Button
              variant="secondary"
              leading={<IconCopy />}
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(lastInvite.url)
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
        </SettingsRow>
      )}

      {/* Members */}
      {activeMembers.map((m) => (
        <SettingsRow
          key={m.id}
          title={m.name || m.email}
          sublabel={m.email}
          trailing={
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--cfs-space-md)', alignItems: 'center', maxWidth: '100%' }}>
              <select
                aria-label={`Role for ${m.name || m.email}`}
                value={m.role}
                disabled={rowBusyId === m.id || (m.role === 'owner' && user?.orgRole !== 'Owner')}
                onChange={(e) => changeRole(m, e.target.value as MemberRole)}
                className="cfs-set-select"
              >
                {ROLE_OPTIONS.filter((r) => r !== 'owner' || user?.orgRole === 'Owner' || m.role === 'owner').map((r) => (
                  <option key={r} value={r}>
                    {ROLE_LABEL[r]}
                  </option>
                ))}
              </select>
              <Button
                variant="destructive"
                aria-label={`Remove ${m.name || m.email}`}
                leading={<IconTrash />}
                disabled={rowBusyId === m.id || (m.role === 'owner' && user?.orgRole !== 'Owner')}
                onClick={() => removeMember(m)}
              >
                Remove
              </Button>
            </div>
          }
        >
          {rowError?.id === m.id && <Banner kind="error" title={rowError.message} />}
        </SettingsRow>
      ))}

      {/* Pending invites */}
      {(invites ?? []).filter((i) => i.status === 'pending').map((i) => (
        <SettingsRow
          key={i.id}
          title={i.email}
          sublabel={`Invited as ${ROLE_LABEL[i.role]} · pending`}
          trailing={
            <Button
              variant="subtle"
              leading={<IconTrash />}
              disabled={rowBusyId === i.id}
              onClick={() => revokeInvite(i)}
            >
              Revoke
            </Button>
          }
        >
          {rowError?.id === i.id && <Banner kind="error" title={rowError.message} />}
        </SettingsRow>
      ))}

      {/* Invite form */}
      <SettingsRow title="Invite a teammate" sublabel="They’ll get a link to join your workspace." align="top">
        {!showInvite ? (
          <Button variant="secondary" leading={<IconPlus />} onClick={() => setShowInvite(true)}>
            Invite member
          </Button>
        ) : (
          <Modal title="Invite members" busy={inviting} onClose={() => { setShowInvite(false); setInviteError(null) }}>
          <p className="cfs-modal__description">Invite someone to your workspace and choose their access. They’ll receive a single-use invitation link.</p>
          <div className="cfs-invite-specific"><strong>Specific person</strong><span>Only the person with this email address can accept.</span></div>
          <div className="cfs-set-row__body cfs-invite-form">
            {inviteError && <Banner kind="error" title={inviteError} />}
            <LabeledField
              label="Work email"
              type="email"
              placeholder="teammate@acme.example"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
            />
            <label className="cfs-set-field">
              <span className="cfs-set-field__label">Role</span>
              <select
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value as MemberRole)}
                className="cfs-set-select"
              >
                {ROLE_OPTIONS.filter((r) => r !== 'owner').map((r) => (
                  <option key={r} value={r}>
                    {ROLE_LABEL[r]}
                  </option>
                ))}
              </select>
            </label>
            {inviteRole === 'standard' ? <><label className="cfs-set-field">
              <span className="cfs-set-field__label">Filespace access</span>
              <select className="cfs-set-select" value={inviteSpace} onChange={(e) => setInviteSpace(e.target.value)}>
                <option value="">Assign access later</option>
                {filespaces.map((fs) => <option key={fs.id} value={fs.id}>{fs.name}</option>)}
              </select>
            </label>
            {inviteSpace ? <label className="cfs-set-field"><span className="cfs-set-field__label">Permission</span>
              <select className="cfs-set-select" value={inviteAccess} onChange={(e) => setInviteAccess(e.target.value as FilespaceAccessLevel)}>
                <option value="read">Can view</option><option value="edit">Can edit</option><option value="admin">Folder admin (this filespace)</option>
              </select>
              {inviteAccess === 'admin' && <span className="cfs-field__hint">Manages read and edit access within this filespace. Does not become a workspace admin. Delegate a specific subfolder in the Mac app.</span>}
            </label> : inviteRole === 'standard' && <p className="cfs-field__hint">This member will need filespace or folder access before they can work with files. You can grant it in the Mac app.</p>}
            </> : <p className="cfs-field__hint">{inviteRole === 'space_admin' ? 'This role can read, edit, and manage access in every filespace. It cannot manage workspace accounts or storage.' : 'Admins can manage workspace members, storage, and every filespace.'}</p>}
            <div style={{ display: 'flex', gap: 'var(--cfs-space-md)' }}>
              <Button variant="primary" disabled={!emailOk || inviting} onClick={sendInvite}>
                {inviting ? 'Creating invitation…' : 'Generate invite link'}
              </Button>
              <Button variant="subtle" disabled={inviting} onClick={() => { setShowInvite(false); setInviteError(null) }}>
                Cancel
              </Button>
            </div>
          </div>
          </Modal>
        )}
      </SettingsRow>
    </SettingsGroup>
  )
}
