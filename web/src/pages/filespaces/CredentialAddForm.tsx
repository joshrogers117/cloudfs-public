/*
 * CredentialAddForm — the ONLY place a storage secret is ever entered.
 *
 * label + access key id + secret access key. The secret is write-only: a note
 * tells the user it's stored encrypted and never shown again. On submit it calls
 * createStorageCredential(org, …) and hands the saved (secret-free) credential
 * back to the parent. Shared by the Account-Settings management section and the
 * Create-Filespace picker's inline "+ Add credential…" affordance.
 *
 * Owned by the Filespaces / Settings screen lanes.
 */
import { useState } from 'react'
import { Banner, Button, LabeledField } from '../../design'
import { IconKey, IconLock } from '../../design/icons'
import { getApi, type StorageCredential } from '../../api'
import {
  hasCredentialErrors,
  validateCredential,
  type CredentialFormErrors,
} from './credentials'

export function CredentialAddForm({
  org,
  onAdded,
  onCancel,
  autoFocus = true,
}: {
  org: string
  onAdded: (cred: StorageCredential) => void
  onCancel?: () => void
  autoFocus?: boolean
}) {
  const [label, setLabel] = useState('')
  const [accessKeyId, setAccessKeyId] = useState('')
  const [secret, setSecret] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showErrors, setShowErrors] = useState(false)

  const input = { label, accessKeyId, secretAccessKey: secret }
  const errors: CredentialFormErrors = validateCredential(input)

  async function save() {
    setError(null)
    if (hasCredentialErrors(errors)) {
      setShowErrors(true)
      return
    }
    setSaving(true)
    try {
      const cred = await getApi().createStorageCredential(org, {
        label: label.trim(),
        accessKeyId: accessKeyId.trim(),
        secretAccessKey: secret.trim(),
      })
      onAdded(cred)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Couldn’t save the credential. Try again.')
      setSaving(false)
    }
  }

  const shown = (key: keyof CredentialFormErrors) => (showErrors ? errors[key] : undefined)

  return (
    <div className="cfs-set-form">
      {error && <Banner kind="error" title="Couldn’t add credential" detail={error} />}
      <LabeledField
        label="Label"
        icon={<IconKey />}
        placeholder="r2-prod-key"
        value={label}
        onChange={(e) => setLabel(e.target.value)}
        hint={shown('label')}
        autoComplete="off"
        spellCheck={false}
        autoFocus={autoFocus}
      />
      <LabeledField
        label="Access key ID"
        placeholder="AKIA… / R2 token id"
        value={accessKeyId}
        onChange={(e) => setAccessKeyId(e.target.value)}
        hint={shown('accessKeyId')}
        autoComplete="off"
        spellCheck={false}
      />
      <LabeledField
        label="Secret access key"
        type="password"
        icon={<IconLock />}
        placeholder="••••••••••••••••"
        value={secret}
        onChange={(e) => setSecret(e.target.value)}
        hint={shown('secretAccessKey')}
        autoComplete="off"
        spellCheck={false}
      />
      <p className="cfs-cred-secret-note">
        <IconLock />
        The secret is stored encrypted and is never shown again. This is the only place you enter
        it — save it somewhere safe before continuing.
      </p>
      <div className="cfs-set-form__actions">
        <Button onClick={() => void save()} disabled={saving}>
          {saving ? 'Saving…' : 'Save credential'}
        </Button>
        {onCancel && (
          <Button variant="subtle" onClick={onCancel} disabled={saving}>
            Cancel
          </Button>
        )}
      </div>
    </div>
  )
}
