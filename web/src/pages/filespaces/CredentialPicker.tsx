/*
 * CredentialPicker — choose a SAVED storage credential to back a filespace,
 * with an inline "+ Add credential…" affordance so you can create one without
 * leaving the create/settings flow. Replaces the old free-text credential
 * reference. The secret is never entered here — only in the inline add form.
 *
 * Loads the org's credentials on mount; when the list is empty it nudges the
 * user straight into the add form. Owned by the Filespaces screen lane.
 */
import { useEffect, useState } from 'react'
import { getApi, type StorageCredential } from '../../api'
import { LabeledSelect } from './fields'
import { CredentialAddForm } from './CredentialAddForm'
import { maskAccessKeyId } from './credentials'

const ADD_SENTINEL = '__add__'

export function CredentialPicker({
  org,
  value,
  error,
  onChange,
}: {
  org: string
  /** Currently selected credential id (or '' for none). */
  value: string
  error?: string
  onChange: (credentialId: string) => void
}) {
  const [creds, setCreds] = useState<StorageCredential[] | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)

  useEffect(() => {
    let alive = true
    getApi()
      .listStorageCredentials(org)
      .then((list) => {
        if (!alive) return
        setCreds(list)
        // No saved credentials yet → open the inline add form immediately.
        if (list.length === 0) setAdding(true)
      })
      .catch(() => alive && setLoadError('Couldn’t load saved credentials.'))
    return () => {
      alive = false
    }
  }, [org])

  function handleSelect(next: string) {
    if (next === ADD_SENTINEL) {
      setAdding(true)
      return
    }
    onChange(next)
  }

  function handleAdded(cred: StorageCredential) {
    setCreds((cur) => [...(cur ?? []), cred])
    onChange(cred.id)
    setAdding(false)
  }

  const loading = creds == null && !loadError

  return (
    <div className="cfs-cred-picker">
      <LabeledSelect
        label="Storage credential"
        id="fs-credential"
        hint={
          loadError ??
          'Choose a saved access key, or add one. Secrets are stored encrypted — never the secret itself.'
        }
        error={error}
        value={value}
        onChange={(e) => handleSelect(e.target.value)}
        disabled={loading}
      >
        <option value="" disabled>
          {loading ? 'Loading credentials…' : 'Select a credential…'}
        </option>
        {(creds ?? []).map((c) => (
          <option key={c.id} value={c.id}>
            {c.label} ({maskAccessKeyId(c.accessKeyId)})
          </option>
        ))}
        <option value={ADD_SENTINEL}>+ Add credential…</option>
      </LabeledSelect>

      {adding && (
        <div className="cfs-cred-picker__add">
          <CredentialAddForm
            org={org}
            onAdded={handleAdded}
            onCancel={
              // Only allow cancel when there's already a credential to fall back on.
              creds && creds.length > 0 ? () => setAdding(false) : undefined
            }
          />
        </div>
      )}
    </div>
  )
}
