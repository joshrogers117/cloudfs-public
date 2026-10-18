/*
 * StorageCredentialsSection — owner/admin-only management of the org's saved
 * S3-compatible storage access keys. Renders inside AccountSettings.
 *
 *   - List saved credentials: label + access key id + created date. The secret
 *     is NEVER shown (it is write-only).
 *   - "Add credential" reveals the shared CredentialAddForm (the one place a
 *     secret is entered; it's stored encrypted and never shown again).
 *   - Per-row Delete. If the backend rejects with `credential_in_use` (409) we
 *     surface the blocking filespaces by name.
 *
 * Org scope comes from the live session slug. Owned by the Settings lane.
 */
import { useEffect, useState } from 'react'
import { Banner, Button } from '../../design'
import { IconKey, IconPlus } from '../../design/icons'
import { getApi, CredentialInUseError, type StorageCredential, type DeploymentStorage, type StorageTestResult } from '../../api'
import { SettingsGroup, SettingsRow } from './SettingsGroup'
import { IconTrash } from './icons'
import { CredentialAddForm } from '../filespaces/CredentialAddForm'
import { maskAccessKeyId } from '../filespaces/credentials'
import { TestResultPanel } from '../filespaces/TestConnection'

export function StorageCredentialsSection({ org }: { org: string }) {
  const [storage, setStorage] = useState<DeploymentStorage | null>(null)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<StorageTestResult | null>(null)
  const [storageError, setStorageError] = useState<string | null>(null)
  useEffect(() => {
    let alive = true
    getApi().getDefaultStorage(org).then((value) => { if (alive) setStorage(value) })
      .catch(() => { if (alive) setStorageError('Couldn’t load the default storage connection.') })
    return () => { alive = false }
  }, [org])
  async function testDefault() {
    setTesting(true); setStorageError(null); setTestResult(null)
    try { setTestResult(await getApi().validateDefaultStorage(org)) }
    catch (error) { setStorageError(error instanceof Error ? error.message : 'The storage test failed.') }
    finally { setTesting(false) }
  }
  const [creds, setCreds] = useState<StorageCredential[] | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [showAdd, setShowAdd] = useState(false)
  const [removingId, setRemovingId] = useState<string | null>(null)
  // Per-row delete error (string) — names the filespaces for the in-use case.
  const [rowError, setRowError] = useState<{ id: string; message: string } | null>(null)

  useEffect(() => {
    let alive = true
    getApi()
      .listStorageCredentials(org)
      .then((list) => alive && setCreds(list))
      .catch(() => alive && setLoadError('Couldn’t load storage credentials.'))
    return () => {
      alive = false
    }
  }, [org])

  async function remove(cred: StorageCredential) {
    setRowError(null)
    setRemovingId(cred.id)
    try {
      await getApi().deleteStorageCredential(org, cred.id)
      setCreds((cur) => (cur ?? []).filter((c) => c.id !== cred.id))
    } catch (err) {
      if (err instanceof CredentialInUseError) {
        const names = err.spaces.length
          ? err.spaces.join(', ')
          : 'one or more filespaces'
        setRowError({
          id: cred.id,
          message: `“${cred.label}” is in use by ${names}. Re-point those filespaces to another credential before deleting it.`,
        })
      } else {
        setRowError({
          id: cred.id,
          message: err instanceof Error ? err.message : 'Couldn’t delete the credential.',
        })
      }
    } finally {
      setRemovingId(null)
    }
  }

  const count = creds?.length ?? 0

  return (
    <SettingsGroup
      label="Storage"
      description="New filespaces can use the storage connection configured with this deployment. Add separate access keys only when using another bucket."
    >
      <SettingsRow title="Default storage" sublabel={storage
        ? storage.configured ? `${storage.bucket} · ${storage.provider}` : 'Finish configuring storage in the deployment before creating a filespace.'
        : 'Loading storage connection…'} trailing={storage?.configured && <Button size="small" disabled={testing} onClick={() => void testDefault()}>{testing ? 'Testing…' : 'Test connection'}</Button>} />
      {storageError && <SettingsRow><Banner kind="error" title={storageError} /></SettingsRow>}
      {testResult && <SettingsRow><TestResultPanel result={testResult} sharedBucket /></SettingsRow>}
      <SettingsRow
        leading={<IconKey />}
        title="Saved access keys"
        sublabel={
          creds == null
            ? 'Loading…'
            : count === 0
              ? 'No additional access keys. Filespaces can use the default storage connection.'
              : `${count} credential${count === 1 ? '' : 's'} available to this organization.`
        }
        trailing={
          !showAdd && (
            <Button
              size="small"
              leading={<IconPlus size={13} />}
              onClick={() => setShowAdd(true)}
            >
              Add credential
            </Button>
          )
        }
      />

      {loadError && (
        <SettingsRow>
          <Banner kind="error" title={loadError} />
        </SettingsRow>
      )}

      {showAdd && (
        <SettingsRow align="top">
          <CredentialAddForm
            org={org}
            onAdded={(cred) => {
              setCreds((cur) => [...(cur ?? []), cred])
              setShowAdd(false)
            }}
            onCancel={() => setShowAdd(false)}
          />
        </SettingsRow>
      )}

      {creds != null && count > 0 && (
        <SettingsRow>
          <div className="cfs-cred-list">
            {creds.map((cred) => (
              <div key={cred.id} className="cfs-cred">
                <span className="cfs-cred__icon">
                  <IconKey />
                </span>
                <div className="cfs-cred__text">
                  <span className="cfs-cred__label">{cred.label}</span>
                  <span className="cfs-cred__meta">
                    <code className="cfs-cred__akid">{maskAccessKeyId(cred.accessKeyId)}</code>
                    <span aria-hidden> · </span>
                    Added {formatDate(cred.createdAt)}
                  </span>
                </div>
                <Button
                  className="cfs-cred__action"
                  variant="destructive"
                  size="small"
                  leading={<IconTrash size={13} />}
                  onClick={() => void remove(cred)}
                  disabled={removingId === cred.id}
                >
                  {removingId === cred.id ? 'Deleting…' : 'Delete'}
                </Button>
                {rowError?.id === cred.id && (
                  <div className="cfs-cred__error">
                    <Banner kind="warning" title="Can’t delete this credential" detail={rowError.message} />
                  </div>
                )}
              </div>
            ))}
          </div>
        </SettingsRow>
      )}
    </SettingsGroup>
  )
}

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
