/*
 * FilespaceSettings — AUTH screen lane. Renders inside <RootLayout/> content pane
 * at /filespaces/:id/settings. Owned by the Filespace-Settings screen agent.
 *
 * Rename, view/edit storage settings, and a Delete behind a typed confirmation.
 * Loads via getApi().listFilespaces() (no single-getter in the seam) and persists
 * via updateFilespace / deleteFilespace. No members/permissions UI — that lives in
 * the Mac app, out of scope for the web app.
 */
import { useEffect, useState } from 'react'
import { Navigate, useNavigate, useParams } from 'react-router-dom'
import { ApiError, bytesLabel, getApi, type Filespace, type SnapshotSchedule } from '../api'
import { Banner, Button, Card, PaneHeader, StatePane, TextField } from '../design'
import { permissionsFor } from '../app/permissions'
import { useAuth } from '../app/auth'
import { LabeledInput } from './filespaces/fields'
import './filespaces/filespaces.css'

type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'notfound' }
  | { kind: 'loaded'; filespace: Filespace }

export function FilespaceSettings() {
  const { user } = useAuth()
  const { id } = useParams()
  if (!permissionsFor(user?.orgRole).manageFilespaceSettings) return <Navigate to="/filespaces" replace />
  return <AuthorizedFilespaceSettings key={id} />
}

function AuthorizedFilespaceSettings() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [state, setState] = useState<LoadState>(() =>
    id ? { kind: 'loading' } : { kind: 'notfound' },
  )
  // Bumped to re-run the load effect (retry).
  const [reloadKey, setReloadKey] = useState(0)

  useEffect(() => {
    if (!id) return
    let alive = true
    getApi()
      .listFilespaces()
      .then((all) => {
        if (!alive) return
        const fs = all.find((f) => f.id === id)
        setState(fs ? { kind: 'loaded', filespace: fs } : { kind: 'notfound' })
      })
      .catch(
        (err: unknown) =>
          alive &&
          setState({
            kind: 'error',
            message: err instanceof Error ? err.message : 'Unable to load this filespace.',
          }),
      )
    return () => {
      alive = false
    }
  }, [id, reloadKey])

  const load = () => {
    setState({ kind: 'loading' })
    setReloadKey((k) => k + 1)
  }

  return (
    <>
      <PaneHeader
        title={state.kind === 'loaded' ? state.filespace.name : 'Filespace Settings'}
        subtitle={
          state.kind === 'loaded'
            ? `${state.filespace.storageBackend} · ${state.filespace.role}`
            : 'Rename, storage, and deletion'
        }
        trailing={
          <Button variant="secondary" size="small" onClick={() => navigate('/filespaces')}>
            All filespaces
          </Button>
        }
      />

      {state.kind === 'loading' && <StatePane state="loading" loadingText="Loading filespace…" />}
      {state.kind === 'error' && (
        <StatePane state="error" message={state.message} onRetry={load} />
      )}
      {state.kind === 'notfound' && (
        <StatePane
          state="empty"
          title="Filespace not found"
          hint="It may have been deleted, or you no longer have access."
        />
      )}
      {state.kind === 'loaded' && (
        <SettingsBody
          filespace={state.filespace}
          onUpdated={(fs) => setState({ kind: 'loaded', filespace: fs })}
        />
      )}
    </>
  )
}

function SettingsBody({
  filespace,
  onUpdated,
}: {
  filespace: Filespace
  onUpdated: (fs: Filespace) => void
}) {
  const navigate = useNavigate()
  const { session } = useAuth()
  const orgRole = session?.user.orgRole
  // Backend: DELETE/purge of a filespace is org-OWNER only (org-do.ts); schedules are owner/admin.
  const isOwner = orgRole === 'Owner'
  const canManageSchedules = orgRole === 'Owner' || orgRole === 'Admin'

  return (
    <div className="cfs-fs-form">
      <OverviewCard filespace={filespace} />
      {permissionsFor(orgRole).manageFilespaceSettings && <RenameCard filespace={filespace} onUpdated={onUpdated} />}
      <StorageCard filespace={filespace} />
      {canManageSchedules && <div id="snapshots"><SchedulesCard filespace={filespace} /></div>}
      {isOwner && <DangerCard filespace={filespace} onDeleted={() => navigate('/filespaces')} />}
    </div>
  )
}

/* ----- Overview (read-only) ----- */
function OverviewCard({ filespace }: { filespace: Filespace }) {
  return (
    <Card title="Overview">
      <div className="cfs-fs-kv">
        <div className="cfs-fs-kv__row">
          <span className="cfs-fs-kv__key">Connection</span>
          <span className="cfs-fs-kv__val">Managed in the Mac app</span>
        </div>
        <div className="cfs-fs-kv__row">
          <span className="cfs-fs-kv__key">Role</span>
          <span className="cfs-fs-kv__val">{filespace.role}</span>
        </div>
        <div className="cfs-fs-kv__row">
          <span className="cfs-fs-kv__key">Members</span>
          <span className="cfs-fs-kv__val">{filespace.memberCountKnown === false ? 'See workspace members' : filespace.memberCount}</span>
        </div>
        <div className="cfs-fs-kv__row">
          <span className="cfs-fs-kv__key">Total size</span>
          <span className="cfs-fs-kv__val">{filespace.usageKnown === false ? 'Not available yet' : bytesLabel(filespace.usedBytes)}</span>
        </div>
        {filespace.mountPath && (
          <div className="cfs-fs-kv__row">
            <span className="cfs-fs-kv__key">Mount path</span>
            <span className="cfs-fs-kv__val cfs-fs-kv__val--mono">{filespace.mountPath}</span>
          </div>
        )}
      </div>
    </Card>
  )
}

/* ----- Rename ----- */
function RenameCard({
  filespace,
  onUpdated,
}: {
  filespace: Filespace
  onUpdated: (fs: Filespace) => void
}) {
  const [name, setName] = useState(filespace.name)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const trimmed = name.trim()
  const dirty = trimmed !== filespace.name
  const nameError = trimmed ? undefined : 'A filespace name is required.'

  async function save() {
    setError(null)
    setSaved(false)
    if (nameError || !dirty) return
    setSaving(true)
    try {
      const updated = await getApi().updateFilespace(filespace.id, { name: trimmed })
      onUpdated(updated)
      setName(updated.name)
      setSaved(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not rename the filespace.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title="Name">
      {error && <Banner kind="error" title="Couldn’t rename" detail={error} />}
      {saved && !dirty && <Banner kind="success" title="Filespace renamed" />}
      <LabeledInput
        label="Filespace name"
        id="rename"
        value={name}
        error={saved ? undefined : nameError}
        onChange={(e) => {
          setName(e.target.value)
          setSaved(false)
        }}
      />
      <div className="cfs-fs-form__actions">
        <Button onClick={save} disabled={!dirty || Boolean(nameError) || saving}>
          {saving ? 'Saving…' : 'Save name'}
        </Button>
      </div>
    </Card>
  )
}

/* ----- Snapshot schedules ----- */
function describeInterval(ms: number): string {
  const day = 86_400_000
  if (ms % (7 * day) === 0) return ms === 7 * day ? 'Every week' : `Every ${ms / (7 * day)} weeks`
  if (ms % day === 0) return ms === day ? 'Every day' : `Every ${ms / day} days`
  if (ms % 3_600_000 === 0) return `Every ${ms / 3_600_000} hours`
  return `Every ${Math.round(ms / 60_000)} minutes`
}

function SchedulesCard({ filespace }: { filespace: Filespace }) {
  const [schedules, setSchedules] = useState<SnapshotSchedule[] | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [busyId, setBusyId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    getApi()
      .listSnapshotSchedules(filespace.id)
      .then((list) => alive && setSchedules(list))
      .catch((err: unknown) => alive && setLoadError(err instanceof Error ? err.message : 'Could not load snapshot schedules.'))
    return () => {
      alive = false
    }
  }, [filespace.id])

  async function patch(s: SnapshotSchedule, change: { retain?: number; enabled?: boolean }) {
    setError(null)
    setBusyId(s.id)
    try {
      await getApi().updateSnapshotSchedule(filespace.id, s.id, change)
      setSchedules((cur) => (cur ?? []).map((x) => (x.id === s.id ? { ...x, ...change } : x)))
      setDrafts((d) => {
        const { [s.id]: _drop, ...rest } = d
        void _drop
        return rest
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update the schedule.')
    } finally {
      setBusyId(null)
    }
  }

  return (
    <Card title="Snapshot schedules">
      <p className="cfs-fs-card__lead">
        Automatic snapshots give you recovery points to browse and restore from. Each schedule keeps
        the most recent snapshots of its tier and prunes older ones.
      </p>
      {loadError && <Banner kind="error" title="Couldn’t load schedules" detail={loadError} />}
      {error && <Banner kind="error" title="Couldn’t update the schedule" detail={error} />}
      {schedules && schedules.length === 0 && (
        <p className="cfs-fs-card__lead">No snapshot schedules are configured for this filespace.</p>
      )}
      {schedules && schedules.length > 0 && (
        <div className="cfs-fs-kv">
          {schedules.map((s) => {
            const draft = drafts[s.id] ?? String(s.retain)
            const parsed = Number(draft)
            const valid = draft.trim() !== '' && Number.isInteger(parsed) && parsed >= 0 && parsed <= 10_000
            const dirty = valid && parsed !== s.retain
            return (
              <div className="cfs-fs-kv__row" key={s.id}>
                <span className="cfs-fs-kv__key">
                  {s.tier.charAt(0).toUpperCase() + s.tier.slice(1)} · {describeInterval(s.intervalMs)}
                </span>
                <span className="cfs-fs-kv__val" style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--cfs-space-md)', alignItems: 'center' }}>
                  <label htmlFor={`retain-${s.id}`}>Keep</label>
                  <input
                    id={`retain-${s.id}`}
                    type="number"
                    min={0}
                    max={10000}
                    value={draft}
                    aria-invalid={!valid}
                    style={{ width: '5rem' }}
                    onChange={(e) => setDrafts((d) => ({ ...d, [s.id]: e.target.value }))}
                  />
                  <Button size="small" variant="secondary" disabled={!dirty || busyId === s.id} onClick={() => patch(s, { retain: parsed })}>
                    Save
                  </Button>
                  <Button size="small" variant="subtle" disabled={busyId === s.id} onClick={() => patch(s, { enabled: !s.enabled })}>
                    {s.enabled ? 'Disable' : 'Enable'}
                  </Button>
                  {!s.enabled && <span>Disabled</span>}
                </span>
              </div>
            )
          })}
        </div>
      )}
    </Card>
  )
}

/* ----- Storage ----- */
function StorageCard({ filespace }: { filespace: Filespace }) {
  return <Card title="Storage connection">
    <div className="cfs-fs-kv">
      <div className="cfs-fs-kv__row"><span className="cfs-fs-kv__key">Provider</span><span className="cfs-fs-kv__val">{filespace.storageBackend}</span></div>
      <div className="cfs-fs-kv__row"><span className="cfs-fs-kv__key">Bucket</span><span className="cfs-fs-kv__val">{filespace.storageBucket || 'Workspace default'}</span></div>
      <div className="cfs-fs-kv__row"><span className="cfs-fs-kv__key">Region</span><span className="cfs-fs-kv__val">{filespace.region === 'auto' ? 'Set by the connected bucket' : filespace.region}</span></div>
    </div>
    <p className="cfs-fs-card__lead">This connection was chosen when the filespace was created. Moving existing files to another bucket requires a planned migration.</p>
  </Card>
}

/* ----- Danger zone (two-step: reversible soft delete → IRREVERSIBLE purge) -----
 *
 * Both steps are OWNER-only on the backend (they 403 a non-owner). We mirror that in the UI so a
 * non-owner sees a calm explanation, not a button that would just fail.
 *
 *   Step 1 (soft delete): REVERSIBLE — sets the registry tombstone. On success we DON'T navigate
 *     away; we reveal step 2 in place (the freshly soft-deleted space is invisible to the space
 *     list, so this is the one moment its id/name are still in hand to offer the purge).
 *   Step 2 (purge): IRREVERSIBLE — permanently deletes the encrypted objects from storage AND the
 *     metadata. A distinctly SCARIER, separate confirmation (type the name again; explicit
 *     "permanently deletes all data and cannot be undone"). Wired to purgeFilespace(); the backend
 *     refuses unless the space is already soft-deleted and the confirm echoes the exact id.
 */
function DangerCard({
  filespace,
  onDeleted,
}: {
  filespace: Filespace
  onDeleted: () => void
}) {
  // Rendered for owners only (gated in SettingsBody). 'live' → show soft-delete; 'soft-deleted' → reveal the purge step in place.
  const [stage, setStage] = useState<'live' | 'soft-deleted'>('live')

  if (stage === 'soft-deleted') {
    return <PurgeCard filespace={filespace} onPurged={onDeleted} onLeave={onDeleted} />
  }
  return <SoftDeleteCard filespace={filespace} onSoftDeleted={() => setStage('soft-deleted')} />
}

/* ----- Step 1: reversible soft delete ----- */
function SoftDeleteCard({
  filespace,
  onSoftDeleted,
}: {
  filespace: Filespace
  onSoftDeleted: () => void
}) {
  const [confirm, setConfirm] = useState('')
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const matches = confirm === filespace.name

  async function remove() {
    setError(null)
    if (!matches) return
    setDeleting(true)
    try {
      await getApi().deleteFilespace(filespace.id)
      onSoftDeleted()
    } catch (err) {
      const message =
        err instanceof ApiError && err.status === 403
          ? 'Only the organization owner can delete a filespace.'
          : err instanceof Error
            ? err.message
            : 'Could not delete the filespace.'
      setError(message)
      setDeleting(false)
    }
  }

  return (
    <Card title="Delete filespace" className="cfs-fs-danger">
      {error && <Banner kind="error" title="Couldn’t delete" detail={error} />}
      <p className="cfs-fs-danger__lead">
        Deleting <strong>{filespace.name}</strong> disconnects every member and removes it from the
        filespace list. This is <strong>reversible</strong> — the objects in the storage bucket are
        kept and the filespace can be recovered by an administrator. To permanently destroy the
        data, delete it first, then purge it on the next step. This action is owner-only.
      </p>
      <div className="cfs-fs-danger__confirm">
        <div className="cfs-fs-field">
          <label className="cfs-fs-field__label" htmlFor="delete-confirm">
            Type <strong style={{ color: 'var(--cfs-text-primary)' }}>{filespace.name}</strong> to
            confirm
          </label>
          <TextField
            id="delete-confirm"
            value={confirm}
            placeholder={filespace.name}
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </div>
        <div className="cfs-fs-form__actions">
          <Button variant="destructive" onClick={remove} disabled={!matches || deleting}>
            {deleting ? 'Deleting…' : 'Delete filespace'}
          </Button>
        </div>
      </div>
    </Card>
  )
}

/* ----- Step 2: IRREVERSIBLE purge (only reachable AFTER a successful soft delete) ----- */
function PurgeCard({
  filespace,
  onPurged,
  onLeave,
}: {
  filespace: Filespace
  onPurged: () => void
  onLeave: () => void
}) {
  const [confirm, setConfirm] = useState('')
  const [purging, setPurging] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // The purge sweep is ASYNC on the backend (object deletes run on a DO alarm). After the POST is
  // accepted we POLL the status so we can surface a TERMINAL FAILURE ("Purge failed — retry")
  // instead of leaving the owner on an endless "Purging…" spinner when the sweep stalls on per-key
  // delete errors (object-lock / legal-hold / a scoped DeleteObject Deny). `purgeFailed` carries the
  // operator-readable reason from the backend; the retry button re-issues the purge.
  const [purgeFailed, setPurgeFailed] = useState<string | null>(null)
  const matches = confirm === filespace.name

  async function purge() {
    setError(null)
    setPurgeFailed(null)
    if (!matches) return
    setPurging(true)
    try {
      await getApi().purgeFilespace(filespace.id)
      // Poll the async sweep to a terminal state (done OR failed). Bounded so a wedged sweep can't
      // spin the UI forever — if it's still running after the budget we treat it as "accepted, still
      // working" and leave the page (the sweep continues server-side; a later visit 404s the space).
      const MAX_POLLS = 20
      for (let i = 0; i < MAX_POLLS; i++) {
        let status
        try {
          status = await getApi().purgeFilespaceStatus(filespace.id)
        } catch (pollErr) {
          // Once the space is fully purged its registry row is gone → the status GET 404s. That is
          // the SUCCESS signal (there's nothing left to report on).
          if (pollErr instanceof ApiError && pollErr.status === 404) {
            onPurged()
            return
          }
          throw pollErr
        }
        if (status.failed) {
          setPurgeFailed(status.error ?? 'The purge could not finish. Some objects could not be deleted.')
          setPurging(false)
          return
        }
        if (status.done) {
          onPurged()
          return
        }
        await new Promise((r) => setTimeout(r, 500))
      }
      // Still purging after the poll budget — accepted and progressing server-side. Leave the page.
      onPurged()
    } catch (err) {
      // Map the backend's two-step / confirmation / owner guards to clear copy.
      let message = 'Could not purge the filespace.'
      if (err instanceof ApiError) {
        if (err.status === 403) message = 'Only the organization owner can purge a filespace.'
        else if (err.code === 'must_soft_delete_first')
          message = 'The filespace must be deleted before it can be purged.'
        else if (err.code === 'confirmation_required')
          message = 'Confirmation did not match. Type the filespace name exactly.'
        else message = err.message
      } else if (err instanceof Error) {
        message = err.message
      }
      setError(message)
      setPurging(false)
    }
  }

  return (
    <Card title="Permanently purge filespace" className="cfs-fs-danger">
      <Banner
        kind="warning"
        title="Filespace deleted — it can still be recovered"
        detail="It’s now removed from the filespace list but its data is intact. You can stop here and an administrator can recover it. Purging below CANNOT be undone."
      />
      {error && <Banner kind="error" title="Couldn’t purge" detail={error} />}
      {purgeFailed && (
        <Banner
          kind="error"
          title="Purge failed — retry"
          detail={`Some objects could not be deleted, so the filespace was NOT fully purged (it remains recoverable). This is usually an object-lock, legal hold, or a storage permission denying deletes. Resolve it, then retry. Details: ${purgeFailed}`}
        />
      )}
      <p className="cfs-fs-danger__lead">
        Purging <strong>{filespace.name}</strong> permanently deletes <strong>all of its data</strong>
        {' '}— every encrypted object in the storage bucket and all of its metadata.{' '}
        <strong style={{ color: 'var(--cfs-text-primary)' }}>
          This cannot be undone and the data cannot be recovered.
        </strong>
      </p>
      <div className="cfs-fs-danger__confirm">
        <div className="cfs-fs-field">
          <label className="cfs-fs-field__label" htmlFor="purge-confirm">
            Type <strong style={{ color: 'var(--cfs-text-primary)' }}>{filespace.name}</strong> to
            permanently purge
          </label>
          <TextField
            id="purge-confirm"
            value={confirm}
            placeholder={filespace.name}
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </div>
        <div className="cfs-fs-form__actions">
          <Button variant="secondary" onClick={onLeave} disabled={purging}>
            Keep recoverable
          </Button>
          <Button variant="destructive" onClick={purge} disabled={!matches || purging}>
            {purging ? 'Purging…' : purgeFailed ? 'Retry purge' : 'Permanently purge'}
          </Button>
        </div>
      </div>
    </Card>
  )
}
