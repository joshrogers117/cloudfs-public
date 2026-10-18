// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { getApi, type Filespace } from '../api'
import { useAuth } from '../app/auth'
import { Button, PaneHeader, StatePane } from '../design'
import { IconPlus } from '../design/icons'
import { IconDrive, IconMembers } from './filespaces/presentation'
import { DriveIllustration } from '../design/DriveIllustration'
import './filespaces/filespaces.css'

type LoadState = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'loaded'; filespaces: Filespace[] }
export function Filespaces() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const [state, setState] = useState<LoadState>({ kind: 'loading' })
  const [reloadKey, setReloadKey] = useState(0)
  const [query, setQuery] = useState('')
  const admin = user?.orgRole === 'Owner' || user?.orgRole === 'Admin'
  useEffect(() => {
    let alive = true
    getApi().listFilespaces().then((filespaces) => { if (alive) setState({ kind: 'loaded', filespaces }) })
      .catch((err: unknown) => { if (alive) setState({ kind: 'error', message: err instanceof Error ? err.message : 'Unable to load filespaces.' }) })
    return () => { alive = false }
  }, [reloadKey])
  const filespaces = state.kind === 'loaded' ? state.filespaces.filter((fs) => fs.name.toLowerCase().includes(query.toLowerCase())) : []
  return <>
    <PaneHeader title={`Filespaces${state.kind === 'loaded' ? ` (${state.filespaces.length})` : ''}`}
      trailing={admin && <><Button variant="secondary" leading={<IconMembers />} onClick={() => navigate('/members?invite=1')}>Invite members</Button><Button leading={<IconPlus size={15} />} onClick={() => navigate('/filespaces/new')}>Create filespace</Button></>} />
    {state.kind === 'loading' && <div className="cfs-fs-skeletons" role="status" aria-label="Loading filespaces">{[0, 1, 2].map((n) => <div key={n} className="cfs-fs-skeleton" />)}</div>}
    {state.kind === 'error' && <StatePane state="error" message={state.message} onRetry={() => { setState({ kind: 'loading' }); setReloadKey((n) => n + 1) }} />}
    {state.kind === 'loaded' && state.filespaces.length === 0 && <div className="cfs-empty-filespaces">
      <IconDrive size={38} /><h2>{admin ? 'Create your first filespace' : 'No filespaces assigned yet'}</h2>
      <p>{admin ? 'Give your team one place to work together. Files stream from your connected storage as you need them.' : 'Ask your workspace admin to grant access. Your shared drives will appear here.'}</p>
      {admin && <Button onClick={() => navigate('/filespaces/new')}>Create filespace</Button>}
    </div>}
    {state.kind === 'loaded' && state.filespaces.length > 0 && <section className="cfs-fs-directory" aria-label="Filespaces">
      {state.filespaces.length > 8 && <div className="cfs-fs-directory__toolbar"><span className="cfs-fs-directory__label">Your shared drives</span>
        <input type="search" className="cfs-input" aria-label="Search filespaces" placeholder="Find a filespace…" value={query} onChange={(e) => setQuery(e.target.value)} />
      </div>}
      <div className="cfs-volume-grid">{filespaces.map((fs) => <FilespaceRow key={fs.id} fs={fs} />)}</div>
      {filespaces.length === 0 && <p className="cfs-fs-no-results">No filespaces match “{query}”.</p>}
    </section>}
  </>
}

function FilespaceRow({ fs }: { fs: Filespace }) {
  return <Link to={`/filespaces/${encodeURIComponent(fs.id)}`} className="cfs-volume-tile" aria-label={`Open ${fs.name}`}>
    <DriveIllustration size={112} /><strong>{fs.name}</strong>
  </Link>
}
