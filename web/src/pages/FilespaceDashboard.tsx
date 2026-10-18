// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getApi, type Filespace } from '../api'
import { useAuth } from '../app/auth'
import { permissionsFor } from '../app/permissions'
import { Button, StatePane } from '../design'
import { DriveIllustration } from '../design/DriveIllustration'
import './filespaces/filespaces.css'

export function FilespaceDashboard() {
  const { id } = useParams()
  return <FilespaceDashboardContent key={id} id={id} />
}

function FilespaceDashboardContent({ id }: { id?: string }) {
  const { user } = useAuth()
  const [space, setSpace] = useState<Filespace | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    let active = true
    getApi().listFilespaces().then((spaces) => {
      if (!active) return
      const found = spaces.find((item) => item.id === id)
      if (found) setSpace(found)
      else setError('This filespace is unavailable or you no longer have access.')
    }).catch((err: unknown) => { if (active) setError(err instanceof Error ? err.message : 'Could not load filespace.') })
    return () => { active = false }
  }, [id, retry])
  if (error) return <StatePane state="error" message={error} onRetry={() => { setError(null); setRetry((n) => n + 1) }} />
  if (!space || space.id !== id) return <StatePane state="loading" />
  return <section className="cfs-desktop-access">
    <div className="cfs-desktop-illustration"><div className="cfs-desktop-illustration__screen"><DriveIllustration size={96} /></div><div className="cfs-desktop-illustration__base" /></div>
    <h1>{space.name}</h1>
    <p>Connect your filespace in CloudFS to work with your files directly in Finder.</p>
    <Button size="large" onClick={() => window.location.assign(`cloudfs://${encodeURIComponent(space.id)}`)}>Open Mac app</Button>
    <p className="cfs-desktop-access__download">Need the app? <Link to="/devices">Download CloudFS for Mac</Link></p>
    {permissionsFor(user?.orgRole).manageFilespaceSettings && <div className="cfs-desktop-access__secondary"><span>Manage storage and recovery points in your browser.</span><Link to={`/filespaces/${encodeURIComponent(space.id)}/settings`}>Filespace settings</Link></div>}
  </section>
}
