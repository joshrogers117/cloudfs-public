// SPDX-License-Identifier: AGPL-3.0-or-later
import { Navigate } from 'react-router-dom'
import { useAuth } from '../app/auth'
import { PaneHeader } from '../design'
import { MembersSection } from './settings/MembersSection'
import { GetTheAppCard } from './join/GetTheAppCard'
import { DevicesSection } from './settings/DevicesSection'
import './settings/settings.css'

export function MembersPage() {
  const { user, session } = useAuth()
  if (!session || (user?.orgRole !== 'Owner' && user?.orgRole !== 'Admin')) return <Navigate to="/filespaces" replace />
  return <div className="cfs-settings-page"><PaneHeader title="Members" subtitle="Invite your team and manage workspace roles." /><MembersSection org={session.org.slug} /></div>
}

export function DevicesPage() {
  return <div className="cfs-settings-page"><PaneHeader title="Apps and devices" /><GetTheAppCard /><DevicesSection /></div>
}
