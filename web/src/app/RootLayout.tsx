// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from 'react'
import { Link, NavLink, Navigate, Outlet, useLocation } from 'react-router-dom'
import { BrandMark, Button } from '../design'
import { IconPlus, IconSettings, IconSignOut } from '../design/icons'
import { IconDrive, IconMembers } from '../pages/filespaces/presentation'
import { IconLaptop, IconShield } from '../pages/settings/icons'
import { getApi, isMockMode, type Filespace } from '../api'
import { useAuth } from './auth'
import { permissionsFor } from './permissions'
import './shell.css'

export function RootLayout() {
  const { isAuthenticated, loading, logout, user, session } = useAuth()
  const location = useLocation()
  const mock = isMockMode()
  const [sidebarOpen, setSidebarOpen] = useState(() => window.innerWidth > 760)
  const [spaces, setSpaces] = useState<Filespace[] | null>(null)
  const [spacesFailed, setSpacesFailed] = useState(false)
  useEffect(() => {
    if (!isAuthenticated) return
    let active = true
    getApi().listFilespaces().then((items) => {
      if (active) { setSpaces(items); setSpacesFailed(false) }
    }).catch(() => { if (active) setSpacesFailed(true) })
    return () => { active = false }
  }, [isAuthenticated, session?.org.id, location.pathname])
  if (loading) return <div className="cfs-root" aria-busy="true" aria-label="Loading workspace" />
  if (!isAuthenticated) return <Navigate to="/signin" replace />
  const permissions = permissionsFor(user?.orgRole)
  const admin = permissions.manageWorkspace
  const workspace = session?.org.name ?? 'Workspace'
  const initials = workspace.slice(0, 2).toUpperCase()
  const personInitials = (user?.name || user?.email || 'Account').slice(0, 2).toUpperCase()
  const nav = [
    ...(admin ? [{ to: '/members', label: 'Members', Icon: IconMembers }, { to: '/workspace', label: 'Workspace settings', Icon: IconSettings }] : []),
    { to: '/devices', label: 'Apps and devices', Icon: IconLaptop },
  ]
  const accountPage = location.pathname === '/settings'
  const creating = location.pathname === '/filespaces/new'
  const current = location.pathname === '/filespaces' ? 'Workspace dashboard'
    : location.pathname === '/filespaces/new' ? 'Create filespace'
    : location.pathname.startsWith('/filespaces/') ? (location.pathname.endsWith('/settings') ? 'Filespace settings' : 'Filespace dashboard')
    : location.pathname === '/settings' ? 'My account'
    : nav.find((item) => location.pathname.startsWith(item.to))?.label ?? 'Workspace dashboard'
  return (
    <div className={`cfs-root${sidebarOpen ? '' : ' is-sidebar-collapsed'}${accountPage ? ' is-account-page' : ''}${creating ? ' is-creating' : ''}`}>
      <a href="#main-content" className="cfs-skip-link">Skip to content</a>
      <header className="cfs-topbar">
        <button className="cfs-icon-button cfs-sidebar-toggle" onClick={() => setSidebarOpen((open) => !open)} aria-label={sidebarOpen ? 'Hide sidebar' : 'Show sidebar'} aria-expanded={sidebarOpen} aria-controls="workspace-sidebar"><svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><rect x="2.5" y="3" width="15" height="14" rx="2" /><path d="M7 3v14" /></svg></button>
        <span className="cfs-topbar__title">{current}</span>
        <Link className="cfs-topbar__app" to="/devices" aria-label="Get the Mac app"><IconLaptop size={20} /><span>Get the Mac app</span></Link>
        <details className="cfs-account-menu" key={location.pathname}>
          <summary aria-label="Account menu" title={user?.email}><span className="cfs-profile-avatar">{personInitials}</span></summary>
          <div className="cfs-account-menu__panel"><strong>{user?.name || user?.email}</strong><span>{user?.email}</span><span>{user?.orgRole}</span><Link to="/settings"><IconShield />My account</Link><Button variant="subtle" leading={<IconSignOut />} onClick={() => void logout()}>Sign out</Button></div>
        </details>
      </header>
      <nav className="cfs-workspace-rail" aria-label="Workspaces">
        <Link className="cfs-workspace-rail__avatar" to="/filespaces" aria-label={`${workspace} workspace`} title={workspace}>{initials}</Link>
        <Link className="cfs-workspace-rail__brand" to="/filespaces" aria-label="CloudFS home" title="CloudFS"><BrandMark size={36} /></Link>
      </nav>
      {sidebarOpen && <button className="cfs-sidebar-backdrop" aria-label="Close sidebar" onClick={() => setSidebarOpen(false)} />}
      <aside id="workspace-sidebar" className="cfs-sidebar" aria-label="Workspace sidebar" onClick={(event) => { if (window.innerWidth <= 760 && event.target instanceof Element && event.target.closest('a')) setSidebarOpen(false) }}>
        <div className="cfs-workspace"><Link to="/filespaces" className="cfs-workspace__home" aria-label="Workspace dashboard"><svg width="25" height="25" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><path d="M3 10 12 3l9 7v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1Z" /><path d="M8 14a4 4 0 0 0 8 0" /></svg></Link><div><span className="cfs-workspace__label">Workspace</span><Link to="/filespaces" title={workspace}>{workspace}</Link></div>{admin && <details className="cfs-workspace-menu" key={location.pathname}><summary className="cfs-icon-button" aria-label="Workspace menu">⋮</summary><nav aria-label="Workspace actions"><Link to="/filespaces/new"><IconPlus />Create filespace</Link>{nav.map(({ to, label, Icon }) => <Link key={to} to={to}><Icon />{label}</Link>)}</nav></details>}</div>
        <div className="cfs-sidebar__filespaces">
          <div className="cfs-sidebar__section"><NavLink to="/filespaces" end>Filespaces{spaces && ` (${spaces.length})`}</NavLink>{admin && <Link to="/filespaces/new" className="cfs-icon-button" aria-label="Create filespace" title="Create filespace"><span className="cfs-circle-plus"><IconPlus size={15} /></span></Link>}</div>
          <nav className="cfs-space-nav" aria-label="Filespaces">
            {spaces?.map((space) => {
              const base = `/filespaces/${encodeURIComponent(space.id)}`
              const selected = location.pathname === base || location.pathname.startsWith(base + '/')
              return <div key={space.id}>
                <Link to={base} className={`cfs-space-nav__row${selected ? ' is-active' : ''}`}><IconDrive size={20} /><span>{space.name}</span><span className="cfs-space-nav__chevron" aria-hidden="true">{selected ? '⌃' : '⌄'}</span></Link>
                {selected && <nav className="cfs-filespace-subnav" aria-label={`${space.name} navigation`}>
                  <NavLink to={base} end>Filespace dashboard</NavLink>
                  {admin && <Link to={`${base}/settings#snapshots`}>Snapshots</Link>}
                  {permissions.manageFilespaceSettings && <NavLink to={`${base}/settings`}>Filespace settings</NavLink>}
                  <a href={`cloudfs://${encodeURIComponent(space.id)}`}>Open in desktop app ↗</a>
                </nav>}
              </div>
            })}
            {!spaces && !spacesFailed && <span className="cfs-sidebar__loading" role="status">Loading filespaces…</span>}
            {spacesFailed && <Link className="cfs-sidebar__loading" to="/filespaces">View filespaces</Link>}
            {spaces?.length === 0 && <span className="cfs-sidebar__loading">No filespaces yet</span>}
          </nav>
        </div>
        <div className="cfs-sidebar__spacer" />
        <footer className="cfs-sidebar__footer">
          {mock && <span className="cfs-preview-label">Preview · sample data</span>}
          <Link className="cfs-sidebar__get-app" to="/devices"><BrandMark size={22} /><span>CloudFS for Mac</span><svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><path d="M4 12 12 4M4 4h8v8" /></svg></Link>
          <span className="cfs-sidebar__account-role">{user?.orgRole} workspace access</span>
        </footer>
      </aside>
      <div className="cfs-content">
        <main id="main-content" className="cfs-content__body" tabIndex={-1}><div className="cfs-content__inner"><Outlet /></div></main>
      </div>
    </div>
  )
}
