/*
 * CreateFilespace — AUTH screen lane. Renders inside <RootLayout/> content pane
 * at /filespaces/new. Owned by the Create-Filespace screen agent.
 *
 * Thin route wrapper around `FilespaceCreateForm` (web/src/pages/filespaces/), which owns the
 * actual name + S3-compatible storage backend fields, client-side validation, and the
 * `getApi().createFilespace()` submit — extracted so the SAME form embeds in the setup
 * wizard's "First filespace" step (Setup.tsx, ONBOARDING.md build step 5) without duplicating
 * it. This route only supplies the PaneHeader chrome and the post-submit/cancel navigation.
 * No members/permissions UI — that lives in the Mac app.
 */
import { Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../app/auth'
import { FilespaceCreateForm } from './filespaces/FilespaceCreateForm'
import './filespaces/filespaces.css'

export function CreateFilespace() {
  const navigate = useNavigate()
  const { user } = useAuth()
  if (user?.orgRole !== 'Owner' && user?.orgRole !== 'Admin') return <Navigate to="/filespaces" replace />

  return (
    <>
      <FilespaceCreateForm
        onCreated={(fs) => navigate(`/filespaces/${encodeURIComponent(fs.id)}`)}
        onCancel={() => navigate('/filespaces')}
      />
    </>
  )
}
