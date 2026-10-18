/*
 * RootRedirect — the "/" (and catch-all) gate (auth-spec §1.1 step 1 / W4).
 *
 * A brand-new deployment (GET /v1/setup/status → needed:true) redirects to the
 * first-run /setup wizard — without this, a fresh deploy dead-ends on a sign-in
 * form no credential can pass. Otherwise the normal flow: /filespaces, which
 * bounces to /signin when signed out.
 */
import { Navigate } from 'react-router-dom'
import { useSetupNeeded } from './setupStatus'
import './shell.css'

export function RootRedirect() {
  const setupNeeded = useSetupNeeded()
  if (setupNeeded === null) return <div className="cfs-auth-layout" aria-busy="true" />
  return <Navigate to={setupNeeded ? '/setup' : '/filespaces'} replace />
}
