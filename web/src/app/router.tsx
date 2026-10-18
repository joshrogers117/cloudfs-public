/*
 * Router — the route table the screen lanes plug their pages into.
 *
 * Unauthenticated routes render under <AuthLayout/> (centered branded card):
 *   /signup  → pages/SignUp.tsx
 *   /signin  → pages/SignIn.tsx
 *
 * Standalone (own chrome):
 *   /auth/callback     → pages/AuthCallback.tsx   (SSO landing)
 *   /device/authorize  → pages/DeviceAuthorize.tsx (Mac-app handoff approval;
 *                         REQUIRES a session — bounces via /signin?next=…)
 *   /setup             → pages/Setup.tsx          (first-run wizard; renders
 *                         signed-out AND signed-in, self-hides when complete)
 *   /join              → pages/Join.tsx           (invite-based join, ONBOARDING.md
 *                         build step 1; renders signed-out AND signed-in, same
 *                         reason as /setup — a plain <AuthLayout/> redirect would
 *                         bounce away mid-flow the moment /join mints a session)
 *
 * Authenticated routes render under <RootLayout/> (sidebar + content):
 *   /filespaces            → pages/Filespaces.tsx
 *   /filespaces/new        → pages/CreateFilespace.tsx
 *   /filespaces/:id/settings → pages/FilespaceSettings.tsx
 *   /settings              → pages/AccountSettings.tsx
 *
 * Root: a fresh deploy (GET /v1/setup/status → needed:true) lands on /setup;
 * otherwise the normal sign-in flow (auth-spec §1.1 step 1 / W4).
 *
 * FROZEN: screen agents own the page components, not this table. If a screen
 * needs a new route, coordinate — this file is shared.
 * (Edited for the auth overhaul per OVERNIGHT/auth-spec.md W1/W3/W4.)
 */
import { createBrowserRouter } from 'react-router-dom'
import { AuthLayout } from './AuthLayout'
import { RootLayout } from './RootLayout'
import { RootRedirect } from './RootRedirect'
import { SignUp } from '../pages/SignUp'
import { SignIn } from '../pages/SignIn'
import { PasswordRecovery } from '../pages/PasswordRecovery'
import { VerifyEmail } from '../pages/VerifyEmail'
import { AuthCallback } from '../pages/AuthCallback'
import { DeviceAuthorize } from '../pages/DeviceAuthorize'
import { Setup } from '../pages/Setup'
import { Join } from '../pages/Join'
import { FilespaceDashboard } from '../pages/FilespaceDashboard'
import { Filespaces } from '../pages/Filespaces'
import { CreateFilespace } from '../pages/CreateFilespace'
import { FilespaceSettings } from '../pages/FilespaceSettings'
import { AccountSettings } from '../pages/AccountSettings'
import { MembersPage, DevicesPage } from '../pages/WorkspacePages'

export const router = createBrowserRouter([
  {
    element: <AuthLayout />,
    children: [
      { path: '/signup', element: <SignUp /> },
      { path: '/signin', element: <SignIn /> },
      { path: '/forgot-password', element: <PasswordRecovery /> },
      { path: '/reset-password', element: <PasswordRecovery reset /> },
      { path: '/finish-sign-in', element: <PasswordRecovery reset legacy /> },
      // Public email-verification landing route — the link in the verification
      // email points here (?token=&orgId=); no session required.
      { path: '/verify-email', element: <VerifyEmail /> },
    ],
  },
  // SSO landing route — standalone (no AuthLayout) so it controls its own UI while
  // it completes the OIDC round-trip and hydrates the session.
  { path: '/auth/callback', element: <AuthCallback /> },
  // Mac-app browser-handoff approval — standalone because it needs the INVERSE of
  // AuthLayout's redirect (it requires a session; signed-out → /signin?next=…).
  { path: '/device/authorize', element: <DeviceAuthorize /> },
  // First-run setup wizard — standalone; gated by GET /v1/setup/status and
  // self-hiding once setup is complete.
  { path: '/setup', element: <Setup /> },
  // Invite-based join — standalone (see the header note above for why).
  { path: '/join', element: <Join /> },
  {
    element: <RootLayout />,
    children: [
      { path: '/filespaces', element: <Filespaces /> },
      { path: '/filespaces/new', element: <CreateFilespace /> },
      { path: '/filespaces/:id', element: <FilespaceDashboard /> },
      { path: '/filespaces/:id/settings', element: <FilespaceSettings /> },
      { path: '/settings', element: <AccountSettings /> },
      { path: '/workspace', element: <AccountSettings workspace /> },
      { path: '/members', element: <MembersPage /> },
      { path: '/devices', element: <DevicesPage /> },
    ],
  },
  { path: '/', element: <RootRedirect /> },
  { path: '*', element: <RootRedirect /> },
])
