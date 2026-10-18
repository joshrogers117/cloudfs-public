// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * GetTheAppCard — "get the app onto this Mac" card (ONBOARDING.md build step 3).
 * Shared between the post-/join success screen (editor journey step 3, Join.tsx), the
 * signed-in Settings → Devices area (settings/GetTheAppSection.tsx), and the admin setup
 * wizard's closing step (Setup.tsx, ONBOARDING.md build step 5 "set up your own Mac").
 *
 * "Open cloud-fs" fires `cloudfs://connect?server=<gateway origin>`
 * (client-app/Sources/CloudFSKit/ConnectLink.swift parses it and pre-fills the
 * app's login form) so the user never types or copies a server address. The web
 * console can be hosted separately from the API gateway, so use the public
 * `gatewayBaseUrl` when available and retain the browser origin for older
 * same-origin deployments. This mirrors the existing
 * `window.location.assign('cloudfs://...')` pattern DeviceAuthorize.tsx already
 * uses to hand the device-approval code to the app.
 *
 * Clicking the button does nothing VISIBLE in a browser with no cloud-fs app
 * installed (no protocol handler registered, so nothing happens — most browsers
 * don't even show an error). The hint copy below names that explicitly instead
 * of leaving what looks like a dead button.
 *
 * "Download for macOS" prefers the SERVER-configured `appDownloadUrl` (`GET
 * /v1/auth/config/public`, backend `APP_DOWNLOAD_URL` — ONBOARDING.md build step 6), so an
 * operator can set/change the download link at runtime with no rebuild, falling back to the
 * build-time `VITE_APP_DOWNLOAD_URL` for a deployment that hasn't set the server var yet. cloud-fs
 * is self-hosted (AGPLv3, BYO Cloudflare account) — there's no single canonical download URL, so
 * both being unset ⇒ honest fallback copy ("ask your admin"), never a dead link.
 */
import { useEffect, useState } from 'react'
import { Button } from '../../design'
import { getApi } from '../../api'
import { connectLink } from './getTheAppLinks'
import '../auth/auth.css'

export function GetTheAppCard({ compact = false }: { compact?: boolean }) {
  // Synchronous fallback (build-time var) so the card never flashes "no download button" while
  // the server config request is in flight; the effect below replaces it with the server value
  // once that resolves, per the preference order documented above.
  const [downloadUrl, setDownloadUrl] = useState(() => import.meta.env.VITE_APP_DOWNLOAD_URL?.trim() || undefined)
  const [gatewayBaseUrl, setGatewayBaseUrl] = useState<string>()
  const [gatewayResolved, setGatewayResolved] = useState(false)

  useEffect(() => {
    let alive = true
    getApi()
      .getPublicAuthConfig()
      .then((cfg) => {
        if (!alive) return
        const server = cfg.appDownloadUrl?.trim()
        if (server) setDownloadUrl(server)
        setGatewayBaseUrl(cfg.gatewayBaseUrl)
        setGatewayResolved(true)
      })
      .catch(() => {
        /* PUBLIC, best-effort — the build-time fallback (or honest copy) already covers this. */
        if (alive) setGatewayResolved(true)
      })
    return () => {
      alive = false
    }
  }, [])

  const cardClassName = compact
    ? 'cfs-get-app cfs-get-app--compact'
    : 'cfs-setup-next__card cfs-get-app'

  return (
    <section className={cardClassName} aria-label="Get CloudFS for Mac">
      <span className="cfs-setup-next__title cfs-get-app__title">
        Get CloudFS for Mac
      </span>

      <div className="cfs-get-app__actions">
        {downloadUrl ? (
          <a
            className="cfs-btn cfs-btn--primary"
            href={downloadUrl}
            target="_blank"
            rel="noopener noreferrer"
          >
            <svg className="cfs-get-app__apple" viewBox="0 0 16 16" aria-hidden="true">
              <path d="M11.9 8.5c0-1.7 1.4-2.5 1.5-2.5-.8-1.1-2-1.3-2.5-1.3-1.1-.1-2.1.7-2.7.7-.6 0-1.4-.7-2.3-.7-1.2 0-2.3.7-2.9 1.8-1.2 2.1-.3 5.1.8 6.8.6.8 1.2 1.7 2.1 1.7.8 0 1.1-.5 2.2-.5s1.4.5 2.2.5 1.5-.8 2-1.7c.7-.9.9-1.8.9-1.8s-1.3-.5-1.3-3ZM10.1 3.5c.5-.6.8-1.4.7-2.2-.7 0-1.6.5-2.1 1.1-.5.5-.9 1.3-.8 2.1.8.1 1.6-.4 2.2-1Z" />
            </svg>
            Download for Mac
          </a>
        ) : null}
        <Button
          type="button"
          size="regular"
          variant="secondary"
          disabled={!gatewayResolved}
          onClick={() => window.location.assign(connectLink(gatewayBaseUrl, window.location.origin))}
        >
          Open Mac app
        </Button>
      </div>

      <span className="cfs-setup-next__hint cfs-get-app__hint">
        Install the app, then open it to connect to this server.
        {!downloadUrl && ' Ask your administrator for the download.'}
      </span>

      <details className="cfs-get-app__update">
        <summary>Updating CloudFS?</summary>
        <p>
          Wait for uploads to finish, quit CloudFS, replace the app in Applications, then restart
          your Mac to load the updated background engine.
        </p>
      </details>
    </section>
  )
}
