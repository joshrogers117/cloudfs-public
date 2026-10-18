/// <reference types="vite/client" />

/*
 * Typed access to the app's build-time env vars (Vite exposes only VITE_*).
 *
 *   VITE_USE_MOCK  "1" (default) → MockApi (offline, no backend);
 *                  "0" → real HttpApi.
 *   VITE_API_BASE  base URL of the backend gateway, e.g.
 *                  "https://gw.cloud-fs.example". EMPTY = same-origin (the dev
 *                  proxy in dev, or a same-origin reverse proxy in prod).
 *   VITE_DEV_PROXY_TARGET  dev-only: where the Vite dev server proxies /v1/* to
 *                  (default http://localhost:8787). Read in vite.config.ts, not app code.
 *   VITE_APP_DOWNLOAD_URL  optional. Deployment-specific download link for the cloud-fs
 *                  Mac app (ONBOARDING.md build step 3, GetTheAppCard.tsx). Self-hosted
 *                  product — there's no single canonical URL. Build-time FALLBACK only as
 *                  of build step 6: GetTheAppCard now prefers the server-configured
 *                  `appDownloadUrl` (GET /v1/auth/config/public, backend APP_DOWNLOAD_URL)
 *                  so an operator can set/change it without a rebuild; this var only
 *                  matters until that's set, or for a deployment that intentionally skips
 *                  the server var. Both unset ⇒ honest "ask your admin" copy, never a dead
 *                  button.
 */
interface ImportMetaEnv {
  readonly VITE_USE_MOCK?: string
  /** DEV + mock only, for verifying regular-member navigation. */
  readonly VITE_DEMO_ROLE?: string
  readonly VITE_API_BASE?: string
  readonly VITE_DEV_PROXY_TARGET?: string
  readonly VITE_APP_DOWNLOAD_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
