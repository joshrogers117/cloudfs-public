/*
 * API entry point — the single seam the app swaps mock ↔ real through.
 *
 * Screens import `getApi()` (or the `CloudFsApi` type) and never touch a concrete
 * implementation. Which implementation `getApi()` returns is decided ONCE here,
 * from build-time env (see src/vite-env.d.ts):
 *
 *   VITE_USE_MOCK=1   → MockApi  (in-memory, offline; the default for now so the
 *                                 app runs with no backend for visual checks).
 *   VITE_USE_MOCK=0   → HttpApi  against VITE_API_BASE (the real backend gateway,
 *                                 cookie session + X-CFS-CSRF, CONTRACTS-AUTH §4).
 *
 * Same-origin dev default: with mock OFF and VITE_API_BASE EMPTY, the HttpApi uses
 * a base of "" — i.e. SAME-ORIGIN. In `npm run dev` the Vite proxy (vite.config.ts)
 * forwards `/v1/*` to the local Worker, so browser calls are first-party (no CORS,
 * the cfs_session cookie is same-site). For prod set VITE_API_BASE to the deployed
 * gateway origin (or keep it empty when the gateway is reverse-proxied same-origin).
 */
import type { CloudFsApi } from './api'
import { MockApi } from './mock'
import { HttpApi } from './http'

/**
 * Whether to use the in-memory mock API.
 *
 * Audit B9: the mock used to default ON even in a PRODUCTION build, so a deployed
 * console with no env config silently shipped FAKE data that accepts any login —
 * indistinguishable from the real thing. Now the default is environment-aware:
 *   - PROD build (the deployed console): default OFF (real HTTP). An operator who
 *     genuinely wants a demo build sets VITE_USE_MOCK=1 explicitly.
 *   - DEV build (`npm run dev`): default ON, so the app runs offline for visual work.
 * An explicit VITE_USE_MOCK always wins in either environment.
 */
function mockEnabled(): boolean {
  const v = import.meta.env.VITE_USE_MOCK
  if (v === undefined) return !import.meta.env.PROD // prod ⇒ real; dev ⇒ mock
  return v !== '0' && v.toLowerCase() !== 'false'
}

function createApi(): CloudFsApi {
  if (mockEnabled()) return new MockApi()

  // Mock off → real client. An empty VITE_API_BASE means SAME-ORIGIN (the dev proxy
  // forwards /v1/* to the Worker; in prod a same-origin reverse proxy serves it).
  const base = import.meta.env.VITE_API_BASE ?? ''
  if (!base && import.meta.env.PROD) {
    console.warn(
      '[cloud-fs] VITE_USE_MOCK is off and VITE_API_BASE is empty — using SAME-ORIGIN. ' +
        'This only works if the gateway is reverse-proxied at this origin. Set ' +
        'VITE_API_BASE to the gateway origin otherwise.',
    )
  }
  return new HttpApi(base)
}

let instance: CloudFsApi | null = null

export function getApi(): CloudFsApi {
  if (!instance) instance = createApi()
  return instance
}

/**
 * Whether the active API is the in-memory MockApi (offline) rather than the real
 * HttpApi. Decided by the same build-time toggle as `getApi()` (above), so the UI
 * can show an honest connection status: "Offline (mock data)" only when mocked,
 * "Connected" when the real backend client is live. Stable for the page lifetime.
 */
export function isMockMode(): boolean {
  return mockEnabled()
}

export type { CloudFsApi } from './api'
export { ApiError } from './http'
export { CredentialInUseError } from './errors'
export * from './types'
export { bytesLabel } from './format'
