import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// cloud-fs web app — SPA build, dark by default.
// Configured for Cloudflare Pages: static SPA in `dist/` with a `_redirects`
// fallback so client-side routes (e.g. /filespaces) resolve to index.html.
//
// CORS-free local dev: the dev server PROXIES `/v1/*` to the local Worker so the
// browser only ever makes SAME-ORIGIN requests (no CORS preflight, and the
// `cfs_session` cookie is first-party). The proxy target is VITE_DEV_PROXY_TARGET
// (default http://localhost:8787 — wrangler dev's default). In dev the real client
// leaves VITE_API_BASE empty so requests go to the same origin (the proxy); in prod
// set VITE_API_BASE to the deployed gateway origin.
// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const proxyTarget = env.VITE_DEV_PROXY_TARGET || 'http://localhost:8787'
  return {
    plugins: [react()],
    build: {
      outDir: 'dist',
      sourcemap: false,
    },
    server: {
      port: 5173,
      strictPort: false,
      proxy: {
        // Forward the gateway API surface to the local Worker. `changeOrigin`
        // rewrites the Host header so the Worker sees its own origin; cookies the
        // Worker sets (cfs_session) are stored against the dev origin and replayed
        // by `credentials: 'include'` calls — same-origin, so no CORS.
        '/v1': {
          target: proxyTarget,
          changeOrigin: true,
        },
      },
    },
    preview: {
      port: 4173,
    },
  }
})
