# cloud-fs web console

This directory contains the React single-page console for signing in, setting up a
workspace, managing filespaces and members, and configuring storage and authentication.
It is built with Vite and TypeScript.

## Develop

```sh
cd web
npm ci
npm run dev
```

The development server listens on port `5173` and proxies `/v1/*` to the local gateway at
`http://localhost:8787`. Set `VITE_DEV_PROXY_TARGET` to use a different local gateway.

Development builds use the in-memory mock API by default, so the interface can be worked
on without a gateway. To exercise the real API locally, set `VITE_USE_MOCK=0`; requests
then use the same-origin Vite proxy unless `VITE_API_BASE` is set to a gateway origin.

## Build and checks

```sh
npm run build
npm run lint
npm test
npm run preview
```

`npm run build` type-checks the app, checks required brand assets, and writes the static
site to `dist/`. A production build uses the real HTTP API by default. Set
`VITE_API_BASE` to the gateway origin, or serve the site behind a same-origin reverse
proxy for `/v1/*`. Set `VITE_USE_MOCK=1` only when intentionally building a mock/demo
console.

`VITE_APP_DOWNLOAD_URL` is an optional build-time fallback for the native app download
link; the API's public auth configuration can provide a deployment-specific link at
runtime. The web app also reads the configured product name and portal URL from the
gateway's public auth configuration.
