# CloudFS gateway

Development test commands on this page require the full source repository. For the curated server archive, use [Build CloudFS](../docs/BUILD.md) and [Install CloudFS](../INSTALL.md).

The gateway is a Cloudflare Worker backed by Durable Objects for filespace
metadata, organization membership and authentication. It authorizes operations
and issues short-lived S3-compatible URLs; file bytes move between the Mac and
object storage without passing through the Worker.

For customer installation, use [Install CloudFS](../INSTALL.md). Advanced
deployment configuration and operations are in
[Self-hosting](../docs/SELF-HOSTING.md) and
[Server operations](../docs/SERVER-OPERATIONS.md). The HTTP contract is
[`API.md`](API.md); first-owner setup and its automation endpoint are in
[`BOOTSTRAP.md`](BOOTSTRAP.md).

## Local development

Use Node.js 22.12 or newer. From this directory:

```sh
npm ci
npm test
npm run typecheck
npm run dev
```

`wrangler dev` serves the local Worker at `http://127.0.0.1:8787`. Tests use
the local `workerd` runtime and do not require a Cloudflare account. Local
secrets belong in the ignored `.dev.vars` file; use
[`API.md` configuration reference](API.md#8-required-secrets-deployment) and
`.dev.vars.example` for names and development-only values.

Do not use a bare `wrangler deploy` for production. Use the guided installer
for a fresh R2 deployment, or the named deployment commands in
[`INSTALL.md`](../INSTALL.md) and [`SELF-HOSTING.md`](../docs/SELF-HOSTING.md)
for an existing deployment. The production wrapper builds the web console,
uses the selected deployment profile, and checks the deployed service.

The local MinIO helper under `tools/` exercises an isolated data-plane
transport demonstration. It does not provision or validate a production
deployment, and it is not a substitute for testing through a mounted Mac
filespace.
