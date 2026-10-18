# Server operations

[Install CloudFS](../INSTALL.md) is the customer guide for initial setup and
updates. This page covers readiness checks, safe operator actions, diagnostics,
and recovery. Keep the current deployment profile and its secrets together; the
Worker code, browser console, Mac app, and data/schema behavior should be treated
as one release.

## Readiness and health checks

`GET /v1/health` reports public API liveness and version. It does not test
storage or metadata services. For deployment readiness, use the signed-in
console's **Workspace settings → Troubleshooting → Run checks**. The operator
endpoint `GET /v1/admin/doctor` requires the `X-Bootstrap-Secret` header and
returns 503 when a required check fails. An owner or administrator can run the
organization doctor through `GET /v1/orgs/:org/doctor`; that endpoint returns
HTTP 200 with a report, so inspect its `ok` field and individual checks.

The doctor checks required secrets and encryption, metadata Durable Object
initialization, data-bucket access and upload-integrity behavior, audit storage,
signup policy, public URLs, and configured email delivery. Storage probes write
random temporary keys under `.cloudfs-doctor/` and
`.cloudfs-doctor-integrity/` and remove only those keys. A provider outage can
leave a probe object behind; it is separate from file data.

A missing local secrets file during deployment means full authenticated
readiness was not verified. Sign in and run the console check afterward. Email
is optional, but without a delivery provider invitations must be copied from
the console and password-reset email is unavailable. A successful Worker
upload or a passing `/v1/health` response alone does not establish readiness.

## Safe updates and compatibility

Use the same protected deployment profile for updates. Follow release-specific
backup and migration instructions, run the profile check, then deploy and run
readiness checks. Preserve the previous release and its configuration until the
new version is verified. Do not run fresh setup or generate replacement keys
over an existing deployment.

Database migrations preserve state, but rolling Worker code back does not undo
a migration. Test upgrades and recovery on an isolated deployment first. Do not
rename Durable Object bindings or remove their migration history as a
troubleshooting step. For API/client compatibility, use the release notes and
[`backend/API.md`](../backend/API.md); compatibility depends on the specific
server and client release pair.

When a behavior check against an existing filespace disagrees with deployment
readiness, keep it failed. Confirm the deployed version and release artifact,
preserve the result, then retry with a bounded delay and disposable test data.
Do not reset databases or infer success from elapsed time.

## Diagnose failures without exposing credentials

Start from the app's request ID and the Worker logs for the matching time.
Use available request IDs and status details to locate the matching Worker
logs. Redact URLs, request bodies, account details, and private email links
before sharing diagnostics. Do not enable the development email console sender
in production. Never share signed object URLs, passwords, setup secrets, API
tokens, encryption keys, or the deployment secrets file in support diagnostics.

| Symptom | First response |
| --- | --- |
| Public liveness fails | Check the public origin, Worker route, and deployment result. |
| Metadata readiness fails | Check Durable Object bindings and migration errors. Preserve current databases. |
| Storage or integrity check fails | Check the selected endpoint, bucket, credentials, and provider support. Keep upload verification enabled. |
| Upload remains pending | Keep the Mac app's pending-write cache intact. Resolve the reported storage or connectivity error and wait for remote durability before restarting or updating. |
| Mounted file returns an I/O error after reopening | Preserve unsaved work, finish pending uploads, close volume users, then use normal Disconnect and Connect. If flush or graceful disconnect fails, resolve that before remounting; do not force-unmount pending writes. |
| A large transfer receives 429 | Respect `Retry-After`; investigate the separate presign and mutation limits before changing capacity. |
| Authentication authority is unavailable | Expect a fail-closed 503 and retry after the service recovers. |
| Audit or snapshot maintenance fails | Check storage availability and retry status; preserve the deployment state while queued work resumes. |

Already-issued presigned URLs remain usable until expiry, and downloaded bytes
cannot be recalled. Treat revocation as prospective rather than as a way to
erase data already retrieved by a device.

## Backups and recovery

Filespace snapshots reference objects in the same data bucket. They help recover
ordinary file changes while those objects remain available, but they are not an
independent backup. Audit archives are not a backup of file metadata or keys.

Use [Backup and restore](BACKUP-RESTORE.md) for the supported encrypted archive
and fresh-server recovery procedure. Protect the deployment profile, especially
`STORAGE_ENC_KEY`, separately from the server and bucket. Restore also requires
the metadata authorities and referenced objects. The restore workflow retires
sessions, devices, service tokens, invitations, share links, and recovery codes;
review restored account permissions before users return.

Cloudflare's SQLite point-in-time recovery is scoped to an individual Durable
Object and does not provide an application-wide coordinated restore. See
[Cloudflare's SQLite recovery documentation](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/#pitr-point-in-time-recovery-api).
Practice the CloudFS backup procedure instead of relying on isolated object
recovery.

## Capacity and validation

Use `scripts/benchmark-server.mjs` for read-only listing/change-feed load
measurements. Use `scripts/benchmark-mounted.py` with a disposable test
filespace for an end-to-end write, remote-flush, and cold-read checksum check.
The mounted benchmark creates a uniquely named remote fixture; retain or clean
that fixture according to the test plan. A local Worker and MinIO exercise
local behavior and do not predict Internet or production R2 capacity.

The API limits request bodies to 16 MiB, and the main-file manifest is bounded
at 131,072 blocks. Large resource forks use the chunked storage path; see
[`cloudfsd/RESOURCE-FORKS.md`](../cloudfsd/RESOURCE-FORKS.md).
Measure metadata growth and workload capacity for the deployment rather than
extrapolating from a local test.
