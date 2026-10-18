# First-owner setup and automation

For a normal fresh installation, follow [Install CloudFS](../INSTALL.md). The
guided browser setup at `/setup` creates the first organization and owner
account, then starts a browser session. It is the supported human path; do not
manually seed metadata or object blocks with `curl`.

The setup secret is `BOOTSTRAP_SECRET`, stored in the protected deployment
secrets file. Keep it private. The setup page requires it once, creates a real
password credential, and durably closes setup. A successful setup cannot be
repeated by setting the secret again. The same secret also gates the operator
readiness endpoint, `GET /v1/admin/doctor`.

## Automation-only bootstrap endpoint

`POST /v1/bootstrap` is retained for controlled automation that needs to create
the first owner through the API. It is gated by `X-Bootstrap-Secret`, rate
limited, and single-use for the deployment. If the secret is absent or shorter
than 16 characters, the route returns 404. A wrong secret returns 401; after
setup completes, another attempt returns a conflict. Human operators should
use the browser setup instead.

The request requires `orgId`, `email`, and `password`; `displayName` is
optional. Passwordless creation is disabled unless an automation explicitly
sets `allowTokenOnly: true`. The response includes a short-lived owner bearer
token. Treat the response as a secret: capture it only in a protected process
or secret store, never print it in shared logs or paste it into a ticket.

For request and response details, see the `POST /v1/bootstrap` entry in
[`API.md`](API.md). Do not use an automation token as a permanent login; after
bootstrap, normal users and operators use the browser sign-in and scoped
service-token flows.

## Verify a deployment through the native client

After owner setup, create a filespace, invite a test member with the intended
read or edit access, and install the signed Mac app. Follow
[Verify the trial](../INSTALL.md#verify-the-trial): upload a disposable file
through the mounted volume, wait for the app to report that changes are saved,
then reconnect and verify the downloaded bytes. This exercises the actual Mac
engine, gateway authorization, and object storage together.

The local MinIO demonstration under `backend/tools/` checks a narrow S3
byte-range transport path. It does not create an encrypted CloudFS file and is
not an end-to-end native round trip. The backend unit and integration suite is
run with `npm test` from this directory; see [`README.md`](README.md).
