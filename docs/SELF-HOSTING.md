# Advanced self-hosting

[Install CloudFS](../INSTALL.md) is the canonical guide for fresh server setup,
Mac installation, onboarding, updates, and the first trial. This page covers
configuration choices for operators who need an existing S3-compatible bucket,
an isolated named deployment profile, or optional authentication and email
providers. It does not repeat the installer walkthrough.

The gateway configuration contract is maintained in
[`backend/src/env.ts`](../backend/src/env.ts) (`CONFIG_MANIFEST`), and the
deployment script validates production values in
[`scripts/deploy-config.mjs`](../scripts/deploy-config.mjs). Use those sources
when a key not described here is needed.

## Isolated trial alongside an existing server

Profiles keep each environment's variables and secrets under
`.deployments/<profile>/`, which is ignored by Git. Use a different profile,
Worker name, data bucket, and audit bucket for a trial or staging deployment.

For an existing bucket or a non-R2 S3-compatible provider, create a private
configuration without provisioning cloud resources. For a fresh installation
using the guided Cloudflare/R2 setup, use [Install CloudFS](../INSTALL.md).

```sh
node scripts/deployment.mjs studio prepare
```

Edit `.deployments/studio/deployment.vars` and `secrets.json`. Set the selected
Cloudflare account, a unique Worker name, audit bucket, data bucket, public
HTTPS origin, and storage endpoint/region. Put the bucket's access key pair in
the secrets file. Keep the generated application secrets unchanged and back up
the complete profile securely. The deployment wrapper requires explicit
`CLOUDFS_WORKER_NAME` and `CLOUDFS_AUDIT_BUCKET` for named profiles.

Install the pinned dependencies in `backend/` and `web/` (`npm ci` in each),
then validate and deploy the selected profile:

```sh
node scripts/deployment.mjs studio check
node scripts/deployment.mjs studio deploy
```

`check` builds and validates without deploying. `deploy` runs the production
deployment wrapper, which builds the console, deploys the Worker and runs
deployment checks. For a new Cloudflare/R2 server, or an update to an existing
one, follow [Install CloudFS](../INSTALL.md); do not run `prepare` over existing
configuration. The scripts refuse to replace an existing profile's generated
keys.

### Automatic fresh Cloudflare/R2 installation

The guided fresh-install procedure is documented in
[Install CloudFS](../INSTALL.md#set-up-a-new-server). This advanced guide does
not repeat its provisioning-token prompts or browser setup steps.

### The config split: generic `wrangler.jsonc` + git-ignored `.prod.vars`

The committed `backend/wrangler.jsonc` describes Worker bindings and local
development defaults. Production values belong in the selected profile's
`deployment.vars`; secrets belong in its `secrets.json`. Do not put credentials
in vars or source control. Production deployment requires public HTTPS origins
for `S3_ENDPOINT`, `PUBLIC_BASE_URL`, and `WEB_BASE_URL`; `WEB_BASE_URL` defaults
to `PUBLIC_BASE_URL`, and the R2 endpoint is derived from `CLOUDFLARE_ACCOUNT_ID`
when omitted. The deployment wrapper enforces upload verification and closed
signup by default. A bare `wrangler deploy` bypasses these production checks.

Core values:

| Setting | Location | Purpose |
| --- | --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | vars | Account that owns the Worker and any bound R2 buckets. |
| `CLOUDFS_WORKER_NAME` | vars | Distinct Worker name for this profile. |
| `CLOUDFS_AUDIT_BUCKET` | vars | R2 bucket used for archived audit segments. |
| `S3_ENDPOINT`, `S3_BUCKET`, `S3_REGION` | vars | Default S3-compatible storage endpoint, bucket, and SigV4 region (`auto` for R2). |
| `PUBLIC_BASE_URL`, `WEB_BASE_URL` | vars | Public HTTPS origins for the gateway and browser console. Normally use one origin. |
| `AUTH_SIGNING_SECRET` | secrets | Signs bearer tokens. Rotating it invalidates outstanding signed tokens. |
| `BOOTSTRAP_SECRET` | secrets | Opens first-owner setup and the operator doctor endpoint. Setup closes after the first owner is created. |
| `STORAGE_ENC_KEY` | secrets | Protects filespace master keys and console-managed credentials. Preserve it with a secure backup. |
| `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | secrets | Default storage credential. Use a dedicated, least-privileged key. |

See [`backend/API.md`](../backend/API.md#8-required-secrets-deployment) for the
complete configuration reference, including optional R2 native verification
bindings and per-filespace storage credentials. When the deployment-default
bucket is R2 in the Worker account, the wrapper adds the native `DATA_BUCKET`
mapping used for object verification. Other providers continue through the
signed S3 verification path.

## Storage choices

Filespace file blocks are client-encrypted and stored in the selected bucket;
the Worker stores namespace metadata and controls access. The Worker does not
proxy media bytes. A filespace can use the deployment-default backend or an
administrator-configured per-filespace S3-compatible backend.

For a per-filespace backend, configure the endpoint origin, region, bucket, and
path-style setting in the filespace storage form. If using a secret reference,
add matching `S3_ACCESS_KEY_ID__<REF>` and `S3_SECRET_ACCESS_KEY__<REF>` Worker
secrets (and `S3_SESSION_TOKEN__<REF>` for temporary credentials). A missing
referenced credential fails closed. Console-managed credentials are encrypted
under `STORAGE_ENC_KEY`. See the storage section in
[`backend/API.md`](../backend/API.md#8a-bring-your-own-s3-compatible-storage-per-filespace-backend).

Use the console's **Test connection** before creating a filespace. A successful
test verifies the configured bucket connection; it does not move data or prove
that a different region or jurisdiction has been selected. Filespace location
follows its bucket.

## Authentication and email

Closed signup is the production default. Invite teammates from the console;
new-org signup settings are independent of organization member invitations.
`SIGNUP_MODE` supports `closed`, `invite`, `domain`, and `open`. Open signup on
HTTPS requires the explicit `SIGNUP_OPEN_ON_HTTPS=1` opt-in. Prefer closed
signup for a private team deployment.

OIDC and WebAuthn passkeys are optional. OIDC requires the issuer, client ID,
client secret, exact redirect URI, and target organization to match the identity
provider registration. Passkeys require the relying-party domain and exact
browser origin. Configure these after the public domain is final; unset
configuration leaves the respective routes disabled. See
[`backend/API.md`](../backend/API.md) for the full setting list.

Email is optional for a controlled trial. Without a delivering provider, the
console can provide invitation links to copy, but email verification, invitations,
and password resets are not delivered. Never enable the development console
sender in production; deployment validation rejects it. Supported senders are
Cloudflare Email Sending, Resend, Postmark, and Amazon SES. Set `EMAIL_FROM` to
a verified sender address; Cloudflare Email Sending also needs the sender
domain onboarded and the generated sender-restricted Worker binding. Send a
real test message and check inbox placement before relying on email recovery.

## Day-two operations

- **Protect recovery material.** Back up the profile's `secrets.json`, the data
  bucket, audit bucket, and metadata using the procedure in
  [Backup and restore](BACKUP-RESTORE.md). Losing `STORAGE_ENC_KEY` can make
  filespace master keys unrecoverable. Snapshots are not an independent backup.
- **Rotate cautiously.** Rotate bucket keys at the provider, update the
  corresponding Worker secrets, then verify storage readiness. Do not replace
  `STORAGE_ENC_KEY` without a tested migration. Rotating `AUTH_SIGNING_SECRET`
  invalidates existing signed tokens. After first-owner setup, rotating or
  removing `BOOTSTRAP_SECRET` cannot reopen setup; removing it disables the
  operator doctor endpoint.
- **Revoke a lost device.** Use the console's **Settings → Devices → Revoke**.
  A revoked device can no longer refresh its session; already-downloaded data
  and unexpired object URLs cannot be recalled.
- **Recover access.** Store TOTP recovery codes offline and maintain another
  administrator account. Password-reset email requires a working provider. The
  setup secret is not an account-password reset mechanism. For recovery of an
  existing pre-login deployment, see the legacy-account procedure below.
- **Use scoped machine access.** Create and revoke service tokens through the
  administration API or CLI. Avoid sharing human browser credentials with
  automation.

## Troubleshooting and operator recovery

Start with the signed-in console's **Workspace settings → Troubleshooting → Run
checks**. The operator endpoint `GET /v1/admin/doctor` is gated by
`X-Bootstrap-Secret`; it returns 503 when a required readiness check fails.
`GET /v1/health` reports public liveness only and does not verify storage or
metadata readiness. See [Server operations](SERVER-OPERATIONS.md) for checks,
diagnostics, updates, and recovery limits.

| Symptom | Check |
| --- | --- |
| Deployment rejected | Confirm the selected Cloudflare account, Worker and bucket names, public HTTPS origins, and required secrets in the same profile. Keep the current secrets; do not initialize a replacement profile to repair the server. |
| Setup page says setup is disabled | Confirm the configured `BOOTSTRAP_SECRET` is at least 16 characters, redeploy, and use it only for the first owner. Setup cannot be reopened after successful initialization. |
| Filespace storage test fails | Check endpoint, bucket, region, permissions, network reachability, and whether the provider supports the required S3 operations. Do not disable upload verification. |
| Invitation or reset mail does not arrive | Check the sender/provider configuration and delivery test. Until delivery works, use copied invitation links for controlled onboarding; password reset by email is unavailable. |
| Signed in but cannot see files | Ask an administrator to grant access to the filespace or folder. Signing in alone does not grant file access. |
| Upload remains pending | Keep the app's pending-write cache intact. Resolve the reported storage or connectivity error and wait for remote durability before restarting or updating the app. |

For a legacy deployment that has an owner and filespaces but no login-directory
entry, use the supported migration utility rather than creating another org or
changing keys. It accepts a private owner-token file or the original deployment
signing-key file; both paths require private input files. This example uses an
existing owner token:

```sh
node scripts/migrate-legacy-account.mjs \
  --gateway https://your-server.example \
  --org your-org \
  --owner-token-file /private/owner-token \
  --output /private/migration.json
```

Keep the input credential file mode 0600. The output file is created privately;
do not commit or share it. If the existing password is lost and email recovery
is unavailable, the same utility has an explicitly invoked password-recovery
path that requires the original signing-key file and owner ID. This is an
operator recovery procedure, not a normal login method; see the script's
argument definitions in [`migrate-legacy-account.mjs`](../scripts/migrate-legacy-account.mjs).
