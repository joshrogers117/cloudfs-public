# cloud-fs Gateway — HTTP API (canonical contract)

This is the **canonical HTTP contract** for the cloud-fs gateway Worker. The macOS
client and the `cloudfs` CLI code their `HttpGatewayClient` against this document.
It is derived from the routes actually wired in `backend/src/index.ts` — if code and
this file disagree, the code is right; file a fix.

- **Base URL:** the deployed Worker origin (e.g. `https://gw.cloudfs.example`). Local
  dev: `http://127.0.0.1:8787` (`npm run dev`).
- **Transport:** use HTTPS in production. JSON routes use
  `content-type: application/json`; redirects, WebSockets, empty responses, and object
  bytes use their route-specific transport.
- **File contents normally bypass the gateway.** Clients transfer encrypted objects
  directly to and from storage using short-lived URLs minted by `POST …/presign`.

---

## 1. Authentication

Every route requires a credential unless its route entry says public. The gateway accepts
**TWO** credential
kinds (bearer FIRST, then cookie):

**1. Bearer token** — machines (cloudfsd, CLI, service tokens, OIDC/bootstrap sessions):

```
Authorization: Bearer <token>
```

**2. Browser session cookie** — human SPA sessions:

```
Cookie: __Host-cfs_session=<orgId>.<sessionId>   # HTTPS
Cookie: cfs_session=<orgId>.<sessionId>          # local HTTP development
```

Over HTTPS the `__Host-cfs_session` cookie is `HttpOnly; Secure; SameSite=Lax; Path=/`;
over local HTTP the cookie is named `cfs_session` and omits `Secure`. The gateway loads
the live server-side session row, enforces **idle (30 m) + absolute (12 h) + revocation**,
re-mints the short-lived (15 m) session JWS internally, and derives the SAME `Principal`
shape as a bearer. **CSRF:** every state-changing cookie-authed request (POST/PUT/DELETE/
PATCH) must echo the session's CSRF token in the **`X-CFS-CSRF`** header (double-submit;
returned in login/signup response bodies as `csrf`). Bearer (machine) callers carry no
ambient cookie and are CSRF-exempt. A request with neither credential → **401 `no_token`**.
A revoked session or service-token JWS → **401 `revoked`** (its `jti` is in the org's
revocation set).

### Token format

Compact **JWS / JWT**, `header.payload.signature` (base64url), signed **HS256** with
the Worker's `AUTH_SIGNING_SECRET`. The gateway rejects `alg:none` and any non-HS256
(no algorithm confusion), enforces `exp`/`nbf` with bounded clock skew, and supports
`jti` revocation. Tokens are minted by the SSO callback / service-account / guest-link
flows (`mintToken` in `src/security/auth.ts`) — **not** by this gateway.

Payload claims:

| Claim | Meaning |
|---|---|
| `sub` | stable principal id (member / service-account / guest-link id) |
| `typ` | `session` \| `service` \| `guest` |
| `org` | org tenant the token is bound to (root of tenant isolation) |
| `spc` | *(optional)* filespace binding; omitted = any space the org owns |
| `scp` | array of scopes (see below) |
| `jti`, `iat`, `exp`, `nbf?` | id / issued / expiry / not-before (epoch seconds) |

Default TTLs (clamped at mint): `session` 15 min · `service` 24 h · `guest` 7 days.

### Scopes (coarse capability gate)

Scopes gate the *kind* of operation; per-folder **ACLs** gate the *target* (§7).

| Scope | Grants |
|---|---|
| `fs:read` | list/stat metadata, read block maps, change feed, read presigns |
| `fs:write` | create/modify/delete items, write block maps, uploads, write presigns |
| `fs:lock` | acquire/renew/release advisory leases |
| `fs:admin` | grant/revoke ACLs, manage snapshot schedules |
| `snapshot:read` | list/browse snapshots |
| `snapshot:write` | create snapshots |
| `audit:read` | read the audit log |

### Tenant isolation

The token's `org` is authoritative. A request to `/v1/filespaces/:space` resolves the
Durable Object as `idFromName("<org>::<space>")`, so **two orgs that pick the same space
name never share a DO**. A token for org A addressing org B (via `/v1/orgs/:org/…` or a
mismatched space binding) gets **403 `cross_tenant`**.

---

## 2. Error envelope & status codes

All errors return a JSON envelope:

```json
{ "error": "<code>", "reason": "<optional human detail>" }
```

`409` conflicts add `"conflict": true` (and `expected`/`actual` for version conflicts).
Rate-limit `429`s add `Retry-After` + `X-RateLimit-*` headers.

| Status | `error` code(s) | When |
|---|---|---|
| 400 | `item required`, field-validation messages | malformed/missing body or query |
| 401 | `no_token`, `malformed`, `expired`, `bad_signature`, `unauthorized` | bad/absent token |
| 403 | `forbidden`, `forbidden_scope`, `cross_tenant`, `wrong_space`, `signup_disabled`, `domain_not_allowed` | scope/ACL/tenant denial; signup-mode gate (§8a) |
| 404 | `not found`, `no such item` | unknown route or item |
| 405 | `method not allowed` | wrong verb / disallowed presign method |
| 410 | route-specific expired/consumed errors | expired one-time links and soft-deleted filespaces |
| 409 | conflict (`conflict: true`) | optimistic-concurrency mismatch, incomplete upload |
| 413 | `body_too_large` | request exceeds a route-specific body limit |
| 426 | `websocket_required` | change subscription requires a WebSocket upgrade |
| 429 | `rate_limited` | token-bucket exhausted |
| 503 | dependency/maintenance errors | retryable service or storage failure |
| 507 | `metadata_capacity` | filespace metadata admission is full |
| 500 | error message | unexpected failure |

**Fail-closed:** any auth/scope/tenant error aborts before the privileged action.

---

## 3. Pagination (cursor format)

Directory listings and the change feed are **keyset-paginated** — never `OFFSET`.

- **Directory listing** (`GET …/items`): response is `{ items, cursor }`. `cursor` is an
  **opaque base64 string** (encodes the last `(is_dir, name)` seen) or `null` when the
  page is the last. Pass it back as `?cursor=<opaque>` to fetch the next page; treat it
  as a black box, do not parse it. `limit` defaults to 500, max 2000.
- **Change feed** (`GET …/changes`): response is `{ anchor, items, cursor }`. Here `cursor`
  is a **numeric `updatedSeq`** (or `null` at the tail); pass it back as `?since=<n>`.
  `anchor` is the current head seq — persist it as your sync anchor.

---

## 4. Core object shapes

```ts
Item {
  id: string;            // OPAQUE, immutable inode id, e.g. "ino-3f2a…" ("root" = the space root,
                         //   the one well-known literal id). Clients MUST treat it as opaque — do
                         //   NOT construct it from parent+name. IDs are opaque so the (parent, name) pair is the
                         //   human lookup key — case-insensitive, NFC-normalized.)
  parent: string | null; // parent inode id; null only for root
  name: string;
  isDir: boolean;
  size: number;          // bytes (sum of block lengths)
  contentVersion: string;// changes when content changes ("cv-<size>-<seq>")
  etag: string | null;   // assembled-object ETag; null until first upload completes
  version: number;       // optimistic-concurrency token; bumps on every metadata write
  updatedSeq: number;    // change-feed cursor value for this item
  deleted: boolean;      // tombstone (still surfaced in the change feed)
}
Block { chunkIdx, blockIdx, blockHash, objectKey, offset, length }      // all numbers except hashes/keys
LockResult { granted, path, owner?, mode?, fence?, heldBy?, expiresAt?, reason? }
UploadSession { uploadId, itemId, key, totalSize, partSize, state, uploadedParts:[{partNumber,etag,size}] }
Snapshot { id, label, scope, seqAnchor, tier, createdAt, immutableUntil, scheduleId }
RestoreResult { snapshotId, restored: string[], recreated: string[], conflicts: [{id,heldBy}], newerThanSnapshot: string[] }
AuditRecord { seq, ts, prevHash, hash, actorSub, actorType, orgId, spaceId, action, decision, ... }

// Live-activity feed — DO hot state, NOT the audit history:
ActiveTransfer  { id, path, direction:"upload"|"download", bytesDone, bytesTotal, state:"active"|"completing" }
LiveActivityEvent { seq, type, path, actor, ts, kind:"single"|"bulk", op?, count? }   // op/count present only when kind="bulk"
LiveActivity    { transfers: ActiveTransfer[], events: LiveActivityEvent[] }
```

---

## 5. Routes

`:fs` is the space id; the effective DO is `<org>::<fs>`. Unless noted, requests need a
valid token and the listed scope **and** a per-folder ACL check (§7) for mutations/mints.

### Health, setup and public routes

| Method | Path | Notes |
|---|---|---|
| GET / HEAD | `/v1/health` | No auth. GET returns `{ "ok": true, "apiVersion": <int> }`; HEAD returns an empty 200. `apiVersion` is the wire-contract version (`3` currently), separate from package versions. Clients should compare it with their supported version; v3 clients must honor signed upload headers and verify existing objects on retries. The version is also advertised by `X-CloudFS-API-Version`. `cloudfs version` reports the gateway version and warns when it differs from the CLI's expected version. |
| GET | `/v1/admin/doctor` | Public to call but gated by `X-Bootstrap-Secret`. Returns the deployment readiness report; status is 200 when all checks pass, 503 when any check fails, and 404 when bootstrap is disabled. |
| POST | `/v1/bootstrap` | **Deploy-time bootstrap** — secret-gated (`X-Bootstrap-Secret`, constant-time compared), single-use per deployment. Creates the first org + admin (`owner`) and mints an admin token. **`password` is now REQUIRED** (it sets the admin's real sign-in credential) unless the body explicitly opts out with `allowTokenOnly: true` (automation/CI escape hatch — 400 `password_required` otherwise). A successful bootstrap also marks the deployment **set-up** (the `/setup` wizard self-disables). 401 wrong/absent secret · 409 if already bootstrapped · 404 if `BOOTSTRAP_SECRET` unset/weak. Body `{ orgId, email, displayName?, password? \| allowTokenOnly:true }` → `{ orgId, userId, role, token, scopes, credentialed }`. Humans should prefer the web **setup wizard** (`POST /v1/setup/init`). **See `BOOTSTRAP.md`.** |
| GET | `/v1/setup/status` | **First-run probe (public, UNAUTHENTICATED, 10s per-isolate cache).** → `{ needed: boolean }` — `true` until first-run setup completes (via `/v1/setup/init` OR a successful legacy `/v1/bootstrap`). The SPA redirects `/` + `/signin` to the `/setup` wizard while `needed`. Leaks nothing else (no org names/counts). Owned by `setup.ts`. |
| POST | `/v1/setup/init` | **Setup wizard (public, gated by `BOOTSTRAP_SECRET`).** Body `{ secret, orgId, orgName, email, displayName, password }` → 201 `{ orgId, userId, csrf, account:{ email, displayName, role } }` + an org-qualified browser-session cookie (the operator is signed in; cookie name follows the HTTPS/local-HTTP rules above). Creates the org + owner + a REAL scrypt password (email pre-verified) and marks the deployment set-up (self-disables). Errors: 404 `setup_disabled` (secret unset/<16 chars — fail closed) · 401 `unauthorized` (wrong secret) · 400 `weak_password`/`invalid_body` · 409 `setup_complete`/`already_bootstrapped`/`bootstrap_credential_failed` · 429. Same per-IP limiter as bootstrap. Owned by `setup.ts`. |
| GET | `/v1/auth/config/public` | Public auth and portal configuration. Includes `mode`, `oidcEnabled`, optional `providerLabel`, `webBaseUrl`, `gatewayBaseUrl`, `productName`, `passkeysEnabled`, `signupMode`, and optional `appDownloadUrl`. It exposes no provider secrets or client ID. Runtime auth configuration takes precedence over deployment OIDC settings. |
| GET | `/v1/auth/oidc/start` | **OIDC SSO login (public).** 302 → the IdP authorize endpoint with `state`, `nonce`, PKCE `code_challenge` (S256), and a sealed HttpOnly login-state cookie. No body. The effective IdP is resolved at RUNTIME — the encrypted admin-console auth-config FIRST, then the deploy `OIDC_*` env. 404 if neither is configured. Owned by `security/oidc.ts` + `auth-config.ts`. |
| GET | `/v1/auth/oidc/callback` | **OIDC SSO callback (public, browser flow).** The IdP returns with `?code&state`; the gateway validates the state cookie and identity, then redirects to `<WEB_BASE_URL>/auth/callback` with the session cookie and clears the OIDC state cookie. Errors redirect to the same SPA route with `?error=<code>`. On an empty organization, the first verified identity can become owner only when its email matches `OIDC_BOOTSTRAP_EMAIL` or its domain is in `OIDC_ALLOWED_DOMAINS`; otherwise setup fails with `bootstrap_denied`. Later users follow the normal provisioning policy. 404 if OIDC is not configured. |
| POST | `/v1/orgs/:org/invites/redeem` | **Public** — the invite token *is* the credential. Per-IP rate-limited. Owned by `invites.ts`. |
| POST | `/v1/orgs/:org/shares/resolve` | **Public** — the share token *is* the credential. Per-IP rate-limited. Owned by `sharing.ts`. |

### 5a. Accounts, sessions & credentials — `/v1/auth/*`

Self-serve email+password accounts, browser sessions, MFA, passkeys, and email
verification. **Email is the username and is globally unique across all orgs** (the
`DirectoryDO` enforces it; a colliding signup → 409 `email_taken`). "Auth: public" routes
are pre-auth + rate-limited (per-IP + per-email token buckets); "Auth: session" routes
require a live browser session cookie (transport-specific name above); mutating session routes also require the `X-CFS-CSRF`
header. Sessions/credentials live in `AuthDO(orgId)`; the `email→{orgId,accountId}` index
lives in `DirectoryDO("global")`. State stores are wired by `auth-stores.ts`/`auth-wiring.ts`.
Session-cookie examples below refer to the same cookie described above: HTTPS uses
`__Host-cfs_session`, while local HTTP uses `cfs_session`.

**Signup + login**

| Method | Path | Auth | Body → Success |
|---|---|---|---|
| POST | `/v1/auth/signup` | public | `{ orgName, email, password, displayName, inviteToken? }` → 201 `{ orgId, accountId, userId, emailSent, state:"verify_email", csrf }` + session cookie. Creates org + owner account, claims the email, sends a verification email. **Gated by `SIGNUP_MODE`** (§8a): blocked signups return **403 `signup_disabled`** (mode `closed`, or `invite` without a valid `inviteToken`) or **403 `domain_not_allowed`** (mode `domain`, disallowed email domain). The gate runs before any org is provisioned. |
| GET | `/v1/auth/join/preview?token=…` | public | → 200 `{ orgName, email, role, expiresAt, invitedByName }` for an active invite; invalid or unknown invite → 404, expired/revoked/used invite → 410. Does not consume the invite. |
| POST | `/v1/auth/join` | public | `{ token, displayName, password }` → 201 `{ orgId, accountId, userId, role, scopes, emailVerified:true, state:"active", csrf }` + session cookie. Redeems the org-qualified invite and provisions the member's password account; invite-token possession verifies the invited email. Rate-limited by IP and invited email. |
| POST | `/v1/auth/login` | public | `{ email, password }` → 200 `{ userId, orgId, role, scopes, csrf }` + cookie. If the account has **confirmed TOTP OR ≥1 registered passkey** → 200 `{ mfaRequired:true, methods, challengeId }` (no session yet), where `methods` reflects what's available: `["totp","recovery"]` if TOTP, plus `["webauthn"]` if any passkey. 401 `invalid_credentials` (enumeration-safe). |
| POST | `/v1/auth/login/totp` | public | `{ challengeId, code }` → 200 `{ userId, orgId, role, scopes, csrf }` + cookie. 401 `invalid_challenge`/`bad_code`. A **wrong code does NOT burn the single-use challenge** — the challenge is consumed only on success, so a mistyped digit can be retried within the 5-min window. |
| POST | `/v1/auth/login/recovery` | public | `{ challengeId, recoveryCode }` → 200 (same shape) + cookie. A wrong/used recovery code likewise does not burn the login challenge. |
| POST | `/v1/auth/logout` | session+CSRF | — → 204, clears the cookie, revokes the session row + its jti. |
| GET | `/v1/auth/me` | session | → 200 `{ userId, orgId, email, displayName, role, scopes, emailVerified, orgName, orgSlug, mfa:{ totp:bool, webauthn:int } }`. `orgName` is the org's display name (null until renamed); `orgSlug` is the stable org id. |
| PATCH | `/v1/auth/account` | session+CSRF | `{ displayName?, email? }` → 200 `{ userId, orgId, email, displayName, role, emailVerified, orgName, orgSlug }`. Self-service profile update for the current session user. A changed **email** is re-claimed in the global `DirectoryDO` index (**409 `email_taken`** if owned by another account) and mirrored into the OrgDO User row; changing the email **resets `emailVerified` to false** (the new address is unproven). 400 `invalid_email`/`invalid_display_name`/`nothing to update`. |
| GET | `/v1/auth/sessions` | session | → 200 `[{ id, orgId, issuedAt, expiresAt, lastSeenAt, revokedAt, current }]` (no CSRF leaked). |
| DELETE | `/v1/auth/sessions/:id` | session+CSRF | → 204. Revoke one of the caller's own sessions (404 if not owned). |

Native clients may also call `GET /v1/auth/me` with a session or service bearer. This uses the gateway signature, revocation, and account-status gates, returns the current OrgDO identity/role and token scopes, and omits browser CSRF/MFA fields. Bearer credentials take precedence over cookies; invalid bearers never fall back to a browser session. Guest tokens are rejected.

**Device sessions — the native app's browser handoff (`security/auth-device.ts`)**

The app opens `<webBaseUrl>/device/authorize?state&code_challenge&code_challenge_method=S256&device_name[&device_model][&app_version]`
in the system browser; the signed-in user approves; the app exchanges the one-time code (+ its
PKCE verifier) for a long-lived **device session**. All opaque handles are org-qualified
(`<orgId>.<handle>`), like the session cookie. Secrets are stored **hashed only**.

| Method | Path | Auth | Body → Success |
|---|---|---|---|
| POST | `/v1/auth/device/approve` | session+CSRF | `{ state, codeChallenge (43–128 b64url), codeChallengeMethod:"S256", deviceName (≤64), deviceModel? (≤32) }` → 201 `{ code:"<orgId>.dac-<id>.<secret>", state, expiresInSeconds:300 }`. Single-use, 5-min, PKCE-bound code. 400 `bad_method`/`bad_challenge`/`bad_device_name` · per-account rate limit (10 burst / 1 per 60s). |
| POST | `/v1/auth/device/token` | **public** (code+verifier IS the credential) | `{ code, codeVerifier (43–128) }` → 200 `{ refreshToken:"<orgId>.dvt-<deviceSessionId>.<secret>", accessToken (15-min session JWS, `jti == deviceSessionId`), accessTtlSeconds:900, orgId, orgName, account:{ email, displayName, role }, device:{ id, name } }`. The code is **consumed even on failure** (a failed PKCE attempt burns it). 400 `invalid_code` (absent/expired/used/bad secret — one opaque code) / `pkce_mismatch` · 401 `account_inactive` · per-IP limit (10 burst / 1 per 6s). |
| POST | `/v1/auth/device/refresh` | **public** (refresh token IS the credential) | `{ refreshToken }` → 200 `{ refreshToken (ROTATED), accessToken, accessTtlSeconds:900 }`. Rotate-on-use; the superseded secret keeps working for a **60s race grace** (lost-response retry); presenting it **after** the grace ⇒ theft assumed ⇒ the whole device session is revoked (`refresh_reused`). Sliding expiry: every rotation re-arms **now+400d**. Scopes recomputed from the live role; a non-active account revokes the session. 401 `invalid_refresh`/`device_revoked`/`device_expired`/`refresh_reused`/`account_inactive` · per-IP limit (30 burst / 1 per 2s). |
| POST | `/v1/auth/device/daemon-token` | **Bearer device access JWS** (its `jti` must name a LIVE device session bound to the same user — a browser session or pasted service token cannot call this) | `{}` → 201 `{ id:"svc-…", token (service JWS, shown once), expiresAt (+30d), scopes }`. Mints the daemon's data-plane service token **as the human user** (daemon I/O runs under the user's own ACLs): label `daemon:<deviceName>`, scopes = `["fs:read","fs:write","fs:lock","snapshot:read"] ∩ deviceSession.scopes`, record carries `deviceSessionId`. A re-mint **soft-expires** the prior token for the same device (+10 min). NO admin role required. 401 `unauthorized`/`device_revoked`/`device_expired`/`account_inactive` · per-device limit (5 burst / 1 per 600s). |
| GET | `/v1/auth/devices` | session | → 200 `{ devices:[{ id, name, model, createdAt, lastSeenAt, expiresAt, revokedAt }] }`. Refresh hashes never leave the DO. |
| DELETE | `/v1/auth/devices/:id` | session+CSRF | → 204. Revokes the device session (reason `user_revoked`), **cascades** to its daemon service tokens, and invalidates the gate cache so the residual access JWS dies on the next request. 404 if not owned (opaque). |

Revocation: the device access JWS carries `jti == deviceSessionId`, so a revoked/expired device
session is rejected by the **existing** `isJtiRevoked` gate. Account offboarding revokes the
account's device sessions (and their daemon tokens) too.

**Passwords**

| Method | Path | Auth | Body → Success |
|---|---|---|---|
| POST | `/v1/auth/password/change` | session+CSRF | `{ currentPassword, newPassword }` → 204. 401 `bad_current_password`. **Revokes the account's other live sessions** (keeps the current one), so a changed password boots every other device. |
| POST | `/v1/auth/password/forgot` | public | `{ email }` → always **202** (no enumeration); emails a reset link if the account exists. |
| POST | `/v1/auth/password/reset` | public | `{ token, newPassword, orgId }` → 204; revokes the account's live sessions. 400/410 on bad/expired token. |
| POST | `/v1/auth/password/enroll-legacy` | public (single-use enrollment token) | `{ orgId, token, newPassword }` → 200 `{ ok:true }`. Completes password enrollment for a migrated legacy owner. |

**TOTP (RFC 6238)**

| Method | Path | Auth | Body → Success |
|---|---|---|---|
| POST | `/v1/auth/totp/enroll` | session+CSRF | — → 200 `{ secret, otpauthUri }` (unconfirmed). |
| POST | `/v1/auth/totp/confirm` | session+CSRF | `{ code }` → 200 `{ confirmed:true, recoveryCodes:[…10] }` (shown ONCE). 401 `bad_code`. |
| DELETE | `/v1/auth/totp` | session+CSRF **+ step-up** | `{ currentPassword }` → 204. **Removing a second factor requires a fresh password proof** (like change-password): 401 `reauth_required` if absent / no password credential, 401 `bad_current_password` if wrong. |

**WebAuthn / passkeys** (404 if `WEBAUTHN_RP_ID` unset — fail closed)

| Method | Path | Auth | Body → Success |
|---|---|---|---|
| POST | `/v1/auth/webauthn/register/options` | session+CSRF | — → 200 `PublicKeyCredentialCreationOptionsJSON` + `challengeId`. |
| POST | `/v1/auth/webauthn/register/verify` | session+CSRF | attestation `{ challengeId, response, label? }` → 201 `{ credentialId, label }`. |
| POST | `/v1/auth/webauthn/authenticate/options` | public | `{ email? }` (passwordless) **OR** `{ challengeId }` (a login-MFA `challengeId` from `/v1/auth/login`, for a passkey used as the **second factor** after a password) → 200 `PublicKeyCredentialRequestOptionsJSON` + `challengeId` (non-enumerating). In second-factor mode the login challenge is consumed here and the returned webauthn challenge is bound to the password-proven account. |
| POST | `/v1/auth/webauthn/authenticate/verify` | public | assertion `{ challengeId, response }` → 200 `{ userId, orgId, role, scopes, csrf }` + cookie. The asserting credential must belong to the challenge's bound account (defeats credential substitution); only this completes a passkey-second-factor login. |
| GET | `/v1/auth/webauthn/credentials` | session | → 200 `[{ id, credentialId, label, transports, createdAt, lastUsedAt }]`. |
| DELETE | `/v1/auth/webauthn/credentials/:id` | session+CSRF **+ step-up** | `{ currentPassword }` → 204 (404 if not owned). **Removing a passkey requires a fresh password proof**: 401 `reauth_required` if absent / no password credential, 401 `bad_current_password` if wrong. |

**Email verification**

| Method | Path | Auth | Body → Success |
|---|---|---|---|
| POST | `/v1/auth/verify-email/send` | session+CSRF | — → 202 (re)send the verification email. |
| POST | `/v1/auth/verify-email` | public | `{ token, orgId }` → 200 `{ verified:true }`. 400/410 on bad/expired token. **On success it upgrades the account's live sessions to full role scopes** (see the gate below). |

**Email verification.** A self-signed-up owner starts `emailVerified:false`.
Rather than a per-route 403, the gate is enforced by **reduced session scopes**: an unverified
account's session is minted with only `["fs:read","snapshot:read"]` (read-only). The user **stays
signed in** and can reach the "verify your email" UI, re-send the link (`/v1/auth/verify-email/send`),
read, and browse — but every **mutating / admin** route fails the normal scope gate (403) because
the session lacks `fs:write`/`fs:admin`/etc. This holds for password login, signup, and passkey
login alike. When the email is verified (`POST /v1/auth/verify-email`), the account's live sessions
are **re-scoped in place to full role scopes** — no re-login needed — and the next login mints full
scopes regardless. `GET /v1/auth/me` continues to report the real `emailVerified` + `scopes` so the
SPA can render the gated state.

### 5b. Service tokens (machine credentials) — `/v1/orgs/:org/service-tokens`

Owner/admin only. The minted credential is a normal `service` HS256 JWS (`jti == id`)
consumed unchanged by cloudfsd's token-file and the CLI `--token`.

| Method | Path | Auth | Body → Success |
|---|---|---|---|
| POST | `/v1/orgs/:org/service-tokens` | admin | `{ label, scopes, spaceId?, serviceAccountUserId?, expiresAt? }` → 201 `{ id, token, label, scopes, expiresAt }` — **`token` shown ONCE**. Creates a `service_account` OrgDO user if `serviceAccountUserId` is absent. |
| GET | `/v1/orgs/:org/service-tokens` | admin | → 200 `[ServiceToken-public]` (no secrets). |
| DELETE | `/v1/orgs/:org/service-tokens/:id` | admin | → 204. Revoke (adds the jti to the org's revocation set → the JWS 401s `revoked` on next call). |

### Namespace — `items`

| Method | Path | Scope | Body / Query | Success |
|---|---|---|---|---|
| GET | `/v1/filespaces/:fs/items?parent=&limit=&cursor=` | `fs:read` | query only | 200 `{ items: Item[], cursor: string\|null }` |
| GET | `/v1/filespaces/:fs/items/:id` | `fs:read` | — | 200 `Item` · 404 `no such item` |
| POST | `/v1/filespaces/:fs/items` | `fs:write` + ACL `create` on parent | `{ parent?="root", name, isDir?, size?, expectedVersion?, etag? }` | 201 `Item` (the server mints the opaque `id`) · 409 `{conflict,expected,actual}` · 400 `{error:"invalid_name"}` (empty / contains `/`,`\0` / `.` / `..`) |
| PATCH | `/v1/filespaces/:fs/items/:id` | `fs:write` + ACL `rename` (and `create` on the destination parent for a move) | `{ parent?, name? }` | 200 `Item` (the opaque `id` is **unchanged** — a move/rename is a single-row metadata update, so the file's encrypted blocks stay valid) · 404 `no such item` · 409 `{error:"name_collision"}` (a live sibling already has that name) · 409 `{locked,heldBy}` (item leased by another) · 400 `{error:"invalid_name"}` / `{error:"invalid_move"}` (moving a dir into its own subtree). |
| DELETE | `/v1/filespaces/:fs/items/:id?expectedVersion=` | `fs:write` + ACL `delete` | — | 200 `{ deleted: true }` · 200 `{deleted:false,reason}` on version mismatch |
| DELETE | `/v1/filespaces/:fs/items/:id?recursive=true` | `fs:write` + ACL `delete` | — | 200 `{ deleted: <count>, kind:"single"\|"bulk" }` — recursive subtree delete; tombstones the item + every live descendant and **rolls the deletion up into ONE live-activity event** (a `"large-delete"` rollup when the collapsed count ≥ 50; see `…/activity/live`). |
| GET | `/v1/filespaces/:fs/items/:id/access` | `fs:read` + ACL `read` | — | 200 `{ read:true, write:boolean }`; `write` is true only when `fs:write` scope and a current write ACL are both present. Missing/unreadable item → 404. |
| PATCH | `/v1/filespaces/:fs/items/:id/basic-info` | `fs:write` + ACL `write` | `{ expectedVersion, fence?, createdAt?, modifiedAt?, accessedAt?, changedAt?, fileAttributes? }` | 200 updated `Item`; metadata-only update with version and lease checks. |
| GET | `/v1/filespaces/:fs/items/:id/streams` | `fs:read` + ACL `read` | — | 200 `{ streams:[{name,size}] }` |
| GET / PUT / DELETE | `/v1/filespaces/:fs/items/:id/streams/:name` | `fs:read` or `fs:write` + ACL `read` or `write` | PUT sends encrypted stream bytes; optional `?size=` plaintext size and `?fence=` | GET returns `application/octet-stream`; PUT/DELETE return stream metadata. Manifest-backed streams use the manifest route. |
| GET / PUT | `/v1/filespaces/:fs/items/:id/streams/:name/manifest?offset=&length=` | `fs:read` or `fs:write` + ACL `read` or `write` | PUT sends a stream manifest delta | GET reads a bounded manifest range; PUT verifies referenced objects before publishing the stream manifest. |

Test and benchmark routes (still protected by scope and folder ACL):

| Method | Path | Scope / ACL | Body → Success |
|---|---|---|---|
| POST | `/v1/filespaces/:fs/items/_seed` | `fs:write` + ACL `create` on parent | `{ parent, prefix, count, isDir? }` → `{ created }` (bounded bulk seed) |
| GET | `/v1/filespaces/:fs/items/_count?parent=` | `fs:read` + ACL `read` on parent | `{ count }` (inaccessible parent returns 404) |

### Block map — `blocks` (large-file read/write path)

| Method | Path | Scope | Body | Success |
|---|---|---|---|---|
| GET | `/v1/filespaces/:fs/blocks/:itemId` | `fs:read` + ACL `read` | — | 200 `Block[]` (ordered by chunk,block) |
| PUT | `/v1/filespaces/:fs/blocks/:itemId` | `fs:write` + ACL `write` | `{ blocks: Block[], etag?, expectedVersion?, force?, fence? }` | 200 `Item` (size/contentVersion recomputed) |
| PATCH | `/v1/filespaces/:fs/blocks/:itemId` | `fs:write` + ACL `write` | block-manifest delta | 200 updated manifest; newly referenced objects are verified before publication. |
| GET | `/v1/filespaces/:fs/blocks/:itemId/range?after=&limit=&version=` | `fs:read` + ACL `read` | — | 200 paged manifest with item metadata and a continuation cursor; version mismatch → 409. |
| GET | `/v1/filespaces/:fs/blocks/:itemId/range?offset=&length=&contentVersion=` | `fs:read` + ACL `read` | — | 200 bounded extent of the manifest; see §9 for paging semantics. |
| POST | `/v1/filespaces/:fs/blocks/:itemId/verify` | `fs:write` + ACL `write` + upload provenance | `{ blocks: [{objectKey,blockHash,length}] }` (1–128 objects) | 200 `{verified:number}`; receipts only, no file publication |

`itemId` may also be passed as `?item=`. `objectKey`s must live under the space prefix.

Publication rechecks the target's write permission and every block's provenance in the same Durable Object turn. A folder-scoped writer may reference a currently readable committed/retained object, or a new object's server-issued PUT authorization bound to that principal and that target inode. Supplying a private object key in a manifest or a client-declared `itemId` is not ownership evidence. Unknown keys without an upload authorization, expired authorizations, and foreign/private/retired keys return 403 without modifying the manifest. Legacy administrators retain direct ingestion of genuinely unknown objects.

API v3 validates the entire manifest before mutation: unique ordered block coordinates, contiguous offsets, positive safe lengths, bounded identifiers, and one immutable object key per hash. Invalid manifests return 400 without changing the old image. Requests are limited to 16 MiB encoded JSON and 131,072 blocks. Production objects use a lowercase SHA-256 ciphertext hash as the final key component; metadata-only test fixtures explicitly bypass object verification.

Before publication, the gateway checks block provenance, then verifies newly referenced objects in batches of at most 128, with six concurrent bucket requests per batch. A stored SHA-256 checksum and ciphertext size must match; older objects without a stored checksum are streamed through SHA-256 once. Verification receipts are persisted against the storage endpoint/bucket, object identity and logical length. Already verified unchanged blocks do not incur another HEAD. The final transaction rechecks ACLs, leases, receipts and the expected version. Missing or unverifiable objects return retryable 503 and leave the current image unchanged. An exact retry of the immediately previous successful CAS returns the existing version without another mutation.

Clients may submit completed objects to the optional `POST …/verify` endpoint while later objects are uploading. It applies the same object-identity, item-access, upload-claim and storage-checksum checks, and charges the existing verification rate budget. Storage HEAD/GET work runs in the stateless gateway so independent requests do not share the metadata object's outbound connection budget. Only the gateway's own verified results enter the binding-only atomic receipt transaction; HTTP-supplied proof is never trusted. The response counts distinct verified submitted identities, including existing receipts. It does not change file size, contents or version and never replaces the final manifest commit. Unsupported or failed early verification can fall back to the ordinary commit path; a final commit still fails closed if any receipt is absent or invalid.


### Change feed — `changes`

| Method | Path | Scope | Success |
|---|---|---|---|
| GET | `/v1/filespaces/:fs/changes?since=&limit=` | `fs:read` | 200 `{ anchor, items: Item[], cursor: number\|null }` |
| GET (WebSocket upgrade) | `/v1/filespaces/:fs/changes/subscribe` | `fs:read` + filespace read access | Sends invalidation hints; clients fetch missed changes from the paged change feed. |

### Locks / leases — `locks`

Lease ownership combines the authenticated principal (`sub`) with the optional
`X-CloudFS-Client-ID` UUID header. Each daemon uses one fresh UUID throughout its
session, so two Macs signed into the same account are independent writers.
Legacy callers without the header retain principal-only ownership. Request-body
or query-string owner overrides are ignored. TTL must be positive and is clamped
to 60 seconds; invalid UUIDs, TTLs and fences return 400.

| Method | Path | Scope | Body / Query | Success |
|---|---|---|---|---|
| POST | `/v1/filespaces/:fs/locks` | `fs:lock` + ACL `write` | `{ path, ttlMs?, mode?="exclusive"\|"shared", purpose?="advisory"\|"publication" }` | 200 `LockResult` (`granted`, `mode`, `purpose`, `fence`, `expiresAt`) |
| POST (publication metadata fast path) | `/v1/filespaces/:fs/locks` | `fs:read` + `fs:write` + `fs:lock`; ACL `read` + `write` | `{ path, ttlMs?, purpose:"publication", mode?="exclusive", includeItem:true }` | 200 `LockResult & { item: Item }` on grant; conflict result has no item |
| POST (renew) | `/v1/filespaces/:fs/locks` | `fs:lock` + ACL `write` | `{ path, renew:true, fence, ttlMs? }` | 200 `LockResult` with original purpose · `granted:false,reason:"fence-stale"` |
| GET | `/v1/filespaces/:fs/locks?path=` | `fs:read` | — | 200 `LockResult` (status) |
| DELETE | `/v1/filespaces/:fs/locks?path=&fence=` | `fs:lock` | — | 200 `{ released: true }` · `{released:false,reason}` if not owner |

`LockResult.reason ∈ { held-by-other, fence-stale, not-found, purpose-mismatch }`. A denied acquire returns
`granted:false` with `heldBy` + `expiresAt`. The `fence` is a monotonic token the writer
presents at manifest commit and named-stream PUT/DELETE (`?fence=N`) so an expired
lease cannot overwrite a newer writer. Release should include the matching fence,
preventing delayed close requests from releasing a newer lease. Other clients can
see the owner/expiry but never the fence. Metadata delete/rename/replace and named
streams all enforce the same client ownership.

`includeItem:true` is an opt-in publication-only fast path. It is rejected for shared,
advisory, and renewal requests. On grant, the response adds current, stream-enriched
`Item` metadata captured in the same synchronous Durable Object turn as the lease.
Denied and conflicting responses never contain item metadata. DOS read-only attributes
are returned unchanged for the client to enforce. The ordinary response shape is
unchanged when the flag is absent or false. This path requires the same read/write/lock
scopes and read/write ACL checks as writable-open authorization and metadata refresh;
the filespace DO rechecks current ACLs before returning any item fields. It does not
require an SMB open handle, preserving crash-recovery and other openless publishers.

Whole-inode leases default to `advisory`. `publication` identifies an exclusive
manifest-writer lease and may be acquired without an SMB open for crash replay or
other upload paths. Existing leases migrate as `advisory`; same-owner reacquisition
cannot change purpose, and renewal preserves the stored purpose. A foreign
publication lease may remain on an inode during namespace replacement only while
its holder has an active writable open that shares delete. Missing or expired
opens, explicit advisory leases, and shared leases continue to block replacement.

### Open-file lifetime — `open-handles`

`POST /v1/filespaces/:fs/open-handles` requires `fs:read`, a valid
`X-CloudFS-Client-ID` UUID, and the authenticated principal. Handle ownership is
the combination of that principal and client ID; a UUID `handleId` alone is not
authority. Access and sharing masks use read=1, write=2, delete=4. Write or
delete access also requires `fs:write` and the corresponding current inode ACL.

- `action:"acquire"`: `{id,handleId,accessMask,shareMask,ttlMs?}` retains the inode
  and enforces both directions of share compatibility. TTL defaults to 90 seconds
  and accepts 1–120 seconds. Returns `{granted,expiresAt?,reason?}`.
- `action:"renew"`: `{handleId,ttlMs?}` rechecks current ACLs. `renew-batch` uses
  `handles` (1–128 unique UUIDs) and returns individual results in `handles`.
- `action:"close"`: `{handleId}` releases the exact owner's handle, including
  after ACL revocation. It is unthrottled; clients can treat `not_found` as already
  closed. Unlinked payload remains retained until its final open expires or closes.

An acquire may include `stream:{name,required}`. After ACL and share admission,
the same transaction checks stream existence. Successful grants add
`stream:{exists,size}`. A required miss returns `stream_not_found` without leaving
the exact handle registered, including on a same-handle retry. This is a size
snapshot, not a promise to pin that stream's bytes. A missing response field means
an older gateway; clients must use their ordinary stream-list and close path.
Writable stream dispositions still require a fresh existence check under their
publication lease.

`action:"directory-snapshot"` accepts the acquire fields with read-only access
(0 or 1). One transaction authorizes the directory, checks share compatibility,
captures its metadata and ACL-filtered children, and closes the temporary open.
Success is `{granted:true,directory,items}`; no handle remains. A scan exceeding
500 children returns `snapshot_too_large` without a handle, so clients can use
normal paged enumeration. A reused persistent handle is rejected and preserved.
This supports self-contained metadata probes, not persistent directory handles.
Older gateways reject the unknown action with `400 invalid_open_handle`.

### Handle-owned byte ranges — `range-locks`

`POST /v1/filespaces/:fs/range-locks` accepts `{ action, path, handle, ... }`. The authenticated client identity is bound to `handle`; callers cannot supply another owner. Handle IDs are 1–160 ASCII letters, digits, `.`, `_`, `:`, or `-`. All requests require `fs:read`; exclusive acquisitions/renewals additionally require `fs:lock` and ACL `write`. Shared ranges require ACL `read`. Release remains possible after folder access is revoked so clients can clean up. Acquisition is charged per requested range to the existing mutation budget; renewal uses one mutation token. Read admission uses the separate higher read/presign budget. Release bypasses throttling.

- `action:"acquire"`: `{ ranges:[{offset,length,exclusive}], fence?, ttlMs? }` returns `LockResult`. Offsets and lengths are canonical decimal UInt64 strings; overflow is rejected. Maximum 64 ranges per request, 256 held ranges per handle, 256 handles and 4096 total ranges per inode. A supplied fence must match the existing lease; TTL is capped at 60 seconds.
- `action:"renew"`: `{ fence, ttlMs? }` renews the same handle/fence after current ACL checks.
- `action:"release"`: `{ fence, ranges? }` releases exact ranges atomically, or all ranges when omitted. Stale fences cannot release a replacement lease.
- `action:"check"`: `{ range:{offset,length,exclusive}, fence? }` checks a READ (`exclusive:false`) or WRITE (`true`) against every other handle. Returns `{allowed,reason?,heldBy?}`; a valid broad READ authority additionally returns `{permitTtlMs:1000,permitFence}`. The server blocks other handles' exclusive range grants until the permit expires. Clients must use a monotonic deadline from request start with a safety margin; this is positive authority, not a cache of missing locks.
- `action:"release-read"`: `{ fence:permitFence }` releases only that read-permit generation.

Shared ranges coexist, incompatible overlaps fail, and disjoint ranges coexist. Whole-inode writer leases remain conservative: another client's range blocks writable open/publication. Neither range fences nor legacy shared-mode fences authorize publication. Read permits allow ordinary writer acquisition, but a competing explicit exclusive LOCK may need to retry for up to 1 second. A failed exclusive acquisition suppresses fresh permits for 1.5 seconds to prevent renewal starvation.

### Multipart / resumable uploads — `uploads`

| Method | Path | Scope | Body | Success |
|---|---|---|---|---|
| POST | `/v1/filespaces/:fs/uploads` | `fs:write` + ACL `write` on item | `{ uploadId, itemId, key, totalSize, partSize }` | 201 `UploadSession` |
| GET | `/v1/filespaces/:fs/uploads/:uploadId` | `fs:read` | — | 200 `{ session: UploadSession\|null, missing: number[] }` |
| PUT | `/v1/filespaces/:fs/uploads/:uploadId/parts` | `fs:write` | `{ partNumber, etag, size, checksum? }` | 200 `{ recorded: true }` (idempotent) |
| POST | `/v1/filespaces/:fs/uploads/:uploadId/complete` | `fs:write` | `{ etag }` | 409 `{ error: "legacy_multipart_unverified" }` in strict mode |
| DELETE | `/v1/filespaces/:fs/uploads/:uploadId` | `fs:write` | — | 200 `{ aborted: true }` |

Every follow-up checks the session inode's current read/write ACL. Repeating `begin` with the same identity preserves progress; reusing an ID for another item/key/geometry or restarting an aborted upload returns 409. Part numbers and exact expected part lengths are checked before recording progress. Under the explicit metadata-fixture bypass only, `GET …/uploads/:id` reports missing parts and completion retries are idempotent.

These multipart endpoints coordinate reported parts; they do not create or complete an S3 multipart upload and do not prove bucket durability. Strict production mode rejects their completion without publishing a success activity event. The desktop block path uses the verified immutable PUT/manifest protocol above.

### Snapshots — `snapshots`

| Method | Path | Scope | Body / Query | Success |
|---|---|---|---|---|
| GET | `/v1/filespaces/:fs/snapshots` | `snapshot:read` | — | 200 `Snapshot[]` |
| POST | `/v1/filespaces/:fs/snapshots` | `snapshot:write` | `{ id?, label?, scope?, tier?, immutableUntil? }` | 201 `Snapshot` (freezes the as-of content of `scope`) |
| GET | `/v1/filespaces/:fs/snapshots/:id/dir?parent=` | `snapshot:read` | — | 200 `Item[]` (directory **as-of** the snapshot) — **lazy, per-directory** |
| POST | `/v1/filespaces/:fs/snapshots/:id/restore` | `snapshot:read` + ACL **EDIT** on `path` | `{ path, recursive?, mode? }` | 200 `RestoreResult` · 403 when nothing is authorized · 409 when all targets are locked · 404 (unknown snapshot/path) |

**Manual snapshot create.** `id` is **optional** — omit it and the DO mints a
server-side id (`manual-<ts>-<rnd>`) so a client can request a snapshot without inventing a
unique id; an explicit `id` is still honored (scheduled/auto snapshots pass one). The create
is a **real** point-in-time freeze: it copies the as-of metadata + block manifests of `scope`
(no media bytes) so a later restore can reconstruct old content even after in-place edits.

**Lazy per-directory browse.** `GET …/snapshots/:id/dir?parent=<inodeId>` returns only
the children of ONE directory (root when `parent` is omitted), served from the frozen
point-in-time. The client expands a folder tree by calling it once per expanded node — never
materializing the whole subtree. It reflects the as-of `size`/`contentVersion`, not the
current (possibly edited) live row.

**Restore semantics.** Restores `path` (a file, or — with `recursive:true` —
a whole subtree) to its state **as of** the snapshot, using the frozen point-in-time
manifest. **Non-destructive:** each restored item is re-written as a **new current version**
(bumped `version`, new `updatedSeq` → appears in the change feed); prior/current state stays
in history (other snapshots + the feed), and items that exist now but **not** in the snapshot
are **never deleted** (reported in `newerThanSnapshot`). Items deleted since the snapshot are
**re-created**. Respects locks: a target **exclusively leased by another owner** is skipped
and surfaced as a `conflict` (never clobbered) — a 409 is returned only if *nothing* could be
restored because every target was locked. A lock held by the requester does not block.

`RestoreResult { snapshotId, restored: string[], recreated: string[], conflicts: [{id, heldBy}], newerThanSnapshot: string[] }`.

> Use the `/v1/filespaces/:fs/...` form above. (There is no `/v1/orgs/:org/spaces/:fs/snapshots/...`
> org-scoped alias — the org route has no snapshot sub-routing and would 404.)

### Snapshot schedules (GFS retention) — `schedules`

| Method | Path | Scope | Body | Success |
|---|---|---|---|---|
| POST | `/v1/filespaces/:fs/schedules` | `fs:admin` | `{ id, scope?, tier, intervalMs, retain }` | 201 `{ ok: true }` |
| GET | `/v1/filespaces/:fs/schedules` | `fs:admin` (owner/admin) | — | 200 `{ schedules: [{ id, scope, tier, intervalMs, retain, enabled, nextRunAt, lastRunAt }] }` |
| PATCH | `/v1/filespaces/:fs/schedules/:id` | `fs:admin` (owner/admin) | `{ enabled?: boolean, retain?: integer 0..10000 }` (at least one) | 200 `{ ok: true }` · 400 `invalid_schedule` · 404 `no such schedule` (unknown id on `retain`) |

**Default schedules.** Creating a *new* filespace (`POST /v1/orgs/:org/spaces`, not an upsert/revive of an
existing id) seeds two enabled schedules scoped to `root`: `default-daily` (tier `daily`, every 24 h,
`retain` 7) and `default-weekly` (tier `weekly`, every 7 d, `retain` 4). Seeding is best-effort and
idempotent (`INSERT OR IGNORE`), so admin edits are never overwritten. Existing filespaces are not backfilled.

Schedules run **server-side** via the DO alarm — they fire even with every client offline.

### Folder administration — `access-management` and `grants`

| Method | Path | Authorization | Success |
|---|---|---|---|
| GET | `/v1/filespaces/:fs/access-management` | Human session `fs:read`, or service token `fs:admin`; live folder ACL | `{ canManageAccess, canDelegateAdmin, canManageWorkspace, roots, grants, members, groups }` |
| GET | `/v1/filespaces/:fs/access-management?parent=&cursor=` | Same, plus `manage_acl` on parent | `{ items, cursor }`, only manageable live child folders |
| GET | `/v1/filespaces/:fs/grants?inodeId=` | Same | `{ grants }`, filtered to manageable live inodes |
| POST | `/v1/filespaces/:fs/grants` | Human session `fs:write`, or service token `fs:admin`; live `manage_acl` | 201 `{ id }` |
| DELETE | `/v1/filespaces/:fs/grants?inodeId=&principalType=&principalId=` | Same as POST | 200 `{ revoked }` |

POST accepts `{ inodeId, principalType, principalId, level:"read"|"edit"|"admin", mountAsRoot?, expiresAt? }`. Only existing same-workspace principals may be targeted, and new grants require an active account. Setting a tuple replaces its previous level, so lowering edit to read removes the former edit grant. The server supplies grantor and delegation lineage; client fields cannot forge them. Every grant write rechecks current namespace/ACL authority synchronously inside FilespaceDO after the gateway resolves the actor's current workspace role and groups without the data-plane cache.

Owner, Admin, and the existing workspace-wide Filespace Admin role may appoint a **Folder admin** on a chosen folder. This is the ACL `admin` level, not a workspace role. A delegated standard member can issue read/edit grants only within that authority, to existing standard members/service accounts or existing groups. They cannot appoint another folder admin, change workspace roles/accounts/group membership, alter their own authority, change another original administrator's authority, or modify grants issued directly by a workspace administrator. The native editor follows explicit capability flags and per-row `canModify`; safe root-relative folder paths never disclose private ancestors. The ordinary organization directory retains its existing authenticated-member read policy.

A delegated grant is bound to an original admin grant and its folder inode. It stops authorizing access when that source is revoked, expires, is deleted/demoted, receives a weaker workspace-issued descendant override, or when the granted child is moved outside its authority. The override walk uses the exact source user/group with bounded cycle protection, never an issuer's unrelated groups. Expiry cannot exceed the source. Recreating a deleted path or reissuing an expired/revoked authority does not revive earlier grants. Adjusting an active admin grant's mount setting preserves its authority identity.

Suspending or deprovisioning a directly delegated account first disables new admin grants for both user/service-account aliases, then retires its original admin grants across registered filespaces, including soft-deleted spaces. A request admitted before suspension cannot recreate authority after retirement. Status changes for the same account serialize across this work; retirement failures propagate rather than reporting completed deactivation. Explicit reactivation removes the creation barrier but requires new delegation and does not revive old source IDs or previously issued grants. Removing or suspending one member of an administering group stops that person's ability to manage access; previously issued grants belong to the group's shared authority and remain until that authority is revoked. Deleting the group retires its grants and authority in every registered filespace, with durable per-filespace principal tombstones rejecting late writes for that deleted group. Ordinary token scopes are not broadened; daemon tokens without explicit `fs:admin` cannot manage permissions.

### Audit log — `audit` (DO ring → R2 archive)

| Method | Path | Scope | Query | Success |
|---|---|---|---|---|
| GET | `/v1/filespaces/:fs/audit?action=&decision=&actor=&limit=&since=&until=&cursor=` | `audit:read` + current workspace owner/admin | filters (all optional) | 200 `AuditRecord[]` |

Append-only, **tamper-evident hash chain** (`hash = SHA-256(prevHash ‖ canonicalJSON(record))`).
Allow *and* deny decisions are logged. Per-(org,space) chain; `seq` monotonic, `prevHash`
links the prior `hash` so any insert/edit/reorder is detectable.

**Ordering + page-back (`cursor`).** The reader returns rows **NEWEST-FIRST** (`seq`
descending) so the first page is the most recent activity. `limit` keeps the newest matching
rows of the window. `cursor` is an **EXCLUSIVE upper bound on `seq`** for paging back ("Load
older"): with `?cursor=<seq>` the reader returns only rows with `seq < cursor`, still
newest-first. The client's continuation cursor = the **lowest `seq` of the previous FULL
page**; a short/empty page signals end-of-history (no more older rows). Successive pages are
therefore strictly older and non-overlapping, and the loop terminates. `cursor` is a `seq`
value (distinct from `since`/`until`, which are ms-epoch `ts` bounds). `verifyChain` consumers
must re-sort ascending first (the chain verifier requires ascending `seq`).

The FilespaceDO keeps only a recent **ring buffer** of
audit events in its SQLite — **min(last 24h, last 2000 events)**, whichever is *smaller*.
Older sealed records are archived to **R2** as append-style NDJSON segments, partitioned by
filespace + UTC day:

```
audit/{filespaceId}/{YYYY-MM-DD}.ndjson   // one sealed segment per filespace-day
audit/{filespaceId}/index.json            // segment manifest (chain continuity)
```

`{filespaceId}` is the effective DO key `<org>::<fs>`. The reader is **transparent**: it
reads the DO ring first (newest), then **falls back to the R2 segments** for ranges older
than the ring (the optional appended `since`/`until` ms-epoch params + `cursor` seq bound page
into R2 history). **Page-back crosses the ring→R2 boundary seamlessly**: when the `cursor`
descends below `ringStartsAtSeq`, the reader continues reading older rows from the R2
day-segments, still newest-first and still honoring the exclusive-`seq` cursor. The
`AuditRecord` shape is unchanged.

**Chain continuity across the DO→R2 boundary.** `index.json` records, per segment,
`firstPrevHash` (the prevHash of the segment's first record) and `lastHash` (the hash of its
last record), plus `firstSeq`/`lastSeq`/`count`. The invariant
`segments[i].firstPrevHash == segments[i-1].lastHash` (and the DO ring's earliest record's
`prevHash == segments[last].lastHash`, or `GENESIS_HASH` when no segments yet) means a
verifier can **concatenate the R2 segments (ascending seq) then the DO ring and run the
existing `verifyChain` unchanged** — the chain is unbroken. Rows are deleted from the DO ring
**only after** a durable R2 flush; `archived_through_seq` (DO `meta`) is the high-water mark.
The trim runs on the DO alarm (hourly) and is best-effort (an R2 hiccup just leaves the ring
larger until the next tick). When `AUDIT_BUCKET` is unbound (local dev), archival is a no-op
and the full chain stays in the DO.

### Live activity feed — `activity/live`

| Method | Path | Scope | Success |
|---|---|---|---|
| GET | `/v1/filespaces/:fs/activity/live` | `audit:read` + current workspace owner/admin | 200 `LiveActivity` |

The **ephemeral** live feed (distinct from the audit history): in-progress transfers +
rolled-up bulk ops, sourced from **DO hot state** (lost on hibernation, rebuilt as ops flow).
`transfers[]` are in-flight uploads/downloads (added on upload-begin, updated on progress,
cleared on complete/abort). `events[]` is a short rolling tail of recent activity, where
`kind:"single"` is an ordinary op and `kind:"bulk"` is a collapsed bulk op (`op:"large-delete"`,
`count` = items collapsed) emitted when a recursive delete touches ≥ 50 items — so an N-file
delete shows as ONE line, not N. The per-item audit records still chain normally; this feed
is purely for the live UI.

### Presigned URL minting — `presign` (THE enforcement gate)

| Method | Path | Scope | Body | Success |
|---|---|---|---|---|
| POST | `/v1/filespaces/:fs/presign` | `fs:read` (GET/HEAD) or `fs:write` (PUT) + ACL | `{ key, method?="GET", expiresIn?, itemId?, contentLength? }` | 200 `{ url, expiresIn, contentLength?, headers?, verificationUrl? }` |
| POST | `/v1/filespaces/:fs/presign/batch` | `fs:read` for any GET/HEAD, `fs:write` for any PUT + per-key ACL | `{ keys: [{ key, method?, itemId? }], expiresIn? }` (≤256 keys) | 200 `{ urls: [{ key, url?, headers?, verificationUrl?, error? }], expiresIn }` |

Enforcement order before any URL is signed: **scope → method allow-list (`GET`/`HEAD`/`PUT`
only, else 405) → rate-limit (per-space DO counter; 429) → key-prefix confinement (`key`
must start `blocks/<org>::<fs>/`, no `..`, else 403) → per-folder ACL (`read` for GET/HEAD,
`write` for PUT) → server-side TTL clamp to `[60, 900]` seconds (client `expiresIn` is ignored
beyond this) → mint → audit.**

**PUT behavior.** On a PUT mint:
- `contentLength` (optional) is **signed into the URL** (`X-Amz-SignedHeaders` includes
  `content-length`), so the bucket rejects an upload of any other size — a client cannot mint a
  URL and then stream an arbitrarily large object. It must be an integer in `[0, 5 GiB]`, else 400
  `invalid_content_length`. Omitting it leaves the PUT unpinned (back-compat).
- `itemId` (optional) lets the client **declare which namespace item** a not-yet-committed block
  belongs to. The per-folder ACL then runs against that inode at mint time (a content-addressed
  block key alone has no owning inode until its manifest commit binds it). A PUT to a key with no
  owning inode requires a declared writable `itemId` for folder-scoped users (single
  and batch routes); omission returns `item_required`. Legacy owner/admin clients
  may upload unowned objects, audited with `unownedPut`.
- The gateway records new PUT authorization against the authenticated principal and declared inode. It remains usable for a manifest commit for seven days; a later retry must renew it through presign. Expiry does not transfer the object's ownership to another user. **Same-inode takeover:** a claim declared for a concrete inode is shared by every principal with write access on that same inode: a co-writer's presign for the same key succeeds (renewing the claim) and either claimant may commit it once the object is verified. This cannot substitute bytes (the key is the ciphertext hash, PUTs are signed with the SHA-256 header and `If-None-Match: *`, receipts are immutable). A claim declared for a different inode, or an inode-less admin claim, is still refused to other principals (`forbidden`). These compact records remain until publication or filespace purge, because uncommitted bucket bytes may still exist.
- API v3 PUT clients must send every returned `headers` value. All PUTs sign `If-None-Match: *`; content-addressed keys also sign `x-amz-checksum-sha256`. The bucket rejects incorrect bytes and refuses any replacement of an existing key. On HTTP 412, the client must read `verificationUrl` and verify exact ciphertext size and SHA-256 against its intended body before treating the upload as an identical retry. A bare 412 is never success.
- Existing current **and historical** keys retain their owning inode checks for PUT. A canonical SHA-256 key may be retried using the immutable upload contract. Known legacy keys without that identity cannot receive a new PUT URL. A client cannot overwrite private history by declaring a different writable inode. A known retired object is not a new upload.

**Encrypted block validation.** Before issuing an upload receipt or publishing a manifest, the gateway verifies the stored SHA-256, byte bounds, and CFB2/CFB3 framing. The nine-byte public prefix must declare supported flags and the same plaintext length as the manifest; uncompressed objects must contain exactly that length plus 69 envelope bytes. Provider-checksummed objects need only a conditional nine-byte range read; checksumless objects are streamed and hashed. Hash-valid plain bytes are refused with `object_verification_failed`, leaving the existing manifest unchanged. Receipts issued before this framing check are reverified on future publication. AEAD authentication and plaintext integrity remain client responsibilities; the gateway does not decrypt uploaded blocks.

**Recovery reads.** GET/HEAD resolve server-recorded ownership across the current manifest and retained previous committed versions, then check the owning live inode's **current** ACL. Any readable owner suffices for a deduplicated key. Both single and batch routes apply this rule; a client-supplied read `itemId` never grants authority. Moves, revocations, grant expiry, and deletion take effect on the next mint. Already-issued object-store URLs keep their authority until their signed TTL expires.

**Retention policy.** Replacing a manifest retains one reference per unique inode/object pair for the live inode's lifetime, without a timer or version-count cutoff. GC excludes those references even when no live/snapshot refcount remains. Explicit inode/subtree deletion releases its recovery references; snapshot references remain independent. Same-name recreation uses a new inode and does not inherit old data. A persistent object-key catalog prevents deleted objects from being reclaimed as unknown uploads. There is no automatic recovery-history pruning or user-facing history browser: old payload storage grows with unique changed blocks of live files, and catalog metadata grows with unique object keys. Operators must account for this retention; automatic pruning requires future coordination with outstanding client journals. See [retained-block recovery](HISTORICAL-RECOVERY.md).

`POST …/presign/batch` mints up to **256** URLs in one request so a
large Finder copy or a multi-block scrub isn't N round-trips. It charges the rate bucket **cost =
#keys** in a single DO check and resolves the space's storage descriptor + managed credentials
**once** for the whole batch. Each key still runs its own per-folder ACL; per-key failures are
reported inline (`{ key, error }`) rather than failing the whole batch. Namespace and
ACL checks run together in one DO call. Storage credentials are resolved once per batch and signatures share a request-local signing-key cache. The daemon coalesces read presigns into batches.

**Throughput tuning (`RL_CONFIGS`).** The `presign` and `mutation` token buckets default to
`{capacity, refillPerSec}` of `{8192, 2048}` and `{300, 50}` respectively (per-principal, per-filespace counters),
overridable via `RL_PRESIGN_CAPACITY`/`RL_PRESIGN_REFILL`/`RL_MUTATION_CAPACITY`/`RL_MUTATION_REFILL`.
Each presign (or batch key) costs ONE presign token. A newly verified object at manifest commit costs one additional token; persisted receipts avoid repeat charges for unchanged objects. Sustained cache-miss read throughput is
therefore `refillPerSec × blockSize`:

The default allows 2,048 signed 1 MiB blocks per second. This is an admission
ceiling, **not a throughput guarantee**: network, storage, CPU and filesystem
performance still determine transfer speed. The daemon honors `Retry-After` per
block without restarting already successful transfers.

Raise `RL_PRESIGN_REFILL` for a high-bitrate scrubbing workload (4K/8K ProRes); raise
`RL_MUTATION_REFILL` for bulk Finder copies (each item create/commit is one mutation token —
50/s clears a 1,000-file copy in ~20s).

### Filespace master-key delivery — `key`

Filespace content is encrypted **client-side** by `cloudfsd` under one 32-byte master key per
filespace. The key is generated by the Worker at filespace creation and stored **encrypted at
rest** in the OrgDO under the deployment `STORAGE_ENC_KEY` — the SAME AES-256-GCM envelope
pattern §5c uses for BYO S3 secrets (`filespace-keys.ts`). It is **never** returned by
`POST/PATCH/GET …/spaces` or any listing — only by this authenticated delivery route.

| Method | Path | Scope | Success |
|---|---|---|---|
| GET | `/v1/filespaces/:fs/key` | `fs:read` + ACL (see below) | 200 `FilespaceKeyEnvelope` |

**Authorization.** The caller needs `fs:read` and an effective read grant somewhere in the
filespace; a live subfolder-only grant qualifies. This works over the same channel the
data plane already uses, including a device-minted daemon token whose scope ceiling includes
`fs:read` — `cloudfsd`
authenticates with the same bearer it uses for presign/items/etc. Denied → 403 `{error:
"forbidden", reason}` (ACL/scope). A filespace that predates this feature and hasn't been
migrated yet (see the import route, §5c) → 404 `{error:"no_master_key"}` — distinct from a
403, since the caller IS authorized, there's just nothing to serve yet.

**Response — `FilespaceKeyEnvelope` (an OPAQUE, forward-compatible wrapped-key blob, never a
bare key):**

```jsonc
{ "keyId": "3fa2b91c7d8e0a41", "format": "plain-v1", "material": "<base64, 32 bytes>" }
```

- `keyId` — stable, non-secret identifier (a SHA-256 prefix of the key; never reversible to the
  key itself). The handle a future rotation flow would reference.
- `format` — a **closed-but-extensible** tag the client MUST switch on and reject if unknown.
  `"plain-v1"` is server-decrypted and handed over TLS as raw key bytes (`material`). A future
  zero-knowledge mode adds a NEW `format` (e.g. `"device-wrapped-v1"`, wrapped per-device with an
  enrolled device keypair) **without breaking this envelope shape** — clients that don't
  understand it must fail loudly, never silently treat unknown bytes as a raw key.
- `material` — present for `"plain-v1"` only: base64, exactly 32 raw AES-256 key bytes.

### 5c′. Filespace master-key IMPORT/migration (owner/admin; org-plane)

For a filespace that **predates** the key service — its data was encrypted under an
operator-provisioned key (`key.hex` file or Keychain item `com.cloudfs.masterkey`) with no
server-held copy — this uploads that EXACT key into the server store so a fresh device's
`cloudfsd` can fetch it too (§5, `key`, above). Owner/admin only (deployment-admin surface, like
§5c's storage-credentials, not a data-plane op).

| Method | Path | Auth | Body → Success |
|---|---|---|---|
| POST | `/v1/orgs/:org/spaces/:id/key/import` | owner/admin | `{ material, replace? }` → **201** (first import) or **200** (`replace:true` over an existing key) `{ keyId, replaced, warning? }` |

- `material` — base64, **exactly 32 bytes**, else 400 `bad_key_length` (wrong length) or 400
  `invalid_base64`.
- No existing server-held key for this space → 201, `replaced:false`, no `warning`.
- An existing key AND `replace` is not `true` → **409** `{error:"key_exists", reason}` — the
  route never silently clobbers a key that might already be in active use.
- An existing key AND `replace:true` → 200, `replaced:true`, plus a `warning` string reminding
  the caller that replacing the key makes any content encrypted under the OLD key unreadable
  unless the uploaded material is that exact same key.
- Unknown `:id` → 404. Non-admin caller → 403.
- 500 `storage_enc_key_unconfigured` if `STORAGE_ENC_KEY` is unset (fail closed, same as §5c).

### Org / multi-user routes (mounted, owned by other modules)

These are tenant-scoped (`assertTenant(principal, :org)`) and dispatched to the modules
listed below. This table summarizes the mounted routes; consult the named backend modules
for implementation details.

| Path prefix | Handler module |
|---|---|
| `/v1/orgs/:org` | `org-do.ts` (org rename; owner/admin — see below) |
| `/v1/orgs/:org/users[/…]`, `/groups[/…]` | `users.ts` (read and write: owner/admin; delegated folder administrators use `/access-management`). **Offboarding** (`PATCH {status:"suspended"\|"deprovisioned"}` or `DELETE` → deprovision) propagates into the AuthDO: the credential account's status is flipped, **all its browser sessions + service tokens are revoked**, and on deprovision its global email claim is released. The block bites at both the login path AND every live request (the suspended/deprovisioned account is rejected immediately, not after its ≤15-min session JWS expires). |
| `/v1/orgs/:org/legacy-account` | `legacy-account.ts` (POST; active owner session token only; upgrades the existing owner's account without changing its ACL identity). |
| `/v1/orgs/:org/spaces[/:id]` | `org-do.ts` (filespace registry; create admin · PATCH admin/space_admin — see below) |
| `/v1/orgs/:org/storage-credentials[/:id]`, `/storage/test` | `storage-credentials.ts` (owner/admin; UI-managed encrypted creds + conn-test — §5c) |
| `/v1/orgs/:org/email-config[/test]` | `email-config.ts` (owner/admin; UI-managed encrypted per-org email provider + test-send — §8) |
| `/v1/orgs/:org/auth-config[/validate]` | `auth-config.ts` (owner/admin; UI-managed encrypted **deployment** auth provider: built-in vs. external OIDC IdP — §8d) |
| `/v1/orgs/:org/doctor` | `index.ts` (GET; owner/admin deployment readiness report) |
| `/v1/orgs/:org/invites[/…]` | `invites.ts` (admin; `redeem` is public — §5) |
| `/v1/orgs/:org/shares[/…]`, `/links` | `sharing.ts` (admin; `resolve` is public — §5) |

**`GET /v1/orgs/:org/spaces` — access-scoped list (any member).**
- Owner / admin / space_admin: every live filespace with the full registry row (including the
  storage descriptor: `storageEndpoint`, `storageBucket`, `storageRegion`, `storageForcePathStyle`,
  `storageCredentialRef`, `bucketProvider`, `bucketName`, `keyPrefix`).
- Any other member (`standard`): only filespaces where it holds an effective live grant (direct or
  via a group, any level, unexpired, on a non-deleted folder). Entries are reduced to
  `{ id, orgId, name, createdAt, role, usedBytes? }` — **no storage descriptor or credential
  reference**. Fails closed if the per-space check is unavailable.
- Added fields on every entry: `role` — the caller's effective role for that space:
  `owner | admin | space_admin` (org role) or, for a standard member, `folder_admin` (holds an
  effective admin-level grant) / `standard`; `usedBytes` — logical bytes of live (non-deleted) files in the
  filespace (`SUM(items.size)`), one DO RPC per space. To bound fan-out, `usedBytes` is computed for at most the
  first 50 spaces (ordered by name); later entries omit the field. `usedBytes` is only returned to org
  owner/admin/space_admin and to members with read access to the whole filespace (root); a member scoped to
  folders never learns the filespace-wide total. **Cost:** it is a full `SUM(size)` scan of the filespace's
  items table on every list call, run only for callers who receive the field (candidate for a maintained counter).
- **Degradation flags (response headers; the body stays a plain array):** for a non-admin member the list needs one
  Durable Object access check per space, capped at the first 200 spaces. `X-CloudFS-Spaces-Truncated: true` means
  the cap was hit and later spaces were not checked (so they are omitted). `X-CloudFS-Spaces-Partial: true` means at
  least one space's check failed (DO error) and that space was omitted. Absent headers mean the list is complete. The Mac app reads `usedBytes` and `role` from this response.

**Org + filespace mutation (owned by `org-do.ts`):**

| Method | Path | Auth | Body → Success |
|---|---|---|---|
| GET | `/v1/orgs/:org` | session/bearer | → 200 `{ orgId, name, slug }`. `name` is the display name (null until set); `slug` is the org id. |
| PATCH | `/v1/orgs/:org` | owner/admin | `{ name }` → 200 `{ orgId, name, slug }`. Renames the org's display name (the slug == orgId is immutable). 400 `invalid_name`; 403 if not owner/admin. |
| POST | `/v1/orgs/:org/spaces` | admin | `{ spaceId, name, bucketProvider, bucketName, keyPrefix, storage*? }` → 201 `SpaceRegistration`. Create (upsert on `spaceId`). Also generates and seals a fresh filespace **master key** the first time a given `spaceId` is created — re-registering an existing id does not rotate it. 500 `storage_enc_key_unconfigured` if `STORAGE_ENC_KEY` is unset. |
| PATCH | `/v1/orgs/:org/spaces/:id` | admin/space_admin | `{ name?, storageEndpoint?, storageRegion?, storageBucket?, storageForcePathStyle?, storageCredentialRef? }` → 200 `SpaceRegistration`. Updates only the supplied mutable fields of an **existing** space (immutable create-time fields preserved; `storage*: null` clears an override). 400 `nothing to update`; 404 unknown space id; 403 if not admin/space_admin. |

### 5c. UI-managed storage credentials + connection test (`storage-credentials.ts`)

Owner/admin–only. Lets the web settings page manage S3-compatible presign credentials WITHOUT
`wrangler secret put`, and probe a backend before saving. The **secret access key** is sealed
with AES-256-GCM (`STORAGE_ENC_KEY`, §8) and stored in the OrgDO; the access-key id + label are
plaintext for display. **The secret is NEVER returned by any API after creation** — it is
decrypted only server-side at presign time. A filespace's `storageCredentialRef` may name a
managed credential **id**; at presign time the gateway resolves it via the managed store (decrypt)
**FIRST**, then falls back to the env `S3_ACCESS_KEY_ID__<REF>` / `S3_SECRET_ACCESS_KEY__<REF>`
scheme (§8a) for back-compat, and **fails closed** if neither resolves.

`StorageCredential = { id, label, accessKeyId, createdAt }` (no secret, ever).

| Method | Path | Auth | Body → Success |
|---|---|---|---|
| GET | `/v1/orgs/:org/storage-credentials` | owner/admin | → 200 `{ credentials: StorageCredential[] }` |
| POST | `/v1/orgs/:org/storage-credentials` | owner/admin | `{ label, accessKeyId, secretAccessKey }` → **201** `StorageCredential`. The secret is sealed (AES-256-GCM) before it touches the DO. 500 `storage_enc_key_unconfigured` if `STORAGE_ENC_KEY` is unset (fail closed). |
| DELETE | `/v1/orgs/:org/storage-credentials/:id` | owner/admin | → **204**. **409 `{ error:"credential_in_use", spaces:[names…] }`** if a filespace references it; 404 unknown id. |
| POST | `/v1/orgs/:org/storage/test` | owner/admin | `{ endpoint, region?, bucket, forcePathStyle?, keyPrefix?, credentialId? }` **OR** `{ …, accessKeyId, secretAccessKey }` (unsaved creds) → 200 `{ reachable, canWrite, canRead, canDelete, prefixEmpty, sampleKeys?, error? }`. Does a REAL probe (PUT → GET → DELETE a throwaway `<keyPrefix>/.cloudfs-conntest-<rand>` object + LIST the prefix). Never throws — failures map into the result. Rate-limited per principal. |

---

## 6. `cloudfs://` deep links

Internal navigation deep links are **not** credentials and grant no access:

```
cloudfs://<spaceId>/<url-encoded/path/segments>[?select=0]
```

- `spaceId` is the URL host; each path segment is URL-encoded. Path is POSIX-style within
  the space, e.g. `cloudfs://active-edit/ShowA/Edit/timeline.prproj`.
- `?select=0` means "reveal the enclosing folder" rather than select-in-Finder (default).
- Built/parsed by `buildDeepLink` / `parseDeepLink` (`src/sharing.ts`). The recipient's
  client resolves the path, **permission-checks via the gateway**, and reveals it in Finder.
- Distinct from external **share links** (`POST /v1/orgs/:org/shares`), which DO carry a
  scoped, time-limited grant and are resolved via the public `…/shares/resolve` route.

---

## 7. Authorization model (how ACL checks resolve)

Scope gates the verb; the **per-folder ACL** gates the target inode:
- The gateway resolves the principal's groups + org role from `OrgDO`, then calls
  `canAccess(store, principal, inodeId, action)` (`permissions.ts`), evaluated inside the
  FilespaceDO against its `items` tree + `grants` table.
- Levels: `read` ⊂ `edit` ⊂ `admin`. Actions map to a minimum level; `delete`/`rename`
  additionally require `edit` on the **parent**.
- Org `owner`/`admin` short-circuit to full access. Absence of a grant = no access (no deny
  verb). Grants inherit down the tree from the nearest explicit ACL.

---

## 8. Required secrets (deployment)

Non-secret config lives in `wrangler.jsonc` `vars` (`S3_ENDPOINT`, `S3_BUCKET`, `S3_REGION?`,
`SIGNUP_MODE`, `SIGNUP_ALLOWED_DOMAINS?`, `EMAIL_PROVIDER?`, `EMAIL_FROM?`, `SES_REGION?`,
`SCRYPT_COST_N?`, `CHECK_BREACHED_PASSWORDS?`) and bindings
(`durable_objects` — `FILESPACE`, `ORG_DO`, plus the auth DOs **`AUTH_DO`** (per-org accounts/
credentials/sessions/service-tokens/email-tokens) and **`DIRECTORY_DO`** (global email + passkey
index) — and the **`AUDIT_BUCKET`** R2 binding for audit archival; the vitest pool
provisions local simulated bindings automatically, so tests need no account). The
**secret-class** values are NOT in `vars`. For local dev/test they live in `.dev.vars`
(git-ignored, auto-loaded by `wrangler dev` and the test runtime). For deploy, set them as
Worker secrets:

```bash
wrangler secret put AUTH_SIGNING_SECRET   # HMAC key for HS256 tokens (>= 16 chars; use 32+); also signs the OIDC login cookie
wrangler secret put BOOTSTRAP_SECRET      # deploy-time bootstrap gate (>= 16; use 32+). Rotate/clear after first run.
wrangler secret put OIDC_CLIENT_SECRET    # OAuth client secret (only if OIDC SSO is enabled)
wrangler secret put RESEND_API_KEY        # Resend API key (only if EMAIL_PROVIDER=resend / auto-detect picks Resend)
wrangler secret put POSTMARK_SERVER_TOKEN # Postmark Server API token (only if EMAIL_PROVIDER=postmark)
wrangler secret put SES_ACCESS_KEY_ID     # AWS SES SigV4 creds (only if EMAIL_PROVIDER=ses); SES_REGION is a non-secret var
wrangler secret put SES_SECRET_ACCESS_KEY
wrangler secret put S3_ACCESS_KEY_ID      # DEFAULT-backend presign credential (least-privileged, separate from GC key)
wrangler secret put S3_SECRET_ACCESS_KEY
wrangler secret put STORAGE_ENC_KEY       # AES-256-GCM key for UI-managed encrypted storage creds (§8c) AND filespace master keys (§5 `key`); `openssl rand -base64 32`
wrangler secret put SIGNUP_INVITE_TOKENS  # valid signup invite tokens (only if SIGNUP_MODE=invite)
wrangler secret put DEV_TOKEN             # legacy fallback token; prefer real SSO/service tokens
# Per-backend presign credentials (only if a filespace overrides its storage backend with a
# storageCredentialRef — see §8a). The ref "<r>" is uppercased + non-alnum→`_` (e.g. "b2" -> B2):
wrangler secret put S3_ACCESS_KEY_ID__<REF>
wrangler secret put S3_SECRET_ACCESS_KEY__<REF>
```

`BOOTSTRAP_SECRET` is optional: if unset or weak (< 16 chars), `POST /v1/bootstrap` is
disabled (404). Set it to seed the first admin, then rotate/clear it. See `BOOTSTRAP.md`.

### 8a. Bring-your-own S3-compatible storage (per-filespace backend)

cloud-fs never proxies object bytes — the client streams media directly to/from the bucket via
the short-lived presigned URLs minted by `…/presign` (§4.4). The presigner is **provider-agnostic
S3 SigV4** (via `aws4fetch`, WebCrypto-backed), so any S3-compatible backend works: **Cloudflare
R2, AWS S3, Backblaze B2, MinIO, Wasabi, Ceph**. (R2 stays first-class: it exposes both an S3
endpoint — used for presigning — and the native binding `AUDIT_BUCKET`, used by the DO for audit
archival; bytes the client touches always go through the S3 endpoint.)

**Deployment-default backend** (non-secret `vars` + secrets): `S3_ENDPOINT`, `S3_BUCKET`,
`S3_REGION?` (default `"auto"`, R2) and the credential secrets `S3_ACCESS_KEY_ID` /
`S3_SECRET_ACCESS_KEY`. Every filespace that doesn't override its storage uses this — a
single-backend deployment needs nothing more.

**Per-filespace override** lives in the OrgDO filespace registry (`POST /v1/orgs/:org/spaces`,
`GET …/spaces`) as a **secret-free** descriptor — access keys are NEVER stored in the DO:

| Field | Meaning |
|---|---|
| `storageEndpoint` | S3 endpoint origin (no bucket/key), e.g. `https://<acct>.r2.cloudflarestorage.com`, `https://s3.us-east-1.amazonaws.com`, `https://s3.us-west-002.backblazeb2.com`, `http://127.0.0.1:9000` |
| `storageRegion` | SigV4 region (`auto` for R2; a real region for AWS/B2/Wasabi; ignored by MinIO/Ceph) |
| `storageBucket` | bucket name the presigner addresses |
| `storageForcePathStyle` | `true` (default) = `<endpoint>/<bucket>/<key>` (MinIO/Ceph/R2-S3); `false` = virtual-host `<bucket>.<endpoint>/<key>` |
| `storageCredentialRef` | **names** either a UI-managed credential **id** (§5c — resolved + decrypted FIRST) or, as fallback, a Worker secret pair (below); absent ⇒ the default `S3_*` keys |

A descriptor that omits endpoint/region/bucket inherits the default backend.
`storageCredentialRef: "<ref>"` is resolved at presign time in this order: **(1)** a UI-managed
credential whose **id** equals the ref (§5c — its AES-256-GCM secret is decrypted via
`STORAGE_ENC_KEY`); **(2)** the Worker secrets **`S3_ACCESS_KEY_ID__<REF>` /
`S3_SECRET_ACCESS_KEY__<REF>`** (ref uppercased, non-alnum → `_`, e.g. `b2` → `B2`,
`Backblaze-Prod` → `BACKBLAZE_PROD`). If NEITHER resolves the presign **fails closed** (errors
rather than silently signing with the default keys). Implementation: `src/storage.ts`
(`resolveStorageConfigAsync`, `resolveCredentialsManagedFirst`, `presignWith`) +
`src/storage-credentials.ts` (`managedCredentialResolver`).

### 8b. Self-serve signup gate — `SIGNUP_MODE`

`POST /v1/auth/signup` (self-serve org creation) is gated by the non-secret `vars`
**`SIGNUP_MODE`** ∈ `closed` | `invite` | `domain` | `open`. The gate runs **before** any org is
provisioned and returns a typed **403** when blocked. **Default (unset) = `invite`** (safe for
self-host); an unrecognized value also resolves to `invite` (fail closed).

| Mode | Semantics | Blocked → |
|---|---|---|
| `closed` | signup disabled (bootstrap / out-of-band invite only) | 403 `signup_disabled` |
| `invite` | only with a valid `inviteToken` in the body (compared constant-time against the `SIGNUP_INVITE_TOKENS` **secret** set; if that secret is unset/empty, ALL signups are blocked) | 403 `signup_disabled` |
| `domain` | open, but only emails whose domain ∈ `SIGNUP_ALLOWED_DOMAINS` (comma/space-separated, non-secret var) may sign up; empty list blocks everyone | 403 `domain_not_allowed` |
| `open` | anyone may sign up (legacy public-SaaS behaviour) | — |

`SIGNUP_INVITE_TOKENS` (comma/space/newline-separated) is a **secret** — `wrangler secret put
SIGNUP_INVITE_TOKENS` (prod) or `.dev.vars` (local); never a `var`. `SIGNUP_ALLOWED_DOMAINS` is a
non-secret `var`. The committed dev `wrangler.jsonc` sets `SIGNUP_MODE: "open"` so the local
signup flow + vitest suite run without a token; the **code default when the var is absent is
`invite`**. Implementation: `src/signup-mode.ts` (`evaluateSignupGate`).

**OIDC SSO** is now configurable **at runtime from the admin console** (§8d, `src/auth-config.ts`) —
this is the preferred path (no redeploy; encrypted client secret). The legacy **deploy-time env**
remains as a **fallback** when no runtime config is saved: non-secret `vars` `OIDC_ISSUER`,
`OIDC_CLIENT_ID`, `OIDC_REDIRECT_URI`, `OIDC_ORG_ID` (plus optional `OIDC_ALLOWED_DOMAINS`,
`OIDC_AUTO_PROVISION`, `OIDC_BOOTSTRAP_EMAIL`, and hard-set `OIDC_AUTHORIZATION_ENDPOINT`/
`OIDC_TOKEN_ENDPOINT`/`OIDC_JWKS_URI` to skip discovery) and the `OIDC_CLIENT_SECRET` secret above.
The `/v1/auth/oidc/*` routes are **disabled (404)** unless a runtime config OR the env (issuer+
client_id+client_secret+redirect+org) is present. See §8d for runtime configuration details.

**First-login owner bootstrap is fail-closed.** The FIRST verified SSO identity for an *empty* org
becomes its `owner`, AND requires an explicit allow-list match: the email equals **`OIDC_BOOTSTRAP_EMAIL`**
(exact) OR its domain is in **`OIDC_ALLOWED_DOMAINS`**. With NEITHER configured the owner mint is
**refused** (`?error=bootstrap_denied`) rather than handing org ownership to any random verified
login. SSO provisioning also requires `email_verified === true` in the id_token — an **absent**
claim is treated as unverified (fail closed), never as verified.

**Transactional email** (signup/verify/reset) is provider-agnostic behind the
`EmailSender` interface. A deployer picks the provider **explicitly** with the non-secret var
**`EMAIL_PROVIDER`** ∈ `cloudflare` | `resend` | `postmark` | `ses` | `console`. **Cloudflare Email
Sending (the `send_email` binding) is the zero-external-account DEFAULT for self-hosters** — no API
key, no third party — with **Resend / Postmark / SES** as opt-in **deliverability upgrades**.
Selection is `emailSenderFor(env)` in `src/auth-stores.ts`.

| `EMAIL_PROVIDER` | Provider | Required env / secret | Notes |
|---|---|---|---|
| `cloudflare` | **Cloudflare Email Sending** (self-host default) | `EMAIL` binding (`send_email`) + `EMAIL_FROM` | Workerd-native; **no external account/API key**. The binding is commented out in `wrangler.jsonc` by default — onboard a domain first (`wrangler email sending enable <domain>`), then uncomment. |
| `resend` | **Resend** | `RESEND_API_KEY` **secret** + `EMAIL_FROM` | POSTs `https://api.resend.com/emails` via `fetch` (bearer auth). Verify the from-domain in the Resend dashboard. |
| `postmark` | **Postmark** | `POSTMARK_SERVER_TOKEN` **secret** + `EMAIL_FROM` | POSTs `https://api.postmark.com/email` via `fetch` with the `X-Postmark-Server-Token` header (PascalCase body; `MessageStream: "outbound"`). Confirm the sender signature/domain in Postmark. |
| `ses` | **AWS SES v2** | `SES_ACCESS_KEY_ID` + `SES_SECRET_ACCESS_KEY` **secrets** + `SES_REGION` (var) + `EMAIL_FROM` | SigV4-signed (via `aws4fetch`) `POST` to `https://email.<region>.amazonaws.com/v2/email/outbound` (SES v2 `SendEmail`, `Simple` content). The IAM creds need `ses:SendEmail`; `EMAIL_FROM` must be a verified SES identity. |
| `console` | **Console (dev)** | — | Logs `to` + `subject` + the verification/invite **LINK** to the Worker console so signup can be exercised locally with **no real email**. Never use in prod. |

**Auto-detect** (when `EMAIL_PROVIDER` is **unset**): the first configured provider wins, in order
**Resend → Postmark → SES → Cloudflare → console (`EMAIL_DEV_CONSOLE=1`) → fake/no-op**. The
**fake/no-op** sender (nothing configured) drops mail silently (records it in-memory), never fails
the request — verification links are still issued + re-sendable; the **vitest suite uses this** (no
network). An **explicitly-selected but misconfigured** provider does NOT silently fall through to a
different provider — it falls to the console/no-op fallback, so a misconfig is visible.

`EMAIL_FROM` (a verified `from`) and optional `EMAIL_FROM_NAME` are non-secret `vars` shared by all
providers. With `EMAIL_PROVIDER=cloudflare` **no secret is required** for email; Resend / Postmark /
SES each need their secret(s) above.

#### Runtime per-org email config (`src/email-config.ts`) — overrides the deploy env

So self-hosters can configure email **in the admin console instead of editing secrets + redeploying**,
each org may store an **encrypted-at-rest** email-provider config in its OrgDO. The provider SECRET
(Resend API key / Postmark server token / SES secret access key) is sealed with **AES-256-GCM** under
the same **`STORAGE_ENC_KEY`** (§8c) as managed storage creds; the provider / from address / from name /
SES region / SES access-key id are stored plaintext for display. **The secret is NEVER returned by any
API after it is saved** — it is decrypted ONLY server-side when building the runtime sender.

**Resolution order** (`emailSenderForOrg(env, orgId)` in `src/auth-stores.ts`, used by login / MFA /
forgot-password / resend-verification): **(1) RUNTIME** — the org's saved config, decrypted and built
into the matching sender (a saved config **overrides the deploy `EMAIL_PROVIDER`/env for that org**);
**(2) ENV** — the existing `emailSenderFor(env)` `EMAIL_PROVIDER`/auto-detect path; **(3) FALLBACK** —
console/fake. The runtime step never throws — an absent or undecryptable config simply falls through to
the env path. (Self-signup runs before the org exists, so it uses the env path.)

`EmailConfig` (the **frozen**, safe shape; never carries the secret):
`{ provider: "cloudflare"|"resend"|"postmark"|"ses", fromAddress, fromName?, region?, configured: true }`.

| Method | Path | Auth | Behaviour |
|---|---|---|---|
| GET | `/v1/orgs/:org/email-config` | owner/admin | → 200 `{ config: EmailConfig \| null }`. `null` = "using the deploy env / default". |
| PUT | `/v1/orgs/:org/email-config` | owner/admin | `{ provider, fromAddress, fromName?, secret?, sesAccessKeyId?, sesSecretAccessKey?, sesRegion? }` → 200 `EmailConfig`. Seals the secret(s) before they touch the DO. `secret` is the Resend API key / Postmark server token; SES uses the `ses*` fields; **Cloudflare needs no secret**. Editing the same provider without resending the secret **retains** the stored one. 400 on a bad provider / missing `fromAddress` / missing required secret; 500 `storage_enc_key_unconfigured` if `STORAGE_ENC_KEY` is unset (fail closed). |
| DELETE | `/v1/orgs/:org/email-config` | owner/admin | → **204**. Reverts the org to the env/default path. |
| POST | `/v1/orgs/:org/email-config/test` | owner/admin | `{ to, provider?, fromAddress?, fromName?, secret?, sesAccessKeyId?, sesSecretAccessKey?, sesRegion? }` → 200 `{ sent: boolean, error? }`. Sends a real **"cloud-fs test email"** via the **SAVED** config, OR via **unsaved creds in the body** (so "Test" works before saving). **Never throws** — every failure maps to `{ sent:false, error }`. Rate-limited per principal. |

### 8d. Pluggable auth provider (`src/auth-config.ts`) — built-in OR external OIDC, no redeploy

The deployment's **auth provider** is configurable at **runtime from the admin console** — no
`wrangler secret put` + redeploy. It is a **deployment singleton** (one row on the global
`DirectoryDO`), not per-org: the sign-in page resolves it **before any org is known**. `mode` selects
the **built-in** lanes (password/2FA/passkey — the default), an **external OIDC IdP**, or **both**.
For OIDC, presets `clerk | okta | entra | auth0 | google | generic` are all standards OIDC, so a preset
is just a default SSO-button **label** — the authorize/token/jwks endpoints are always **derived from
the issuer's `.well-known/openid-configuration`** (`discover()`), so the operator supplies only
**issuer + clientId + clientSecret**. The redirect URI to register with the IdP is
**`<PUBLIC_BASE_URL>/v1/auth/oidc/callback`**.

The OAuth **client secret** is sealed with **AES-256-GCM** under the same **`STORAGE_ENC_KEY`** (§8c) as
managed storage creds / email config and stored on the `DirectoryDO`; preset/issuer/clientId/
allowedDomains/autoProvision are plaintext for display. **The clientSecret is NEVER returned by any
API** — it is decrypted ONLY server-side at token-exchange time. The existing OIDC flow
(`security/oidc.ts`) is reused wholesale; this only supplies the runtime, encrypted config it consumes.

**Resolution order** (`resolveOidcConfig` / `resolveAuthMode` in `src/oidc-wiring.ts`): the **RUNTIME**
config (admin console) is resolved FIRST; with no runtime row the deploy `OIDC_*` env is the fallback
(env `OIDC_*` present ⇒ effective mode `both`). A saved runtime config **overrides** the env; an
explicit `mode='builtin'` row disables the env OIDC fallback.

**Behaviour:** when `mode='oidc'` the built-in credential routes (password signup/login + MFA,
forgot/reset, passwordless WebAuthn assertion) **refuse with `403 auth_mode_oidc`** (the SPA shows only
the SSO button); `mode='both'` allows either; `mode='builtin'` is the default. **Bootstrap-via-OIDC:**
when the deployment org has **no members yet**, the first verified identity may provision the owner
only when it matches `OIDC_BOOTSTRAP_EMAIL` or a configured `allowedDomains` entry. Without either
allow-list, bootstrap fails closed. Subsequent users map per `allowedDomains`/`autoProvision`.

`AuthConfig` (the **frozen**, owner/admin shape; never carries `clientSecret`):
`{ mode, oidc?: { preset, issuer, clientId, allowedDomains: string[], autoProvision: boolean, configured: true } }`.

**Admin-org gate (all four verbs).** Because this row is **deployment-wide**, owner/admin of the org
in the path is **not sufficient** — the caller's org MUST also be the **designated auth-config admin
org**: `AUTH_CONFIG_ADMIN_ORG` (non-secret var), falling back to `OIDC_ORG_ID`. If **neither** is set,
**every** request to `/v1/orgs/:org/auth-config[/validate]` (GET/PUT/DELETE/validate) returns
**`403 forbidden: not the auth-config admin org`** — fail safe, so a throwaway org's admin can't hijack
the deployment's SSO. Set `AUTH_CONFIG_ADMIN_ORG` (or `OIDC_ORG_ID`) to your primary org to enable it.

| Method | Path | Auth | Behaviour |
|---|---|---|---|
| GET | `/v1/auth/config/public` | **public (unauth)** | → 200 `{ mode, oidcEnabled, providerLabel?, webBaseUrl, gatewayBaseUrl, productName, passkeysEnabled, signupMode, appDownloadUrl? }`. Never exposes a secret/clientId. |
| GET | `/v1/orgs/:org/auth-config` | owner/admin **of the auth-config admin org** | → 200 `{ config: AuthConfig \| null }`. `null` = built-in default (or env OIDC fallback). 403 if the caller's org isn't `AUTH_CONFIG_ADMIN_ORG`/`OIDC_ORG_ID` (or neither is set). |
| PUT | `/v1/orgs/:org/auth-config` | owner/admin **of the auth-config admin org** | `{ mode, oidc?: { preset, issuer, clientId, clientSecret?, allowedDomains?, autoProvision? } }` → 200 `AuthConfig`. Seals `clientSecret` before it touches the DO. For known presets the endpoints are derived from the issuer's discovery doc. Editing the same issuer/clientId without resending `clientSecret` **retains** the stored one. 400 on a bad mode/preset / non-https issuer / missing clientId / missing required secret; 403 if not the auth-config admin org; 500 `storage_enc_key_unconfigured` if `STORAGE_ENC_KEY` is unset. |
| DELETE | `/v1/orgs/:org/auth-config` | owner/admin **of the auth-config admin org** | → **204**. Reverts to built-in/env. 403 if not the auth-config admin org. |
| POST | `/v1/orgs/:org/auth-config/validate` | owner/admin **of the auth-config admin org** | `{ issuer }` → 200 `{ valid: boolean, endpoints?, error? }`. Fetches the issuer's discovery doc and reports the derived endpoints. **Never throws** — a discovery failure maps to `{ valid:false, error }`. 403 if not the auth-config admin org. |

**Password hardening** (`src/security/auth-password.ts`): passwords are scrypt-hashed at the
**OWASP-current default N = 2¹⁷ (131072), r=8, p=1, dkLen=32**. Cost params are stored **per-row**, so
raising the default never invalidates existing hashes — an older (cheaper) hash still verifies with
its own params and is flagged `needsRehash`, so it **transparently upgrades on the next successful
login**. Two non-secret knobs:

- **`SCRYPT_COST_N`** — override the default scrypt `N` (CPU/memory cost) to fit your CPU budget;
  **MUST be a power of two** (a missing/invalid value is ignored → falls back to the default). The
  vitest suite sets a tiny value via the test pool so auth flows stay fast; **production keeps
  131072**.
- **`CHECK_BREACHED_PASSWORDS`** (`"1"`/`"true"`, **default OFF**) — enable the optional
  **HaveIBeenPwned** breached-password check at signup + password change + reset. Privacy-preserving
  **k-anonymity**: only the first **5 hex chars** of the password's SHA-1 leave the Worker (to
  `https://api.pwnedpasswords.com/range/<prefix>`); a match rejects with **`password_breached`**
  before hashing/persisting. It **FAILS OPEN** — an HIBP outage never blocks signup. **Turn it ON in
  prod** for defence-in-depth; leave OFF in dev/tests (no network).

**WebAuthn / passkeys** (optional) uses non-secret vars `WEBAUTHN_RP_ID` (the registrable
portal domain; `localhost` in dev), `WEBAUTHN_RP_NAME`, and `WEBAUTHN_ORIGIN` (comma-separated
ceremony origins). The `/v1/auth/webauthn/*` routes are **disabled (404)** unless
`WEBAUTHN_RP_ID` is set (fail closed). `PUBLIC_BASE_URL` + `PRODUCT_NAME` (non-secret vars)
shape email links and copy. No secrets are required for passkeys.

`WEB_BASE_URL` (non-secret var) is the **web-app (SPA) origin** for links a HUMAN clicks in
email — distinct from `PUBLIC_BASE_URL` (the Worker/API origin). The email-verification link is
built as `<WEB_BASE_URL>/verify-email?token=<t>&orgId=<o>`, pointing at the SPA's public
`/verify-email` page (which POSTs `{token, orgId}` to the **POST** `/v1/auth/verify-email` confirm
route) — a GET against that API route would 401 (`no_token`). Dev default `http://localhost:5173`
(Vite); falls back to `PUBLIC_BASE_URL`, then the request origin, if unset.

Rotate the local stand-in values before any non-dev use — treat the committed defaults as public.

---

## 9. Operational notes and implementation limits

The public API includes token minting through login, OIDC, service-token, and share flows;
authorization and token verification are described above. Public pre-auth routes are
rate-limited, while filespace mutations and presign requests also use filespace-level
limits.

Snapshot restore and browsing are implemented. Object reclamation is exposed through the
operator quarantine route: deletion begins only after an administrator supplies a
`recoveredThrough` watermark, the object remains eligible for seven days, and the durable
alarm rechecks it before storage deletion. The API does not sweep arbitrary bucket orphans or
automatically prune retained recovery history.

Audit records are archived to `AUDIT_BUCKET` and read through the audit route. The live
activity endpoint reports current Durable Object state; it is not a durable history store.

### Deployment storage discovery and first-owner setup

`GET /v1/orgs/:org/storage/default` (owner/admin only) returns the secret-free deployment descriptor:
`{configured, provider, endpoint, region, bucket, forcePathStyle, problems: string[]}`.
`configured` means required settings exist; it does not assert reachability. Access-key IDs and secrets are never included.

`POST /v1/orgs/:org/storage/default/validate` (owner/admin + normal CSRF requirements for cookies) returns the existing connection-test shape `{reachable, canWrite, canRead, canDelete, prefixEmpty, sampleKeys?, error?}`. It uses deployment secrets internally and probes an isolated prefix with a write/read byte comparison and cleanup.

`POST /v1/orgs/:org/spaces` accepts `storageMode: "deployment"` with `name`. The server fills and snapshots bucket coordinates, inherits deployment credentials without saving another credential row, and assigns the filespace ID. Conflicting storage overrides are ignored in this mode. Unconfigured default storage yields `409 default_storage_unconfigured`. A missing encryption key yields `503 storage_enc_key_unconfigured` before any registry row is persisted.

`POST /v1/setup/init` and `POST /v1/bootstrap` share a durable deployment-wide claim. Success closes both routes (`409 setup_complete` thereafter), including attempts with another workspace ID. Concurrent attempts receive `409 setup_in_progress` or `setup_target_mismatch`. An interrupted attempt can resume the reserved workspace/email after its request releases the claim or its two-minute lease expires. Neither route returns owner credentials before the durable completion flag is stored.

`GET /v1/auth/config/public` returns `passkeysEnabled: boolean` and `signupMode: "closed" | "invite" | "domain" | "open"`, reflecting passkey availability, the HTTPS open-signup guard, and OIDC-only mode.

### Folder-only mounts and key access

`GET /v1/filespaces/:fs/mount-roots` requires `fs:read` and returns
`{roots: [{id, name, mountAsRoot}]}`. Owners and members who can read the whole space
receive `root`. Folder-only members receive their minimal live granted folder roots;
disjoint shares remain separate entries, group grants are included, and expired or
deleted folders are absent. The endpoint does not reveal unreadable ancestor names.
Clients can project one returned opaque inode ID as the mount root or present disjoint
roots in a synthetic shared-folder root. An empty array means no mountable folders.

Master-key retrieval requires an effective read grant somewhere in this filespace,
including a subfolder-only grant. The shared key alone grants no object-storage access:
each presigned URL and metadata mutation still uses its original per-inode ACL.
Named-stream/resource-fork writes and deletions require edit access on that inode;
a read-only root grant does not authorize them.

### Writable-open access preflight

`GET /v1/filespaces/:fs/items/:id/access` requires `fs:read` and a readable live inode.
It returns `{ read: true, write: boolean }` with `Cache-Control: no-store`.
`write` requires both the `fs:write` token scope and the effective edit/admin ACL.
Missing or unreadable inodes return 404. This endpoint lets the Mac client reject
read-only writable opens before acknowledging journaled bytes; it is not a grant
or an upload authorization. Upload presigning and commit retain their live checks.

### Immutable snapshot mounts and Mac metadata

The native daemon uses the following `snapshot:read` routes under
`/v1/filespaces/:fs/snapshots/:snapshotId`:

- `GET /mount-roots` → `{snapshot,roots:[{id,name,mountAsRoot}],streamsCaptured}`.
- `GET /items/:inode` → authorized frozen `Item`.
- `GET /page?parent=:inode&cursor=:opaque` → `{items,cursor}` (256 rows/page).
- `GET /blocks/:inode?cursor=:offset` → `{item,blocks,cursor}` (512 blocks/page).
- `GET /items/:inode/streams` → `{streams:[{name,size}],captured:true}`.
- `GET /items/:inode/streams/:name` → original encrypted stream bytes for legacy captured streams; manifest-backed streams return 409 `stream_uses_manifest`.
- `GET /items/:inode/streams/:name/manifest?offset=&length=` → bounded frozen stream manifest for manifest-backed streams. Legacy stream payloads have no manifest.
- `POST /presign/batch` with `{itemId,keys:[{key,method:"GET"}],expiresIn?}` →
  `{results:[{key,url?|error?}],expiresIn}`. At most 256 exact frozen object keys;
  `fs:read` is also required. PUT and arbitrary declared keys are rejected.

Snapshot metadata is immutable. Public creation performs the duplicate-ID check
and freeze in one Durable Object turn and returns 409 if the ID exists. Creation
requires `snapshot:write` and current folder-admin authority on the scope; broader
token scopes do not override resource permissions. Listings hide inaccessible
snapshot scopes/labels. Each historical request evaluates today's live grants
against both frozen ancestry and current/last-known ancestry. Deleted children
can still be recovered through live authorized ancestors; moved-private history,
deleted grant roots and revoked delegation cannot confer access. Already-issued
object URLs remain valid until their short expiry; daemon reads recheck authority
before consulting them or its cache.

Schema v18 freezes encrypted named-stream payloads for changed inodes alongside
each snapshot delta. Stream deletions are represented by the changed inode's exact
stream set. Pruning a base transfers inherited streams into its children before
removal. Restoring a captured inode restores its exact stream set atomically with
content; newly-created unrelated files remain untouched. Recursive restore checks
every descendant before mutation, skips permission/lock conflicts, and removes
stale direct/delegated grants before recreating tombstoned inodes.

Legacy snapshots have `streamsCaptured:false`; their stream-list route reports
409 `snapshot_predates_mac_metadata`. New snapshots never inherit an incomplete
legacy base. Their first capture after upgrade is complete, then normal delta
storage resumes. Frozen Mac stream bytes consume Durable Object storage in
addition to manifest rows and follow snapshot retention. Neither API nor daemon
falls back to a live stream for historical reads.

Live and frozen directory metadata may include `finderInfoCiphertext`, the bounded
base64 encrypted `AFP_AfpInfo` envelope (logical size 60, envelope at most 256
bytes), plus `rsrcForkSize`. The daemon authenticates/decrypts this with the
original inode/stream identity and extracts FinderInfo bytes 16–47 for SMB AAPL
attributes. The gateway must never slice ciphertext into plaintext FinderInfo.

Encrypted named-stream writes are limited to 1.5 MiB, including the encryption
envelope. Oversized writes return 413 without replacing the existing stream;
the limit leaves headroom below Cloudflare's 2 MB SQLite row ceiling. Normal
file blocks use object storage and are unaffected by this named-stream bound.

## Operator backup and restore

Use [the encrypted archive tool](../docs/BACKUP-RESTORE.md) rather than scripting
individual database exports. These routes require `x-bootstrap-secret` and an
explicit deployment `BACKUP_MODE=export|restore`; otherwise they return 404.
While maintenance is enabled, normal API requests return retryable 503. Durable
per-authority holds also survive a restart or premature removal of that variable.

- `GET /v1/admin/backup/status` or `/restore/status` reports the maintenance
  generation and key fingerprints to the authenticated operator.
- `POST /backup/start` requires `organizations` and
  `scope:"operator-declared-organizations"`. It freezes registries, inventories
  every filespace including soft-deleted ones, freezes those authorities and
  validates account/key references before returning schemas.
- `GET /backup/:id/metadata?target=...&table=...&afterRowId=...` returns a bounded
  typed page with its SHA-256. Integers are decimal strings; BLOBs are base64.
- `GET /backup/:id/objects?target=...&cursor=...` enumerates unique referenced
  blocks and audit objects with temporary download URLs. Audit transfers use the
  operator credential only on the configured Worker origin.
- `POST /backup/:id/finish` or `/abort` durably fences the generation and releases
  its holds. Both leave deployment maintenance enabled.
- `POST /restore/start` requires the authenticated archive catalog, expected
  object counts, original wrapping-key fingerprint and different signing and
  bootstrap key fingerprints. Every target must be pristine and schema-compatible.
- `POST /restore/:id/metadata` stages `{targetId,pageIndex,page}`. Exact retries
  are idempotent; changed or reordered pages fail.
- `POST /restore/:id/objects` registers bounded object expectation pages.
  `/object-url` issues conditional upload tickets; `/object-verify` records a
  receipt only after checking remote size/checksum or reading the object bytes.
- `POST /restore/:id/finish` takes `{targets:[{id,pageCount}]}`. It validates
  complete catalogs, data references and the entire audit chain, commits each
  authority, then releases holds. Repeating it resumes commit/release safely.

There is no partial-restore abort or merge into an existing deployment. Recovery
always retains maintenance until successful completion and deliberate redeploy.
New token secrets retire old signed credentials; transient authorization tables,
invitations, share links and recovery codes are excluded from restored access.
Schedules are disabled and storage remaps to the fresh target default. See the
operator guide for historical credential review, capacity limits and cutover.


### Durable change notifications

`GET /v1/filespaces/:id/changes/subscribe` with `Upgrade: websocket` uses the same bearer authentication, `fs:read` scope and filespace-read authorization as the metadata API. The gateway builds a fresh internal identity envelope; client identity headers are not trusted. The server sends `{ "type": "invalidate" }`. Clients replay `/changes` through every continuation and then send `ack`. A `check` message probes the current stamp/expiry without acknowledging. Only one hint is outstanding per connection; messages contain no file names, object keys, counts or tokens. Limits are 512 sockets per filespace and 8 per identity.

The connection lifetime is at most 30 seconds or the token expiry, whichever is sooner. Send/check re-evaluates local ACL access; reconnect goes through current authentication and membership resolution. Native clients check every 10 seconds and retain a 5-second HTTP replay fallback. This bounds external-session/group revocation freshness; it is not a promise of instantaneous cross-authority revocation. Hibernation state lives in socket attachments.

`/changes` adds an opaque `visibility` string. A change requires invalidating cached metadata and re-listing authorized roots, even when `anchor` is unchanged. Continue using `cursor` while present, including empty permission-filtered pages. Persist a cursor only after applying its page. Hints are advisory; the HTTP feed is authoritative.


### Main-file manifest deltas and bounded reads

`PATCH /v1/filespaces/:fs/blocks/:item` accepts `{format:1, blockSize, size, expectedVersion, fence, blocks}`. Blocks use the existing wire shape; coordinates are fixed (`chunkIdx = index`, `blockIdx = 0`, `offset = index * blockSize`). At most 1,024 changed entries are accepted per atomic batch. Main files remain dense: growth supplies every new extent and any formerly short boundary; shrink replaces the surviving partial boundary. Canonical payload SHA-256 plus the expected version identifies an exact retry (lease fence is deliberately excluded from the digest but checked again). Only an identical retry at `expectedVersion + 1` is a no-op.

The final authority turn rechecks ACL, provenance, receipts, lease and version. `409 manifest_layout` permits a full replacement for an older variable layout. Other conflicts never permit an unconditional fallback. Full PUT optionally declares `blockSize`, establishes that layout, and clears the last-delta identity. Larger changes use full PUT; its existing 16 MiB body and 131,072-entry bounds still apply.

`GET /v1/filespaces/:fs/blocks/:item/range?after=-1&limit=1024` returns `{format:1,item,blocks,cursor}` with item metadata and rows from one SQL turn. `cursor` is the last returned offset, or null. Continuation supplies `after=cursor&version=item.version`; a changed version returns 409. Pages include at most 1,024 rows. The new native build requires the matching server for these range reads; old clients can continue using full GET/PUT.

`GET /v1/filespaces/:fs/blocks/:item/range?offset=…&length=…&contentVersion=…` selects format 2: `{format:2,item,firstBlockIndex,blocks,nextOffset}`. Offset is a nonnegative safe integer and length is 1–33,554,432 bytes. A seek returns the block containing offset and following intersecting blocks, at most 1,024 entries. `firstBlockIndex` is the absolute index used by file-block encryption, including for legacy variable layouts. `nextOffset` is the next byte offset when the row cap cuts the requested extent short. An extent at/past EOF is empty. Current read ACL and optional content version are checked in the same authority turn. Fixed layouts use indexed seeks without reading the preceding map; legacy variable layouts count preceding index entries to recover the encryption index. Gaps/inconsistent extents fail with `invalid_manifest`; a version mismatch is HTTP 409. Clients must keep every continuation bound to one content version.

### Basic filesystem metadata

`PATCH /v1/filespaces/:fs/items/:id/basic-info` accepts `{expectedVersion,fence?,createdAt?,modifiedAt?,accessedAt?,changedAt?,fileAttributes?}`. Times are integer Unix milliseconds in the 1601–9999 range. Omitted fields remain unchanged. `expectedVersion` is mandatory. The authority rechecks write ACL, competing leases, an optional fence, and metadata version before an atomic update. A successful mutation advances metadata version/change sequence without changing content version or block references. If not supplied, change time becomes the mutation time. Content changes and renames update change time too.

`fileAttributes` holds only the supported stored DOS bits: hidden `0x2`, system `0x4`, archive `0x20`, temporary `0x100`, and not-content-indexed `0x2000`. Zero clears them. Directory/normal presentation is derived by the SMB adapter. Unsupported bits are rejected; setting read-only is not yet supported. Invalid metadata returns 400, permission denial 403, missing items 404, and stale versions/leases 409. These fields are preserved through snapshot freeze, delta inheritance, base compaction and restore. New snapshots start a complete metadata base after upgrading an older snapshot chain.

### Object reclamation

Org owner/admin `GET /v1/filespaces/:fs/reclamation` reports candidates, verified ciphertext bytes (unknown sizes are not estimated), quarantine/deletion state and bounded failures. It performs no deletion.

Org owner/admin `POST /v1/filespaces/:fs/reclamation/quarantine` requires `fs:admin` scope and, with `{recoveredThrough:<epoch milliseconds>}`, quarantines up to 64 candidates. The cutoff is an operator assertion that pending client recovery through that timestamp has been reconciled. It is required and cannot be in the future. An unreferenced object must have become unreferenced by that cutoff, have no live/snapshot/retained reference, and have no upload claim or in-progress multipart upload. Retained history and expired claims are not pruned automatically.

After seven days, a durable alarm rechecks candidates and commits retirement tokens before issuing storage deletion. New references cancel quarantine; retiring/deleted objects cannot be republished. Ambiguous deletes retry with backoff. Success cleans verification and zero-count reference rows while preserving compact permanent retirement/catalog records. Monthly repeat deletion covers late pre-retirement uploads. Backup holds stop admission and drain in-flight deletion work. No endpoint in this implementation sweeps arbitrary bucket orphans or changes retention for live recovery history.

### Metadata capacity

Org owner/admin `GET /v1/filespaces/:fs/capacity` returns `databaseBytes`, `warningBytes`, `admissionBytes`, `platformBytes`, `headroomBytes` and `state` (`ok`, `warning`, `full`). `?contributors=1` adds explicit table row counts; these scans are omitted from normal requests and health checks. Rows are not per-table byte estimates.

`METADATA_ADMISSION_BYTES` defaults to 9,000,000,000. `METADATA_WARNING_BYTES` defaults to the lower of 8,000,000,000 and 80% of the admission threshold (7,200,000,000 with the default admission setting). Overrides must be nonnegative integers, warning ≤ admission, and admission ≤ 9,900,000,000. Growth paths use conservative admission estimates. SQLite allocation/full failures remain authoritative. HTTP 507 `{error:"metadata_capacity",reason:...}` tells clients to preserve pending writes. Read/delete operations remain available within the maintenance reserve; oversized maintenance may still fail atomically.

### Administrative visibility and CLI enforcement

Workspace members/groups/invitations, storage credentials, email and identity-provider settings,
snapshot schedules, and workspace activity/history require owner/admin. Filespace administrators
can manage filespace names, guest links, and folder permissions, but cannot manage workspace
accounts or schedules. Storage redirection and filespace deletion/purge remain owner-only.
The administrative gateway reads the current persisted role on every request, including bearer
and service tokens. An old token scope never substitutes for current administrative authority.
Scoped folder administrators may manage grants and create snapshots only in their delegated roots.
Regular users retain their permitted file operations, snapshot reads/restores, local cache, mount,
and recovery controls. The CLI uses these same endpoints; denied administration returns HTTP 403
and CLI exit code 30. Local cache settings are personal preferences, not workspace administration.
