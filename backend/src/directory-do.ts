// SPDX-License-Identifier: AGPL-3.0-or-later
// directory-do.ts — the GLOBAL email -> {orgId, accountId} directory (CONTRACTS-AUTH.md §1.7).
//
// A single global Durable Object instance (`idFromName("global")`). Its ONLY job is the
// `email_index` table: it resolves a login before the org is known, and enforces that an
// email address is GLOBALLY UNIQUE across all orgs (one email = one account = one org).
//
// Why a separate DO (not OrgDO): login is bare `email + password` with no org selector, so we
// must resolve `email -> orgId` before we can address the right `AuthDO(orgId)`. A global
// point-key store is the only place that mapping can live. Per §1.7 it does point-key
// reads/writes only (no scans), and the resolved `{orgId}` is cached in the session afterward,
// so this DO is touched only at login/signup/deprovision — never on the authenticated hot path.
//
// Addressed by `idFromName("global")` (one instance, system-wide). Single-threaded + strongly
// consistent, SQLite-backed — same pattern as OrgDO/FilespaceDO.

import { DurableObject } from "cloudflare:workers";
import { BackupState, type BackupEnv } from "./backup-state";
import { consume, type RateLimitConfig, type RateLimitResult } from "./security/ratelimit";

export interface DirectoryDOEnv extends BackupEnv {
  DIRECTORY_DO: DurableObjectNamespace<DirectoryDO>;
}

/// The stable name every caller uses to address the single global instance.
export const DIRECTORY_DO_NAME = "global";

export interface DirectoryEntry {
  orgId: string;
  accountId: string;
}

/// The DEPLOYMENT-level auth-provider config (auth-config.ts). One row, system-wide. `mode` selects
/// the built-in lanes vs. an external OIDC IdP vs. both. When `mode` is `oidc`/`both` the `preset` +
/// `issuer` + `clientId` carry the OIDC parameters; the OAuth client SECRET is AES-256-GCM encrypted
/// (secretIv + secretCiphertext) under STORAGE_ENC_KEY and is NEVER returned by any API. The
/// authorize/token/jwks endpoints are NOT stored — they're derived from the issuer's discovery doc
/// at use time. `allowedDomains` is a JSON-encoded string[]; `providerLabel` is the human SSO-button
/// label (e.g. "Okta", "Google").
export interface AuthConfigRow {
  mode: "builtin" | "oidc" | "both";
  preset: string | null;
  issuer: string | null;
  clientId: string | null;
  /// JSON-encoded `string[]` of allowed email domains (empty `[]` when none). Null only for builtin.
  allowedDomains: string | null;
  autoProvision: boolean;
  providerLabel: string | null;
  /// AES-256-GCM envelope of the OAuth client secret. Empty strings when no secret is set yet
  /// (built-in mode, or a same-config edit that retained the prior secret without resending it).
  secretIv: string;
  secretCiphertext: string;
  createdAt: number;
  updatedAt: number;
}

/// Thrown (as a plain Error with `code: "email_taken"`) when a claim collides. The signup lane
/// recognizes `email_taken` and maps it to a generic 409 (no enumeration of which org owns it).
export class EmailTakenError extends Error {
  readonly code = "email_taken";
  constructor(message = "email already in use") {
    super(message);
    this.name = "EmailTakenError";
  }
}

function now(): number {
  return Date.now();
}

export class DirectoryDO extends DurableObject<DirectoryDOEnv> {
  private sql: SqlStorage;
  private readonly backupState: BackupState;

  constructor(ctx: DurableObjectState, env: DirectoryDOEnv) {
    super(ctx, env);
    this.backupState = new BackupState(ctx.storage, env, 'directory');
    this.sql = this.backupState.guardedSQL;
    ctx.blockConcurrencyWhile(async () => { this.migrate(); this.backupState.initialize(); });
  }


  backupDescribe() { return this.backupState.describe(); }
  async backupFreeze(input: Parameters<BackupState['freeze']>[0]) {
    this.backupState.freeze(input);
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.sync();
  }
  backupRelease(input: Parameters<BackupState['release']>[0]) { return this.backupState.release(input); }
  backupExportPage(input: Parameters<BackupState['exportPage']>[0]) { return this.backupState.exportPage(input); }
  backupCatalogPage(input: Parameters<BackupState['catalogPage']>[0]) { return this.backupState.catalogPage(input); }
  backupCheckReferences(input: Parameters<BackupState['checkReferences']>[0]) { return this.backupState.checkReferences(input); }
  backupRestoreBegin(input: Parameters<BackupState['restoreBegin']>[0]) { return this.backupState.restoreBegin(input); }
  backupRestorePage(input: Parameters<BackupState['restorePage']>[0]) { return this.backupState.restorePage(input); }
  backupRestoreCommit(input: Parameters<BackupState['restoreCommit']>[0]) { return this.backupState.restoreCommit(input); }
  backupRestoreStatus() { return this.backupState.restoreStatus(); }
  backupValidateCatalog(input: Parameters<BackupState['validateCatalog']>[0]) { return this.backupState.validateCatalog(input); }
  backupInventory() { return this.backupState.inventory(); }
  backupCoordinatorGet() { return this.backupState.coordinatorGet(); }
  backupCoordinatorSet(input: Parameters<BackupState['coordinatorSet']>[0]) { return this.backupState.coordinatorSet(input); }

  async readiness(): Promise<{ schemaVersion: number; databaseBytes: number }> {
    const schemaVersion = Number(this.sql.exec(`SELECT COALESCE(MAX(id), 0) AS v FROM _schema_migrations;`).one().v);
    await this.ctx.storage.sync();
    return { schemaVersion, databaseBytes: this.sql.databaseSize };
  }

  private migrate(): void {
    // Track applied migrations (same durable pattern as metadata/schema.ts) so the table set
    // can evolve without data loss.
    this.sql.exec(`CREATE TABLE IF NOT EXISTS _schema_migrations (
      id INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);`);
    const current = Number(
      this.sql.exec(`SELECT COALESCE(MAX(id), 0) AS v FROM _schema_migrations;`).one().v,
    );
    if (current < 1) {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS email_index (
        email_lower TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        created_at INTEGER NOT NULL);`);
      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (1, ?);`, now());
    }
    // ---- v2: WebAuthn credential -> org index --------------------------------
    // Passwordless / discoverable login carries no email, so `authenticate/verify` can't address
    // the right `AuthDO(orgId)` to look the credential up. This point-key index maps the public
    // base64url credential id to its owning org so verify can resolve it without a global scan.
    // (Off the authenticated hot path — touched only at passkey register + the rare assertion.)
    if (current < 2) {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS webauthn_index (
        credential_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        created_at INTEGER NOT NULL);`);
      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (2, ?);`, now());
    }
    // ---- v3: fleet-wide pre-auth rate-limit buckets ---------------------------
    // The signup/login per-IP + per-email token buckets MUST be fleet-wide, not per-isolate: an
    // in-memory store is diluted across ephemeral Workers isolates, so a credential-stuffing
    // attacker simply spreads requests across isolates to evade the cap. Backing the buckets with
    // this already-global singleton DO makes the counters strongly consistent system-wide. The
    // `bucket_key` is fully namespaced by the caller (`signupIp:ip:…`, `loginEmail:email:…`), so
    // the four buckets stay disjoint here (a prior bug shared them) — one row per (bucket, key).
    if (current < 3) {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS rate_buckets (
        bucket_key TEXT PRIMARY KEY,
        tokens REAL NOT NULL,
        updated_at INTEGER NOT NULL);`);
      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (3, ?);`, now());
    }
    // ---- v4: deployment-level pluggable auth-provider config -------------------
    // The auth provider (built-in password/2FA/passkey vs. an external OIDC IdP) is a DEPLOYMENT
    // singleton, configurable at RUNTIME from the admin console with NO redeploy (auth-config.ts).
    // It lives here — on the one global DO — because the sign-in page resolves it BEFORE any org is
    // known (the unauthenticated `GET /v1/auth/config/public` reads it to decide whether to show the
    // password form and/or the SSO button). A SINGLE row (PK 'k'='auth'). The OIDC client SECRET is
    // stored AES-256-GCM encrypted (secret_iv + secret_ct) under STORAGE_ENC_KEY; issuer/clientId/
    // preset/allowedDomains/autoProvision are plaintext. Absent row ⇒ built-in default (or, for
    // back-compat, the deploy `OIDC_*` env). The plaintext secret is recovered ONLY server-side at
    // token-exchange time and is NEVER returned by any API.
    if (current < 4) {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS auth_config (
        k TEXT PRIMARY KEY,
        mode TEXT NOT NULL,
        preset TEXT,
        issuer TEXT,
        client_id TEXT,
        allowed_domains TEXT,
        auto_provision INTEGER NOT NULL DEFAULT 0,
        provider_label TEXT,
        secret_iv TEXT NOT NULL DEFAULT '',
        secret_ct TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL);`);
      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (4, ?);`, now());
    }
    // ---- v5: deployment setup flag (auth-spec §4.4) -----------------------------
    // "Has first-run setup completed?" — a DURABLE deployment-wide boolean, set by the web setup
    // wizard (`POST /v1/setup/init`) and by a successful legacy `POST /v1/bootstrap`. The wizard
    // self-disables once it's set (`GET /v1/setup/status` → { needed:false }). Deliberately NOT
    // "is the directory empty" — OIDC/bootstrap users don't always create directory rows.
    if (current < 5) {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS setup_state (
        k TEXT PRIMARY KEY,
        v INTEGER NOT NULL,
        updated_at INTEGER NOT NULL);`);
      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (5, ?);`, now());
    }
    if (current < 6) {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS setup_claim (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        org_id TEXT NOT NULL, email TEXT NOT NULL, token TEXT NOT NULL, lease_until INTEGER NOT NULL);`);
      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (6, ?);`, now());
    }
    if (current < 7) {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS org_registry (org_id TEXT PRIMARY KEY);`);
      this.sql.exec(`INSERT OR IGNORE INTO org_registry SELECT org_id FROM email_index UNION SELECT org_id FROM webauthn_index UNION SELECT org_id FROM setup_claim;`);
      this.sql.exec(`INSERT INTO _schema_migrations(id,applied_at) VALUES (7,?);`, now());
    }
  }

  registerOrganization(orgId: string): void {
    this.sql.exec(`INSERT OR IGNORE INTO org_registry(org_id) VALUES (?);`, orgId);
  }

  /// Claim `emailLower` for (orgId, accountId). INSERTs; throws `email_taken` if the email
  /// already exists in ANY org. This is the AUTHORITATIVE global-uniqueness enforcement
  /// (CONTRACTS-AUTH.md §1.7). Single-threaded DO => the check+insert is atomic (no race).
  async claim(emailLower: string, orgId: string, accountId: string): Promise<void> {
    const email = emailLower.trim().toLowerCase();
    const existing = this.sql
      .exec(`SELECT org_id, account_id FROM email_index WHERE email_lower = ?;`, email)
      .toArray();
    if (existing.length) {
      // Idempotent: a re-claim by the SAME (org, account) is a no-op, not a collision. This
      // makes signup safely retryable if the account already owns the address.
      const row = existing[0];
      if (String(row.org_id) === orgId && String(row.account_id) === accountId) {
        this.registerOrganization(orgId);
        return;
      }
      throw new EmailTakenError();
    }
    this.registerOrganization(orgId);
    this.sql.exec(
      `INSERT INTO email_index (email_lower, org_id, account_id, created_at) VALUES (?,?,?,?);`,
      email, orgId, accountId, now(),
    );
  }

  /// Re-point an account's email in the global index: claim `newEmailLower` for (orgId, accountId)
  /// and release `oldEmailLower`. Used by self-service profile email change. Atomic (single-threaded
  /// DO). Returns the OUTCOME rather than throwing (so a cross-owner collision doesn't surface as an
  /// uncaught DO-RPC rejection — same convention as `indexWebAuthn`):
  ///   - "ok"    : the new email was claimed (or re-affirmed for the same owner) + the old released.
  ///   - "taken" : the NEW email is already owned by a DIFFERENT (org, account) — REJECTED, the old
  ///               claim is left intact (fail closed).
  async reclaim(
    oldEmailLower: string,
    newEmailLower: string,
    orgId: string,
    accountId: string,
  ): Promise<"ok" | "taken"> {
    const oldEmail = oldEmailLower.trim().toLowerCase();
    const newEmail = newEmailLower.trim().toLowerCase();
    // Check the new email's current owner FIRST so we never throw across the RPC boundary.
    const existing = this.sql
      .exec(`SELECT org_id, account_id FROM email_index WHERE email_lower = ?;`, newEmail)
      .toArray();
    if (existing.length) {
      const row = existing[0];
      if (!(String(row.org_id) === orgId && String(row.account_id) === accountId)) return "taken";
    } else {
      this.sql.exec(
        `INSERT INTO email_index (email_lower, org_id, account_id, created_at) VALUES (?,?,?,?);`,
        newEmail, orgId, accountId, now(),
      );
    }
    // Release the old address (point-key delete) once the new claim is secured.
    if (oldEmail !== newEmail) {
      this.sql.exec(`DELETE FROM email_index WHERE email_lower = ?;`, oldEmail);
    }
    return "ok";
  }

  /// Resolve a login email to its org + account, or null if unknown. Point-key read.
  async resolve(emailLower: string): Promise<DirectoryEntry | null> {
    const email = emailLower.trim().toLowerCase();
    const r = this.sql
      .exec(`SELECT org_id, account_id FROM email_index WHERE email_lower = ?;`, email)
      .toArray();
    if (!r.length) return null;
    return { orgId: String(r[0].org_id), accountId: String(r[0].account_id) };
  }

  /// Release an email so it can be reclaimed (on deprovision). Idempotent.
  async release(emailLower: string): Promise<void> {
    this.sql.exec(`DELETE FROM email_index WHERE email_lower = ?;`, emailLower.trim().toLowerCase());
  }

  /// Index a WebAuthn credential id -> its owning org (called at passkey registration). Returns the
  /// outcome rather than throwing (so a conflict doesn't surface as an uncaught DO-RPC rejection):
  ///   - "created"   : first time this id was seen.
  ///   - "exists"    : idempotent re-index by the SAME (org, account) — no change.
  ///   - "conflict"  : the id is already bound to a DIFFERENT account/org — REJECTED, binding kept.
  /// A credential id is a stable per-authenticator handle that must map to exactly one account for
  /// its lifetime; silently re-pointing it (the prior upsert behaviour) would let a later
  /// registration of the same id hijack the original account's resolution at `authenticate/verify`
  /// (fix #6). Single-threaded DO => the read+write is atomic.
  async indexWebAuthn(
    credentialId: string,
    orgId: string,
    accountId: string,
  ): Promise<"created" | "exists" | "conflict"> {
    const existing = this.sql
      .exec(`SELECT org_id, account_id FROM webauthn_index WHERE credential_id = ?;`, credentialId)
      .toArray();
    if (existing.length) {
      const row = existing[0];
      if (String(row.org_id) !== orgId || String(row.account_id) !== accountId) return "conflict";
      this.registerOrganization(orgId);
      return "exists";
    }
    this.registerOrganization(orgId);
    this.sql.exec(
      `INSERT INTO webauthn_index (credential_id, org_id, account_id, created_at) VALUES (?,?,?,?);`,
      credentialId, orgId, accountId, now(),
    );
    return "created";
  }

  /// Resolve a WebAuthn credential id -> { orgId, accountId }, or null. Point-key read used by
  /// `authenticate/verify` to find the credential's home org.
  async resolveWebAuthn(credentialId: string): Promise<DirectoryEntry | null> {
    const r = this.sql
      .exec(`SELECT org_id, account_id FROM webauthn_index WHERE credential_id = ?;`, credentialId)
      .toArray();
    if (!r.length) return null;
    return { orgId: String(r[0].org_id), accountId: String(r[0].account_id) };
  }

  /// Drop a credential's index entry (on passkey deletion / deprovision). Idempotent.
  async unindexWebAuthn(credentialId: string): Promise<void> {
    this.sql.exec(`DELETE FROM webauthn_index WHERE credential_id = ?;`, credentialId);
  }

  /// Read a fleet-wide token-bucket state for `bucketKey`, or null if unseen. Point-key read,
  /// off the authenticated hot path (only pre-auth signup/login limiting touches this).
  async getRateBucket(bucketKey: string): Promise<{ tokens: number; updatedAt: number } | null> {
    const r = this.sql
      .exec(`SELECT tokens, updated_at FROM rate_buckets WHERE bucket_key = ?;`, bucketKey)
      .toArray();
    if (!r.length) return null;
    return { tokens: Number(r[0].tokens), updatedAt: Number(r[0].updated_at) };
  }

  /// Upsert a token-bucket state for `bucketKey` (the limiter computes the next state; we just
  /// persist it). Single-threaded DO => the limiter's get→compute→set sequence is atomic per key.
  async setRateBucket(bucketKey: string, tokens: number, updatedAt: number): Promise<void> {
    this.sql.exec(
      `INSERT INTO rate_buckets (bucket_key, tokens, updated_at) VALUES (?,?,?)
       ON CONFLICT(bucket_key) DO UPDATE SET tokens=excluded.tokens, updated_at=excluded.updated_at;`,
      bucketKey, tokens, updatedAt,
    );
  }

  /// ATOMIC check-and-consume for a fleet-wide token bucket. Runs read → token-bucket math →
  /// upsert in ONE DO method call. Because the DO is single-threaded, this whole triple is
  /// serialized per instance, so two concurrent Worker isolates can no longer each read the same
  /// prior state and both admit (the burst-boundary OVER-ADMIT the review flagged). The prior
  /// split `getRateBucket`/`setRateBucket` RPCs left a window between the two network round-trips;
  /// this collapses it. Math is delegated to the shared `consume()` (single source of truth).
  async consumeRateBucket(
    bucketKey: string,
    config: RateLimitConfig,
    cost: number,
    now: number,
  ): Promise<RateLimitResult> {
    const r = this.sql
      .exec(`SELECT tokens, updated_at FROM rate_buckets WHERE bucket_key = ?;`, bucketKey)
      .toArray();
    const prior = r.length ? { tokens: Number(r[0].tokens), updatedAt: Number(r[0].updated_at) } : null;
    const { result, next } = consume(prior, config, cost, now);
    this.sql.exec(
      `INSERT INTO rate_buckets (bucket_key, tokens, updated_at) VALUES (?,?,?)
       ON CONFLICT(bucket_key) DO UPDATE SET tokens=excluded.tokens, updated_at=excluded.updated_at;`,
      bucketKey, next.tokens, next.updatedAt,
    );
    return result;
  }

  // ---- deployment setup flag (auth-spec §4.4) -------------------------------------------

  /// True once first-run setup has completed on this deployment (wizard or legacy bootstrap).
  async getSetupComplete(): Promise<boolean> {
    const r = this.sql.exec(`SELECT v FROM setup_state WHERE k = 'setup_complete';`).toArray();
    return r.length > 0 && Number(r[0].v) === 1;
  }

  /** Atomic deployment-wide claim. The target survives failures, allowing only that owner
   *  to resume partial provisioning. A bounded lease lets a crashed request recover. */
  acquireSetup(orgId: string, email: string, token: string): { status: "acquired"; resumed: boolean } | { status: "setup_complete" | "setup_in_progress" | "setup_target_mismatch" } {
    const done = this.sql.exec(`SELECT v FROM setup_state WHERE k = 'setup_complete';`).toArray();
    if (done.length && Number(done[0].v) === 1) return { status: "setup_complete" };
    const previous = this.sql.exec(`SELECT * FROM setup_claim WHERE singleton = 1;`).toArray()[0];
    if (previous) {
      if (previous.org_id !== orgId || previous.email !== email) return { status: "setup_target_mismatch" };
      if (Number(previous.lease_until) > now()) return { status: "setup_in_progress" };
    }
    this.registerOrganization(orgId);
    this.sql.exec(`INSERT INTO setup_claim (singleton, org_id, email, token, lease_until) VALUES (1, ?, ?, ?, ?)
      ON CONFLICT(singleton) DO UPDATE SET token = excluded.token, lease_until = excluded.lease_until;`, orgId, email, token, now() + 120_000);
    return { status: "acquired", resumed: !!previous };
  }

  releaseSetup(token: string, abandon = false): void {
    if (abandon) this.sql.exec(`DELETE FROM setup_claim WHERE token = ?;`, token);
    else this.sql.exec(`UPDATE setup_claim SET lease_until = 0 WHERE token = ?;`, token);
  }

  getSetupOrgId(): string | null {
    const row = this.sql.exec(`SELECT org_id FROM setup_claim WHERE singleton = 1;`).toArray()[0];
    return row ? String(row.org_id) : null;
  }

  /** Authenticated legacy-owner migration, never a public fresh-workspace claim.
   * Preserve an existing primary org and refuse to steal an in-progress setup. */
  completeLegacySetup(orgId: string, email: string): boolean {
    return this.ctx.storage.transactionSync(() => {
      const done = this.sql.exec(`SELECT v FROM setup_state WHERE k='setup_complete';`).toArray()[0];
      if (done && Number(done.v) === 1) return true;
      const claim = this.sql.exec(`SELECT * FROM setup_claim WHERE singleton=1;`).toArray()[0];
      if (claim && (claim.org_id !== orgId || claim.email !== email || Number(claim.lease_until) > now())) return false;
      this.registerOrganization(orgId);
      this.sql.exec(`INSERT INTO setup_claim (singleton,org_id,email,token,lease_until) VALUES (1,?,?,'legacy-migration',0)
        ON CONFLICT(singleton) DO NOTHING;`, orgId, email);
      this.sql.exec(`INSERT INTO setup_state (k,v,updated_at) VALUES ('setup_complete',1,?)
        ON CONFLICT(k) DO UPDATE SET v=1,updated_at=excluded.updated_at;`, now());
      return true;
    });
  }

  /// Mark setup complete. Idempotent; never un-set by any API (a fresh deploy starts unset).
  async markSetupComplete(): Promise<void> {
    this.sql.exec(
      `INSERT INTO setup_state (k, v, updated_at) VALUES ('setup_complete', 1, ?)
       ON CONFLICT(k) DO UPDATE SET v = 1, updated_at = excluded.updated_at;`,
      now(),
    );
  }

  // ---- deployment auth-provider config (singleton; encrypted-at-rest; auth-config.ts) ----

  private rowToAuthConfig(r: Record<string, SqlStorageValue>): AuthConfigRow {
    return {
      mode: String(r.mode) as AuthConfigRow["mode"],
      preset: r.preset == null ? null : String(r.preset),
      issuer: r.issuer == null ? null : String(r.issuer),
      clientId: r.client_id == null ? null : String(r.client_id),
      allowedDomains: r.allowed_domains == null ? null : String(r.allowed_domains),
      autoProvision: Number(r.auto_provision) === 1,
      providerLabel: r.provider_label == null ? null : String(r.provider_label),
      secretIv: String(r.secret_iv ?? ""),
      secretCiphertext: String(r.secret_ct ?? ""),
      createdAt: Number(r.created_at),
      updatedAt: Number(r.updated_at),
    };
  }

  /// The FULL deployment auth config (incl. the encrypted OIDC client secret) — used server-side to
  /// build the runtime OidcConfig. Null when nothing has been configured (built-in default, or the
  /// deploy `OIDC_*` env fallback). Never serialize this directly to a client; project to the safe
  /// shape in the handler. Point-key read on the global DO, off the authenticated hot path.
  async getAuthConfig(): Promise<AuthConfigRow | null> {
    const rows = this.sql.exec(`SELECT * FROM auth_config WHERE k = 'auth' LIMIT 1;`).toArray();
    return rows.length ? this.rowToAuthConfig(rows[0]) : null;
  }

  /// Upsert the deployment auth config. The gateway seals the OIDC client secret BEFORE calling
  /// this, so the DO never sees a plaintext secret. Single row (`k`='auth'); a PUT upserts.
  async putAuthConfig(input: {
    mode: AuthConfigRow["mode"];
    preset: string | null;
    issuer: string | null;
    clientId: string | null;
    allowedDomains: string | null;
    autoProvision: boolean;
    providerLabel: string | null;
    secretIv: string;
    secretCiphertext: string;
  }): Promise<AuthConfigRow> {
    const ts = now();
    const existing = this.sql.exec(`SELECT created_at FROM auth_config WHERE k = 'auth' LIMIT 1;`).toArray();
    const createdAt = existing.length ? Number(existing[0].created_at) : ts;
    this.sql.exec(
      `INSERT INTO auth_config
         (k,mode,preset,issuer,client_id,allowed_domains,auto_provision,provider_label,secret_iv,secret_ct,created_at,updated_at)
       VALUES ('auth',?,?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(k) DO UPDATE SET
         mode=excluded.mode, preset=excluded.preset, issuer=excluded.issuer,
         client_id=excluded.client_id, allowed_domains=excluded.allowed_domains,
         auto_provision=excluded.auto_provision, provider_label=excluded.provider_label,
         secret_iv=excluded.secret_iv, secret_ct=excluded.secret_ct, updated_at=excluded.updated_at;`,
      input.mode, input.preset, input.issuer, input.clientId, input.allowedDomains,
      input.autoProvision ? 1 : 0, input.providerLabel, input.secretIv, input.secretCiphertext,
      createdAt, ts,
    );
    return {
      mode: input.mode,
      preset: input.preset,
      issuer: input.issuer,
      clientId: input.clientId,
      allowedDomains: input.allowedDomains,
      autoProvision: input.autoProvision,
      providerLabel: input.providerLabel,
      secretIv: input.secretIv,
      secretCiphertext: input.secretCiphertext,
      createdAt,
      updatedAt: ts,
    };
  }

  /// Delete the deployment auth config (revert to built-in / the env OIDC fallback). Returns true if
  /// a row was removed (false ⇒ none existed). Idempotent.
  async deleteAuthConfig(): Promise<boolean> {
    const before = Number(this.sql.exec(`SELECT COUNT(*) AS c FROM auth_config WHERE k = 'auth';`).one().c);
    if (before === 0) return false;
    this.sql.exec(`DELETE FROM auth_config WHERE k = 'auth';`);
    return true;
  }
}
