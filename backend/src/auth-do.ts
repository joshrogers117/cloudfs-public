// SPDX-License-Identifier: AGPL-3.0-or-later
// auth-do.ts — the per-org AUTH Durable Object (CONTRACTS-AUTH.md §0, §1.7).
//
// One instance per org (`idFromName(orgId)`, mirroring OrgDO). It is the credential trust
// boundary: it holds accounts, password/TOTP/WebAuthn credentials, recovery codes, browser
// sessions, service tokens, email/reset tokens, and short-lived challenges for that org.
//
// The auth MODULE lanes (auth-password/session/totp/webauthn/email/service-tokens/signup) never
// touch this DO directly — they depend on the store INTERFACES (CONTRACTS-AUTH.md §2). The
// integration adapters in `auth-stores.ts` translate those interface calls into the RPC methods
// below. This keeps every lane unit-testable against an in-memory fake while production uses a
// real strongly-consistent SQLite-backed DO.
//
// Addressed by `idFromName(orgId)`. Single-threaded + strongly consistent, SQLite-backed — the
// same pattern as OrgDO/FilespaceDO. Crypto/JWT is NOT here (the security lanes own it); this DO
// is pure persistence + atomic single-use semantics (challenge/token consume, recovery codes).

import { DurableObject } from "cloudflare:workers";
import { BackupState, type BackupEnv } from "./backup-state";
import type { Scope } from "./security/auth";
import type {
  Account,
  AccountStatus,
  AccountRole,
  PasswordCredential,
  TotpCredential,
  WebAuthnCredential,
  AuthnTransport,
  BrowserSession,
  ServiceToken,
  EmailTokenRecord,
  EmailTokenPurpose,
  ChallengeRecord,
} from "./security/auth-types";
import type { DeviceCodeRecord, DeviceSessionRecord } from "./security/auth-device";
import { scopesForLogin } from "./security/auth-signup";

export interface AuthDOEnv extends BackupEnv {
  AUTH_DO: DurableObjectNamespace<AuthDO>;
}

function now(): number {
  return Date.now();
}

/// Bump this when the AuthDO table set changes. Tracked in `_schema_migrations` (DO SQLite has
/// no PRAGMA user_version). Existing rows are preserved across version bumps (additive DDL).
export const AUTH_DO_SCHEMA_VERSION = 5;

// ---- device-session pruning (auth-spec §4.5) --------------------------------
// Device codes are 5-min single-use artifacts; keep them 1h past expiry (ample for any in-flight
// exchange + clock skew), then physically delete. Dead device SESSIONS (revoked or expired) are
// kept for 30 days past their last activity so the account-settings devices list can still show
// "revoked" entries for a while, then deleted.
const DEVICE_CODE_PRUNE_GRACE_MS = 60 * 60 * 1000; // 1 h past expiry
const DEVICE_SESSION_PRUNE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 d past last_seen_at

// ---- PERF P3: session-table prune -----------------------------------------
// The access JWS carries `jti == session.id` and lives ≤15 min (DEFAULT_TTL_SECONDS.session).
// Once a session row's `expires_at` is older than that TTL, no live JWS can still name it (any
// JWS minted while it was valid has itself expired), so it never needs to appear in the revoked
// set again and can be physically deleted. `SESSION_PRUNE_GRACE_MS` is the safety margin past the
// JWS TTL we keep dead rows before deleting — it MUST exceed the ≤15-min access-JWS TTL. We use
// 1 hour (4× the TTL) so clock skew / a slightly stale JWS can never slip past the gate.
const SESSION_PRUNE_GRACE_MS = 60 * 60 * 1000; // 1 h, comfortably > the ≤15-min access-JWS TTL
// How often the prune alarm re-arms when there is still session state to watch.
const SESSION_PRUNE_INTERVAL_MS = 60 * 60 * 1000; // hourly

export class AuthDO extends DurableObject<AuthDOEnv> {
  private sql: SqlStorage;
  private readonly backupState: BackupState;

  constructor(ctx: DurableObjectState, env: AuthDOEnv) {
    super(ctx, env);
    this.backupState = new BackupState(ctx.storage, env, 'auth');
    this.sql = this.backupState.guardedSQL;
    ctx.blockConcurrencyWhile(async () => {
      this.migrate();
      this.backupState.initialize();
      // PERF P3: make sure the session-prune alarm is armed after a cold start /
      // hibernation wake. armPruneAlarm() only persists an alarm time (no in-memory
      // state), so it is hibernation-safe and idempotent.
      await this.armPruneAlarm();
    });
  }

  // ---- schema -------------------------------------------------------------


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

  private migrate(): void {
    this.sql.exec(`CREATE TABLE IF NOT EXISTS _schema_migrations (
      id INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);`);
    const current = Number(
      this.sql.exec(`SELECT COALESCE(MAX(id), 0) AS v FROM _schema_migrations;`).one().v,
    );

    // ---- v1: accounts + credentials + sessions + service tokens + email tokens + challenges
    if (current < 1) {
      // §1.1 Account — PK id; unique index on lowercased email (per-org uniqueness; the GLOBAL
      // uniqueness lives in DirectoryDO).
      this.sql.exec(`CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL, org_id TEXT NOT NULL,
        email TEXT NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL,
        status TEXT NOT NULL, email_verified INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL);`);
      this.sql.exec(`CREATE UNIQUE INDEX IF NOT EXISTS accounts_email ON accounts(email);`);
      this.sql.exec(`CREATE UNIQUE INDEX IF NOT EXISTS accounts_user ON accounts(user_id);`);

      // §1.2 Password — one per account (PK account_id). Cost params stored per-row.
      this.sql.exec(`CREATE TABLE IF NOT EXISTS passwords (
        account_id TEXT PRIMARY KEY, algo TEXT NOT NULL,
        n INTEGER NOT NULL, r INTEGER NOT NULL, p INTEGER NOT NULL, dk_len INTEGER NOT NULL,
        salt TEXT NOT NULL, hash TEXT NOT NULL, updated_at INTEGER NOT NULL);`);

      // §1.3 TOTP — one per account (PK account_id).
      this.sql.exec(`CREATE TABLE IF NOT EXISTS totp (
        account_id TEXT PRIMARY KEY, secret TEXT NOT NULL, confirmed INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL, confirmed_at INTEGER);`);

      // §1.3 Recovery codes — many per account; stored sha256-hashed only.
      this.sql.exec(`CREATE TABLE IF NOT EXISTS recovery_codes (
        account_id TEXT NOT NULL, code_hash TEXT NOT NULL, used_at INTEGER,
        PRIMARY KEY (account_id, code_hash));`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS recovery_account ON recovery_codes(account_id);`);

      // §1.4 WebAuthn — PK id; unique credential_id; index account_id.
      this.sql.exec(`CREATE TABLE IF NOT EXISTS webauthn_creds (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL, credential_id TEXT NOT NULL,
        public_key TEXT NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0,
        transports TEXT NOT NULL, label TEXT, created_at INTEGER NOT NULL, last_used_at INTEGER);`);
      this.sql.exec(`CREATE UNIQUE INDEX IF NOT EXISTS webauthn_credid ON webauthn_creds(credential_id);`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS webauthn_account ON webauthn_creds(account_id);`);

      // §1.5 Browser sessions — PK id; index account_id.
      this.sql.exec(`CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL, user_id TEXT NOT NULL, org_id TEXT NOT NULL,
        scopes TEXT NOT NULL, csrf_token TEXT NOT NULL, issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, revoked_at INTEGER);`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS sessions_account ON sessions(account_id);`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS sessions_revoked ON sessions(revoked_at);`);

      // §1.6 Service tokens — PK id; index org_id.
      this.sql.exec(`CREATE TABLE IF NOT EXISTS service_tokens (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL, user_id TEXT NOT NULL, label TEXT NOT NULL,
        scopes TEXT NOT NULL, space_id TEXT, hashed_secret TEXT NOT NULL,
        created_by TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER,
        expires_at INTEGER, revoked INTEGER NOT NULL DEFAULT 0);`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS svc_org ON service_tokens(org_id);`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS svc_revoked ON service_tokens(revoked);`);

      // §1.7 Email/reset tokens — PK id; index token_hash + (account_id, purpose).
      this.sql.exec(`CREATE TABLE IF NOT EXISTS email_tokens (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL, account_id TEXT NOT NULL, email TEXT NOT NULL,
        purpose TEXT NOT NULL, token_hash TEXT NOT NULL, created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL, consumed_at INTEGER);`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS email_tokens_hash ON email_tokens(token_hash);`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS email_tokens_acct ON email_tokens(account_id, purpose);`);

      // Short-lived challenges (login MFA, webauthn register/auth, totp replay guard) — PK id;
      // index account_id; TTL via expires_at.
      this.sql.exec(`CREATE TABLE IF NOT EXISTS challenges (
        id TEXT PRIMARY KEY, account_id TEXT, purpose TEXT NOT NULL, value TEXT NOT NULL,
        expires_at INTEGER NOT NULL);`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS challenges_account ON challenges(account_id);`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS challenges_expiry ON challenges(expires_at);`);

      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (1, ?);`, now());
    }

    // ---- v2: device sessions (auth-spec §4.1) — the Mac app's browser-handoff sign-in.
    //      Additive: two new tables + a nullable column on service_tokens (the daemon-token
    //      cascade link). Existing rows are untouched.
    if (current < 2) {
      // One-time device authorization codes (handoff §2.2/§2.3). Secret stored hashed; PKCE S256
      // challenge bound at approval; single-use via consumed_at; 5-min TTL.
      this.sql.exec(`CREATE TABLE IF NOT EXISTS device_codes (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL, user_id TEXT NOT NULL, org_id TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        device_name TEXT NOT NULL, device_model TEXT,
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        consumed_at INTEGER);`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS device_codes_expiry ON device_codes(expires_at);`);

      // Long-lived per-device sessions (decision B). `id` is ALSO the jti of every access JWS the
      // session mints (isJtiRevoked covers it). refresh_hash = sha256(current opaque secret);
      // prev_refresh_hash/prev_grace_until implement the 60s rotation race window; expires_at is
      // SLIDING (now+400d on every successful rotation).
      this.sql.exec(`CREATE TABLE IF NOT EXISTS device_sessions (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL, user_id TEXT NOT NULL, org_id TEXT NOT NULL,
        scopes TEXT NOT NULL,
        device_name TEXT NOT NULL, device_model TEXT,
        refresh_hash TEXT NOT NULL,
        prev_refresh_hash TEXT, prev_grace_until INTEGER,
        rotation_counter INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER, revoke_reason TEXT);`);
      this.sql.exec(`CREATE INDEX IF NOT EXISTS device_sessions_account ON device_sessions(account_id);`);

      // The daemon service token a device session minted — revoking the device cascades to it
      // (§2.6), and a re-mint soft-expires the prior token for the same device (§2.7).
      this.sql.exec(`ALTER TABLE service_tokens ADD COLUMN device_session_id TEXT;`);

      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (2, ?);`, now());
    }
    if (current < 3) {
      this.sql.exec(`ALTER TABLE accounts ADD COLUMN auth_epoch INTEGER NOT NULL DEFAULT 0;`);
      this.sql.exec(`ALTER TABLE device_codes ADD COLUMN auth_epoch INTEGER NOT NULL DEFAULT 0;`);
      this.sql.exec(`ALTER TABLE challenges ADD COLUMN auth_epoch INTEGER;`);
      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (3, ?);`, now());
    }
    if (current < 4) {
      this.sql.exec(`ALTER TABLE sessions ADD COLUMN auth_epoch INTEGER NOT NULL DEFAULT 0;`);
      // Preserve live sessions on upgrade; v3 already retired old ones atomically.
      this.sql.exec(`UPDATE sessions SET auth_epoch = COALESCE(
        (SELECT auth_epoch FROM accounts WHERE accounts.id = sessions.account_id),0)
        WHERE revoked_at IS NULL;`);
      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (4, ?);`, now());
    }
    if (current < 5) {
      // Only accounts created by the authenticated legacy migration may enroll this way.
      // Existing passwordless/SSO accounts must never become password-reset targets.
      this.sql.exec(`ALTER TABLE accounts ADD COLUMN legacy_enrollment_pending INTEGER NOT NULL DEFAULT 0;`);
      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (5, ?);`, now());
    }
  }

  readiness(): { schemaVersion: number; databaseBytes: number } {
    return { schemaVersion: Number(this.sql.exec(`SELECT MAX(id) AS v FROM _schema_migrations;`).one().v),
      databaseBytes: this.sql.databaseSize };
  }

  private assertAuthEpoch(accountId: string, expected = 0): void {
    const account = this.sql.exec(`SELECT auth_epoch,status FROM accounts WHERE id = ?;`, accountId).toArray()[0];
    // OIDC-only principals can have no built-in credential account.
    if (account && (Number(account.auth_epoch) !== expected || account.status !== "active")) {
      throw new Error("authentication_changed");
    }
  }

  // ---- row mappers --------------------------------------------------------

  private rowToAccount(r: Record<string, SqlStorageValue>): Account {
    return {
      id: String(r.id),
      userId: String(r.user_id),
      orgId: String(r.org_id),
      email: String(r.email),
      displayName: String(r.display_name),
      role: String(r.role) as AccountRole,
      status: String(r.status) as AccountStatus,
      emailVerified: Number(r.email_verified) === 1,
      createdAt: Number(r.created_at),
      authEpoch: Number(r.auth_epoch ?? 0),
    };
  }

  private rowToSession(r: Record<string, SqlStorageValue>): BrowserSession {
    return {
      authEpoch: Number(r.auth_epoch ?? 0),
      id: String(r.id),
      accountId: String(r.account_id),
      userId: String(r.user_id),
      orgId: String(r.org_id),
      scopes: JSON.parse(String(r.scopes)) as Scope[],
      csrfToken: String(r.csrf_token),
      issuedAt: Number(r.issued_at),
      expiresAt: Number(r.expires_at),
      lastSeenAt: Number(r.last_seen_at),
      revokedAt: r.revoked_at === null ? null : Number(r.revoked_at),
    };
  }

  private rowToServiceToken(r: Record<string, SqlStorageValue>): ServiceToken {
    return {
      id: String(r.id),
      orgId: String(r.org_id),
      userId: String(r.user_id),
      label: String(r.label),
      scopes: JSON.parse(String(r.scopes)) as Scope[],
      spaceId: r.space_id === null ? null : String(r.space_id),
      hashedSecret: String(r.hashed_secret),
      createdByUserId: String(r.created_by),
      createdAt: Number(r.created_at),
      lastUsedAt: r.last_used_at === null ? null : Number(r.last_used_at),
      expiresAt: r.expires_at === null ? null : Number(r.expires_at),
      revoked: Number(r.revoked) === 1,
      deviceSessionId:
        r.device_session_id === null || r.device_session_id === undefined
          ? null
          : String(r.device_session_id),
    };
  }

  private rowToDeviceCode(r: Record<string, SqlStorageValue>): DeviceCodeRecord {
    return {
      authEpoch: Number(r.auth_epoch ?? 0),
      id: String(r.id),
      accountId: String(r.account_id),
      userId: String(r.user_id),
      orgId: String(r.org_id),
      secretHash: String(r.secret_hash),
      codeChallenge: String(r.code_challenge),
      deviceName: String(r.device_name),
      deviceModel: r.device_model === null ? null : String(r.device_model),
      createdAt: Number(r.created_at),
      expiresAt: Number(r.expires_at),
      consumedAt: r.consumed_at === null ? null : Number(r.consumed_at),
    };
  }

  private rowToDeviceSession(r: Record<string, SqlStorageValue>): DeviceSessionRecord {
    return {
      id: String(r.id),
      accountId: String(r.account_id),
      userId: String(r.user_id),
      orgId: String(r.org_id),
      scopes: JSON.parse(String(r.scopes)) as Scope[],
      deviceName: String(r.device_name),
      deviceModel: r.device_model === null ? null : String(r.device_model),
      refreshHash: String(r.refresh_hash),
      prevRefreshHash: r.prev_refresh_hash === null ? null : String(r.prev_refresh_hash),
      prevGraceUntil: r.prev_grace_until === null ? null : Number(r.prev_grace_until),
      rotationCounter: Number(r.rotation_counter),
      createdAt: Number(r.created_at),
      lastSeenAt: Number(r.last_seen_at),
      expiresAt: Number(r.expires_at),
      revokedAt: r.revoked_at === null ? null : Number(r.revoked_at),
      revokeReason: r.revoke_reason === null ? null : String(r.revoke_reason),
    };
  }

  private rowToEmailToken(r: Record<string, SqlStorageValue>): EmailTokenRecord {
    return {
      id: String(r.id),
      orgId: String(r.org_id),
      accountId: String(r.account_id),
      email: String(r.email),
      purpose: String(r.purpose) as EmailTokenPurpose,
      tokenHash: String(r.token_hash),
      createdAt: Number(r.created_at),
      expiresAt: Number(r.expires_at),
      consumedAt: r.consumed_at === null ? null : Number(r.consumed_at),
    };
  }

  private rowToWebAuthn(r: Record<string, SqlStorageValue>): WebAuthnCredential {
    return {
      id: String(r.id),
      accountId: String(r.account_id),
      credentialId: String(r.credential_id),
      publicKey: String(r.public_key),
      signCount: Number(r.sign_count),
      transports: JSON.parse(String(r.transports)) as AuthnTransport[],
      label: r.label === null ? null : String(r.label),
      createdAt: Number(r.created_at),
      lastUsedAt: r.last_used_at === null ? null : Number(r.last_used_at),
    };
  }

  // ---- accounts -----------------------------------------------------------

  async createAccount(input: {
    orgId: string;
    userId: string;
    email: string;
    displayName: string;
    role: AccountRole;
    emailVerified?: boolean;
  }): Promise<Account> {
    const email = input.email.trim().toLowerCase();
    const dupe = this.sql.exec(`SELECT id FROM accounts WHERE email = ?;`, email).toArray();
    if (dupe.length) {
      // Local (per-org) dupe guard; the GLOBAL guard is DirectoryDO.claim. The integration
      // adapter claims the directory FIRST, so this is defense-in-depth.
      const e = new Error("email_taken");
      (e as { code?: string }).code = "email_taken";
      throw e;
    }
    const acc: Account = {
      id: `acc-${crypto.randomUUID()}`,
      userId: input.userId,
      orgId: input.orgId,
      email,
      displayName: input.displayName,
      role: input.role,
      status: "active",
      emailVerified: input.emailVerified ?? false,
      createdAt: now(),
    };
    this.sql.exec(
      `INSERT INTO accounts (id,user_id,org_id,email,display_name,role,status,email_verified,created_at)
       VALUES (?,?,?,?,?,?,?,?,?);`,
      acc.id, acc.userId, acc.orgId, acc.email, acc.displayName, acc.role, acc.status,
      acc.emailVerified ? 1 : 0, acc.createdAt,
    );
    return acc;
  }

  async getAccount(accountId: string): Promise<Account | null> {
    const r = this.sql.exec(`SELECT * FROM accounts WHERE id = ?;`, accountId).toArray();
    return r.length ? this.rowToAccount(r[0] as any) : null;
  }

  async provisionSetupAccount(input: { orgId: string; userId: string; email: string; displayName: string }): Promise<Account | null> {
    const rows = this.sql.exec(`SELECT * FROM accounts WHERE email = ?;`, input.email).toArray();
    if (rows.length) {
      const account = this.rowToAccount(rows[0]);
      return account.userId === input.userId && account.role === "owner" && account.status === "active" ? account : null;
    }
    return this.createAccount({ ...input, role: "owner", emailVerified: true });
  }

  async getAccountByEmail(emailLower: string): Promise<Account | null> {
    const r = this.sql
      .exec(`SELECT * FROM accounts WHERE email = ?;`, emailLower.trim().toLowerCase())
      .toArray();
    return r.length ? this.rowToAccount(r[0] as any) : null;
  }

  provisionLegacyOwner(input: { orgId: string; userId: string; email: string; displayName: string }): { account: Account; pending: boolean } | null {
    return this.ctx.storage.transactionSync(() => {
      const email = input.email.trim().toLowerCase();
      const rows = this.sql.exec(`SELECT * FROM accounts WHERE email=? OR user_id=?;`, email, input.userId).toArray();
      if (rows.length) {
        if (rows.length !== 1) return null;
        const account = this.rowToAccount(rows[0]);
        if (account.userId !== input.userId || account.email !== email || account.orgId !== input.orgId ||
            account.role !== 'owner' || account.status !== 'active') return null;
        return { account, pending: Number(rows[0].legacy_enrollment_pending) === 1 };
      }
      const id = `acc-${crypto.randomUUID()}`;
      this.sql.exec(`INSERT INTO accounts (id,user_id,org_id,email,display_name,role,status,email_verified,created_at,legacy_enrollment_pending)
        VALUES (?,?,?,?,?,'owner','active',1,?,1);`, id, input.userId, input.orgId, email, input.displayName, now());
      return { account: this.rowToAccount(this.sql.exec(`SELECT * FROM accounts WHERE id=?;`, id).one()), pending: true };
    });
  }

  /** Token consumption, initial password and enrollment closure are one transaction.
   * The caller has verified the secret; repeat its durable predicates after hashing. */
  completeLegacyEnrollment(token: EmailTokenRecord, cred: PasswordCredential): boolean {
    return this.ctx.storage.transactionSync(() => {
      const row = this.sql.exec(`SELECT * FROM accounts WHERE id=? AND email=? AND org_id=?
        AND status='active' AND role='owner' AND legacy_enrollment_pending=1;`,
        cred.accountId, token.email, token.orgId).toArray()[0];
      if (!row || token.accountId !== cred.accountId) return false;
      for (const table of ['passwords', 'totp', 'webauthn_creds']) {
        if (this.sql.exec(`SELECT 1 FROM ${table} WHERE account_id=? LIMIT 1;`, cred.accountId).toArray().length) return false;
      }
      const consumed = this.sql.exec(`UPDATE email_tokens SET consumed_at=? WHERE id=? AND account_id=?
        AND token_hash=? AND email=? AND purpose='legacy_enrollment' AND consumed_at IS NULL AND expires_at>?
        RETURNING id;`, now(), token.id, cred.accountId, token.tokenHash, token.email, now()).toArray();
      if (!consumed.length) return false;
      this.sql.exec(`INSERT INTO passwords (account_id,algo,n,r,p,dk_len,salt,hash,updated_at) VALUES (?,?,?,?,?,?,?,?,?);`,
        cred.accountId, cred.algo, cred.N, cred.r, cred.p, cred.dkLen, cred.salt, cred.hash, cred.updatedAt);
      this.sql.exec(`UPDATE accounts SET legacy_enrollment_pending=0 WHERE id=?;`, cred.accountId);
      this.sql.exec(`UPDATE email_tokens SET consumed_at=? WHERE account_id=? AND purpose='legacy_enrollment' AND consumed_at IS NULL;`, now(), cred.accountId);
      return true;
    });
  }

  claimOperatorRecovery(id: string, accountId: string, expiresAt: number): boolean {
    return this.sql.exec(`INSERT INTO challenges (id,account_id,purpose,value,expires_at)
      VALUES (?,?,'operator_recovery','consumed',?) ON CONFLICT(id) DO NOTHING RETURNING id;`,
      id, accountId, expiresAt).toArray().length === 1;
  }

  async getAccountByUserId(userId: string): Promise<Account | null> {
    const r = this.sql.exec(`SELECT * FROM accounts WHERE user_id = ?;`, userId).toArray();
    return r.length ? this.rowToAccount(r[0] as any) : null;
  }

  async setEmailVerified(accountId: string, verified: boolean): Promise<void> {
    this.sql.exec(`UPDATE accounts SET email_verified = ? WHERE id = ?;`, verified ? 1 : 0, accountId);
  }

  confirmEmailAddress(accountId: string, email: string): boolean {
    return this.ctx.storage.transactionSync(() => {
      const row = this.sql.exec(`SELECT * FROM accounts WHERE id=? AND email=? AND status='active';`, accountId, email).toArray()[0];
      if (!row) return false;
      this.sql.exec(`UPDATE accounts SET email_verified=1 WHERE id=?;`, accountId);
      this.sql.exec(`UPDATE sessions SET scopes=? WHERE account_id=? AND revoked_at IS NULL;`,
        JSON.stringify(scopesForLogin(String(row.role) as AccountRole, true)), accountId);
      return true;
    });
  }

  /// Self-service profile update: change `displayName` and/or `email` on an existing account. Only
  /// the keys present in `patch` are touched. A changed email is re-canonicalized (lowercased) and
  /// re-claims this account's directory entry is the gateway's job; here the local unique-email
  /// index is the per-org guard (it rejects collisions inside this org). Changing the email RESETS
  /// `email_verified` to 0 — the new address is unproven until re-verified. Returns the updated row
  /// (or null if the account is unknown).
  async setAccountProfile(
    accountId: string,
    patch: { displayName?: string; email?: string },
  ): Promise<Account | null> {
    const current = await this.getAccount(accountId);
    if (!current) return null;
    const sets: string[] = [];
    const args: SqlStorageValue[] = [];
    if (patch.displayName !== undefined) {
      sets.push("display_name = ?");
      args.push(patch.displayName);
    }
    if (patch.email !== undefined) {
      const email = patch.email.trim().toLowerCase();
      if (email !== current.email) {
        const dupe = this.sql
          .exec(`SELECT id FROM accounts WHERE email = ? AND id <> ?;`, email, accountId)
          .toArray();
        if (dupe.length) {
          const e = new Error("email_taken");
          (e as { code?: string }).code = "email_taken";
          throw e;
        }
        sets.push("email = ?", "email_verified = 0");
        args.push(email);
      }
    }
    if (sets.length) {
      this.sql.exec(`UPDATE accounts SET ${sets.join(", ")} WHERE id = ?;`, ...args, accountId);
      if (patch.email && patch.email.trim().toLowerCase() !== current.email) {
        this.sql.exec(`UPDATE email_tokens SET consumed_at=? WHERE account_id=? AND consumed_at IS NULL;`, now(), accountId);
      }
    }
    return this.getAccount(accountId);
  }

  async setStatus(accountId: string, status: AccountStatus): Promise<void> {
    this.sql.exec(`UPDATE accounts SET auth_epoch = auth_epoch + CASE WHEN status <> ? AND ? <> 'active' THEN 1 ELSE 0 END,
      status = ? WHERE id = ?;`, status, status, status, accountId);
  }

  async setRole(accountId: string, role: AccountRole): Promise<void> {
    this.sql.exec(`UPDATE accounts SET role = ? WHERE id = ?;`, role, accountId);
  }

  // ---- password credential ------------------------------------------------

  async getPassword(accountId: string): Promise<PasswordCredential | null> {
    const r = this.sql.exec(`SELECT * FROM passwords WHERE account_id = ?;`, accountId).toArray();
    if (!r.length) return null;
    const row = r[0];
    return {
      accountId: String(row.account_id),
      algo: String(row.algo) as "scrypt",
      N: Number(row.n),
      r: Number(row.r),
      p: Number(row.p),
      dkLen: Number(row.dk_len),
      salt: String(row.salt),
      hash: String(row.hash),
      updatedAt: Number(row.updated_at),
    };
  }

  async putPassword(cred: PasswordCredential): Promise<void> {
    this.sql.exec(
      `INSERT INTO passwords (account_id,algo,n,r,p,dk_len,salt,hash,updated_at)
       VALUES (?,?,?,?,?,?,?,?,?)
       ON CONFLICT(account_id) DO UPDATE SET algo=excluded.algo, n=excluded.n, r=excluded.r,
         p=excluded.p, dk_len=excluded.dk_len, salt=excluded.salt, hash=excluded.hash,
         updated_at=excluded.updated_at;`,
      cred.accountId, cred.algo, cred.N, cred.r, cred.p, cred.dkLen, cred.salt, cred.hash, cred.updatedAt,
    );
  }

  async putPasswordAtEpoch(cred: PasswordCredential, authEpoch: number): Promise<void> {
    this.assertAuthEpoch(cred.accountId, authEpoch);
    await this.putPassword(cred);
  }

  /// Atomically replace a password and retire every authorization derived from
  /// the old sign-in generation. A later stale login/code completion is rejected
  /// by the same durable generation before it can create a new session.
  replacePasswordAndRetireSessions(cred: PasswordCredential, expectedEpoch: number,
                                  keepSessionId?: string, expectedEmail?: string): string[] {
    return this.ctx.storage.transactionSync(() => {
      this.assertAuthEpoch(cred.accountId, expectedEpoch);
      if (expectedEmail !== undefined && !this.sql.exec(`SELECT 1 FROM accounts WHERE id=? AND email=?;`,
          cred.accountId, expectedEmail).toArray().length) throw new Error("authentication_changed");
      const t = now();
      this.sql.exec(`UPDATE accounts SET auth_epoch = auth_epoch + 1, legacy_enrollment_pending = 0 WHERE id = ?;`, cred.accountId);
      this.sql.exec(`INSERT INTO passwords (account_id,algo,n,r,p,dk_len,salt,hash,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET algo=excluded.algo,
        n=excluded.n,r=excluded.r,p=excluded.p,dk_len=excluded.dk_len,salt=excluded.salt,
        hash=excluded.hash,updated_at=excluded.updated_at;`,
        cred.accountId,cred.algo,cred.N,cred.r,cred.p,cred.dkLen,cred.salt,cred.hash,cred.updatedAt);
      const sessions = this.sql.exec(`UPDATE sessions SET revoked_at = ?
        WHERE account_id = ? AND revoked_at IS NULL AND id <> ? RETURNING id;`,
        t, cred.accountId, keepSessionId ?? "").toArray();
      if (keepSessionId) this.sql.exec(`UPDATE sessions SET auth_epoch = ?
        WHERE id = ? AND account_id = ? AND revoked_at IS NULL;`, expectedEpoch + 1, keepSessionId, cred.accountId);
      const devices = this.sql.exec(`UPDATE device_sessions SET revoked_at = ?,revoke_reason = 'password_changed'
        WHERE account_id = ? AND revoked_at IS NULL RETURNING id;`, t, cred.accountId).toArray();
      const tokens = this.sql.exec(`UPDATE service_tokens SET revoked = 1 WHERE revoked = 0
        AND device_session_id IN (SELECT id FROM device_sessions WHERE account_id = ?) RETURNING id;`,
        cred.accountId).toArray();
      this.sql.exec(`UPDATE device_codes SET consumed_at = ? WHERE account_id = ? AND consumed_at IS NULL;`, t, cred.accountId);
      // Keep consumed operator assertions until expiry so a password reset cannot reopen one.
      this.sql.exec(`DELETE FROM challenges WHERE account_id = ? AND purpose <> 'operator_recovery';`, cred.accountId);
      this.sql.exec(`UPDATE email_tokens SET consumed_at = ? WHERE account_id = ?
        AND purpose = 'password_reset' AND consumed_at IS NULL;`, t, cred.accountId);
      return [...sessions, ...devices, ...tokens].map(r => String(r.id));
    });
  }

  provisionSetupPassword(cred: PasswordCredential): void {
    this.sql.exec(`INSERT INTO passwords (account_id,algo,n,r,p,dk_len,salt,hash,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(account_id) DO NOTHING;`,
      cred.accountId, cred.algo, cred.N, cred.r, cred.p, cred.dkLen, cred.salt, cred.hash, cred.updatedAt);
  }

  async deletePassword(accountId: string): Promise<void> {
    this.sql.exec(`DELETE FROM passwords WHERE account_id = ?;`, accountId);
  }

  // ---- TOTP ---------------------------------------------------------------

  async beginTotpEnrollment(cred: TotpCredential): Promise<boolean> {
    return this.sql.exec(`INSERT INTO totp (account_id,secret,confirmed,created_at,confirmed_at)
      VALUES (?,?,0,?,NULL) ON CONFLICT(account_id) DO UPDATE
      SET secret=excluded.secret,confirmed=0,created_at=excluded.created_at,confirmed_at=NULL
      WHERE totp.confirmed = 0 RETURNING account_id;`, cred.accountId, cred.secret, cred.createdAt).toArray().length === 1;
  }

  async completeTotpEnrollment(accountId: string, secret: string, confirmedAt: number,
      step: number, expiresAt: number, recoveryHashes: string[]): Promise<boolean> {
    return this.ctx.storage.transactionSync(() => {
      const won = this.sql.exec(`UPDATE totp SET confirmed=1,confirmed_at=?
        WHERE account_id=? AND secret=? AND confirmed=0 RETURNING account_id;`,
        confirmedAt, accountId, secret).toArray();
      if (!won.length) return false;
      this.sql.exec(`DELETE FROM recovery_codes WHERE account_id=?;`, accountId);
      for (const hash of recoveryHashes) {
        this.sql.exec(`INSERT INTO recovery_codes (account_id,code_hash,used_at) VALUES (?,?,NULL);`, accountId, hash);
      }
      this.sql.exec(`INSERT INTO challenges (id,account_id,purpose,value,expires_at)
        VALUES (?,?,'totp_used',?,?) ON CONFLICT(id) DO UPDATE SET expires_at=excluded.expires_at;`,
        `totp_used:${accountId}:${step}`, accountId, String(step), expiresAt);
      return true;
    });
  }

  async getTotp(accountId: string): Promise<TotpCredential | null> {
    const r = this.sql.exec(`SELECT * FROM totp WHERE account_id = ?;`, accountId).toArray();
    if (!r.length) return null;
    const row = r[0];
    return {
      accountId: String(row.account_id),
      secret: String(row.secret),
      confirmed: Number(row.confirmed) === 1,
      createdAt: Number(row.created_at),
      confirmedAt: row.confirmed_at === null ? null : Number(row.confirmed_at),
    };
  }

  async putTotp(cred: TotpCredential): Promise<void> {
    this.sql.exec(
      `INSERT INTO totp (account_id,secret,confirmed,created_at,confirmed_at)
       VALUES (?,?,?,?,?)
       ON CONFLICT(account_id) DO UPDATE SET secret=excluded.secret, confirmed=excluded.confirmed,
         created_at=excluded.created_at, confirmed_at=excluded.confirmed_at;`,
      cred.accountId, cred.secret, cred.confirmed ? 1 : 0, cred.createdAt, cred.confirmedAt,
    );
  }

  async confirmTotp(accountId: string, confirmedAt: number): Promise<void> {
    this.sql.exec(`UPDATE totp SET confirmed = 1, confirmed_at = ? WHERE account_id = ?;`, confirmedAt, accountId);
  }

  async deleteTotp(accountId: string): Promise<void> {
    this.sql.exec(`DELETE FROM totp WHERE account_id = ?;`, accountId);
    this.sql.exec(`DELETE FROM recovery_codes WHERE account_id = ?;`, accountId);
  }

  async putRecoveryCodes(accountId: string, codeHashes: string[]): Promise<void> {
    // Replace any prior set so re-confirming reissues a clean batch.
    this.sql.exec(`DELETE FROM recovery_codes WHERE account_id = ?;`, accountId);
    for (const h of codeHashes) {
      this.sql.exec(
        `INSERT OR IGNORE INTO recovery_codes (account_id, code_hash, used_at) VALUES (?,?,NULL);`,
        accountId, h,
      );
    }
  }

  /// Atomic single-use consume: marks the (account, hash) used IFF it exists and is unused.
  /// Returns true only if THIS call flipped an unused code to used.
  async consumeRecoveryCode(accountId: string, codeHash: string, usedAt: number): Promise<boolean> {
    return this.sql.exec(
      `UPDATE recovery_codes SET used_at = ? WHERE account_id = ? AND code_hash = ? AND used_at IS NULL RETURNING code_hash;`,
      usedAt, accountId, codeHash,
    ).toArray().length === 1;
  }

  // ---- WebAuthn -----------------------------------------------------------

  async listWebAuthn(accountId: string): Promise<WebAuthnCredential[]> {
    return this.sql
      .exec(`SELECT * FROM webauthn_creds WHERE account_id = ? ORDER BY created_at;`, accountId)
      .toArray()
      .map((r) => this.rowToWebAuthn(r as any));
  }

  async getWebAuthnByCredentialId(credentialId: string): Promise<WebAuthnCredential | null> {
    const r = this.sql.exec(`SELECT * FROM webauthn_creds WHERE credential_id = ?;`, credentialId).toArray();
    return r.length ? this.rowToWebAuthn(r[0] as any) : null;
  }

  async putWebAuthn(cred: WebAuthnCredential): Promise<void> {
    this.sql.exec(
      `INSERT INTO webauthn_creds (id,account_id,credential_id,public_key,sign_count,transports,label,created_at,last_used_at)
       VALUES (?,?,?,?,?,?,?,?,?)
       ON CONFLICT(id) DO UPDATE SET sign_count=excluded.sign_count, label=excluded.label,
         last_used_at=excluded.last_used_at;`,
      cred.id, cred.accountId, cred.credentialId, cred.publicKey, cred.signCount,
      JSON.stringify(cred.transports), cred.label, cred.createdAt, cred.lastUsedAt,
    );
  }

  async updateWebAuthnSignCount(id: string, signCount: number, lastUsedAt: number): Promise<void> {
    this.sql.exec(
      `UPDATE webauthn_creds SET sign_count = ?, last_used_at = ? WHERE id = ?;`,
      signCount, lastUsedAt, id,
    );
  }

  async deleteWebAuthn(id: string): Promise<void> {
    this.sql.exec(`DELETE FROM webauthn_creds WHERE id = ?;`, id);
  }

  // ---- browser sessions ---------------------------------------------------

  async createSession(input: {
    authEpoch?: number;
    accountId: string;
    userId: string;
    orgId: string;
    scopes: Scope[];
    csrfToken: string;
    expiresAt: number;
  }): Promise<BrowserSession> {
    this.assertAuthEpoch(input.accountId, input.authEpoch);
    const t = now();
    const session: BrowserSession = {
      authEpoch: input.authEpoch ?? 0,
      id: `sess-${crypto.randomUUID()}`,
      accountId: input.accountId,
      userId: input.userId,
      orgId: input.orgId,
      scopes: input.scopes,
      csrfToken: input.csrfToken,
      issuedAt: t,
      expiresAt: input.expiresAt,
      lastSeenAt: t,
      revokedAt: null,
    };
    this.sql.exec(
      `INSERT INTO sessions (id,account_id,user_id,org_id,scopes,csrf_token,issued_at,expires_at,last_seen_at,revoked_at,auth_epoch)
       VALUES (?,?,?,?,?,?,?,?,?,NULL,?);`,
      session.id, session.accountId, session.userId, session.orgId, JSON.stringify(session.scopes),
      session.csrfToken, session.issuedAt, session.expiresAt, session.lastSeenAt, session.authEpoch ?? 0,
    );
    // PERF P3: a new session is the thing that eventually becomes a dead row — make
    // sure the prune alarm is (re-)armed so the table can't grow without bound.
    await this.armPruneAlarm();
    return session;
  }

  async getSession(sessionId: string): Promise<BrowserSession | null> {
    const r = this.sql.exec(`SELECT * FROM sessions WHERE id = ?;`, sessionId).toArray();
    return r.length ? this.rowToSession(r[0] as any) : null;
  }

  async touchSession(sessionId: string, lastSeenAt: number): Promise<void> {
    this.sql.exec(`UPDATE sessions SET last_seen_at = ? WHERE id = ?;`, lastSeenAt, sessionId);
  }

  async revokeSession(sessionId: string): Promise<void> {
    this.sql.exec(
      `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL;`,
      now(), sessionId,
    );
  }

  async listSessions(accountId: string): Promise<BrowserSession[]> {
    return this.sql
      .exec(`SELECT * FROM sessions WHERE account_id = ? ORDER BY issued_at DESC;`, accountId)
      .toArray()
      .map((r) => this.rowToSession(r as any));
  }

  /// Re-scope an account's LIVE (non-revoked) sessions in place. Used to UPGRADE scopes the moment
  /// the account verifies its email (CONTRACTS-AUTH.md §4.2 gate, approach (b)): the user stays
  /// signed in but their reduced read-only session is lifted to full role scopes without a re-login.
  /// `scopes` is stored as the same JSON the session row uses; the re-minted 15-min JWS picks it up.
  async updateSessionsScopesForAccount(accountId: string, scopes: Scope[]): Promise<void> {
    this.sql.exec(
      `UPDATE sessions SET scopes = ? WHERE account_id = ? AND revoked_at IS NULL;`,
      JSON.stringify(scopes), accountId,
    );
  }

  /// The revoked-jti set the gateway folds into VerifyOptions.revokedJtis. We include both
  /// explicitly-revoked AND expired sessions: once the row is dead, its residual ≤15-min JWS
  /// (jti == session.id) must be rejected on the stateless hot path too.
  ///
  /// PERF P3: the prune alarm only deletes rows whose `expires_at` is already older than the
  /// access-JWS TTL + grace, i.e. rows for which NO live JWS can still be presented. So every jti
  /// that could still appear on the wire is still returned here — security is unchanged, the set
  /// just stops accumulating ancient, unpresentable ids.
  async revokedSessionJtis(): Promise<string[]> {
    const t = now();
    return this.sql
      .exec(`SELECT id FROM sessions WHERE revoked_at IS NOT NULL OR expires_at <= ?;`, t)
      .toArray()
      .map((r) => String(r.id));
  }

  /// Audit B21 — POINT-KEYED revocation check for ONE jti (replaces the two full-list transfers the
  /// per-request gate used to do). A jti is the id of either a browser session (jti == session.id)
  /// or a service token (jti == service_token.id), so we check BOTH tables for the single id. A
  /// session is "revoked" if it's explicitly revoked OR already expired (its residual ≤15-min JWS
  /// must still be rejected on the stateless hot path); a service token is revoked iff `revoked=1`.
  /// Returns the boolean only — no set is materialized, so this is O(1) index lookups regardless of
  /// how many sessions/tokens the org has. The gateway folds this into the same fail-closed decision
  /// it made before; security is unchanged (the prune alarm only deletes rows for which NO live JWS
  /// can still be presented, so a still-presentable jti is always still found here).
  async isJtiRevoked(jti: string): Promise<boolean> {
    const t = now();
    const sess = this.sql
      .exec(`SELECT 1 FROM sessions WHERE id = ? AND (revoked_at IS NOT NULL OR expires_at <= ?) LIMIT 1;`, jti, t)
      .toArray();
    if (sess.length) return true;
    // Service tokens: explicit revoke OR record expiry. The record expiry matters for the
    // device-daemon SOFT CUTOVER (auth-spec §2.7): a re-mint shortens the prior token's
    // `expires_at` to now+10min WITHOUT touching its JWS exp, so the gate must enforce the
    // record's expiry server-side for the cutover to bite.
    const svc = this.sql
      .exec(
        `SELECT 1 FROM service_tokens WHERE id = ? AND (revoked = 1 OR (expires_at IS NOT NULL AND expires_at <= ?)) LIMIT 1;`,
        jti, t,
      )
      .toArray();
    if (svc.length) return true;
    const deadParent = this.sql.exec(`SELECT 1 FROM service_tokens AS token
      LEFT JOIN device_sessions AS device ON device.id = token.device_session_id
      WHERE token.id = ? AND token.device_session_id IS NOT NULL
      AND (device.id IS NULL OR device.revoked_at IS NOT NULL OR device.expires_at <= ?) LIMIT 1;`, jti, t).toArray();
    if (deadParent.length) return true;
    // Device sessions (auth-spec §4.2): the device access JWS carries jti == device_sessions.id,
    // so a revoked or expired device session kills its residual ≤15-min access token through the
    // SAME gate — zero new gateway code.
    const dev = this.sql
      .exec(
        `SELECT 1 FROM device_sessions WHERE id = ? AND (revoked_at IS NOT NULL OR expires_at <= ?) LIMIT 1;`,
        jti, t,
      )
      .toArray();
    return dev.length > 0;
  }

  // ---- PERF P3: session-table prune (alarm) -------------------------------

  /// Arm the periodic prune alarm. Idempotent + hibernation-safe (it persists ONLY an alarm time,
  /// no in-memory state) and follows FilespaceDO.armAlarm: setAlarm replaces any existing alarm, so
  /// we only set when there's no sooner alarm pending. When the `sessions` table is empty there is
  /// nothing left to prune, so we clear any pending alarm (mirroring FilespaceDO.armAlarm's
  /// deleteAlarm when there are no candidates) — a quiet org schedules no work until its next
  /// session is created.
  private async armPruneAlarm(): Promise<void> {
    if (this.backupState.isBlocked()) { await this.ctx.storage.deleteAlarm(); return; }
    // auth-spec §4.5: device codes + device sessions are pruned by the same alarm, so they must
    // count toward the arm condition too (a device-only org still schedules cleanup).
    const count = Number(
      this.sql
        .exec(
          `SELECT (SELECT COUNT(*) FROM sessions)
                + (SELECT COUNT(*) FROM device_codes)
                + (SELECT COUNT(*) FROM device_sessions) AS n;`,
        )
        .one().n,
    );
    if (count === 0) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    const next = now() + SESSION_PRUNE_INTERVAL_MS;
    const existing = await this.ctx.storage.getAlarm();
    if (existing === null || next < existing) {
      await this.ctx.storage.setAlarm(next);
    }
  }

  /// Physically delete truly-dead session rows: those expired longer ago than the access-JWS TTL +
  /// grace. Revoked-but-not-yet-expired rows are KEPT (the revocation gate still needs them until
  /// they expire). Returns the number of rows deleted (used by tests). Exposed as a method so the
  /// alarm and tests can both drive it.
  private pruneDeadSessions(at: number): number {
    const cutoff = at - SESSION_PRUNE_GRACE_MS;
    const before = Number(this.sql.exec(`SELECT COUNT(*) AS n FROM sessions;`).one().n);
    this.sql.exec(`DELETE FROM sessions WHERE expires_at <= ?;`, cutoff);
    const after = Number(this.sql.exec(`SELECT COUNT(*) AS n FROM sessions;`).one().n);
    return before - after;
  }

  /// auth-spec §4.5: prune long-dead device artifacts. Codes go 1h past their 5-min expiry (no
  /// live exchange can still present one). Dead device sessions (revoked OR expired) are kept for
  /// 30 days past last activity so the devices list can show "revoked" entries for a while, then
  /// deleted — by which point no ≤15-min access JWS naming them can still exist, so dropping them
  /// from the `isJtiRevoked` set is safe (same argument as pruneDeadSessions).
  private pruneDeadDeviceState(at: number): void {
    this.sql.exec(`DELETE FROM device_codes WHERE expires_at <= ?;`, at - DEVICE_CODE_PRUNE_GRACE_MS);
    this.sql.exec(
      `DELETE FROM device_sessions
       WHERE (revoked_at IS NOT NULL OR expires_at <= ?) AND last_seen_at <= ?;`,
      at, at - DEVICE_SESSION_PRUNE_RETENTION_MS,
    );
  }

  async alarm(): Promise<void> {
    if (this.backupState.isBlocked()) { await this.ctx.storage.deleteAlarm(); return; }
    const t = now();
    this.pruneDeadSessions(t);
    this.pruneDeadDeviceState(t);
    // Re-arm for the next tick (alarms are one-shot). armPruneAlarm() no-ops if the tables are now
    // empty, so a quiet org stops scheduling work until its next session is created.
    await this.armPruneAlarm();
  }

  // ---- service tokens -----------------------------------------------------

  async createServiceToken(rec: ServiceToken): Promise<void> {
    if (rec.deviceSessionId) {
      const live = this.sql.exec(`SELECT 1 FROM device_sessions WHERE id = ? AND user_id = ?
        AND org_id = ? AND revoked_at IS NULL AND expires_at > ?;`,
        rec.deviceSessionId, rec.userId, rec.orgId, now()).toArray();
      if (!live.length) throw new Error("device_revoked");
    }
    this.sql.exec(
      `INSERT INTO service_tokens (id,org_id,user_id,label,scopes,space_id,hashed_secret,created_by,created_at,last_used_at,expires_at,revoked,device_session_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);`,
      rec.id, rec.orgId, rec.userId, rec.label, JSON.stringify(rec.scopes), rec.spaceId,
      rec.hashedSecret, rec.createdByUserId, rec.createdAt, rec.lastUsedAt, rec.expiresAt,
      rec.revoked ? 1 : 0, rec.deviceSessionId ?? null,
    );
  }

  /// Re-point a token's record expiry (the daemon-token SOFT CUTOVER, auth-spec §2.7): a re-mint
  /// gives the PRIOR token a short grace (now+10min) instead of an instant revoke, so in-flight
  /// daemon requests finish while the new credential takes over. Enforced at the gate by the
  /// expiry check in `isJtiRevoked`.
  async setServiceTokenExpiry(id: string, expiresAt: number): Promise<void> {
    this.sql.exec(`UPDATE service_tokens SET expires_at = ? WHERE id = ?;`, expiresAt, id);
  }

  async getServiceToken(id: string): Promise<ServiceToken | null> {
    const r = this.sql.exec(`SELECT * FROM service_tokens WHERE id = ?;`, id).toArray();
    return r.length ? this.rowToServiceToken(r[0] as any) : null;
  }

  async listServiceTokens(orgId: string): Promise<ServiceToken[]> {
    return this.sql
      .exec(`SELECT * FROM service_tokens WHERE org_id = ? ORDER BY created_at DESC;`, orgId)
      .toArray()
      .map((r) => this.rowToServiceToken(r as any));
  }

  async touchServiceToken(id: string, lastUsedAt: number): Promise<void> {
    this.sql.exec(`UPDATE service_tokens SET last_used_at = ? WHERE id = ?;`, lastUsedAt, id);
  }

  async revokeServiceToken(id: string): Promise<void> {
    this.sql.exec(`UPDATE service_tokens SET revoked = 1 WHERE id = ?;`, id);
  }

  async revokedServiceJtis(): Promise<string[]> {
    return this.sql
      .exec(`SELECT id FROM service_tokens WHERE revoked = 1;`)
      .toArray()
      .map((r) => String(r.id));
  }

  // ---- device sessions (auth-spec §4.1) -------------------------------------

  async createDeviceCode(rec: DeviceCodeRecord): Promise<void> {
    this.assertAuthEpoch(rec.accountId, rec.authEpoch);
    this.sql.exec(
      `INSERT INTO device_codes (id,account_id,user_id,org_id,secret_hash,code_challenge,device_name,device_model,created_at,expires_at,consumed_at,auth_epoch)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?);`,
      rec.id, rec.accountId, rec.userId, rec.orgId, rec.secretHash, rec.codeChallenge,
      rec.deviceName, rec.deviceModel, rec.createdAt, rec.expiresAt, rec.consumedAt, rec.authEpoch ?? 0,
    );
    // A device code is short-lived garbage-to-be — make sure the prune alarm is armed.
    await this.armPruneAlarm();
  }

  /// Atomic single-use consume (same read-then-act pattern as `takeChallenge` — the DO is
  /// single-threaded so the read+stamp is uninterruptible). Returns the row IFF this call won
  /// the consume; null when absent OR already consumed.
  async consumeDeviceCode(id: string, consumedAt: number): Promise<DeviceCodeRecord | null> {
    const r = this.sql.exec(`SELECT * FROM device_codes WHERE id = ?;`, id).toArray();
    if (!r.length) return null;
    const rec = this.rowToDeviceCode(r[0] as any);
    if (rec.consumedAt !== null) return null;
    this.sql.exec(`UPDATE device_codes SET consumed_at = ? WHERE id = ?;`, consumedAt, id);
    return { ...rec, consumedAt };
  }

  async createDeviceSession(rec: DeviceSessionRecord): Promise<void> {
    this.assertAuthEpoch(rec.accountId, rec.authEpoch);
    this.sql.exec(
      `INSERT INTO device_sessions (id,account_id,user_id,org_id,scopes,device_name,device_model,refresh_hash,prev_refresh_hash,prev_grace_until,rotation_counter,created_at,last_seen_at,expires_at,revoked_at,revoke_reason)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);`,
      rec.id, rec.accountId, rec.userId, rec.orgId, JSON.stringify(rec.scopes),
      rec.deviceName, rec.deviceModel, rec.refreshHash, rec.prevRefreshHash, rec.prevGraceUntil,
      rec.rotationCounter, rec.createdAt, rec.lastSeenAt, rec.expiresAt, rec.revokedAt,
      rec.revokeReason,
    );
    await this.armPruneAlarm();
  }

  async getDeviceSession(id: string): Promise<DeviceSessionRecord | null> {
    const r = this.sql.exec(`SELECT * FROM device_sessions WHERE id = ?;`, id).toArray();
    return r.length ? this.rowToDeviceSession(r[0] as any) : null;
  }

  /// Persist a successful refresh rotation: new secret hash, the superseded hash + its 60s race
  /// grace, role-refreshed scopes, bumped rotation counter, and the SLID expiry (§2.4 step 3).
  async rotateDeviceSession(
    id: string,
    patch: {
      refreshHash: string;
      prevRefreshHash: string;
      prevGraceUntil: number;
      scopes: Scope[];
      lastSeenAt: number;
      expiresAt: number;
    },
  ): Promise<boolean> {
    return this.sql.exec(
      `UPDATE device_sessions
       SET refresh_hash = ?, prev_refresh_hash = ?, prev_grace_until = ?, scopes = ?,
           rotation_counter = rotation_counter + 1, last_seen_at = ?, expires_at = ?
       WHERE id = ? AND revoked_at IS NULL AND expires_at > ? RETURNING id;`,
      patch.refreshHash, patch.prevRefreshHash, patch.prevGraceUntil, JSON.stringify(patch.scopes),
      patch.lastSeenAt, patch.expiresAt, id, now(),
    ).toArray().length === 1;
  }

  /// Idempotent revoke (first reason wins). The id == every access JWS's jti, so `isJtiRevoked`
  /// rejects residual access tokens immediately after.
  async revokeDeviceSession(id: string, reason: string, revokedAt: number): Promise<void> {
    this.sql.exec(
      `UPDATE device_sessions SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL;`,
      revokedAt, reason, id,
    );
  }

  async listDeviceSessions(accountId: string): Promise<DeviceSessionRecord[]> {
    return this.sql
      .exec(`SELECT * FROM device_sessions WHERE account_id = ? ORDER BY created_at DESC;`, accountId)
      .toArray()
      .map((r) => this.rowToDeviceSession(r as any));
  }

  // ---- email / reset tokens -----------------------------------------------

  async putEmailToken(rec: EmailTokenRecord): Promise<void> {
    this.sql.exec(
      `INSERT INTO email_tokens (id,org_id,account_id,email,purpose,token_hash,created_at,expires_at,consumed_at)
       VALUES (?,?,?,?,?,?,?,?,?);`,
      rec.id, rec.orgId, rec.accountId, rec.email, rec.purpose, rec.tokenHash,
      rec.createdAt, rec.expiresAt, rec.consumedAt,
    );
  }

  async getEmailToken(id: string): Promise<EmailTokenRecord | null> {
    const r = this.sql.exec(`SELECT * FROM email_tokens WHERE id = ?;`, id).toArray();
    return r.length ? this.rowToEmailToken(r[0] as any) : null;
  }

  /// Atomic single-use consume: stamp consumed_at IFF currently unconsumed. Returns true only
  /// if THIS call won the race.
  async consumeEmailToken(id: string, consumedAt: number): Promise<boolean> {
    return this.sql.exec(
      `UPDATE email_tokens SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL RETURNING id;`,
      consumedAt, id,
    ).toArray().length === 1;
  }

  /// Best-effort: drop outstanding (unconsumed) tokens for (account, purpose) so a resend
  /// invalidates older links.
  async invalidateOutstandingEmailTokens(accountId: string, purpose: string): Promise<void> {
    const t = now();
    this.sql.exec(
      `UPDATE email_tokens SET consumed_at = ? WHERE account_id = ? AND purpose = ? AND consumed_at IS NULL;`,
      t, accountId, purpose,
    );
  }

  // ---- short-lived challenges ---------------------------------------------

  async claimTotpStep(accountId: string, secret: string, step: number, expiresAt: number): Promise<boolean> {
    return this.sql.exec(`INSERT INTO challenges (id,account_id,purpose,value,expires_at)
      SELECT ?,?,'totp_used',?,? WHERE EXISTS
        (SELECT 1 FROM totp WHERE account_id = ? AND secret = ? AND confirmed = 1)
      ON CONFLICT(id) DO NOTHING RETURNING id;`,
      `totp_used:${accountId}:${step}`, accountId, String(step), expiresAt, accountId, secret).toArray().length === 1;
  }

  async putChallenge(c: ChallengeRecord): Promise<void> {
    if (c.accountId && c.authEpoch !== undefined) this.assertAuthEpoch(c.accountId, c.authEpoch);
    this.sql.exec(
      `INSERT INTO challenges (id,account_id,purpose,value,expires_at,auth_epoch) VALUES (?,?,?,?,?,?)
       ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id, purpose=excluded.purpose,
         value=excluded.value, expires_at=excluded.expires_at, auth_epoch=excluded.auth_epoch;`,
      c.id, c.accountId, c.purpose, c.value, c.expiresAt, c.authEpoch ?? null,
    );
  }

  /// Single-use: read + delete atomically (DO is single-threaded so the read-then-delete is
  /// uninterruptible). Returns null if absent.
  async takeChallenge(id: string): Promise<Omit<ChallengeRecord, "id"> | null> {
    const r = this.sql.exec(`SELECT * FROM challenges WHERE id = ?;`, id).toArray();
    if (!r.length) return null;
    this.sql.exec(`DELETE FROM challenges WHERE id = ?;`, id);
    const row = r[0];
    return {
      ...(row.auth_epoch === null ? {} : { authEpoch: Number(row.auth_epoch) }),
      accountId: row.account_id === null ? null : String(row.account_id),
      purpose: String(row.purpose),
      value: String(row.value),
      expiresAt: Number(row.expires_at),
    };
  }
}
