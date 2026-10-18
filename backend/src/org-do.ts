// SPDX-License-Identifier: AGPL-3.0-or-later
// org-do.ts — the Org / Account-level Durable Object (multi-user tenancy authority).
//
// Analogous to FilespaceDO, but one level UP: where FilespaceDO is the per-filespace
// metadata + lock authority, OrgDO is the per-ORG coordination authority for tenancy:
// users, groups, group memberships, org roles, the filespace registry, and invite
// records (SPEC §4.1 Org, §4.2 roles, §4.5 identity, §4.10 data model).
//
// Addressed by `idFromName(orgId)` (one instance per org). Single-threaded + strongly
// consistent, SQLite-backed — the same pattern as FilespaceDO so the metadata-plane
// agent's mental model carries over. Crypto/JWT is NOT here (security agent owns it);
// this DO trusts an already-authenticated principal passed in by the gateway.
//
// NOTE (ownership): this file does NOT edit env.ts. The gateway must add an `ORG_DO`
// DurableObjectNamespace binding — see multiuser-INTEGRATION.md. We type the env we
// need locally to stay self-contained.

import { DurableObject } from "cloudflare:workers";
import { BackupState, type BackupEnv } from "./backup-state";
import type { OrgRole } from "./permissions";
import type { FilespaceDO } from "./filespace-do";
import type { SpaceStorageDescriptor } from "./storage";
import { describeDefaultStorage, type DefaultStorageEnv } from "./storage";
// Audit B21: invalidate the gateway's per-isolate space-registry cache on every space-registry
// mutation so a (soft-)delete/purge/revive/register/storage-repoint takes effect on the NEXT
// filespace-plane request, never after the TTL. These are no-ops in the DO isolate (the cache is
// only ever populated/read in the gateway isolate that runs handleOrgRequest).
import { invalidateSpace } from "./gate-cache";
// ONBOARDING.md "Key model": filespace master-key generation (create) + operator-upload
// (migration) live here, sealed under STORAGE_ENC_KEY via the SAME crypto module
// storage-credentials.ts uses. See filespace-keys.ts for the full design note.
import { generateSealedMasterKey, sealImportedMasterKey, MasterKeyError } from "./filespace-keys";

// Minimal env this DO needs. The real Env (env.ts) is owned by the metadata agent;
// we only require the ORG_DO binding to exist there (documented in INTEGRATION).
export interface OrgDOEnv extends DefaultStorageEnv, BackupEnv {
  ORG_DO: DurableObjectNamespace<OrgDO>;
  // OPTIONAL in this type (the gateway's real Env always has it): used ONLY by the owner-gated
  // soft-delete DELETE route to also flip the target FilespaceDO's durable tombstone (defense in
  // depth). We only ever call its `markDeleted()` RPC.
  FILESPACE?: DurableObjectNamespace<FilespaceDO>;
  // OPTIONAL in this type (the gateway's real Env always has it): AES-256-GCM key used to seal
  // filespace master keys (filespace-keys.ts) at creation/import time — the SAME deployment
  // secret storage-credentials.ts uses for BYO S3 secrets. Only referenced from the `spaces`
  // create/import routes below; every other route in this file is crypto-free.
  STORAGE_ENC_KEY?: string;
}

export type UserStatus = "active" | "suspended" | "deprovisioned";
export type UserKind = "human" | "service_account";

/// Audit B12 — thrown when a role/status change would remove the org's LAST active owner.
/// The gateway maps it to 409 so an org can never become un-administrable.
export class LastOwnerError extends Error {
  constructor() {
    super("cannot remove the last active owner of the org");
    this.name = "LastOwnerError";
  }
}

export interface User {
  id: string;
  orgId: string;
  email: string; // for service accounts, a synthetic "<name>@svc.<org>" address
  displayName: string;
  role: OrgRole;
  kind: UserKind;
  status: UserStatus;
  idpSubject: string | null; // set by SSO/SCIM (SPEC §4.5)
  createdAt: number;
}

export interface Group {
  id: string;
  orgId: string;
  name: string;
  source: "manual" | "scim";
  scimExternalId: string | null;
  createdAt: number;
}

export interface SpaceRegistration {
  id: string; // spaceId (== FilespaceDO idFromName)
  orgId: string;
  name: string;
  bucketProvider: string;
  bucketName: string;
  keyPrefix: string;
  createdAt: number;
  // ---- bring-your-own S3-compatible storage backend (storage.ts) ----
  // The PERSISTED, SECRET-FREE storage descriptor. When endpoint/region/bucket are all
  // absent the gateway falls back to the deployment-default backend (the `S3_*` env), so a
  // single-backend deployment needs none of these. Access keys are NEVER stored here — only
  // a `credentialRef` naming a pair of Worker secrets (see storage.ts). `bucketProvider` /
  // `bucketName` above stay as descriptive metadata; `storageBucket` (when set) is the
  // authoritative bucket the presigner uses.
  storageEndpoint: string | null;
  storageRegion: string | null;
  storageBucket: string | null;
  storageForcePathStyle: boolean | null;
  storageCredentialRef: string | null;
  /// Soft-delete marker (owner-gated SOFT delete). Null ⇒ live; a ms-epoch ⇒ the space was
  /// soft-deleted at that time. A soft-deleted space is INVISIBLE to listSpaces/getSpace (it
  /// vanishes from the org's registry) so the gateway refuses every filespace-plane op on it.
  /// REVERSIBLE: the row + the FilespaceDO's SQLite + the R2 objects all stay intact (recoverable);
  /// purging underlying object storage is a separate, deliberate maintainer decision (see the
  /// gateway DELETE handler's TODO(r2-cleanup)).
  deletedAt: number | null;
}

/// A UI-managed object-storage credential (storage-credentials.ts). The secret access key is
/// stored AES-256-GCM encrypted (iv + ciphertext columns); the access-key id is plaintext for
/// display. The SECRET is NEVER returned to a client after creation — only decrypted server-side
/// at presign time. A filespace's `storageCredentialRef` may name one of these by `id`.
export interface StorageCredentialRow {
  id: string;
  orgId: string;
  label: string;
  accessKeyId: string;
  secretIv: string; // base64 — per-record random GCM nonce
  secretCiphertext: string; // base64 — AES-256-GCM ciphertext || tag
  createdAt: number;
}

/// The SAFE, client-facing projection — never carries the encrypted secret material.
export interface StorageCredentialPublic {
  id: string;
  label: string;
  accessKeyId: string;
  createdAt: number;
}

/// A filespace's server-held master key (filespace-keys.ts, ONBOARDING.md "Key model"). One row
/// per space (PK spaceId) — the whole filespace shares ONE master key. The key material is
/// stored AES-256-GCM encrypted (keyIv + keyCiphertext, sealed under the deployment
/// `STORAGE_ENC_KEY`), the SAME envelope shape `StorageCredentialRow` uses for BYO S3 secrets.
/// `keyId` is a non-secret hash-prefix identifier (never the key itself). The plaintext key is
/// NEVER returned by any API except the authorized delivery/import endpoints (index.ts /
/// org-do.ts `handleOrgRequest`), and is decrypted ONLY server-side, on demand.
export interface FilespaceKeyRow {
  spaceId: string;
  orgId: string;
  keyId: string;
  keyIv: string; // base64 — per-record random GCM nonce
  keyCiphertext: string; // base64 — AES-256-GCM ciphertext || tag
  createdAt: number;
}

/// A per-org, UI-managed transactional-email provider configuration (email-config.ts). One row
/// per org (singleton). The provider + from address/name + SES region are stored plaintext for
/// display/operation; the provider SECRET(s) (Resend API key / Postmark server token / SES
/// secret access key) are stored AES-256-GCM encrypted (secret_iv + secret_ct columns) under the
/// deployment `STORAGE_ENC_KEY`. The plaintext secret is recovered ONLY server-side when building
/// the runtime sender and is NEVER returned by any API. When this row is absent the deployment
/// falls back to the `EMAIL_PROVIDER`/env path. Cloudflare needs no secret (binding-based), so
/// its row carries empty secret columns.
export interface EmailConfigRow {
  orgId: string;
  provider: "cloudflare" | "resend" | "postmark" | "ses";
  fromAddress: string;
  fromName: string | null;
  /// SES region (e.g. "us-east-1"); null for non-SES providers.
  region: string | null;
  /// AES-256-GCM envelope of the provider secret (Resend key / Postmark token / SES secret access
  /// key). Empty strings when the provider needs no secret (Cloudflare).
  secretIv: string;
  secretCiphertext: string;
  /// SES additionally needs the (non-secret) access-key id — stored plaintext, null otherwise.
  sesAccessKeyId: string | null;
  createdAt: number;
  updatedAt: number;
}

export type InviteStatus = "pending" | "accepted" | "revoked" | "expired";

export interface InviteRecord {
  id: string;
  orgId: string;
  email: string;
  role: OrgRole;
  tokenHash: string; // we store only a hash; the raw token is returned once on create
  spaceId: string | null; // optional scope (SPEC: scoped filespace)
  inodeId: string | null; // optional scope (scoped folder); paired with a level
  level: "read" | "edit" | "admin" | null;
  status: InviteStatus;
  createdByMemberId: string;
  createdAt: number;
  expiresAt: number;
  acceptedByUserId: string | null;
  acceptedAt: number | null;
}

function now(): number {
  return Date.now();
}

export class OrgDO extends DurableObject<OrgDOEnv> {
  private sql: SqlStorage;
  private readonly backupState: BackupState;
  private readonly userStatusTurns = new Map<string, Promise<void>>();

  constructor(ctx: DurableObjectState, env: OrgDOEnv) {
    super(ctx, env);
    this.backupState = new BackupState(ctx.storage, env, 'org');
    this.sql = this.backupState.guardedSQL;
    ctx.blockConcurrencyWhile(async () => { this.migrate(); this.backupState.initialize(); });
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
  backupInventory() { return this.backupState.inventory(); }
  backupStorageCredential(ref: string) { return this.backupState.storageCredential(ref); }

  async readiness(): Promise<{ schemaVersion: number; databaseBytes: number }> {
    const schemaVersion = Number(this.sql.exec(`SELECT COALESCE(MAX(id), 0) AS v FROM _schema_migrations;`).one().v);
    await this.ctx.storage.sync();
    return { schemaVersion, databaseBytes: this.sql.databaseSize };
  }

  private migrate() {
    // Audit B20: OrgDO was the ONLY DO without a `_schema_migrations` version table — it
    // re-ran every DDL per cold start and could not express a backfill/data migration. Adopt
    // the same versioned pattern the other three DOs use. v1 = the baseline schema (all the
    // CREATE-IF-NOT-EXISTS below, which existing DOs already have); v2 = canonicalize stored
    // emails to lowercase (matching AuthDO/DirectoryDO; closes the duplicate-user seam).
    this.sql.exec(`CREATE TABLE IF NOT EXISTS _schema_migrations (id INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);`);
    const schemaVersion = Number(this.sql.exec(`SELECT COALESCE(MAX(id), 0) AS v FROM _schema_migrations;`).one().v);

    this.sql.exec(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL,
      display_name TEXT NOT NULL, role TEXT NOT NULL, kind TEXT NOT NULL,
      status TEXT NOT NULL, idp_subject TEXT, created_at INTEGER NOT NULL);`);
    this.sql.exec(`CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users(email);`);

    this.sql.exec(`CREATE TABLE IF NOT EXISTS groups (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, name TEXT NOT NULL,
      source TEXT NOT NULL, scim_external_id TEXT, created_at INTEGER NOT NULL);`);
    this.sql.exec(`CREATE UNIQUE INDEX IF NOT EXISTS groups_name ON groups(org_id, name);`);

    this.sql.exec(`CREATE TABLE IF NOT EXISTS group_members (
      group_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (group_id, user_id));`);

    this.sql.exec(`CREATE TABLE IF NOT EXISTS spaces (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, name TEXT NOT NULL,
      bucket_provider TEXT NOT NULL, bucket_name TEXT NOT NULL,
      key_prefix TEXT NOT NULL, created_at INTEGER NOT NULL,
      storage_endpoint TEXT, storage_region TEXT, storage_bucket TEXT,
      storage_force_path_style INTEGER, storage_credential_ref TEXT);`);
    // Additive migration for DOs created before bring-your-own storage existed: add the new
    // storage_* columns if missing (no-op on fresh DOs, which already have them above).
    this.addColumnIfMissing("spaces", "storage_endpoint", "TEXT");
    this.addColumnIfMissing("spaces", "storage_region", "TEXT");
    this.addColumnIfMissing("spaces", "storage_bucket", "TEXT");
    this.addColumnIfMissing("spaces", "storage_force_path_style", "INTEGER");
    this.addColumnIfMissing("spaces", "storage_credential_ref", "TEXT");
    // Owner-gated SOFT delete: a nullable marker so a deleted space can be excluded from the
    // registry without dropping the row (reversible). NULLABLE on purpose — adding a NOT-NULL
    // column to the already-populated `spaces` table would fail; existing rows default to NULL
    // (= live), which is exactly the desired "not deleted" state.
    this.addColumnIfMissing("spaces", "deleted_at", "INTEGER");
    // P-F2: a durable purge marker so a purge is a POINT OF NO RETURN for an id. Once a purge is
    // started the row is marked 'purging' (then 'purged' when the row is hard-deleted, though in
    // practice the row is gone by then); while it is 'purging' the OrgDO REFUSES to revive/re-register
    // the same id (clearing deleted_at would route live traffic to a DO that is mid-sweep + about to
    // deleteAll — split-brain). NULL ⇒ never purged (normal soft-delete→revive is unaffected).
    this.addColumnIfMissing("spaces", "purge_state", "TEXT");

    // UI-managed object-storage credentials (storage-credentials.ts). The secret access key is
    // stored AES-256-GCM encrypted (secret_iv + secret_ct); access_key_id is plaintext for the
    // settings UI. A space's storage_credential_ref may reference one of these rows by id.
    this.sql.exec(`CREATE TABLE IF NOT EXISTS storage_credentials (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, label TEXT NOT NULL,
      access_key_id TEXT NOT NULL, secret_iv TEXT NOT NULL, secret_ct TEXT NOT NULL,
      created_at INTEGER NOT NULL);`);

    // Filespace server-held master keys (filespace-keys.ts, ONBOARDING.md "Key model", build
    // step 2). One row per space (PK space_id); AES-256-GCM sealed under STORAGE_ENC_KEY, same
    // envelope pattern as storage_credentials above. Generated at space creation (registerSpace
    // callers, see the `spaces` create route below) or uploaded via the owner/admin import path
    // for filespaces that predate this feature.
    this.sql.exec(`CREATE TABLE IF NOT EXISTS filespace_keys (
      space_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, key_id TEXT NOT NULL,
      key_iv TEXT NOT NULL, key_ct TEXT NOT NULL, created_at INTEGER NOT NULL);`);

    // UI-managed transactional-email provider config (email-config.ts). A SINGLE row per org
    // (PK 'k'='email'), so a PUT upserts. The provider SECRET(s) are stored AES-256-GCM encrypted
    // (secret_iv + secret_ct) under STORAGE_ENC_KEY; provider/from/region/sesAccessKeyId are
    // plaintext. Absent row ⇒ fall back to the EMAIL_PROVIDER/env path.
    this.sql.exec(`CREATE TABLE IF NOT EXISTS email_config (
      k TEXT PRIMARY KEY, org_id TEXT NOT NULL, provider TEXT NOT NULL,
      from_address TEXT NOT NULL, from_name TEXT, region TEXT,
      secret_iv TEXT NOT NULL, secret_ct TEXT NOT NULL, ses_access_key_id TEXT,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);`);

    this.sql.exec(`CREATE TABLE IF NOT EXISTS invites (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL,
      token_hash TEXT NOT NULL, space_id TEXT, inode_id TEXT, level TEXT,
      status TEXT NOT NULL, created_by TEXT NOT NULL, created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL, accepted_by TEXT, accepted_at INTEGER);`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS invites_tokenhash ON invites(token_hash);`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS invites_status ON invites(status);`);

    // External share links (SPEC §4.10 GuestLink). Durable backing for sharing.ts.
    this.sql.exec(`CREATE TABLE IF NOT EXISTS share_links (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, space_id TEXT NOT NULL, inode_id TEXT NOT NULL,
      audience TEXT NOT NULL, level TEXT NOT NULL, token_hash TEXT NOT NULL, email TEXT,
      created_by TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0);`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS share_tokenhash ON share_links(token_hash);`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS share_space ON share_links(space_id);`);

    // ACL grants written on invite-redeem (SPEC §4.10 Grant). The FilespaceDO is the
    // canonical ACL home for enforcement, but recording the invite-promised grant here
    // makes redeem self-contained and durable; the gateway syncs it into the space's
    // grant store (see multiuser-INTEGRATION.md §5).
    this.sql.exec(`CREATE TABLE IF NOT EXISTS grants (
      id TEXT PRIMARY KEY, space_id TEXT NOT NULL, inode_id TEXT NOT NULL,
      principal_type TEXT NOT NULL, principal_id TEXT NOT NULL, level TEXT NOT NULL,
      mount_as_root INTEGER NOT NULL DEFAULT 0, expires_at INTEGER,
      granted_by TEXT NOT NULL, granted_at INTEGER NOT NULL);`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS grants_inode ON grants(inode_id);`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS grants_principal ON grants(principal_type, principal_id);`);

    // Org-level metadata (display name, etc.). A single-row key/value table keyed by `k`. The
    // org's stable slug is its DO name (orgId); only the human-facing display `name` is mutable
    // here, set via `setOrgName` (PATCH /v1/orgs/:org). Created lazily on first write/read.
    this.sql.exec(`CREATE TABLE IF NOT EXISTS org_meta (
      k TEXT PRIMARY KEY, v TEXT NOT NULL);`);

    // Record the baseline once (the CREATE-IF-NOT-EXISTS above are the v1 schema).
    if (schemaVersion < 1) {
      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (1, ?);`, Date.now());
    }
    // v2 (audit B20): canonicalize stored emails to lowercase so OrgDO matches AuthDO/DirectoryDO
    // (which already lowercase). Without this, an invite/signup seam could create duplicate users
    // differing only by case. New writes are canonicalized by createUser; this backfills old rows.
    if (schemaVersion < 2) {
      this.sql.exec(`UPDATE users SET email = LOWER(email) WHERE email <> LOWER(email);`);
      this.sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (2, ?);`, Date.now());
    }
  }

  /// Idempotently add a column to an existing table (SQLite has no `ADD COLUMN IF NOT
  /// EXISTS`). Used for additive migrations of DOs created before a column existed.
  private addColumnIfMissing(table: string, column: string, type: string): void {
    const cols = this.sql.exec(`PRAGMA table_info(${table});`).toArray();
    if (cols.some((c) => String((c as Record<string, SqlStorageValue>).name) === column)) return;
    this.sql.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type};`);
  }

  // ---- row mappers --------------------------------------------------------

  private rowToUser(r: Record<string, SqlStorageValue>): User {
    return {
      id: String(r.id),
      orgId: String(r.org_id),
      email: String(r.email),
      displayName: String(r.display_name),
      role: String(r.role) as OrgRole,
      kind: String(r.kind) as UserKind,
      status: String(r.status) as UserStatus,
      idpSubject: r.idp_subject === null ? null : String(r.idp_subject),
      createdAt: Number(r.created_at),
    };
  }

  private rowToGroup(r: Record<string, SqlStorageValue>): Group {
    return {
      id: String(r.id),
      orgId: String(r.org_id),
      name: String(r.name),
      source: String(r.source) as "manual" | "scim",
      scimExternalId: r.scim_external_id === null ? null : String(r.scim_external_id),
      createdAt: Number(r.created_at),
    };
  }

  private rowToInvite(r: Record<string, SqlStorageValue>): InviteRecord {
    return {
      id: String(r.id),
      orgId: String(r.org_id),
      email: String(r.email),
      role: String(r.role) as OrgRole,
      tokenHash: String(r.token_hash),
      spaceId: r.space_id === null ? null : String(r.space_id),
      inodeId: r.inode_id === null ? null : String(r.inode_id),
      level: r.level === null ? null : (String(r.level) as "read" | "edit" | "admin"),
      status: String(r.status) as InviteStatus,
      createdByMemberId: String(r.created_by),
      createdAt: Number(r.created_at),
      expiresAt: Number(r.expires_at),
      acceptedByUserId: r.accepted_by === null ? null : String(r.accepted_by),
      acceptedAt: r.accepted_at === null ? null : Number(r.accepted_at),
    };
  }

  // ---- users --------------------------------------------------------------

  createUser(input: {
    orgId: string;
    email: string;
    displayName: string;
    role?: OrgRole;
    kind?: UserKind;
    idpSubject?: string | null;
  }): User {
    // Audit B20: canonicalize the email to lowercase so OrgDO matches AuthDO/DirectoryDO and the
    // unique index can't be defeated by a case variant (a duplicate user across the signup/invite seam).
    const email = input.email.trim().toLowerCase();
    const existing = this.sql.exec(`SELECT id FROM users WHERE email = ?;`, email).toArray();
    if (existing.length) throw new Error(`user with email ${email} already exists`);
    const u: User = {
      id: `usr-${crypto.randomUUID()}`,
      orgId: input.orgId,
      email,
      displayName: input.displayName,
      role: input.role ?? "standard",
      kind: input.kind ?? "human",
      status: "active",
      idpSubject: input.idpSubject ?? null,
      createdAt: now(),
    };
    this.sql.exec(
      `INSERT INTO users (id,org_id,email,display_name,role,kind,status,idp_subject,created_at)
       VALUES (?,?,?,?,?,?,?,?,?);`,
      u.id, u.orgId, u.email, u.displayName, u.role, u.kind, u.status, u.idpSubject, u.createdAt,
    );
    return u;
  }

  getUser(userId: string): User | null {
    const r = this.sql.exec(`SELECT * FROM users WHERE id = ?;`, userId).toArray();
    return r.length ? this.rowToUser(r[0] as any) : null;
  }

  async getUserByEmail(email: string): Promise<User | null> {
    // Audit B20: match the canonicalized (lowercase) storage form.
    const r = this.sql.exec(`SELECT * FROM users WHERE email = ?;`, email.trim().toLowerCase()).toArray();
    return r.length ? this.rowToUser(r[0] as any) : null;
  }

  async listUsers(): Promise<User[]> {
    return this.sql.exec(`SELECT * FROM users ORDER BY created_at;`).toArray().map((r) => this.rowToUser(r as any));
  }

  /** Count of members in this org. Used by the single-use bootstrap route so it
   *  can 409 once an admin/org already exists without loading every user row. */
  async countUsers(): Promise<number> {
    return Number(this.sql.exec(`SELECT COUNT(*) AS c FROM users;`).one().c);
  }

  /** Only the secret-gated setup coordinator calls this. No await separates the empty
   *  check from insertion; retries may reuse exactly the reserved active owner. */
  async provisionSetupOwner(input: { orgId: string; email: string; displayName: string; resumed: boolean }): Promise<User | null> {
    const users = this.sql.exec(`SELECT * FROM users;`).toArray();
    if (users.length) {
      if (!input.resumed || users.length !== 1) return null;
      const owner = this.rowToUser(users[0]);
      return owner.email === input.email && owner.role === "owner" && owner.status === "active" ? owner : null;
    }
    return this.createUser({ ...input, role: "owner" });
  }

  async setUserStatus(userId: string, status: UserStatus): Promise<User> {
    // Cross-filespace retirement awaits must not let a concurrent activation
    // clear this account's barrier before its suspension finishes (or vice versa).
    const previous = this.userStatusTurns.get(userId) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>(resolve => { release = resolve; });
    this.userStatusTurns.set(userId, current);
    await previous;
    try { return await this.setUserStatusInTurn(userId, status); }
    finally {
      release();
      if (this.userStatusTurns.get(userId) === current) this.userStatusTurns.delete(userId);
    }
  }

  private async setUserStatusInTurn(userId: string, status: UserStatus): Promise<User> {
    // Audit B12 (last-owner guard): suspending/deprovisioning the LAST active owner
    // would lock the org out of owner-only operations. Refuse it.
    const guardOwner = () => { if (status !== "active") {
      const current = this.getUser(userId);
      if (current && current.role === "owner" && current.status === "active") {
        if ((this.countActiveOwners()) <= 1) {
          throw new LastOwnerError();
        }
      }
    } };
    guardOwner();
    const user = this.getUser(userId);
    if (!user) throw new Error("no such user");
    if (this.env.FILESPACE) {
      for (const space of this.sql.exec(`SELECT id FROM spaces;`).toArray()) {
        const key = `${user.orgId}::${String(space.id)}`;
        const filespace = this.env.FILESPACE.get(this.env.FILESPACE.idFromName(key));
        if (status === "active") await filespace.reactivateUserDelegation(userId);
        else await filespace.retireUserDelegation(userId);
      }
    }
    // Network awaits above permit another owner's concurrent status/role change.
    // Recheck in the same synchronous turn as the final status write.
    guardOwner();
    this.sql.exec(`UPDATE users SET status = ? WHERE id = ?;`, status, userId);
    const u = this.getUser(userId);
    if (!u) throw new Error("no such user");
    return u;
  }

  /// Count of ACTIVE owners (audit B12 last-owner guard). A role/status change that
  /// would drop this to zero must be refused so an org can never become un-administrable.
  countActiveOwners(): number {
    return Number(this.sql.exec(
      `SELECT COUNT(*) AS c FROM users WHERE role = 'owner' AND status = 'active';`,
    ).one().c);
  }

  setUserRole(userId: string, role: OrgRole): User {
    // Audit B12 (last-owner guard, defense-in-depth at the DO): demoting the LAST active
    // owner would leave the org with no owner (the only role that can repoint storage /
    // manage owners). Refuse it here too, not just at the gateway.
    const current = this.getUser(userId);
    if (current && current.role === "owner" && role !== "owner" && current.status === "active") {
      if ((this.countActiveOwners()) <= 1) {
        throw new LastOwnerError();
      }
    }
    this.sql.exec(`UPDATE users SET role = ? WHERE id = ?;`, role, userId);
    const u = this.getUser(userId);
    if (!u) throw new Error("no such user");
    return u;
  }

  /// Self-service profile update for an existing user (display name and/or email). Only the keys
  /// present in `patch` are touched (an `undefined` field is left as-is). Email re-claim in the
  /// GLOBAL DirectoryDO index is the gateway's job (it owns cross-DO orchestration); this just
  /// mirrors the resolved email into the OrgDO User row, throwing if the new email already belongs
  /// to a DIFFERENT user in THIS org (the unique index would otherwise reject the UPDATE).
  async setUserProfile(userId: string, patch: { displayName?: string; email?: string }): Promise<User> {
    if (patch.email !== undefined) {
      const taken = this.sql
        .exec(`SELECT id FROM users WHERE email = ? AND id <> ?;`, patch.email, userId)
        .toArray();
      if (taken.length) throw new Error(`user with email ${patch.email} already exists`);
    }
    const sets: string[] = [];
    const args: SqlStorageValue[] = [];
    if (patch.displayName !== undefined) {
      sets.push("display_name = ?");
      args.push(patch.displayName);
    }
    if (patch.email !== undefined) {
      sets.push("email = ?");
      args.push(patch.email);
    }
    if (sets.length) this.sql.exec(`UPDATE users SET ${sets.join(", ")} WHERE id = ?;`, ...args, userId);
    const u = await this.getUser(userId);
    if (!u) throw new Error("no such user");
    return u;
  }

  /** Create a service account (CLI / render-farm identity, SPEC §3.8 / README). */
  async createServiceAccount(input: { orgId: string; name: string; role?: OrgRole }): Promise<User> {
    return this.createUser({
      orgId: input.orgId,
      email: `${input.name}@svc.${input.orgId}`,
      displayName: input.name,
      role: input.role ?? "standard",
      kind: "service_account",
    });
  }

  // ---- groups -------------------------------------------------------------

  async createGroup(input: {
    orgId: string;
    name: string;
    source?: "manual" | "scim";
    scimExternalId?: string | null;
  }): Promise<Group> {
    const g: Group = {
      id: `grp-${crypto.randomUUID()}`,
      orgId: input.orgId,
      name: input.name,
      source: input.source ?? "manual",
      scimExternalId: input.scimExternalId ?? null,
      createdAt: now(),
    };
    this.sql.exec(
      `INSERT INTO groups (id,org_id,name,source,scim_external_id,created_at) VALUES (?,?,?,?,?,?);`,
      g.id, g.orgId, g.name, g.source, g.scimExternalId, g.createdAt,
    );
    return g;
  }

  async listGroups(): Promise<Group[]> {
    return this.sql.exec(`SELECT * FROM groups ORDER BY name;`).toArray().map((r) => this.rowToGroup(r as any));
  }

  async deleteGroup(groupId: string): Promise<void> {
    const group = this.sql.exec(`SELECT org_id FROM groups WHERE id=?;`, groupId).toArray()[0];
    if (group && this.env.FILESPACE) {
      // Include soft-deleted filespaces: restoring one must not revive authority
      // for a deleted directory group. Each DO also rejects late grant writes.
      const spaces = this.sql.exec(`SELECT id FROM spaces;`).toArray();
      for (const space of spaces) {
        const key = `${String(group.org_id)}::${String(space.id)}`;
        await this.env.FILESPACE.get(this.env.FILESPACE.idFromName(key)).revokeDeletedAclPrincipal("group", groupId);
      }
    }
    this.sql.exec(`DELETE FROM group_members WHERE group_id = ?;`, groupId);
    this.sql.exec(`DELETE FROM groups WHERE id = ?;`, groupId);
  }

  async addGroupMember(groupId: string, userId: string): Promise<void> {
    this.sql.exec(
      `INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?);`,
      groupId, userId,
    );
  }

  async removeGroupMember(groupId: string, userId: string): Promise<void> {
    this.sql.exec(`DELETE FROM group_members WHERE group_id = ? AND user_id = ?;`, groupId, userId);
  }

  /** Group ids a user belongs to — feeds Principal.groupIds for ACL group-union. */
  async groupsForUser(userId: string): Promise<string[]> {
    return this.sql.exec(`SELECT group_id FROM group_members WHERE user_id = ?;`, userId)
      .toArray().map((r) => String(r.group_id));
  }

  async membersOfGroup(groupId: string): Promise<string[]> {
    return this.sql.exec(`SELECT user_id FROM group_members WHERE group_id = ?;`, groupId)
      .toArray().map((r) => String(r.user_id));
  }

  // ---- filespace registry -------------------------------------------------

  private rowToSpace(r: Record<string, SqlStorageValue>): SpaceRegistration {
    return {
      id: String(r.id),
      orgId: String(r.org_id),
      name: String(r.name),
      bucketProvider: String(r.bucket_provider),
      bucketName: String(r.bucket_name),
      keyPrefix: String(r.key_prefix),
      createdAt: Number(r.created_at),
      storageEndpoint: r.storage_endpoint == null ? null : String(r.storage_endpoint),
      storageRegion: r.storage_region == null ? null : String(r.storage_region),
      storageBucket: r.storage_bucket == null ? null : String(r.storage_bucket),
      storageForcePathStyle: r.storage_force_path_style == null ? null : Number(r.storage_force_path_style) !== 0,
      storageCredentialRef: r.storage_credential_ref == null ? null : String(r.storage_credential_ref),
      deletedAt: r.deleted_at == null ? null : Number(r.deleted_at),
    };
  }

  registerSpace(input: {
    /// Stable space id. OPTIONAL: when omitted/blank (the create path — the client doesn't choose
    /// the id), a fresh `fs-<uuid>` is generated so the row never lands with a `"null"`/empty id.
    /// When provided (idempotent re-register / explicit id), it's used as-is and upserts by id.
    spaceId?: string | null;
    orgId: string;
    name: string;
    bucketProvider: string;
    bucketName: string;
    keyPrefix: string;
    // Optional bring-your-own S3-compatible storage descriptor (secret-free; storage.ts).
    storageEndpoint?: string | null;
    storageRegion?: string | null;
    storageBucket?: string | null;
    storageForcePathStyle?: boolean | null;
    storageCredentialRef?: string | null;
    /// Audit B12: when true, REFUSE to upsert over an EXISTING space id — the create path
    /// must not silently repoint storage or revive a soft-deleted space (which is how a
    /// non-owner admin could redirect the data plane to an attacker bucket through `POST
    /// /spaces`). The gateway sets this for any non-owner create. An owner-gated
    /// reconfigure/revive path passes it false.
    expectInsertOnly?: boolean;
  }): SpaceRegistration {
    // Assign a stable, unique id on create when the caller didn't supply one (a `null`/undefined/
    // blank spaceId previously stringified to the literal `"null"` in the row — fix BUG 5).
    const spaceId =
      typeof input.spaceId === "string" && input.spaceId.trim().length > 0
        ? input.spaceId.trim()
        : `fs-${crypto.randomUUID()}`;
    // P-F2: a purge is a POINT OF NO RETURN for an id. If a purge has started/completed on this id,
    // REFUSE the re-register (which would clear deleted_at and route live traffic to a FilespaceDO
    // that is mid-sweep deleting its own objects + about to deleteAll — split-brain). A purged id
    // must get a FRESH id, not silently revive. Normal soft-delete→revive (purge_state NULL) is
    // unaffected. The throw is mapped to 409 space_purged at the gateway (DO RPC loses .name, so we
    // signal via a recognizable message prefix).
    const existing = this.sql
      .exec(`SELECT purge_state FROM spaces WHERE id = ? LIMIT 1;`, spaceId)
      .toArray()[0];
    if (existing && existing.purge_state != null) {
      throw new Error(`space_purged: filespace ${spaceId} was purged and cannot be revived; create a new filespace`);
    }
    // Audit B12: insert-only create — an existing id must NOT be upserted by the create path
    // (that's how a non-owner admin could repoint storage / revive a deleted space). The
    // owner-gated PATCH path is where storage reconfig lives.
    if (input.expectInsertOnly && existing) {
      throw new Error(`space_exists: filespace ${spaceId} already exists; storage/reconfigure is an owner-only PATCH`);
    }
    const s: SpaceRegistration = {
      id: spaceId,
      orgId: input.orgId,
      name: input.name,
      bucketProvider: input.bucketProvider,
      bucketName: input.bucketName,
      keyPrefix: input.keyPrefix,
      createdAt: now(),
      storageEndpoint: input.storageEndpoint ?? null,
      storageRegion: input.storageRegion ?? null,
      storageBucket: input.storageBucket ?? null,
      storageForcePathStyle: input.storageForcePathStyle ?? null,
      storageCredentialRef: input.storageCredentialRef ?? null,
      deletedAt: null,
    };
    this.sql.exec(
      `INSERT INTO spaces (id,org_id,name,bucket_provider,bucket_name,key_prefix,created_at,
         storage_endpoint,storage_region,storage_bucket,storage_force_path_style,storage_credential_ref)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(id) DO UPDATE SET name=excluded.name, bucket_provider=excluded.bucket_provider,
         bucket_name=excluded.bucket_name, key_prefix=excluded.key_prefix,
         storage_endpoint=excluded.storage_endpoint, storage_region=excluded.storage_region,
         storage_bucket=excluded.storage_bucket, storage_force_path_style=excluded.storage_force_path_style,
         storage_credential_ref=excluded.storage_credential_ref,
         -- Re-registering an id REVIVES a soft-deleted space (clears the tombstone), matching the
         -- create path's deletedAt:null and the returned row. An ordinary re-register of a live
         -- space is unaffected (it was already NULL).
         deleted_at=NULL;`,
      s.id, s.orgId, s.name, s.bucketProvider, s.bucketName, s.keyPrefix, s.createdAt,
      s.storageEndpoint, s.storageRegion, s.storageBucket,
      s.storageForcePathStyle == null ? null : (s.storageForcePathStyle ? 1 : 0),
      s.storageCredentialRef,
    );
    return s;
  }

  /// LIVE spaces only — soft-deleted rows (deleted_at set) are excluded so a deleted space
  /// vanishes from the org's registry (the UI's space list, admin inspection, etc.).
  async listSpaces(): Promise<SpaceRegistration[]> {
    return this.sql
      .exec(`SELECT * FROM spaces WHERE deleted_at IS NULL ORDER BY name;`)
      .toArray()
      .map((r) => this.rowToSpace(r));
  }

  /** A single LIVE space's registry row (or null) — the gateway uses this to resolve the
   *  space's storage backend before minting a presigned URL. A SOFT-DELETED space is treated as
   *  ABSENT here (returns null), so it cannot be presigned/resolved. To DISTINGUISH a deleted
   *  space from one that never existed (for a 410-vs-404 gate), use `getSpaceIncludingDeleted`. */
  async getSpace(spaceId: string): Promise<SpaceRegistration | null> {
    const rows = this.sql
      .exec(`SELECT * FROM spaces WHERE id = ? AND deleted_at IS NULL LIMIT 1;`, spaceId)
      .toArray();
    return rows.length ? this.rowToSpace(rows[0]) : null;
  }

  /** The registry row REGARDLESS of soft-delete state (or null if it never existed). The gateway
   *  uses this at the filespace-plane chokepoint to refuse a soft-deleted space with 410 Gone
   *  (vs. 404 for a truly-unknown space): a non-null row with `deletedAt` set ⇒ tombstoned. */
  async getSpaceIncludingDeleted(spaceId: string): Promise<SpaceRegistration | null> {
    const rows = this.sql.exec(`SELECT * FROM spaces WHERE id = ? LIMIT 1;`, spaceId).toArray();
    return rows.length ? this.rowToSpace(rows[0]) : null;
  }

  /// Owner-gated SOFT delete of a filespace (REVERSIBLE — sets the `deleted_at` marker, never
  /// drops the row). Idempotent: returns `{ deleted: true, newlyDeleted }` where `newlyDeleted`
  /// is true only on the FIRST delete (a re-delete is a safe no-op with newlyDeleted=false), and
  /// `{ deleted: false }` for an unknown space id (the gateway maps that to 404). Owner gating is
  /// enforced by the gateway BEFORE this RPC is reached. NOTE: this only marks the OrgDO registry
  /// row — it does NOT touch the FilespaceDO's SQLite or any R2 object storage (recoverable).
  async deleteSpace(spaceId: string): Promise<{ deleted: boolean; newlyDeleted: boolean }> {
    const rows = this.sql
      .exec(`SELECT deleted_at FROM spaces WHERE id = ? LIMIT 1;`, spaceId)
      .toArray();
    if (rows.length === 0) return { deleted: false, newlyDeleted: false };
    if (rows[0].deleted_at != null) return { deleted: true, newlyDeleted: false }; // idempotent
    this.sql.exec(`UPDATE spaces SET deleted_at = ? WHERE id = ?;`, now(), spaceId);
    return { deleted: true, newlyDeleted: true };
  }

  /// HARD delete of a filespace registry row — IRREVERSIBLE. Drops the row entirely (not just the
  /// `deleted_at` marker), so the space is absent from BOTH listSpaces AND getSpaceIncludingDeleted.
  /// This is the FINAL step of a purge: the FilespaceDO calls it once it has permanently deleted the
  /// space's encrypted objects from BYO storage and is about to wipe its own SQLite. SAFETY: this
  /// only removes the OrgDO registry row; it does NOT touch object storage or any other space.
  /// Idempotent: removing an unknown/already-removed id returns `{ removed: false }`. We do NOT
  /// require the row to be soft-deleted here (the gateway enforces the two-step gate BEFORE the
  /// sweep), but a purge always tombstones first, so in practice the row is soft-deleted.
  async hardDeleteSpace(spaceId: string): Promise<{ removed: boolean }> {
    const before = this.sql.exec(`SELECT id FROM spaces WHERE id = ? LIMIT 1;`, spaceId).toArray();
    if (before.length === 0) return { removed: false };
    this.sql.exec(`DELETE FROM spaces WHERE id = ?;`, spaceId);
    return { removed: true };
  }

  /// P-F2: durably mark a space's registry row as 'purging' — the POINT OF NO RETURN. Called by the
  /// gateway purge handler BEFORE it arms the FilespaceDO sweep, so a concurrent re-register/revive
  /// of the SAME id is refused (registerSpace throws space_purged) and cannot clear deleted_at to
  /// route live traffic into a DO that is mid-purge (split-brain). Idempotent. Returns
  /// `{ marked:false }` for an unknown id (nothing to mark). The row is later hard-deleted by
  /// finalize; this marker covers the in-flight window before that.
  async markSpacePurging(spaceId: string): Promise<{ marked: boolean }> {
    const before = this.sql.exec(`SELECT id FROM spaces WHERE id = ? LIMIT 1;`, spaceId).toArray();
    if (before.length === 0) return { marked: false };
    this.sql.exec(`UPDATE spaces SET purge_state = 'purging' WHERE id = ?;`, spaceId);
    return { marked: true };
  }

  /// P-F2: has a purge started/completed on this id (purge_state set)? Used by the gateway create
  /// path to refuse a revive with a clean 409 BEFORE calling registerSpace (which would otherwise
  /// throw across the RPC boundary). registerSpace ALSO throws on this state as defense in depth for
  /// direct (non-gateway) callers.
  async isSpacePurged(spaceId: string): Promise<boolean> {
    const r = this.sql.exec(`SELECT purge_state FROM spaces WHERE id = ? LIMIT 1;`, spaceId).toArray()[0];
    return !!r && r.purge_state != null;
  }

  /// PATCH the MUTABLE fields of an EXISTING space (name + bring-your-own storage descriptor).
  /// Unlike `registerSpace` (which upserts by spaceId and is the create path), this never creates
  /// a row: an unknown spaceId returns null. Only the keys present in `patch` are touched — an
  /// `undefined` field is left as-is, so a partial update (e.g. just `name`) preserves the rest.
  /// `storage*: null` explicitly CLEARS that override (falls back to the deployment-default).
  async updateSpace(
    spaceId: string,
    patch: {
      name?: string;
      storageEndpoint?: string | null;
      storageRegion?: string | null;
      storageBucket?: string | null;
      storageForcePathStyle?: boolean | null;
      storageCredentialRef?: string | null;
    },
  ): Promise<SpaceRegistration | null> {
    const existing = await this.getSpace(spaceId);
    if (!existing) return null;
    const sets: string[] = [];
    const args: SqlStorageValue[] = [];
    if (patch.name !== undefined) {
      sets.push("name = ?");
      args.push(patch.name);
    }
    if (patch.storageEndpoint !== undefined) {
      sets.push("storage_endpoint = ?");
      args.push(patch.storageEndpoint);
    }
    if (patch.storageRegion !== undefined) {
      sets.push("storage_region = ?");
      args.push(patch.storageRegion);
    }
    if (patch.storageBucket !== undefined) {
      sets.push("storage_bucket = ?");
      args.push(patch.storageBucket);
    }
    if (patch.storageForcePathStyle !== undefined) {
      sets.push("storage_force_path_style = ?");
      args.push(patch.storageForcePathStyle == null ? null : patch.storageForcePathStyle ? 1 : 0);
    }
    if (patch.storageCredentialRef !== undefined) {
      sets.push("storage_credential_ref = ?");
      args.push(patch.storageCredentialRef);
    }
    if (sets.length === 0) return existing; // nothing to update — return the row unchanged
    this.sql.exec(`UPDATE spaces SET ${sets.join(", ")} WHERE id = ?;`, ...args, spaceId);
    return this.getSpace(spaceId);
  }

  // ---- org metadata (display name; slug == orgId) -------------------------

  /// The org's human-facing display name, or null if never set. The stable slug is the orgId
  /// (the DO name), so we store only the mutable display name here.
  async getOrgName(): Promise<string | null> {
    const r = this.sql.exec(`SELECT v FROM org_meta WHERE k = 'name';`).toArray();
    return r.length ? String(r[0].v) : null;
  }

  /// Set (rename) the org's display name. Owner/admin gating is enforced by the gateway before
  /// this RPC is reached.
  async setOrgName(name: string): Promise<void> {
    this.sql.exec(
      `INSERT INTO org_meta (k, v) VALUES ('name', ?)
       ON CONFLICT(k) DO UPDATE SET v = excluded.v;`,
      name,
    );
  }

  // ---- UI-managed storage credentials (encrypted-at-rest; storage-credentials.ts) ----

  private rowToStorageCredential(r: Record<string, SqlStorageValue>): StorageCredentialRow {
    return {
      id: String(r.id),
      orgId: String(r.org_id),
      label: String(r.label),
      accessKeyId: String(r.access_key_id),
      secretIv: String(r.secret_iv),
      secretCiphertext: String(r.secret_ct),
      createdAt: Number(r.created_at),
    };
  }

  /// Persist an already-ENCRYPTED credential (the gateway seals the secret before calling this,
  /// so the DO never sees the plaintext secret). Returns the SAFE projection (no secret).
  async putStorageCredential(input: {
    orgId: string;
    label: string;
    accessKeyId: string;
    secretIv: string;
    secretCiphertext: string;
  }): Promise<StorageCredentialPublic> {
    const row: StorageCredentialRow = {
      id: `scr-${crypto.randomUUID()}`,
      orgId: input.orgId,
      label: input.label,
      accessKeyId: input.accessKeyId,
      secretIv: input.secretIv,
      secretCiphertext: input.secretCiphertext,
      createdAt: now(),
    };
    this.sql.exec(
      `INSERT INTO storage_credentials (id,org_id,label,access_key_id,secret_iv,secret_ct,created_at)
       VALUES (?,?,?,?,?,?,?);`,
      row.id, row.orgId, row.label, row.accessKeyId, row.secretIv, row.secretCiphertext, row.createdAt,
    );
    return { id: row.id, label: row.label, accessKeyId: row.accessKeyId, createdAt: row.createdAt };
  }

  /// List the SAFE projection of every managed credential — the encrypted secret is dropped.
  async listStorageCredentials(): Promise<StorageCredentialPublic[]> {
    return this.sql
      .exec(`SELECT id,label,access_key_id,created_at FROM storage_credentials ORDER BY created_at;`)
      .toArray()
      .map((r) => ({
        id: String(r.id),
        label: String(r.label),
        accessKeyId: String(r.access_key_id),
        createdAt: Number(r.created_at),
      }));
  }

  /// FULL row (incl. encrypted secret) — used ONLY server-side at presign time so the gateway
  /// can decrypt. Never serialize this to a client.
  async getStorageCredential(id: string): Promise<StorageCredentialRow | null> {
    const rows = this.sql.exec(`SELECT * FROM storage_credentials WHERE id = ? LIMIT 1;`, id).toArray();
    return rows.length ? this.rowToStorageCredential(rows[0]) : null;
  }

  /// Names of filespaces whose storage_credential_ref points at this credential id (in-use scan
  /// for delete-guard). Empty ⇒ safe to delete.
  async spacesUsingStorageCredential(id: string): Promise<string[]> {
    return this.sql
      .exec(`SELECT name FROM spaces WHERE storage_credential_ref = ? ORDER BY name;`, id)
      .toArray()
      .map((r) => String(r.name));
  }

  /// Delete a managed credential. Returns true if a row was removed (false ⇒ unknown id). The
  /// in-use guard is enforced by the gateway BEFORE calling this (it returns the referencing
  /// space names), so this is the unconditional delete after that check passes.
  async deleteStorageCredential(id: string): Promise<boolean> {
    const before = Number(this.sql.exec(`SELECT COUNT(*) AS c FROM storage_credentials WHERE id = ?;`, id).one().c);
    if (before === 0) return false;
    this.sql.exec(`DELETE FROM storage_credentials WHERE id = ?;`, id);
    return true;
  }

  // ---- filespace server-held master keys (encrypted-at-rest; filespace-keys.ts) ----

  private rowToFilespaceKey(r: Record<string, SqlStorageValue>): FilespaceKeyRow {
    return {
      spaceId: String(r.space_id),
      orgId: String(r.org_id),
      keyId: String(r.key_id),
      keyIv: String(r.key_iv),
      keyCiphertext: String(r.key_ct),
      createdAt: Number(r.created_at),
    };
  }

  /// Persist an already-SEALED filespace master key (the gateway seals it under STORAGE_ENC_KEY
  /// via filespace-keys.ts BEFORE calling this, so the DO never sees plaintext key material —
  /// exactly the `putStorageCredential` contract above). Creation uses `ifAbsent` so a racing
  /// retry cannot replace the original key; explicit key-import replacement uses upsert.
  async putFilespaceKey(input: {
    spaceId: string;
    orgId: string;
    keyId: string;
    keyIv: string;
    keyCiphertext: string;
    ifAbsent?: boolean;
  }): Promise<FilespaceKeyRow> {
    const row: FilespaceKeyRow = {
      spaceId: input.spaceId,
      orgId: input.orgId,
      keyId: input.keyId,
      keyIv: input.keyIv,
      keyCiphertext: input.keyCiphertext,
      createdAt: now(),
    };
    this.sql.exec(
      `INSERT INTO filespace_keys (space_id,org_id,key_id,key_iv,key_ct,created_at)
       VALUES (?,?,?,?,?,?)
       ${input.ifAbsent ? "ON CONFLICT(space_id) DO NOTHING" : "ON CONFLICT(space_id) DO UPDATE SET key_id=excluded.key_id, key_iv=excluded.key_iv, key_ct=excluded.key_ct, created_at=excluded.created_at"};`,
      row.spaceId, row.orgId, row.keyId, row.keyIv, row.keyCiphertext, row.createdAt,
    );
    return this.rowToFilespaceKey(this.sql.exec(`SELECT * FROM filespace_keys WHERE space_id = ?;`, input.spaceId).one());
  }

  /// FULL row (sealed) — server-side only. Used to (a) decrypt at delivery time and (b) check
  /// whether a space already has a key before generating/importing one. `null` ⇒ no server-held
  /// key provisioned yet for this space (a pre-existing filespace that hasn't been migrated, or
  /// — in principle — a space created before STORAGE_ENC_KEY was configured). Never serialize
  /// keyIv/keyCiphertext to a client.
  async getFilespaceKey(spaceId: string): Promise<FilespaceKeyRow | null> {
    const rows = this.sql.exec(`SELECT * FROM filespace_keys WHERE space_id = ? LIMIT 1;`, spaceId).toArray();
    return rows.length ? this.rowToFilespaceKey(rows[0]) : null;
  }

  // ---- UI-managed email-provider config (encrypted-at-rest; email-config.ts) ----

  private rowToEmailConfig(r: Record<string, SqlStorageValue>): EmailConfigRow {
    return {
      orgId: String(r.org_id),
      provider: String(r.provider) as EmailConfigRow["provider"],
      fromAddress: String(r.from_address),
      fromName: r.from_name == null ? null : String(r.from_name),
      region: r.region == null ? null : String(r.region),
      secretIv: String(r.secret_iv),
      secretCiphertext: String(r.secret_ct),
      sesAccessKeyId: r.ses_access_key_id == null ? null : String(r.ses_access_key_id),
      createdAt: Number(r.created_at),
      updatedAt: Number(r.updated_at),
    };
  }

  /// The FULL email-config row (incl. the encrypted secret) — used server-side to build the
  /// runtime sender. Null when the org has no managed config (env fallback applies). Never
  /// serialize this directly to a client; project to the safe shape in the handler.
  async getEmailConfig(): Promise<EmailConfigRow | null> {
    const rows = this.sql.exec(`SELECT * FROM email_config WHERE k = 'email' LIMIT 1;`).toArray();
    return rows.length ? this.rowToEmailConfig(rows[0]) : null;
  }

  /// Upsert the org's email config. The gateway seals the provider secret(s) BEFORE calling this,
  /// so the DO never sees a plaintext secret. Returns the stored row.
  async putEmailConfig(input: {
    orgId: string;
    provider: EmailConfigRow["provider"];
    fromAddress: string;
    fromName: string | null;
    region: string | null;
    secretIv: string;
    secretCiphertext: string;
    sesAccessKeyId: string | null;
  }): Promise<EmailConfigRow> {
    const ts = now();
    const existing = this.sql.exec(`SELECT created_at FROM email_config WHERE k = 'email' LIMIT 1;`).toArray();
    const createdAt = existing.length ? Number(existing[0].created_at) : ts;
    this.sql.exec(
      `INSERT INTO email_config
         (k,org_id,provider,from_address,from_name,region,secret_iv,secret_ct,ses_access_key_id,created_at,updated_at)
       VALUES ('email',?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(k) DO UPDATE SET
         org_id=excluded.org_id, provider=excluded.provider, from_address=excluded.from_address,
         from_name=excluded.from_name, region=excluded.region, secret_iv=excluded.secret_iv,
         secret_ct=excluded.secret_ct, ses_access_key_id=excluded.ses_access_key_id,
         updated_at=excluded.updated_at;`,
      input.orgId, input.provider, input.fromAddress, input.fromName, input.region,
      input.secretIv, input.secretCiphertext, input.sesAccessKeyId, createdAt, ts,
    );
    return {
      orgId: input.orgId,
      provider: input.provider,
      fromAddress: input.fromAddress,
      fromName: input.fromName,
      region: input.region,
      secretIv: input.secretIv,
      secretCiphertext: input.secretCiphertext,
      sesAccessKeyId: input.sesAccessKeyId,
      createdAt,
      updatedAt: ts,
    };
  }

  /// Delete the org's managed email config (revert to the env/default path). Returns true if a
  /// row was removed (false ⇒ none existed).
  async deleteEmailConfig(): Promise<boolean> {
    const before = Number(this.sql.exec(`SELECT COUNT(*) AS c FROM email_config WHERE k = 'email';`).one().c);
    if (before === 0) return false;
    this.sql.exec(`DELETE FROM email_config WHERE k = 'email';`);
    return true;
  }

  // ---- invites (raw persistence; token logic lives in invites.ts) ---------

  async putInvite(rec: InviteRecord): Promise<void> {
    this.sql.exec(
      `INSERT INTO invites
        (id,org_id,email,role,token_hash,space_id,inode_id,level,status,created_by,created_at,expires_at,accepted_by,accepted_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);`,
      rec.id, rec.orgId, rec.email, rec.role, rec.tokenHash, rec.spaceId, rec.inodeId, rec.level,
      rec.status, rec.createdByMemberId, rec.createdAt, rec.expiresAt, rec.acceptedByUserId, rec.acceptedAt,
    );
  }

  async getInviteByTokenHash(tokenHash: string): Promise<InviteRecord | null> {
    const r = this.sql.exec(`SELECT * FROM invites WHERE token_hash = ?;`, tokenHash).toArray();
    return r.length ? this.rowToInvite(r[0] as any) : null;
  }

  async getInvite(id: string): Promise<InviteRecord | null> {
    const r = this.sql.exec(`SELECT * FROM invites WHERE id = ?;`, id).toArray();
    return r.length ? this.rowToInvite(r[0] as any) : null;
  }

  async updateInviteStatus(id: string, status: InviteStatus, acceptedByUserId?: string): Promise<void> {
    if (status === "accepted" && acceptedByUserId) {
      this.sql.exec(
        `UPDATE invites SET status = ?, accepted_by = ?, accepted_at = ? WHERE id = ?;`,
        status, acceptedByUserId, now(), id,
      );
    } else {
      this.sql.exec(`UPDATE invites SET status = ? WHERE id = ?;`, status, id);
    }
  }

  async listPendingInvites(): Promise<InviteRecord[]> {
    const t = now();
    // lazily expire as we read (no alarm needed for the prototype)
    this.sql.exec(`UPDATE invites SET status='expired' WHERE status='pending' AND expires_at <= ?;`, t);
    return this.sql.exec(`SELECT * FROM invites WHERE status='pending' ORDER BY created_at;`)
      .toArray().map((r) => this.rowToInvite(r as any));
  }

  // ---- share links (durable backing for sharing.ts) ----------------------

  private rowToShareLink(r: Record<string, SqlStorageValue>): ShareLinkRow {
    return {
      id: String(r.id),
      orgId: String(r.org_id),
      spaceId: String(r.space_id),
      inodeId: String(r.inode_id),
      audience: String(r.audience) as "internal" | "public",
      level: String(r.level) as "read" | "edit" | "admin",
      tokenHash: String(r.token_hash),
      email: r.email === null ? null : String(r.email),
      createdByMemberId: String(r.created_by),
      createdAt: Number(r.created_at),
      expiresAt: Number(r.expires_at),
      revoked: Number(r.revoked) === 1,
    };
  }

  async putShareLink(rec: ShareLinkRow): Promise<void> {
    this.sql.exec(
      `INSERT INTO share_links
        (id,org_id,space_id,inode_id,audience,level,token_hash,email,created_by,created_at,expires_at,revoked)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(id) DO UPDATE SET audience=excluded.audience, level=excluded.level,
         email=excluded.email, expires_at=excluded.expires_at, revoked=excluded.revoked;`,
      rec.id, rec.orgId, rec.spaceId, rec.inodeId, rec.audience, rec.level, rec.tokenHash,
      rec.email, rec.createdByMemberId, rec.createdAt, rec.expiresAt, rec.revoked ? 1 : 0,
    );
  }

  async getShareLinkById(id: string): Promise<ShareLinkRow | null> {
    const r = this.sql.exec(`SELECT * FROM share_links WHERE id = ?;`, id).toArray();
    return r.length ? this.rowToShareLink(r[0] as any) : null;
  }

  async getShareLinkByTokenHash(tokenHash: string): Promise<ShareLinkRow | null> {
    const r = this.sql.exec(`SELECT * FROM share_links WHERE token_hash = ?;`, tokenHash).toArray();
    return r.length ? this.rowToShareLink(r[0] as any) : null;
  }

  async setShareLinkRevoked(id: string): Promise<void> {
    this.sql.exec(`UPDATE share_links SET revoked = 1 WHERE id = ?;`, id);
  }

  async listActiveShareLinks(spaceId?: string): Promise<ShareLinkRow[]> {
    const t = now();
    const rows = spaceId
      ? this.sql.exec(
          `SELECT * FROM share_links WHERE revoked = 0 AND expires_at > ? AND space_id = ? ORDER BY created_at;`,
          t, spaceId,
        )
      : this.sql.exec(`SELECT * FROM share_links WHERE revoked = 0 AND expires_at > ? ORDER BY created_at;`, t);
    return rows.toArray().map((r) => this.rowToShareLink(r as any));
  }

  // ---- ACL grants (written on invite-redeem; SPEC §4.10) ------------------

  private rowToGrant(r: Record<string, SqlStorageValue>): GrantRow {
    return {
      id: String(r.id),
      spaceId: String(r.space_id),
      inodeId: String(r.inode_id),
      principalType: String(r.principal_type) as "user" | "group" | "service_account",
      principalId: String(r.principal_id),
      level: String(r.level) as "read" | "edit" | "admin",
      mountAsRoot: Number(r.mount_as_root) === 1,
      expiresAt: r.expires_at === null ? null : Number(r.expires_at),
      grantedByMemberId: String(r.granted_by),
      grantedAt: Number(r.granted_at),
    };
  }

  async putGrant(rec: GrantRow): Promise<void> {
    this.sql.exec(
      `INSERT INTO grants
        (id,space_id,inode_id,principal_type,principal_id,level,mount_as_root,expires_at,granted_by,granted_at)
       VALUES (?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(id) DO UPDATE SET level=excluded.level, mount_as_root=excluded.mount_as_root,
         expires_at=excluded.expires_at;`,
      rec.id, rec.spaceId, rec.inodeId, rec.principalType, rec.principalId, rec.level,
      rec.mountAsRoot ? 1 : 0, rec.expiresAt ?? null, rec.grantedByMemberId, rec.grantedAt,
    );
  }

  async grantsForInode(inodeId: string): Promise<GrantRow[]> {
    return this.sql.exec(`SELECT * FROM grants WHERE inode_id = ?;`, inodeId)
      .toArray().map((r) => this.rowToGrant(r as any));
  }

  async grantsForPrincipal(principalType: string, principalId: string): Promise<GrantRow[]> {
    return this.sql.exec(
      `SELECT * FROM grants WHERE principal_type = ? AND principal_id = ?;`,
      principalType, principalId,
    ).toArray().map((r) => this.rowToGrant(r as any));
  }
}

/** Durable shape of an external share link row (mirrors sharing.ts ShareLinkRecord). */
export interface ShareLinkRow {
  id: string;
  orgId: string;
  spaceId: string;
  inodeId: string;
  audience: "internal" | "public";
  level: "read" | "edit" | "admin";
  tokenHash: string;
  email: string | null;
  createdByMemberId: string;
  createdAt: number;
  expiresAt: number;
  revoked: boolean;
}

/** Durable shape of an ACL grant row (mirrors permissions.ts Grant). */
export interface GrantRow {
  id: string;
  spaceId: string;
  inodeId: string;
  principalType: "user" | "group" | "service_account";
  principalId: string;
  level: "read" | "edit" | "admin";
  mountAsRoot: boolean;
  expiresAt: number | null;
  grantedByMemberId: string;
  grantedAt: number;
}

// ---------------------------------------------------------------------------
// handleOrgRequest — gateway-mountable entry point for org admin endpoints.
// Routes /v1/orgs/:orgId/{users,groups,spaces} to the OrgDO. Invites & sharing
// have their own modules (invites.ts, sharing.ts) that also talk to this DO.
// ---------------------------------------------------------------------------

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** The gateway resolves+authenticates the principal (security agent) and passes it in.
 *  We never parse tokens here. */
export interface AuthedContext {
  principalUserId: string;
  orgRole: OrgRole;
}

/// Max spaces per list response for which a per-space usedBytes RPC is made (admin view); beyond
/// this, `usedBytes` is omitted from the remaining entries.
const SPACES_LIST_USAGE_CAP = 50;
/// Max spaces per list response for which a per-space ACL check (one DO RPC each) is made for a
/// non-admin member. Beyond it the response is flagged `truncated`.
const SPACES_LIST_ACCESS_CAP = 200;

export async function handleOrgRequest(
  req: Request,
  env: OrgDOEnv,
  ctx: AuthedContext,
  pathParts: string[], // already-split path after /v1/orgs/:orgId — e.g. ["users", ...]
  orgId: string,
): Promise<Response> {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  const resource = pathParts[0];

  // Org management is owner/admin only (SPEC §4.2). CHANGE E: space_admin is an ORG-WIDE
  // admin (not per-space-scoped), so it is allowed wherever admin is for spaces; org-wide
  // user/group CRUD below still require admin+ (owner/admin). `isAdmin` excludes space_admin
  // intentionally for those org-management routes; space resources check space_admin explicitly.
  const isAdmin = ctx.orgRole === "owner" || ctx.orgRole === "admin";

  try {
    switch (resource) {
      case "users": {
        if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);
        if (req.method === "GET" && !pathParts[1]) return json(await stub.listUsers());
        if (req.method === "GET" && pathParts[1]) {
          const u = await stub.getUser(decodeURIComponent(pathParts[1]));
          return u ? json(u) : json({ error: "no such user" }, 404);
        }
        if (req.method === "POST") {
          if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);
          const b = (await req.json()) as any;

          if (b.kind === "service_account") {
            return json(await stub.createServiceAccount({ orgId, name: b.name, role: b.role }), 201);
          }
          return json(
            await stub.createUser({ orgId, email: b.email, displayName: b.displayName, role: b.role }),
            201,
          );
        }
        if (req.method === "PATCH" && pathParts[1]) {
          if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);
          const b = (await req.json()) as any;
          const id = decodeURIComponent(pathParts[1]);
          if (b.status) return json(await stub.setUserStatus(id, b.status));
          if (b.role) return json(await stub.setUserRole(id, b.role));
          return json({ error: "nothing to update" }, 400);
        }
        break;
      }

      case "groups": {
        if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);
        if (req.method === "GET") return json(await stub.listGroups());
        if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);
        if (req.method === "POST" && !pathParts[1]) {
          const b = (await req.json()) as any;
          return json(await stub.createGroup({ orgId, name: b.name, source: b.source }), 201);
        }
        // /groups/:groupId/members  (POST add, DELETE remove)
        if (pathParts[1] && pathParts[2] === "members") {
          const groupId = decodeURIComponent(pathParts[1]);
          if (req.method === "POST") {
            const b = (await req.json()) as any;
            await stub.addGroupMember(groupId, b.userId);
            return json({ ok: true });
          }
          if (req.method === "DELETE") {
            const u = new URL(req.url).searchParams.get("userId") ?? "";
            await stub.removeGroupMember(groupId, u);
            return json({ ok: true });
          }
        }
        if (req.method === "DELETE" && pathParts[1]) {
          await stub.deleteGroup(decodeURIComponent(pathParts[1]));
          return json({ ok: true });
        }
        break;
      }

      case "spaces": {
        if (req.method === "GET" && !pathParts[1]) {
          // Access-scoped list (see API.md §5 "List filespaces"). Org admins (owner/admin/space_admin)
          // get every live space with the full storage descriptor; a standard member gets only the
          // spaces where it holds an effective live grant (direct or via group) and NO storage
          // descriptor fields. `usedBytes` is filled for at most SPACES_LIST_USAGE_CAP spaces.
          const all = await stub.listSpaces();
          const orgAdminView = isAdmin || ctx.orgRole === "space_admin";
          const fsNs = env.FILESPACE;
          const groupIds = orgAdminView ? [] : await stub.groupsForUser(ctx.principalUserId);
          const aclP = { type: "user" as const, id: ctx.principalUserId, groupIds, orgRole: ctx.orgRole };
          let truncated = false;
          let partial = false;
          const rows = await Promise.all(all.map(async (sp, i) => {
            let summary: { hasAccess: boolean; folderAdmin: boolean; usedBytes: number | null } | null = null;
            if (!orgAdminView && i >= SPACES_LIST_ACCESS_CAP) { truncated = true; return { sp, summary }; }
            if (fsNs && (!orgAdminView || i < SPACES_LIST_USAGE_CAP)) {
              try {
                summary = await fsNs.get(fsNs.idFromName(`${orgId}::${sp.id}`)).spaceSummaryFor(aclP, i < SPACES_LIST_USAGE_CAP);
              } catch { summary = null; if (!orgAdminView) partial = true; }
            }
            return { sp, summary };
          }));
          const out: Array<Record<string, unknown>> = [];
          for (const { sp, summary } of rows) {
            if (orgAdminView) {
              out.push({
                ...sp,
                role: ctx.orgRole,
                ...(summary && summary.usedBytes !== null ? { usedBytes: summary.usedBytes } : {}),
              });
              continue;
            }
            if (!summary || !summary.hasAccess) continue; // fail closed
            out.push({
              id: sp.id, orgId: sp.orgId, name: sp.name, createdAt: sp.createdAt,
              role: summary.folderAdmin ? "folder_admin" : "standard",
              ...(summary.usedBytes !== null ? { usedBytes: summary.usedBytes } : {}),
            });
          }
          // Body stays a plain array (wire-compatible); degradation is signalled by headers.
          const headers: Record<string, string> = { "content-type": "application/json" };
          if (truncated) headers["x-cloudfs-spaces-truncated"] = "true";
          if (partial) headers["x-cloudfs-spaces-partial"] = "true";
          return new Response(JSON.stringify(out), { status: 200, headers });
        }
        // CREATE a space: POST /v1/orgs/:org/spaces (NO sub-path). The `!pathParts[1]` guard keeps
        // a POST to a sub-action (e.g. .../spaces/:id/purge) from falling into the create handler.
        if (req.method === "POST" && !pathParts[1]) {
          if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);
          const b = (await req.json()) as any;
          if (b.storageMode === "deployment") {
            const storage = describeDefaultStorage(env, new URL(req.url).protocol === "https:");
            if (!storage.configured) return json({ error: "default_storage_unconfigured", problems: storage.problems }, 409);
            b.bucketProvider = storage.provider;
            b.bucketName = storage.bucket;
            // An immutable snapshot of the destination avoids silently repointing existing
            // filespaces if the deployment default changes later. Credentials stay inherited.
            b.storageEndpoint = storage.endpoint;
            b.storageRegion = storage.region;
            b.storageBucket = storage.bucket;
            b.storageForcePathStyle = storage.forcePathStyle;
            b.storageCredentialRef = null;
            b.keyPrefix = "";
          }
          // P-F2: re-registering a PURGED id is refused — it must get a FRESH id, not revive into a
          // mid-/post-purge DO (split-brain). Pre-check here so registerSpace doesn't throw across
          // the RPC boundary on the happy gateway path (registerSpace still throws as defense in
          // depth for direct callers).
          if (typeof b.spaceId === "string" && b.spaceId.trim().length > 0
              && (await stub.isSpacePurged(b.spaceId.trim()))) {
            return json({ error: "space_purged" }, 409);
          }
          // Audit B12: only an OWNER may upsert an existing space through the create path
          // (the only path that can repoint storage / revive a deleted space). A non-owner
          // admin's create is INSERT-ONLY — a collision on an existing id is refused.
          const isOwner = ctx.orgRole === "owner";
          try {
            // Check the encryption key before persisting a new registry row. A configuration
            // error must not leave a visible filespace that can never be mounted.
            const existingKey = typeof b.spaceId === "string" ? await stub.getFilespaceKey(b.spaceId.trim()) : null;
            let preparedKey;
            if (!existingKey) {
              try { preparedKey = await generateSealedMasterKey(env.STORAGE_ENC_KEY); }
              catch { return json({ error: "storage_enc_key_unconfigured" }, 503); }
            }
            // `spaceId` is OPTIONAL on create: when the body omits it, registerSpace mints a stable
            // `fs-<uuid>` and returns it in the 201 body (the client routes by this id). Passing an
            // absent id here previously persisted the literal string "null" as the row id (BUG 5).
            const created = await stub.registerSpace({
              spaceId: b.spaceId,
              orgId,
              name: b.name,
              bucketProvider: b.bucketProvider,
              bucketName: b.bucketName,
              keyPrefix: b.keyPrefix,
              // Optional bring-your-own S3-compatible storage backend (secret-free; storage.ts).
              storageEndpoint: b.storageEndpoint ?? null,
              storageRegion: b.storageRegion ?? null,
              storageBucket: b.storageBucket ?? null,
              storageForcePathStyle: b.storageForcePathStyle ?? null,
              storageCredentialRef: b.storageCredentialRef ?? null,
              expectInsertOnly: !isOwner,
            });
            // Audit B21: an owner upsert can REVIVE a soft-deleted id (clear deleted_at) or repoint
            // storage — drop the cached registry row so the gate re-reads the live state.
            invalidateSpace(orgId, created.id);
            // ONBOARDING.md "Key model": provision the server-held filespace master key. Generate
            // ONLY if this space doesn't already have one — registerSpace UPSERTS by id, so a
            // REVIVE of a soft-deleted space (an owner re-POSTing the same id) must NOT get a new
            // key: its existing encrypted objects were written under the ORIGINAL key, and
            // clobbering it here would make them permanently unreadable. A brand-new spaceId (the
            // ordinary create path) never has a row yet, so this always provisions on first
            // create. The key material is NEVER included in `created` — registration responses
            // never carry key bytes.
            try {
              if (!(await stub.getFilespaceKey(created.id)) && preparedKey) {
                const sealed = preparedKey;
                await stub.putFilespaceKey({
                  spaceId: created.id, orgId, keyId: sealed.keyId,
                  keyIv: sealed.iv, keyCiphertext: sealed.ciphertext,
                  ifAbsent: true,
                });
              }
            } catch (e) {
              // Fail closed: a filespace with no usable master key is useless (every daemon mount
              // FATALs per ONBOARDING.md). The space row is already committed at this point —
              // surface a clear 500 so the admin fixes STORAGE_ENC_KEY. Retrying the SAME create
              // request is safe: registerSpace's upsert is idempotent and this branch re-enters
              // (getFilespaceKey is still null) until the key is successfully sealed.
              return json({ error: "storage_enc_key_unconfigured", detail: String((e as Error)?.message ?? e) }, 500);
            }
            // New filespace (no key existed before this request): seed the default GFS snapshot
            // schedules (daily x7, weekly x4). Best-effort — a failure must not fail the create;
            // the admin can still add schedules manually. Revives/upserts of an existing space skip it.
            if (!existingKey && env.FILESPACE) {
              try { await env.FILESPACE.get(env.FILESPACE.idFromName(`${orgId}::${created.id}`)).ensureDefaultSnapshotSchedules(); } catch { /* best-effort */ }
            }
            return json(created, 201);
          } catch (e) {
            const msg = String((e as Error)?.message ?? e);
            if (msg.startsWith("space_exists")) return json({ error: "space_exists", reason: "storage/reconfigure is owner-only (PATCH)" }, 409);
            if (msg.startsWith("space_purged")) return json({ error: "space_purged" }, 409);
            throw e;
          }
        }
        // PATCH /v1/orgs/:org/spaces/:id — update an EXISTING space's mutable fields (name +
        // bring-your-own storage descriptor). Name edits are admin/space_admin gated; CHANGE E
        // reserves STORAGE-BACKEND edits to the org OWNER (see below). Only the keys present in the
        // body are applied; `registerSpace` (create) is untouched. 404 on an unknown space id.
        if (req.method === "PATCH" && pathParts[1]) {
          if (!(isAdmin || ctx.orgRole === "space_admin")) {
            return json({ error: "forbidden: admin required" }, 403);
          }
          const spaceId = decodeURIComponent(pathParts[1]);
          const b = (await req.json()) as any;
          const patch: {
            name?: string;
            storageEndpoint?: string | null;
            storageRegion?: string | null;
            storageBucket?: string | null;
            storageForcePathStyle?: boolean | null;
            storageCredentialRef?: string | null;
          } = {};
          if (b.name !== undefined) patch.name = b.name;
          // CHANGE E: repointing a space's STORAGE BACKEND is the single most dangerous
          // op (it can silently redirect every read/write to attacker-controlled storage
          // or orphan all existing blocks), so it is reserved to the org OWNER alone — a
          // space_admin/admin attempting it gets 403. Non-storage fields (display name)
          // stay admin/space_admin-editable above. `provider`/`bucket`/`region` here are
          // the storage-backend fields; the create-time bucketProvider is not patchable.
          const touchesStorageBackend =
            b.storageEndpoint !== undefined ||
            b.storageRegion !== undefined ||
            b.storageBucket !== undefined ||
            b.storageForcePathStyle !== undefined ||
            b.storageCredentialRef !== undefined ||
            b.bucketProvider !== undefined ||
            b.provider !== undefined;
          if (touchesStorageBackend && ctx.orgRole !== "owner") {
            return json({ error: "forbidden: owner required to repoint storage backend" }, 403);
          }
          if (b.storageEndpoint !== undefined) patch.storageEndpoint = b.storageEndpoint;
          if (b.storageRegion !== undefined) patch.storageRegion = b.storageRegion;
          if (b.storageBucket !== undefined) patch.storageBucket = b.storageBucket;
          if (b.storageForcePathStyle !== undefined) patch.storageForcePathStyle = b.storageForcePathStyle;
          if (b.storageCredentialRef !== undefined) patch.storageCredentialRef = b.storageCredentialRef;
          if (Object.keys(patch).length === 0) return json({ error: "nothing to update" }, 400);
          const updated = await stub.updateSpace(spaceId, patch);
          // Audit B21: a storage-backend repoint changes where the gate presigns — drop the cached
          // registry row so the next presign resolves the live descriptor (also keeps the gate's
          // soft-delete read fresh after any registry edit).
          if (updated) invalidateSpace(orgId, spaceId);
          return updated ? json(updated) : json({ error: "no such space" }, 404);
        }
        // DELETE /v1/orgs/:org/spaces/:id — owner-gated SOFT delete of a filespace. Reserved to
        // the org OWNER alone (mirrors the CHANGE E owner-gate on storage-backend repointing): a
        // space_admin/admin attempting it gets 403. This is REVERSIBLE — it only sets the OrgDO
        // registry's `deleted_at` marker so the space vanishes from the registry and the gateway
        // refuses every filespace-plane op on it.
        //
        // TODO(r2-cleanup): this is a SOFT delete by design. The encrypted blocks in R2/object
        // storage and the FilespaceDO's SQLite are deliberately LEFT INTACT so the space stays
        // recoverable. Purging the underlying objects (and tearing down the FilespaceDO) is a
        // SEPARATE, deliberate decision the maintainer will make later — it is intentionally NOT
        // part of this change. Do NOT add R2 deletion here.
        // ---- MIGRATION: POST /v1/orgs/:org/spaces/:id/key/import — owner/admin-only upload of an
        // EXISTING master key (ONBOARDING.md "Key model" migration path). For a filespace that
        // predates the key service (its data was encrypted under an operator-provisioned
        // key.hex / Keychain `com.cloudfs.masterkey` item), this is how that EXACT key gets into
        // the server store so a fresh device's daemon can fetch it too. Refuses to clobber an
        // existing server-held key unless `replace:true` is explicit (a replace on a space with
        // existing encrypted data makes that old content unreadable unless the uploaded material
        // IS the same key it was written under — the response carries a `warning` reminder).
        if (pathParts[1] && pathParts[2] === "key" && pathParts[3] === "import" && req.method === "POST") {
          if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);
          const spaceId = decodeURIComponent(pathParts[1]);
          if (!(await stub.getSpace(spaceId))) return json({ error: "no such space" }, 404);
          const b = (await req.json().catch(() => ({}))) as { material?: unknown; replace?: unknown };
          const material = typeof b.material === "string" ? b.material : "";
          if (!material) return json({ error: "invalid_body", reason: "material (base64, 32 bytes) is required" }, 400);
          const replace = b.replace === true;
          const existingKey = await stub.getFilespaceKey(spaceId);
          if (existingKey && !replace) {
            return json({
              error: "key_exists",
              reason: "a server-held key already exists for this filespace; pass replace:true to overwrite it",
            }, 409);
          }
          let sealed;
          try {
            sealed = await sealImportedMasterKey(env.STORAGE_ENC_KEY, material);
          } catch (e) {
            if (e instanceof MasterKeyError) return json({ error: e.code, reason: e.message }, 400);
            return json({ error: "storage_enc_key_unconfigured", detail: String((e as Error)?.message ?? e) }, 500);
          }
          const row = await stub.putFilespaceKey({
            spaceId, orgId, keyId: sealed.keyId, keyIv: sealed.iv, keyCiphertext: sealed.ciphertext,
          });
          return json({
            keyId: row.keyId,
            replaced: !!existingKey,
            ...(existingKey
              ? { warning: "Replacing the master key on a filespace with existing encrypted data makes that old content unreadable UNLESS the uploaded material is the SAME key it was originally encrypted under." }
              : {}),
          }, existingKey ? 200 : 201);
        }
        if (req.method === "DELETE" && pathParts[1]) {
          if (ctx.orgRole !== "owner") {
            return json({ error: "forbidden: owner required to delete a filespace" }, 403);
          }
          const spaceId = decodeURIComponent(pathParts[1]);
          const res = await stub.deleteSpace(spaceId);
          if (!res.deleted) return json({ error: "no such space" }, 404);
          // Audit B21: the soft-delete tombstone MUST bite immediately — drop the cached registry row
          // so the very next filespace-plane request 410s instead of being admitted for up to the TTL.
          invalidateSpace(orgId, spaceId);
          // Defense in depth: also flip the target FilespaceDO's durable tombstone so even a
          // DIRECT (non-gateway) data-plane DO call is refused. Best-effort — the OrgDO registry
          // marker (above) is the source of truth the gateway gate reads, so a FilespaceDO blip
          // here never fails the delete. The DO name is the `<org>::<space>` form the gateway uses.
          if (env.FILESPACE) {
            try {
              const fsStub = env.FILESPACE.get(env.FILESPACE.idFromName(`${orgId}::${spaceId}`));
              await fsStub.markDeleted();
            } catch {
              /* tombstone is belt-and-suspenders; the registry marker already refuses ops */
            }
          }
          // Idempotent: a re-delete of an already-deleted space still returns success (200).
          return json({ deleted: true, id: spaceId });
        }
        // ---- PURGE: /v1/orgs/:org/spaces/:id/purge — owner-gated, two-step, IRREVERSIBLE -------
        // POST kicks off an async, prefix-scoped sweep that PERMANENTLY deletes the space's
        // encrypted objects from BYO storage AND then hard-deletes its DO metadata + registry row.
        // GET polls progress. This is a SEPARATE action from the DELETE soft-delete above: it is
        // ONLY allowed on an ALREADY soft-deleted space (two-step), and the body must echo the
        // exact spaceId as confirmation. See the SAFETY INVARIANTS in filespace-do.ts startPurge().
        if (pathParts[1] && pathParts[2] === "purge") {
          const spaceId = decodeURIComponent(pathParts[1]);
          // (2) OWNER-ONLY — mirrors the soft-delete + storage-repoint owner gates.
          if (ctx.orgRole !== "owner") {
            return json({ error: "forbidden: owner required to purge a filespace" }, 403);
          }

          // GET: status poll (no mutation). Owner-only too (above). Reads the FilespaceDO's purge
          // progress; an absent/never-purged space reports purging:false, done:false.
          if (req.method === "GET") {
            if (!env.FILESPACE) return json({ error: "purge_unavailable" }, 503);
            // If the registry row is GONE, the purge has FINALIZED: hardDeleteSpace removed the row
            // and the FilespaceDO's storage — including its `meta`/`meta_text` tables — was wiped by
            // deleteAll(). Calling purgeStatus() on that wiped DO throws `no such table: meta`, so we
            // must report completion HERE instead. The web's PurgeCard treats this 404 as the "purge
            // done" success signal. (While a purge is still in flight or failed-terminal the row
            // still exists, so we fall through to the live FilespaceDO status below.)
            const reg = await stub.getSpaceIncludingDeleted(spaceId);
            if (!reg) return json({ id: spaceId, purging: false, done: true }, 404);
            const fsStub = env.FILESPACE.get(env.FILESPACE.idFromName(`${orgId}::${spaceId}`));
            const status = await fsStub.purgeStatus();
            return json({ id: spaceId, ...status });
          }

          if (req.method === "POST") {
            // (1) TWO-STEP: the space MUST already be soft-deleted. A LIVE space (or unknown id) is
            // refused with 409 must_soft_delete_first — there is NO delete+purge in one call.
            const reg = await stub.getSpaceIncludingDeleted(spaceId);
            if (!reg) return json({ error: "no such space" }, 404);
            if (reg.deletedAt == null) {
              return json({ error: "must_soft_delete_first" }, 409);
            }
            // (3) EXPLICIT CONFIRMATION: the body must echo the exact spaceId and it must match the
            // path :id. A missing/wrong confirm is 400 confirmation_required (the web UI makes the
            // owner type the filespace name/id).
            let body: { confirm?: string } = {};
            try {
              body = (await req.json()) as { confirm?: string };
            } catch {
              /* empty/invalid body → confirm undefined → 400 below */
            }
            if (typeof body.confirm !== "string" || body.confirm !== spaceId) {
              return json({ error: "confirmation_required" }, 400);
            }
            if (!env.FILESPACE) return json({ error: "purge_unavailable" }, 503);

            // Kick off the async, prefix-scoped sweep. The prefix is built INSIDE the DO from the
            // TRUSTED orgId+spaceId (path-derived, tenant-asserted upstream), never from the body.
            // The descriptor is the space's secret-free storage row so the sweep resolves the SAME
            // per-space credentials the presigner uses.
            const descriptor: SpaceStorageDescriptor = {
              provider: reg.bucketProvider,
              endpoint: reg.storageEndpoint,
              region: reg.storageRegion,
              bucket: reg.storageBucket,
              forcePathStyle: reg.storageForcePathStyle,
              credentialRef: reg.storageCredentialRef,
            };
            const fsStub = env.FILESPACE.get(env.FILESPACE.idFromName(`${orgId}::${spaceId}`));
            // P-F2: durably mark the registry row 'purging' BEFORE arming the sweep so a concurrent
            // re-register of this id cannot revive it (clear deleted_at) and route live traffic into
            // the mid-purge DO (split-brain). registerSpace now throws space_purged on this id.
            await stub.markSpacePurging(spaceId);
            // Audit B21: a purging space must never serve a presign/mutation — drop the cached
            // registry row so the gate re-reads the (already-deleted) tombstone state immediately.
            invalidateSpace(orgId, spaceId);
            // Audit the purge INITIATION to the space's own (soon-to-be-wiped) audit chain plus —
            // durably — the OrgDO is the registry authority; we record it best-effort and never
            // fail the purge on a logging error.
            try {
              await fsStub.appendAudit({
                actorSub: ctx.principalUserId,
                actorType: "session",
                orgId,
                spaceId,
                action: "space.purge.initiate",
                decision: "allow",
                detail: { confirmed: true },
              });
            } catch {
              /* audit is best-effort */
            }
            const res = await fsStub.startPurge({ orgId, spaceId, descriptor });
            return json({ purging: true, id: spaceId, prefix: res.prefix }, 202);
          }
        }
        break;
      }

      // Org-level routes: `/v1/orgs/:org` with no sub-resource. PATCH renames the org. Owner/admin
      // only (SPEC §4.2). The org's stable slug is its id; only the display name is mutable.
      case undefined: {
        if (req.method === "PATCH") {
          if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);
          const b = (await req.json()) as any;
          if (typeof b.name !== "string" || b.name.trim().length === 0) {
            return json({ error: "invalid_name" }, 400);
          }
          if (b.name.trim().length > 100) return json({ error: "invalid_name" }, 400);
          await stub.setOrgName(b.name.trim());
          return json({ orgId, name: b.name.trim(), slug: orgId });
        }
        if (req.method === "GET") {
          return json({ orgId, name: await stub.getOrgName(), slug: orgId });
        }
        break;
      }
    }
    return json({ error: "not found" }, 404);
  } catch (e: any) {
    return json({ error: String(e?.message ?? e) }, 500);
  }
}
