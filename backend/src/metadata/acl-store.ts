// SPDX-License-Identifier: AGPL-3.0-or-later
/// SQLite-backed adapter binding the multiuser permissions module
/// (`src/permissions.ts`) to the FilespaceDO's storage.
///
/// `canAccess()` is pure + synchronous, so its `PermissionStore` reads must be
/// synchronous. DO SQLite IS synchronous, so we run the evaluation INSIDE the DO
/// (where `this.sql` lives) — the integration note's recommended home for the
/// ACL store, since the inode tree AND the grants both belong to the filespace
/// (multiuser-INTEGRATION.md §4). The gateway passes the resolved Principal
/// (incl. groupIds fetched from OrgDO); the DO never couples to OrgDO.
///
/// We do NOT reimplement the evaluator — we only supply the store shape it reads.

import type {
  Grant,
  InodeNode,
  MutablePermissionStore,
  PrincipalType,
  Principal,
} from "../permissions";

export class DoAclStore implements MutablePermissionStore {
  constructor(private readonly sql: SqlStorage, private readonly onChange: () => void = () => {}) {}

  /// The `items` table already models the inode tree: id, parent → parentId,
  /// is_dir → type. Tombstoned items are treated as absent.
  getInode(inodeId: string): InodeNode | null {
    const r = this.sql
      .exec(`SELECT id, parent, is_dir, deleted FROM items WHERE id = ?;`, inodeId)
      .toArray()[0];
    if (!r || Number(r.deleted) === 1) return null;
    return {
      id: String(r.id),
      parentId: r.parent === null ? null : String(r.parent),
      type: Number(r.is_dir) === 1 ? "folder" : "file",
    };
  }

  /// N-F1: like `getInode` but IGNORES the tombstone flag — returns the inode (and its parent link)
  /// even when `deleted=1`. Needed to evaluate readability of a DELETION event against the item's
  /// PRE-deletion position: a deletion must reach every principal who could previously see the item,
  /// so the ancestor walk must traverse rows that `getInode` (correctly) hides for live reads. The
  /// row may be physically absent (returns null) only if it never existed.
  getRawInode(inodeId: string): InodeNode | null {
    const r = this.sql
      .exec(`SELECT id, parent, is_dir FROM items WHERE id = ?;`, inodeId)
      .toArray()[0];
    if (!r) return null;
    return {
      id: String(r.id),
      parentId: r.parent === null ? null : String(r.parent),
      type: Number(r.is_dir) === 1 ? "folder" : "file",
    };
  }

  grantsForInode(inodeId: string): Grant[] {
    return this.sql
      .exec(`SELECT * FROM grants WHERE inode_id = ?;`, inodeId)
      .toArray()
      .map((r) => this.rowToGrant(r as any));
  }

  /** Only live grants for this identity/group union on existing, nondeleted inodes.
   * Used for filespace entry points; it does not authorize any other file or ancestor. */
  matchingLiveInodes(principal: Principal, now = Date.now()): { id: string; name: string; isDir: boolean; mountAsRoot: boolean }[] {
    const groups = principal.type === "group" ? [principal.id] : principal.groupIds ?? [];
    return this.sql.exec(`SELECT i.id, i.name, i.is_dir, MAX(g.mount_as_root) AS mount_as_root
      FROM grants g JOIN items i ON i.id = g.inode_id
      WHERE i.deleted = 0 AND (g.expires_at IS NULL OR g.expires_at = 0 OR g.expires_at > ?)
        AND ((g.principal_type IN ('user','service_account') AND ? IN ('user','service_account') AND g.principal_id = ?)
          OR (g.principal_type = 'group' AND g.principal_id IN (SELECT value FROM json_each(?))))
      GROUP BY i.id, i.name, i.is_dir ORDER BY i.name, i.id;`, now, principal.type, principal.id, JSON.stringify(groups))
      .toArray().map(row => ({ id: String(row.id), name: String(row.name), isDir: Number(row.is_dir) === 1, mountAsRoot: Number(row.mount_as_root) === 1 }));
  }

  putGrant(g: Grant): void {
    this.onChange();
    if (this.isRevokedPrincipal(g.principalType, g.principalId)) throw new Error("principal was deleted");
    if (g.level === "admin" && this.isDisabledAuthority(g.principalType, g.principalId)) throw new Error("principal delegation is disabled");
    this.sql.exec(
      `INSERT OR REPLACE INTO grants
       (id,space_id,inode_id,principal_type,principal_id,level,mount_as_root,expires_at,granted_by,granted_at,authority_grant_id,authority_inode_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?);`,
      g.id, g.spaceId, g.inodeId, g.principalType, g.principalId, g.level,
      g.mountAsRoot ? 1 : 0, g.expiresAt ?? null, g.grantedByMemberId, g.grantedAt,
      g.authorityGrantId ?? null, g.authorityInodeId ?? null,
    );
  }

  deleteGrant(grantId: string): boolean {
    this.onChange();
    const before = Number(this.sql.exec(`SELECT COUNT(*) AS c FROM grants WHERE id = ?;`, grantId).one().c);
    if (before === 0) return false;
    this.sql.exec(`DELETE FROM grants WHERE id = ?;`, grantId);
    return true;
  }

  /// Finding I3: drop every grant attached to a set of inode ids. Inode ids are
  /// path-deterministic (`id=parent/name`), so a tombstoned item's stale grants
  /// would silently RE-APPLY if an item is later recreated at the same path
  /// (privilege escalation). Called at RECREATE-time (the deleted→live transition in
  /// FilespaceDO.createItem), NOT at delete-time: grants deliberately SURVIVE a
  /// deletion so the change-feed tombstone delivery (N-F1) can walk to them and
  /// notify the grant-holder; clearing them on recreate prevents the resurrection.
  /// Set-based: chunked IN (...) so a large id set stays a handful of statements
  /// rather than one-per-inode. Returns rows deleted.
  deleteGrantsForInodes(inodeIds: string[]): number {
    this.onChange();
    if (inodeIds.length === 0) return 0;
    let deleted = 0;
    // DO SQLite caps bind variables per statement (well below SQLite's default),
    // so a big subtree delete must be chunked. `rowsWritten` gives the per-chunk
    // delete count without a second COUNT round-trip.
    const CHUNK = 50;
    for (let i = 0; i < inodeIds.length; i += CHUNK) {
      const chunk = inodeIds.slice(i, i + CHUNK);
      const placeholders = chunk.map(() => "?").join(",");
      const cursor = this.sql.exec(
        `DELETE FROM grants WHERE inode_id IN (${placeholders});`,
        ...chunk,
      );
      deleted += cursor.rowsWritten;
    }
    return deleted;
  }

  findGrants(inodeId: string, principalType: PrincipalType, principalId: string): Grant[] {
    return this.sql
      .exec(
        `SELECT * FROM grants WHERE inode_id = ? AND principal_type = ? AND principal_id = ?;`,
        inodeId, principalType, principalId,
      )
      .toArray()
      .map((r) => this.rowToGrant(r as any));
  }

  allGrants(): Grant[] {
    return this.sql.exec(`SELECT * FROM grants;`).toArray().map(row => this.rowToGrant(row));
  }

  isRevokedPrincipal(type: PrincipalType, id: string): boolean {
    return this.sql.exec(`SELECT 1 FROM revoked_acl_principals WHERE principal_type=? AND principal_id=?;`, type, id).toArray().length > 0;
  }

  isDisabledAuthority(type: PrincipalType, id: string): boolean {
    return type !== "group" && this.sql.exec(`SELECT 1 FROM disabled_acl_authorities WHERE principal_id=?;`, id).toArray().length > 0;
  }

  revokeDeletedPrincipal(type: PrincipalType, id: string): void {
    this.onChange();
    this.sql.exec(`INSERT OR IGNORE INTO revoked_acl_principals VALUES (?,?);`, type, id);
    this.sql.exec(`DELETE FROM grants WHERE principal_type=? AND principal_id=?;`, type, id);
  }

  private rowToGrant(r: Record<string, SqlStorageValue>): Grant {
    return {
      id: String(r.id),
      spaceId: r.space_id === null ? "" : String(r.space_id),
      inodeId: String(r.inode_id),
      principalType: String(r.principal_type) as PrincipalType,
      principalId: String(r.principal_id),
      level: String(r.level) as Grant["level"],
      mountAsRoot: Number(r.mount_as_root) === 1,
      expiresAt: r.expires_at === null ? null : Number(r.expires_at),
      grantedByMemberId: r.granted_by === null ? "" : String(r.granted_by),
      grantedAt: Number(r.granted_at),
      authorityGrantId: r.authority_grant_id == null ? null : String(r.authority_grant_id),
      authorityInodeId: r.authority_inode_id == null ? null : String(r.authority_inode_id),
    };
  }
}
