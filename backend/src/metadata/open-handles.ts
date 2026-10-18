// SPDX-License-Identifier: AGPL-3.0-or-later

export const OPEN_HANDLE_READ = 1;
export const OPEN_HANDLE_WRITE = 2;
export const OPEN_HANDLE_DELETE = 4;
export const OPEN_HANDLE_MASK = OPEN_HANDLE_READ | OPEN_HANDLE_WRITE | OPEN_HANDLE_DELETE;
export const OPEN_HANDLE_MAX_TTL_MS = 120_000;
export const OPEN_HANDLE_MAX_PER_OWNER = 4096;
export const OPEN_HANDLE_MAX_TOTAL = 65_536;
export const OPEN_HANDLE_REAP_BATCH_MAX = 256;

export type OpenHandle = {
  handleId: string;
  owner: string;
  inodeId: string;
  accessMask: number;
  shareMask: number;
  openedAt: number;
  expiresAt: number;
};

export type OpenHandleResult =
  | { granted: true; handle: OpenHandle; reused: boolean }
  | { granted: false; reason: "invalid" | "expired" | "handle_conflict" | "not_found" | "sharing_violation" | "capacity" };

/** Per-filespace open descriptions. Callers wrap mutations in transactionSync
 * so handle admission, namespace changes, and final payload release are atomic. */
export class OpenHandleStore {
  constructor(private readonly sql: SqlStorage) {}

  acquire(input: {
    handleId: string;
    owner: string;
    inodeId: string;
    accessMask: number;
    shareMask: number;
    expiresAt: number;
  }, now = Date.now()): OpenHandleResult {
    if (!input.handleId || input.handleId.length > 128 || !input.owner || input.owner.length > 512
      || !input.inodeId || !Number.isSafeInteger(input.accessMask) || input.accessMask < 0
      || (input.accessMask & ~OPEN_HANDLE_MASK) !== 0 || !Number.isSafeInteger(input.shareMask)
      || input.shareMask < 0 || (input.shareMask & ~OPEN_HANDLE_MASK) !== 0) return { granted: false, reason: "invalid" };

    const prior = this.row(input.handleId);
    if (prior) {
      if (prior.expiresAt <= now) return { granted: false, reason: "expired" };
      if (prior.owner !== input.owner || prior.inodeId !== input.inodeId
        || prior.accessMask !== input.accessMask || prior.shareMask !== input.shareMask) {
        return { granted: false, reason: "handle_conflict" };
      }
      if (!this.validExpiry(input.expiresAt, now)) return { granted: false, reason: "invalid" };
      // A retry is only a read of the original grant; it cannot renew or widen it.
      return { granted: true, handle: prior, reused: true };
    }
    if (!this.validExpiry(input.expiresAt, now)) return { granted: false, reason: "invalid" };

    const inode = this.sql.exec(`SELECT deleted FROM items WHERE id=?;`, input.inodeId).toArray()[0];
    if (!inode || Number(inode.deleted) !== 0) return { granted: false, reason: "not_found" };

    const active = this.sql.exec(`SELECT access_mask,share_mask FROM open_handles WHERE inode_id=? AND expires_at>?;`, input.inodeId, now).toArray();
    for (const row of active) {
      const existingAccess = Number(row.access_mask), existingShare = Number(row.share_mask);
      if ((existingAccess & ~input.shareMask) !== 0 || (input.accessMask & ~existingShare) !== 0) {
        return { granted: false, reason: "sharing_violation" };
      }
    }

    const total = Number(this.sql.exec(`SELECT COUNT(*) AS count FROM open_handles WHERE expires_at>?;`, now).one().count);
    const ownerCount = Number(this.sql.exec(`SELECT COUNT(*) AS count FROM open_handles WHERE owner=? AND expires_at>?;`, input.owner, now).one().count);
    if (total >= OPEN_HANDLE_MAX_TOTAL || ownerCount >= OPEN_HANDLE_MAX_PER_OWNER) return { granted: false, reason: "capacity" };

    this.sql.exec(`INSERT INTO open_handles(handle_id,owner,inode_id,access_mask,share_mask,opened_at,expires_at)
      VALUES(?,?,?,?,?,?,?);`, input.handleId, input.owner, input.inodeId, input.accessMask, input.shareMask, now, input.expiresAt);
    return { granted: true, handle: this.row(input.handleId)!, reused: false };
  }

  renew(handleId: string, owner: string, expiresAt: number, now = Date.now()): { renewed: true; handle: OpenHandle } | { renewed: false; reason: "not_found" | "forbidden" | "expired" | "invalid" } {
    if (!this.validExpiry(expiresAt, now)) return { renewed: false, reason: "invalid" };
    const row = this.row(handleId);
    if (!row) return { renewed: false, reason: "not_found" };
    if (row.owner !== owner) return { renewed: false, reason: "forbidden" };
    if (row.expiresAt <= now) return { renewed: false, reason: "expired" };
    this.sql.exec(`UPDATE open_handles SET expires_at=? WHERE handle_id=? AND owner=? AND expires_at>?;`, expiresAt, handleId, owner, now);
    return { renewed: true, handle: this.row(handleId)! };
  }

  close(handleId: string, owner: string): { closed: true; inodeId: string | null } | { closed: false; reason: "not_found" | "forbidden" } {
    const row = this.row(handleId);
    if (!row) return { closed: false, reason: "not_found" };
    if (row.owner !== owner) return { closed: false, reason: "forbidden" };
    this.sql.exec(`DELETE FROM open_handles WHERE handle_id=? AND owner=?;`, handleId, owner);
    return { closed: true, inodeId: row.inodeId };
  }

  get(handleId: string): OpenHandle | null {
    return this.row(handleId);
  }

  hasAnyFor(inodeId: string, owner: string, now = Date.now()): boolean {
    return this.sql.exec(`SELECT 1 FROM open_handles WHERE inode_id=? AND owner=? AND expires_at>? LIMIT 1;`,
      inodeId, owner, now).toArray().length > 0;
  }

  hasAccess(inodeId: string, owner: string, requiredMask: number, now = Date.now()): boolean {
    if (!Number.isSafeInteger(requiredMask) || requiredMask <= 0 || (requiredMask & ~OPEN_HANDLE_MASK) !== 0) return false;
    return this.sql.exec(`SELECT 1 FROM open_handles WHERE inode_id=? AND owner=? AND expires_at>?
      AND (access_mask & ?)=? LIMIT 1;`, inodeId, owner, now, requiredMask, requiredMask).toArray().length > 0;
  }

  /** A foreign exclusive lease may survive namespace replacement only when
   * its holder still has a writable open description that permits deletion. */
  hasWritableDeleteShareHandle(inodeId: string, owner: string, now = Date.now()): boolean {
    return this.sql.exec(`SELECT 1 FROM open_handles WHERE inode_id=? AND owner=? AND expires_at>?
      AND (access_mask & ?)=? AND (share_mask & ?)=? LIMIT 1;`,
      inodeId, owner, now, OPEN_HANDLE_WRITE, OPEN_HANDLE_WRITE, OPEN_HANDLE_DELETE, OPEN_HANDLE_DELETE).toArray().length > 0;
  }

  hasOpens(inodeId: string, now = Date.now()): boolean {
    return this.sql.exec(`SELECT 1 FROM open_handles WHERE inode_id=? AND expires_at>? LIMIT 1;`, inodeId, now).toArray().length > 0;
  }

  deleteSharingAllowed(inodeId: string, now = Date.now(), owner?: string, initiatorHandle?: string): boolean {
    // A caller may exempt its own unlinking open description only when the
    // exact active record is bound to this owner/inode and carries DELETE
    // access. A guessed handle id, a different owner's handle, or an ordinary
    // open without DELETE access never bypasses another open's share mode.
    return this.sql.exec(`SELECT 1 FROM open_handles WHERE inode_id=? AND expires_at>? AND (share_mask & ?)=0
      AND NOT (handle_id=? AND owner=? AND (access_mask & ?)=? ) LIMIT 1;`,
      inodeId, now, OPEN_HANDLE_DELETE, initiatorHandle ?? "", owner ?? "", OPEN_HANDLE_DELETE, OPEN_HANDLE_DELETE).toArray().length === 0;
  }

  /** Delete at most `limit` expired rows and return their inode ids. Callers
   * release payloads for those ids in the same transaction, after all rows in
   * the bounded batch have been removed. */
  reapCandidates(now = Date.now(), limit = OPEN_HANDLE_REAP_BATCH_MAX): string[] {
    if (!Number.isSafeInteger(limit) || limit < 1) return [];
    const bounded = Math.min(limit, OPEN_HANDLE_REAP_BATCH_MAX);
    const rows = this.sql.exec(`SELECT handle_id,inode_id FROM open_handles WHERE expires_at<=?
      ORDER BY expires_at,handle_id LIMIT ${bounded};`, now).toArray();
    const inodes = new Set<string>();
    for (const row of rows) {
      this.sql.exec(`DELETE FROM open_handles WHERE handle_id=? AND expires_at<=?;`, String(row.handle_id), now);
      inodes.add(String(row.inode_id));
    }
    return [...inodes];
  }

  nextExpiry(): number | null {
    const value = this.sql.exec(`SELECT MIN(expires_at) AS expires_at FROM open_handles;`).one().expires_at;
    return value === null ? null : Number(value);
  }

  private validExpiry(expiresAt: number, now: number): boolean {
    return Number.isSafeInteger(expiresAt) && expiresAt > now && expiresAt <= now + OPEN_HANDLE_MAX_TTL_MS;
  }

  private row(handleId: string): OpenHandle | null {
    const row = this.sql.exec(`SELECT * FROM open_handles WHERE handle_id=?;`, handleId).toArray()[0];
    return row ? {
      handleId: String(row.handle_id), owner: String(row.owner), inodeId: String(row.inode_id),
      accessMask: Number(row.access_mask), shareMask: Number(row.share_mask), openedAt: Number(row.opened_at),
      expiresAt: Number(row.expires_at),
    } : null;
  }
}
