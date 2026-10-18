// SPDX-License-Identifier: AGPL-3.0-or-later
// Handle-owned SMB ranges are separate from whole-inode publication leases.
// Decimal strings preserve the complete UInt64 wire domain through JSON/SQLite.
import type { LockResult } from './types';

export interface FileLockRange { offset: string; length: string; exclusive: boolean }
interface RangeRow extends Record<string, SqlStorageValue> { path: string; owner: string; handle: string; fence: number; expires_at: number; ranges: string }
export interface RangeAccess { allowed: boolean; reason?: string; heldBy?: string; permitTtlMs?: number; permitFence?: number }
const READ_PERMIT_MS = 1_000;
const MAX_U64 = (1n << 64n) - 1n;
export function validRange(value: unknown): value is FileLockRange {
  if (!value || typeof value !== 'object') return false;
  const r = value as Partial<FileLockRange>;
  return typeof r.offset === 'string' && typeof r.length === 'string' && typeof r.exclusive === 'boolean'
    && /^(0|[1-9][0-9]{0,19})$/.test(r.offset) && /^(0|[1-9][0-9]{0,19})$/.test(r.length)
    && BigInt(r.offset) + BigInt(r.length) <= MAX_U64;
}
function overlaps(a: FileLockRange, b: FileLockRange): boolean {
  return BigInt(a.length) > 0n && BigInt(b.length) > 0n
    && BigInt(a.offset) < BigInt(b.offset) + BigInt(b.length)
    && BigInt(b.offset) < BigInt(a.offset) + BigInt(a.length);
}
function same(a: FileLockRange, b: FileLockRange): boolean { return a.offset === b.offset && a.length === b.length; }

export class RangeLockManager {
  constructor(private readonly sql: SqlStorage, private readonly nextFence: () => number) {}
  reapExpired(now = Date.now()): void {
    this.sql.exec('DELETE FROM range_locks WHERE expires_at <= ?', now);
    this.sql.exec('DELETE FROM read_permits WHERE expires_at <= ?', now);
    this.sql.exec('DELETE FROM range_waiters WHERE expires_at <= ?', now);
  }
  private rows(path: string): RangeRow[] {
    this.reapExpired();
    return this.sql.exec<RangeRow>('SELECT * FROM range_locks WHERE path = ?', path).toArray();
  }
  private ranges(row: RangeRow): FileLockRange[] { return JSON.parse(row.ranges) as FileLockRange[]; }
  private own(path: string, owner: string, handle: string): RangeRow | undefined {
    return this.rows(path).find(r => r.owner === owner && r.handle === handle);
  }
  heldRanges(path: string, owner: string, handle: string): FileLockRange[] { const r=this.own(path,owner,handle); return r ? this.ranges(r) : []; }
  heldByOther(path: string, owner?: string): string | null { return this.rows(path).find(r => r.owner !== owner)?.owner ?? null; }
  acquire(path: string, owner: string, handle: string, requested: FileLockRange[], ttlMs: number, expectedFence?: number): LockResult {
    const rows = this.rows(path), own = rows.find(r => r.owner === owner && r.handle === handle);
    if (expectedFence !== undefined && own?.fence !== expectedFence) return {granted:false,path,reason:'fence-stale'};
    const held = own ? this.ranges(own) : [];
    if (requested.some(r=>r.exclusive)) {
      const reader=this.sql.exec('SELECT owner FROM read_permits WHERE path=? AND NOT(owner=? AND handle=?) LIMIT 1',path,owner,handle).toArray()[0];
      if (reader) {
        // A nonblocking exclusive waiter prevents fresh permits from continually
        // renewing ahead of it. Reads remain possible via direct checks until
        // the waiter retries after the <=1s incumbent permit expires.
        this.sql.exec('INSERT INTO range_waiters(path,expires_at) VALUES(?,?) ON CONFLICT(path) DO UPDATE SET expires_at=excluded.expires_at',path,Date.now()+READ_PERMIT_MS+500);
        return {granted:false,path,heldBy:String(reader.owner),reason:'held-by-other'};
      }
    }
    // The wire retry of the exact request is idempotent. Changing a held range's
    // mode requires unlock/relock; no implicit upgrade drops another holder.
    for (const request of requested) {
      if (requested.some(r=>same(r,request) && r.exclusive !== request.exclusive)) return {granted:false,path,reason:'range-already-held'};
      const duplicate = held.find(r => same(r,request));
      if (duplicate && duplicate.exclusive !== request.exclusive) return { granted:false,path,reason:'range-already-held' };
      for (const row of rows) {
        if (row === own) continue;
        if (this.ranges(row).some(r => overlaps(r,request) && (r.exclusive || request.exclusive)))
          return {granted:false,path,heldBy:row.owner,reason:'held-by-other',expiresAt:row.expires_at};
      }
    }
    const ranges = [...held];
    for (const r of requested) if (!ranges.some(h => same(h,r))) ranges.push(r);
    const total=rows.reduce((sum,row)=>sum+(row===own ? 0 : this.ranges(row).length),ranges.length);
    if (ranges.length > 256 || total > 4096 || rows.length >= 256 && !own) return {granted:false,path,reason:'lock-capacity'};
    const fence=own?.fence ?? this.nextFence(), expiresAt=Date.now()+ttlMs;
    this.sql.exec(`INSERT INTO range_locks(path,owner,handle,fence,expires_at,ranges) VALUES(?,?,?,?,?,?)
      ON CONFLICT(path,owner,handle) DO UPDATE SET expires_at=excluded.expires_at,ranges=excluded.ranges`,
      path,owner,handle,fence,expiresAt,JSON.stringify(ranges));
    return {granted:true,path,owner,fence,expiresAt};
  }
  renew(path: string, owner: string, handle: string, fence: number, ttlMs: number): LockResult {
    const row=this.own(path,owner,handle);
    if (!row || row.fence !== fence) return {granted:false,path,reason:'fence-stale'};
    const expiresAt=Date.now()+ttlMs;
    this.sql.exec('UPDATE range_locks SET expires_at=? WHERE path=? AND owner=? AND handle=? AND fence=?',expiresAt,path,owner,handle,fence);
    return {granted:true,path,owner,fence,expiresAt};
  }
  release(path: string, owner: string, handle: string, fence: number, requested?: FileLockRange[]): {released:boolean;reason?:string} {
    const row=this.own(path,owner,handle);
    if (!row) return requested ? {released:false,reason:'range-not-locked'} : {released:true};
    if (row.fence !== fence) return {released:false,reason:'fence-stale'};
    const held=this.ranges(row);
    if (requested?.some(r=>!held.some(h=>same(h,r)))) return {released:false,reason:'range-not-locked'};
    const kept=requested ? held.filter(h=>!requested.some(r=>same(r,h))) : [];
    if (!kept.length) this.sql.exec('DELETE FROM range_locks WHERE path=? AND owner=? AND handle=? AND fence=?',path,owner,handle,fence);
    else this.sql.exec('UPDATE range_locks SET ranges=? WHERE path=? AND owner=? AND handle=? AND fence=?',JSON.stringify(kept),path,owner,handle,fence);
    return {released:true};
  }
  access(path: string, owner: string, handle: string, range: FileLockRange, fence?: number): RangeAccess {
    const rows=this.rows(path);
    if (fence !== undefined && !rows.some(r=>r.owner===owner && r.handle===handle && r.fence===fence))
      return {allowed:false,reason:'fence-stale'};
    for (const row of rows) {
      const owns=row.owner===owner && row.handle===handle;
      // A handle may read/write through its own exclusive lock, but a shared
      // lock denies writes from every handle, including its owner (MS-SMB2
      // 2.2.26.1). This also covers shared ranges stacked over an own exclusive.
      if (this.ranges(row).some(r=>overlaps(r,range) && (r.exclusive ? !owns : range.exclusive)))
        return {allowed:false,heldBy:row.owner,reason:owns?'shared-lock':'held-by-other'};
    }
    if (!range.exclusive && !rows.some(row=>!(row.owner===owner && row.handle===handle) && this.ranges(row).some(r=>r.exclusive))
      && !this.sql.exec('SELECT path FROM range_waiters WHERE path=?',path).toArray().length) {
      // Positive read authority, not a cached observation of "no locks". An
      // exclusive range cannot be granted to another handle until it expires.
      const prior=this.sql.exec('SELECT fence FROM read_permits WHERE path=? AND owner=? AND handle=?',path,owner,handle).toArray()[0];
      const count=Number(this.sql.exec('SELECT COUNT(*) AS n FROM read_permits WHERE path=?',path).one().n);
      if (prior || count<256) {
        const permitFence=prior ? Number(prior.fence) : this.nextFence();
        this.sql.exec('INSERT INTO read_permits(path,owner,handle,fence,expires_at) VALUES(?,?,?,?,?) ON CONFLICT(path,owner,handle) DO UPDATE SET expires_at=excluded.expires_at',
          path,owner,handle,permitFence,Date.now()+READ_PERMIT_MS);
        return {allowed:true,permitTtlMs:READ_PERMIT_MS,permitFence};
      }
    }
    return {allowed:true};
  }
  releaseRead(path:string,owner:string,handle:string,fence:number): void {
    this.sql.exec('DELETE FROM read_permits WHERE path=? AND owner=? AND handle=? AND fence=?',path,owner,handle,fence);
  }
  earliestExpiry(): number | null {
    const r=this.sql.exec('SELECT MIN(expires_at) AS e FROM (SELECT expires_at FROM range_locks UNION ALL SELECT expires_at FROM read_permits UNION ALL SELECT expires_at FROM range_waiters)').one(); return r.e === null ? null : Number(r.e);
  }
}
