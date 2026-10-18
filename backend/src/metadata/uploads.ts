// SPDX-License-Identifier: AGPL-3.0-or-later
/// Resumable multipart metadata. These rows describe reported object-store parts;
/// they do not by themselves prove the bucket has accepted the bytes.
import type { UploadSession } from './types';

export class UploadInvalidError extends Error {
  constructor(reason: string) { super(`upload_invalid: ${reason}`); this.name = 'UploadInvalidError'; }
}
export class UploadConflictError extends Error {
  constructor(reason: string) { super(`upload_conflict: ${reason}`); this.name = 'UploadConflictError'; }
}
const MAX_PARTS = 10_000;
function validText(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
}
export class UploadCoordinator {
  constructor(private readonly sql: SqlStorage) {}

  begin(opts: { uploadId: string; itemId: string; key: string; totalSize: number; partSize: number }): UploadSession {
    if (!validText(opts.uploadId, 1024) || !validText(opts.itemId, 1024) || !validText(opts.key, 1024)
      || !Number.isSafeInteger(opts.totalSize) || opts.totalSize <= 0
      || !Number.isSafeInteger(opts.partSize) || opts.partSize <= 0
      || Math.ceil(opts.totalSize / opts.partSize) > MAX_PARTS) throw new UploadInvalidError('invalid upload identity or part geometry');
    const existing = this.status(opts.uploadId);
    if (existing) {
      if (existing.itemId !== opts.itemId || existing.key !== opts.key || existing.totalSize !== opts.totalSize || existing.partSize !== opts.partSize) {
        throw new UploadConflictError('upload id already belongs to another immutable session');
      }
      if (existing.state === 'aborted') throw new UploadConflictError('aborted upload requires a new id');
      return existing; // lost response/resume preserves state and acknowledged parts
    }
    // Orphan part records from old deployments can never seed a new session.
    this.sql.exec(`DELETE FROM upload_parts WHERE upload_id=?;`, opts.uploadId);
    const now = Date.now();
    this.sql.exec(`INSERT INTO uploads (upload_id,item_id,key,total_size,part_size,state,created_at,updated_at)
      VALUES (?,?,?,?,?,'in_progress',?,?);`, opts.uploadId, opts.itemId, opts.key, opts.totalSize, opts.partSize, now, now);
    return { ...opts, state: 'in_progress', uploadedParts: [] };
  }

  recordPart(uploadId: string, partNumber: number, etag: string, size: number, checksum?: string): void {
    const upload = this.status(uploadId);
    if (!upload) throw new UploadInvalidError('no such upload');
    if (upload.state !== 'in_progress') throw new UploadConflictError(`upload is ${upload.state}`);
    const count = Math.ceil(upload.totalSize / upload.partSize);
    if (!Number.isSafeInteger(partNumber) || partNumber < 1 || partNumber > count
      || !Number.isSafeInteger(size) || size !== Math.min(upload.partSize, upload.totalSize - (partNumber - 1) * upload.partSize)
      || !validText(etag, 1024) || (checksum !== undefined && !validText(checksum, 256))) {
      throw new UploadInvalidError('invalid part number, byte length, or checksum identity');
    }
    this.sql.exec(`INSERT INTO upload_parts (upload_id,part_number,etag,size,checksum) VALUES (?,?,?,?,?)
      ON CONFLICT(upload_id,part_number) DO UPDATE SET etag=excluded.etag,size=excluded.size,checksum=excluded.checksum;`,
      uploadId, partNumber, etag, size, checksum ?? null);
    this.sql.exec(`UPDATE uploads SET updated_at=? WHERE upload_id=?;`, Date.now(), uploadId);
  }

  status(uploadId: string): UploadSession | null {
    const row = this.sql.exec(`SELECT * FROM uploads WHERE upload_id=?;`, uploadId).toArray()[0];
    if (!row) return null;
    const parts = this.sql.exec(`SELECT part_number,etag,size FROM upload_parts WHERE upload_id=? ORDER BY part_number;`, uploadId).toArray();
    return { uploadId, itemId: String(row.item_id), key: String(row.key), totalSize: Number(row.total_size), partSize: Number(row.part_size),
      state: String(row.state) as UploadSession['state'],
      uploadedParts: parts.map(p => ({ partNumber: Number(p.part_number), etag: String(p.etag), size: Number(p.size) })) };
  }

  missingParts(uploadId: string): number[] {
    const upload = this.status(uploadId);
    if (!upload) throw new UploadInvalidError('no such upload');
    const total = Math.ceil(upload.totalSize / upload.partSize);
    if (!Number.isSafeInteger(total) || total < 1 || total > MAX_PARTS) throw new UploadInvalidError('invalid persisted part geometry');
    const have = new Map(upload.uploadedParts.map(p => [p.partNumber, p]));
    const missing: number[] = [];
    for (let n = 1; n <= total; n++) {
      const part = have.get(n), expected = Math.min(upload.partSize, upload.totalSize - (n - 1) * upload.partSize);
      if (!part || part.size !== expected || !validText(part.etag, 1024)) missing.push(n);
    }
    return missing;
  }

  complete(uploadId: string, etag: string): { completed: boolean; missing?: number[] } {
    if (!validText(etag, 1024)) throw new UploadInvalidError('invalid completion etag');
    const upload = this.status(uploadId);
    if (!upload) throw new UploadInvalidError('no such upload');
    if (upload.state === 'aborted') throw new UploadConflictError('upload is aborted');
    if (upload.state === 'completed') return { completed: true };
    const missing = this.missingParts(uploadId);
    if (missing.length) return { completed: false, missing };
    this.sql.exec(`UPDATE uploads SET state='completed',updated_at=? WHERE upload_id=?;`, Date.now(), uploadId);
    return { completed: true };
  }

  abort(uploadId: string): void {
    const upload = this.status(uploadId);
    if (upload?.state === 'completed') throw new UploadConflictError('completed upload cannot be aborted');
    this.sql.exec(`UPDATE uploads SET state='aborted',updated_at=? WHERE upload_id=?;`, Date.now(), uploadId);
    this.sql.exec(`DELETE FROM upload_parts WHERE upload_id=?;`, uploadId);
  }
}
