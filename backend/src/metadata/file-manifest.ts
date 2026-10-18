// SPDX-License-Identifier: AGPL-3.0-or-later
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { InvalidManifestError, MAX_MANIFEST_BLOCKS, validateBlockManifest } from './block-manifest';
import { decrementStreamReferences } from './stream-manifest';
import type { Block } from './types';

export const FILE_DELTA_MAX = 1024;
export type FileDelta = { format: 1; size: number; blockSize: number; expectedVersion: number; fence: number; blocks: Block[] };
export class ManifestLayoutError extends Error { constructor() { super('manifest layout requires a full replacement'); } }
export class FileDeltaConflict extends Error { constructor(public readonly actual: number) { super('file version conflict'); } }
export function validBlockSize(size: number): boolean { return Number.isSafeInteger(size) && size > 0 && size <= 16 * 1024 * 1024; }
/** Full publications establish the fixed layout once; delta commits never scan
 * the unchanged map. Legacy variable extents retain the full-image API. */
export function fixedBlockSize(blocks: Block[], requested?: number): number | null {
  const size = requested ?? (blocks.length > 1 ? blocks[0].length : 1024 * 1024);
  if (!validBlockSize(size)) throw new InvalidManifestError('invalid block size');
  if (!blocks.every((b,i) => b.chunkIdx === i && b.blockIdx === 0 && b.offset === i * size
    && b.length <= size && (i === blocks.length - 1 || b.length === size))) {
    if (requested !== undefined) throw new InvalidManifestError('blocks do not match declared layout');
    return null;
  }
  return size;
}
/** Contiguous projection for existing ownership and verification gates. Original
 * coordinates are validated separately and are the only coordinates stored. */
export function fileVerificationBlocks(blocks: Block[]): Block[] {
  let offset = 0;
  return blocks.map((b,i) => { const result = {...b,chunkIdx:i,blockIdx:0,offset}; offset += b.length; return result; });
}
export function validateFileDelta(value: unknown): asserts value is FileDelta {
  const d = value as FileDelta;
  if (!d || d.format !== 1 || !validBlockSize(d.blockSize) || !Number.isSafeInteger(d.size) || d.size < 0
    || Math.ceil(d.size / d.blockSize) > MAX_MANIFEST_BLOCKS || !Number.isSafeInteger(d.expectedVersion) || d.expectedVersion < 1
    || !Number.isSafeInteger(d.fence) || d.fence < 1 || !Array.isArray(d.blocks) || d.blocks.length > FILE_DELTA_MAX) {
    throw new InvalidManifestError('invalid file delta header');
  }
  let previous = -1;
  for (const b of d.blocks) {
    if (!b || !Number.isSafeInteger(b.chunkIdx) || b.chunkIdx <= previous || b.blockIdx !== 0
      || b.offset !== b.chunkIdx * d.blockSize || b.offset >= d.size || b.length !== Math.min(d.blockSize,d.size-b.offset)) {
      throw new InvalidManifestError('delta blocks must be ordered fixed extents');
    }
    previous = b.chunkIdx;
  }
  validateBlockManifest(fileVerificationBlocks(d.blocks));
}
export function fileDeltaDigest(d: FileDelta): string {
  // Fence deliberately excluded: an exact retry may acquire a new lease, but
  // still passes the current lease/ACL/receipt gate before consulting this ID.
  return bytesToHex(sha256(new TextEncoder().encode(JSON.stringify([1,d.blockSize,d.size,d.expectedVersion,
    d.blocks.map(b => [b.chunkIdx,b.blockHash,b.objectKey,b.length])]))));
}
/** Caller supplies a synchronous transaction and checks ACL, lease and receipts.
 * Returns false for an exact lost-response retry without changing any rows. */
export function applyFileDelta(sql: SqlStorage, item: string, d: FileDelta, nextSeq: () => number, admit: (bytes: number) => void = () => {}, allowRetained = false): boolean {
  validateFileDelta(d);
  const current = sql.exec(`SELECT size,version,manifest_block_size,last_manifest_delta_digest FROM items
    WHERE id=? AND is_dir=0 AND (deleted=0 OR (deleted=1 AND ?=1 AND EXISTS(
      SELECT 1 FROM open_handles h WHERE h.inode_id=items.id AND h.expires_at>?
    )));`,item,allowRetained?1:0,Date.now()).toArray()[0];
  if (!current) throw new InvalidManifestError('no such file');
  const digest = fileDeltaDigest(d), version = Number(current.version), size = Number(current.size);
  if (version !== d.expectedVersion) {
    if (version === d.expectedVersion + 1 && current.last_manifest_delta_digest === digest) return false;
    throw new FileDeltaConflict(version);
  }
  admit(65_536 + d.blocks.length * 4096);
  if (size > 0 && current.manifest_block_size !== d.blockSize) throw new ManifestLayoutError();
  const changed = new Set(d.blocks.map(b=>b.chunkIdx));
  // Main files are dense. Appends must supply every new extent, including a
  // formerly short boundary block. Shrinks must replace the surviving boundary.
  const firstNew = Math.floor(size / d.blockSize), count = Math.ceil(d.size / d.blockSize);
  if (d.size > size) {
    if (count-firstNew > changed.size) throw new InvalidManifestError('growth requires all new blocks');
    for (let i=firstNew;i<count;i++) if (!changed.has(i)) throw new InvalidManifestError('growth requires all new blocks');
  } else if (d.size < size && d.size % d.blockSize && !changed.has(count-1)) {
    throw new InvalidManifestError('shrink requires a replacement boundary block');
  }
  for (const b of d.blocks) {
    const known=sql.exec('SELECT block_hash FROM known_objects WHERE object_key=?;',b.objectKey).toArray()[0];
    const ref=sql.exec('SELECT object_key FROM block_refs WHERE block_hash=?;',b.blockHash).toArray()[0];
    if ((known && known.block_hash !== b.blockHash) || (ref && ref.object_key !== b.objectKey)) throw new InvalidManifestError('immutable object identity cannot change');
  }
  const selected = 'SELECT rowid FROM blocks WHERE item_id=?1 AND chunk_idx>=?2 UNION SELECT rowid FROM blocks WHERE item_id=?1 AND chunk_idx IN(SELECT value FROM json_each(?3))';
  const where = `rowid IN (${selected})`, args = [item,count,JSON.stringify([...changed])];
  sql.exec(`INSERT OR IGNORE INTO retained_blocks(item_id,object_key,block_hash,retained_at)
    SELECT item_id,object_key,block_hash,${Date.now()} FROM blocks WHERE ${where};`,...args);
  decrementStreamReferences(sql,`SELECT block_hash FROM blocks WHERE ${where}`,args);
  sql.exec(`DELETE FROM blocks WHERE ${where};`,...args);
  for (let i=0;i<d.blocks.length;i+=256) {
    const json=JSON.stringify(d.blocks.slice(i,i+256));
    sql.exec(`INSERT OR IGNORE INTO known_objects(object_key,block_hash) SELECT json_extract(value,'$.objectKey'),json_extract(value,'$.blockHash') FROM json_each(?);`,json);
    sql.exec(`DELETE FROM block_upload_claims WHERE object_key IN(SELECT json_extract(value,'$.objectKey') FROM json_each(?));`,json);
    sql.exec(`INSERT INTO blocks(item_id,chunk_idx,block_idx,block_hash,object_key,offset,length)
      SELECT ?1,json_extract(value,'$.chunkIdx'),0,json_extract(value,'$.blockHash'),json_extract(value,'$.objectKey'),json_extract(value,'$.offset'),json_extract(value,'$.length') FROM json_each(?2);`,item,json);
    sql.exec(`INSERT INTO block_refs(block_hash,object_key,refcount) SELECT json_extract(value,'$.blockHash'),json_extract(value,'$.objectKey'),COUNT(*) FROM json_each(?) GROUP BY json_extract(value,'$.blockHash')
      ON CONFLICT(block_hash) DO UPDATE SET refcount=refcount+excluded.refcount;`,json);
  }
  const seq=nextSeq();
  sql.exec(`UPDATE items SET size=?,content_version=?,version=version+1,
    updated_seq=CASE WHEN deleted=1 THEN updated_seq ELSE ? END,modified_at=?,manifest_block_size=?,last_manifest_delta_digest=? WHERE id=?;`,
    d.size,`cv-${d.size}-${seq}`,seq,Date.now(),d.blockSize,digest,item);
  return true;
}
