// SPDX-License-Identifier: AGPL-3.0-or-later
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import type { Block } from './types';
import { InvalidManifestError } from './block-manifest';
export const STREAM_BLOCK_SIZE = 1024 * 1024;
export const STREAM_RANGE_MAX = 16 * STREAM_BLOCK_SIZE;
export type StreamBlock = { index: number; hash: string; length: number; objectKey: string };
export type StreamManifest = { format: 1; exists: boolean; legacy: boolean; size: number; version: number; blockSize: number; blocks: StreamBlock[] };
export type StreamDelta = { format: 1; size: number; blockSize: number; expectedVersion: number; fence: number; blocks: StreamBlock[] };
export function validateStreamDelta(value: unknown): asserts value is StreamDelta {
  const d = value as StreamDelta;
  if (!d || d.format !== 1 || d.blockSize !== STREAM_BLOCK_SIZE || !Number.isSafeInteger(d.size) || d.size < 0
    || !Number.isSafeInteger(d.expectedVersion) || d.expectedVersion < 0 || !Number.isSafeInteger(d.fence) || d.fence < 1
    || !Array.isArray(d.blocks) || d.blocks.length > 128) throw new InvalidManifestError('invalid stream manifest header');
  const indices = new Set<number>(), identities = new Map<string,string>();
  for (const b of d.blocks) {
    if (!b || !Number.isSafeInteger(b.index) || b.index < 0 || !Number.isSafeInteger(b.index * STREAM_BLOCK_SIZE)
      || b.index * STREAM_BLOCK_SIZE >= d.size || indices.has(b.index) || !Number.isSafeInteger(b.length) || b.length < 1
      || b.length > Math.min(STREAM_BLOCK_SIZE, d.size - b.index * STREAM_BLOCK_SIZE)
      || typeof b.hash !== 'string' || !/^[a-f0-9]{64}$/.test(b.hash)
      || typeof b.objectKey !== 'string' || b.objectKey.length > 1024 || !b.objectKey.endsWith('/' + b.hash)
      || /[\x00-\x1f\x7f]/.test(b.objectKey)) throw new InvalidManifestError('invalid stream block');
    const identity = `${b.hash}:${b.length}`;
    if (identities.has(b.objectKey) && identities.get(b.objectKey) !== identity) throw new InvalidManifestError('conflicting stream block identity');
    identities.set(b.objectKey,identity); indices.add(b.index);
  }
}
/** Existing verification/provenance APIs consume contiguous manifests. This is
 * only a bounded verification projection; stored stream indices stay sparse. */
export function streamVerificationBlocks(blocks: StreamBlock[]): Block[] {
  let offset = 0;
  return blocks.map((b,index) => { const block = {chunkIdx:0,blockIdx:index,blockHash:b.hash,objectKey:b.objectKey,offset,length:b.length}; offset += b.length; return block; });
}
export function validateStreamRange(offset: number, length: number): void {
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 0 || length > STREAM_RANGE_MAX
    || !Number.isSafeInteger(offset + length)) throw new InvalidManifestError('invalid stream range');
}
export function readStreamManifest(sql: SqlStorage, item: string, name: string, offset=0, length=STREAM_RANGE_MAX, snapshot?: string): StreamManifest {
  validateStreamRange(offset,length);
  const where = snapshot === undefined ? 'item_id=?1 AND name=?2' : 'item_id=?1 AND name=?2 AND snapshot_id=?3';
  const args: SqlStorageValue[] = snapshot === undefined ? [item,name] : [item,name,snapshot];
  const row = sql.exec(`SELECT size,version,storage_kind FROM ${snapshot === undefined ? 'item_streams' : 'snapshot_streams'} WHERE ${where};`,...args).toArray()[0];
  const result: StreamManifest = {format:1,exists:!!row && row.storage_kind !== 'deleted',legacy:row?.storage_kind === 'inline',size:Number(row?.size ?? 0),version:Number(row?.version ?? 0),blockSize:STREAM_BLOCK_SIZE,blocks:[]};
  if (row?.storage_kind !== 'blocks' || !length) return result;
  const lower = Math.floor(offset / STREAM_BLOCK_SIZE), upper = Math.ceil((offset + length) / STREAM_BLOCK_SIZE);
  const rangeIndex = args.length + 1;
  result.blocks = sql.exec(`SELECT block_idx,block_hash,object_key,length FROM ${snapshot === undefined ? 'stream_blocks' : 'snapshot_stream_blocks'} WHERE ${where}
    AND block_idx>=?${rangeIndex} AND block_idx<?${rangeIndex+1} ORDER BY block_idx;`,...args,lower,upper).toArray()
    .map(r=>({index:Number(r.block_idx),hash:String(r.block_hash),objectKey:String(r.object_key),length:Number(r.length)}));
  return result;
}
/** Release a subset, retaining ownership for durable local recovery. Caller owns
 * transaction and deletes rows only after this set-based reference adjustment. */
export function releaseStreamBlocks(sql: SqlStorage, item: string, name?: string, indices?: number[]): void {
  const args: SqlStorageValue[] = [item];
  let where = 'item_id=?1';
  if (name !== undefined) { args.push(name); where += ` AND name=?${args.length}`; }
  if (indices !== undefined) { args.push(JSON.stringify(indices)); where += ` AND block_idx IN (SELECT value FROM json_each(?${args.length}))`; }
  sql.exec(`INSERT OR IGNORE INTO retained_blocks(item_id,object_key,block_hash,retained_at)
    SELECT item_id,object_key,block_hash,${Date.now()} FROM stream_blocks WHERE ${where};`,...args);
  decrementStreamReferences(sql,`SELECT block_hash FROM stream_blocks WHERE ${where}`,args);
  sql.exec(`DELETE FROM stream_blocks WHERE ${where};`,...args);
}
export function commitStreamDelta(sql: SqlStorage, item: string, name: string, d: StreamDelta, seq: number, allowRetained = false): StreamManifest {
  validateStreamDelta(d);
  const accessible = sql.exec(`SELECT 1 FROM items i WHERE i.id=? AND i.is_dir=0 AND
    (i.deleted=0 OR (i.deleted=1 AND ?=1 AND EXISTS(
      SELECT 1 FROM open_handles h WHERE h.inode_id=i.id AND h.expires_at>?
    )));`,item,allowRetained?1:0,Date.now()).toArray()[0];
  if (!accessible) throw new InvalidManifestError('no such file');
  const current = readStreamManifest(sql,item,name,0,0);
  const digest=bytesToHex(sha256(new TextEncoder().encode(JSON.stringify([d.format,d.blockSize,d.size,d.expectedVersion,
    [...d.blocks].sort((a,b)=>a.index-b.index).map(b=>[b.index,b.hash,b.length,b.objectKey])]))));
  if (current.version !== d.expectedVersion) {
    const prior=sql.exec(`SELECT last_delta_digest FROM item_streams WHERE item_id=? AND name=?;`,item,name).toArray()[0];
    if (current.exists && !current.legacy && current.version===d.expectedVersion+1 && prior?.last_delta_digest===digest) return current;
    throw new StreamConflictError(current.version);
  }
  if (current.legacy) for (let index=0;index<Math.ceil(Math.min(current.size,d.size)/STREAM_BLOCK_SIZE);index++) {
    if (!d.blocks.some(b=>b.index===index)) throw new InvalidManifestError('inline migration requires all existing chunks');
  }
  // A shrink must replace the remaining partial chunk so later growth cannot
  // expose bytes that were truncated away.
  if (d.size < current.size && d.size % STREAM_BLOCK_SIZE) {
    const index = Math.floor(d.size / STREAM_BLOCK_SIZE);
    const prior = sql.exec(`SELECT length FROM stream_blocks WHERE item_id=? AND name=? AND block_idx=?;`,item,name,index).toArray()[0];
    if (prior && Number(prior.length) > d.size % STREAM_BLOCK_SIZE && !d.blocks.some(b=>b.index===index)) throw new InvalidManifestError('shrink requires a replacement boundary block');
  }
  // Large truncations stay set based rather than binding or reading every row.
  releaseStreamBlocksWhere(sql,item,name,Math.ceil(d.size/STREAM_BLOCK_SIZE),d.blocks.map(b=>b.index));
  for (const b of d.blocks) {
    const known = sql.exec(`SELECT block_hash FROM known_objects WHERE object_key=?;`,b.objectKey).toArray()[0];
    const ref = sql.exec(`SELECT object_key FROM block_refs WHERE block_hash=?;`,b.hash).toArray()[0];
    if ((known && known.block_hash !== b.hash) || (ref && ref.object_key !== b.objectKey)) throw new InvalidManifestError('immutable object identity cannot change');
    sql.exec(`INSERT OR IGNORE INTO known_objects(object_key,block_hash) VALUES(?,?);`,b.objectKey,b.hash);
    sql.exec(`DELETE FROM block_upload_claims WHERE object_key=?;`,b.objectKey);
    sql.exec(`INSERT INTO stream_blocks(item_id,name,block_idx,block_hash,object_key,length) VALUES(?,?,?,?,?,?);`,item,name,b.index,b.hash,b.objectKey,b.length);
    sql.exec(`INSERT INTO block_refs(block_hash,object_key,refcount) VALUES(?,?,1) ON CONFLICT(block_hash) DO UPDATE SET refcount=refcount+1;`,b.hash,b.objectKey);
  }
  sql.exec(`INSERT INTO item_streams(item_id,name,size,data,updated_seq,storage_kind,version,last_delta_digest) VALUES(?,?,?,X'',?,'blocks',?,?)
    ON CONFLICT(item_id,name) DO UPDATE SET size=excluded.size,data=X'',updated_seq=excluded.updated_seq,storage_kind='blocks',version=excluded.version,last_delta_digest=excluded.last_delta_digest;`,item,name,d.size,seq,current.version+1,digest);
  sql.exec(`UPDATE items SET updated_seq=? WHERE id=? AND deleted=0;`,seq,item);
  return readStreamManifest(sql,item,name,0,0);
}
function releaseStreamBlocksWhere(sql: SqlStorage,item:string,name:string,cutoff:number,indices:number[]):void {
  // Split OR into two index seeks: otherwise SQLite scans every prior chunk on
  // each append/overwrite. rowid lookup makes the outer mutation bounded too.
  const selected='SELECT rowid FROM stream_blocks WHERE item_id=?1 AND name=?2 AND block_idx>=?3 UNION SELECT rowid FROM stream_blocks WHERE item_id=?1 AND name=?2 AND block_idx IN(SELECT value FROM json_each(?4))';
  const where=`rowid IN (${selected})`;
  const args=[item,name,cutoff,JSON.stringify(indices)];
  sql.exec(`INSERT OR IGNORE INTO retained_blocks(item_id,object_key,block_hash,retained_at) SELECT item_id,object_key,block_hash,${Date.now()} FROM stream_blocks WHERE ${where};`,...args);
  decrementStreamReferences(sql,`SELECT block_hash FROM stream_blocks WHERE ${where}`,args);
  sql.exec(`DELETE FROM stream_blocks WHERE ${where};`,...args);
}
export class StreamConflictError extends Error { constructor(public readonly actual:number){super('stream version conflict');} }

/** Group removed references once. Correlating COUNT over the whole removed set
 * for each distinct hash turns large truncations/deletes into quadratic work. */
export function decrementStreamReferences(sql:SqlStorage,selection:string,args:SqlStorageValue[]):void {
  sql.exec(`WITH removed AS MATERIALIZED(SELECT block_hash,COUNT(*) AS n FROM (${selection}) GROUP BY block_hash)
    UPDATE block_refs SET refcount=refcount-(SELECT n FROM removed WHERE removed.block_hash=block_refs.block_hash)
    WHERE block_hash IN(SELECT block_hash FROM removed);`,...args);
}
