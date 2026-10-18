// SPDX-License-Identifier: AGPL-3.0-or-later
import { AwsClient } from 'aws4fetch';
import { sha256 } from '@noble/hashes/sha256';
import { objectUrl, type StorageConfig } from './storage';
import type { Env } from './env';

export interface ObjectVerificationInput { objectKey: string; blockHash: string; length: number }
export interface VerifiedObject extends ObjectVerificationInput { ciphertextSize: number }
export class ObjectVerificationError extends Error {
  constructor(public readonly reason: string) { super(reason); this.name = 'ObjectVerificationError'; }
}
export function storageIdentity(config: StorageConfig): string {
  return JSON.stringify([config.endpoint.replace(/\/+$/, ''), config.bucket, config.region, config.forcePathStyle ?? true, "cfb-envelope-v1"]);
}
export function validateObjectVerificationInput(block: ObjectVerificationInput): void {
  if (!/^[0-9a-f]{64}$/.test(block.blockHash) || block.objectKey.slice(block.objectKey.lastIndexOf('/') + 1) !== block.blockHash
    || !Number.isSafeInteger(block.length) || block.length <= 0) throw new ObjectVerificationError('invalid content-addressed object identity');
}
const digestHex = (bytes: Uint8Array) => [...bytes].map(b => b.toString(16).padStart(2,'0')).join('');

/** The binding is a separate authority from S3 credentials. Use it only for an
 * explicitly mapped deployment-default R2 bucket, never a referenced/managed
 * credential or another filespace backend, even if its bucket name is equal. */
export function nativeVerificationBucket(env: Env, config: StorageConfig): R2Bucket | undefined {
  if (!env.DATA_BUCKET || !env.DATA_BUCKET_ENDPOINT || !env.DATA_BUCKET_NAME
    || config.credentialSource !== 'deployment-default') return undefined;
  const endpoint = env.DATA_BUCKET_ENDPOINT.replace(/\/+$/, '');
  try {
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' || url.origin !== endpoint
      || !/^[a-f0-9]{32}(?:\.(?:eu|fedramp))?\.r2\.cloudflarestorage\.com$/.test(url.hostname)) return undefined;
  } catch { return undefined; }
  if (endpoint !== env.S3_ENDPOINT.replace(/\/+$/, '') || env.DATA_BUCKET_NAME !== env.S3_BUCKET
    || config.endpoint.replace(/\/+$/, '') !== endpoint || config.bucket !== env.DATA_BUCKET_NAME
    || config.region !== (env.S3_REGION || 'auto') || !(config.forcePathStyle ?? true)
    || config.accessKeyId !== env.S3_ACCESS_KEY_ID || config.secretAccessKey !== env.S3_SECRET_ACCESS_KEY
    || (config.sessionToken ?? '') !== (env.S3_SESSION_TOKEN ?? '')) return undefined;
  return env.DATA_BUCKET;
}

function validateCiphertextSize(size: number, block: ObjectVerificationInput): void {
  if (!Number.isSafeInteger(size) || size <= 69 || size > block.length + 69) {
    throw new ObjectVerificationError('invalid ciphertext byte length');
  }
}
export function validateVerifiedObject(block: VerifiedObject): void {
  validateObjectVerificationInput(block);
  validateCiphertextSize(block.ciphertextSize, block);
}
/** Public framing only. Clients still verify the AEAD tag and plaintext digest.
 * Never treat a hash-valid plaintext object as an encrypted file block. */
function validateEnvelope(header: Uint8Array, size: number, block: ObjectVerificationInput): void {
  if (header.length !== 9 || header[0] !== 67 || header[1] !== 70 || header[2] !== 66
    || (header[3] !== 50 && header[3] !== 51) || (header[4] & ~1) !== 0) {
    throw new ObjectVerificationError('invalid encrypted block envelope');
  }
  const plaintextLength = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(5);
  if (plaintextLength !== block.length || (header[4] === 0 && size !== block.length + 69)) {
    throw new ObjectVerificationError('encrypted block length differs from manifest');
  }
}
async function verifyEnvelopePrefix(body: ReadableStream<Uint8Array>, size: number, block: ObjectVerificationInput): Promise<void> {
  const reader = body.getReader(), header = new Uint8Array(9); let copied = 0;
  try {
    while (copied < header.length) {
      const {value,done} = await reader.read(); if (done) break;
      const count = Math.min(value.byteLength, header.length - copied);
      header.set(value.subarray(0,count),copied); copied += count;
    }
    validateEnvelope(header.subarray(0,copied), size, block);
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
async function verifyCiphertextBody(body: ReadableStream<Uint8Array>, size: number, block: ObjectVerificationInput): Promise<void> {
  const reader = body.getReader(), digest = sha256.create(), header = new Uint8Array(9); let total = 0;
  try {
    while (true) {
      const {value,done} = await reader.read(); if (done) break;
      if (total < header.length) header.set(value.subarray(0,header.length-total),total);
      total += value.byteLength;
      if (total > size) throw new ObjectVerificationError('object size changed during verification');
      digest.update(value);
    }
    if (total !== size || digestHex(digest.digest()) !== block.blockHash) throw new ObjectVerificationError('object checksum mismatch');
    validateEnvelope(header.subarray(0,Math.min(total,header.length)), size, block);
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

/** Verify fresh objects only. Six verifications maximum, refilled as each finishes.
 * HEAD supplies server-validated SHA-256 for new uploads; a bounded nine-byte
 * range GET checks the encrypted envelope against the manifest. Legacy objects without
 * that stored checksum are hashed incrementally through a bounded GET before
 * their first receipt; an ETag is never treated as SHA-256. */
export async function verifyStorageObjects(config: StorageConfig, blocks: ObjectVerificationInput[], fetchImpl: typeof fetch = fetch,
  bucket?: Pick<R2Bucket, 'head' | 'get'>): Promise<VerifiedObject[]> {
  if (blocks.length > 128) throw new ObjectVerificationError('verification batch exceeds 128 objects');
  blocks.forEach(validateObjectVerificationInput);
  const aws = new AwsClient({...config, service:'s3'}), results = new Array<VerifiedObject>(blocks.length);
  async function verify(block: ObjectVerificationInput): Promise<VerifiedObject> {
    if (bucket) {
      const object = await bucket.head(block.objectKey);
      if (!object) throw new ObjectVerificationError('object missing');
      if (object.key !== block.objectKey) throw new ObjectVerificationError('object identity mismatch');
      const size = object.size;
      validateCiphertextSize(size, block);
      const checksum = object.checksums.sha256;
      if (checksum !== undefined) {
        if (digestHex(new Uint8Array(checksum)) !== block.blockHash) throw new ObjectVerificationError('object checksum mismatch');
        const prefix = await bucket.get(block.objectKey, {range:{offset:0,length:9}, onlyIf:{etagMatches:object.etag}});
        if (!prefix || !('body' in prefix)) throw new ObjectVerificationError('encrypted block header GET failed');
        if (prefix.key !== block.objectKey || prefix.size !== size || prefix.etag !== object.etag) {
          await prefix.body.cancel().catch(() => {});
          throw new ObjectVerificationError('object changed during header verification');
        }
        await verifyEnvelopePrefix(prefix.body, size, block);
      } else {
        // An ETag or uploader-supplied custom metadata is not a SHA-256 receipt.
        // Legacy objects must still be read and hashed, using the same byte cap.
        const bytes = await bucket.get(block.objectKey);
        if (!bytes || !('body' in bytes)) throw new ObjectVerificationError('object verification GET failed');
        if (bytes.key !== block.objectKey || bytes.size !== size) {
          await bytes.body.cancel().catch(() => {});
          throw new ObjectVerificationError('object size or identity changed during verification');
        }
        await verifyCiphertextBody(bytes.body, size, block);
      }
      return {...block,ciphertextSize:size};
    }
    const url = objectUrl(config, block.objectKey);
    const signed = await aws.sign(url, {method:'HEAD', headers:{'x-amz-checksum-mode':'ENABLED'}});
    const response = await fetchImpl(signed.url, {method:'HEAD', headers:signed.headers, redirect:'manual', signal:AbortSignal.timeout(30_000)});
    if (!response.ok) throw new ObjectVerificationError(response.status === 404 ? 'object missing' : 'object storage HEAD failed');
    const rawLength = response.headers.get('content-length'), size = Number(rawLength);
    // CFB2/3 envelopes add 69 bytes; compression may make the object smaller.
    // This cap bounds a legacy fallback read even if an S3 endpoint lies about size.
    if (!rawLength || !/^\d+$/.test(rawLength)) {
      throw new ObjectVerificationError('invalid ciphertext byte length');
    }
    validateCiphertextSize(size, block);
    const checksum = response.headers.get('x-amz-checksum-sha256');
    if (checksum) {
      let observed = '';
      try { observed = digestHex(Uint8Array.from(atob(checksum), c => c.charCodeAt(0))); } catch { /* fail closed */ }
      if (observed !== block.blockHash) throw new ObjectVerificationError('object checksum mismatch');
      const requestHeaders: Record<string,string> = {Range:'bytes=0-8'};
      const etag = response.headers.get('etag'); if (etag) requestHeaders['If-Match'] = etag;
      const get = await aws.sign(url, {method:'GET',headers:requestHeaders});
      const prefix = await fetchImpl(get.url, {method:'GET',headers:get.headers,redirect:'manual',signal:AbortSignal.timeout(30_000)});
      if (!prefix.ok || !prefix.body || (prefix.status === 206 && prefix.headers.get('content-range') !== `bytes 0-8/${size}`)) {
        await prefix.body?.cancel().catch(() => {});
        throw new ObjectVerificationError('encrypted block header GET failed');
      }
      await verifyEnvelopePrefix(prefix.body, size, block);
    } else {
      const get = await aws.sign(url, {method:'GET'});
      const bytes = await fetchImpl(get.url, {method:'GET', headers:get.headers, redirect:'manual', signal:AbortSignal.timeout(30_000)});
      if (!bytes.ok || !bytes.body) {
        await bytes.body?.cancel().catch(() => {});
        throw new ObjectVerificationError('object verification GET failed');
      }
      await verifyCiphertextBody(bytes.body, size, block);
    }
    return {...block,ciphertextSize:size};
  }
  // A slow object must not strand five available verification slots. Each worker
  // retains its slot through a legacy GET and streaming digest, so neither HEADs
  // nor fallback bodies can push concurrency past six. Preserve input ordering
  // even when requests finish out of order.
  let cursor = 0, failed = false, firstError: unknown;
  async function worker(): Promise<void> {
    while (!failed && cursor < blocks.length) {
      const index = cursor++;
      try { results[index] = await verify(blocks[index]); }
      catch (error) {
        if (!failed) { failed = true; firstError = error; }
      }
    }
  }
  // Stop admitting new objects on failure, but await every started request before
  // returning. The caller publishes receipts only after this entire batch passes.
  await Promise.all(Array.from({length:Math.min(6,blocks.length)}, () => worker()));
  if (failed) throw firstError;
  return results;
}

/** Operator-initiated readiness probe of the actual upload safety contract.
 * Writes two tiny random probe keys, tests checksum rejection and conditional
 * immutability, verifies the accepted bytes, then deletes only those exact keys. */
export async function probeStorageIntegrity(config: StorageConfig, prefix: string, fetchImpl: typeof fetch = fetch,
  sleep: (milliseconds: number) => Promise<void> = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)),
): Promise<{ok:true} | {ok:false;reason:string}> {
  if (!prefix || prefix.startsWith('/') || prefix.includes('..')) return {ok:false,reason:'invalid probe prefix'};
  const {presignWith,requiredUploadHeaders} = await import('./storage');
  const payload = crypto.getRandomValues(new Uint8Array(165));
  payload.set([67,70,66,51,0]); new DataView(payload.buffer).setUint32(5,96);
  const hash = digestHex(sha256(payload));
  const run = `${prefix.replace(/\/+$/,'')}/${crypto.randomUUID()}`;
  const key = `${run}/${hash}`, badKey = `${run}/wrong/${hash}`;
  const aws = new AwsClient({...config,service:'s3'});
  const request = async(url:string,init:RequestInit) => fetchImpl(url,{...init,redirect:'manual',signal:AbortSignal.timeout(30_000)});
  const status = async(response:Response) => { const code=response.status; await response.body?.cancel(); return code; };
  // R2 limits writes to one per second per key. Throttling is neither proof of
  // checksum rejection nor proof of immutability: require the original status
  // after a bounded retry. Cancel each response before sleeping (connection cap).
  const putStatus = async(url:string,init:RequestInit):Promise<number> => {
    for (let attempt=0;attempt<3;attempt++) {
      const response=await request(url,init), retryAfter=response.headers.get('retry-after');
      const code=await status(response);
      if (code!==429 || attempt===2) return code;
      let delay=1_000;
      if (retryAfter) {
        const value=retryAfter.trim();
        const requested=/^\d+(?:\.\d+)?$/.test(value)?Number(value)*1_000:Date.parse(value)-Date.now();
        if (Number.isFinite(requested)) delay=Math.min(3_000,Math.max(1_000,requested));
      }
      await sleep(delay);
    }
    return 429; // Exhaustion never satisfies any successful probe stage.
  };
  try {
    const headers = requiredUploadHeaders(key), wrong = new Uint8Array(payload);wrong[0]^=0xff;
    const bad = await presignWith(config,badKey,'PUT',60);
    const rejected = await putStatus(bad,{method:'PUT',headers,body:wrong});
    if (rejected !== 400) return {ok:false,reason:'storage does not reject incorrect signed SHA-256'};
    const url = await presignWith(config,key,'PUT',60);
    const accepted = await putStatus(url,{method:'PUT',headers,body:payload});
    if (accepted !== 200) return {ok:false,reason:'storage rejects required checksum/conditional upload contract'};
    const repeat = await putStatus(url,{method:'PUT',headers,body:payload});
    if (repeat !== 412) return {ok:false,reason:'storage does not enforce conditional immutable uploads'};
    await verifyStorageObjects(config,[{objectKey:key,blockHash:hash,length:96}],fetchImpl);
    const get = await aws.sign(objectUrl(config,key),{method:'GET'});
    const read = await request(get.url,{method:'GET',headers:get.headers});
    if (!read.ok || digestHex(sha256(new Uint8Array(await read.arrayBuffer()))) !== hash) return {ok:false,reason:'probe readback checksum mismatch'};
    return {ok:true};
  } catch { return {ok:false,reason:'storage integrity probe failed'}; }
  finally {
    for (const probe of [key,badKey]) {
      try { const del=await aws.sign(objectUrl(config,probe),{method:'DELETE'}); await status(await request(del.url,{method:'DELETE',headers:del.headers})); } catch { /* bounded probe prefix; no unrelated cleanup */ }
    }
  }
}
