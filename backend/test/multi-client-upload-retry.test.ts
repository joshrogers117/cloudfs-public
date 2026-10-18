// SPDX-License-Identifier: AGPL-3.0-or-later
import { encryptedBlockFixture } from './encrypted-block-fixture';
import { createExecutionContext, env, runInDurableObject, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import worker from '../src/index';
import type { Env } from '../src/env';
import { defaultStorageConfig } from '../src/storage';
import { storageIdentity } from '../src/storage-object-verifier';
import { uploadVerificationManifest } from '../src/upload-verification';
import { hex, itemOf, makeOrg } from './multi-client-fixture';

const payload = encryptedBlockFixture(), digest = sha256(payload), hash = hex(digest);
const endpoint = `https://${'a'.repeat(32)}.r2.cloudflarestorage.com`;

async function fixture() {
  const o = await makeOrg(['files'], 'mcretry');
  const base = env as Env;
  const config = { S3_ENDPOINT: endpoint, S3_BUCKET: 'cloudfs-data', S3_REGION: 'auto', DATA_BUCKET_ENDPOINT: endpoint, DATA_BUCKET_NAME: 'cloudfs-data', STORAGE_VERIFY_UPLOADS: '1' };
  const bindings = { ...base, ...config } as Env;
  const stub = o.fs('files');
  await runInDurableObject(stub, instance => { Object.assign((instance as unknown as { env: Env }).env, config); });
  const item = itemOf(await stub.createItem('root', 'clip.mov', false, 0));
  const key = `blocks/${o.orgId}::files/${hash}`;
  const block = { objectKey: key, blockHash: hash, length: 4 };
  const manifest = uploadVerificationManifest([block]);
  const send = async (method: string, path: string, body?: unknown) => {
    const ctx = createExecutionContext();
    const res = await worker.fetch(new Request(`https://gw.local/v1/filespaces/files${path}`, {
      method, headers: { authorization: `Bearer ${o.owner.token}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body),
    }), bindings, ctx);
    await waitOnExecutionContext(ctx);
    return res;
  };
  const identity = storageIdentity(defaultStorageConfig(bindings));
  const receipts = () => runInDurableObject(stub, (_i, state) => state.storage.sql.exec('SELECT * FROM verified_objects;').toArray());
  const snapshot = async () => ({ item: await stub.getItem(item.id), blocks: await stub.getBlockMap(item.id), feed: await stub.changesSince(0) });
  return { ...o, bindings, stub, item, key, block, manifest, send, identity, receipts, snapshot };
}

describe('retry and cancellation of uploads', () => {
  it('duplicate and concurrent receipt verification is idempotent and the receipt is immutable', async () => {
    const f = await fixture();
    await f.bindings.DATA_BUCKET!.put(f.key, payload, { sha256: digest });
    try {
      const before = await f.snapshot();
      const results = await Promise.all(Array.from({ length: 6 }, () => f.send('POST', `/blocks/${f.item.id}/verify`, { blocks: [f.block] })));
      for (const res of results) { expect(res.status).toBe(200); expect(await res.json()).toEqual({ verified: 1 }); }
      const rows = await f.receipts();
      expect(rows).toHaveLength(1);
      // A later duplicate does not rewrite the receipt (timestamp included).
      expect((await f.send('POST', `/blocks/${f.item.id}/verify`, { blocks: [f.block, f.block] })).status).toBe(200);
      expect(await f.receipts()).toEqual(rows);
      // A conflicting interpretation of the same stored object is refused and changes nothing.
      const conflicting = await f.stub.recordVerifiedObjects([{ ...f.block, length: 3, ciphertextSize: 3 }], f.identity);
      expect(conflicting).toHaveProperty('error', 'object_verification_failed');
      const forged = await f.stub.recordVerifiedObjects([{ ...f.block, blockHash: 'b'.repeat(64), ciphertextSize: 4 }], f.identity);
      expect(forged).toHaveProperty('error', 'object_verification_failed');
      expect(await f.receipts()).toEqual(rows);
      expect(await f.stub.unverifiedObjects(f.manifest, f.identity)).toEqual([]);
      // Verification never publishes anything.
      expect(await f.snapshot()).toEqual(before);
    } finally { await f.bindings.DATA_BUCKET!.delete(f.key); }
  });

  it('an upload that is presigned/started and then abandoned leaves the manifest and feed unchanged', async () => {
    const f = await fixture();
    const before = await f.snapshot();
    expect((await f.send('POST', '/presign', { key: f.key, method: 'PUT', itemId: f.item.id })).status).toBe(200);
    // Multipart session begun, a part recorded, then aborted by the client.
    await f.stub.beginUpload('up-1', f.item.id, f.key, 8, 4);
    await f.stub.recordUploadPart('up-1', 1, 'etag-1', 4);
    await f.stub.abortUpload('up-1');
    expect((await f.stub.uploadStatus('up-1')).session).toMatchObject({ state: 'aborted' });
    // Even with bytes now present, nothing is published without a commit.
    await f.bindings.DATA_BUCKET!.put(f.key, payload, { sha256: digest });
    try { expect(await f.snapshot()).toEqual(before); } finally { await f.bindings.DATA_BUCKET!.delete(f.key); }
    expect(await f.receipts()).toEqual([]);
  });

  it('a commit referencing missing or corrupt objects is refused with the typed 503 and the manifest is unchanged; the retry succeeds once the upload completes', async () => {
    const f = await fixture();
    const before = await f.snapshot();
    const commit = () => f.send('PUT', `/blocks/${f.item.id}`, { blocks: f.manifest, expectedVersion: f.item.version });
    // Object never uploaded.
    const missing = await commit();
    expect(missing.status).toBe(503);
    expect(await missing.json()).toMatchObject({ error: 'object_verification_failed' });
    expect(await f.snapshot()).toEqual(before);
    // Object present but with different bytes than its content address.
    const wrong = new Uint8Array([4, 3, 2, 1]);
    await f.bindings.DATA_BUCKET!.put(f.key, wrong, { sha256: sha256(wrong) });
    try {
      const corrupt = await commit();
      expect(corrupt.status).toBe(503);
      expect(await corrupt.json()).toMatchObject({ error: 'object_verification_failed' });
      expect(await f.snapshot()).toEqual(before);
      expect(await f.receipts()).toEqual([]);
    } finally { await f.bindings.DATA_BUCKET!.delete(f.key); }
    // DO-level backstop: even a caller that skips the gateway verification cannot publish without receipts.
    const principal = { type: 'user' as const, id: f.owner.userId, orgRole: 'owner' as const };
    expect(await f.stub.setBlockMap(f.item.id, f.manifest, { principal, storageIdentity: f.identity, expectedVersion: f.item.version }))
      .toMatchObject({ invalidManifest: true, reason: 'objects require storage verification before publication' });
    expect(await f.snapshot()).toEqual(before);
    // The honest client retries after finishing the upload: exactly one version bump, and a duplicate retry is a no-op.
    await f.bindings.DATA_BUCKET!.put(f.key, payload, { sha256: digest });
    try {
      const ok = await commit();
      expect(ok.status).toBe(200);
      const committed = await ok.json() as { version: number };
      expect(committed.version).toBe(f.item.version! + 1);
      const again = await commit();
      expect(again.status).toBe(200);
      expect((await again.json() as { version: number }).version).toBe(committed.version);
      expect(await f.stub.getBlockMap(f.item.id)).toEqual(f.manifest);
    } finally { await f.bindings.DATA_BUCKET!.delete(f.key); }
  });
});
