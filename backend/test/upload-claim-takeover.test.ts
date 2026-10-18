// SPDX-License-Identifier: AGPL-3.0-or-later
import { encryptedBlockFixture } from './encrypted-block-fixture';
import { createExecutionContext, env, runInDurableObject, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import worker from '../src/index';
import type { Env } from '../src/env';
import { uploadVerificationManifest } from '../src/upload-verification';
import { hex, itemOf, makeOrg } from './multi-client-fixture';

const payload = encryptedBlockFixture(), digest = sha256(payload), hash = hex(digest);
const endpoint = `https://${'a'.repeat(32)}.r2.cloudflarestorage.com`;

async function fixture() {
  const o = await makeOrg(['files'], 'claimtake');
  const config = { S3_ENDPOINT: endpoint, S3_BUCKET: 'cloudfs-data', S3_REGION: 'auto', DATA_BUCKET_ENDPOINT: endpoint, DATA_BUCKET_NAME: 'cloudfs-data', STORAGE_VERIFY_UPLOADS: '1' };
  const bindings = { ...(env as Env), ...config } as Env;
  const stub = o.fs('files');
  await runInDurableObject(stub, instance => { Object.assign((instance as unknown as { env: Env }).env, config); });
  const folder = itemOf(await stub.createItem('root', 'Shared', true, 0));
  const file = itemOf(await stub.createItem(folder.id, 'clip.mov', false, 0));
  const other = itemOf(await stub.createItem('root', 'other.mov', false, 0));
  const a = await o.user('A'), b = await o.user('B'), c = await o.user('C');
  const tok = { a: await o.tokenFor(a.id), b: await o.tokenFor(b.id), c: await o.tokenFor(c.id) };
  await stub.grantAccess({ spaceId: 'files', inodeId: folder.id, principalType: 'user', principalId: a.id, level: 'edit' }, o.owner.userId);
  await stub.grantAccess({ spaceId: 'files', inodeId: folder.id, principalType: 'user', principalId: b.id, level: 'edit' }, o.owner.userId);
  await stub.grantAccess({ spaceId: 'files', inodeId: other.id, principalType: 'user', principalId: c.id, level: 'edit' }, o.owner.userId);
  const key = `blocks/${o.orgId}::files/${hash}`;
  const manifest = uploadVerificationManifest([{ objectKey: key, blockHash: hash, length: 4 }]);
  const send = async (token: string, method: string, path: string, body?: unknown) => {
    const ctx = createExecutionContext();
    const res = await worker.fetch(new Request(`https://gw.local/v1/filespaces/files${path}`, {
      method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body),
    }), bindings, ctx);
    await waitOnExecutionContext(ctx);
    return res;
  };
  const presign = (token: string, itemId: string) => send(token, 'POST', '/presign', { key, method: 'PUT', itemId });
  return { ...o, bindings, stub, file, other, tok, folderId: folder.id, aId: a.id, key, manifest, send, presign };
}

describe('upload claim takeover for the same inode', () => {
  it('a co-writer on the same inode takes over an abandoned claim, uploads and commits; the original uploader then also commits (idempotent) ', async () => {
    const f = await fixture();
    expect((await f.presign(f.tok.a, f.file.id)).status).toBe(200); // A never commits
    expect((await f.presign(f.tok.b, f.file.id)).status).toBe(200); // B takes over
    await f.bindings.DATA_BUCKET!.put(f.key, payload, { sha256: digest });
    try {
      const commit = (t: string, expectedVersion: number) => f.send(t, 'PUT', `/blocks/${f.file.id}`, { blocks: f.manifest, expectedVersion });
      const ok = await commit(f.tok.b, f.file.version!);
      expect(ok.status).toBe(200);
      const v = (await ok.json() as { version: number }).version;
      expect(v).toBe(f.file.version! + 1);
      expect(await f.stub.getBlockMap(f.file.id)).toEqual(f.manifest);
      // A's later commit of the same manifest: the object is now published/known,
      // so it is a normal idempotent write (no stale-claim error).
      const again = await commit(f.tok.a, v);
      expect(again.status).toBe(200);
    } finally { await f.bindings.DATA_BUCKET!.delete(f.key); }
  });

  it('the original claimant can still commit after another writer took the claim over (before publication)', async () => {
    const f = await fixture();
    await f.presign(f.tok.a, f.file.id);
    await f.presign(f.tok.b, f.file.id);
    await f.bindings.DATA_BUCKET!.put(f.key, payload, { sha256: digest });
    try {
      const res = await f.send(f.tok.a, 'PUT', `/blocks/${f.file.id}`, { blocks: f.manifest, expectedVersion: f.file.version });
      expect(res.status).toBe(200);
    } finally { await f.bindings.DATA_BUCKET!.delete(f.key); }
  });

  it('a principal without write access on the inode is still refused', async () => {
    const f = await fixture();
    expect((await f.presign(f.tok.a, f.file.id)).status).toBe(200);
    const reader = await f.user('Reader');
    const t = await f.tokenFor(reader.id);
    expect((await f.presign(t, f.file.id)).status).toBe(403);
    expect((await f.presign(f.tok.c, f.file.id)).status).toBe(403); // writes a different inode only
  });

  it('a claim declared for a different inode is not adoptable for the same key', async () => {
    const f = await fixture();
    expect((await f.presign(f.tok.c, f.other.id)).status).toBe(200);
    // B can write file but the key is claimed for `other`.
    expect((await f.presign(f.tok.b, f.file.id)).status).toBe(403);
    // And C's claim cannot be used by B to commit into file.
    await f.bindings.DATA_BUCKET!.put(f.key, payload, { sha256: digest });
    try {
      const res = await f.send(f.tok.b, 'PUT', `/blocks/${f.file.id}`, { blocks: f.manifest, expectedVersion: f.file.version });
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(await f.stub.getBlockMap(f.file.id)).toEqual([]);
    } finally { await f.bindings.DATA_BUCKET!.delete(f.key); }
  });

  it('a writer whose grant is revoked after presigning cannot commit (typed 403, manifest unchanged)', async () => {
    const f = await fixture();
    expect((await f.presign(f.tok.a, f.file.id)).status).toBe(200);
    await f.bindings.DATA_BUCKET!.put(f.key, payload, { sha256: digest });
    try {
      await f.stub.revokeAccess(f.folderId, 'user', f.aId);
      const res = await f.send(f.tok.a, 'PUT', `/blocks/${f.file.id}`, { blocks: f.manifest, expectedVersion: f.file.version });
      expect(res.status).toBe(403);
      const body = await res.json() as { error?: string };
      expect(typeof body.error).toBe('string');
      expect(await f.stub.getBlockMap(f.file.id)).toEqual([]);
    } finally { await f.bindings.DATA_BUCKET!.delete(f.key); }
  });
});
