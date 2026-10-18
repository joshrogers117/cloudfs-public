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

/** Verification-on fixture: one writer, one folder with a file, one unrelated sibling folder. */
async function fixture() {
  const o = await makeOrg(['files'], 'mcperm');
  const base = env as Env;
  const config = { S3_ENDPOINT: endpoint, S3_BUCKET: 'cloudfs-data', S3_REGION: 'auto', DATA_BUCKET_ENDPOINT: endpoint, DATA_BUCKET_NAME: 'cloudfs-data', STORAGE_VERIFY_UPLOADS: '1' };
  const bindings = { ...base, ...config } as Env;
  const stub = o.fs('files');
  await runInDurableObject(stub, instance => { Object.assign((instance as unknown as { env: Env }).env, config); });
  const folder = itemOf(await stub.createItem('root', 'Shared', true, 0));
  const sibling = itemOf(await stub.createItem('root', 'Unrelated', true, 0));
  const file = itemOf(await stub.createItem(folder.id, 'clip.mov', false, 0));
  const otherFile = itemOf(await stub.createItem(sibling.id, 'other.mov', false, 0));
  const writer = await o.user('Writer'), peer = await o.user('Peer');
  const writerToken = await o.tokenFor(writer.id), peerToken = await o.tokenFor(peer.id);
  const key = `blocks/${o.orgId}::files/${hash}`;
  const block = { objectKey: key, blockHash: hash, length: 4 };
  const manifest = uploadVerificationManifest([block]);
  const send = async (token: string, method: string, path: string, body?: unknown) => {
    const ctx = createExecutionContext();
    const res = await worker.fetch(new Request(`https://gw.local/v1/filespaces/files${path}`, {
      method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body),
    }), bindings, ctx);
    await waitOnExecutionContext(ctx);
    return res;
  };
  const grant = (inodeId: string, principalId: string, level: 'read' | 'edit' | 'admin') =>
    stub.grantAccess({ spaceId: 'files', inodeId, principalType: 'user', principalId, level }, o.owner.userId);
  const identity = () => storageIdentity(defaultStorageConfig(bindings));
  return { ...o, bindings, stub, folder, sibling, file, otherFile, writer, peer, writerToken, peerToken, key, block, manifest, send, grant, identity };
}

describe('permission change while an upload is in flight', () => {
  it('revoking edit after presign + receipts refuses the commit and later write presigns, leaving the manifest untouched', async () => {
    const f = await fixture();
    await f.grant(f.folder.id, f.writer.id, 'edit');
    const presign = await f.send(f.writerToken, 'POST', '/presign', { key: f.key, method: 'PUT', itemId: f.file.id });
    expect(presign.status).toBe(200);
    await f.bindings.DATA_BUCKET!.put(f.key, payload, { sha256: digest });
    try {
      expect((await f.send(f.writerToken, 'POST', `/blocks/${f.file.id}/verify`, { blocks: [f.block] })).status).toBe(200);
      expect(await f.stub.unverifiedObjects(f.manifest, f.identity())).toEqual([]);
      const before = await f.stub.getItem(f.file.id);

      await f.stub.revokeAccess(f.folder.id, 'user', f.writer.id);

      const commit = await f.send(f.writerToken, 'PUT', `/blocks/${f.file.id}`, { blocks: f.manifest, expectedVersion: f.file.version });
      expect(commit.status).toBe(403);
      expect(await f.stub.getItem(f.file.id)).toEqual(before);
      expect(await f.stub.getBlockMap(f.file.id)).toEqual([]);
      for (const [path, body] of [['/presign', { key: f.key, method: 'PUT', itemId: f.file.id }],
        ['/presign/batch', { keys: [{ key: f.key, method: 'PUT', itemId: f.file.id }] }]] as const) {
        const res = await f.send(f.writerToken, 'POST', path, body);
        if (path === '/presign') expect(res.status).toBe(403);
        else expect(((await res.json()) as { urls: { error?: string; url?: string }[] }).urls[0]).toMatchObject({ error: 'forbidden' });
      }
      expect((await f.send(f.writerToken, 'POST', `/blocks/${f.file.id}/verify`, { blocks: [f.block] })).status).toBe(403);
    } finally { await f.bindings.DATA_BUCKET!.delete(f.key); }
  });

  it('downgrading edit to read blocks commit and write presign but still allows read presign and reads', async () => {
    const f = await fixture();
    await f.grant(f.folder.id, f.writer.id, 'edit');
    const first = payload, second = encryptedBlockFixture(); second[10] ^= 0xff;
    const hash2 = hex(sha256(second)), key2 = `blocks/${f.orgId}::files/${hash2}`;
    const manifest2 = uploadVerificationManifest([{ objectKey: key2, blockHash: hash2, length: 4 }]);
    for (const [key, bytes] of [[f.key, first], [key2, second]] as const) {
      expect((await f.send(f.writerToken, 'POST', '/presign', { key, method: 'PUT', itemId: f.file.id })).status).toBe(200);
      await f.bindings.DATA_BUCKET!.put(key, bytes, { sha256: sha256(bytes) });
    }
    try {
      expect((await f.send(f.writerToken, 'POST', `/blocks/${f.file.id}/verify`, { blocks: manifest2 })).status).toBe(200);
      // v1 commits while the grant is still edit (verifies the first object inline).
      const v1 = await f.send(f.writerToken, 'PUT', `/blocks/${f.file.id}`, { blocks: f.manifest, expectedVersion: f.file.version });
      expect(v1.status).toBe(200);
      const committed = await f.stub.getItem(f.file.id);

      // The API replaces the tuple (the raw store seam is additive), so this is a true downgrade.
      expect((await f.send(f.owner.token, 'POST', '/grants', { inodeId: f.folder.id, principalType: 'user', principalId: f.writer.id, level: 'read' })).status).toBe(201);
      expect((await f.send(f.writerToken, 'PUT', `/blocks/${f.file.id}`, { blocks: manifest2, expectedVersion: committed!.version })).status).toBe(403);
      expect((await f.send(f.writerToken, 'POST', '/presign', { key: key2, method: 'PUT', itemId: f.file.id })).status).toBe(403);
      expect((await f.send(f.writerToken, 'POST', '/presign', { key: f.key, method: 'GET' })).status).toBe(200);
      expect((await f.send(f.writerToken, 'POST', '/presign', { key: f.key, method: 'HEAD' })).status).toBe(200);
      expect(await (await f.send(f.writerToken, 'GET', `/blocks/${f.file.id}`)).json()).toEqual(f.manifest);
      expect(await f.stub.getItem(f.file.id)).toEqual(committed);
      expect(await f.stub.getBlockMap(f.file.id)).toEqual(f.manifest);
      // Restoring edit restores the ability; the early receipt for object 2 was never consumed.
      expect((await f.send(f.owner.token, 'POST', '/grants', { inodeId: f.folder.id, principalType: 'user', principalId: f.writer.id, level: 'edit' })).status).toBe(201);
      expect((await f.send(f.writerToken, 'PUT', `/blocks/${f.file.id}`, { blocks: manifest2, expectedVersion: committed!.version })).status).toBe(200);
    } finally { await f.bindings.DATA_BUCKET!.delete([f.key, key2]); }
  });

  it('a folder administrator revoking a sibling grant cannot touch an unrelated subtree', async () => {
    const f = await fixture();
    const admin = await f.user('Folder admin');
    const adminToken = await f.tokenFor(admin.id);
    await f.grant(f.folder.id, admin.id, 'admin');
    // Delegated authority covers only grants the folder admin issued itself.
    expect((await f.send(adminToken, 'POST', '/grants', { inodeId: f.folder.id, principalType: 'user', principalId: f.writer.id, level: 'edit' })).status).toBe(201);
    await f.grant(f.sibling.id, f.writer.id, 'edit');
    await f.grant(f.sibling.id, f.peer.id, 'edit');
    const revoke = (token: string, inodeId: string, principalId: string) =>
      f.send(token, 'DELETE', `/grants?${new URLSearchParams({ inodeId, principalType: 'user', principalId })}`);
    // The delegated admin has no authority over the unrelated subtree.
    expect([403, 404]).toContain((await revoke(adminToken, f.sibling.id, f.writer.id)).status);
    expect((await f.stub.checkAccess({ type: 'user', id: f.writer.id }, f.otherFile.id, 'write')).allow).toBe(true);
    expect((await f.stub.checkAccess({ type: 'user', id: f.peer.id }, f.otherFile.id, 'write')).allow).toBe(true);
    // Within its own folder revocation works and affects only that tuple.
    expect((await revoke(adminToken, f.folder.id, f.writer.id)).status).toBe(200);
    expect((await f.stub.checkAccess({ type: 'user', id: f.writer.id }, f.file.id, 'write')).allow).toBe(false);
    expect((await f.stub.checkAccess({ type: 'user', id: f.writer.id }, f.otherFile.id, 'write')).allow).toBe(true);
    expect((await f.stub.checkAccess({ type: 'user', id: f.peer.id }, f.otherFile.id, 'write')).allow).toBe(true);
  });
});
