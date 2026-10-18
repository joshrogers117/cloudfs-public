// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import type { FilespaceDO } from '../src/filespace-do';
import type { Block, Item } from '../src/metadata/types';
import { NamespaceStore } from '../src/metadata/namespace';
import { SnapshotStore } from '../src/metadata/snapshots';
import { migrate } from '../src/metadata/schema';
import { restorePreV30LocksTable } from './metadata-schema-fixtures';
import { filespaceDoName, mintToken } from '../src/security/auth';
import { seedOwnerFixture } from './setup-fixture';

const e = env as Env;
const headers = (token: string) => ({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' });
function itemOf(result: Awaited<ReturnType<FilespaceDO['createItem']>>): Item {
  if (!('item' in result)) throw new Error('fixture creation failed');
  return result.item;
}
const block = (objectKey: string, blockHash: string): Block => ({
  chunkIdx: 0, blockIdx: 0, objectKey, blockHash, offset: 0, length: 1024,
});
async function fixture() {
  const orgId = `history-${crypto.randomUUID().slice(0, 8)}`, spaceId = 'shared';
  const owner = await seedOwnerFixture(orgId);
  const org = e.ORG_DO.get(e.ORG_DO.idFromName(orgId));
  const fs = e.FILESPACE.get(e.FILESPACE.idFromName(filespaceDoName(orgId, spaceId)));
  const member = await org.createUser({ orgId, email: `member@${orgId}.test`, displayName: 'Member', role: 'standard' });
  const memberToken = await mintToken(e.AUTH_SIGNING_SECRET, { sub: member.id, type: 'session', orgId, scopes: ['fs:read', 'fs:write'], ttlSeconds: 900 });
  const folder = itemOf(await fs.createItem('root', 'Shared', true, 0));
  const privateFolder = itemOf(await fs.createItem('root', 'Private', true, 0));
  const file = itemOf(await fs.createItem(folder.id, 'clip.mov', false, 0));
  await fs.grantAccess({ spaceId, inodeId: folder.id, principalType: 'user', principalId: member.id, level: 'edit', mountAsRoot: true }, owner.userId);
  const base = `https://gw.local/v1/filespaces/${spaceId}`;
  const key = (suffix: string) => `blocks/${orgId}::${spaceId}/${suffix}`;
  const call = (method: string, path: string, body?: unknown, token = owner.token) => SELF.fetch(base + path, {
    method, headers: headers(token), body: body === undefined ? undefined : JSON.stringify(body),
  });
  const commit = async (item: Item, suffix: string) => {
    const response = await call('PUT', `/blocks/${item.id}`, { blocks: [block(key(suffix), suffix)], expectedVersion: item.version });
    expect(response.status, await response.clone().text()).toBe(200);
    return await response.json() as Item;
  };
  const presign = (objectKey: string, method = 'GET', token = memberToken, itemId?: string) => call('POST', '/presign', { key: objectKey, method, itemId }, token);
  return { orgId, owner, member, memberToken, fs, folder, privateFolder, file, key, call, commit, presign };
}

describe('retained committed block authorization for offline recovery', () => {
  it('single and batch GET/HEAD authorize the original key after overwrite, but never a declared arbitrary key', async () => {
    const f = await fixture();
    const before = await f.commit(f.file, 'old');
    await f.commit(before, 'new');
    for (const method of ['GET', 'HEAD']) {
      expect((await f.presign(f.key('old'), method)).status).toBe(200);
      expect((await f.presign(f.key('unknown'), method, f.memberToken, f.file.id)).status).toBe(403);
      expect((await f.presign(f.key('unknown'), method, f.owner.token, f.file.id)).status).toBe(403);
    }
    const response = await f.call('POST', '/presign/batch', { keys: [
      { key: f.key('old'), method: 'GET' }, { key: f.key('old'), method: 'HEAD' },
      { key: f.key('unknown'), method: 'GET', itemId: f.file.id },
    ] }, f.memberToken);
    expect(response.status).toBe(200);
    const { urls } = await response.json() as { urls: { url?: string; error?: string }[] };
    expect(urls[0].url).toBeTruthy(); expect(urls[1].url).toBeTruthy();
    expect(urls[2].error).toBe('object_not_in_namespace');
    // A fresh store instance uses persisted history, not any hot-state memory.
    const owners = await runInDurableObject(f.fs, (_instance, state) => [...new NamespaceStore(state.storage.sql).readOwnersForObjectKey(f.key('old'))]);
    expect(owners).toEqual([f.file.id]);
  });

  it('current permission and move boundaries apply to historical bytes on every mint', async () => {
    const f = await fixture(); const before = await f.commit(f.file, 'old'); const current = await f.commit(before, 'new');
    expect((await f.presign(f.key('old'))).status).toBe(200);
    await f.fs.renameItem(current.id, { parent: f.privateFolder.id });
    expect((await f.presign(f.key('old'))).status).toBe(403);
    await f.fs.renameItem(current.id, { parent: f.folder.id });
    expect((await f.presign(f.key('old'))).status).toBe(200);
    await f.fs.revokeAccess(f.folder.id, 'user', f.member.id);
    expect((await f.presign(f.key('old'))).status).toBe(403);
    const response = await f.call('POST', '/presign/batch', { keys: [{ key: f.key('old') }] }, f.memberToken);
    expect((await response.json() as { urls: { error: string }[] }).urls[0].error).toBe('forbidden');
  });

  it('a readable historical owner authorizes a deduplicated key despite another inaccessible current owner', async () => {
    const f = await fixture();
    const secret = itemOf(await f.fs.createItem(f.privateFolder.id, 'secret.mov', false, 0));
    await f.commit(secret, 'shared-object');
    const before = await f.commit(f.file, 'shared-object');
    await f.commit(before, 'new');
    expect((await f.presign(f.key('shared-object'))).status).toBe(200);
    await f.fs.revokeAccess(f.folder.id, 'user', f.member.id);
    expect((await f.presign(f.key('shared-object'))).status).toBe(403);
  });

  it('deletion drops recovery ownership and same-name recreation never inherits old reads, even for an administrator', async () => {
    const f = await fixture(); const before = await f.commit(f.file, 'old'); await f.commit(before, 'new');
    const removed = await f.call('DELETE', `/items/${f.file.id}`); expect(removed.status).toBe(200);
    const recreated = itemOf(await f.fs.createItem(f.folder.id, f.file.name, false, 0));
    expect(recreated.id).not.toBe(f.file.id);
    await f.commit(recreated, 'recreated');
    expect((await f.presign(f.key('old'), 'GET', f.owner.token, recreated.id)).status).toBe(403);
    expect((await f.presign(f.key('old'), 'GET', f.memberToken, recreated.id)).status).toBe(403);
    const collectible = await f.fs.collectableBlocks();
    expect(collectible.map(row => row.objectKey)).toContain(f.key('old'));
    expect(collectible.map(row => row.objectKey)).toContain(f.key('new'));
  });

  it('recursive delete releases history only for the deleted subtree', async () => {
    const f = await fixture(); const before = await f.commit(f.file, 'old'); await f.commit(before, 'new');
    const sibling = itemOf(await f.fs.createItem('root', 'survivor.mov', false, 0));
    const siblingBefore = await f.commit(sibling, 'survivor-old'); await f.commit(siblingBefore, 'survivor-new');
    const response = await f.call('DELETE', `/items/${f.folder.id}?recursive=true`); expect(response.status).toBe(200);
    expect((await f.presign(f.key('old'), 'GET', f.owner.token)).status).toBe(403);
    expect((await f.presign(f.key('survivor-old'), 'GET', f.owner.token)).status).toBe(200);
    expect((await f.fs.collectableBlocks()).map(row => row.objectKey)).not.toContain(f.key('survivor-old'));
  });

  it('snapshot restore retains displaced versions without changing snapshot refcounts; deletion releases only its own roots', async () => {
    const f = await fixture();
    await runInDurableObject(f.fs, (_instance, state) => {
      const sql = state.storage.sql, ns = new NamespaceStore(sql), snapshots = new SnapshotStore(sql, () => ns.currentSeq(), ns);
      ns.setBlockMap(f.file.id, [block(f.key('old'), 'old')]);
      snapshots.create({ id: 'saved', scope: 'root' });
      const current = ns.setBlockMap(f.file.id, [block(f.key('new'), 'new')]);
      const refs = (hash: string) => Number(sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?;', hash).one().refcount);
      expect(refs('old')).toBe(1); // snapshot only; recovery roots are tracked independently
      expect(snapshots.collectableBlocks().map(row => row.blockHash)).not.toContain('old');
      expect(() => ns.setBlockMap(f.file.id, [block(f.key('rejected'), 'rejected')], { expectedVersion: current.version - 1 })).toThrow();
      expect([...ns.readOwnersForObjectKey(f.key('rejected'))]).toEqual([]);
      snapshots.restore('saved', f.file.id);
      expect([...ns.readOwnersForObjectKey(f.key('new'))]).toEqual([f.file.id]);
      expect(snapshots.collectableBlocks().map(row => row.blockHash)).not.toContain('new');
      ns.remove(f.file.id);
      expect(snapshots.collectableBlocks().map(row => row.blockHash)).toContain('new');
      expect(snapshots.collectableBlocks().map(row => row.blockHash)).not.toContain('old');
      expect([...ns.readOwnersForObjectKey(f.key('old'))]).toEqual([]); // snapshot cannot bypass deletion ACL
      snapshots.deleteSnapshot('saved');
      expect(snapshots.collectableBlocks().map(row => row.blockHash)).toContain('old');
    });
  });

  it('upgrades existing snapshot ownership and indexes idempotently without reviving a tombstone', async () => {
    const f = await fixture();
    await runInDurableObject(f.fs, (_instance, state) => {
      const sql = state.storage.sql, ns = new NamespaceStore(sql), snapshots = new SnapshotStore(sql, () => ns.currentSeq(), ns);
      ns.setBlockMap(f.file.id, [block(f.key('old'), 'old')]); snapshots.create({ id: 'saved', scope: 'root' });
      ns.setBlockMap(f.file.id, [block(f.key('new'), 'new')]);
      restorePreV30LocksTable(sql);
      sql.exec('DROP TABLE retained_blocks;'); sql.exec('DELETE FROM _schema_migrations WHERE id>=15;');
      migrate(sql); migrate(sql);
      expect([...ns.readOwnersForObjectKey(f.key('old'))]).toEqual([f.file.id]);
      const indexNames = sql.exec('PRAGMA index_list(retained_blocks);').toArray().map(row => String(row.name));
      expect(indexNames).toContain('retained_blocks_object_key'); expect(indexNames).toContain('retained_blocks_hash');
      ns.remove(f.file.id);
      restorePreV30LocksTable(sql);
      sql.exec('DROP TABLE retained_blocks;'); sql.exec('DELETE FROM _schema_migrations WHERE id>=15;'); migrate(sql);
      expect([...ns.readOwnersForObjectKey(f.key('old'))]).toEqual([]);
    });
  });
});

describe('manifest references require real read or upload authority', () => {
  it('a scoped writer cannot attach private current, historical, or retired keys to a writable inode', async () => {
    const f = await fixture();
    const secret = itemOf(await f.fs.createItem(f.privateFolder.id, 'secret.mov', false, 0));
    const before = await f.commit(secret, 'private-old'); await f.commit(before, 'private-current');
    for (const suffix of ['private-old', 'private-current']) {
      const rejected = await f.call('PUT', `/blocks/${f.file.id}`, { blocks: [block(f.key(suffix), suffix)], expectedVersion: f.file.version }, f.memberToken);
      expect(rejected.status, await rejected.clone().text()).toBe(403);
      expect((await f.presign(f.key(suffix))).status).toBe(403);
      expect((await f.presign(f.key(suffix), 'PUT', f.memberToken, f.file.id)).status).toBe(403);
    }
    await f.call('DELETE', `/items/${secret.id}`);
    expect((await f.presign(f.key('private-old'), 'PUT', f.memberToken, f.file.id)).status).toBe(403);
    const forged = await f.call('PUT', `/blocks/${f.file.id}`, { blocks: [block(f.key('private-old'), 'private-old')], expectedVersion: f.file.version }, f.memberToken);
    expect(forged.status).toBe(403);
    expect(await f.fs.getBlockMap(f.file.id)).toEqual([]);
    const batch = await f.call('POST', '/presign/batch', { keys: [{ key: f.key('private-old'), method: 'PUT', itemId: f.file.id }] }, f.memberToken);
    expect((await batch.json() as { urls: { error: string }[] }).urls[0].error).toBe('forbidden');
  });

  it('new scoped uploads require matching server claims and cannot steal another pending uploader key', async () => {
    const f = await fixture();
    const pending = f.key('pending');
    const commit = () => f.call('PUT', `/blocks/${f.file.id}`, { blocks: [block(pending, 'pending')], expectedVersion: f.file.version }, f.memberToken);
    expect((await commit()).status).toBe(403); // arbitrary declaration is not evidence
    expect((await f.presign(pending, 'PUT', f.memberToken, f.file.id)).status).toBe(200);
    expect((await f.presign(pending)).status).toBe(403); // mint itself does not grant reads
    const other = itemOf(await f.fs.createItem(f.folder.id, 'other.mov', false, 0));
    const wrongItem = await f.call('PUT', `/blocks/${other.id}`, { blocks: [block(pending, 'pending')], expectedVersion: other.version }, f.memberToken);
    expect(wrongItem.status).toBe(403);
    expect((await f.presign(pending, 'PUT', f.owner.token, other.id)).status).toBe(403);
    expect((await commit()).status).toBe(200);
    expect((await f.presign(pending)).status).toBe(200);
  });

  it('expired claims require renewal by a writer of the declared inode and never become another inode’s bytes', async () => {
    const f = await fixture(), key = f.key('expired');
    expect((await f.presign(key, 'PUT', f.memberToken, f.file.id)).status).toBe(200);
    await runInDurableObject(f.fs, (_instance, state) => { state.storage.sql.exec('UPDATE block_upload_claims SET expires_at=0 WHERE object_key=?;', key); });
    const commit = () => f.call('PUT', `/blocks/${f.file.id}`, { blocks: [block(key, 'expired')], expectedVersion: f.file.version }, f.memberToken);
    expect((await commit()).status).toBe(403);
    // Same-inode takeover: another writer of THIS inode may renew; a different inode may not.
    const elsewhere = itemOf(await f.fs.createItem(f.folder.id, 'elsewhere.mov', false, 0));
    expect((await f.presign(key, 'PUT', f.owner.token, elsewhere.id)).status).toBe(403);
    expect((await f.presign(key, 'PUT', f.owner.token, f.file.id)).status).toBe(200);
    expect((await f.presign(key, 'PUT', f.memberToken, f.file.id)).status).toBe(200);
    expect((await commit()).status).toBe(200);
  });

  it('same-principal access revoked after PUT mint prevents publishing that claim', async () => {
    const f = await fixture(), key = f.key('revoked-pending');
    expect((await f.presign(key, 'PUT', f.memberToken, f.file.id)).status).toBe(200);
    await f.fs.revokeAccess(f.folder.id, 'user', f.member.id);
    const response = await f.call('PUT', `/blocks/${f.file.id}`, { blocks: [block(key, 'revoked-pending')], expectedVersion: f.file.version }, f.memberToken);
    expect(response.status).toBe(403);
    expect(await f.fs.getBlockMap(f.file.id)).toEqual([]);
  });

  it('batch upload claims support real scoped commits and owner unowned ingest remains compatible', async () => {
    const f = await fixture(), key = f.key('batch-new');
    const minted = await f.call('POST', '/presign/batch', { keys: [{ key, method: 'PUT', itemId: f.file.id }] }, f.memberToken);
    expect((await minted.json() as { urls: { url: string }[] }).urls[0].url).toBeTruthy();
    const response = await f.call('PUT', `/blocks/${f.file.id}`, { blocks: [block(key, 'batch-new')], expectedVersion: f.file.version }, f.memberToken);
    expect(response.status).toBe(200);
    const ingest = itemOf(await f.fs.createItem(f.folder.id, 'ingest.mov', false, 0));
    expect((await f.presign(f.key('ingest'), 'PUT', f.owner.token)).status).toBe(200);
    await f.commit(ingest, 'ingest');
  });
});
