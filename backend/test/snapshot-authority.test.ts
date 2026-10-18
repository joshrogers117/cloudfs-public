// SPDX-License-Identifier: AGPL-3.0-or-later
// Independent gateway regressions: historical reads/restores are not a second
// route around live folder permissions, and mounted snapshots cannot be refrozen.
import { SELF, env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import type { FilespaceDO } from '../src/filespace-do';
import type { Level } from '../src/permissions';
import { filespaceDoName, mintToken, type Scope } from '../src/security/auth';
import { seedOwnerFixture } from './setup-fixture';

const e = env as Env;
const origin = 'https://gw.local';
const headers = (token: string) => ({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' });
const itemOf = (result: Awaited<ReturnType<FilespaceDO['createItem']>>) => {
  if (!('item' in result)) throw new Error('fixture item creation failed');
  return result.item;
};

async function fixture() {
  const orgId = `snapshot-authority-${crypto.randomUUID().slice(0, 8)}`;
  const owner = await seedOwnerFixture(orgId);
  const org = e.ORG_DO.get(e.ORG_DO.idFromName(orgId));
  const spaceId = 'team';
  const created = await SELF.fetch(`${origin}/v1/orgs/${orgId}/spaces`, {
    method: 'POST', headers: headers(owner.token),
    body: JSON.stringify({ spaceId, name: 'Team', bucketProvider: 'r2', bucketName: 'bucket', keyPrefix: '' }),
  });
  expect(created.status).toBe(201);
  const member = await org.createUser({ orgId, email: `member@${orgId}.test`, displayName: 'Editor', role: 'standard' });
  // Deliberately broad token scopes. Resource ACLs must still constrain them.
  const scopes: Scope[] = ['fs:read', 'fs:write', 'fs:lock', 'snapshot:read', 'snapshot:write'];
  const token = await mintToken(e.AUTH_SIGNING_SECRET, { sub: member.id, type: 'session', orgId, scopes, ttlSeconds: 900 });
  const fs = e.FILESPACE.get(e.FILESPACE.idFromName(filespaceDoName(orgId, spaceId)));
  const shared = itemOf(await fs.createItem('root', 'Shared', true, 0));
  const privateFolder = itemOf(await fs.createItem('root', 'Private', true, 0));
  const clip = itemOf(await fs.createItem(shared.id, 'clip.mov', false, 0));
  const secret = itemOf(await fs.createItem(privateFolder.id, 'secret.mov', false, 0));
  const base = `${origin}/v1/filespaces/${spaceId}`;
  const post = (path: string, body: unknown, auth = token) => SELF.fetch(`${base}${path}`, {
    method: 'POST', headers: headers(auth), body: JSON.stringify(body),
  });
  const grant = (inodeId: string, level: Level) => fs.grantAccess({
    spaceId, inodeId, principalType: 'user', principalId: member.id, level,
  }, owner.userId);
  const putContent = (id: string, marker: string, size: number) => fs.setBlockMap(id, [{
    chunkIdx: 0, blockIdx: 0, blockHash: marker, objectKey: `blocks/${orgId}::${spaceId}/${marker}`, offset: 0, length: size,
  }]);
  return { owner, fs, shared, privateFolder, clip, secret, base, token, post, grant, putContent };
}

describe('snapshot authority and immutability', () => {
  it('public creation cannot overwrite an existing snapshot identifier or change its frozen content', async () => {
    const f = await fixture();
    await f.putContent(f.clip.id, 'original', 4);
    const first = await f.post('/snapshots', { id: 'stable-point', label: 'Original', scope: f.shared.id }, f.owner.token);
    expect(first.status).toBe(201);
    const saved = await first.json() as { id: string };
    await f.putContent(f.clip.id, 'changed', 9);
    const overwrite = await f.post('/snapshots', { id: saved.id, label: 'Replacement', scope: f.shared.id }, f.owner.token);
    expect(overwrite.status).toBe(409);
    const frozen = await f.fs.listSnapshotDir(saved.id, f.shared.id);
    expect(frozen.find(item => item.id === f.clip.id)?.size).toBe(4);
    expect((await f.fs.listSnapshots()).find(snapshot => snapshot.id === saved.id)?.label).toBe('Original');
  });

  it('concurrent creators cannot replace the same snapshot at the check/create boundary', async () => {
    const f = await fixture();
    const responses = await Promise.all(['First', 'Second'].map(label =>
      f.post('/snapshots', { id: 'contested-point', label, scope: f.shared.id }, f.owner.token)));
    expect(responses.map(response => response.status).sort()).toEqual([201, 409]);
    const winner = await responses.find(response => response.status === 201)!.json() as { id: string; label: string };
    const saved = (await f.fs.listSnapshots()).find(snapshot => snapshot.id === winner.id);
    expect(saved?.label).toBe(winner.label);
  });

  it('read/edit access cannot create snapshots despite a snapshot:write token scope', async () => {
    for (const level of ['read', 'edit'] as const) {
      const f = await fixture();
      await f.grant(f.shared.id, level);
      for (const scope of ['root', f.shared.id, f.privateFolder.id]) {
        const response = await f.post('/snapshots', { scope, label: 'Unauthorized snapshot' });
        expect(response.status, `${level} grant on ${scope}`).toBe(403);
      }
      expect(await f.fs.listSnapshots()).toEqual([]);
    }
  });

  it('a folder administrator can create only a snapshot inside the delegated scope', async () => {
    const f = await fixture();
    await f.grant(f.shared.id, 'admin');
    expect((await f.post('/snapshots', { scope: f.shared.id, label: 'Shared checkpoint' })).status).toBe(201);
    expect((await f.post('/snapshots', { scope: 'root', label: 'Whole filespace' })).status).toBe(403);
    expect((await f.post('/snapshots', { scope: f.privateFolder.id, label: 'Private checkpoint' })).status).toBe(403);
    expect((await f.fs.listSnapshots()).map(snapshot => snapshot.scope)).toEqual([f.shared.id]);
  });

  it('snapshot listings do not reveal private folder labels', async () => {
    const f = await fixture();
    await f.grant(f.shared.id, 'read');
    const visible = await f.fs.createSnapshot({ label: 'Shared history', scope: f.shared.id });
    const hidden = await f.fs.createSnapshot({ label: 'Confidential unreleased project', scope: f.privateFolder.id });
    const response = await SELF.fetch(`${f.base}/snapshots`, { headers: headers(f.token) });
    expect(response.status).toBe(200);
    const list = await response.json() as { id: string; label: string }[];
    expect(list.map(snapshot => snapshot.id)).toContain(visible.id);
    expect(list.map(snapshot => snapshot.id)).not.toContain(hidden.id);
    expect(JSON.stringify(list)).not.toContain('Confidential');
  });

  it('recursive restore cannot pull a live private file back into a formerly shared folder', async () => {
    const f = await fixture();
    await f.grant(f.shared.id, 'edit');
    await f.putContent(f.clip.id, 'original', 4);
    const ordinary = itemOf(await f.fs.createItem(f.shared.id, 'ordinary.mov', false, 0));
    await f.putContent(ordinary.id, 'ordinary-original', 2);
    const snap = await f.fs.createSnapshot({ scope: f.shared.id });
    await f.fs.renameItem(f.clip.id, { parent: f.privateFolder.id });
    await f.putContent(f.clip.id, 'private-current', 17);
    await f.putContent(ordinary.id, 'ordinary-current', 23);
    const response = await f.post(`/snapshots/${snap.id}/restore`, { path: f.shared.id, recursive: true });
    expect(response.status).toBe(200);
    const result = await response.json() as { restored: string[]; recreated: string[] };
    expect([...result.restored, ...result.recreated]).not.toContain(f.clip.id);
    const current = await f.fs.getItem(f.clip.id);
    expect(current?.parent).toBe(f.privateFolder.id);
    expect(current?.size).toBe(17);
    expect((await f.fs.getItem(ordinary.id))?.size).toBe(2);
  });

  it('live access after a move does not grant access to private historical content', async () => {
    const f = await fixture();
    await f.grant(f.shared.id, 'edit');
    await f.putContent(f.secret.id, 'private-before', 41);
    const snap = await f.fs.createSnapshot({ scope: 'root' });
    await f.fs.renameItem(f.secret.id, { parent: f.shared.id });
    await f.putContent(f.secret.id, 'public-now', 8);
    const response = await f.post(`/snapshots/${snap.id}/restore`, { path: f.secret.id });
    expect([403, 404]).toContain(response.status);
    expect((await f.fs.getItem(f.secret.id))?.parent).toBe(f.shared.id);
    expect((await f.fs.getItem(f.secret.id))?.size).toBe(8);
  });

  it('restoring an editable ancestor respects a read-only descendant override', async () => {
    const f = await fixture();
    await f.grant(f.shared.id, 'edit');
    await f.grant(f.clip.id, 'read');
    await f.putContent(f.clip.id, 'before', 4);
    const snap = await f.fs.createSnapshot({ scope: f.shared.id });
    await f.putContent(f.clip.id, 'after', 15);
    const response = await f.post(`/snapshots/${snap.id}/restore`, { path: f.shared.id, recursive: true });
    expect(response.status).toBe(200);
    const result = await response.json() as { restored: string[]; recreated: string[] };
    expect([...result.restored, ...result.recreated]).not.toContain(f.clip.id);
    expect((await f.fs.getItem(f.clip.id))?.size).toBe(15);
  });

  it('restoring a deleted inode does not resurrect its old direct grant', async () => {
    const f = await fixture();
    await f.grant(f.clip.id, 'read');
    await f.putContent(f.clip.id, 'original', 4);
    const snap = await f.fs.createSnapshot({ scope: f.shared.id });
    expect((await SELF.fetch(`${f.base}/items/${f.clip.id}`, { headers: headers(f.token) })).status).toBe(200);
    await f.fs.deleteItem(f.clip.id);
    expect((await SELF.fetch(`${f.base}/items/${f.clip.id}`, { headers: headers(f.token) })).status).toBe(404);
    const response = await f.post(`/snapshots/${snap.id}/restore`, { path: f.clip.id }, f.owner.token);
    expect(response.status).toBe(200);
    expect((await f.fs.getItem(f.clip.id))?.deleted).toBe(false);
    expect((await SELF.fetch(`${f.base}/items/${f.clip.id}`, { headers: headers(f.token) })).status).toBe(404);
  });
  it('mounted-view endpoints retain deleted content but fail closed after moves and revocation', async () => {
    const f = await fixture();
    await f.grant(f.shared.id, 'read');
    await f.putContent(f.clip.id, 'frozen-block', 4);
    const snapshot = await f.fs.createSnapshot({ scope: f.shared.id });
    const get = (suffix: string) => SELF.fetch(`${f.base}/snapshots/${snapshot.id}${suffix}`, { headers: headers(f.token) });
    expect((await get('/mount-roots')).status).toBe(200);
    expect((await get(`/items/${f.secret.id}`)).status).toBe(404);
    await f.fs.deleteItem(f.clip.id);
    expect((await get(`/items/${f.clip.id}`)).status).toBe(200);
    const blocks = await (await get(`/blocks/${f.clip.id}`)).json() as { blocks: { objectKey: string }[] };
    expect(blocks.blocks[0].objectKey).toContain('frozen-block');
    const list = await (await get(`/page?parent=${f.shared.id}`)).json() as { items: { id: string }[] };
    expect(list.items.map(item => item.id)).toContain(f.clip.id);
    const grants = await f.fs.listGrants(f.shared.id);
    await f.fs.revokeAccess(f.shared.id, 'user', grants[0].principalId);
    expect((await get('/mount-roots')).status).toBe(403);
    expect((await get(`/items/${f.clip.id}`)).status).toBe(404);
    expect((await get(`/blocks/${f.clip.id}`)).status).toBe(404);
    expect((await get(`/items/${f.clip.id}/streams`)).status).toBe(404);
  });

  it('snapshot presigning accepts only exact frozen keys and never writes or private history', async () => {
    const f = await fixture();
    await f.grant(f.shared.id, 'read');
    await f.putContent(f.clip.id, 'frozen-block', 4);
    const snapshot = await f.fs.createSnapshot({ scope: f.shared.id });
    const route = `/snapshots/${snapshot.id}/presign/batch`;
    const key = (await f.fs.getBlockMap(f.clip.id))[0].objectKey;
    const allowed = await f.post(route, { itemId: f.clip.id, keys: [{ key, method: 'GET' }] });
    expect(allowed.status).toBe(200);
    const ok = await allowed.json() as { results: { url?: string; error?: string }[] };
    expect(ok.results[0].url).toBeTruthy();
    expect((await f.post(route, { itemId: f.clip.id, keys: [{ key, method: 'PUT' }] })).status).toBe(400);
    const unknown = await (await f.post(route, { itemId: f.clip.id, keys: [{ key: key + '-not-frozen' }] })).json() as { results: { url?: string; error?: string }[] };
    expect(unknown.results[0].url).toBeUndefined();
    expect(unknown.results[0].error).toBe('object_not_in_snapshot');
    await f.fs.renameItem(f.clip.id, { parent: f.privateFolder.id });
    const moved = await (await f.post(route, { itemId: f.clip.id, keys: [{ key }] })).json() as { results: { url?: string; error?: string }[] };
    expect(moved.results[0].url).toBeUndefined();
    expect(moved.results[0].error).toBe('forbidden');
  });

});
