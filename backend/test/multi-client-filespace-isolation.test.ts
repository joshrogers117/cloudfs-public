// SPDX-License-Identifier: AGPL-3.0-or-later
import { runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { principalKey } from '../src/security/ratelimit';
import { itemOf, makeOrg, manifestFor } from './multi-client-fixture';

async function fixture() {
  const o = await makeOrg(['alpha', 'beta'], 'mcspace');
  const a = o.fs('alpha'), b = o.fs('beta');
  const fileA = itemOf(await a.createItem('root', 'a.mov', false, 0));
  const fileB = itemOf(await b.createItem('root', 'b.mov', false, 0));
  const member = await o.user('Member');
  return { ...o, a, b, fileA, fileB, member, memberToken: await o.tokenFor(member.id) };
}

describe('two filespaces in one organization are independent', () => {
  it('a token bound to one space cannot act on the other, on any route family', async () => {
    const f = await fixture();
    const scoped = await f.tokenFor(f.owner.userId, { spaceId: 'alpha', scopes: ['fs:read', 'fs:write', 'fs:lock', 'fs:admin', 'snapshot:read'] });
    expect((await f.call(scoped, 'alpha', 'GET', `/items/${f.fileA.id}`)).status).toBe(200);
    const key = `blocks/${f.orgId}::beta/x`;
    const attempts: [string, string, unknown?][] = [
      ['GET', `/items/${f.fileB.id}`], ['GET', '/items?parent=root'], ['POST', '/items', { name: 'x', isDir: false }],
      ['POST', '/locks', { path: f.fileB.id }], ['GET', `/locks?path=${f.fileB.id}`], ['DELETE', `/locks?path=${f.fileB.id}`],
      ['PUT', `/blocks/${f.fileB.id}`, { blocks: manifestFor(f.orgId, 'beta', 'x') }], ['GET', `/blocks/${f.fileB.id}`],
      ['POST', '/presign', { key, method: 'PUT', itemId: f.fileB.id }], ['POST', '/presign', { key, method: 'GET' }],
      ['GET', '/changes?since=0'],
    ];
    for (const [method, path, body] of attempts) {
      const res = await f.call(scoped, 'beta', method, path, body);
      expect(res.status, `${method} ${path}`).toBe(403);
      await res.arrayBuffer();
    }
    expect(await f.b.getBlockMap(f.fileB.id)).toEqual([]);
    expect((await f.b.getItem(f.fileB.id))!.version).toBe(f.fileB.version);
  });

  it('locks, grants and the change feed of one space never leak into the other', async () => {
    const f = await fixture();
    const c1 = crypto.randomUUID(), c2 = crypto.randomUUID();
    const lease = await (await f.call(f.owner.token, 'alpha', 'POST', '/locks', { path: f.fileA.id }, c1)).json() as { granted: boolean; fence: number };
    expect(lease.granted).toBe(true);
    // Another client in the OTHER space gets its own independent lease on its own inode.
    const other = await (await f.call(f.owner.token, 'beta', 'POST', '/locks', { path: f.fileB.id }, c2)).json() as { granted: boolean; fence: number };
    expect(other.granted).toBe(true);
    // The same client may commit to beta while c1 holds alpha; c2 is still blocked in beta only by its own lease.
    expect((await f.call(f.owner.token, 'beta', 'PUT', `/blocks/${f.fileB.id}`, { blocks: manifestFor(f.orgId, 'beta', 'b1'), fence: other.fence }, c2)).status).toBe(200);
    expect((await f.call(f.owner.token, 'beta', 'PUT', `/blocks/${f.fileB.id}`, { blocks: manifestFor(f.orgId, 'beta', 'b2') }, c1)).status).toBe(409);
    // Alpha's lease and manifest are untouched by beta traffic.
    expect(await f.a.validateFence(f.fileA.id, lease.fence)).toBe(true);
    expect(await f.a.getBlockMap(f.fileA.id)).toEqual([]);
    // A lease in alpha on an inode id that exists only in beta is not a beta lease.
    await runInDurableObject(f.a, (_i, state) => {
      expect(state.storage.sql.exec('SELECT path FROM locks;').toArray().map(r => r.path)).toEqual([f.fileA.id]);
    });

    // Grants: edit in alpha confers nothing in beta.
    await f.a.grantAccess({ spaceId: 'alpha', inodeId: f.fileA.id, principalType: 'user', principalId: f.member.id, level: 'edit' }, f.owner.userId);
    expect((await f.call(f.memberToken, 'alpha', 'GET', `/items/${f.fileA.id}`)).status).toBe(200);
    expect((await f.call(f.memberToken, 'beta', 'GET', `/items/${f.fileB.id}`)).status).toBe(404);
    expect((await f.call(f.memberToken, 'beta', 'POST', '/locks', { path: f.fileB.id })).status).toBeGreaterThanOrEqual(403);
    expect((await f.call(f.memberToken, 'beta', 'PUT', `/blocks/${f.fileB.id}`, { blocks: manifestFor(f.orgId, 'beta', 'm') })).status).toBe(403);
    expect((await f.b.checkAccess({ type: 'user', id: f.member.id }, f.fileB.id, 'read')).allow).toBe(false);
    expect(await f.b.listGrants()).toEqual([]);

    // Change feeds are per space.
    const feed = async (space: string) => (await (await f.call(f.owner.token, space, 'GET', '/changes?since=0')).json() as { items: { id: string }[] }).items.map(i => i.id);
    expect(await feed('alpha')).toContain(f.fileA.id);
    expect(await feed('alpha')).not.toContain(f.fileB.id);
    expect(await feed('beta')).toContain(f.fileB.id);
    expect(await feed('beta')).not.toContain(f.fileA.id);
  });

  it('rate-limit buckets are per filespace and per class', async () => {
    const f = await fixture();
    const key = principalKey(f.member.id);
    const capacity = (await f.a.rateLimit('mutation', key, 0)).limit;
    expect((await f.a.rateLimit('mutation', key, capacity)).allowed).toBe(true);
    expect((await f.a.rateLimit('mutation', key, 1)).allowed).toBe(false);
    expect((await f.b.rateLimit('mutation', key, capacity)).allowed).toBe(true);
    expect((await f.a.rateLimit('presign', key, 1)).allowed).toBe(true);
    // Observable through HTTP: the exhausted space answers 429 + Retry-After, the other one serves.
    await f.a.grantAccess({ spaceId: 'alpha', inodeId: 'root', principalType: 'user', principalId: f.member.id, level: 'edit' }, f.owner.userId);
    await f.b.grantAccess({ spaceId: 'beta', inodeId: 'root', principalType: 'user', principalId: f.member.id, level: 'edit' }, f.owner.userId);
    const slow = await f.call(f.memberToken, 'alpha', 'POST', '/items', { name: 'denied', isDir: false });
    expect(slow.status).toBe(429);
    expect(slow.headers.get('retry-after')).toBeTruthy();
    await slow.arrayBuffer();
    // beta's bucket was filled by the direct call above; use a fresh principal to prove independence.
    const fresh = await f.user('Fresh');
    const freshToken = await f.tokenFor(fresh.id);
    await f.b.grantAccess({ spaceId: 'beta', inodeId: 'root', principalType: 'user', principalId: fresh.id, level: 'edit' }, f.owner.userId);
    expect((await f.call(freshToken, 'beta', 'POST', '/items', { name: 'ok', isDir: false })).status).toBe(201);
  });

  it('upload receipts and manifest verification state are not shared between spaces', async () => {
    const f = await fixture();
    const [block] = manifestFor(f.orgId, 'alpha', 'shared-bytes');
    const objectKey = block.objectKey;
    const identity = 'test-storage';
    const principal = { type: 'user' as const, id: f.owner.userId, orgRole: 'owner' as const };
    for (const stub of [f.a, f.b]) await runInDurableObject(stub, i => { (i as unknown as { env: Record<string, string> }).env.STORAGE_VERIFY_UPLOADS = '1'; });
    try {
      expect(await f.a.recordVerifiedObjects([{ objectKey, blockHash: block.blockHash, length: 4, ciphertextSize: 73 }], identity)).toEqual({ verified: 1 });
      expect(await f.a.unverifiedObjects([block], identity)).toEqual([]);
      expect(await f.b.unverifiedObjects([block], identity)).toHaveLength(1);
      const okA = await f.a.setBlockMap(f.fileA.id, [block], { principal, storageIdentity: identity });
      expect(okA).toMatchObject({ id: f.fileA.id });
      const refused = await f.b.setBlockMap(f.fileB.id, [block], { principal, storageIdentity: identity });
      expect(refused).toMatchObject({ invalidManifest: true });
      expect(await f.b.getBlockMap(f.fileB.id)).toEqual([]);
      // Reference counts and known-object catalogs are per space too.
      await runInDurableObject(f.b, (_i, state) => {
        expect(state.storage.sql.exec('SELECT COUNT(*) AS c FROM block_refs;').one().c).toBe(0);
        expect(state.storage.sql.exec('SELECT COUNT(*) AS c FROM known_objects;').one().c).toBe(0);
      });
    } finally {
      for (const stub of [f.a, f.b]) await runInDurableObject(stub, i => { (i as unknown as { env: Record<string, string> }).env.STORAGE_VERIFY_UPLOADS = '0'; });
    }
  });
});
