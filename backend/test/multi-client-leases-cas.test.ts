// SPDX-License-Identifier: AGPL-3.0-or-later
import { runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { blockFor, itemOf, makeOrg } from './multi-client-fixture';

async function fixture() {
  const o = await makeOrg(['team']);
  const stub = o.fs('team');
  const item = itemOf(await stub.createItem('root', 'project.mov', false, 0));
  const a = crypto.randomUUID(), b = crypto.randomUUID();
  const as = (client: string) => (method: string, path: string, body?: unknown) => o.call(o.owner.token, 'team', method, path, body, client);
  const acquire = async (client: string) =>
    (await as(client)('POST', '/locks', { path: item.id, ttlMs: 60_000 })).json() as Promise<{ granted: boolean; fence: number; heldBy?: string }>;
  const expireLease = (when = Date.now() - 1) => runInDurableObject(stub, (_i, state) => {
    state.storage.sql.exec('UPDATE locks SET expires_at=? WHERE path=?;', when, item.id);
  });
  return { ...o, stub, item, a, b, as, acquire, expireLease };
}

describe('two clients of one account: lease expiry and fencing', () => {
  it('refuses a second writer while held, grants after expiry, and rejects the zombie writer by fence', async () => {
    const f = await fixture();
    const first = await f.acquire(f.a);
    expect(first.granted).toBe(true);
    const denied = await f.acquire(f.b);
    expect(denied).toMatchObject({ granted: false, reason: 'held-by-other' });
    expect(denied.fence).toBeUndefined();

    await f.expireLease();
    const second = await f.acquire(f.b);
    expect(second.granted).toBe(true);
    expect(second.fence).toBeGreaterThan(first.fence);

    // Zombie A (old fence) is refused with the typed lease conflict, manifest unchanged.
    const block = blockFor(f.orgId, 'team', 0);
    const zombie = await f.as(f.a)('PUT', `/blocks/${f.item.id}`, { blocks: [block], expectedVersion: f.item.version, fence: first.fence });
    expect(zombie.status).toBe(409);
    expect(await zombie.json()).toMatchObject({ error: 'locked', locked: true, conflict: true });
    expect(await f.stub.getBlockMap(f.item.id)).toEqual([]);
    // Even presenting B's fence, A cannot commit: the fence is bound to its owner.
    expect((await f.as(f.a)('PUT', `/blocks/${f.item.id}`, { blocks: [block], fence: second.fence })).status).toBe(409);

    // A's delayed release after expiry must not drop B's lease.
    const lateRelease = await (await f.as(f.a)('DELETE', `/locks?path=${f.item.id}&fence=${first.fence}`)).json();
    expect(lateRelease).toMatchObject({ released: false });
    expect(await f.stub.validateFence(f.item.id, second.fence)).toBe(true);
    expect((await f.acquire(f.a)).granted).toBe(false);

    // The live owner commits with its live fence.
    const ok = await f.as(f.b)('PUT', `/blocks/${f.item.id}`, { blocks: [block], expectedVersion: f.item.version, fence: second.fence });
    expect(ok.status).toBe(200);
    expect(await f.stub.getBlockMap(f.item.id)).toEqual([block]);
  });

  it('an expired-but-unreplaced lease still rejects its old fence, and renew keeps the fence', async () => {
    const f = await fixture();
    const lease = await f.acquire(f.a);
    const renewed = await (await f.as(f.a)('POST', '/locks', { path: f.item.id, renew: true, fence: lease.fence, ttlMs: 30_000 })).json() as { granted: boolean; fence: number };
    expect(renewed).toMatchObject({ granted: true, fence: lease.fence });
    await f.expireLease();
    const block = blockFor(f.orgId, 'team', 1);
    const late = await f.as(f.a)('PUT', `/blocks/${f.item.id}`, { blocks: [block], fence: lease.fence });
    expect(late.status).toBe(409);
    expect((await late.json() as { reason: string }).reason).toBe('fence-stale');
    // Renewing an expired lease is refused rather than resurrecting it.
    const dead = await (await f.as(f.a)('POST', '/locks', { path: f.item.id, renew: true, fence: lease.fence })).json();
    expect(dead).toMatchObject({ granted: false });
    // The alarm-driven reaper removes expired rows without disturbing live ones.
    const other = itemOf(await f.stub.createItem('root', 'other.mov', false, 0));
    expect((await (await f.as(f.b)('POST', '/locks', { path: other.id, ttlMs: 60_000 })).json() as { granted: boolean }).granted).toBe(true);
    await runInDurableObject(f.stub, (_i, state) => {
      state.storage.sql.exec('UPDATE locks SET expires_at=? WHERE path=?;', Date.now() - 5, f.item.id);
    });
    await runInDurableObject(f.stub, i => i.alarm());
    await runInDurableObject(f.stub, (_i, state) => {
      const rows = state.storage.sql.exec('SELECT path FROM locks;').toArray().map(r => r.path);
      expect(rows).toEqual([other.id]);
    });
  });
});

describe('version CAS across clients', () => {
  it('exactly one of two same-version commits wins; an exact retry is idempotent; a changed stale retry conflicts', async () => {
    const f = await fixture();
    const m1 = [blockFor(f.orgId, 'team', 10)], m2 = [blockFor(f.orgId, 'team', 20)];
    const put = (client: string, blocks: unknown) => f.as(client)('PUT', `/blocks/${f.item.id}`, { blocks, expectedVersion: f.item.version });
    const [r1, r2] = await Promise.all([put(f.a, m1), put(f.b, m2)]);
    expect([r1.status, r2.status].sort()).toEqual([200, 409]);
    const [win, lose, winner] = r1.status === 200 ? [r1, r2, m1] : [r2, r1, m2];
    const loser = r1.status === 200 ? m2 : m1;
    const committed = await win.json() as { version: number };
    expect(committed.version).toBe(f.item.version! + 1);
    expect(await lose.json()).toMatchObject({ conflict: true, expected: f.item.version, actual: committed.version });
    expect(await f.stub.getBlockMap(f.item.id)).toEqual(winner);

    // Lost-reply retry from either client: same CAS + same manifest -> same item, no bump.
    for (const client of [f.a, f.b]) {
      const retry = await put(client, winner);
      expect(retry.status).toBe(200);
      expect((await retry.json() as { version: number }).version).toBe(committed.version);
    }
    expect((await f.stub.getItem(f.item.id))!.version).toBe(committed.version);
    // The loser's different manifest on the stale CAS still conflicts, and nothing changes.
    expect((await put(f.a, loser)).status).toBe(409);
    expect(await f.stub.getBlockMap(f.item.id)).toEqual(winner);
    // Rebasing on the new version succeeds and bumps exactly once.
    const rebased = await f.as(f.a)('PUT', `/blocks/${f.item.id}`, { blocks: loser, expectedVersion: committed.version });
    expect(rebased.status).toBe(200);
    expect((await rebased.json() as { version: number }).version).toBe(committed.version + 1);
  });
});
