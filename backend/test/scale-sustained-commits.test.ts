// SPDX-License-Identifier: AGPL-3.0-or-later
import { runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Block, Item } from '../src/metadata/types';
import { NamespaceStore } from '../src/metadata/namespace';
import { blockFor, itemOf, makeOrg, manifestFor } from './multi-client-fixture';

const FILES = 20, COMMITS = 1500;

describe('sustained manifest traffic on one filespace', () => {
  it(`${COMMITS} sequential small commits across ${FILES} files stay bounded and the change feed stays consistent`, async () => {
    const o = await makeOrg(['busy'], 'scale');
    const stub = o.fs('busy');
    const items: Item[] = [];
    for (let i = 0; i < FILES; i++) items.push(itemOf(await stub.createItem('root', `f${i}.mov`, false, 0)));
    const versions = new Map(items.map(i => [i.id, i.version!]));
    const owner = { type: 'user' as const, id: o.owner.userId, orgRole: 'owner' as const };
    const startedAt = Date.now();
    let lastSeq = 0;
    for (let n = 0; n < COMMITS; n++) {
      const item = items[n % FILES];
      // Every commit replaces the file with a fresh 2-block manifest (one new object, one carried over).
      const blocks: Block[] = [{ ...blockFor(o.orgId, 'busy', n % 7, 'shared', 0), blockIdx: 0 }, { ...blockFor(o.orgId, 'busy', n, 'uniq', 4), blockIdx: 1 }];
      const res = await stub.setBlockMap(item.id, blocks, { expectedVersion: versions.get(item.id), principal: owner });
      if (!('version' in res)) throw new Error(`commit ${n} failed: ${JSON.stringify(res)}`);
      expect(res.version).toBe(versions.get(item.id)! + 1);
      expect(res.updatedSeq!).toBeGreaterThan(lastSeq); // sequence is strictly monotonic
      lastSeq = res.updatedSeq!;
      versions.set(item.id, res.version!);
    }
    const elapsed = Date.now() - startedAt;
    expect(elapsed).toBeLessThan(45_000);

    // Change feed: each changed item exactly once at its final version, any page size, consistent anchors.
    for (const limit of [7, 50, 1000]) {
      const seen = new Map<string, number>();
      let cursor: number | null = 0, pages = 0, anchor = -1;
      while (cursor !== null) {
        const page: { anchor: number; items: Item[]; cursor: number | null } = await stub.changesSince(cursor, limit);
        pages++;
        expect(page.anchor).toBeGreaterThanOrEqual(anchor); // anchor never goes backwards
        anchor = page.anchor;
        let prev = cursor;
        for (const it of page.items) {
          expect(it.updatedSeq!).toBeGreaterThan(prev); prev = it.updatedSeq!;
          expect(seen.has(it.id)).toBe(false);
          seen.set(it.id, it.version!);
        }
        if (page.cursor !== null) expect(page.cursor).toBe(prev);
        cursor = page.cursor;
        if (pages > 400) throw new Error('feed did not terminate');
      }
      expect([...seen.entries()].filter(([id]) => versions.has(id)).sort()).toEqual([...versions.entries()].sort());
      expect(anchor).toBe(lastSeq);
      expect((await stub.changesSince(anchor)).items).toEqual([]); // a client at the anchor sees nothing new
    }

    // Bookkeeping stays exact: live refcounts equal the live manifests; nothing negative; retained history is bounded by unique objects.
    await runInDurableObject(stub, (_i, state) => {
      const sql = state.storage.sql;
      const live = Number(sql.exec('SELECT COUNT(*) AS c FROM blocks;').one().c);
      expect(live).toBe(FILES * 2);
      expect(Number(sql.exec('SELECT SUM(refcount) AS s FROM block_refs;').one().s)).toBe(live);
      expect(Number(sql.exec('SELECT COUNT(*) AS c FROM block_refs WHERE refcount<0;').one().c)).toBe(0);
      expect(Number(sql.exec('SELECT COUNT(*) AS c FROM retained_blocks;').one().c)).toBeLessThanOrEqual(COMMITS * 2);
    });
  }, 55_000);

  it('per-commit SQL statement count is bounded and independent of history length', async () => {
    const o = await makeOrg(['stmts'], 'scale');
    const stub = o.fs('stmts');
    const item = itemOf(await stub.createItem('root', 'x.mov', false, 0));
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      let statements = 0;
      const counted = { exec: (...args: Parameters<SqlStorage['exec']>) => { statements++; return sql.exec(...args); } } as SqlStorage;
      const ns = new NamespaceStore(counted);
      const perCommit: number[] = [];
      let version = item.version!;
      for (let n = 0; n < 300; n++) {
        statements = 0;
        const updated = state.storage.transactionSync(() => ns.setBlockMap(item.id, [blockFor(o.orgId, 'stmts', n, 'h')], { expectedVersion: version }));
        version = updated.version!;
        perCommit.push(statements);
      }
      expect(Math.max(...perCommit)).toBeLessThan(25);
      // Late commits cost the same as early ones: no O(history) scans.
      expect(Math.max(...perCommit.slice(-50))).toBeLessThanOrEqual(Math.max(...perCommit.slice(0, 50)));
    });
  });

  it('a 1,024-block manifest replace is bounded in SQL statements and round-trips through the gateway', async () => {
    const o = await makeOrg(['big'], 'scale');
    const stub = o.fs('big');
    const item = itemOf(await stub.createItem('root', 'big.mov', false, 0));
    const first = manifestFor(o.orgId, 'big', 'first', 1024), second = manifestFor(o.orgId, 'big', 'second', 1024);
    const put = (blocks: Block[], expectedVersion: number) => o.call(o.owner.token, 'big', 'PUT', `/blocks/${item.id}`, { blocks, expectedVersion });
    const r1 = await put(first, item.version!);
    expect(r1.status).toBe(200);
    const v1 = (await r1.json() as Item).version!;
    // Statement counting on the replace (all-new blocks vs. old 1,024 blocks released).
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql; let statements = 0;
      const counted = { exec: (...args: Parameters<SqlStorage['exec']>) => { statements++; return sql.exec(...args); } } as SqlStorage;
      const ns = new NamespaceStore(counted);
      const replaced = state.storage.transactionSync(() => ns.setBlockMap(item.id, second, { expectedVersion: v1 }));
      expect(replaced.version).toBe(v1 + 1);
      expect(statements).toBeLessThan(50);
      expect(Number(sql.exec('SELECT COUNT(*) AS c FROM blocks WHERE item_id=?;', item.id).one().c)).toBe(1024);
      expect(Number(sql.exec('SELECT SUM(refcount) AS s FROM block_refs;').one().s)).toBe(1024);
    });
    const read = await o.call(o.owner.token, 'big', 'GET', `/blocks/${item.id}`);
    expect(await read.json()).toEqual(second);
    expect((await stub.getItem(item.id))!.size).toBe(1024 * 4);
  });
});
