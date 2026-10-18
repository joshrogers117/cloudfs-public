// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import type { Block, Item } from '../src/metadata/types';
import { sameBlockManifest } from '../src/metadata/block-manifest';
import { itemOf, makeOrg, manifestFor } from './multi-client-fixture';

describe('readers concurrent with a writer never observe a partial manifest', () => {
  it('item reads, listings and block maps are each exactly one committed version, monotonic per reader', async () => {
    const o = await makeOrg(['live'], 'scale');
    const stub = o.fs('live');
    const item = itemOf(await stub.createItem('root', 'timeline.mov', false, 0));
    const other = itemOf(await stub.createItem('root', 'sibling.mov', false, 0));
    const COMMITS = 15;
    // Commit k has k+1 blocks (so every version has a distinct size) and its own object keys.
    const byVersion = new Map<number, Block[]>([[item.version!, []]]);
    let writerDone = false;
    const violations: string[] = [];

    const writer = (async () => {
      let version = item.version!;
      for (let k = 0; k < COMMITS; k++) {
        const blocks = manifestFor(o.orgId, 'live', `v${k}`, k + 1);
        // Publish the expectation BEFORE the commit so a reader can never see an unknown version.
        byVersion.set(version + 1, blocks);
        const res = await o.call(o.owner.token, 'live', 'PUT', `/blocks/${item.id}`, { blocks, expectedVersion: version });
        if (res.status !== 200) { violations.push(`commit ${k} -> ${res.status}`); break; }
        version = (await res.json() as Item).version!;
      }
      writerDone = true;
    })();

    const sizeOf = (blocks: Block[]) => blocks.reduce((n, b) => n + b.length, 0);
    const reader = async (id: number) => {
      let last = -1, reads = 0;
      while (!writerDone || reads < 3) {
        reads++;
        await new Promise(r => setTimeout(r, 15)); // paced readers: interleave with, not starve, the writer
        const [itemRes, mapRes, listRes] = await Promise.all([
          o.call(o.owner.token, 'live', 'GET', `/items/${item.id}`),
          o.call(o.owner.token, 'live', 'GET', `/blocks/${item.id}`),
          o.call(o.owner.token, 'live', 'GET', '/items?parent=root'),
        ]);
        const seen = await itemRes.json() as Item;
        const map = await mapRes.json() as Block[];
        const listed = ((await listRes.json()) as { items: Item[] }).items.find(i => i.id === item.id)!;
        for (const view of [seen, listed]) {
          const expected = byVersion.get(view.version!);
          if (!expected) violations.push(`reader ${id}: unknown version ${view.version}`);
          else if (view.size !== sizeOf(expected)) violations.push(`reader ${id}: version ${view.version} has size ${view.size}, expected ${sizeOf(expected)}`);
        }
        // The block map is some complete committed manifest: contiguous, and equal to the one recorded for its length.
        const candidate = [...byVersion.values()].find(m => m.length === map.length);
        if (!candidate || !sameBlockManifest(candidate, map)) violations.push(`reader ${id}: partial/unknown manifest of ${map.length} blocks`);
        if (seen.version! < last) violations.push(`reader ${id}: version went backwards ${last} -> ${seen.version}`);
        last = Math.max(last, seen.version!);
        if (listed.version! < seen.version! - COMMITS) violations.push('listing wildly stale');
      }
      return reads;
    };
    const reads = await Promise.all([writer, ...Array.from({ length: 4 }, (_, i) => reader(i))]);
    expect(violations).toEqual([]);
    expect(reads.slice(1).every(n => (n as number) >= 3)).toBe(true);
    // The untouched sibling never changed, and the final state is the last commit.
    expect((await stub.getItem(other.id))!.version).toBe(other.version);
    expect(await stub.getBlockMap(item.id)).toEqual(manifestFor(o.orgId, 'live', `v${COMMITS - 1}`, COMMITS));
  }, 55_000);
});
