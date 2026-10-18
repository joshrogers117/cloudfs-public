// SPDX-License-Identifier: AGPL-3.0-or-later
// snapshot-deltas.test.ts — audit B19: copy-on-write snapshot deltas. A snapshot freezes only the
// CHANGE vs. its base (the prior snapshot of the same scope) and inherits the rest by chain
// resolution. These run against the real DO SqlStorage so we can assert the actual frozen-row
// counts (the storage win) AND the resolved as-of correctness (no behavior regression).
import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { filespaceDoName } from "../src/security/auth";
import { NamespaceStore } from "../src/metadata/namespace";
import { SnapshotStore } from "../src/metadata/snapshots";
import type { Block } from "../src/metadata/types";

const ORG = "org-b19";

async function withStores<T>(
  space: string,
  fn: (s: { sql: SqlStorage; ns: NamespaceStore; snaps: SnapshotStore }) => T | Promise<T>,
): Promise<T> {
  const stub = (env as any).FILESPACE.get((env as any).FILESPACE.idFromName(filespaceDoName(ORG, space)));
  return runInDurableObject(stub, async (_inst: unknown, state: DurableObjectState) => {
    const sql = state.storage.sql;
    const ns = new NamespaceStore(sql);
    const snaps = new SnapshotStore(sql, () => ns.currentSeq(), ns);
    return fn({ sql, ns, snaps });
  });
}

const block = (key: string, hash: string, len = 100): Block => ({
  chunkIdx: 0, blockIdx: 0, blockHash: hash, objectKey: key, offset: 0, length: len,
});
const snapItemRows = (sql: SqlStorage, id: string) =>
  Number(sql.exec(`SELECT COUNT(*) AS c FROM snapshot_items WHERE snapshot_id=?;`, id).one().c);

describe("B19: a snapshot freezes only the DELTA vs. its base", () => {
  it("the SECOND snapshot stores only the changed item (not the whole tree)", async () => {
    await withStores("b19-delta", ({ sql, ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "root" });
      ns.put("root", "dir", true, 0, { id: "root/dir" });
      ns.put("root/dir", "a", false, 1, { id: "root/dir/a" });
      ns.put("root/dir", "b", false, 1, { id: "root/dir/b" });
      ns.put("root/dir", "c", false, 1, { id: "root/dir/c" });

      // S1 (no base) freezes the full scope (a handful of rows — exact count depends on whether the
      // DO seeded demo fixtures; we only care that it's the FULL set).
      snaps.create({ id: "S1", scope: "root" });
      const fullRows = snapItemRows(sql, "S1");
      expect(fullRows).toBeGreaterThanOrEqual(5); // at least root+dir+a+b+c

      // Change ONLY `a`, then S2 (base S1) freezes JUST the delta — far fewer rows than the full copy.
      ns.put("root/dir", "a", false, 99, { id: "root/dir/a" });
      snaps.create({ id: "S2", scope: "root" });
      const deltaRows = snapItemRows(sql, "S2");
      expect(deltaRows).toBeLessThan(fullRows);   // the storage win: a delta, not a full copy
      expect(deltaRows).toBeGreaterThanOrEqual(1); // at least the changed `a`
      // Concretely: a delta of one changed file should be a small constant, not O(tree).
      expect(deltaRows).toBeLessThanOrEqual(2);
    });
  });

  it("chain resolution reconstructs the correct as-of state for each snapshot", async () => {
    await withStores("b19-resolve", ({ ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "root" });
      ns.put("root", "dir", true, 0, { id: "root/dir" });
      ns.put("root/dir", "keep.mov", false, 10, { id: "root/dir/keep.mov" });

      snaps.create({ id: "S1", scope: "root" });
      // After S1: add a new file + edit keep.mov.
      ns.put("root/dir", "new.mov", false, 5, { id: "root/dir/new.mov" });
      ns.put("root/dir", "keep.mov", false, 20, { id: "root/dir/keep.mov" });
      snaps.create({ id: "S2", scope: "root" });

      // S1 as-of: dir has keep.mov (size 10), NO new.mov.
      const s1 = snaps.listAt("S1", "root/dir").map((i) => `${i.name}:${i.size}`).sort();
      expect(s1).toEqual(["keep.mov:10"]);
      // S2 as-of: dir has keep.mov (size 20) + new.mov (inherits dir from S1, overlays the edits).
      const s2 = snaps.listAt("S2", "root/dir").map((i) => `${i.name}:${i.size}`).sort();
      expect(s2).toEqual(["keep.mov:20", "new.mov:5"]);
    });
  });

  it("records a delta-TOMBSTONE so a delete after the base is reflected as-of the snapshot", async () => {
    await withStores("b19-tombstone", ({ ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "root" });
      ns.put("root", "gone.mov", false, 1, { id: "root/gone.mov" });
      ns.put("root", "stays.mov", false, 1, { id: "root/stays.mov" });

      snaps.create({ id: "S1", scope: "root" });
      // Delete gone.mov, then S2.
      ns.remove("root/gone.mov");
      snaps.create({ id: "S2", scope: "root" });

      const s1Names = snaps.listAt("S1", "root").map((i) => i.name);
      expect(s1Names).toContain("gone.mov"); // present as-of S1
      const s2Names = snaps.listAt("S2", "root").map((i) => i.name);
      expect(s2Names).not.toContain("gone.mov"); // absent as-of S2 (delta-tombstone)
      expect(s2Names).toContain("stays.mov");
    });
  });

  it("restore from a DELTA snapshot brings back the as-of content (chain-resolved)", async () => {
    await withStores("b19-restore", ({ ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "root" });
      ns.setBlockMap("root/cut.mov", [block("k/v1", "v1", 100)], { upsert: { parent: "root", name: "cut.mov" } });
      snaps.create({ id: "S1", scope: "root" });
      // Change something ELSE so S2 is a delta that does NOT re-freeze cut.mov (it inherits it).
      ns.setBlockMap("root/other.mov", [block("k/o", "o", 5)], { upsert: { parent: "root", name: "other.mov" } });
      snaps.create({ id: "S2", scope: "root" });
      // Now overwrite cut.mov live → v2.
      ns.setBlockMap("root/cut.mov", [block("k/v2", "v2", 200)]);

      // Restore cut.mov to S2 — even though S2 inherited cut.mov from S1 (didn't re-freeze it).
      const res = snaps.restore("S2", "root/cut.mov");
      expect(res.restored).toContain("root/cut.mov");
      const map = ns.getBlockMap("root/cut.mov");
      expect(map[0].blockHash).toBe("v1"); // restored to the inherited (S1) content
    });
  });

  it("deleting a BASE snapshot preserves the child's resolved view (chain-preserving delete)", async () => {
    await withStores("b19-delete-base", ({ ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "root" });
      ns.put("root", "dir", true, 0, { id: "root/dir" });
      ns.put("root/dir", "a.mov", false, 1, { id: "root/dir/a.mov" });
      ns.put("root/dir", "b.mov", false, 1, { id: "root/dir/b.mov" });
      snaps.create({ id: "BASE", scope: "root" });
      // Child delta: change only a.mov.
      ns.put("root/dir", "a.mov", false, 9, { id: "root/dir/a.mov" });
      snaps.create({ id: "CHILD", scope: "root" });

      // CHILD's resolved view BEFORE deleting BASE: a.mov(9) inherits dir + b.mov(1) from BASE.
      const before = snaps.listAt("CHILD", "root/dir").map((i) => `${i.name}:${i.size}`).sort();
      expect(before).toEqual(["a.mov:9", "b.mov:1"]);

      // Delete the BASE — CHILD must still resolve b.mov (inherited) via chain-preservation.
      snaps.deleteSnapshot("BASE");
      expect(snaps.get("BASE")).toBeNull();
      const after = snaps.listAt("CHILD", "root/dir").map((i) => `${i.name}:${i.size}`).sort();
      expect(after).toEqual(before); // byte-identical resolved view
    });
  });
});
