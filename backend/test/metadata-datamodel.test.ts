// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { filespaceDoName } from "../src/security/auth";
import { NamespaceStore } from "../src/metadata/namespace";
import { SnapshotStore } from "../src/metadata/snapshots";
import type { Block } from "../src/metadata/types";

// Regression tests for the 4 metadata-layer code-review findings:
//   1) snapshot freeze() uses set-based INSERT...SELECT (semantics unchanged)
//   2) restore bumps version exactly once + emits one change-feed entry per file
//   3) restore returns correct content + newerThanSnapshot (no N+1, set-based diff)
//   4) recursive subtree delete decrements block refcounts correctly (set-based)
//
// These drive NamespaceStore/SnapshotStore directly against a real, migrated DO
// SqlStorage (the FilespaceDO migrates on init), so we can assert on raw rows,
// versions, the change feed (changesSince) and refcounts with full precision.

const ORG = "org-datamodel";

/// A migrated DO SqlStorage + fresh stores built on it. Each test gets its own
/// space (own DO instance) so state never bleeds between tests.
async function withStores<T>(
  space: string,
  fn: (s: { sql: SqlStorage; ns: NamespaceStore; snaps: SnapshotStore }) => T | Promise<T>,
): Promise<T> {
  const stub = (env as any).FILESPACE.get(
    (env as any).FILESPACE.idFromName(filespaceDoName(ORG, space)),
  );
  return runInDurableObject(stub, async (_inst: unknown, state: DurableObjectState) => {
    const sql = state.storage.sql;
    const ns = new NamespaceStore(sql);
    const snaps = new SnapshotStore(sql, () => ns.currentSeq(), ns);
    return fn({ sql, ns, snaps });
  });
}

const block = (objectKey: string, hash: string, length = 100, idx = 0): Block => ({
  chunkIdx: 0,
  blockIdx: idx,
  blockHash: hash,
  objectKey,
  offset: idx * length,
  length,
});

function refcount(sql: SqlStorage, hash: string): number {
  const r = sql.exec(`SELECT refcount FROM block_refs WHERE block_hash=?;`, hash).toArray()[0];
  return r ? Number(r.refcount) : 0;
}

// ---------------------------------------------------------------------------
describe("finding #1 — snapshot freeze copies items + blocks (set-based, semantics unchanged)", () => {
  it("copies every live item and its block manifest into the snapshot_* tables", async () => {
    await withStores("snap-freeze", ({ sql, ns, snaps }) => {
      // Build a small tree: root/dir/{fileA, fileB}, root/file0
      ns.put(null, "root", true, 0, { id: "r" });
      ns.put("r", "dir", true, 0, { id: "r/dir" });
      ns.put("r/dir", "fileA", false, 0, { id: "r/dir/fileA" });
      ns.put("r/dir", "fileB", false, 0, { id: "r/dir/fileB" });
      ns.put("r", "file0", false, 0, { id: "r/file0" });

      ns.setBlockMap("r/dir/fileA", [block("k/a0", "ha0"), block("k/a1", "ha1", 100, 1)]);
      ns.setBlockMap("r/dir/fileB", [block("k/b0", "hb0")]);
      ns.setBlockMap("r/file0", [block("k/f0", "hf0")]);

      snaps.create({ id: "S1", scope: "r" });

      // Every live inode under the scope is frozen (5 items: r, dir, A, B, file0).
      const items = sql
        .exec(`SELECT item_id FROM snapshot_items WHERE snapshot_id='S1' ORDER BY item_id;`)
        .toArray()
        .map((x) => String(x.item_id));
      expect(items).toEqual(["r", "r/dir", "r/dir/fileA", "r/dir/fileB", "r/file0"]);

      // Frozen block rows mirror the live manifests exactly (4 blocks total).
      const fa = sql
        .exec(`SELECT block_hash,object_key,offset,length FROM snapshot_blocks
               WHERE snapshot_id='S1' AND item_id='r/dir/fileA' ORDER BY block_idx;`)
        .toArray();
      expect(fa.map((b) => String(b.block_hash))).toEqual(["ha0", "ha1"]);
      expect(fa.map((b) => Number(b.length))).toEqual([100, 100]);

      const totalBlocks = Number(
        sql.exec(`SELECT COUNT(*) AS c FROM snapshot_blocks WHERE snapshot_id='S1';`).one().c,
      );
      expect(totalBlocks).toBe(4);

      // Frozen item rows mirror the live content_version (the as-of pointer).
      const liveA = ns.getItem("r/dir/fileA")!;
      const frozenA = sql
        .exec(`SELECT content_version,size FROM snapshot_items WHERE snapshot_id='S1' AND item_id='r/dir/fileA';`)
        .one();
      expect(String(frozenA.content_version)).toBe(liveA.contentVersion);
      expect(Number(frozenA.size)).toBe(liveA.size); // 200
    });
  });

  it("excludes tombstoned items and is idempotent across re-freeze", async () => {
    await withStores("snap-freeze-tomb", ({ sql, ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "r" });
      ns.put("r", "keep", false, 10, { id: "r/keep" });
      ns.put("r", "gone", false, 10, { id: "r/gone" });
      ns.remove("r/gone");

      snaps.create({ id: "S1", scope: "r" });
      snaps.create({ id: "S1", scope: "r" }); // re-freeze same id (idempotent / REPLACE)

      const items = sql
        .exec(`SELECT item_id FROM snapshot_items WHERE snapshot_id='S1' ORDER BY item_id;`)
        .toArray()
        .map((x) => String(x.item_id));
      expect(items).toEqual(["r", "r/keep"]); // tombstoned 'gone' not frozen
    });
  });
});

// ---------------------------------------------------------------------------
describe("finding #2 — restore bumps version once + one change-feed entry per file", () => {
  it("a file restore advances version by exactly 1 and emits exactly one feed entry", async () => {
    await withStores("restore-once", ({ ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "r" });
      const created = ns.put("r", "f", false, 0, { id: "r/f" });
      const afterBlocks = ns.setBlockMap("r/f", [block("k/v1", "hv1")]);
      const versionBeforeSnap = afterBlocks.version; // put(=v1) + setBlockMap(=v2)
      expect(versionBeforeSnap).toBe(created.version + 1);

      snaps.create({ id: "S1", scope: "r" });

      // Mutate the file after the snapshot (new content).
      const mutated = ns.setBlockMap("r/f", [block("k/v2", "hv2")]);
      expect(mutated.version).toBe(versionBeforeSnap + 1);

      // Anchor the change-feed cursor right before the restore.
      const anchor = ns.currentSeq();
      const res = snaps.restore("S1", "r/f");
      expect(res.restored).toEqual(["r/f"]);
      expect(res.notFound).toBeUndefined();

      // Version bumped by exactly 1 (the bug double-bumped via put()+setBlockMap()).
      const after = ns.getItem("r/f")!;
      expect(after.version).toBe(mutated.version + 1);

      // Exactly one change-feed entry for this inode since the anchor (the bug
      // surfaced two mutations: a put() then a setBlockMap()).
      const changed = ns.changesSince(anchor).items.filter((i) => i.id === "r/f");
      expect(changed.length).toBe(1);

      // Content was restored to the as-of (v1) blocks, and the etag survives.
      const blocks = ns.getBlockMap("r/f");
      expect(blocks.map((b) => b.blockHash)).toEqual(["hv1"]);
    });
  });

  it("a recursive restore bumps each restored inode exactly once", async () => {
    await withStores("restore-recursive-once", ({ ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "r" });
      ns.put("r", "d", true, 0, { id: "r/d" });
      ns.put("r/d", "f1", false, 0, { id: "r/d/f1" });
      ns.put("r/d", "f2", false, 0, { id: "r/d/f2" });
      ns.setBlockMap("r/d/f1", [block("k/1", "h1")]);
      ns.setBlockMap("r/d/f2", [block("k/2", "h2")]);

      snaps.create({ id: "S1", scope: "r" });

      const vBefore = {
        d: ns.getItem("r/d")!.version,
        f1: ns.getItem("r/d/f1")!.version,
        f2: ns.getItem("r/d/f2")!.version,
      };

      const anchor = ns.currentSeq();
      const res = snaps.restore("S1", "r/d", { recursive: true });
      expect(new Set(res.restored)).toEqual(new Set(["r/d", "r/d/f1", "r/d/f2"]));

      // Each restored inode advanced by exactly 1.
      expect(ns.getItem("r/d")!.version).toBe(vBefore.d + 1);
      expect(ns.getItem("r/d/f1")!.version).toBe(vBefore.f1 + 1);
      expect(ns.getItem("r/d/f2")!.version).toBe(vBefore.f2 + 1);

      // One change-feed entry per restored file (files would have double-counted).
      const feed = ns.changesSince(anchor).items;
      expect(feed.filter((i) => i.id === "r/d/f1").length).toBe(1);
      expect(feed.filter((i) => i.id === "r/d/f2").length).toBe(1);
    });
  });

  it("re-creates a deleted file in a single write (recreated, one version)", async () => {
    await withStores("restore-recreate", ({ ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "r" });
      ns.put("r", "f", false, 0, { id: "r/f" });
      ns.setBlockMap("r/f", [block("k/v1", "hv1")]);

      snaps.create({ id: "S1", scope: "r" });

      ns.remove("r/f");
      expect(ns.getItem("r/f")!.deleted).toBe(true);

      const anchor = ns.currentSeq();
      const res = snaps.restore("S1", "r/f");
      expect(res.recreated).toEqual(["r/f"]);

      const after = ns.getItem("r/f")!;
      expect(after.deleted).toBe(false);
      expect(after.parent).toBe("r");
      expect(after.name).toBe("f");
      expect(ns.getBlockMap("r/f").map((b) => b.blockHash)).toEqual(["hv1"]);

      // Single change-feed entry for the un-tombstone+content restore.
      const changed = ns.changesSince(anchor).items.filter((i) => i.id === "r/f");
      expect(changed.length).toBe(1);
    });
  });
});

// ---------------------------------------------------------------------------
describe("finding #3 — restore returns correct content + newerThanSnapshot set", () => {
  it("reports live items created since the snapshot, and not the restored ones", async () => {
    await withStores("restore-newer", ({ ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "r" });
      ns.put("r", "d", true, 0, { id: "r/d" });
      ns.put("r/d", "old", false, 0, { id: "r/d/old" });
      ns.setBlockMap("r/d/old", [block("k/old", "hold")]);

      snaps.create({ id: "S1", scope: "r" });

      // Add NEW work after the snapshot: a new file and a new nested dir+file.
      ns.put("r/d", "new", false, 0, { id: "r/d/new" });
      ns.put("r/d", "sub", true, 0, { id: "r/d/sub" });
      ns.put("r/d/sub", "deep", false, 0, { id: "r/d/sub/deep" });

      const res = snaps.restore("S1", "r/d", { recursive: true });

      // Restored = the frozen subtree (d + old). 'new'/'sub'/'deep' are NOT touched.
      expect(new Set(res.restored)).toEqual(new Set(["r/d", "r/d/old"]));
      // newerThanSnapshot = exactly the live items absent from the snapshot subtree.
      expect(new Set(res.newerThanSnapshot)).toEqual(
        new Set(["r/d/new", "r/d/sub", "r/d/sub/deep"]),
      );
      // The new items still exist (non-destructive).
      expect(ns.getItem("r/d/new")!.deleted).toBe(false);
      expect(ns.getItem("r/d/sub/deep")!.deleted).toBe(false);
    });
  });

  it("restores frozen content even after an in-place content edit (as-of manifest)", async () => {
    await withStores("restore-asof", ({ ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "r" });
      ns.put("r", "f", false, 0, { id: "r/f" });
      ns.setBlockMap("r/f", [block("k/v1a", "v1a"), block("k/v1b", "v1b", 100, 1)]);
      const asOfCv = ns.getItem("r/f")!.contentVersion;

      snaps.create({ id: "S1", scope: "r" });

      // Overwrite content in place.
      ns.setBlockMap("r/f", [block("k/v2", "v2only")]);
      expect(ns.getBlockMap("r/f").map((b) => b.blockHash)).toEqual(["v2only"]);

      snaps.restore("S1", "r/f");
      // Block map restored to the v1 manifest (2 blocks).
      expect(ns.getBlockMap("r/f").map((b) => b.blockHash)).toEqual(["v1a", "v1b"]);
      // Size recomputed from the restored manifest (200).
      expect(ns.getItem("r/f")!.size).toBe(200);
      // content_version is freshly derived (a new current version), not the frozen one.
      expect(ns.getItem("r/f")!.contentVersion).not.toBe(asOfCv);
    });
  });

  it("non-recursive restore of a single file reports no newerThanSnapshot", async () => {
    await withStores("restore-single-nonrec", ({ ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "r" });
      ns.put("r", "f", false, 0, { id: "r/f" });
      ns.setBlockMap("r/f", [block("k/v1", "hv1")]);
      snaps.create({ id: "S1", scope: "r" });
      ns.put("r", "g", false, 0, { id: "r/g" }); // added after

      const res = snaps.restore("S1", "r/f");
      expect(res.newerThanSnapshot).toEqual([]);
      expect(res.restored).toEqual(["r/f"]);
    });
  });
});

// ---------------------------------------------------------------------------
describe("finding #4 — recursive subtree delete decrements refcounts correctly", () => {
  it("set-based subtree delete decrements each referenced block once and deletes block rows", async () => {
    await withStores("subtree-delete", ({ sql, ns }) => {
      ns.put(null, "root", true, 0, { id: "r" });
      ns.put("r", "d", true, 0, { id: "r/d" });
      ns.put("r/d", "f1", false, 0, { id: "r/d/f1" });
      ns.put("r/d", "f2", false, 0, { id: "r/d/f2" });
      ns.put("r/d", "sub", true, 0, { id: "r/d/sub" });
      ns.put("r/d/sub", "f3", false, 0, { id: "r/d/sub/f3" });
      // A sibling OUTSIDE the deleted subtree that shares a hash with f1.
      ns.put("r", "outside", false, 0, { id: "r/outside" });

      ns.setBlockMap("r/d/f1", [block("k/shared", "hShared"), block("k/u1", "hU1", 100, 1)]);
      ns.setBlockMap("r/d/f2", [block("k/u2", "hU2")]);
      ns.setBlockMap("r/d/sub/f3", [block("k/u3", "hU3")]);
      ns.setBlockMap("r/outside", [block("k/shared", "hShared")]); // 2nd ref of hShared

      expect(refcount(sql, "hShared")).toBe(2);
      expect(refcount(sql, "hU1")).toBe(1);
      expect(refcount(sql, "hU3")).toBe(1);

      const { deleted } = ns.removeSubtree("r/d");
      expect(new Set(deleted)).toEqual(
        new Set(["r/d", "r/d/f1", "r/d/f2", "r/d/sub", "r/d/sub/f3"]),
      );

      // Each inode in the subtree is tombstoned.
      for (const id of deleted) expect(ns.getItem(id)!.deleted).toBe(true);

      // Refcounts: subtree-only hashes drop to 0; the shared hash drops by 1 (the
      // 'outside' file still references it).
      expect(refcount(sql, "hShared")).toBe(1);
      expect(refcount(sql, "hU1")).toBe(0);
      expect(refcount(sql, "hU2")).toBe(0);
      expect(refcount(sql, "hU3")).toBe(0);

      // Block rows for all deleted items are gone; 'outside' keeps its block row.
      const remaining = sql
        .exec(`SELECT DISTINCT item_id FROM blocks ORDER BY item_id;`)
        .toArray()
        .map((x) => String(x.item_id));
      expect(remaining).toEqual(["r/outside"]);

      // The still-live 'outside' file is unaffected.
      expect(ns.getItem("r/outside")!.deleted).toBe(false);
      expect(ns.getBlockMap("r/outside").map((b) => b.blockHash)).toEqual(["hShared"]);
    });
  });

  it("subtree delete matches per-item remove() refcount semantics (a file with duplicate-hash blocks)", async () => {
    await withStores("subtree-delete-dup", ({ sql, ns }) => {
      ns.put(null, "root", true, 0, { id: "r" });
      ns.put("r", "f", false, 0, { id: "r/f" });
      // A file whose two blocks point at the SAME hash → refcount 2 from one file.
      ns.setBlockMap("r/f", [block("k/dup", "hDup", 100, 0), block("k/dup", "hDup", 100, 1)]);
      expect(refcount(sql, "hDup")).toBe(2);

      ns.removeSubtree("r");
      // Both refs released by the subtree delete → 0 (matches the per-block loop).
      expect(refcount(sql, "hDup")).toBe(0);
      expect(sql.exec(`SELECT COUNT(*) AS c FROM blocks;`).one().c).toBe(0);
    });
  });

  it("each tombstoned inode gets its own change-feed seq (granularity preserved)", async () => {
    await withStores("subtree-delete-feed", ({ ns }) => {
      ns.put(null, "root", true, 0, { id: "r" });
      ns.put("r", "d", true, 0, { id: "r/d" });
      ns.put("r/d", "f1", false, 0, { id: "r/d/f1" });
      ns.put("r/d", "f2", false, 0, { id: "r/d/f2" });

      const anchor = ns.currentSeq();
      const { deleted } = ns.removeSubtree("r/d");

      const feed = ns.changesSince(anchor).items;
      const tombstoned = feed.filter((i) => i.deleted).map((i) => i.id);
      // One distinct change-feed tombstone entry per deleted inode.
      expect(new Set(tombstoned)).toEqual(new Set(deleted));
      // Each carries a distinct updated_seq (monotonic per-inode emission).
      const seqs = feed.filter((i) => i.deleted).map((i) => i.updatedSeq);
      expect(new Set(seqs).size).toBe(seqs.length);
    });
  });

  it("does NOT clobber a live orphan beneath an already-tombstoned dir in the subtree", async () => {
    // Regression: the set-based block-release CTE must carry the same `deleted=0`
    // guard `subtreeIds()` has, or it walks THROUGH a tombstoned dir into a still
    // -live orphan and wipes that live file's block map + refcounts (→ GC frees R2
    // blocks a live file still references = data loss).
    await withStores("subtree-delete-orphan", ({ sql, ns }) => {
      ns.put(null, "root", true, 0, { id: "r" });
      ns.put("r", "d", true, 0, { id: "r/d" });
      ns.put("r/d", "sub", true, 0, { id: "r/d/sub" });
      ns.put("r/d/sub", "live", false, 0, { id: "r/d/sub/live" });
      ns.setBlockMap("r/d/sub/live", [block("k/live", "hLive")]);
      expect(refcount(sql, "hLive")).toBe(1);

      // Simulate a legacy corrupt tree. Current nonrecursive deletion rejects
      // nonempty directories and cannot produce this orphan.
      sql.exec(`UPDATE items SET deleted=1 WHERE id='r/d/sub';`);
      expect(ns.getItem("r/d/sub")!.deleted).toBe(true);
      expect(ns.getItem("r/d/sub/live")!.deleted).toBe(false); // live orphan

      // Recursively delete an ANCESTOR. `subtreeIds` stops at the tombstoned dir,
      // so only r/d is tombstoned; the live orphan must be left completely intact.
      const { deleted } = ns.removeSubtree("r/d");
      expect(new Set(deleted)).toEqual(new Set(["r/d"]));

      // The live orphan is untouched: still live, block map intact, refcount > 0.
      expect(ns.getItem("r/d/sub/live")!.deleted).toBe(false);
      expect(ns.getBlockMap("r/d/sub/live").map((b) => b.blockHash)).toEqual(["hLive"]);
      expect(refcount(sql, "hLive")).toBe(1);
    });
  });
});
