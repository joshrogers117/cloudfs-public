// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { filespaceDoName } from "../src/security/auth";
import { NamespaceStore } from "../src/metadata/namespace";
import { SnapshotStore } from "../src/metadata/snapshots";
import { DoAclStore } from "../src/metadata/acl-store";
import { grant as grantAcl, canAccess, type Principal } from "../src/permissions";
import type { Block } from "../src/metadata/types";

// Regression tests for the 3 confirmed data-integrity findings:
//   I1 — snapshot freeze() must hold its OWN block_refs so an overwrite/delete of
//        the live file can't drop a snapshotted block to refcount 0 (GC = data loss).
//   I2 — snapshot prune()/deleteSnapshot must release those refs AND delete the
//        frozen snapshot_items/snapshot_blocks rows (no leak); a block referenced
//        only by the pruned snapshot then becomes collectable, one still referenced
//        does not.
//   I3 — a recreate at the same (path-deterministic) inode id must NOT resurrect a
//        stale grant from a prior incarnation. Grant-cleanup runs at RECREATE-time
//        (the deleted→live transition in createItem), NOT at delete-time: the grants
//        deliberately SURVIVE the deleted window so the change-feed tombstone
//        delivery (N-F1) can walk to them and notify the grant-holder. The invariant
//        is "no access after recreate", which is what these tests assert.
//
// All drive the real stores on a migrated DO SqlStorage (via runInDurableObject),
// so we can assert raw block_refs rows and ACL decisions with full precision.

const ORG = "org-di3";

/// A migrated DO + stores built directly on its SqlStorage. Each test gets its own
/// space (own DO instance) so state never bleeds between tests.
async function withStores<T>(
  space: string,
  fn: (s: { sql: SqlStorage; ns: NamespaceStore; snaps: SnapshotStore; acl: DoAclStore }) => T | Promise<T>,
): Promise<T> {
  const stub = (env as any).FILESPACE.get(
    (env as any).FILESPACE.idFromName(filespaceDoName(ORG, space)),
  );
  return runInDurableObject(stub, async (_inst: unknown, state: DurableObjectState) => {
    const sql = state.storage.sql;
    const ns = new NamespaceStore(sql);
    const snaps = new SnapshotStore(sql, () => ns.currentSeq(), ns);
    const acl = new DoAclStore(sql);
    return fn({ sql, ns, snaps, acl });
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

function snapBlockRows(sql: SqlStorage, snapshotId: string): number {
  return Number(
    sql.exec(`SELECT COUNT(*) AS c FROM snapshot_blocks WHERE snapshot_id=?;`, snapshotId).one().c,
  );
}
function snapItemRows(sql: SqlStorage, snapshotId: string): number {
  return Number(
    sql.exec(`SELECT COUNT(*) AS c FROM snapshot_items WHERE snapshot_id=?;`, snapshotId).one().c,
  );
}

// ---------------------------------------------------------------------------
describe("Finding I1 — snapshot-frozen blocks are NOT GC-collectable after overwrite", () => {
  it("freeze() bumps block_refs so an overwritten snapshotted hash stays referenced", async () => {
    await withStores("i1-overwrite", ({ sql, ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "root" });
      // root/f → hV1 (live refcount 1)
      ns.setBlockMap("root/f", [block("k/hV1", "hV1")], { upsert: { parent: "root", name: "f" } });
      expect(refcount(sql, "hV1")).toBe(1);

      // Snapshot S1 freezes hV1 → it now holds its OWN ref (live 1 + snapshot 1 = 2).
      snaps.create({ id: "S1", scope: "root" });
      expect(refcount(sql, "hV1")).toBe(2);

      // Overwrite root/f → hV2 (drops the live ref on hV1, adds a live ref on hV2).
      ns.setBlockMap("root/f", [block("k/hV2", "hV2")]);
      // hV1 still referenced by S1's frozen manifest → refcount 1 (NOT 0).
      expect(refcount(sql, "hV1")).toBe(1);
      expect(refcount(sql, "hV2")).toBe(1);

      // GC must NOT offer the snapshotted hash. A truly-unreferenced hash (write +
      // overwrite with NO snapshot in between) MUST still be collectable.
      ns.setBlockMap("root/g", [block("k/orphan", "orphan")], { upsert: { parent: "root", name: "g" } });
      ns.setBlockMap("root/g", [block("k/g2", "g2")]); // drops orphan to 0, no snapshot froze it
      expect(refcount(sql, "orphan")).toBe(0);

      const collectable = snaps.collectableBlocks().map((b) => b.blockHash);
      expect(collectable).not.toContain("hV1"); // snapshotted — must survive
      expect(collectable).not.toContain("orphan"); // live inode retains its old recovery blocks
      ns.remove("root/g");
      expect(snaps.collectableBlocks().map((b) => b.blockHash)).toContain("orphan");
    });
  });

  it("freeze() counts duplicate hashes within one snapshot manifest (+N, not +1)", async () => {
    await withStores("i1-dups", ({ sql, ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "root" });
      // Same hash appears twice in one file's manifest (e.g. two identical blocks).
      ns.setBlockMap(
        "root/f",
        [block("k/dup", "dup", 100, 0), block("k/dup", "dup", 100, 1)],
        { upsert: { parent: "root", name: "f" } },
      );
      // live: +2 for the two manifest entries of the same hash.
      expect(refcount(sql, "dup")).toBe(2);
      snaps.create({ id: "S1", scope: "root" });
      // snapshot adds +2 (two frozen rows of the same hash) → 4 total.
      expect(refcount(sql, "dup")).toBe(4);
    });
  });

  it("re-freezing the same snapshot id nets zero double-counting", async () => {
    await withStores("i1-refreeze", ({ sql, ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "root" });
      ns.setBlockMap("root/f", [block("k/h", "h")], { upsert: { parent: "root", name: "f" } });
      snaps.create({ id: "S1", scope: "root" });
      expect(refcount(sql, "h")).toBe(2); // live 1 + snapshot 1
      snaps.create({ id: "S1", scope: "root" }); // re-freeze same id (REPLACE)
      expect(refcount(sql, "h")).toBe(2); // still live 1 + snapshot 1, no leak
    });
  });
});

// ---------------------------------------------------------------------------
describe("Finding I2 — snapshot deletion releases block_refs + deletes frozen rows", () => {
  it("deleting a snapshot frees a snapshot-only block; one a kept snapshot holds survives", async () => {
    await withStores("i2-delete", ({ sql, ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "root" });
      // hShared lives in BOTH snapshots (and a live file); hOnly lives ONLY in OLD
      // after the live overwrite drops its live ref.
      ns.setBlockMap("root/a", [block("k/hOnly", "hOnly")], { upsert: { parent: "root", name: "a" } });
      ns.setBlockMap("root/b", [block("k/hShared", "hShared")], { upsert: { parent: "root", name: "b" } });

      snaps.create({ id: "OLD", scope: "root" });
      // Overwrite root/a so hOnly's LIVE ref drops — now only OLD references hOnly.
      ns.setBlockMap("root/a", [block("k/a2", "a2")]);
      snaps.create({ id: "KEEP", scope: "root" });

      // Audit B19 (delta model): KEEP bases on OLD and only freezes root/a (changed→a2); root/b is
      // UNCHANGED so KEEP inherits it from OLD (no re-freeze). So hOnly is held only by OLD (1);
      // hShared by live b + OLD's freeze (2) — KEEP does NOT add a third ref (it inherits).
      expect(refcount(sql, "hOnly")).toBe(1);
      expect(refcount(sql, "hShared")).toBe(2);
      expect(snapBlockRows(sql, "OLD")).toBeGreaterThan(0);

      // Delete OLD — chain-preserving: hShared's frozen row (root/b) the child KEEP relies on MOVES
      // into KEEP (ref transferred, net zero); hOnly (no child override-or-inherit need... actually
      // KEEP overrode root/a, so hOnly is NOT inherited) is released → collectable.
      snaps.deleteSnapshot("OLD");

      // Frozen rows for OLD are GONE (no leak); the snapshot row too.
      expect(snapBlockRows(sql, "OLD")).toBe(0);
      expect(snapItemRows(sql, "OLD")).toBe(0);
      expect(snaps.get("OLD")).toBeNull();

      // hOnly now has NO ref (live dropped at overwrite; KEEP overrode root/a so didn't inherit it;
      // OLD's ref released) → 0, collectable.
      expect(refcount(sql, "hOnly")).toBe(0);
      // hShared still referenced by live b + KEEP (inherited the row) → 2 (NOT collectable).
      expect(refcount(sql, "hShared")).toBe(2);
      // KEEP still resolves root/b (hShared) and root/a (a2) correctly after the delete.
      const keepDir = snaps.listAt("KEEP", "root").map((i) => i.name);
      expect(keepDir).toContain("a");
      expect(keepDir).toContain("b");

      const collectable = snaps.collectableBlocks().map((b) => b.blockHash);
      expect(collectable).not.toContain("hOnly"); // live inode still retains its old recovery block
      ns.remove("root/a");
      expect(snaps.collectableBlocks().map((b) => b.blockHash)).toContain("hOnly");
      expect(collectable).not.toContain("hShared"); // still held by KEEP (inherited) + live b
    });
  });

  it("prune() performs the FULL deletion: rows + refs for the pruned id are gone", async () => {
    await withStores("i2-prune", ({ sql, ns, snaps }) => {
      ns.put(null, "root", true, 0, { id: "root" });
      ns.setBlockMap("root/f", [block("k/h", "h")], { upsert: { parent: "root", name: "f" } });

      // Two schedule-scoped snapshots; prune keeps the newest 1 and deletes the other.
      snaps.create({ id: "OLD", scope: "root", scheduleId: "s", tier: "auto" });
      snaps.create({ id: "KEEP", scope: "root", scheduleId: "s", tier: "auto" });
      // Audit B19 (delta): root/f is UNCHANGED between OLD and KEEP, so KEEP inherits it from OLD
      // (no re-freeze). h: live 1 + OLD's freeze 1 = 2 (KEEP adds no ref — it inherits).
      expect(refcount(sql, "h")).toBe(2);

      const deleted = snaps.prune("s", 1);
      expect(deleted.length).toBe(1); // exactly one pruned (created_at-DESC tiebreak)
      const prunedId = deleted[0];
      const keptId = prunedId === "OLD" ? "KEEP" : "OLD";

      // Whichever was pruned: its frozen rows + snapshot row are gone.
      expect(snapBlockRows(sql, prunedId)).toBe(0);
      expect(snapItemRows(sql, prunedId)).toBe(0);
      expect(snaps.get(prunedId)).toBeNull();
      // h is still referenced by live f + the kept snapshot (which now holds root/f's row, either
      // because it froze it or inherited it via chain-preserving delete) → 2, NOT collectable.
      expect(refcount(sql, "h")).toBe(2);
      // The kept snapshot still resolves root/f.
      expect(snaps.listAt(keptId, "root").map((i) => i.name)).toContain("f");
      const collectable = snaps.collectableBlocks().map((b) => b.blockHash);
      expect(collectable).not.toContain("h");
    });
  });
});

// ---------------------------------------------------------------------------
// I3 drives the real FilespaceDO delete orchestration (deleteItem/deleteSubtree),
// where the grant cleanup is wired, rather than ns.remove directly.
const bob: Principal = { type: "user", id: "bob" };

// Cast `runInDurableObject` to a minimal shape so its generic doesn't deeply
// instantiate the full FilespaceDO RPC type (TS2589).
const runInDo = runInDurableObject as unknown as <R>(
  s: unknown,
  cb: (inst: any, state: DurableObjectState) => R | Promise<R>,
) => Promise<R>;

async function withDo<T>(space: string, fn: (inst: any, sql: SqlStorage) => T | Promise<T>): Promise<T> {
  const stub = (env as any).FILESPACE.get(
    (env as any).FILESPACE.idFromName(filespaceDoName(ORG, space)),
  );
  return runInDo(stub, async (inst, state) => fn(inst, state.storage.sql));
}

// Audit B17: with OPAQUE immutable ids, the grant-resurrection hazard is retired BY
// CONSTRUCTION — a recreate at the same (parent, name) gets a BRAND-NEW id, so a stale grant
// (bound to the dead id) can never apply to the new item. These tests assert that property.
describe("Finding I3 (post-B17) — opaque ids make a recreate get a fresh id; stale grants never apply", () => {
  it("delete → recreate at same (parent,name) yields a NEW id; the dead id's grant doesn't apply", async () => {
    await withDo("i3-resurrect", async (inst, sql) => {
      const acl = new DoAclStore(sql);
      // secret + a live sibling other (via the DO create path → opaque ids).
      const secret = await inst.createItem("root", "secret", false, 10);
      const other = await inst.createItem("root", "other", false, 10);
      expect("item" in secret && "item" in other).toBe(true);
      const secretId = (secret as { item: { id: string } }).item.id;
      const otherId = (other as { item: { id: string } }).item.id;
      expect(secretId).toMatch(/^ino-/);

      // Grant bob edit on both opaque ids.
      grantAcl(acl, { spaceId: "sp", inodeId: secretId, principalType: "user", principalId: "bob", level: "edit" }, "admin");
      grantAcl(acl, { spaceId: "sp", inodeId: otherId, principalType: "user", principalId: "bob", level: "edit" }, "admin");
      expect(canAccess(acl, bob, secretId, "write").allow).toBe(true);

      // Delete the secret item. The grant row deliberately SURVIVES (so N-F1 can deliver the
      // tombstone to bob); live read is denied because the inode is tombstoned.
      const del = await inst.deleteItem(secretId);
      expect(del.deleted).toBe(true);
      expect(canAccess(acl, bob, secretId, "write").allow).toBe(false);

      // Recreate at the SAME (parent, name) → a BRAND-NEW opaque id. The old grant is bound to
      // the dead id, so the new item has NO grant → access DENIED. No resurrection possible.
      const re = await inst.createItem("root", "secret", false, 10);
      expect("item" in re).toBe(true);
      const newId = (re as { item: { id: string } }).item.id;
      expect(newId).not.toBe(secretId);
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM grants WHERE inode_id=?;`, newId).one().c)).toBe(0);
      expect(canAccess(acl, bob, newId, "write").allow).toBe(false);

      // The still-live sibling's grant is UNAFFECTED.
      expect(canAccess(acl, bob, otherId, "write").allow).toBe(true);
    });
  });

  it("removeSubtree: grants survive the delete (for N-F1); a recreate gets fresh ids with no grants", async () => {
    await withDo("i3-subtree", async (inst, sql) => {
      const acl = new DoAclStore(sql);
      const dir = (await inst.createItem("root", "dir", true, 0) as { item: { id: string } }).item.id;
      const child = (await inst.createItem(dir, "child", false, 5) as { item: { id: string } }).item.id;
      const keep = (await inst.createItem("root", "keep", false, 5) as { item: { id: string } }).item.id;

      grantAcl(acl, { spaceId: "sp", inodeId: dir, principalType: "user", principalId: "bob", level: "edit" }, "admin");
      grantAcl(acl, { spaceId: "sp", inodeId: child, principalType: "user", principalId: "bob", level: "edit" }, "admin");
      grantAcl(acl, { spaceId: "sp", inodeId: keep, principalType: "user", principalId: "bob", level: "edit" }, "admin");

      const res = await inst.deleteSubtree(dir, "admin");
      expect(res.deleted).toBeGreaterThanOrEqual(2);

      // Grants on the deleted subtree inodes deliberately SURVIVE (so N-F1 can deliver tombstones
      // to bob); the out-of-subtree grant is untouched. Live access is denied via the tombstone.
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM grants WHERE inode_id IN (?,?);`, dir, child).one().c)).toBe(2);
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM grants WHERE inode_id=?;`, keep).one().c)).toBe(1);
      expect(canAccess(acl, bob, child, "write").allow).toBe(false); // tombstoned → denied

      // Recreate dir + child at the same (parent,name) → BRAND-NEW ids with no grants → denied.
      const dir2 = (await inst.createItem("root", "dir", true, 0) as { item: { id: string } }).item.id;
      const child2 = (await inst.createItem(dir2, "child", false, 5) as { item: { id: string } }).item.id;
      expect(dir2).not.toBe(dir);
      expect(child2).not.toBe(child);
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM grants WHERE inode_id IN (?,?);`, dir2, child2).one().c)).toBe(0);
      expect(canAccess(acl, bob, child2, "write").allow).toBe(false);
    });
  });
});
