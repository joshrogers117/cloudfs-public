// SPDX-License-Identifier: AGPL-3.0-or-later
// acl-grant-on-deleted-node.test.ts — interaction bug between I3 (grant-resurrection
// fix) and N-F1 (change-feed tombstone delivery).
//
// N-F1 delivers a deletion event (tombstone) to every principal who could read the
// item PRE-deletion, by walking the RAW (tombstone-ignoring) parent chain to the
// nearest SURVIVING grant. I3 originally deleted grants AT DELETE-TIME. When a
// principal's grant is ON the deleted node itself (or on a node WITHIN the deleted
// subtree), I3's delete-time cleanup removed that grant before N-F1 could walk to it
// → N-F1 found NO surviving grant → the principal NEVER received the tombstone →
// their client kept the deleted item forever (namespace divergence).
//
// The existing N-F1 test (acl-completeness.test.ts) only covers a grant on a
// SURVIVING ANCESTOR (grant on root/team, delete the child root/team/proj), so it
// never exercised this case. This file pins the grant-ON-deleted-node case.
//
// FIX: grant-cleanup moved from DELETE-time to RECREATE-time. Grants now SURVIVE a
// deletion (so N-F1 can still reach them), and are cleared only when the same
// path-deterministic inode id transitions deleted→live again (resurrection still
// prevented). This test must therefore FAIL on the pre-fix delete-time-cleanup code
// (revert-proof, Step 4).

import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { filespaceDoName } from "../src/security/auth";
import { NamespaceStore } from "../src/metadata/namespace";
import { DoAclStore } from "../src/metadata/acl-store";
import { grant as grantAcl, type Principal } from "../src/permissions";

const ORG = "acl-gond-org";

// Cast runInDurableObject so its generic doesn't deeply instantiate the full
// FilespaceDO RPC type (TS2589), matching data-integrity-3.test.ts.
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

// A non-full-access user: plain "user", no org admin role, no grant on root.
const bob: Principal = { type: "user", id: "bob" };
// A full-access admin: org role short-circuits in hasFullAccess().
const admin: Principal = { type: "user", id: "admin", orgRole: "admin" };

describe("interaction(I3×N-F1): grant ON the deleted subtree still delivers tombstones", () => {
  it("recursive delete of root/team/proj (grant ON proj) delivers proj/* tombstones to the grant-holder", async () => {
    await withDo("gond-subtree", async (inst, sql) => {
      const ns = new NamespaceStore(sql);
      const acl = new DoAclStore(sql);

      // Tree: root/team/proj/{a,b}. bob's grant is ON the deleted-subtree root (proj),
      // NOT on a surviving ancestor — exactly the uncovered N-F1 case.
      ns.put(null, "root", true, 0, { id: "root" });
      ns.put("root", "team", true, 0, { id: "root/team" });
      ns.put("root/team", "proj", true, 0, { id: "root/team/proj" });
      ns.put("root/team/proj", "a", false, 1, { id: "root/team/proj/a" });
      ns.put("root/team/proj", "b", false, 2, { id: "root/team/proj/b" });

      // bob holds read ON proj (inherits to a + b). No grant on root/team or root.
      grantAcl(acl, { spaceId: "sp", inodeId: "root/team/proj", principalType: "user", principalId: "bob", level: "read" }, "admin");

      // Cursors just before the delete, so we read ONLY the delete's tombstones.
      const bobBefore = (await inst.changesSinceFor(bob, 0)).anchor as number;
      const adminBefore = (await inst.changesSinceFor(admin, 0)).anchor as number;

      // Recursively delete proj — tombstones proj + a + b.
      const del = await inst.deleteSubtree("root/team/proj", "admin");
      expect(del.deleted).toBeGreaterThanOrEqual(3);

      // bob MUST receive the tombstones for proj + a + b. PRE-fix this FAILS: I3's
      // delete-time cleanup dropped bob's grant on proj, so N-F1's raw-chain walk
      // found no surviving grant and delivered nothing.
      const bobFeed = await inst.changesSinceFor(bob, bobBefore);
      const bobDeleted = bobFeed.items.filter((i: any) => i.deleted).map((i: any) => i.id);
      expect(bobDeleted).toContain("root/team/proj");
      expect(bobDeleted).toContain("root/team/proj/a");
      expect(bobDeleted).toContain("root/team/proj/b");

      // The full-access admin sees every tombstone (short-circuit) — control.
      const adminFeed = await inst.changesSinceFor(admin, adminBefore);
      const adminDeleted = adminFeed.items.filter((i: any) => i.deleted).map((i: any) => i.id);
      expect(adminDeleted).toContain("root/team/proj");
      expect(adminDeleted).toContain("root/team/proj/a");
      expect(adminDeleted).toContain("root/team/proj/b");
    });
  });

  it("single-file delete (grant ON the file) still delivers that file's tombstone", async () => {
    await withDo("gond-single", async (inst, sql) => {
      const ns = new NamespaceStore(sql);
      const acl = new DoAclStore(sql);

      ns.put(null, "root", true, 0, { id: "root" });
      ns.put("root", "docs", true, 0, { id: "root/docs" });
      ns.put("root/docs", "f", false, 3, { id: "root/docs/f" });

      // bob's ONLY grant is ON the file itself — the node that gets tombstoned.
      grantAcl(acl, { spaceId: "sp", inodeId: "root/docs/f", principalType: "user", principalId: "bob", level: "read" }, "admin");

      const bobBefore = (await inst.changesSinceFor(bob, 0)).anchor as number;

      const del = await inst.deleteItem("root/docs/f");
      expect(del.deleted).toBe(true);

      // bob MUST still get the file's tombstone (PRE-fix: dropped by I3's delete-time cleanup).
      const bobFeed = await inst.changesSinceFor(bob, bobBefore);
      const bobDeleted = bobFeed.items.filter((i: any) => i.deleted).map((i: any) => i.id);
      expect(bobDeleted).toContain("root/docs/f");
    });
  });

  it("recreate at the deleted (parent,name) gets a NEW opaque id; resurrection prevented by construction (B17)", async () => {
    await withDo("gond-recreate", async (inst, sql) => {
      const acl = new DoAclStore(sql);

      // Create + grant via the DO create path → an OPAQUE id (audit B17).
      const orig = (await inst.createItem("root", "secret", false, 10) as { item: { id: string } }).item.id;
      grantAcl(acl, { spaceId: "sp", inodeId: orig, principalType: "user", principalId: "bob", level: "edit" }, "admin");

      // Delete the file — its grant SURVIVES on the dead id (so N-F1 could deliver a tombstone).
      await inst.deleteItem(orig);

      // Recreate at the SAME (parent, name) → a BRAND-NEW opaque id. The stale grant is bound to
      // the DEAD id, so the new incarnation has NO grant → bob is denied. With opaque ids the
      // resurrection hazard is gone by construction (no path-id reuse).
      const res = await inst.createItem("root", "secret", false, 10);
      expect("item" in res).toBe(true);
      const newId = (res as { item: { id: string } }).item.id;
      expect(newId).not.toBe(orig);
      expect((await inst.checkAccess(bob, newId, "write")).allow).toBe(false);
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM grants WHERE inode_id=?;`, newId).one().c)).toBe(0);
      // The dead id is tombstoned, so even its surviving grant grants no live access.
      expect((await inst.checkAccess(bob, orig, "write")).allow).toBe(false);
    });
  });
});
