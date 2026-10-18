// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
  InMemoryPermissionStore,
  canAccess,
  effectiveLevel,
  resolveMountRoot,
  grant,
  revokePrincipal,
  revokeGrantById,
  type Principal,
  type Grant,
} from "../src/permissions";

// Build the SPEC §4.11 worked-example tree:
//   /ShowA
//     /Footage   /Edit   /Color   /Deliverables
// plus a file under /Edit to test file-inherits-folder.
function buildTree(): InMemoryPermissionStore {
  const s = new InMemoryPermissionStore();
  s.addInode({ id: "root", parentId: null, type: "folder" });
  s.addInode({ id: "showA", parentId: "root", type: "folder" });
  s.addInode({ id: "footage", parentId: "showA", type: "folder" });
  s.addInode({ id: "edit", parentId: "showA", type: "folder" });
  s.addInode({ id: "color", parentId: "showA", type: "folder" });
  s.addInode({ id: "deliverables", parentId: "showA", type: "folder" });
  s.addInode({ id: "timeline", parentId: "edit", type: "file" });
  s.addInode({ id: "clip", parentId: "footage", type: "file" });
  return s;
}

const SYS = "usr-admin";

describe("canAccess — core ACL semantics (SPEC §4.3)", () => {
  it("no grant == no access (no deny verb; invisible)", () => {
    const s = buildTree();
    const marco: Principal = { type: "user", id: "marco", groupIds: [] };
    const d = canAccess(s, marco, "color", "list");
    expect(d.allow).toBe(false);
    expect(d.effectiveLevel).toBe(null);
  });

  it("recursive inheritance: a grant high in the tree flows down", () => {
    const s = buildTree();
    grant(s, { spaceId: "sp", inodeId: "showA", principalType: "user", principalId: "dana", level: "edit" }, SYS);
    const dana: Principal = { type: "user", id: "dana", groupIds: [] };
    // dana has no explicit grant on the file, inherits edit from /ShowA
    expect(canAccess(s, dana, "clip", "read").allow).toBe(true);
    expect(canAccess(s, dana, "clip", "write").allow).toBe(true);
    expect(effectiveLevel(s, dana, "clip")).toBe("edit");
  });

  it("the strict ladder: read < edit < admin", () => {
    const s = buildTree();
    grant(s, { spaceId: "sp", inodeId: "footage", principalType: "user", principalId: "p", level: "read" }, SYS);
    const p: Principal = { type: "user", id: "p", groupIds: [] };
    expect(canAccess(s, p, "footage", "read").allow).toBe(true);
    expect(canAccess(s, p, "footage", "list").allow).toBe(true);
    expect(canAccess(s, p, "footage", "write").allow).toBe(false); // read < edit
    expect(canAccess(s, p, "footage", "manage_acl").allow).toBe(false); // read < admin
  });

  it("group union: a member picks up grants targeting any of its groups; MAX level wins", () => {
    const s = buildTree();
    // ShowA-Color group gets read on /Footage; a direct grant gives edit on /Footage
    grant(s, { spaceId: "sp", inodeId: "footage", principalType: "group", principalId: "ShowA-Color", level: "read" }, SYS);
    grant(s, { spaceId: "sp", inodeId: "footage", principalType: "group", principalId: "ShowA-Editors", level: "edit" }, SYS);
    const priya: Principal = { type: "user", id: "priya", groupIds: ["ShowA-Color", "ShowA-Editors"] };
    // union => MAX(read, edit) = edit
    expect(effectiveLevel(s, priya, "footage")).toBe("edit");
    expect(canAccess(s, priya, "footage", "write").allow).toBe(true);
  });

  it("nearest explicit ACL wins over an inherited one (even if lower)", () => {
    const s = buildTree();
    grant(s, { spaceId: "sp", inodeId: "showA", principalType: "user", principalId: "q", level: "admin" }, SYS);
    grant(s, { spaceId: "sp", inodeId: "color", principalType: "user", principalId: "q", level: "read" }, SYS);
    const q: Principal = { type: "user", id: "q", groupIds: [] };
    // /Color has an explicit read grant — it wins over the inherited admin from /ShowA
    expect(effectiveLevel(s, q, "color")).toBe("read");
    expect(canAccess(s, q, "color", "write").allow).toBe(false);
    // but /Edit (no explicit grant) still inherits admin from /ShowA
    expect(effectiveLevel(s, q, "edit")).toBe("admin");
  });
});

describe("mutation rule §4.3(4): rename/delete needs write on item AND parent", () => {
  it("denies delete when the principal lacks write on the parent folder", () => {
    const s = buildTree();
    // edit on the file only; the parent /Edit has no grant for this user
    grant(s, { spaceId: "sp", inodeId: "timeline", principalType: "user", principalId: "r", level: "edit" }, SYS);
    const r: Principal = { type: "user", id: "r", groupIds: [] };
    expect(canAccess(s, r, "timeline", "write").allow).toBe(true); // write the file: ok
    expect(canAccess(s, r, "timeline", "delete").allow).toBe(false); // delete needs parent write
    expect(canAccess(s, r, "timeline", "rename").allow).toBe(false);
  });

  it("allows delete when the principal has write on both item and parent", () => {
    const s = buildTree();
    grant(s, { spaceId: "sp", inodeId: "edit", principalType: "user", principalId: "r", level: "edit" }, SYS);
    const r: Principal = { type: "user", id: "r", groupIds: [] };
    // inherits edit on the file from /Edit, and has edit on the parent /Edit itself
    expect(canAccess(s, r, "timeline", "delete").allow).toBe(true);
    expect(canAccess(s, r, "timeline", "rename").allow).toBe(true);
  });
});

describe("org-role short-circuit (SPEC §4.2 'admins see all')", () => {
  it("owner/admin get full access without any ACL", () => {
    const s = buildTree();
    const admin: Principal = { type: "user", id: "dana", orgRole: "admin" };
    const d = canAccess(s, admin, "color", "manage_acl");
    expect(d.allow).toBe(true);
    expect(d.effectiveLevel).toBe("admin");
    expect(effectiveLevel(s, admin, "color")).toBe("admin");
  });

  it("standard role gets no special treatment", () => {
    const s = buildTree();
    const std: Principal = { type: "user", id: "x", orgRole: "standard", groupIds: [] };
    expect(canAccess(s, std, "color", "read").allow).toBe(false);
  });
});

describe("RootPoint / sub-path mount (SPEC §4.3)", () => {
  it("surfaces the mount root from a mountAsRoot grant", () => {
    const s = buildTree();
    grant(
      s,
      { spaceId: "sp", inodeId: "color", principalType: "group", principalId: "ShowA-Color", level: "edit", mountAsRoot: true },
      SYS,
    );
    const priya: Principal = { type: "user", id: "priya", groupIds: ["ShowA-Color"] };
    expect(resolveMountRoot(s, priya, "color")).toBe("color");
    const d = canAccess(s, priya, "color", "write");
    expect(d.allow).toBe(true);
    expect(d.rootInodeId).toBe("color");
  });
});

describe("expiring grants (SPEC §4.3 expires_at)", () => {
  it("an expired grant is ignored at evaluation time", () => {
    const s = buildTree();
    const past = Date.now() - 1000;
    grant(
      s,
      { spaceId: "sp", inodeId: "color", principalType: "user", principalId: "priya", level: "edit", expiresAt: past },
      SYS,
    );
    const priya: Principal = { type: "user", id: "priya", groupIds: [] };
    // grant exists but is expired -> no access
    expect(canAccess(s, priya, "color", "read").allow).toBe(false);
    // a future expiry is honored
    const future = Date.now() + 60_000;
    grant(
      s,
      { spaceId: "sp", inodeId: "edit", principalType: "user", principalId: "priya", level: "edit", expiresAt: future },
      SYS,
    );
    expect(canAccess(s, priya, "edit", "read").allow).toBe(true);
  });
});

describe("grant / revoke helpers", () => {
  it("revokePrincipal removes all of a principal's grants on an inode", () => {
    const s = buildTree();
    grant(s, { spaceId: "sp", inodeId: "footage", principalType: "user", principalId: "z", level: "read" }, SYS);
    grant(s, { spaceId: "sp", inodeId: "footage", principalType: "user", principalId: "z", level: "edit" }, SYS);
    const z: Principal = { type: "user", id: "z", groupIds: [] };
    expect(canAccess(s, z, "footage", "read").allow).toBe(true);
    const removed = revokePrincipal(s, "footage", "user", "z");
    expect(removed).toBe(2);
    expect(canAccess(s, z, "footage", "read").allow).toBe(false);
  });

  it("revokeGrantById removes a single grant", () => {
    const s = buildTree();
    const g: Grant = grant(s, { spaceId: "sp", inodeId: "edit", principalType: "user", principalId: "z", level: "edit" }, SYS);
    expect(revokeGrantById(s, g.id)).toBe(true);
    expect(revokeGrantById(s, g.id)).toBe(false); // already gone
  });

  it("granting on a non-existent inode throws", () => {
    const s = buildTree();
    expect(() =>
      grant(s, { spaceId: "sp", inodeId: "ghost", principalType: "user", principalId: "z", level: "read" }, SYS),
    ).toThrow();
  });
});

// Delegation lineage is deliberately one hop and fails closed on corrupt ancestry.
describe('delegation lineage bounds', () => {
  it('rejects cycles, missing source roots and delegated administrators', async () => {
    const { isGrantLive } = await import('../src/permissions');
    const store = buildTree();
    const authority = grant(store,{spaceId:'sp',inodeId:'showA',principalType:'user',principalId:'manager',level:'admin'},SYS);
    const leaf = { ...grant(store,{spaceId:'sp',inodeId:'edit',principalType:'user',principalId:'reader',level:'read'},'manager'), authorityGrantId:authority.id, authorityInodeId:'showA' };
    store.putGrant(leaf);
    expect(isGrantLive(store,leaf)).toBe(true);
    store.addInode({id:'edit',parentId:'edit',type:'folder'});
    expect(isGrantLive(store,leaf)).toBe(false);
    store.addInode({id:'edit',parentId:'showA',type:'folder'});
    expect(isGrantLive(store,{...leaf,level:'admin'})).toBe(false);
    expect(isGrantLive(store,{...leaf,authorityInodeId:'missing'})).toBe(false);
    store.putGrant({...authority,authorityGrantId:leaf.id,authorityInodeId:'edit'});
    expect(isGrantLive(store,leaf)).toBe(false);
  });
});
