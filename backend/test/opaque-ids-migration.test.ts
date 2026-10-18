// SPDX-License-Identifier: AGPL-3.0-or-later
// opaque-ids-migration.test.ts — audit B17: the v11 path-id → opaque-id migration, the rename
// RPC, and the (parent,name) uniqueness, exercised against the REAL DO SqlStorage.
import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { filespaceDoName } from "../src/security/auth";
import { migrateToOpaqueIds } from "../src/metadata/schema";
import { NamespaceStore, NameCollisionError, InvalidMoveError } from "../src/metadata/namespace";

const ORG = "org-b17";

/// Run against a migrated DO's raw SqlStorage (so we can seed legacy path-id rows + assert raw refs).
async function withSql<T>(space: string, fn: (sql: SqlStorage) => T | Promise<T>): Promise<T> {
  const stub = (env as any).FILESPACE.get((env as any).FILESPACE.idFromName(filespaceDoName(ORG, space)));
  return runInDurableObject(stub, async (_inst: unknown, state: DurableObjectState) =>
    fn(state.storage.sql),
  );
}

/// Seed a LEGACY (pre-B17) tree using path-derived ids directly, plus a reference in each table
/// that the migration must rewrite (blocks, grants, locks, snapshot_items, snapshot_blocks, uploads).
function seedLegacyTree(sql: SqlStorage): void {
  const ins = (id: string, parent: string | null, name: string, isDir: number) =>
    sql.exec(
      `INSERT OR REPLACE INTO items (id,parent,name,is_dir,size,content_version,etag,version,created_seq,updated_seq,deleted)
       VALUES (?,?,?,?,0,'cv',NULL,1,1,1,0);`,
      id, parent, name, isDir,
    );
  ins("root", null, "", 1);
  ins("root/proj", "root", "proj", 1);
  ins("root/proj/clip.mov", "root/proj", "clip.mov", 0);
  // a reference in every id-bearing table, pointing at the legacy path id.
  sql.exec(`INSERT OR REPLACE INTO blocks (item_id,chunk_idx,block_idx,block_hash,object_key,offset,length) VALUES ('root/proj/clip.mov',0,0,'h','k',0,10);`);
  sql.exec(`INSERT OR REPLACE INTO block_refs (block_hash,object_key,refcount) VALUES ('h','k',1);`);
  sql.exec(`INSERT OR REPLACE INTO grants (id,space_id,inode_id,principal_type,principal_id,level,mount_as_root,expires_at,granted_by,granted_at) VALUES ('g1','sp','root/proj','user','bob','edit',0,NULL,'admin',1);`);
  sql.exec(`INSERT OR REPLACE INTO locks (path,owner,mode,fence,acquired_at,expires_at) VALUES ('root/proj/clip.mov','alice','exclusive',1,1,99999999999);`);
  sql.exec(`INSERT OR REPLACE INTO snapshot_items (snapshot_id,item_id,parent,name,is_dir,size,content_version,etag) VALUES ('S1','root/proj/clip.mov','root/proj','clip.mov',0,10,'cv',NULL);`);
  sql.exec(`INSERT OR REPLACE INTO snapshot_blocks (snapshot_id,item_id,chunk_idx,block_idx,block_hash,object_key,offset,length) VALUES ('S1','root/proj/clip.mov',0,0,'h','k',0,10);`);
  sql.exec(`INSERT OR REPLACE INTO uploads (upload_id,item_id,key,total_size,part_size,state,created_at,updated_at) VALUES ('u1','root/proj/clip.mov','k',10,5,'in_progress',1,1);`);
}

describe("B17: migrateToOpaqueIds rewrites every reference idempotently", () => {
  it("re-keys path-derived ids to opaque ids and rewrites all FK-like references", async () => {
    await withSql("mig-rewrite", async (sql) => {
      seedLegacyTree(sql);
      migrateToOpaqueIds(sql);

      // root keeps its literal id; non-root rows get ino-<uuid>.
      const root = sql.exec(`SELECT id, parent FROM items WHERE name='' AND parent IS NULL;`).one();
      expect(String(root.id)).toBe("root");
      const proj = sql.exec(`SELECT id, parent FROM items WHERE name='proj';`).one();
      const clip = sql.exec(`SELECT id, parent FROM items WHERE name='clip.mov';`).one();
      expect(String(proj.id)).toMatch(/^ino-/);
      expect(String(clip.id)).toMatch(/^ino-/);
      // parent pointers were rewritten to the NEW ids.
      expect(String(proj.parent)).toBe("root");
      expect(String(clip.parent)).toBe(String(proj.id));

      const projId = String(proj.id);
      const clipId = String(clip.id);
      // every reference now points at the new opaque ids — none left at the legacy path id.
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM blocks WHERE item_id=?;`, clipId).one().c)).toBe(1);
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM blocks WHERE item_id='root/proj/clip.mov';`).one().c)).toBe(0);
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM grants WHERE inode_id=?;`, projId).one().c)).toBe(1);
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM locks WHERE path=?;`, clipId).one().c)).toBe(1);
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM snapshot_items WHERE item_id=? AND parent=?;`, clipId, projId).one().c)).toBe(1);
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM snapshot_blocks WHERE item_id=?;`, clipId).one().c)).toBe(1);
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM uploads WHERE item_id=?;`, clipId).one().c)).toBe(1);
    });
  });

  it("is IDEMPOTENT: a second run is a no-op (opaque ids map to themselves)", async () => {
    await withSql("mig-idempotent", async (sql) => {
      seedLegacyTree(sql);
      migrateToOpaqueIds(sql);
      const snapshot = () => sql.exec(`SELECT id, parent, name FROM items ORDER BY name;`).toArray().map((r) => `${r.id}|${r.parent}|${r.name}`);
      const after1 = snapshot();
      // Run again — nothing path-derived remains, so the rows are unchanged.
      migrateToOpaqueIds(sql);
      const after2 = snapshot();
      expect(after2).toEqual(after1);
    });
  });

  it("a fresh DO (no path-derived rows) is untouched by the migration", async () => {
    await withSql("mig-fresh", async (sql) => {
      // Only the root anchor + an already-opaque id.
      sql.exec(`INSERT OR REPLACE INTO items (id,parent,name,is_dir,size,content_version,etag,version,created_seq,updated_seq,deleted) VALUES ('root',NULL,'',1,0,'cv',NULL,1,1,1,0);`);
      sql.exec(`INSERT OR REPLACE INTO items (id,parent,name,is_dir,size,content_version,etag,version,created_seq,updated_seq,deleted) VALUES ('ino-abc','root','x',0,0,'cv',NULL,1,1,1,0);`);
      migrateToOpaqueIds(sql);
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM items WHERE id='ino-abc';`).one().c)).toBe(1);
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM items WHERE id='root';`).one().c)).toBe(1);
    });
  });
});

describe("B17: NamespaceStore.rename (the real move RPC)", () => {
  it("renames in place (single-row (parent,name) update, no descendant rewrite)", async () => {
    await withSql("ren-basic", async (sql) => {
      const ns = new NamespaceStore(sql);
      const dir = ns.put("root", "dir", true, 0);
      const f = ns.put(dir.id, "old.mov", false, 0);
      const child = f.id;
      const moved = ns.rename(child, { name: "new.mov" });
      expect(moved.id).toBe(child); // SAME id — opaque + immutable
      expect(moved.name).toBe("new.mov");
      expect(moved.version).toBe(f.version + 1);
      // descendant relationships unchanged (parent still dir).
      expect(moved.parent).toBe(dir.id);
    });
  });

  it("moves a file to a new parent (only the moved node's parent changes)", async () => {
    await withSql("ren-move", async (sql) => {
      const ns = new NamespaceStore(sql);
      const a = ns.put("root", "a", true, 0);
      const b = ns.put("root", "b", true, 0);
      const f = ns.put(a.id, "f.mov", false, 0);
      const moved = ns.rename(f.id, { parent: b.id });
      expect(moved.parent).toBe(b.id);
      expect(moved.name).toBe("f.mov");
      // f is now under b, not a.
      expect(ns.liveSiblingByName(b.id, "f.mov")?.id).toBe(f.id);
      expect(ns.liveSiblingByName(a.id, "f.mov")).toBeNull();
    });
  });

  it("rejects a move that collides with a live sibling at the destination", async () => {
    await withSql("ren-collision", async (sql) => {
      const ns = new NamespaceStore(sql);
      const dir = ns.put("root", "dir", true, 0);
      ns.put(dir.id, "taken.mov", false, 0);
      const other = ns.put(dir.id, "free.mov", false, 0);
      expect(() => ns.rename(other.id, { name: "taken.mov" })).toThrow(NameCollisionError);
    });
  });

  it("rejects moving a directory into its own subtree (cycle guard)", async () => {
    await withSql("ren-cycle", async (sql) => {
      const ns = new NamespaceStore(sql);
      const parent = ns.put("root", "parent", true, 0);
      const childDir = ns.put(parent.id, "child", true, 0);
      expect(() => ns.rename(parent.id, { parent: childDir.id })).toThrow(InvalidMoveError);
    });
  });

  it("a no-op rename (same parent+name) does not bump the version", async () => {
    await withSql("ren-noop", async (sql) => {
      const ns = new NamespaceStore(sql);
      const f = ns.put("root", "x.mov", false, 0);
      const same = ns.rename(f.id, { name: "x.mov" });
      expect(same.version).toBe(f.version);
    });
  });
});

describe("B17: (parent,name) uniqueness + opaque-id put semantics", () => {
  it("two creates of the same (parent,name) upsert the SAME live row (one id)", async () => {
    await withSql("uniq-upsert", async (sql) => {
      const ns = new NamespaceStore(sql);
      const a = ns.put("root", "dup.mov", false, 1);
      const b = ns.put("root", "dup.mov", false, 2);
      expect(b.id).toBe(a.id); // same live row
      expect(Number(sql.exec(`SELECT COUNT(*) AS c FROM items WHERE parent='root' AND name='dup.mov' AND deleted=0;`).one().c)).toBe(1);
    });
  });

  it("a recreate over a tombstone gets a BRAND-NEW id (no resurrection)", async () => {
    await withSql("uniq-recreate", async (sql) => {
      const ns = new NamespaceStore(sql);
      const orig = ns.put("root", "gone.mov", false, 1);
      ns.remove(orig.id);
      const fresh = ns.put("root", "gone.mov", false, 1);
      expect(fresh.id).not.toBe(orig.id);
      expect(fresh.id).toMatch(/^ino-/);
    });
  });
});
