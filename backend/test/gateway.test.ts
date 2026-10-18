// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env } from "cloudflare:test";
import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import { mintToken, type Scope } from "../src/security/auth";

// Round-2 integration: the gateway now authenticates signed bearer tokens, is
// org-namespaced (DO = `org::space`), and enforces scope + per-folder ACL. These
// helpers mint real tokens for the functional metadata-plane suites.

const ORG = "org1";
const ALL_SCOPES: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];

/// Provision a user in this org's OrgDO with the given role and return its id, so
/// `toAclPrincipal` resolves the role (admin short-circuits the ACL evaluator).
async function provisionUser(orgId: string, role: string): Promise<string> {
  const org = (env as any).ORG_DO.getByName(orgId);
  const u = await org.createUser({
    orgId, email: `${role}-${crypto.randomUUID()}@test.local`, displayName: role, role,
  });
  return u.id;
}

/// Mint a bearer token for a principal bound to (org, space) with given scopes.
async function token(opts: { sub: string; orgId?: string; spaceId?: string; scopes?: Scope[]; type?: "session" | "service" }): Promise<string> {
  return mintToken((env as any).AUTH_SIGNING_SECRET, {
    sub: opts.sub,
    type: opts.type ?? "session",
    orgId: opts.orgId ?? ORG,
    spaceId: opts.spaceId,
    scopes: opts.scopes ?? ALL_SCOPES,
    ttlSeconds: 900,
  });
}

// Default admin token for the functional suites (org1, all scopes, admin role).
let ADMIN: string;
let AUTH: Record<string, string>;
const FS = `https://gw.local/v1/filespaces/fs1`;

beforeAll(async () => {
  const adminId = await provisionUser(ORG, "admin");
  ADMIN = await token({ sub: adminId });
  AUTH = { Authorization: `Bearer ${ADMIN}`, "content-type": "application/json" };
});

async function get(path: string) {
  return SELF.fetch(`${FS}${path}`, { headers: AUTH });
}
async function send(method: string, path: string, body?: unknown) {
  return SELF.fetch(`${FS}${path}`, { method, headers: AUTH, body: body ? JSON.stringify(body) : undefined });
}

describe("auth", () => {
  it("rejects requests without the bearer token", async () => {
    const res = await SELF.fetch(`${FS}/items?parent=root`);
    expect(res.status).toBe(401);
  });
});

describe("metadata authority (Durable Object)", () => {
  it("enumerates the seeded root", async () => {
    const res = await get("/items?parent=root");
    expect(res.status).toBe(200);
    // GET /items now returns a paginated page: { items, cursor }.
    const page = (await res.json()) as { items: any[]; cursor: string | null };
    const names = page.items.map((i) => i.name).sort();
    expect(names).toContain("Project A");
    expect(names).toContain("Archive");
  });

  it("enumerates a subfolder and reports a large media file", async () => {
    const page = (await (await get("/items?parent=projectA")).json()) as { items: any[] };
    const clip = page.items.find((i) => i.name === "A001.mov");
    expect(clip).toBeTruthy();
    expect(clip.isDir).toBe(false);
    expect(clip.size).toBeGreaterThan(2_000_000_000); // ~2 GB ProRes
    expect(clip.contentVersion).toMatch(/^cv-/);
    expect(clip.version).toBeGreaterThanOrEqual(1); // optimistic-concurrency token
  });

  it("creates an item, which then appears in enumerate AND in the change feed", async () => {
    const before = (await (await get("/changes?since=0")).json()) as any;
    const created = (await (await send("POST", "/items", { parent: "projectA", name: "render_v2.mov", size: 500 })).json()) as any;
    // Audit B17: ids are now OPAQUE (ino-<uuid>), not path-derived. The client uses the returned id.
    expect(typeof created.id).toBe("string");
    expect(created.id).toMatch(/^ino-/);
    expect(created.parent).toBe("projectA");
    expect(created.name).toBe("render_v2.mov");
    expect(created.updatedSeq).toBeGreaterThan(0);

    const listed = (await (await get("/items?parent=projectA")).json()) as { items: any[] };
    expect(listed.items.map((i) => i.name)).toContain("render_v2.mov");

    const after = (await (await get("/changes?since=0")).json()) as any;
    expect(after.anchor).toBeGreaterThan(before.anchor);
    expect(after.items.map((i: any) => i.name)).toContain("render_v2.mov");
  });
});

describe("file locking / leases", () => {
  // Owner is now the AUTHENTICATED principal (F6), not a request-body string, so
  // a second editor = a second principal. Two admin-role principals are both
  // authorized (ACL short-circuit), and lock ownership distinguishes them.
  let aliceAuth: Record<string, string>;
  let bobAuth: Record<string, string>;
  let aliceId: string;
  let bobId: string;
  beforeAll(async () => {
    aliceId = await provisionUser(ORG, "admin");
    bobId = await provisionUser(ORG, "admin");
    aliceAuth = { Authorization: `Bearer ${await token({ sub: aliceId })}`, "content-type": "application/json" };
    bobAuth = { Authorization: `Bearer ${await token({ sub: bobId })}`, "content-type": "application/json" };
  });
  const sendAs = (auth: Record<string, string>, method: string, path: string, body?: unknown) =>
    SELF.fetch(`${FS}${path}`, { method, headers: auth, body: body ? JSON.stringify(body) : undefined });

  it("grants a lock, blocks a second owner, frees on release", async () => {
    const path = "/Project A/timeline.prproj";

    const a = (await (await sendAs(aliceAuth, "POST", "/locks", { path, ttlMs: 30_000 })).json()) as any;
    expect(a.granted).toBe(true);
    expect(a.owner).toBe(aliceId); // owner = authenticated principal, not body

    const b = (await (await sendAs(bobAuth, "POST", "/locks", { path, ttlMs: 30_000 })).json()) as any;
    expect(b.granted).toBe(false);
    expect(b.heldBy).toBe(aliceId);

    const status = (await (await sendAs(bobAuth, "GET", `/locks?path=${encodeURIComponent(path)}`)).json()) as any;
    expect(status.heldBy).toBe(aliceId);

    const rel = (await (await sendAs(aliceAuth, "DELETE", `/locks?path=${encodeURIComponent(path)}`)).json()) as any;
    expect(rel.released).toBe(true);

    const b2 = (await (await sendAs(bobAuth, "POST", "/locks", { path, ttlMs: 30_000 })).json()) as any;
    expect(b2.granted).toBe(true); // alice released → bob can take it
  });

  it("auto-expires a lease (crashed-client safety)", async () => {
    const path = "/Project A/expiring.prproj";
    // Alice stops renewing a short positive lease (invalid durations are rejected).
    const a = (await (await sendAs(aliceAuth, "POST", "/locks", { path, ttlMs: 1 })).json()) as any;
    expect(a.granted).toBe(true);
    await new Promise(resolve => setTimeout(resolve, 10));
    // bob acquires: the expired lease is swept, so bob wins without alice releasing.
    const b = (await (await sendAs(bobAuth, "POST", "/locks", { path, ttlMs: 30_000 })).json()) as any;
    expect(b.granted).toBe(true);
    expect(b.owner).toBe(bobId);
  });

  it("refuses to release a lock you do not own (owner = authenticated principal)", async () => {
    const path = "/Project A/owned.prproj";
    await sendAs(aliceAuth, "POST", "/locks", { path, ttlMs: 30_000 });
    // mallory (bob here) cannot release alice's lock — the gateway derives owner
    // from the token, so there's no way to spoof alice's ownership.
    const rel = (await (await sendAs(bobAuth, "DELETE", `/locks?path=${encodeURIComponent(path)}`)).json()) as any;
    expect(rel.released).toBe(false);
  });
});

describe("presigned URL minting (direct client↔bucket streaming)", () => {
  // Keys are now confined to the space prefix `blocks/<org>::<space>/...` (F8);
  // a PUT to a not-yet-in-namespace key under the prefix is allowed (first upload).
  const KEY = "blocks/org1::fs1/ab/abcdef0123";

  it("returns a SigV4 presigned URL for a block key under the space prefix", async () => {
    const res = await send("POST", "/presign", { key: KEY, method: "PUT", expiresIn: 300 });
    expect(res.status).toBe(200);
    const { url } = (await res.json()) as { url: string };
    expect(url).toContain("X-Amz-Signature=");
    expect(url).toContain("X-Amz-Credential=");
    expect(url).toContain("X-Amz-Expires=300");
    expect(url).toContain(`/cloudfs/${KEY}`);
  });

  it("clamps an over-long client TTL to the 900s ceiling (F3/F8)", async () => {
    const res = await send("POST", "/presign", { key: KEY, method: "PUT", expiresIn: 604_800 });
    expect(res.status).toBe(200);
    const { expiresIn, url } = (await res.json()) as { expiresIn: number; url: string };
    expect(expiresIn).toBe(900);
    expect(url).toContain("X-Amz-Expires=900");
  });

  it("rejects a key that escapes the space prefix (cross-space confinement)", async () => {
    const res = await send("POST", "/presign", { key: "blocks/org1::other/secret", method: "GET" });
    expect(res.status).toBe(403);
  });

  it("rejects a disallowed method", async () => {
    const res = await send("POST", "/presign", { key: KEY, method: "DELETE" });
    expect(res.status).toBe(405);
  });
});

// ===========================================================================
// New metadata-plane coverage: pagination at scale, optimistic concurrency,
// block maps, resumable uploads, fencing/lease hardening, snapshots+retention.
// Each suite uses its own filespace id so DO SQLite state is isolated.
// ===========================================================================

function fsAt(id: string) {
  const base = `https://gw.local/v1/filespaces/${id}`;
  const send = (method: string, path: string, body?: unknown) =>
    SELF.fetch(`${base}${path}`, { method, headers: AUTH, body: body ? JSON.stringify(body) : undefined });
  return {
    get: (path: string) => SELF.fetch(`${base}${path}`, { headers: AUTH }),
    send,
    // Audit B17: create an item and return its OPAQUE id (clients no longer construct path ids).
    create: async (parent: string, name: string, extra: Record<string, unknown> = {}): Promise<string> =>
      ((await (await send("POST", "/items", { parent, name, size: 0, ...extra })).json()) as any).id as string,
  };
}

describe("large-directory pagination (cursors, never loads whole tree)", () => {
  const api = fsAt("fs-bigdir");
  const N = 2500; // a "huge" directory of camera-roll clips

  it("seeds a large directory and pages through it with keyset cursors", async () => {
    // Seed via the DO RPC path (a POST seam used for benchmarks/tests).
    const seeded = (await (await api.send("POST", "/items/_seed", {
      parent: "root", prefix: "clip-", count: N,
    })).json()) as { created: number };
    expect(seeded.created).toBe(N);

    const count = (await (await api.get("/items/_count?parent=root")).json()) as { count: number };
    expect(count.count).toBeGreaterThanOrEqual(N);

    // Walk the whole directory in pages of 500; assert no dup/skip and that
    // each page is bounded (we never pull all N rows in one response).
    const seen = new Set<string>();
    let cursor: string | null = null;
    let pages = 0;
    do {
      const url = `/items?parent=root&limit=500${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
      const response = await api.get(url);
      expect(response.status, await response.clone().text()).toBe(200);
      const page = (await response.json()) as { items: any[]; cursor: string | null };
      expect(page.items.length).toBeLessThanOrEqual(500);
      for (const it of page.items) {
        expect(seen.has(it.id)).toBe(false); // no duplicates across pages
        seen.add(it.id);
      }
      cursor = page.cursor;
      pages++;
      expect(pages).toBeLessThan(20); // sanity: terminates
    } while (cursor);

    // root also has the 2 seeded dirs (Project A, Archive); all are paged exactly once.
    expect(seen.size).toBe(N + 2);
    expect(pages).toBeGreaterThanOrEqual(5); // proved it actually paginated
  });

  it("orders directories before files, stable across the cursor boundary", async () => {
    const api2 = fsAt("fs-order");
    await api2.send("POST", "/items", { parent: "root", name: "zfolder", isDir: true });
    await api2.send("POST", "/items", { parent: "root", name: "afile.mov", isDir: false });
    const page = (await (await api2.get("/items?parent=root")).json()) as { items: any[] };
    const idxFolder = page.items.findIndex((i) => i.name === "zfolder");
    const idxFile = page.items.findIndex((i) => i.name === "afile.mov");
    expect(idxFolder).toBeGreaterThanOrEqual(0);
    expect(idxFolder).toBeLessThan(idxFile); // dirs sort before files regardless of name
  });
});

describe("optimistic concurrency (project-file anti-clobber, SPEC §5.5)", () => {
  const api = fsAt("fs-occ");

  it("rejects a stale write with 409 and accepts the current version", async () => {
    const v1 = (await (await api.send("POST", "/items", { parent: "root", name: "edit.prproj", size: 100 })).json()) as any;
    expect(v1.version).toBe(1);

    // Two editors both read v1, both try to write expecting version 1.
    const okRes = await api.send("POST", "/items", { parent: "root", name: "edit.prproj", size: 200, expectedVersion: 1 });
    expect(okRes.status).toBe(201);
    const v2 = (await okRes.json()) as any;
    expect(v2.version).toBe(2);

    // The second editor's write (still expecting version 1) is a conflict.
    const conflict = await api.send("POST", "/items", { parent: "root", name: "edit.prproj", size: 300, expectedVersion: 1 });
    expect(conflict.status).toBe(409);
    const body = (await conflict.json()) as any;
    expect(body.conflict).toBe(true);
  });

  it("tombstones a deleted item and surfaces it in the change feed", async () => {
    const trashId = await api.create("root", "trash.mov", { size: 1 });
    const before = (await (await api.get("/changes?since=0")).json()) as any;
    const del = (await (await api.send("DELETE", `/items/${encodeURIComponent(trashId)}`)).json()) as any;
    expect(del.deleted).toBe(true);
    // Gone from the live listing...
    const listed = (await (await api.get("/items?parent=root")).json()) as { items: any[] };
    expect(listed.items.map((i) => i.name)).not.toContain("trash.mov");
    // ...but the tombstone propagates through the change feed.
    const after = (await (await api.get("/changes?since=0")).json()) as any;
    expect(after.anchor).toBeGreaterThan(before.anchor);
    const tomb = after.items.find((i: any) => i.id === trashId);
    expect(tomb?.deleted).toBe(true);
  });
});

describe("large-file block map + resumable multipart upload", () => {
  const api = fsAt("fs-largefile");

  it("stores and returns an ordered content-addressed block map", async () => {
    const r3dId = await api.create("root", "A002.r3d");
    const r3dPath = `/blocks/${encodeURIComponent(r3dId)}`;
    const blocks = [
      { chunkIdx: 0, blockIdx: 0, blockHash: "h0", objectKey: "blocks/org1::fs-largefile/0/0/0/0", offset: 0, length: 4_194_304 },
      { chunkIdx: 0, blockIdx: 1, blockHash: "h1", objectKey: "blocks/org1::fs-largefile/0/0/0/1", offset: 4_194_304, length: 4_194_304 },
      { chunkIdx: 1, blockIdx: 0, blockHash: "h2", objectKey: "blocks/org1::fs-largefile/0/0/1/0", offset: 8_388_608, length: 1_000_000 },
    ];
    const item = (await (await api.send("PUT", r3dPath, { blocks })).json()) as any;
    expect(item.size).toBe(4_194_304 + 4_194_304 + 1_000_000); // size derived from block lengths

    const map = (await (await api.get(r3dPath)).json()) as any[];
    expect(map).toHaveLength(3);
    expect(map[0].blockHash).toBe("h0");
    expect(map[2].chunkIdx).toBe(1); // ordered by (chunk, block)
  });

  it("resumes an interrupted multipart upload by reporting only missing parts", async () => {
    const totalSize = 250_000_000; // 250 MB → multipart
    const partSize = 50_000_000; // 5 parts
    const huge = await (await api.send("POST", "/items", { parent: "root", name: "huge.mov", size: 0 })).json() as { id: string };
    await api.send("POST", "/uploads", { uploadId: "u1", itemId: huge.id, key: "blocks/u1", totalSize, partSize });

    // Client uploads parts 1, 2, 4 then crashes; idempotent re-report of part 2.
    for (const n of [1, 2, 4, 2]) {
      await api.send("PUT", "/uploads/u1/parts", { partNumber: n, etag: `etag-${n}`, size: partSize });
    }
    const status = (await (await api.get("/uploads/u1")).json()) as { session: any; missing: number[] };
    expect(status.session.uploadedParts).toHaveLength(3); // dedup: part 2 not doubled
    expect(status.missing).toEqual([3, 5]); // exactly the gaps to re-PUT on resume

    // Completing before all parts land is a typed 409, not a silent success.
    const early = await api.send("POST", "/uploads/u1/complete", { etag: "final" });
    expect(early.status).toBe(409);

    // Fill the gaps, then complete succeeds.
    await api.send("PUT", "/uploads/u1/parts", { partNumber: 3, etag: "etag-3", size: partSize });
    await api.send("PUT", "/uploads/u1/parts", { partNumber: 5, etag: "etag-5", size: 50_000_000 });
    const done = await api.send("POST", "/uploads/u1/complete", { etag: "final" });
    expect(done.status).toBe(200);
    expect(((await done.json()) as any).completed).toBe(true);
  });
});

// ===========================================================================
// Audit B4 + B5: the content-commit path (PUT /blocks) now carries optimistic
// concurrency (expectedVersion → 409) AND the lock-enforcement gate (a live
// exclusive lease by another editor rejects a clobbering write/delete/create).
// These run against the FULL real Worker (SELF.fetch → index.ts → real DOs), so
// a green mock could not have hidden the bug the audit found.
// ===========================================================================
// Audit B18 — Unicode/name canonicalization at the write boundary: macOS sends NFD, web/CLI
// send NFC; without normalization the same visible name becomes two distinct ids (the canonical
// cross-platform sync bug). Names are NFC-normalized + validated (B17) on create.
describe("B18: name canonicalization (NFC) + validation on createItem", () => {
  const api = fsAt("fs-b18-names");
  // "café" composed (NFC: e+U+0301 → é) vs decomposed (NFD: e + combining acute).
  const NFC = "café.txt";        // café (single é)
  const NFD = "café.txt";       // café (e + combining accent)

  it("an NFD name and an NFC name collapse to ONE item id (no duplicate row)", async () => {
    const a = (await (await api.send("POST", "/items", { parent: "root", name: NFD, size: 1 })).json()) as any;
    // Audit B17: the id is opaque; the stored NAME is the NFC form.
    expect(a.id).toMatch(/^ino-/);
    expect(a.name).toBe(NFC);
    // Re-creating with the NFC spelling targets the SAME row (live-sibling upsert, not a new id).
    const b = (await (await api.send("POST", "/items", { parent: "root", name: NFC, size: 2 })).json()) as any;
    expect(b.id).toBe(a.id);
    const list = (await (await api.get("/items?parent=root")).json()) as { items: any[] };
    const matches = list.items.filter((i) => i.name === NFC);
    expect(matches).toHaveLength(1); // exactly one row, not two
  });

  it("rejects a name containing a path separator (400 invalid_name)", async () => {
    const res = await api.send("POST", "/items", { parent: "root", name: "a/b.txt", size: 1 });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error).toBe("invalid_name");
  });

  it("rejects the reserved names '.' and '..'", async () => {
    expect((await api.send("POST", "/items", { parent: "root", name: ".", size: 0 })).status).toBe(400);
    expect((await api.send("POST", "/items", { parent: "root", name: "..", size: 0 })).status).toBe(400);
  });

  it("rejects an empty name", async () => {
    expect((await api.send("POST", "/items", { parent: "root", name: "", size: 0 })).status).toBe(400);
  });
});

// Audit B17 — the real rename/move RPC (PATCH /items/:id {parent?, name?}). Opaque ids make this
// a single-row update; the id is STABLE across the rename, so a file's encrypted blocks stay valid.
// Audit B28 — GET /grants lists grants (the route the CLI `permission list` + Mac app needed; it
// was missing before, so both 404'd / stubbed to []).
describe("B28: GET /grants lists grants", () => {
  const api = fsAt("fs-b28-grants");
  it("lists grants for an inode and (unscoped) for the whole space", async () => {
    const dir = await api.create("root", "shared", { isDir: true });
    const userId = await provisionUser(ORG, "standard");
    await api.send("POST", "/grants", { inodeId: dir, principalType: "user", principalId: userId, level: "read" });
    // Scoped to the inode.
    const forInode = (await (await api.get(`/grants?inodeId=${encodeURIComponent(dir)}`)).json()) as { grants: any[] };
    expect(forInode.grants).toHaveLength(1);
    expect(forInode.grants[0].principalId).toBe(userId);
    expect(forInode.grants[0].inodeId).toBe(dir);
    expect(forInode.grants[0].level).toBe("read");
    // Unscoped: lists every grant in the space (includes the one we added).
    const all = (await (await api.get("/grants")).json()) as { grants: any[] };
    expect(all.grants.some((g) => g.principalId === userId && g.inodeId === dir)).toBe(true);
  });
});

describe("B17: rename/move (PATCH /items/:id) keeps the opaque id stable", () => {
  const api = fsAt("fs-b17-rename");

  it("renames a file in place: id unchanged, name updated, blocks intact, read-back works", async () => {
    const id = await api.create("root", "old.mov");
    // Seed a block map so we can prove the blocks survive the rename (id is stable).
    await api.send("PUT", `/blocks/${encodeURIComponent(id)}`, {
      blocks: [{ chunkIdx: 0, blockIdx: 0, blockHash: "h", objectKey: `blocks/org1::fs-b17-rename/0`, offset: 0, length: 5 }],
    });
    const res = await api.send("PATCH", `/items/${encodeURIComponent(id)}`, { name: "new.mov" });
    expect(res.status).toBe(200);
    const moved = (await res.json()) as any;
    expect(moved.id).toBe(id); // SAME id — opaque + immutable
    expect(moved.name).toBe("new.mov");
    // The block map is still addressable by the SAME id (the file's content survived the rename).
    const map = (await (await api.get(`/blocks/${encodeURIComponent(id)}`)).json()) as any[];
    expect(map).toHaveLength(1);
    expect(map[0].blockHash).toBe("h");
    // The new name shows up in the listing; the old name is gone.
    const list = (await (await api.get("/items?parent=root")).json()) as { items: any[] };
    const names = list.items.map((i) => i.name);
    expect(names).toContain("new.mov");
    expect(names).not.toContain("old.mov");
  });

  it("moves a file to a new parent (only the moved node's parent changes; subtree intact)", async () => {
    const a = await api.create("root", "a", { isDir: true });
    const b = await api.create("root", "b", { isDir: true });
    const f = await api.create(a, "f.mov");
    const res = await api.send("PATCH", `/items/${encodeURIComponent(f)}`, { parent: b });
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).parent).toBe(b);
    // f is under b now, not a.
    const inB = (await (await api.get(`/items?parent=${encodeURIComponent(b)}`)).json()) as { items: any[] };
    expect(inB.items.map((i) => i.name)).toContain("f.mov");
    const inA = (await (await api.get(`/items?parent=${encodeURIComponent(a)}`)).json()) as { items: any[] };
    expect(inA.items.map((i) => i.name)).not.toContain("f.mov");
  });

  it("renames a NON-EMPTY directory: children keep their ids (no descendant rewrite)", async () => {
    const dir = await api.create("root", "showA", { isDir: true });
    const child1 = await api.create(dir, "clip1.mov");
    const child2 = await api.create(dir, "clip2.mov");
    const res = await api.send("PATCH", `/items/${encodeURIComponent(dir)}`, { name: "showB" });
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).id).toBe(dir);
    // The directory's children are unchanged (same ids, same parent pointer = dir).
    const kids = (await (await api.get(`/items?parent=${encodeURIComponent(dir)}`)).json()) as { items: any[] };
    expect(kids.items.map((i) => i.id).sort()).toEqual([child1, child2].sort());
  });

  it("rejects a rename that collides with a live sibling (409 name_collision)", async () => {
    const taken = await api.create("root", "taken.mov");
    void taken;
    const free = await api.create("root", "free.mov");
    const res = await api.send("PATCH", `/items/${encodeURIComponent(free)}`, { name: "taken.mov" });
    expect(res.status).toBe(409);
    expect((await res.json() as any).error).toBe("name_collision");
  });

  it("rejects an invalid new name (400 invalid_name)", async () => {
    const id = await api.create("root", "valid.mov");
    const res = await api.send("PATCH", `/items/${encodeURIComponent(id)}`, { name: "a/b.mov" });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error).toBe("invalid_name");
  });

  it("rejects moving a directory into its own subtree (400 invalid_move)", async () => {
    const parent = await api.create("root", "parentDir", { isDir: true });
    const child = await api.create(parent, "childDir", { isDir: true });
    const res = await api.send("PATCH", `/items/${encodeURIComponent(parent)}`, { parent: child });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error).toBe("invalid_move");
  });

  it("404s for an unknown item id", async () => {
    const res = await api.send("PATCH", `/items/ino-does-not-exist`, { name: "x.mov" });
    expect(res.status).toBe(404);
  });
});

describe("B4: content-commit optimistic concurrency (PUT /blocks anti-clobber)", () => {
  const api = fsAt("fs-b4-cas");
  const oneBlock = (key: string, len: number) => [
    { chunkIdx: 0, blockIdx: 0, blockHash: `h-${key}`, objectKey: `blocks/org1::fs-b4-cas/${key}`, offset: 0, length: len },
  ];

  it("second concurrent commit at the same base version gets 409; the first survives", async () => {
    const created = (await (await api.send("POST", "/items", { parent: "root", name: "timeline.prproj", size: 0 })).json()) as any;
    // Audit B17: the id is opaque — address the item by its returned id.
    const itemPath = `/blocks/${encodeURIComponent(created.id)}`;
    const base = created.version;

    // Editor A commits first at base version → succeeds, bumps the version.
    const aRes = await api.send("PUT", itemPath, { blocks: oneBlock("A", 100), expectedVersion: base });
    expect(aRes.status).toBe(200);
    const aItem = (await aRes.json()) as any;
    expect(aItem.version).toBe(base + 1);

    // Editor B commits second, still expecting `base` → 409, A's content survives.
    const bRes = await api.send("PUT", itemPath, { blocks: oneBlock("B", 200), expectedVersion: base });
    expect(bRes.status).toBe(409);
    const bBody = (await bRes.json()) as any;
    expect(bBody.conflict).toBe(true);
    expect(bBody.expected).toBe(base);
    expect(bBody.actual).toBe(base + 1);

    // The bucket map still points at A's block, not B's — the loser did NOT clobber.
    const map = (await (await api.get(itemPath)).json()) as any[];
    expect(map).toHaveLength(1);
    expect(map[0].objectKey).toContain("/A");
    expect(map[0].length).toBe(100);
  });

  it("force:true performs an explicit replace (skips the version check)", async () => {
    const created = (await (await api.send("POST", "/items", { parent: "root", name: "replace.prproj", size: 0 })).json()) as any;
    const itemPath = `/blocks/${encodeURIComponent(created.id)}`;
    const base = created.version;
    // Bump once so the stored version is ahead of `base`.
    await api.send("PUT", itemPath, { blocks: oneBlock("v1", 10), expectedVersion: base });
    // A stale expectedVersion would 409 — but force:true overrides it.
    const forced = await api.send("PUT", itemPath, { blocks: oneBlock("v2", 20), expectedVersion: base, force: true });
    expect(forced.status).toBe(200);
    const map = (await (await api.get(itemPath)).json()) as any[];
    expect(map[0].objectKey).toContain("/v2");
  });

  it("a commit WITHOUT expectedVersion is still accepted (back-compat: opt-in CAS)", async () => {
    const created = (await (await api.send("POST", "/items", { parent: "root", name: "loose.prproj", size: 0 })).json()) as any;
    const res = await api.send("PUT", `/blocks/${encodeURIComponent(created.id)}`, { blocks: oneBlock("x", 5) });
    expect(res.status).toBe(200);
  });
});

describe("B5: lock enforcement on the mutation chokepoints (the differentiator)", () => {
  const SPACE = "fs-b5-locks";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;
  let aliceAuth: Record<string, string>;
  let bobAuth: Record<string, string>;
  let aliceId: string;
  let bobId: string;
  beforeAll(async () => {
    aliceId = await provisionUser(ORG, "admin");
    bobId = await provisionUser(ORG, "admin");
    aliceAuth = { Authorization: `Bearer ${await token({ sub: aliceId })}`, "content-type": "application/json" };
    bobAuth = { Authorization: `Bearer ${await token({ sub: bobId })}`, "content-type": "application/json" };
  });
  const sendAs = (auth: Record<string, string>, method: string, path: string, body?: unknown) =>
    SELF.fetch(`${base}${path}`, { method, headers: auth, body: body ? JSON.stringify(body) : undefined });
  const oneBlock = (key: string, len: number) => [
    { chunkIdx: 0, blockIdx: 0, blockHash: `h-${key}`, objectKey: `blocks/org1::${SPACE}/${key}`, offset: 0, length: len },
  ];

  // Audit B17: lock by the item's OPAQUE id (the daemon's convention), captured from create.
  const createItem = async (auth: Record<string, string>, parent: string, name: string, extra: Record<string, unknown> = {}) =>
    ((await (await sendAs(auth, "POST", "/items", { parent, name, size: 0, ...extra })).json()) as any).id as string;

  it("an exclusive lease blocks a SECOND editor's block-map commit (409 locked)", async () => {
    const id = await createItem(aliceAuth, "root", "leased.prproj");
    // Alice takes an exclusive lease on the inode id (the lock key the daemon uses).
    const lock = (await (await sendAs(aliceAuth, "POST", "/locks", { path: id, ttlMs: 30_000 })).json()) as any;
    expect(lock.granted).toBe(true);

    // Bob tries to commit a new block map over Alice's locked file → 409 locked.
    const bob = await sendAs(bobAuth, "PUT", `/blocks/${encodeURIComponent(id)}`, { blocks: oneBlock("bob", 50) });
    expect(bob.status).toBe(409);
    const body = (await bob.json()) as any;
    expect(body.locked).toBe(true);
    expect(body.heldBy).toBe(aliceId);

    // Alice (the holder) can still commit her own changes.
    const alice = await sendAs(aliceAuth, "PUT", `/blocks/${encodeURIComponent(id)}`, { blocks: oneBlock("alice", 60) });
    expect(alice.status).toBe(200);

    // After Alice releases, Bob's commit is accepted.
    await sendAs(aliceAuth, "DELETE", `/locks?path=${encodeURIComponent(id)}`);
    const bob2 = await sendAs(bobAuth, "PUT", `/blocks/${encodeURIComponent(id)}`, { blocks: oneBlock("bob2", 70) });
    expect(bob2.status).toBe(200);
  });

  it("an exclusive lease blocks a SECOND editor's delete (409 locked)", async () => {
    const id = await createItem(aliceAuth, "root", "dontdelete.prproj");
    await sendAs(aliceAuth, "POST", "/locks", { path: id, ttlMs: 30_000 });

    const bob = await sendAs(bobAuth, "DELETE", `/items/${encodeURIComponent(id)}`);
    expect(bob.status).toBe(409);
    expect(((await bob.json()) as any).heldBy).toBe(aliceId);

    // The holder may delete their own locked item.
    const alice = await sendAs(aliceAuth, "DELETE", `/items/${encodeURIComponent(id)}`);
    expect(alice.status).toBe(200);
  });

  it("a recursive (subtree) delete is rejected if any descendant is leased by another", async () => {
    const showId = await createItem(aliceAuth, "root", "show", { isDir: true });
    const sceneId = await createItem(aliceAuth, showId, "scene.prproj");
    await sendAs(aliceAuth, "POST", "/locks", { path: sceneId, ttlMs: 30_000 });

    const bob = await sendAs(bobAuth, "DELETE", `/items/${encodeURIComponent(showId)}?recursive=true`);
    expect(bob.status).toBe(409);
  });

  it("GET /locks does NOT leak the live fence to a non-holder (capability privacy)", async () => {
    const id = await createItem(aliceAuth, "root", "private.prproj");
    const acquired = (await (await sendAs(aliceAuth, "POST", "/locks", { path: id, ttlMs: 30_000 })).json()) as any;
    expect(typeof acquired.fence).toBe("number"); // the holder receives the fence

    // Bob (not the holder) sees the badge fields but NOT the fence.
    const bobView = (await (await sendAs(bobAuth, "GET", `/locks?path=${encodeURIComponent(id)}`)).json()) as any;
    expect(bobView.heldBy).toBe(aliceId);
    expect(bobView.fence).toBeUndefined();

    // The holder still sees their own fence (needed to renew).
    const aliceView = (await (await sendAs(aliceAuth, "GET", `/locks?path=${encodeURIComponent(id)}`)).json()) as any;
    expect(aliceView.fence).toBe(acquired.fence);
  });
});

describe("lock hardening: fencing tokens, idempotent renew, shared/exclusive", () => {
  const SPACE = "fs-locks";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;
  let aliceAuth: Record<string, string>;
  let bobAuth: Record<string, string>;
  let aliceId: string;
  let bobId: string;
  beforeAll(async () => {
    aliceId = await provisionUser(ORG, "admin");
    bobId = await provisionUser(ORG, "admin");
    aliceAuth = { Authorization: `Bearer ${await token({ sub: aliceId })}`, "content-type": "application/json" };
    bobAuth = { Authorization: `Bearer ${await token({ sub: bobId })}`, "content-type": "application/json" };
  });
  const sendAs = (auth: Record<string, string>, path: string, body?: unknown) =>
    SELF.fetch(`${base}${path}`, { method: "POST", headers: auth, body: JSON.stringify(body) });

  it("hands out a monotonic fence and renews idempotently keeping the same token", async () => {
    const path = "/show/cut.prproj";
    const a = (await (await sendAs(aliceAuth, "/locks", { path, ttlMs: 30_000 })).json()) as any;
    expect(a.granted).toBe(true);
    expect(typeof a.fence).toBe("number");

    // Idempotent re-acquire by the same principal keeps the SAME fence (retry-safe).
    const aAgain = (await (await sendAs(aliceAuth, "/locks", { path, ttlMs: 30_000 })).json()) as any;
    expect(aAgain.fence).toBe(a.fence);

    // Explicit renew with the correct fence succeeds.
    const renewed = (await (await sendAs(aliceAuth, "/locks", { path, fence: a.fence, ttlMs: 60_000, renew: true })).json()) as any;
    expect(renewed.granted).toBe(true);
    expect(renewed.fence).toBe(a.fence);

    // Renewing with a stale/wrong fence is rejected with a typed reason.
    const stale = (await (await sendAs(aliceAuth, "/locks", { path, fence: a.fence + 999, ttlMs: 60_000, renew: true })).json()) as any;
    expect(stale.granted).toBe(false);
    expect(stale.reason).toBe("fence-stale");
  });

  it("gives a fresh, higher fence after a lease expires and is reacquired by another owner", async () => {
    const path = "/show/take2.prproj";
    const a = (await (await sendAs(aliceAuth, "/locks", { path, ttlMs: 1 })).json()) as any;
    await new Promise(resolve => setTimeout(resolve, 10));
    const b = (await (await sendAs(bobAuth, "/locks", { path, ttlMs: 30_000 })).json()) as any;
    expect(b.granted).toBe(true);
    expect(b.owner).toBe(bobId);
    expect(b.fence).toBeGreaterThan(a.fence); // fence advanced → alice's old token is now stale
  });

  it("returns a typed conflict reason when another owner holds the lock", async () => {
    const path = "/show/locked.prproj";
    await sendAs(aliceAuth, "/locks", { path, ttlMs: 30_000 });
    const b = (await (await sendAs(bobAuth, "/locks", { path, ttlMs: 30_000 })).json()) as any;
    expect(b.granted).toBe(false);
    expect(b.reason).toBe("held-by-other");
    expect(b.heldBy).toBe(aliceId);
  });
});

describe("snapshots: point-in-time namespace + GFS retention", () => {
  const api = fsAt("fs-snap");

  it("freezes a point in time and browses the directory as-of the snapshot", async () => {
    const beforeId = await api.create("root", "before.mov", { size: 1 });
    const snap = (await (await api.send("POST", "/snapshots", { id: "snap-1", label: "before delete" })).json()) as any;
    expect(snap.seqAnchor).toBeGreaterThan(0);

    // Mutate AFTER the snapshot: add a new file and delete the old one.
    await api.create("root", "after.mov", { size: 1 });
    await api.send("DELETE", `/items/${encodeURIComponent(beforeId)}`);

    // Live listing reflects the mutations.
    const live = (await (await api.get("/items?parent=root")).json()) as { items: any[] };
    const liveNames = live.items.map((i) => i.name);
    expect(liveNames).toContain("after.mov");
    expect(liveNames).not.toContain("before.mov");

    // The snapshot still shows before.mov and not after.mov.
    const asOf = (await (await api.get("/snapshots/snap-1/dir?parent=root")).json()) as any[];
    const snapNames = asOf.map((i) => i.name);
    expect(snapNames).toContain("before.mov"); // existed at the anchor, deleted later
    expect(snapNames).not.toContain("after.mov"); // created after the anchor
  });

  it("registers a schedule and reports it (server-side execution wired to the DO alarm)", async () => {
    const res = await api.send("POST", "/schedules", {
      id: "active-fast", scope: "root", tier: "hourly", intervalMs: 3_600_000, retain: 48,
    });
    expect(res.status).toBe(201);
    // Disable/enable toggle is accepted.
    const patched = await api.send("PATCH", "/schedules/active-fast", { enabled: false });
    expect(patched.status).toBe(200);
  });
});

describe("snapshot RESTORE (server-side, non-destructive, locks + perms enforced)", () => {
  // helper: a block manifest with a single block of `len` bytes at a versioned key
  const manifest = (key: string, len: number) => ({
    blocks: [{ chunkIdx: 0, blockIdx: 0, blockHash: `h-${key}`, objectKey: key, offset: 0, length: len }],
  });

  it("restores a FILE to a prior snapshot's manifest/content pointer (non-destructive)", async () => {
    const api = fsAt("fs-restore-file");
    // v1 content — capture the opaque id (audit B17).
    const cutId = await api.create("root", "cut.mov");
    const cutPath = `/blocks/${encodeURIComponent(cutId)}`;
    await api.send("PUT", cutPath, manifest("blocks/org1::fs-restore-file/v1/0", 100));
    // snapshot freezes v1
    await api.send("POST", "/snapshots", { id: "snap-v1", label: "v1" });
    // v2 content overwrites the manifest in place
    await api.send("PUT", cutPath, manifest("blocks/org1::fs-restore-file/v2/0", 200));
    const beforeRestore = (await (await api.get(cutPath)).json()) as any[];
    expect(beforeRestore[0].objectKey).toContain("/v2/");

    const changesBefore = (await (await api.get("/changes?since=0")).json()) as any;

    // RESTORE the file to snap-v1 (by opaque id)
    const res = await api.send("POST", "/snapshots/snap-v1/restore", { path: cutId });
    expect(res.status).toBe(200);
    const result = (await res.json()) as any;
    expect(result.restored).toContain(cutId);
    expect(result.conflicts).toHaveLength(0);

    // the live manifest now points back at the v1 block (old content pointer restored)
    const afterRestore = (await (await api.get(cutPath)).json()) as any[];
    expect(afterRestore[0].objectKey).toContain("/v1/");
    expect(afterRestore[0].length).toBe(100);

    // NON-DESTRUCTIVE: restore is itself a NEW change in the feed (new version),
    // not a silent rewrite — the item's updatedSeq advanced past the pre-restore head.
    const item = (await (await api.get(`/items/${encodeURIComponent(cutId)}`)).json()) as any;
    expect(item.updatedSeq).toBeGreaterThan(changesBefore.anchor);
    // the v1 snapshot is still intact and browsable (history preserved)
    const asOf = (await (await api.get("/snapshots/snap-v1/dir?parent=root")).json()) as any[];
    expect(asOf.map((i) => i.name)).toContain("cut.mov");
  });

  it("restores a FOLDER subtree recursively", async () => {
    const api = fsAt("fs-restore-folder");
    const showId = await api.create("root", "show", { isDir: true });
    const aId = await api.create(showId, "a.mov");
    await api.send("PUT", `/blocks/${encodeURIComponent(aId)}`, manifest("blocks/org1::fs-restore-folder/a/v1", 10));
    const bId = await api.create(showId, "b.mov");
    await api.send("PUT", `/blocks/${encodeURIComponent(bId)}`, manifest("blocks/org1::fs-restore-folder/b/v1", 20));

    await api.send("POST", "/snapshots", { id: "snap-show", scope: showId, label: "show v1" });

    // mutate both files + delete one after the snapshot
    await api.send("PUT", `/blocks/${encodeURIComponent(aId)}`, manifest("blocks/org1::fs-restore-folder/a/v2", 999));
    await api.send("DELETE", `/items/${encodeURIComponent(bId)}`);

    // recursive restore of the folder
    const res = await api.send("POST", "/snapshots/snap-show/restore", { path: showId, recursive: true });
    expect(res.status).toBe(200);
    const result = (await res.json()) as any;
    // a.mov restored (existed, edited); b.mov recreated (was deleted)
    expect(result.restored).toContain(aId);
    expect(result.recreated).toContain(bId);

    // a.mov back to v1, b.mov back from the dead with its v1 manifest
    const aMap = (await (await api.get(`/blocks/${encodeURIComponent(aId)}`)).json()) as any[];
    expect(aMap[0].objectKey).toContain("/a/v1");
    const bMap = (await (await api.get(`/blocks/${encodeURIComponent(bId)}`)).json()) as any[];
    expect(bMap[0].objectKey).toContain("/b/v1");
    // b.mov is live again in the listing
    const list = (await (await api.get(`/items?parent=${encodeURIComponent(showId)}`)).json()) as { items: any[] };
    expect(list.items.map((i) => i.name).sort()).toEqual(["a.mov", "b.mov"]);
  });

  it("is NON-DESTRUCTIVE: newer files created after the snapshot are NOT deleted", async () => {
    const api = fsAt("fs-restore-nondestructive");
    const projId = await api.create("root", "proj", { isDir: true });
    await api.create(projId, "old.mov", { size: 1 });
    await api.send("POST", "/snapshots", { id: "snap-nd", scope: projId });
    // add a brand-new file after the snapshot
    const newId = await api.create(projId, "brand-new.mov", { size: 1 });

    const res = await api.send("POST", "/snapshots/snap-nd/restore", { path: projId, recursive: true });
    const result = (await res.json()) as any;
    expect(result.newerThanSnapshot).toContain(newId);

    // brand-new.mov survives the restore (not silently lost)
    const list = (await (await api.get(`/items?parent=${encodeURIComponent(projId)}`)).json()) as { items: any[] };
    expect(list.items.map((i) => i.name)).toContain("brand-new.mov");
    expect(list.items.map((i) => i.name)).toContain("old.mov");
  });

  it("requires EDIT on the target path (403 for a principal without it)", async () => {
    const SP = "fs-restore-perm";
    const base = `https://gw.local/v1/filespaces/${SP}`;
    // admin seeds + snapshots
    await SELF.fetch(`${base}/items`, { method: "POST", headers: AUTH, body: JSON.stringify({ parent: "root", name: "doc.mov", size: 1 }) });
    await SELF.fetch(`${base}/snapshots`, { method: "POST", headers: AUTH, body: JSON.stringify({ id: "snap-perm" }) });

    // a standard member with snapshot scopes but NO edit ACL on the path
    const userId = await provisionUser(ORG, "standard");
    const userAuth = {
      Authorization: `Bearer ${await token({ sub: userId, scopes: ["snapshot:read", "snapshot:write", "fs:write", "fs:read"] })}`,
      "content-type": "application/json",
    };
    const res = await SELF.fetch(`${base}/snapshots/snap-perm/restore`, {
      method: "POST", headers: userAuth, body: JSON.stringify({ path: "root/doc.mov" }),
    });
    expect(res.status).toBe(403);
  });

  it("refuses (conflict) to restore a target exclusively locked by ANOTHER owner", async () => {
    const SP = "fs-restore-lock";
    const base = `https://gw.local/v1/filespaces/${SP}`;
    // two admin principals (both authorized; lock ownership distinguishes them)
    const aliceId = await provisionUser(ORG, "admin");
    const bobId = await provisionUser(ORG, "admin");
    const aliceAuth = { Authorization: `Bearer ${await token({ sub: aliceId })}`, "content-type": "application/json" };
    const bobAuth = { Authorization: `Bearer ${await token({ sub: bobId })}`, "content-type": "application/json" };

    // seed + snapshot (as alice) — capture the opaque id (audit B17).
    const lockedId = ((await (await SELF.fetch(`${base}/items`, { method: "POST", headers: aliceAuth, body: JSON.stringify({ parent: "root", name: "locked.mov", size: 1 }) })).json()) as any).id as string;
    await SELF.fetch(`${base}/snapshots`, { method: "POST", headers: aliceAuth, body: JSON.stringify({ id: "snap-lock" }) });

    // bob takes an exclusive lease on the item (lock key = inode id)
    const lock = (await (await SELF.fetch(`${base}/locks`, {
      method: "POST", headers: bobAuth, body: JSON.stringify({ path: lockedId, ttlMs: 60_000 }),
    })).json()) as any;
    expect(lock.granted).toBe(true);

    // alice tries to restore the bob-locked file → conflict, nothing restored (409)
    const res = await SELF.fetch(`${base}/snapshots/snap-lock/restore`, {
      method: "POST", headers: aliceAuth, body: JSON.stringify({ path: lockedId }),
    });
    expect(res.status).toBe(409);
    const result = (await res.json()) as any;
    expect(result.restored).toHaveLength(0);
    expect(result.conflicts[0].id).toBe(lockedId);
    expect(result.conflicts[0].heldBy).toBe(bobId);
  });

  it("404s for an unknown snapshot or a path not present in the snapshot", async () => {
    const api = fsAt("fs-restore-404");
    const noSnap = await api.send("POST", "/snapshots/does-not-exist/restore", { path: "root" });
    expect(noSnap.status).toBe(404);
    await api.send("POST", "/snapshots", { id: "snap-404", scope: "root/projectA" });
    const noPath = await api.send("POST", "/snapshots/snap-404/restore", { path: "root/Archive" });
    expect(noPath.status).toBe(404); // Archive wasn't under the snapshot's scope
  });
});

// ===========================================================================
// Round-2 INTEGRATION: authN + tenant isolation + per-folder ACL enforcement.
// Proves the three properties the integration round must guarantee.
// ===========================================================================

describe("integration: authentication enforcement (F1)", () => {
  it("rejects an unauthenticated request (no bearer token) with 401", async () => {
    const res = await SELF.fetch(`${FS}/items?parent=root`);
    expect(res.status).toBe(401);
  });

  it("rejects a malformed / unsigned token with 401", async () => {
    const res = await SELF.fetch(`${FS}/items?parent=root`, {
      headers: { Authorization: "Bearer not-a-real-jwt" },
    });
    expect(res.status).toBe(401);
  });

  it("rejects a token signed with the WRONG secret (forgery) with 401", async () => {
    const forged = await mintToken("a-totally-different-16+char-secret!!", {
      sub: "attacker", type: "session", orgId: ORG, scopes: ALL_SCOPES, ttlSeconds: 900,
    });
    const res = await SELF.fetch(`${FS}/items?parent=root`, {
      headers: { Authorization: `Bearer ${forged}` },
    });
    expect(res.status).toBe(401);
  });
});

describe("integration: per-folder ACL authorization (F3)", () => {
  const SPACE = "fs-authz";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;
  let viewerAuth: Record<string, string>; // standard role, NO grants → no edit
  let readScopeOnlyAuth: Record<string, string>; // standard role, only fs:read scope

  beforeAll(async () => {
    const viewerId = await provisionUser(ORG, "standard");
    // full scopes but standard org role + no ACL grant ⇒ default-deny on the tree
    viewerAuth = { Authorization: `Bearer ${await token({ sub: viewerId })}`, "content-type": "application/json" };
    const readerId = await provisionUser(ORG, "standard");
    readScopeOnlyAuth = {
      Authorization: `Bearer ${await token({ sub: readerId, scopes: ["fs:read"] })}`,
      "content-type": "application/json",
    };
  });
  const sendAs = (auth: Record<string, string>, method: string, path: string, body?: unknown) =>
    SELF.fetch(`${base}${path}`, { method, headers: auth, body: body ? JSON.stringify(body) : undefined });

  it("denies a create to a principal lacking edit on the parent (403)", async () => {
    const res = await sendAs(viewerAuth, "POST", "/items", { parent: "root", name: "sneaky.mov", size: 1 });
    expect(res.status).toBe(403);
    const body = (await res.json()) as any;
    expect(body.error).toBe("forbidden");
  });

  it("denies a PUT presign to a read-only principal on scope (403)", async () => {
    const res = await sendAs(readScopeOnlyAuth, "POST", "/presign", {
      key: `blocks/${ORG}::${SPACE}/x/y`, method: "PUT",
    });
    expect(res.status).toBe(403); // requireScope('fs:write') fails before minting
  });

  it("denies a GET presign for an object the principal has no ACL on (403)", async () => {
    // seed a file as admin (so it has an owning inode), then a viewer asks to read it.
    // Audit B17: ids are opaque — capture the server-assigned id and PUT the block map
    // against it (the old `root/locked.mov` path-id no longer resolves to an item).
    const lockedId = ((await (await SELF.fetch(`${base}/items`, { method: "POST", headers: AUTH, body: JSON.stringify({ parent: "root", name: "locked.mov", size: 10 }) })).json()) as any).id as string;
    await SELF.fetch(`${base}/blocks/${encodeURIComponent(lockedId)}`, {
      method: "PUT", headers: AUTH,
      body: JSON.stringify({ blocks: [{ chunkIdx: 0, blockIdx: 0, blockHash: "h", objectKey: `blocks/${ORG}::${SPACE}/lk/0`, offset: 0, length: 10 }] }),
    });
    const res = await sendAs(viewerAuth, "POST", "/presign", { key: `blocks/${ORG}::${SPACE}/lk/0`, method: "GET" });
    expect(res.status).toBe(403);
  });

  it("ALLOWS access once an explicit ACL grant is added for the principal", async () => {
    const grantId = await provisionUser(ORG, "standard");
    const granteeAuth = { Authorization: `Bearer ${await token({ sub: grantId })}`, "content-type": "application/json" };
    // before: denied
    const before = await sendAs(granteeAuth, "POST", "/items", { parent: "root", name: "ok.mov", size: 1 });
    expect(before.status).toBe(403);
    // admin grants edit on root to the grantee
    const g = await SELF.fetch(`${base}/grants`, {
      method: "POST", headers: AUTH,
      body: JSON.stringify({ inodeId: "root", principalType: "user", principalId: grantId, level: "edit" }),
    });
    expect(g.status).toBe(201);
    // after: allowed
    const after = await sendAs(granteeAuth, "POST", "/items", { parent: "root", name: "ok.mov", size: 1 });
    expect(after.status).toBe(201);
  });
});

describe("integration: multi-tenant isolation (F2)", () => {
  it("blocks a token for org A from addressing org B's filespace (403)", async () => {
    const orgAId = await provisionUser("orgA", "admin");
    const orgAToken = await token({ sub: orgAId, orgId: "orgA" });
    // orgA token tries to drive a filespace as if it were orgB — assertTenant fires
    const res = await SELF.fetch("https://gw.local/v1/orgs/orgB/users", {
      headers: { Authorization: `Bearer ${orgAToken}` },
    });
    expect(res.status).toBe(403); // cross_tenant
  });

  it("isolates filespace DOs by org (same space id, different org = different DO)", async () => {
    // Two orgs both use space id "shared-name"; each token only sees its own DO's seed.
    const orgXId = await provisionUser("orgX", "admin");
    const orgYId = await provisionUser("orgY", "admin");
    const xAuth = { Authorization: `Bearer ${await token({ sub: orgXId, orgId: "orgX" })}`, "content-type": "application/json" };
    const yAuth = { Authorization: `Bearer ${await token({ sub: orgYId, orgId: "orgY" })}`, "content-type": "application/json" };
    const URL = "https://gw.local/v1/filespaces/shared-name/items";

    // orgX creates a file in its "shared-name" space
    await SELF.fetch(URL, { method: "POST", headers: xAuth, body: JSON.stringify({ parent: "root", name: "x-only.mov", size: 1 }) });
    // orgY lists its OWN "shared-name" space — must NOT see orgX's file (separate DO)
    const yList = (await (await SELF.fetch(`${URL}?parent=root`, { headers: yAuth })).json()) as { items: any[] };
    expect(yList.items.map((i) => i.name)).not.toContain("x-only.mov");
  });
});

describe("integration: audit trail (F4)", () => {
  const SPACE = "fs-audit";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;

  it("records presign mints and ACL denials in the tamper-evident chain", async () => {
    // an allowed PUT mint (admin) + a denied create (viewer)
    await SELF.fetch(`${base}/presign`, {
      method: "POST", headers: AUTH,
      body: JSON.stringify({ key: `blocks/${ORG}::${SPACE}/a/b`, method: "PUT" }),
    });
    const viewerId = await provisionUser(ORG, "standard");
    const viewerAuth = { Authorization: `Bearer ${await token({ sub: viewerId })}`, "content-type": "application/json" };
    await SELF.fetch(`${base}/items`, {
      method: "POST", headers: viewerAuth,
      body: JSON.stringify({ parent: "root", name: "nope.mov", size: 1 }),
    });

    // admin reads the audit log (gated by audit:read scope). Reader is
    // NEWEST-FIRST (seq DESC); sort ascending for the chain-link assertions.
    const records = (await (await SELF.fetch(`${base}/audit`, { headers: AUTH })).json()) as any[];
    const actions = records.map((r) => `${r.action}:${r.decision}`);
    expect(actions).toContain("presign.mint:allow");
    expect(actions).toContain("item.create:deny");
    // newest-first: the page leads with the highest seq.
    expect(records[0].seq).toBe(Math.max(...records.map((r) => r.seq)));
    // chain integrity: monotonic seq, each prevHash links the prior hash
    const asc = [...records].sort((x, y) => x.seq - y.seq);
    for (let i = 1; i < asc.length; i++) {
      expect(asc[i].seq).toBe(asc[i - 1].seq + 1);
      expect(asc[i].prevHash).toBe(asc[i - 1].hash);
    }
  });

  it("denies the audit reader to a principal without audit:read scope (403)", async () => {
    const noAuditId = await provisionUser(ORG, "standard");
    const noAuditAuth = { Authorization: `Bearer ${await token({ sub: noAuditId, scopes: ["fs:read"] })}` };
    const res = await SELF.fetch(`${base}/audit`, { headers: noAuditAuth });
    expect(res.status).toBe(403);
  });
});

// Audit B23 — batch presign: mint many keys in ONE request (a 1,000-file copy shouldn't be 1,000
// round-trips). Each key is ACL-gated; the storage descriptor is resolved once for the batch.
describe("B23: batch presign (POST /presign/batch)", () => {
  const SPACE = "fs-b23-batch";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;
  const PREFIX = `blocks/${ORG}::${SPACE}`;

  it("mints multiple PUT keys in one request", async () => {
    const keys = [0, 1, 2].map((i) => ({ key: `${PREFIX}/b/${i}`, method: "PUT" }));
    const res = await SELF.fetch(`${base}/presign/batch`, { method: "POST", headers: AUTH, body: JSON.stringify({ keys, expiresIn: 300 }) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { urls: { key: string; url?: string; error?: string }[]; expiresIn: number };
    expect(body.urls).toHaveLength(3);
    expect(body.urls.every((u) => typeof u.url === "string" && u.url.includes("X-Amz-Signature="))).toBe(true);
    expect(body.expiresIn).toBe(300);
  });

  it("per-key errors are reported in-line (one bad key doesn't fail the batch)", async () => {
    const keys = [
      { key: `${PREFIX}/ok`, method: "PUT" },
      { key: `blocks/${ORG}::other-space/escape`, method: "PUT" }, // prefix violation
      { key: `${PREFIX}/../traversal`, method: "PUT" },             // path traversal
    ];
    const res = await SELF.fetch(`${base}/presign/batch`, { method: "POST", headers: AUTH, body: JSON.stringify({ keys }) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { urls: { key: string; url?: string; error?: string }[] };
    expect(body.urls[0].url).toBeTruthy();
    expect(body.urls[1].error).toBe("key_prefix_violation");
    expect(body.urls[2].error).toBe("key_prefix_violation");
  });

  it("rejects an empty or oversized batch (400)", async () => {
    expect((await SELF.fetch(`${base}/presign/batch`, { method: "POST", headers: AUTH, body: JSON.stringify({ keys: [] }) })).status).toBe(400);
    const tooMany = Array.from({ length: 300 }, (_, i) => ({ key: `${PREFIX}/${i}`, method: "PUT" }));
    expect((await SELF.fetch(`${base}/presign/batch`, { method: "POST", headers: AUTH, body: JSON.stringify({ keys: tooMany }) })).status).toBe(400);
  });
});

describe("integration: durable per-(org,space) rate limiting (F5)", () => {
  // The presign limiter is DO-backed + operator-tunable (audit B23). The test env pins a SMALL cap
  // (RL_PRESIGN_CAPACITY=60, refill 5/s in wrangler.jsonc) so a modest burst trips it deterministically;
  // production defaults are 600/100. The counter is GLOBAL per space (persists across requests).
  const SPACE = "fs-ratelimit";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;
  const KEY = `blocks/${ORG}::${SPACE}/rl/0`;

  it("enforces the per-space presign cap and returns 429 + Retry-After", async () => {
    // Cap 60, refill 5/s (test env). Fire a CONCURRENT burst far exceeding capacity (a
    // not-in-namespace key under prefix is OK). The durable atomic consume() admits at most ~capacity.
    const N = 120;
    const results = await Promise.all(
      Array.from({ length: N }, () =>
        SELF.fetch(`${base}/presign`, {
          method: "POST", headers: AUTH,
          body: JSON.stringify({ key: KEY, method: "PUT" }),
        }),
      ),
    );
    const statuses = results.map((r) => r.status);
    // every response is either an allowed mint or a rate-limit — no other error
    expect(statuses.every((s) => s === 200 || s === 429)).toBe(true);
    const limited = results.filter((r) => r.status === 429);
    // a 120-deep burst against a 60-capacity bucket must trip the cap
    expect(limited.length).toBeGreaterThan(0);
    const body = (await limited[0].json()) as any;
    expect(body.error).toBe("rate_limited");
    expect(Number(limited[0].headers.get("Retry-After"))).toBeGreaterThan(0);
    // no MORE than capacity (+ a little refill during the burst) may succeed
    const ok = statuses.filter((s) => s === 200).length;
    expect(ok).toBeLessThanOrEqual(75);
  });

  it("a fresh isolate-equivalent request still sees the exhausted bucket (durable, not per-request)", async () => {
    // The bucket from the prior test is drained; subsequent mints are still limited
    // (a per-request in-memory bucket would have reset to full=60 — this proves the
    // DO-backed counter survives across gateway invocations). The bucket refills at 5/s, so
    // between tests a few tokens may have accrued; fire a short burst and assert that we hit the
    // cap quickly (well under a from-full bucket), which a per-request reset could never do.
    let sawRateLimited = false;
    for (let i = 0; i < 12; i++) {
      const res = await SELF.fetch(`${base}/presign`, {
        method: "POST", headers: AUTH,
        body: JSON.stringify({ key: KEY, method: "PUT" }),
      });
      if (res.status === 429) {
        sawRateLimited = true;
        break;
      }
      expect(res.status).toBe(200);
    }
    // A drained DO-backed bucket re-trips within a handful of mints; a per-request bucket (reset
    // to capacity 60 each call) would allow all 12 without a single 429.
    expect(sawRateLimited).toBe(true);
  });
});

describe("integration: redeemed scoped invite is enforced by canAccess (OrgDO→FilespaceDO grant sync)", () => {
  // multiuser's redeemInvite durably writes the scoped grant into OrgDO; the gateway
  // must propagate it into the per-filespace enforcement store so canAccess sees it.
  // The space's seeded namespace has inode "projectA" (a folder under root).
  const SPACE = "fs1"; // org1's seeded filespace (root, projectA, archive, ...)
  const SPACE_BASE = `https://gw.local/v1/filespaces/${SPACE}`;
  const ORG_BASE = `https://gw.local/v1/orgs/${ORG}`;

  async function createScopedInvite(level: "read" | "edit"): Promise<string> {
    // admin creates an invite scoped to projectA at the given level
    const res = await SELF.fetch(`${ORG_BASE}/invites`, {
      method: "POST", headers: AUTH,
      body: JSON.stringify({
        email: `invitee-${crypto.randomUUID()}@test.local`,
        role: "standard",
        scope: { spaceId: SPACE, inodeId: "projectA", level },
      }),
    });
    expect(res.status).toBe(201);
    const { rawToken } = (await res.json()) as { rawToken: string };
    return rawToken;
  }

  async function redeem(rawToken: string): Promise<{ userId: string; grantId?: string }> {
    // public route — token is the credential, no bearer
    const res = await SELF.fetch(`${ORG_BASE}/invites/redeem`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: rawToken, displayName: "Invitee" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.ok).toBe(true);
    expect(body.scope.inodeId).toBe("projectA");
    return { userId: body.userId, grantId: body.grantId };
  }

  it("an edit-scoped redeemed user passes canAccess at edit level (create under projectA)", async () => {
    const { userId } = await redeem(await createScopedInvite("edit"));
    const userAuth = {
      Authorization: `Bearer ${await token({ sub: userId, scopes: ["fs:read", "fs:write"] })}`,
      "content-type": "application/json",
    };
    // create a child under projectA — requires edit on the parent, which the synced grant provides
    const created = await SELF.fetch(`${SPACE_BASE}/items`, {
      method: "POST", headers: userAuth,
      body: JSON.stringify({ parent: "projectA", name: "invited-edit.mov", size: 1 }),
    });
    expect(created.status).toBe(201);
  });

  it("a read-scoped redeemed user can read projectA but is DENIED a write there (level ceiling enforced)", async () => {
    const { userId } = await redeem(await createScopedInvite("read"));
    const userAuth = {
      Authorization: `Bearer ${await token({ sub: userId, scopes: ["fs:read", "fs:write"] })}`,
      "content-type": "application/json",
    };
    // read is allowed (list the granted folder)
    const list = await SELF.fetch(`${SPACE_BASE}/items?parent=projectA`, { headers: userAuth });
    expect(list.status).toBe(200);
    // write above the granted level is denied (403) — proves the ceiling, not blanket access
    const create = await SELF.fetch(`${SPACE_BASE}/items`, {
      method: "POST", headers: userAuth,
      body: JSON.stringify({ parent: "projectA", name: "should-fail.mov", size: 1 }),
    });
    expect(create.status).toBe(403);
  });

  it("the grant does NOT leak outside its scope (no access to root or siblings)", async () => {
    const { userId } = await redeem(await createScopedInvite("edit"));
    const userAuth = {
      Authorization: `Bearer ${await token({ sub: userId, scopes: ["fs:read", "fs:write"] })}`,
      "content-type": "application/json",
    };
    // creating under root (outside the projectA grant) must be denied
    const atRoot = await SELF.fetch(`${SPACE_BASE}/items`, {
      method: "POST", headers: userAuth,
      body: JSON.stringify({ parent: "root", name: "leak.mov", size: 1 }),
    });
    expect(atRoot.status).toBe(403);
  });

  it("cross-tenant: a redeemed org1 user's token cannot drive another org's filespace", async () => {
    const { userId } = await redeem(await createScopedInvite("edit"));
    // mint a token claiming org1 (correct) but address a DIFFERENT org's space
    const userAuth = { Authorization: `Bearer ${await token({ sub: userId, orgId: ORG, scopes: ["fs:read"] })}` };
    const res = await SELF.fetch("https://gw.local/v1/orgs/orgZZ/users", { headers: userAuth });
    expect(res.status).toBe(403); // cross_tenant — assertTenant fires
  });
});

// ===========================================================================
// PART A + B: deploy-time admin/org bootstrap + the dev/admin seed path.
// Proves: bootstrap requires the secret + is single-use; a seeded block is
// fetchable via presign by a granted principal; non-secret/non-admin rejected.
// ===========================================================================

import { resetSetupFixture } from "./setup-fixture";

const BOOTSTRAP_URL = "https://gw.local/v1/bootstrap";
const SECRET = (env as any).BOOTSTRAP_SECRET as string; // from .dev.vars

async function bootstrap(orgId: string, opts?: { secret?: string; header?: boolean; email?: string }): Promise<Response> {
  const useSecret = opts?.secret ?? SECRET;
  const headers: Record<string, string> = { "content-type": "application/json" };
  // allowTokenOnly: token-only seeding (no admin password) is now an explicit opt-in (auth-spec §2.5).
  const body: any = { orgId, email: opts?.email ?? `admin@${orgId}.test`, allowTokenOnly: true };
  if (opts?.header === false) body.secret = useSecret; // secret in body
  else headers["x-bootstrap-secret"] = useSecret; // secret in header (default)
  return SELF.fetch(BOOTSTRAP_URL, { method: "POST", headers, body: JSON.stringify(body) });
}

describe("PART A — admin/org bootstrap (secret-gated, single-use)", () => {
  beforeEach(resetSetupFixture);
  it("creates the first org + admin and mints an admin token when the secret matches", async () => {
    const res = await bootstrap("boot-orgA");
    expect(res.status).toBe(201);
    const b = (await res.json()) as any;
    expect(b.orgId).toBe("boot-orgA");
    expect(b.userId).toMatch(/^usr-/);
    expect(b.role).toBe("owner");
    expect(b.token.split(".")).toHaveLength(3); // a real JWS admin token
    expect(b.scopes).toContain("fs:admin");

    // the minted token actually works against an authed route
    const me = await SELF.fetch("https://gw.local/v1/orgs/boot-orgA/users", {
      headers: { Authorization: `Bearer ${b.token}` },
    });
    expect(me.status).toBe(200);
  });

  it("rejects a wrong secret with 401 (no org created)", async () => {
    const res = await bootstrap("boot-bad", { secret: "wrong-secret-but-long-enough-1234" });
    expect(res.status).toBe(401);
    // confirm nothing was created: a correct bootstrap now succeeds (would be 409 if it had)
    const ok = await bootstrap("boot-bad");
    expect(ok.status).toBe(201);
  });

  it("rejects a missing secret with 401", async () => {
    const res = await SELF.fetch(BOOTSTRAP_URL, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ orgId: "boot-nosecret", email: "a@b.test" }),
    });
    expect(res.status).toBe(401);
  });

  it("accepts the secret in the body too (header optional)", async () => {
    const res = await bootstrap("boot-bodysecret", { header: false });
    expect(res.status).toBe(201);
  });

  it("is single-use per deployment: a second bootstrap is 409", async () => {
    const first = await bootstrap("boot-once");
    expect(first.status).toBe(201);
    const second = await bootstrap("boot-once");
    expect(second.status).toBe(409);
    expect(((await second.json()) as any).error).toBe("setup_complete");
  });

  it("is not a method-open endpoint (GET → 405)", async () => {
    const res = await SELF.fetch(BOOTSTRAP_URL, { headers: { "x-bootstrap-secret": SECRET } });
    expect(res.status).toBe(405);
  });
});

describe("PART B — admin seed path (filespace → grant → manifest → presign-GET)", () => {
  it("bootstraps, creates a filespace, seeds a block manifest, and presign-GETs it", async () => {
    // 1. bootstrap admin
    const boot = (await (await bootstrap("seed-org")).json()) as any;
    const adminAuth = { Authorization: `Bearer ${boot.token}`, "content-type": "application/json" };
    const SP = "edit1";
    const SPACE_BASE = `https://gw.local/v1/filespaces/${SP}`;

    // 2. register the filespace (admin-only)
    const reg = await SELF.fetch(`https://gw.local/v1/orgs/seed-org/spaces`, {
      method: "POST", headers: adminAuth,
      body: JSON.stringify({ spaceId: SP, name: "Edit 1", bucketProvider: "r2", bucketName: "cloudfs", keyPrefix: `blocks/seed-org::${SP}/` }),
    });
    expect(reg.status).toBe(201); // multiuser's spaces route returns 201 Created

    // 3. create an item (admin = owner role → canAccess short-circuits to allow)
    const item = (await (await SELF.fetch(`${SPACE_BASE}/items`, {
      method: "POST", headers: adminAuth,
      body: JSON.stringify({ parent: "root", name: "A001.mov", size: 0 }),
    })).json()) as any;
    // Audit B17: the id is opaque; address the item by its returned id.
    expect(item.id).toMatch(/^ino-/);

    // 4. register a block manifest under the real objectKey scheme
    //    blocks/<org>::<fs>/...  — this is what cloudfsd reads.
    const objectKey = `blocks/seed-org::${SP}/00/0`;
    const withBlocks = (await (await SELF.fetch(`${SPACE_BASE}/blocks/${encodeURIComponent(item.id)}`, {
      method: "PUT", headers: adminAuth,
      body: JSON.stringify({ blocks: [{ chunkIdx: 0, blockIdx: 0, blockHash: "h0", objectKey, offset: 0, length: 1_048_576 }] }),
    })).json()) as any;
    expect(withBlocks.size).toBe(1_048_576);

    // 5a. presign a PUT to upload the encrypted block bytes (client → bucket directly)
    const put = (await (await SELF.fetch(`${SPACE_BASE}/presign`, {
      method: "POST", headers: adminAuth,
      body: JSON.stringify({ key: objectKey, method: "PUT", expiresIn: 300 }),
    })).json()) as any;
    // Legacy keys without a SHA-256 identity cannot be safely re-uploaded once committed.
    expect(put.error).toBe("forbidden");

    // 5b. presign a GET to READ the block back (the cloudfsd read path)
    const getRes = await SELF.fetch(`${SPACE_BASE}/presign`, {
      method: "POST", headers: adminAuth,
      body: JSON.stringify({ key: objectKey, method: "GET", expiresIn: 300 }),
    });
    expect(getRes.status).toBe(200);
    const getBody = (await getRes.json()) as any;
    expect(getBody.url).toContain(`/cloudfs/${objectKey}`);
    expect(getBody.url).toContain("X-Amz-Signature=");
    expect(getBody.expiresIn).toBe(300);
  });

  it("a non-admin principal in the org is DENIED a presign-GET on a seeded block (admin-scoped, not public)", async () => {
    const boot = (await (await bootstrap("seed-org2")).json()) as any;
    const adminAuth = { Authorization: `Bearer ${boot.token}`, "content-type": "application/json" };
    const SP = "edit2";
    const SPACE_BASE = `https://gw.local/v1/filespaces/${SP}`;
    const objectKey = `blocks/seed-org2::${SP}/00/0`;

    // admin seeds the item + manifest
    const secretId = ((await (await SELF.fetch(`${SPACE_BASE}/items`, { method: "POST", headers: adminAuth, body: JSON.stringify({ parent: "root", name: "secret.mov", size: 0 }) })).json()) as any).id as string;
    await SELF.fetch(`${SPACE_BASE}/blocks/${encodeURIComponent(secretId)}`, {
      method: "PUT", headers: adminAuth,
      body: JSON.stringify({ blocks: [{ chunkIdx: 0, blockIdx: 0, blockHash: "h", objectKey, offset: 0, length: 10 }] }),
    });

    // a standard (non-admin) member of the SAME org with no grant is denied the read mint
    const standardId = await provisionUser("seed-org2", "standard");
    const stdAuth = { Authorization: `Bearer ${await token({ sub: standardId, orgId: "seed-org2", scopes: ["fs:read"] })}`, "content-type": "application/json" };
    const res = await SELF.fetch(`${SPACE_BASE}/presign`, {
      method: "POST", headers: stdAuth,
      body: JSON.stringify({ key: objectKey, method: "GET" }),
    });
    expect(res.status).toBe(403); // canAccess denies — seed path is admin-scoped, not public
  });
});

// ===========================================================================
// OIDC SSO wiring (security/oidc.ts mounted at /v1/auth/oidc/*). PUBLIC routes,
// before the verifyRequest gate — same placement as /v1/bootstrap. The deep
// id_token / PKCE / state-cookie behaviour is exhaustively covered by
// test/oidc.test.ts; here we prove the gateway MOUNTS + delegates correctly.
// ===========================================================================

describe("OIDC SSO routes (public, pre-auth; delegate to security/oidc.ts)", () => {
  const START = "https://gw.local/v1/auth/oidc/start";
  const CALLBACK = "https://gw.local/v1/auth/oidc/callback";

  it("GET /start 302-redirects to the IdP authorize endpoint with state + PKCE S256", async () => {
    // No Authorization header — these routes ARE the login, so they're pre-auth.
    const res = await SELF.fetch(START, { redirect: "manual" });
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    expect(loc).toBeTruthy();
    const u = new URL(loc);
    // points at the configured provider authorize endpoint (from wrangler vars)
    expect(`${u.origin}${u.pathname}`).toBe("https://idp.local.test/authorize");
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("client_id")).toBe("cloudfs-dev-client");
    // CSRF state + PKCE challenge present
    expect(u.searchParams.get("state")).toBeTruthy();
    expect(u.searchParams.get("code_challenge")).toBeTruthy();
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("nonce")).toBeTruthy();
    // the sealed login-state cookie is set (HttpOnly transient state)
    const setCookie = res.headers.get("Set-Cookie") ?? "";
    expect(setCookie.toLowerCase()).toContain("httponly");
  });

  it("GET /callback is reachable WITHOUT a bearer token and runs the BROWSER-SSO handler (302 to the SPA with ?error)", async () => {
    // No code/state → the web handler 302-redirects to the SPA /auth/callback with the typed
    // error code (`bad_callback`), proving the route delegates to handleOidcWebCallback rather
    // than hitting verifyRequest (401) or 404. Never a raw JSON error for the browser.
    const res = await SELF.fetch(CALLBACK, { redirect: "manual" });
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.pathname).toBe("/auth/callback");
    expect(loc.searchParams.get("error")).toBe("bad_callback");
  });

  it("GET /callback surfaces a provider-side error as a 302 ?error=provider_error redirect", async () => {
    const res = await SELF.fetch(`${CALLBACK}?error=access_denied`, { redirect: "manual" });
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.pathname).toBe("/auth/callback");
    expect(loc.searchParams.get("error")).toBe("provider_error");
  });

  it("a state mismatch / missing login cookie is rejected by the handler (CSRF defense, 302 ?error)", async () => {
    // code + state present but NO login-state cookie → web handler 302s with an error (not a 500).
    const res = await SELF.fetch(`${CALLBACK}?code=abc&state=xyz`, { redirect: "manual" });
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.pathname).toBe("/auth/callback");
    expect(loc.searchParams.get("error")).toBe("no_state_cookie");
  });

  it("does not weaken auth: an UNKNOWN /v1/auth/* path is not a login bypass", async () => {
    // only start|callback are public; anything else falls through to the auth gate.
    const res = await SELF.fetch("https://gw.local/v1/auth/oidc/bogus");
    expect(res.status).toBe(401); // no bearer → verifyRequest gate (no_token)
  });
});
