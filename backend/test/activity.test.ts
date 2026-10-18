// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env, runInDurableObject, abortAllDurableObjects } from "cloudflare:test";
import { describe, it, expect, beforeAll, vi } from "vitest";
import { mintToken, filespaceDoName, type Scope } from "../src/security/auth";
import { verifyChain, type AuditRecord } from "../src/security/audit";
import type { FilespaceDO } from '../src/filespace-do';

// WS3 + WS4 backend suite: audit ring trim + R2 archival, the live-activity feed,
// bulk-op rollups, snapshot lazy per-dir browse, and real manual snapshot create.

const ORG = "org1";
const ALL_SCOPES: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];

async function provisionUser(orgId: string, role: string): Promise<string> {
  const org = (env as any).ORG_DO.getByName(orgId);
  const u = await org.createUser({ orgId, email: `${role}-${crypto.randomUUID()}@test.local`, displayName: role, role });
  return u.id;
}
async function token(sub: string, scopes: Scope[] = ALL_SCOPES): Promise<string> {
  return mintToken((env as any).AUTH_SIGNING_SECRET, { sub, type: "session", orgId: ORG, scopes, ttlSeconds: 900 });
}

let ADMIN: string;
let AUTH: Record<string, string>;
beforeAll(async () => {
  ADMIN = await token(await provisionUser(ORG, "admin"));
  AUTH = { Authorization: `Bearer ${ADMIN}`, "content-type": "application/json" };
});

function api(space: string) {
  const base = `https://gw.local/v1/filespaces/${space}`;
  return {
    base,
    get: (path: string, auth = AUTH) => SELF.fetch(`${base}${path}`, { headers: auth }),
    send: (method: string, path: string, body?: unknown, auth = AUTH) =>
      SELF.fetch(`${base}${path}`, { method, headers: auth, body: body ? JSON.stringify(body) : undefined }),
  };
}
/// The FilespaceDO stub the gateway uses for (ORG, space) — lets a test drive the
/// archive tick directly (the gateway only schedules it on an alarm).
function fsStub(space: string) {
  return (env as any).FILESPACE.get((env as any).FILESPACE.idFromName(filespaceDoName(ORG, space)));
}

// ---------------------------------------------------------------------------
describe("WS3: audit ring trim → R2 archival, with continuous verifyChain", () => {
  it("trims older events to R2 yet the reader transparently spans DO ring + R2", async () => {
    const SP = "fs-audit-archive";
    const a = api(SP);
    // generate a handful of chained audit records via gateway presign mints.
    for (let i = 0; i < 6; i++) {
      await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/seg/${i}`, method: "PUT" });
    }
    const before = (await (await a.get("/audit")).json()) as AuditRecord[];
    expect(before.length).toBeGreaterThanOrEqual(6);
    // Reader is NEWEST-FIRST (seq DESC); ascending seq list for chain assertions.
    const totalSeqs = before.map((r) => r.seq).sort((x, y) => x - y);
    // The first (default) page leads with the newest event.
    expect(before[0].seq).toBe(totalSeqs[totalSeqs.length - 1]);

    // Force a trim that keeps only the last 2 events in the DO ring; the rest go
    // to R2. (Time window huge so the count policy dominates.)
    const stub = fsStub(SP);
    const res = await stub.archiveAuditRing(Date.now(), { maxEvents: 2, windowMs: 365 * 24 * 3600 * 1000 });
    expect(res.archived).toBeGreaterThan(0);
    expect(res.deleted).toBe(res.archived);
    expect(res.throughSeq).toBe(totalSeqs[totalSeqs.length - 1] - 2);

    // The reader still returns the FULL history (R2 fallback + ring), newest-first.
    const after = (await (await a.get("/audit?limit=10000")).json()) as AuditRecord[];
    expect(after.map((r) => r.seq)).toEqual([...totalSeqs].reverse());

    // And the hash chain is continuous across the DO→R2 boundary (ascending).
    const ascending = [...after].sort((x, y) => x.seq - y.seq);
    const verified = await verifyChain(ascending);
    expect(verified.ok).toBe(true);
    // DO-side continuity probe (archived + ring) agrees.
    const cont = await stub.verifyAuditContinuity();
    expect(cont.ok).toBe(true);
  });

  it("a second trim seals the next batch and the chain still verifies", async () => {
    const SP = "fs-audit-archive-2";
    const a = api(SP);
    for (let i = 0; i < 5; i++) {
      await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/k/${i}`, method: "PUT" });
    }
    const stub = fsStub(SP);
    const all = (await (await a.get("/audit?limit=10000")).json()) as AuditRecord[];
    // Reader is newest-first; the latest seq leads the page.
    const lastSeq = Math.max(...all.map((r) => r.seq));

    await stub.archiveAuditRing(Date.now(), { maxEvents: 3, windowMs: 1e12 }); // seal up to lastSeq-3
    // add two more, then trim again
    await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/k/x`, method: "PUT" });
    await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/k/y`, method: "PUT" });
    const r2 = await stub.archiveAuditRing(Date.now(), { maxEvents: 2, windowMs: 1e12 });
    expect(r2.throughSeq).toBe(lastSeq + 2 - 2);

    const after = (await (await a.get("/audit?limit=10000")).json()) as AuditRecord[];
    const ascending = [...after].sort((x, y) => x.seq - y.seq);
    expect((await verifyChain(ascending)).ok).toBe(true);
    // Newest-first: the highest seq leads the page.
    expect(after[0].seq).toBe(lastSeq + 2);
  });

  it("recovers the R2 fallback even when the in-memory filespace key is cold (post-hibernation)", async () => {
    const SP = "fs-audit-cold";
    const a = api(SP);
    for (let i = 0; i < 4; i++) {
      await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/c/${i}`, method: "PUT" });
    }
    const full = (await (await a.get("/audit?limit=10000")).json()) as AuditRecord[];
    const stub = fsStub(SP);
    await stub.archiveAuditRing(Date.now(), { maxEvents: 1, windowMs: 1e12 });

    // queryAudit called DIRECTLY on a stub view whose in-memory key was never set
    // by a write on this instance — it must recover via keyFromTail and still
    // splice in the R2 history (regression: previously returned only the ring).
    const direct = (await stub.queryAudit({ limit: 10000 })) as AuditRecord[];
    // Reader is newest-first; `full` came from the same newest-first reader.
    expect(direct.map((r) => r.seq)).toEqual(full.map((r) => r.seq));
    const ascending = [...direct].sort((x, y) => x.seq - y.seq);
    expect((await verifyChain(ascending)).ok).toBe(true);
  });

  it("recovers R2 history + re-arms the alarm after the ENTIRE ring is sealed AND the DO hibernates (Finding 5)", async () => {
    // The hard case: seal the WHOLE ring (maxEvents:0 ⇒ nothing kept resident) so
    // the audit table is empty, THEN cold-start the DO (abortAllDurableObjects wipes
    // in-memory state but keeps SQLite). Previously keyFromTail() read the empty
    // table, returned null, and queryAudit SILENTLY DROPPED all R2-archived history
    // (and auditArchiveDue() returned null so the alarm never re-armed). The fix
    // persists the `<org>::<fs>` key durably on the first appendAudit.
    const SP = "fs-audit-cold-empty";
    const a = api(SP);
    for (let i = 0; i < 4; i++) {
      await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/e/${i}`, method: "PUT" });
    }
    const full = (await (await a.get("/audit?limit=10000")).json()) as AuditRecord[];
    expect(full.length).toBeGreaterThanOrEqual(4);

    const stub = fsStub(SP);
    // Seal EVERYTHING to R2 — the DO ring ends up empty.
    const sealed = await stub.archiveAuditRing(Date.now(), { maxEvents: 0, windowMs: 1e12 });
    expect(sealed.archived).toBe(sealed.deleted);
    expect(sealed.deleted).toBe(full.length);

    // Cold start: drop all in-memory DO state (filespaceKey hint is now null), but
    // SQLite — including the durable filespace_key + archived_through_seq — survives.
    await abortAllDurableObjects();

    // Reader on the cold, empty-ringed DO must STILL splice in the full R2 history.
    const cold = fsStub(SP);
    const recovered = (await cold.queryAudit({ limit: 10000 })) as AuditRecord[];
    expect(recovered.map((r) => r.seq)).toEqual(full.map((r) => r.seq));
    const ascending = [...recovered].sort((x, y) => x.seq - y.seq);
    expect((await verifyChain(ascending)).ok).toBe(true);

    // And the archive path can still re-arm: with the key durably recovered, a new
    // event rebuilds the ring and arms the alarm (the gateway's appendAudit does the
    // same). Drive one more write, then confirm a fresh trim still finds the key.
    await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/e/after`, method: "PUT" });
    const after = fsStub(SP);
    const reTrim = await after.archiveAuditRing(Date.now(), { maxEvents: 0, windowMs: 1e12 });
    expect(reTrim.deleted).toBeGreaterThan(0); // key recovered ⇒ archival still works
    // The durable filespace_key survived hibernation (asserted directly on storage).
    const persisted = await runInDurableObject(after, (_inst, state) => {
      return state.storage.sql
        .exec(`SELECT value FROM meta_text WHERE key='filespace_key';`)
        .toArray()[0]?.value as string | undefined;
    });
    expect(persisted).toBe(`${ORG}::${SP}`);
  });

  it("query filters apply across the R2 boundary", async () => {
    const SP = "fs-audit-filter";
    const a = api(SP);
    // a mix of allow (presign PUT) + deny (presign GET on absent key) decisions
    await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/f/a`, method: "PUT" });
    await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/f/missing`, method: "GET" }); // deny
    await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/f/b`, method: "PUT" });

    const stub = fsStub(SP);
    await stub.archiveAuditRing(Date.now(), { maxEvents: 1, windowMs: 1e12 }); // push most to R2

    const denies = (await (await a.get("/audit?decision=deny&limit=10000")).json()) as AuditRecord[];
    expect(denies.length).toBeGreaterThanOrEqual(1);
    expect(denies.every((r) => r.decision === "deny")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PRIMARY BUG FIX: "Load older" page-back. The reader is NEWEST-FIRST and honors
// `cursor` as an EXCLUSIVE upper bound on `seq`. Successive cursor pages return
// strictly older, non-overlapping rows and terminate; paging crosses the
// DO-ring → R2 boundary transparently (CONTRACTS §5.4).
describe("WS3: audit page-back (newest-first + cursor, across ring→R2)", () => {
  // Drive the gateway exactly as the client does: GET /audit?limit=&cursor=,
  // continuation cursor = lowest seq of the previous FULL page, stop on a short
  // page. Returns every page accumulated (in fetch order).
  async function pageBack(a: ReturnType<typeof api>, pageSize: number) {
    const pages: AuditRecord[][] = [];
    let cursor: number | undefined;
    // Hard cap so a paging bug can't loop forever (the assertion is termination).
    for (let guard = 0; guard < 100; guard++) {
      const qs = cursor === undefined
        ? `/audit?limit=${pageSize}`
        : `/audit?limit=${pageSize}&cursor=${cursor}`;
      const page = (await (await a.get(qs)).json()) as AuditRecord[];
      pages.push(page);
      if (page.length < pageSize) break; // short page → end of history
      cursor = Math.min(...page.map((r) => r.seq)); // lowest seq on a full page
    }
    return pages;
  }

  it("page 1 returns the NEWEST events; cursor pages walk strictly older + terminate", async () => {
    const SP = "fs-audit-page1";
    const a = api(SP);
    const N = 7;
    for (let i = 0; i < N; i++) {
      await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/p/${i}`, method: "PUT" });
    }
    const all = (await (await a.get("/audit?limit=10000")).json()) as AuditRecord[];
    const maxSeq = Math.max(...all.map((r) => r.seq));

    const pages = await pageBack(a, 3);
    // Page 1 leads with the newest event.
    expect(pages[0][0].seq).toBe(maxSeq);
    // Each page is internally newest-first (seq strictly descending).
    for (const page of pages) {
      for (let i = 1; i < page.length; i++) expect(page[i].seq).toBeLessThan(page[i - 1].seq);
    }
    // Flattened: strictly descending across pages → NO duplicates, each page older.
    const flat = pages.flat().map((r) => r.seq);
    for (let i = 1; i < flat.length; i++) expect(flat[i]).toBeLessThan(flat[i - 1]);
    // Terminates and covers the whole history exactly once.
    expect([...flat].sort((x, y) => x - y)).toEqual(all.map((r) => r.seq).sort((x, y) => x - y));
    // No duplicate seqs.
    expect(new Set(flat).size).toBe(flat.length);
  });

  it("page-back crosses the ring→R2 boundary with no overlap and terminates", async () => {
    const SP = "fs-audit-page-cross";
    const a = api(SP);
    const N = 9;
    for (let i = 0; i < N; i++) {
      await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/x/${i}`, method: "PUT" });
    }
    const all = (await (await a.get("/audit?limit=10000")).json()) as AuditRecord[];
    const seqs = all.map((r) => r.seq);
    const maxSeq = Math.max(...seqs);

    // Archive all but the newest 2 → most of the history now lives in R2, so a
    // page-back MUST descend below ringStartsAtSeq into the R2 segments.
    const stub = fsStub(SP);
    const res = await stub.archiveAuditRing(Date.now(), { maxEvents: 2, windowMs: 1e12 });
    expect(res.archived).toBeGreaterThan(0);

    const pageSize = 3;
    const pages = await pageBack(a, pageSize);
    const flat = pages.flat().map((r) => r.seq);
    // Strictly descending across the boundary (ring rows then R2 rows).
    for (let i = 1; i < flat.length; i++) expect(flat[i]).toBeLessThan(flat[i - 1]);
    // The first page still starts at the newest (in the ring).
    expect(pages[0][0].seq).toBe(maxSeq);
    // Every seq returned exactly once; the loop terminated covering the full log.
    expect([...flat].sort((x, y) => x - y)).toEqual([...seqs].sort((x, y) => x - y));
    expect(new Set(flat).size).toBe(flat.length);
    // The chain across ring+R2 still verifies (ascending).
    const ascending = [...all].sort((x, y) => x.seq - y.seq);
    expect((await verifyChain(ascending)).ok).toBe(true);
  });

  it("a cursor at the oldest seq yields an empty page (end of history)", async () => {
    const SP = "fs-audit-page-end";
    const a = api(SP);
    for (let i = 0; i < 4; i++) {
      await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/e/${i}`, method: "PUT" });
    }
    const all = (await (await a.get("/audit?limit=10000")).json()) as AuditRecord[];
    const minSeq = Math.min(...all.map((r) => r.seq));
    // cursor == lowest seq → exclusive bound excludes everything → empty page.
    const empty = (await (await a.get(`/audit?limit=10000&cursor=${minSeq}`)).json()) as AuditRecord[];
    expect(empty.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
describe("WS3: live activity feed (in-flight transfers + bulk-op rollup)", () => {
  it("surfaces an in-flight upload and clears it on complete", async () => {
    const SP = "fs-live-xfer";
    const a = api(SP);
    const file = await (await a.send("POST", "/items", { parent: "root", name: "big.mov", size: 1000 })).json() as { id: string };
    await a.send("POST", "/uploads", {
      uploadId: "u-1", itemId: file.id, key: `blocks/${ORG}::${SP}/u/1`, totalSize: 1000, partSize: 500,
    });

    let live = (await (await a.get("/activity/live")).json()) as any;
    expect(live.transfers.map((t: any) => t.id)).toContain("u-1");
    const t = live.transfers.find((x: any) => x.id === "u-1");
    expect(t.direction).toBe("upload");
    expect(t.bytesTotal).toBe(1000);
    expect(t.state).toBe("active");

    // record both required parts (totalSize 1000 / partSize 500 ⇒ 2 parts), then
    // complete → transfer leaves the feed
    await a.send("PUT", "/uploads/u-1/parts", { partNumber: 1, etag: "e1", size: 500 });
    await a.send("PUT", "/uploads/u-1/parts", { partNumber: 2, etag: "e2", size: 500 });
    const done = (await (await a.send("POST", "/uploads/u-1/complete", { etag: "final" })).json()) as any;
    expect(done.completed).toBe(true);

    live = (await (await a.get("/activity/live")).json()) as any;
    expect(live.transfers.map((t: any) => t.id)).not.toContain("u-1");
    // a completed-upload `single` event lands on the rolling tail
    expect(live.events.some((e: any) => e.kind === "single" && e.path === file.id)).toBe(true);
  });

  it("collapses a large recursive delete into ONE 'large-delete' rollup", async () => {
    const SP = "fs-live-bulk";
    const a = api(SP);
    // a folder with > BULK_DELETE_THRESHOLD (50) children — capture its opaque id (B17).
    const trashId = ((await (await a.send("POST", "/items", { parent: "root", name: "trash", isDir: true })).json()) as any).id;
    await a.send("POST", "/items/_seed", { parent: trashId, prefix: "f", count: 120 });

    const del = (await (await a.send("DELETE", `/items/${encodeURIComponent(trashId)}?recursive=true`)).json()) as any;
    expect(del.kind).toBe("bulk");
    expect(del.deleted).toBe(121); // folder + 120 children

    const live = (await (await a.get("/activity/live")).json()) as any;
    const bulk = live.events.find((e: any) => e.kind === "bulk");
    expect(bulk).toBeTruthy();
    expect(bulk.op).toBe("large-delete");
    expect(bulk.count).toBe(121);
    expect(bulk.path).toBe(trashId);
  });

  it("a small recursive delete stays a single event (no rollup)", async () => {
    const SP = "fs-live-small";
    const a = api(SP);
    const fewId = ((await (await a.send("POST", "/items", { parent: "root", name: "few", isDir: true })).json()) as any).id;
    await a.send("POST", "/items/_seed", { parent: fewId, prefix: "f", count: 3 });
    const del = (await (await a.send("DELETE", `/items/${encodeURIComponent(fewId)}?recursive=true`)).json()) as any;
    expect(del.kind).toBe("single");
    expect(del.deleted).toBe(4);
  });

  it("denies the live feed without audit:read scope (403)", async () => {
    const SP = "fs-live-authz";
    const a = api(SP);
    const noAudit = { Authorization: `Bearer ${await token(await provisionUser(ORG, "standard"), ["fs:read"])}` };
    const res = await a.get("/activity/live", noAudit);
    expect(res.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
describe("WS4: snapshot lazy per-directory browse + real manual create", () => {
  it("creates a manual snapshot WITHOUT a client-supplied id (server mints it)", async () => {
    const SP = "fs-snap-create";
    const a = api(SP);
    await a.send("POST", "/items", { parent: "root", name: "doc.mov", size: 10 });

    const res = await a.send("POST", "/snapshots", { label: "before-edit" });
    expect(res.status).toBe(201);
    const snap = (await res.json()) as any;
    expect(typeof snap.id).toBe("string");
    expect(snap.id).toMatch(/^manual-/);
    expect(snap.label).toBe("before-edit");
    expect(snap.tier).toBe("manual");

    // it shows up in the listing
    const list = (await (await a.get("/snapshots")).json()) as any[];
    expect(list.map((s) => s.id)).toContain(snap.id);
  });

  it("browses a snapshot one directory at a time (lazy expansion)", async () => {
    const SP = "fs-snap-browse";
    const a = api(SP);
    const mkdir = async (parent: string, name: string, extra: Record<string, unknown> = {}): Promise<string> =>
      ((await (await a.send("POST", "/items", { parent, name, size: 0, ...extra })).json()) as any).id as string;
    // build a nested tree: proj/{sub/, file.mov}  (opaque ids — audit B17)
    const projId = await mkdir("root", "proj", { isDir: true });
    const subId = await mkdir(projId, "sub", { isDir: true });
    await mkdir(projId, "file.mov", { size: 5 });
    await mkdir(subId, "deep.mov", { size: 7 });

    const snap = (await (await a.send("POST", "/snapshots", { label: "tree" })).json()) as any;

    // root level
    const rootDir = (await (await a.get(`/snapshots/${snap.id}/dir?parent=root`)).json()) as any[];
    expect(rootDir.map((i) => i.name)).toContain("proj");

    // drill into proj (lazy — only this level returned, not the whole subtree)
    const projDir = (await (await a.get(`/snapshots/${snap.id}/dir?parent=${encodeURIComponent(projId)}`)).json()) as any[];
    const names = projDir.map((i) => i.name).sort();
    expect(names).toEqual(["file.mov", "sub"]);
    // proj's listing must NOT include the grandchild deep.mov (that's a deeper level)
    expect(names).not.toContain("deep.mov");

    // drill into proj/sub
    const subDir = (await (await a.get(`/snapshots/${snap.id}/dir?parent=${encodeURIComponent(subId)}`)).json()) as any[];
    expect(subDir.map((i) => i.name)).toEqual(["deep.mov"]);
  });

  it("a created snapshot freezes content for non-destructive restore (semantics unchanged)", async () => {
    const SP = "fs-snap-restore";
    const a = api(SP);
    const vId = ((await (await a.send("POST", "/items", { parent: "root", name: "v.mov", size: 1 })).json()) as any).id;
    const snap = (await (await a.send("POST", "/snapshots", {})).json()) as any;
    // delete it, then restore from the (server-id'd) snapshot
    await a.send("DELETE", `/items/${encodeURIComponent(vId)}`);
    const restore = (await (await a.send("POST", `/snapshots/${snap.id}/restore`, { path: vId })).json()) as any;
    expect(restore.recreated).toContain(vId);
  });
});

// ---------------------------------------------------------------------------
// FilespaceDO durable rate limiter is ATOMIC (Finding 6): two concurrent consumes
// past the bucket cap must admit only the allowed number. Before the fix
// DoRateLimitStore exposed only get()/set(), so RateLimiter.check took the racy
// get→compute→set fallback — two callers could each `get` the same prior tokens
// (the await boundary between get and set is the interleave point) and both admit,
// over-admitting at the burst boundary. The atomic `consume()` collapses the
// triple into one synchronous body with no interleave point.
describe("FilespaceDO rate limiter atomicity (Finding 6)", () => {
  it("two concurrent consumes past a cap-1 bucket admit ONLY one (no over-admit)", async () => {
    // Drive the RateLimiter against a REAL DO-SQLite-backed DoRateLimitStore, but
    // call check() directly (not via the DO input gate) so the get→set fallback's
    // interleave point is actually reachable — this is exactly the race the review
    // flagged. With the atomic consume() present, check() takes that path instead
    // and the race is impossible; without it, two concurrent checks both admit.
    const stub = fsStub("fs-rl-unit");
    const admitted = await runInDurableObject(stub, async (_inst, state) => {
      const { DoRateLimitStore } = await import("../src/metadata/ratelimit-store");
      const { RateLimiter } = await import("../src/security/ratelimit");
      const { migrate } = await import("../src/metadata/schema");
      migrate(state.storage.sql); // ensure the rate_buckets table exists
      const store = new DoRateLimitStore(state.storage.sql);
      // capacity 1 ⇒ only ONE request may pass; refill 0 so `now` can't widen it.
      const limiter = new RateLimiter(store, { capacity: 1, refillPerSec: 0 });
      const now = 1_000_000;
      // Fire both concurrently at the SAME now — the classic burst-boundary race.
      const rs = await Promise.all([
        limiter.check("p:race", 1, now),
        limiter.check("p:race", 1, now),
      ]);
      return rs.filter((r) => r.allowed).length;
    });
    expect(admitted).toBe(1); // atomic ⇒ exactly the cap; racy get→set would give 2
  });

  it("the FilespaceDO mutation limiter denies past its capacity over a single burst", async () => {
    // Test bindings set capacity 30. Keep the intended burst at one logical
    // instant: sequential cross-isolate RPC latency can legitimately refill a
    // token on a busy test host and must not turn correct refill into a failure.
    const stub = fsStub("fs-rl-rpc");
    const admitted = await runInDurableObject(stub, async (instance) => {
      const clock = vi.spyOn(Date, 'now').mockReturnValue(Date.now());
      try {
        const results: { allowed: boolean }[] = [];
        for (let i = 0; i < 40; i++) results.push(await (instance as FilespaceDO).rateLimit("mutation", "p:cap", 1));
        return results.filter(r => r.allowed).length;
      } finally { clock.mockRestore(); }
    });
    expect(admitted).toBe(30);
  });
});
