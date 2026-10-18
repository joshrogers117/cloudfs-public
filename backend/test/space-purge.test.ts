// SPDX-License-Identifier: AGPL-3.0-or-later
// space-purge.test.ts — owner-gated, two-step, IRREVERSIBLE purge of a soft-deleted filespace.
//
// POST /v1/orgs/:org/spaces/:id/purge permanently deletes a soft-deleted space's encrypted
// objects from BYO storage (a prefix-scoped sweep) AND hard-deletes its DO metadata + the OrgDO
// registry row. THIS DELETES REAL DATA, so the safety invariants are non-negotiable and tested
// here against a FAKE S3 that RECORDS every list prefix + every deleted key (never hits network):
//
//   PREFIX SCOPING (the critical one): only `blocks/<org>::A/...` keys are deleted; space B's keys
//     and a decoy key just outside the prefix SURVIVE; every list call carried A's exact prefix.
//   TWO-STEP: purge on a LIVE space → 409 must_soft_delete_first; after soft-delete → proceeds.
//   OWNER GATE: admin/space_admin/standard → 403; owner → ok.
//   CONFIRMATION: missing/wrong confirm → 400 confirmation_required.
//   RESUMABILITY/IDEMPOTENCY: a multi-page sweep deletes all pages across alarm ticks; re-running
//     after completion is a no-op; a simulated mid-sweep crash resumes from the cursor.
//   COMPLETION: the FilespaceDO metadata is wiped + the OrgDO row is gone (listSpaces AND
//     getSpaceIncludingDeleted both absent).

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { mintToken, type Scope } from "../src/security/auth";

// Cast runInDurableObject to a minimal shape so its generic doesn't deeply instantiate the full
// FilespaceDO RPC type (TS2589) — same workaround as space-delete.test.ts.
const runInDo = runInDurableObject as unknown as <R>(
  s: unknown,
  cb: (inst: any, state: DurableObjectState) => R | Promise<R>,
) => Promise<R>;

const ALL_SCOPES: Scope[] = [
  "fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read",
];

let orgCounter = 0;
function freshOrg(): string {
  return `purge-org-${Date.now()}-${orgCounter++}`;
}

async function provisionUser(orgId: string, role: string): Promise<string> {
  const org = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
  const u = await org.createUser({
    orgId,
    email: `${role}-${crypto.randomUUID()}@test.local`,
    displayName: role,
    role,
  });
  return u.id;
}

async function tokenFor(orgId: string, role: string): Promise<string> {
  const sub = await provisionUser(orgId, role);
  // Mark the account verified so the org-admin mutation email-gate doesn't 403 the purge POST.
  return mintToken((env as any).AUTH_SIGNING_SECRET, {
    sub,
    type: "session",
    orgId,
    scopes: ALL_SCOPES,
    ttlSeconds: 900,
  });
}

function authHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, "content-type": "application/json" };
}

async function registerSpace(orgId: string, spaceId: string): Promise<void> {
  const stub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
  await stub.registerSpace({ spaceId, orgId, name: `Space ${spaceId}`, bucketProvider: "r2", bucketName: "bkt", keyPrefix: "p/" });
}

async function softDelete(orgId: string, spaceId: string, ownerTok: string): Promise<void> {
  const res = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces/${spaceId}`, {
    method: "DELETE",
    headers: authHeaders(ownerTok),
  });
  expect(res.status).toBe(200);
}

function purgeUrl(orgId: string, spaceId: string): string {
  return `https://gw.local/v1/orgs/${orgId}/spaces/${spaceId}/purge`;
}

// ===========================================================================================
// FAKE S3 — an in-memory object store with a fetch() that speaks ListObjectsV2 + DeleteObjects.
// It RECORDS every prefix it was asked to list and every key it was asked to delete, so the tests
// can assert the sweep NEVER touched anything outside the target prefix. No network is ever hit.
// ===========================================================================================
class FakeS3 {
  keys = new Set<string>();
  listedPrefixes: string[] = [];
  deletedKeys: string[] = [];
  /// Objects returned per ListObjectsV2 page (forces multi-page sweeps to exercise resumability).
  pageSize: number;
  /// When >0, the Nth delete request (1-based) throws to simulate a mid-sweep crash exactly once.
  crashOnDeleteCall = 0;
  private deleteCalls = 0;

  constructor(pageSize = 1000) {
    this.pageSize = pageSize;
  }

  seed(...keys: string[]) {
    for (const k of keys) this.keys.add(k);
  }

  fetch: typeof fetch = (async (input: any, init?: any) => {
    const url = new URL(typeof input === "string" ? input : input.url);
    const method = (init?.method ?? "GET").toUpperCase();

    // ---- ListObjectsV2: GET <bucket>?list-type=2&prefix=...&continuation-token=... ----
    if (method === "GET" && url.searchParams.get("list-type") === "2") {
      const prefix = url.searchParams.get("prefix") ?? "";
      this.listedPrefixes.push(prefix);
      const all = [...this.keys].filter((k) => k.startsWith(prefix)).sort();
      const cont = url.searchParams.get("continuation-token");
      const start = cont ? Number(atob(cont)) : 0;
      const slice = all.slice(start, start + this.pageSize);
      const nextStart = start + slice.length;
      const truncated = nextStart < all.length;
      const nextToken = truncated ? btoa(String(nextStart)) : "";
      const body =
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<ListBucketResult>` +
        slice.map((k) => `<Contents><Key>${k}</Key></Contents>`).join("") +
        `<IsTruncated>${truncated}</IsTruncated>` +
        (truncated ? `<NextContinuationToken>${nextToken}</NextContinuationToken>` : "") +
        `</ListBucketResult>`;
      return new Response(body, { status: 200 });
    }

    // ---- DeleteObjects: POST <bucket>?delete= ----
    if (method === "POST" && url.searchParams.has("delete")) {
      this.deleteCalls++;
      if (this.crashOnDeleteCall === this.deleteCalls) {
        throw new Error("simulated S3 crash mid-sweep");
      }
      const xml = String(init?.body ?? "");
      const re = /<Key>([^<]*)<\/Key>/g;
      const deleted: string[] = [];
      let m: RegExpExecArray | null;
      while ((m = re.exec(xml))) {
        const key = m[1];
        deleted.push(key);
        this.deletedKeys.push(key);
        this.keys.delete(key); // idempotent: deleting an absent key is harmless
      }
      const resp =
        `<?xml version="1.0" encoding="UTF-8"?><DeleteResult>` +
        deleted.map((k) => `<Deleted><Key>${k}</Key></Deleted>`).join("") +
        `</DeleteResult>`;
      return new Response(resp, { status: 200 });
    }

    return new Response("unexpected request", { status: 400 });
  }) as unknown as typeof fetch;
}

function fsStubFor(orgId: string, spaceId: string) {
  const ns = (env as any).FILESPACE;
  return ns.get(ns.idFromName(`${orgId}::${spaceId}`));
}

/// Drive the purge sweep to completion by calling purgeStep(fakeFetch) repeatedly INSIDE the DO
/// (the alarm would do this in prod; we drive it explicitly so the test stays deterministic and
/// can inject the fake S3). Returns the number of steps taken.
async function drivePurgeToDone(orgId: string, spaceId: string, s3: FakeS3, maxSteps = 100): Promise<number> {
  const stub = fsStubFor(orgId, spaceId);
  let steps = 0;
  for (; steps < maxSteps; steps++) {
    // IMPORTANT: don't touch the DO instance AFTER purgeStep returns — the finalizing step calls
    // deleteAll(), so any later `inst.*` in the same callback would hit a wiped schema. We decide
    // solely from the returned step result.
    const r = await runInDo(stub, (inst: any) => inst.purgeStep(s3.fetch));
    if (r.done || (!r.remaining)) break;
  }
  return steps + 1;
}

describe("POST /v1/orgs/:org/spaces/:id/purge — owner-gated two-step IRREVERSIBLE purge", () => {
  // ---- THE CRITICAL TEST: prefix scoping ----
  it("PREFIX SCOPING: purging space A deletes ONLY blocks/<org>::A/... — space B + a decoy survive", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "A");
    await registerSpace(orgId, "B");

    const s3 = new FakeS3(2); // tiny pages → exercise multi-page sweep too
    const aPrefix = `blocks/${orgId}::A/`;
    const bPrefix = `blocks/${orgId}::B/`;
    // Space A objects (to be deleted), space B objects (must survive), and a DECOY that shares a
    // string prefix up to "A" but is NOT under A's exact prefix (must survive).
    s3.seed(
      `${aPrefix}file1`, `${aPrefix}sub/file2`, `${aPrefix}file3`,
      `${bPrefix}keepB1`, `${bPrefix}keepB2`,
      `blocks/${orgId}::AA/decoy`,            // ::AA is a DIFFERENT space — must NOT match ::A/
      `blocks/${orgId}::A-other/decoy`,       // sibling that shares the "A" stem — must survive
      `blocks/other-org::A/cross-tenant`,     // another org entirely — must survive
    );
    const before = new Set(s3.keys);

    await softDelete(orgId, "A", ownerTok);
    const res = await SELF.fetch(purgeUrl(orgId, "A"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "A" }),
    });
    expect(res.status).toBe(202);
    expect((await res.json() as any).purging).toBe(true);

    await drivePurgeToDone(orgId, "A", s3);

    // EXACTLY space A's keys were deleted — nothing else.
    expect([...s3.deletedKeys].sort()).toEqual([`${aPrefix}file1`, `${aPrefix}file3`, `${aPrefix}sub/file2`]);
    // Survivors: space B + every decoy.
    expect(s3.keys.has(`${bPrefix}keepB1`)).toBe(true);
    expect(s3.keys.has(`${bPrefix}keepB2`)).toBe(true);
    expect(s3.keys.has(`blocks/${orgId}::AA/decoy`)).toBe(true);
    expect(s3.keys.has(`blocks/${orgId}::A-other/decoy`)).toBe(true);
    expect(s3.keys.has(`blocks/other-org::A/cross-tenant`)).toBe(true);
    // No A key survives.
    expect([...s3.keys].some((k) => k.startsWith(aPrefix))).toBe(false);

    // EVERY list call carried space A's EXACT prefix — never an empty/broad prefix, never B's.
    expect(s3.listedPrefixes.length).toBeGreaterThan(0);
    for (const p of s3.listedPrefixes) expect(p).toBe(aPrefix);

    // EVERY deleted key was under A's prefix (defense in depth re-asserted at delete time).
    for (const k of s3.deletedKeys) expect(k.startsWith(aPrefix)).toBe(true);

    // Sanity: the decoys we expected to survive really were present to begin with.
    expect(before.has(`blocks/${orgId}::AA/decoy`)).toBe(true);
  });

  // ---- STATUS AFTER FINALIZE (regression) ----
  // A live-runtime E2E found that once a purge finalizes (hardDeleteSpace + deleteAll wipe the
  // FilespaceDO's `meta` table), GET .../purge errored `no such table: meta: SQLITE_ERROR` forever
  // because the handler called purgeStatus() on the wiped DO. The web treats a 404 as "purge done",
  // so the fix detects the gone registry row and reports completion via 404 instead.
  it("STATUS-after-finalize: GET .../purge returns 404 done (NOT a wiped-DO SQLite error)", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "fin");
    const s3 = new FakeS3(10);
    s3.seed(`blocks/${orgId}::fin/a`, `blocks/${orgId}::fin/b`);

    await softDelete(orgId, "fin", ownerTok);
    const start = await SELF.fetch(purgeUrl(orgId, "fin"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "fin" }),
    });
    expect(start.status).toBe(202);

    await drivePurgeToDone(orgId, "fin", s3);

    const st = await SELF.fetch(purgeUrl(orgId, "fin"), { method: "GET", headers: authHeaders(ownerTok) });
    expect(st.status).toBe(404);
    const body = (await st.json()) as any;
    expect(body.done).toBe(true);
    expect(JSON.stringify(body)).not.toContain("no such table");
  });

  // ---- TWO-STEP ----
  it("TWO-STEP: purge on a LIVE (not soft-deleted) space → 409 must_soft_delete_first", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "live");

    const res = await SELF.fetch(purgeUrl(orgId, "live"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "live" }),
    });
    expect(res.status).toBe(409);
    expect((await res.json() as any).error).toBe("must_soft_delete_first");

    // Still live + present.
    const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    expect(await orgStub.getSpace("live")).not.toBeNull();
  });

  it("TWO-STEP: purge AFTER soft-delete proceeds (202)", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "two-step");
    await softDelete(orgId, "two-step", ownerTok);

    const res = await SELF.fetch(purgeUrl(orgId, "two-step"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "two-step" }),
    });
    expect(res.status).toBe(202);
  });

  it("TWO-STEP: purge on an UNKNOWN space id → 404", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    const res = await SELF.fetch(purgeUrl(orgId, "ghost"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "ghost" }),
    });
    expect(res.status).toBe(404);
  });

  // ---- OWNER GATE ----
  it("OWNER GATE: admin / space_admin / standard → 403; owner → 202", async () => {
    for (const role of ["admin", "space_admin", "standard"]) {
      const orgId = freshOrg();
      const ownerTok = await tokenFor(orgId, "owner");
      const spaceId = `og-${role}`;
      await registerSpace(orgId, spaceId);
      await softDelete(orgId, spaceId, ownerTok);

      const tok = await tokenFor(orgId, role);
      const res = await SELF.fetch(purgeUrl(orgId, spaceId), {
        method: "POST", headers: authHeaders(tok), body: JSON.stringify({ confirm: spaceId }),
      });
      expect(res.status).toBe(403);
      // Not purging — the OrgDO row is still present (soft-deleted but not gone).
      const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
      expect(await orgStub.getSpaceIncludingDeleted(spaceId)).not.toBeNull();
    }
  });

  // ---- CONFIRMATION ----
  it("CONFIRMATION: missing or wrong confirm → 400 confirmation_required", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "conf");
    await softDelete(orgId, "conf", ownerTok);

    const missing = await SELF.fetch(purgeUrl(orgId, "conf"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({}),
    });
    expect(missing.status).toBe(400);
    expect((await missing.json() as any).error).toBe("confirmation_required");

    const wrong = await SELF.fetch(purgeUrl(orgId, "conf"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "not-conf" }),
    });
    expect(wrong.status).toBe(400);

    const empty = await SELF.fetch(purgeUrl(orgId, "conf"), {
      method: "POST", headers: authHeaders(ownerTok),
    });
    expect(empty.status).toBe(400);

    // Still NOT purging.
    const status = await runInDo(fsStubFor(orgId, "conf"), (inst: any) => inst.isPurging());
    expect(status).toBe(false);
  });

  // ---- RESUMABILITY / IDEMPOTENCY ----
  it("RESUMABILITY: a multi-page sweep deletes every page across ticks", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "multi");
    await softDelete(orgId, "multi", ownerTok);

    const prefix = `blocks/${orgId}::multi/`;
    const s3 = new FakeS3(3); // 3 keys/page
    const seeded: string[] = [];
    for (let i = 0; i < 10; i++) seeded.push(`${prefix}obj-${String(i).padStart(2, "0")}`);
    s3.seed(...seeded);

    await SELF.fetch(purgeUrl(orgId, "multi"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "multi" }),
    });
    const steps = await drivePurgeToDone(orgId, "multi", s3);

    expect(steps).toBeGreaterThan(1); // genuinely multi-page
    expect([...s3.deletedKeys].sort()).toEqual([...seeded].sort());
    expect(s3.keys.size).toBe(0);
  });

  it("IDEMPOTENCY: re-running purgeStep after completion is a no-op", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "idem");
    await softDelete(orgId, "idem", ownerTok);

    const prefix = `blocks/${orgId}::idem/`;
    const s3 = new FakeS3(5);
    s3.seed(`${prefix}a`, `${prefix}b`);
    await SELF.fetch(purgeUrl(orgId, "idem"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "idem" }),
    });
    await drivePurgeToDone(orgId, "idem", s3);
    const deletedAfterFirst = s3.deletedKeys.length;
    expect(deletedAfterFirst).toBe(2);

    // The space is now hard-deleted (row gone). Re-issuing the purge POST is a safe no-op → 404
    // (the two-step + registry-authority guard refuses a space that no longer exists), and NO
    // additional storage deletes happen.
    const reissue = await SELF.fetch(purgeUrl(orgId, "idem"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "idem" }),
    });
    expect(reissue.status).toBe(404);
    expect(s3.deletedKeys.length).toBe(deletedAfterFirst);
  });

  it("IDEMPOTENCY: a step that re-lists already-deleted keys (before finalize) deletes nothing extra", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "idem2");
    await softDelete(orgId, "idem2", ownerTok);

    const prefix = `blocks/${orgId}::idem2/`;
    const s3 = new FakeS3(10);
    s3.seed(`${prefix}a`, `${prefix}b`, `${prefix}c`);
    await SELF.fetch(purgeUrl(orgId, "idem2"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "idem2" }),
    });
    const stub = fsStubFor(orgId, "idem2");
    // First step deletes all 3 (page size 10). It returns remaining:true (the page had keys), so
    // the sweep is NOT yet finalized — the DO is still intact + purging.
    const s1 = await runInDo(stub, (inst: any) => inst.purgeStep(s3.fetch));
    expect(s1.deletedThisStep).toBe(3);
    expect(await runInDo(stub, (inst: any) => inst.isPurging())).toBe(true);
    // Second step re-lists (now empty) → deletes nothing → finalizes.
    const s2 = await runInDo(stub, (inst: any) => inst.purgeStep(s3.fetch));
    expect(s2.deletedThisStep).toBe(0);
    expect(s2.done).toBe(true);
    expect(s3.deletedKeys.length).toBe(3); // never deleted a key twice
  });

  it("RESUMABILITY: a simulated mid-sweep crash resumes from the cursor with no double-list gap", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "crash");
    await softDelete(orgId, "crash", ownerTok);

    const prefix = `blocks/${orgId}::crash/`;
    const s3 = new FakeS3(2);
    const seeded: string[] = [];
    for (let i = 0; i < 8; i++) seeded.push(`${prefix}k-${String(i).padStart(2, "0")}`);
    s3.seed(...seeded);
    s3.crashOnDeleteCall = 2; // blow up the 2nd delete batch mid-sweep

    await SELF.fetch(purgeUrl(orgId, "crash"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "crash" }),
    });

    const stub = fsStubFor(orgId, "crash");
    // Step 1 deletes a page. Step 2 throws (simulated crash) — purge state stays intact + armed.
    await runInDo(stub, (inst: any) => inst.purgeStep(s3.fetch));
    await expect(
      runInDo(stub, (inst: any) => inst.purgeStep(s3.fetch)),
    ).rejects.toThrow(/simulated S3 crash/);
    // Still purging (resumable) — the crash didn't clear the durable state or finalize.
    expect(await runInDo(stub, (inst: any) => inst.isPurging())).toBe(true);

    // Resume to completion (no more injected crash).
    s3.crashOnDeleteCall = 0;
    await drivePurgeToDone(orgId, "crash", s3);

    // All seeded keys deleted exactly once-effectively (set membership), prefix empty.
    expect(s3.keys.size).toBe(0);
    for (const k of seeded) expect(s3.deletedKeys).toContain(k);
    // Never listed anything but the crash space's exact prefix.
    for (const p of s3.listedPrefixes) expect(p).toBe(prefix);
  });

  // ---- COMPLETION: metadata wiped + registry row gone ----
  it("COMPLETION: after the sweep, FilespaceDO metadata is wiped + the OrgDO row is gone", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "done");
    await softDelete(orgId, "done", ownerTok);

    const prefix = `blocks/${orgId}::done/`;
    const s3 = new FakeS3(4);
    s3.seed(`${prefix}x`, `${prefix}y`, `${prefix}z`);

    await SELF.fetch(purgeUrl(orgId, "done"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "done" }),
    });
    await drivePurgeToDone(orgId, "done", s3);

    // OrgDO registry row HARD deleted: absent from listSpaces AND getSpaceIncludingDeleted.
    const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    expect(((await orgStub.listSpaces()) as any[]).map((s) => s.id)).not.toContain("done");
    expect(await orgStub.getSpaceIncludingDeleted("done")).toBeNull();

    // FilespaceDO storage WIPED: deleteAll() drops every user table. Prove it via sqlite_master
    // (which always exists) — none of this DO's tables (items / meta / meta_text / audit / blocks)
    // remain. A wiped DO is indistinguishable from a never-created one.
    const tables = await runInDo(fsStubFor(orgId, "done"), (_inst: any, state: DurableObjectState) => {
      const rows = state.storage.sql
        .exec(`SELECT name FROM sqlite_master WHERE type='table';`)
        .toArray()
        .map((r: any) => String(r.name));
      return rows;
    });
    // No application tables survive the wipe (only possibly-internal SQLite bookkeeping like
    // sqlite_sequence, never our schema).
    for (const t of ["items", "meta", "meta_text", "audit", "blocks", "snapshots", "locks"]) {
      expect(tables).not.toContain(t);
    }
  });

  it("STATUS: GET .../purge reports progress and is owner-gated", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "status");
    await softDelete(orgId, "status", ownerTok);

    // Non-owner can't poll.
    const stdTok = await tokenFor(orgId, "standard");
    const denied = await SELF.fetch(purgeUrl(orgId, "status"), { headers: authHeaders(stdTok) });
    expect(denied.status).toBe(403);

    // Owner poll before purge: not purging.
    const pre = await SELF.fetch(purgeUrl(orgId, "status"), { headers: authHeaders(ownerTok) });
    expect(pre.status).toBe(200);
    expect((await pre.json() as any).purging).toBe(false);

    // Start purge, then poll mid-flight (armed, not yet done).
    const prefix = `blocks/${orgId}::status/`;
    const s3 = new FakeS3(1);
    s3.seed(`${prefix}a`, `${prefix}b`, `${prefix}c`);
    await SELF.fetch(purgeUrl(orgId, "status"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "status" }),
    });
    const mid = await SELF.fetch(purgeUrl(orgId, "status"), { headers: authHeaders(ownerTok) });
    const midBody = (await mid.json()) as any;
    expect(midBody.purging).toBe(true);
    expect(midBody.prefix).toBe(prefix);
  });
});
