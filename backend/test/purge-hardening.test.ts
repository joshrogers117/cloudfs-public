// SPDX-License-Identifier: AGPL-3.0-or-later
// purge-hardening.test.ts — termination/ordering/revive safety for the IRREVERSIBLE purge sweep.
//
// These cover the adversarial-review findings on the new purge feature (the happy-path sweep is
// already covered by space-purge.test.ts; this file ONLY exercises the failure/edge modes):
//
//   P-F1  Per-key delete errors must TERMINATE the sweep into a `purge_failed` state instead of an
//         infinite, backoff-free alarm storm. A FakeS3 that returns per-key errors for some keys
//         (and deletes NONE of them) must make the sweep HARD-STOP, NOT loop forever; the status
//         poll must report failed. A clean sweep still completes.  (REVERT-PROOF — see the comment
//         on the "infinite-loop" assertion: the bounded step counter proves we don't loop.)
//   P-F2  Re-registering an id mid-purge is REFUSED (no split-brain revive into a deleting DO).
//   P-F3  A hardDeleteSpace failure during finalize leaves the status NOT-done (still purging),
//         recoverable — never "done but not gone".

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { mintToken, type Scope } from "../src/security/auth";

// Cast runInDurableObject so its generic doesn't deeply instantiate the FilespaceDO RPC type
// (TS2589) — same workaround as space-purge.test.ts / space-delete.test.ts.
const runInDo = runInDurableObject as unknown as <R>(
  s: unknown,
  cb: (inst: any, state: DurableObjectState) => R | Promise<R>,
) => Promise<R>;

const ALL_SCOPES: Scope[] = [
  "fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read",
];

let orgCounter = 0;
function freshOrg(): string {
  return `purge-hard-org-${Date.now()}-${orgCounter++}`;
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
  return mintToken((env as any).AUTH_SIGNING_SECRET, {
    sub, type: "session", orgId, scopes: ALL_SCOPES, ttlSeconds: 900,
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
    method: "DELETE", headers: authHeaders(ownerTok),
  });
  expect(res.status).toBe(200);
}

function purgeUrl(orgId: string, spaceId: string): string {
  return `https://gw.local/v1/orgs/${orgId}/spaces/${spaceId}/purge`;
}

function fsStubFor(orgId: string, spaceId: string) {
  const ns = (env as any).FILESPACE;
  return ns.get(ns.idFromName(`${orgId}::${spaceId}`));
}

// ===========================================================================================
// FakeS3 that can be told to return PER-KEY ERRORS (object-lock/retention/legal-hold/Deny) for a
// set of keys, deleting NONE of the keys in that page — the exact stall P-F1 must terminate on.
// ===========================================================================================
class FakeS3 {
  keys = new Set<string>();
  listedPrefixes: string[] = [];
  deletedKeys: string[] = [];
  pageSize: number;
  /// Keys that DeleteObjects rejects with a per-key <Error> (and never removes). Simulates
  /// object-lock retention / legal hold / a scoped DeleteObject Deny.
  undeletableKeys = new Set<string>();
  errorCode = "AccessDenied";

  constructor(pageSize = 1000) {
    this.pageSize = pageSize;
  }

  seed(...keys: string[]) {
    for (const k of keys) this.keys.add(k);
  }

  fetch: typeof fetch = (async (input: any, init?: any) => {
    const url = new URL(typeof input === "string" ? input : input.url);
    const method = (init?.method ?? "GET").toUpperCase();

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

    if (method === "POST" && url.searchParams.has("delete")) {
      const xml = String(init?.body ?? "");
      const re = /<Key>([^<]*)<\/Key>/g;
      const deleted: string[] = [];
      const errored: string[] = [];
      let m: RegExpExecArray | null;
      while ((m = re.exec(xml))) {
        const key = m[1];
        if (this.undeletableKeys.has(key)) {
          errored.push(key); // reported as a per-key <Error>; the object SURVIVES
          continue;
        }
        deleted.push(key);
        this.deletedKeys.push(key);
        this.keys.delete(key);
      }
      const resp =
        `<?xml version="1.0" encoding="UTF-8"?><DeleteResult>` +
        deleted.map((k) => `<Deleted><Key>${k}</Key></Deleted>`).join("") +
        errored.map((k) =>
          `<Error><Key>${k}</Key><Code>${this.errorCode}</Code><Message>blocked</Message></Error>`).join("") +
        `</DeleteResult>`;
      return new Response(resp, { status: 200 });
    }

    return new Response("unexpected request", { status: 400 });
  }) as unknown as typeof fetch;
}

/// Drive the sweep by calling purgeStep repeatedly INSIDE the DO, with a HARD STEP CAP. This is the
/// revert-proof: if P-F1's no-progress detection regresses (the sweep re-lists undeletable keys
/// forever), this loop hits `maxSteps` and the test FAILS via the explicit assertion below — it can
/// never hang. Returns the number of steps actually taken.
async function drive(orgId: string, spaceId: string, s3: FakeS3, maxSteps = 50): Promise<number> {
  const stub = fsStubFor(orgId, spaceId);
  let steps = 0;
  for (; steps < maxSteps; steps++) {
    const r = await runInDo(stub, (inst: any) => inst.purgeStep(s3.fetch));
    if (r.done || !r.remaining) break;
  }
  return steps + 1;
}

describe("PURGE HARDENING — termination / ordering / revive safety", () => {
  // ---------------------------------------------------------------------------------------
  // P-F1: per-key delete errors → terminal purge_failed, NOT an infinite alarm storm.
  // ---------------------------------------------------------------------------------------
  it("P-F1: a page that lists keys but deletes 0 (per-key Deny) HARD-STOPS into purge_failed — no infinite loop", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "locked");
    await softDelete(orgId, "locked", ownerTok);

    const prefix = `blocks/${orgId}::locked/`;
    const s3 = new FakeS3(10);
    s3.seed(`${prefix}a`, `${prefix}b`, `${prefix}c`);
    // ALL keys are object-locked → DeleteObjects rejects every one; none are removed.
    s3.undeletableKeys = new Set([`${prefix}a`, `${prefix}b`, `${prefix}c`]);

    await SELF.fetch(purgeUrl(orgId, "locked"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "locked" }),
    });

    // REVERT-PROOF: a regression that loops forever would exhaust the step cap. The sweep must stop
    // in ONE step (it lists 3, deletes 0 → no progress → terminal failure), well under maxSteps.
    const MAX = 50;
    const steps = await drive(orgId, "locked", s3, MAX);
    expect(steps).toBeLessThan(MAX); // would equal MAX (and the objects would still be present) if P-F1 regressed

    // Terminal failed state: not purging, not done, failed:true with an error sample.
    const status = await runInDo(fsStubFor(orgId, "locked"), (inst: any) => inst.purgeStatus());
    expect(status.purging).toBe(false);
    expect(status.done).toBe(false);
    expect(status.failed).toBe(true);
    expect(typeof status.error).toBe("string");
    expect(status.error).toContain("AccessDenied");

    // The locked objects SURVIVED (we never wiped them or the registry row).
    expect(s3.keys.size).toBe(3);
    const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    expect(await orgStub.getSpaceIncludingDeleted("locked")).not.toBeNull();
  });

  it("P-F1: a PARTIAL stall (some keys deletable, the rest locked) deletes the deletable page then fails on the stuck page", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "partial");
    await softDelete(orgId, "partial", ownerTok);

    const prefix = `blocks/${orgId}::partial/`;
    const s3 = new FakeS3(2); // tiny pages: first page deletes, a later page stalls
    s3.seed(`${prefix}ok1`, `${prefix}ok2`, `${prefix}stuck1`, `${prefix}stuck2`);
    s3.undeletableKeys = new Set([`${prefix}stuck1`, `${prefix}stuck2`]);

    await SELF.fetch(purgeUrl(orgId, "partial"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "partial" }),
    });
    const steps = await drive(orgId, "partial", s3, 50);
    expect(steps).toBeLessThan(50);

    const status = await runInDo(fsStubFor(orgId, "partial"), (inst: any) => inst.purgeStatus());
    expect(status.failed).toBe(true);
    expect(status.purging).toBe(false);
    // The deletable keys WERE removed (progress was made before the stall); the stuck ones remain.
    expect(s3.keys.has(`${prefix}ok1`)).toBe(false);
    expect(s3.keys.has(`${prefix}ok2`)).toBe(false);
    expect(s3.keys.has(`${prefix}stuck1`)).toBe(true);
    expect(s3.keys.has(`${prefix}stuck2`)).toBe(true);
  });

  it("P-F1: a CLEAN sweep (no errors) still completes normally — the failure path doesn't break the happy path", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "clean");
    await softDelete(orgId, "clean", ownerTok);

    const prefix = `blocks/${orgId}::clean/`;
    const s3 = new FakeS3(2);
    s3.seed(`${prefix}x`, `${prefix}y`, `${prefix}z`);
    await SELF.fetch(purgeUrl(orgId, "clean"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "clean" }),
    });
    await drive(orgId, "clean", s3, 50);

    expect(s3.keys.size).toBe(0);
    const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    expect(await orgStub.getSpaceIncludingDeleted("clean")).toBeNull(); // row hard-deleted → completed
  });

  it("P-F1: a re-issued purge POST after a failure re-arms a FRESH sweep (recoverable once the lock is gone)", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "retry");
    await softDelete(orgId, "retry", ownerTok);

    const prefix = `blocks/${orgId}::retry/`;
    const s3 = new FakeS3(10);
    s3.seed(`${prefix}a`, `${prefix}b`);
    s3.undeletableKeys = new Set([`${prefix}a`, `${prefix}b`]); // first attempt stalls

    await SELF.fetch(purgeUrl(orgId, "retry"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "retry" }),
    });
    await drive(orgId, "retry", s3, 50);
    const status = await runInDo(fsStubFor(orgId, "retry"), (inst: any) => inst.purgeStatus());
    expect(status.failed).toBe(true);

    // Operator removes the object-lock → re-issue the purge. The row is still soft-deleted (the
    // failed purge did NOT hard-delete it), so the two-step gate passes and a fresh sweep arms with
    // purge_failed cleared.
    s3.undeletableKeys.clear();
    const reissue = await SELF.fetch(purgeUrl(orgId, "retry"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "retry" }),
    });
    expect(reissue.status).toBe(202);
    await drive(orgId, "retry", s3, 50);

    // The retry succeeded: all objects gone + the registry row hard-deleted (purge completed). We do
    // NOT poll purgeStatus on the just-wiped instance — in prod a fresh request re-instantiates +
    // re-migrates the DO; reusing the wiped in-memory instance here would hit dropped tables.
    expect(s3.keys.size).toBe(0);
    const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    expect(await orgStub.getSpaceIncludingDeleted("retry")).toBeNull();
  });

  it("P-F1: the gateway status poll surfaces the failed state to an owner", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "pollfail");
    await softDelete(orgId, "pollfail", ownerTok);

    const prefix = `blocks/${orgId}::pollfail/`;
    const s3 = new FakeS3(10);
    s3.seed(`${prefix}a`);
    s3.undeletableKeys = new Set([`${prefix}a`]);
    await SELF.fetch(purgeUrl(orgId, "pollfail"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "pollfail" }),
    });
    await drive(orgId, "pollfail", s3, 50);

    const poll = await SELF.fetch(purgeUrl(orgId, "pollfail"), { headers: authHeaders(ownerTok) });
    expect(poll.status).toBe(200);
    const body = (await poll.json()) as any;
    expect(body.failed).toBe(true);
    expect(body.purging).toBe(false);
    expect(body.done).toBe(false);
  });

  // ---------------------------------------------------------------------------------------
  // P-F2: revive mid-purge is refused (no split-brain).
  // ---------------------------------------------------------------------------------------
  it("P-F2: re-registering an id MID-PURGE is refused (409 space_purged) — no revive into a deleting DO", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    const adminTok = await tokenFor(orgId, "admin"); // create/register is admin-gated
    await registerSpace(orgId, "noresurrect");
    await softDelete(orgId, "noresurrect", ownerTok);

    const prefix = `blocks/${orgId}::noresurrect/`;
    const s3 = new FakeS3(1);
    // Many keys + page size 1 → the sweep is genuinely mid-flight (armed, not finalized) after the
    // POST marks the row 'purging'. We do NOT drive it to completion here.
    for (let i = 0; i < 5; i++) s3.seed(`${prefix}k${i}`);

    const start = await SELF.fetch(purgeUrl(orgId, "noresurrect"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "noresurrect" }),
    });
    expect(start.status).toBe(202);

    // Attempt to RE-REGISTER (revive) the same id while the purge is in progress → REFUSED.
    const revive = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces`, {
      method: "POST", headers: authHeaders(adminTok),
      body: JSON.stringify({ spaceId: "noresurrect", name: "Sneaky Revive", bucketProvider: "r2", bucketName: "bkt", keyPrefix: "p/" }),
    });
    expect(revive.status).toBe(409);
    expect((await revive.json() as any).error).toBe("space_purged");

    // The row was NOT revived: it is still tombstoned (deleted_at set), never NULLed back to live.
    // (The gateway 409 above proves registerSpace refused; the durable row state confirms no revive.)
    const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    const reg = await orgStub.getSpaceIncludingDeleted("noresurrect");
    expect(reg).not.toBeNull();
    expect(reg.deletedAt).not.toBeNull();
  });

  it("P-F2: a NORMAL soft-delete → revive (no purge started) STILL works for the OWNER (we only block purged ids)", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "revivable");
    await softDelete(orgId, "revivable", ownerTok);

    // No purge was started → re-register revives it (clears the tombstone). This is the supported
    // recover-a-soft-deleted-space path P-F2 must NOT break. Audit B12: reviving a soft-deleted
    // space (an upsert that clears the tombstone + can repoint storage) is OWNER-ONLY now, since
    // the create path is the only path that can do this — a non-owner admin's create is insert-only.
    const revive = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces`, {
      method: "POST", headers: authHeaders(ownerTok),
      body: JSON.stringify({ spaceId: "revivable", name: "Revived", bucketProvider: "r2", bucketName: "bkt", keyPrefix: "p/" }),
    });
    expect(revive.status).toBe(201);
    const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    const reg = await orgStub.getSpace("revivable"); // getSpace = LIVE only
    expect(reg).not.toBeNull();
    expect(reg.deletedAt).toBeNull();
  });

  it("B12: a NON-OWNER admin CANNOT revive/repoint an existing space through the create path (409)", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    const adminTok = await tokenFor(orgId, "admin");
    await registerSpace(orgId, "owned");
    await softDelete(orgId, "owned", ownerTok);
    // An admin tries to revive (and could repoint storage) via POST /spaces — refused.
    const attempt = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces`, {
      method: "POST", headers: authHeaders(adminTok),
      body: JSON.stringify({ spaceId: "owned", name: "Hijacked", bucketProvider: "r2", bucketName: "attacker-bkt", keyPrefix: "p/" }),
    });
    expect(attempt.status).toBe(409);
    expect((await attempt.json() as any).error).toBe("space_exists");
  });

  // ---------------------------------------------------------------------------------------
  // P-F3: finalize ordering — hardDeleteSpace failure leaves status NOT-done (still purging).
  // ---------------------------------------------------------------------------------------
  it("P-F3: a hardDeleteSpace failure during finalize leaves the sweep NOT-done + still purging (never 'done but not gone')", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    await registerSpace(orgId, "finalize-fail");
    await softDelete(orgId, "finalize-fail", ownerTok);

    const prefix = `blocks/${orgId}::finalize-fail/`;
    const s3 = new FakeS3(10);
    s3.seed(`${prefix}only`);
    await SELF.fetch(purgeUrl(orgId, "finalize-fail"), {
      method: "POST", headers: authHeaders(ownerTok), body: JSON.stringify({ confirm: "finalize-fail" }),
    });

    const stub = fsStubFor(orgId, "finalize-fail");
    // Step 1: delete the single object (page had 1 key → deletedThisStep 1, remaining true).
    const s1 = await runInDo(stub, (inst: any) => inst.purgeStep(s3.fetch));
    expect(s1.deletedThisStep).toBe(1);

    // Step 2: the prefix is now empty → finalize runs hardDeleteSpace. We force that RPC to THROW by
    // temporarily swapping the DO instance's ORG_DO binding for a stub whose hardDeleteSpace
    // rejects, then RESTORE it. purgeStep must THROW (propagating the finalize failure) and leave
    // the DO recoverable.
    await expect(
      runInDo(stub, async (inst: any) => {
        const realOrgDo = inst.env.ORG_DO;
        inst.env.ORG_DO = {
          idFromName: (n: string) => realOrgDo.idFromName(n),
          get: () => ({ hardDeleteSpace: async () => { throw new Error("simulated OrgDO row removal failure"); } }),
        };
        try {
          return await inst.purgeStep(s3.fetch);
        } finally {
          inst.env.ORG_DO = realOrgDo; // restore so recovery below uses the real registry
        }
      }),
    ).rejects.toThrow();

    // P-F3: NOT done, STILL purging — a stalled finalize reads as in-progress, never falsely done.
    const status = await runInDo(stub, (inst: any) => inst.purgeStatus());
    expect(status.done).toBe(false);
    expect(status.purging).toBe(true);

    // The DO was NOT wiped (it's recoverable): its items table still exists.
    const hasItems = await runInDo(stub, (_inst: any, state: DurableObjectState) =>
      state.storage.sql.exec(`SELECT name FROM sqlite_master WHERE type='table' AND name='items';`).toArray().length > 0);
    expect(hasItems).toBe(true);

    // RECOVERY: with the real OrgDO restored, a re-run of the finalize step (empty prefix) now
    // succeeds → done + row gone.
    await drive(orgId, "finalize-fail", s3, 50);
    const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    expect(await orgStub.getSpaceIncludingDeleted("finalize-fail")).toBeNull();
  });
});
