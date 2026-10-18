// SPDX-License-Identifier: AGPL-3.0-or-later
// sec-hardening-2.test.ts — regression suite for the SECOND-PASS adversarial review findings:
//   A. items/_seed + items/_count had NO authorization (arbitrary namespace write + DoS via
//      unclamped count). Now require fs:write + ACL `create` on the parent for _seed, fs:read for
//      _count, and CLAMP/REJECT an over-bound count.
//   B. cross-tenant confused deputy: any org's owner/admin could rewrite the DEPLOYMENT-WIDE
//      auth-config singleton (SSO hijack). Now only the designated PRIMARY org may. (The end-to-end
//      attacker-refused proof lives in auth-config-integration.test.ts; this file covers the _seed/
//      _count authZ + clamp and the concurrent audit-chain seal.)
//   C. audit-chain append was a read-modify-write across a NON-storage await (crypto digest) → two
//      concurrent appends for the SAME (org,space) dropped/forked records (seq collision). Now the
//      seal is wrapped in blockConcurrencyWhile so it is atomic w.r.t. other deliveries.

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { mintToken, filespaceDoName, type Scope } from "../src/security/auth";
import { verifyChain, type AuditRecord, type AuditEvent } from "../src/security/audit";
import { BULK_SEED_MAX } from "../src/filespace-do";

const ORG = "org1";
const ALL_SCOPES: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];
const SECRET = (env as any).AUTH_SIGNING_SECRET as string;

async function provisionUser(orgId: string, role: string): Promise<string> {
  const org = (env as any).ORG_DO.getByName(orgId);
  const u = await org.createUser({ orgId, email: `${role}-${crypto.randomUUID()}@test.local`, displayName: role, role });
  return u.id;
}
async function token(sub: string, scopes: Scope[] = ALL_SCOPES): Promise<string> {
  return mintToken(SECRET, { sub, type: "session", orgId: ORG, scopes, ttlSeconds: 900 });
}
function api(space: string, auth: Record<string, string>) {
  const base = `https://gw.local/v1/filespaces/${space}`;
  return {
    get: (path: string) => SELF.fetch(`${base}${path}`, { headers: auth }),
    send: (method: string, path: string, body?: unknown) =>
      SELF.fetch(`${base}${path}`, { method, headers: auth, body: body ? JSON.stringify(body) : undefined }),
  };
}
function fsStub(space: string) {
  return (env as any).FILESPACE.get((env as any).FILESPACE.idFromName(filespaceDoName(ORG, space)));
}

// =====================================================================================
// FINDING A — items/_seed and items/_count now require scope + ACL, and count is bounded.
// =====================================================================================
describe("FINDING A: _seed / _count are authorized + count-clamped", () => {
  let adminAuth: Record<string, string>;
  let readOnlyAuth: Record<string, string>;
  beforeAll(async () => {
    adminAuth = { Authorization: `Bearer ${await token(await provisionUser(ORG, "admin"))}`, "content-type": "application/json" };
    // A STANDARD principal holding ONLY fs:read and ZERO ACL grants — the exact "passed
    // verifyRequest + assertTenant but otherwise unprivileged" case the finding describes.
    readOnlyAuth = { Authorization: `Bearer ${await token(await provisionUser(ORG, "standard"), ["fs:read"])}`, "content-type": "application/json" };
  });

  it("a fs:read-only principal is 403 on POST _seed (no write scope / no ACL)", async () => {
    const a = api("fs-A-seed-authz", readOnlyAuth);
    const res = await a.send("POST", "/items/_seed", { parent: "root", prefix: "x", count: 5 });
    expect(res.status).toBe(403);
    // And nothing was written: an admin then sees zero seeded children under root/x*.
    const admin = api("fs-A-seed-authz", adminAuth);
    const count = (await (await admin.get("/items/_count?parent=root")).json()) as { count: number };
    // root has only the default seeded dirs (Project A, Archive) — no injected inodes.
    expect(count.count).toBeLessThanOrEqual(2);
  });

  it("a no-grant fs:read principal is now 404 (INVISIBLE) on _count of an ungranted folder; a no-scope token is 403", async () => {
    // N-F3: `_count` is now gated by the SAME per-folder read ACL as getItem/listPage. A standard
    // principal with fs:read scope but ZERO grants must not learn an ungranted folder exists or its
    // child count — it is INVISIBLE (404), not a leaked 200. (Updated from the pre-N-F3 contract,
    // which only checked the scope and returned 200 — the leak this fix closes.)
    const a = api("fs-A-count-authz", readOnlyAuth);
    expect((await a.get("/items/_count?parent=root")).status).toBe(404);

    // A token with NO fs:read scope is still rejected at the SCOPE gate first (403, before ACL).
    const noScope = { Authorization: `Bearer ${await token(await provisionUser(ORG, "standard"), ["fs:lock"])}` };
    const b = api("fs-A-count-authz", noScope);
    expect((await b.get("/items/_count?parent=root")).status).toBe(403);
  });

  it("an admin can still seed (the legitimate benchmark seam keeps working)", async () => {
    const a = api("fs-A-seed-ok", adminAuth);
    const res = await a.send("POST", "/items/_seed", { parent: "root", prefix: "clip-", count: 50 });
    expect(res.status).toBe(200);
    expect((await res.json() as any).created).toBe(50);
  });

  it("an over-bound count is REJECTED (400) — DoS guard on the single-threaded DO", async () => {
    const a = api("fs-A-seed-clamp", adminAuth);
    const res = await a.send("POST", "/items/_seed", { parent: "root", prefix: "x", count: 100_000_000 });
    expect(res.status).toBe(400);
    expect((await res.json() as any).max).toBe(BULK_SEED_MAX);
    // Nothing was written by the rejected request.
    const count = (await (await a.get("/items/_count?parent=root")).json()) as { count: number };
    expect(count.count).toBeLessThanOrEqual(2);
  });

  it("the DO's bulkCreate clamps defensively even if reached directly (never wedges)", async () => {
    // Direct RPC: seedChildren delegates to bulkCreate, which clamps count to BULK_SEED_MAX.
    const created = await fsStub("fs-A-seed-direct").seedChildren("root", "y", BULK_SEED_MAX + 10_000, false);
    expect(created).toBe(BULK_SEED_MAX);
  });
});

// =====================================================================================
// FINDING C — concurrent appendAudit on the SAME space does not drop or fork records.
// The seal is a read-modify-write: tail() (SQL) → hashRecord() (crypto.subtle.digest, a
// NON-storage await that OPENS the DO input gate) → append() (INSERT, seq is PRIMARY KEY).
// Two appends in flight together both read the same tail across the digest yield, both
// compute the same seq, and the 2nd INSERT throws `UNIQUE constraint failed: audit.seq` —
// a silently-lost audit event / forked chain. The fix wraps the seal in
// blockConcurrencyWhile so no other append interleaves between tail() and append().
//
// REVERT-PROOF: with the blockConcurrencyWhile removed, the first sub-test below FAILS
// (3 of 4 appends throw UNIQUE-constraint; only seq 0 lands). Verified during development.
// =====================================================================================
describe("FINDING C: concurrent audit-chain appends stay contiguous + verifiable", () => {
  /// Drain the full chain for (ORG, space) ascending by seq.
  async function fullChain(space: string): Promise<AuditRecord[]> {
    const recs = (await fsStub(space).queryAudit({ orgId: ORG, spaceId: space, limit: 10_000 })) as AuditRecord[];
    return [...recs].sort((a, b) => a.seq - b.seq);
  }

  function ev(space: string, i: number): AuditEvent {
    return { actorSub: `actor-${i}`, actorType: "session", orgId: ORG, spaceId: space, action: "presign.mint", decision: "allow", detail: { i } };
  }

  it("N concurrent appendAudit calls (one DO context) all land — unique contiguous seqs, continuous chain", async () => {
    const SP = "fs-C-concurrent";
    const stub = fsStub(SP);
    const N = 24;

    // Fire all N appendAudit calls CONCURRENTLY within a single DO execution context — this is
    // where the read→digest→append race is exposed: without the blockConcurrencyWhile seal the
    // crypto-digest await lets the in-flight calls interleave on the same tail() → seq collision.
    type Outcome = { ok: true; seq: number } | { ok: false; reason: string };
    // Cast the stub to a minimal shape so `runInDurableObject`'s generic doesn't deeply
    // instantiate the full FilespaceDO RPC type (TS2589).
    const run = runInDurableObject as unknown as (
      s: unknown,
      cb: (inst: any, state: unknown) => Promise<Outcome[]>,
    ) => Promise<Outcome[]>;
    const results: Outcome[] = await run(stub, async (inst) => {
      const calls: Promise<{ seq: number; hash: string }>[] = Array.from({ length: N }, (_, i) => inst.appendAudit(ev(SP, i)));
      const settled = await Promise.allSettled(calls);
      return settled.map((r): Outcome =>
        r.status === "fulfilled" ? { ok: true, seq: r.value.seq } : { ok: false, reason: String((r.reason as any)?.message ?? r.reason) },
      );
    });

    // (1) Every call SUCCEEDED — none threw a UNIQUE-constraint error / was swallowed/lost.
    const failures = results.filter((r) => !r.ok);
    expect(failures, JSON.stringify(failures)).toHaveLength(0);

    // (2) All seqs are UNIQUE (no collision) and form a CONTIGUOUS run from 0 (no gap/drop).
    const seqs = results.map((r) => (r.ok ? r.seq : -1)).sort((a, b) => a - b);
    expect(new Set(seqs).size).toBe(N);
    expect(seqs).toEqual(seqs.map((_, i) => i));

    // (3) The persisted chain has exactly N records and verifyChain is OK (no fork: each
    //     record's prevHash is the true immediate predecessor's hash).
    const chain = await fullChain(SP);
    expect(chain.length).toBe(N);
    expect((await verifyChain(chain)).ok).toBe(true);

    // (4) All N distinct events are present (none silently lost).
    expect(new Set(chain.map((r) => r.actorSub)).size).toBe(N);
  });

  it("concurrent GATEWAY mutations each produce exactly one chained audit record", async () => {
    const SP = "fs-C-gateway";
    const adminAuth = { Authorization: `Bearer ${await token(await provisionUser(ORG, "admin"))}`, "content-type": "application/json" };
    const a = api(SP, adminAuth);
    const M = 16;

    // Concurrent presign mints — each gated mutation appends one audit record at the gateway.
    await Promise.all(
      Array.from({ length: M }, (_, i) =>
        a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/seg/${i}`, method: "PUT" }),
      ),
    );

    const chain = await fullChain(SP);
    // Each successful mint chained exactly one record; the chain is intact (no drops/forks).
    const mints = chain.filter((r) => r.action === "presign.mint" && r.decision === "allow");
    expect(mints.length).toBe(M);
    const v = await verifyChain(chain);
    expect(v.ok).toBe(true);
    // seqs are contiguous from 0.
    const seqs = chain.map((r) => r.seq);
    expect(seqs).toEqual(seqs.map((_, i) => i));
  });
});
