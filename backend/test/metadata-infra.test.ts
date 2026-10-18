// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { mintToken, filespaceDoName, type Scope } from "../src/security/auth";
import {
  AuditLog,
  InMemoryAuditStore,
  verifyChain,
  type AuditEvent,
  type AuditRecord,
} from "../src/security/audit";
import { R2AuditArchive, type AuditR2 } from "../src/metadata/audit-archive";

// Regression suite for three reviewed metadata-infra findings:
//   1) shared-lock re-acquire by a NEW owner must NOT clobber the incumbent's
//      owner/fence (lost-lock bug),
//   2) same-day audit seal must NOT read-modify-write the whole day file
//      (O(day^2) RMW) — each flush is its own immutable, bounded segment,
//   3) verifyAuditContinuity must verify a multi-segment chain incrementally and
//      still pinpoint a deliberately broken link.

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
function fsStub(space: string) {
  return (env as any).FILESPACE.get((env as any).FILESPACE.idFromName(filespaceDoName(ORG, space)));
}

// A tiny in-memory R2 stand-in (mirrors audit-archive.test.ts's FakeR2).
class FakeR2 implements AuditR2 {
  store = new Map<string, string>();
  puts = 0;
  async get(key: string) {
    const v = this.store.get(key);
    return v === undefined ? null : { text: async () => v };
  }
  async put(key: string, value: string) {
    this.puts++;
    this.store.set(key, value);
    return undefined;
  }
}
function evt(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    actorSub: "alice", actorType: "session", orgId: "acme", spaceId: "space-1",
    action: "presign.mint", decision: "allow", ...over,
  };
}

// ---------------------------------------------------------------------------
// FINDING 1: shared-lock re-acquire by a DIFFERENT owner must not steal the lease.
describe("Finding 1: shared-lock re-acquire never clobbers the incumbent", () => {
  it("a 2nd different shared owner is REJECTED and the 1st holder can still renew", async () => {
    const stub = fsStub("fs-lock-shared");
    const PATH = "root/clip.mov";

    // Holder A takes a shared lease and gets fence Fa.
    const a = await stub.acquireLock(PATH, "userA", 30_000, "shared");
    expect(a.granted).toBe(true);
    expect(a.mode).toBe("shared");
    const Fa = a.fence as number;
    expect(typeof Fa).toBe("number");

    // Holder B (DIFFERENT owner) requests the same shared lock. Pre-fix this did
    // `UPDATE locks SET owner=?, fence=?` — silently evicting A and minting a new
    // fence. Post-fix: B is rejected with a typed conflict naming A.
    const b = await stub.acquireLock(PATH, "userB", 30_000, "shared");
    expect(b.granted).toBe(false);
    expect(b.heldBy).toBe("userA");
    expect(b.reason).toBe("held-by-other");

    // Shared authority must never authorize publication; renewal below proves
    // that A's lease remains intact without granting it write capability.
    expect(await stub.validateFence(PATH, Fa)).toBe(false);
    // And A can still renew with its original fence (proves the row is unchanged).
    const renewed = await stub.renewLock(PATH, "userA", Fa, 30_000);
    expect(renewed.granted).toBe(true);
    expect(renewed.fence).toBe(Fa);
    // Status still reports A as the holder, not B.
    const st = await stub.lockStatus(PATH);
    expect(st.heldBy).toBe("userA");
  });

  it("the SAME shared owner re-acquiring is still an idempotent renew (keeps its fence)", async () => {
    const stub = fsStub("fs-lock-shared-idem");
    const PATH = "root/again.mov";
    const a1 = await stub.acquireLock(PATH, "userA", 30_000, "shared");
    const a2 = await stub.acquireLock(PATH, "userA", 30_000, "shared");
    expect(a2.granted).toBe(true);
    expect(a2.fence).toBe(a1.fence); // same fence ⇒ no token churn on retry
  });

  it("exclusive-lock semantics are unchanged (different owner still conflicts)", async () => {
    const stub = fsStub("fs-lock-excl");
    const PATH = "root/excl.mov";
    const a = await stub.acquireLock(PATH, "userA", 30_000, "exclusive");
    expect(a.granted).toBe(true);
    const b = await stub.acquireLock(PATH, "userB", 30_000, "exclusive");
    expect(b.granted).toBe(false);
    expect(b.heldBy).toBe("userA");
    // A's exclusive fence is intact.
    expect(await stub.validateFence(PATH, a.fence as number)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// FINDING 2: many same-day flushes ⇒ immutable per-flush segments, no RMW.
describe("Finding 2: same-day audit seal writes immutable per-flush segments (no RMW)", () => {
  // All records land on the same UTC day; pre-fix every flush re-read + re-PUT the
  // whole day file (O(M*K)). Post-fix each flush is its own write-once object.
  const DAY = Date.UTC(2026, 5, 1, 12, 0, 0); // 2026-06-01

  async function buildSameDay(n: number): Promise<AuditRecord[]> {
    const log = new AuditLog(new InMemoryAuditStore());
    const recs: AuditRecord[] = [];
    for (let i = 0; i < n; i++) recs.push(await log.write(evt({ action: `a${i}` }), DAY + i));
    return recs;
  }

  it("each flush is a separate immutable object; the day file is never rewritten", async () => {
    const r2 = new FakeR2();
    const archive = new R2AuditArchive(r2, "acme::space-1");
    const FLUSHES = 12;
    const PER = 5;
    const recs = await buildSameDay(FLUSHES * PER);

    // Capture each flush's segment key + the put count, proving no prior segment
    // body is ever re-PUT (RMW would re-PUT a growing day object every flush).
    const segmentKeysAfter: number[] = [];
    for (let f = 0; f < FLUSHES; f++) {
      const before = r2.puts;
      const through = await archive.seal(recs.slice(f * PER, f * PER + PER));
      expect(through).toBe(f * PER + PER - 1);
      // Exactly 2 puts per flush: ONE new immutable segment body + ONE index.json.
      // (RMW would still be 2 puts, but the segment body would GROW each flush;
      // we assert bounded body size below.)
      expect(r2.puts - before).toBe(2);
      const idx = await archive.loadIndex();
      segmentKeysAfter.push(idx.segments.length);
    }

    const index = await archive.loadIndex();
    // One segment PER flush on the same day (the finding's "now-multiple per-day
    // segments"), ascending by firstSeq, contiguous, no gaps.
    expect(index.segments).toHaveLength(FLUSHES);
    for (let i = 0; i < index.segments.length; i++) {
      expect(index.segments[i].firstSeq).toBe(i * PER);
      expect(index.segments[i].lastSeq).toBe(i * PER + PER - 1);
      expect(index.segments[i].count).toBe(PER); // BOUNDED: never grows with day size
      if (i > 0) expect(index.segments[i].firstPrevHash).toBe(index.segments[i - 1].lastHash);
    }

    // Per-object body size is bounded to one flush (PER records), NOT the whole
    // day — the RMW bug grew one object to FLUSHES*PER lines.
    for (const seg of index.segments) {
      const body = r2.store.get(seg.key)!;
      const lines = body.split("\n").filter((l) => l.trim().length > 0);
      expect(lines.length).toBe(PER);
    }
    // The legacy single per-day object is NOT created (proves we left the RMW path).
    expect(r2.store.has("audit/acme::space-1/2026-06-01.ndjson")).toBe(false);

    // Reader still reconstructs the full ordered history across the many segments,
    // and the hash chain verifies end-to-end (continuity preserved).
    const all = await archive.allArchived();
    expect(all.map((r) => r.seq)).toEqual(recs.map((r) => r.seq));
    expect((await verifyChain(all)).ok).toBe(true);
    const cont = await archive.verifyManifestContinuity();
    expect(cont.ok).toBe(true);
  });

  it("re-flushing an already-sealed same-day batch is an idempotent no-op (no fork)", async () => {
    const r2 = new FakeR2();
    const archive = new R2AuditArchive(r2, "acme::space-1");
    const recs = await buildSameDay(4);
    await archive.seal(recs.slice(0, 2));
    await archive.seal(recs.slice(2, 4));
    const putsBefore = r2.puts;
    const again = await archive.seal(recs.slice(0, 2)); // retry an old batch
    expect(again).toBe(3);
    expect(r2.puts).toBe(putsBefore); // nothing written: fully covered already
    const all = await archive.allArchived();
    expect(all.map((r) => r.seq)).toEqual([0, 1, 2, 3]);
    expect((await verifyChain(all)).ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// FINDING 3: incremental continuity verification over a multi-segment chain.
describe("Finding 3: verifyAuditContinuity verifies multi-segment chains incrementally", () => {
  it("returns ok across a chain spanning MANY R2 segments + the DO ring", async () => {
    const SP = "fs-verify-multiseg";
    const a = api(SP);
    // Generate a decent chain via gateway presign mints.
    const N = 12;
    for (let i = 0; i < N; i++) {
      await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/v/${i}`, method: "PUT" });
    }
    const stub = fsStub(SP);
    // Seal in several small batches → MANY per-flush segments, ring keeps the rest.
    await stub.archiveAuditRing(Date.now(), { maxEvents: 9, windowMs: 1e12 });
    await a.send("POST", "/presign", { key: `blocks/${ORG}::${SP}/v/x`, method: "PUT" });
    await stub.archiveAuditRing(Date.now(), { maxEvents: 6, windowMs: 1e12 });
    await stub.archiveAuditRing(Date.now(), { maxEvents: 3, windowMs: 1e12 });

    const cont = await stub.verifyAuditContinuity();
    expect(cont.ok).toBe(true);
    expect(cont.checked).toBeGreaterThanOrEqual(N);

    // Cross-check: the reader-assembled full history also verifies.
    const all = (await (await a.get("/audit?limit=10000")).json()) as AuditRecord[];
    const ascending = [...all].sort((x, y) => x.seq - y.seq);
    expect((await verifyChain(ascending)).ok).toBe(true);
    expect(cont.checked).toBe(ascending.length);
  });

  it("detects a deliberately broken inter-segment link and pinpoints where", async () => {
    // Unit-level: build a real chain, seal it as multiple per-flush segments, then
    // CORRUPT one segment's body in R2 and confirm the incremental verifier flags
    // exactly that record. Uses verifyContinuity directly (the engine the DO calls).
    const r2 = new FakeR2();
    const archive = new R2AuditArchive(r2, "acme::space-1");
    const log = new AuditLog(new InMemoryAuditStore());
    const recs: AuditRecord[] = [];
    const DAY = Date.UTC(2026, 5, 2, 0, 0, 0);
    for (let i = 0; i < 9; i++) recs.push(await log.write(evt({ action: `b${i}` }), DAY + i));
    await archive.seal(recs.slice(0, 3)); // seg seq 0..2
    await archive.seal(recs.slice(3, 6)); // seg seq 3..5
    await archive.seal(recs.slice(6, 9)); // seg seq 6..8

    // Sanity: intact chain (no ring) verifies.
    const ok = await archive.verifyContinuity([]);
    expect(ok.ok).toBe(true);
    expect(ok.checked).toBe(9);

    // Tamper with the MIDDLE segment's body (flip a field on seq 4) — the chain
    // hash for seq 4 no longer matches. The verifier must stream to it and break.
    const index = await archive.loadIndex();
    const midSeg = index.segments.find((s) => s.firstSeq === 3)!;
    const body = r2.store.get(midSeg.key)!;
    const lines = body.split("\n").filter((l) => l.trim().length > 0);
    const tampered = lines.map((l) => {
      const r = JSON.parse(l) as AuditRecord;
      if (r.seq === 4) r.action = "TAMPERED";
      return JSON.stringify(r);
    });
    r2.store.set(midSeg.key, tampered.join("\n"));

    const broken = await archive.verifyContinuity([]);
    expect(broken.ok).toBe(false);
    expect(broken.brokenAtSeq).toBe(4);
    expect(broken.reason).toContain("hash mismatch");
    // It stopped EARLY (only seqs 0..3 checked) — proof it didn't need the whole
    // chain resident to find the break.
    expect(broken.checked).toBe(4);
  });

  it("detects a broken seam between the archive tail and the DO ring", async () => {
    const r2 = new FakeR2();
    const archive = new R2AuditArchive(r2, "acme::space-1");
    const log = new AuditLog(new InMemoryAuditStore());
    const recs: AuditRecord[] = [];
    const DAY = Date.UTC(2026, 5, 3, 0, 0, 0);
    for (let i = 0; i < 6; i++) recs.push(await log.write(evt({ action: `c${i}` }), DAY + i));
    await archive.seal(recs.slice(0, 4)); // archive seq 0..3

    // The "ring" continues correctly with seq 4..5 → ok.
    expect((await archive.verifyContinuity(recs.slice(4))).ok).toBe(true);

    // A ring whose first record's prevHash doesn't match the archive tail → break
    // at the seam (seq 4).
    const forged: AuditRecord = { ...recs[4], prevHash: "f".repeat(64) };
    const bad = await archive.verifyContinuity([forged, recs[5]]);
    expect(bad.ok).toBe(false);
    expect(bad.brokenAtSeq).toBe(4);
    expect(bad.checked).toBe(4); // archive verified; broke at the first ring record
  });
});
