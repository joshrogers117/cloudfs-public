// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
  AuditLog,
  InMemoryAuditStore,
  verifyChain,
  GENESIS_HASH,
  type AuditEvent,
  type AuditRecord,
} from "../src/security/audit";
import { R2AuditArchive, utcDay, type AuditR2 } from "../src/metadata/audit-archive";

// A tiny in-memory R2 stand-in implementing just the surface R2AuditArchive uses.
class FakeR2 implements AuditR2 {
  store = new Map<string, string>();
  async get(key: string) {
    const v = this.store.get(key);
    return v === undefined ? null : { text: async () => v };
  }
  async put(key: string, value: string) {
    this.store.set(key, value);
    return undefined;
  }
}

function evt(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    actorSub: "alice", actorType: "session", orgId: "acme", spaceId: "space-7",
    action: "presign.mint", decision: "allow", ...over,
  };
}

/// Build a real chained log of N records spread across `days` UTC days.
async function buildChain(n: number, dayStarts: number[]): Promise<AuditRecord[]> {
  const log = new AuditLog(new InMemoryAuditStore());
  const recs: AuditRecord[] = [];
  for (let i = 0; i < n; i++) {
    const ts = dayStarts[i % dayStarts.length] + i; // keep ascending within a day bucket
    recs.push(await log.write(evt({ action: `a${i}` }), ts));
  }
  return recs;
}

const DAY1 = Date.UTC(2026, 5, 1, 12, 0, 0); // 2026-06-01
const DAY2 = Date.UTC(2026, 5, 2, 12, 0, 0); // 2026-06-02

describe("R2AuditArchive — segmenting + index.json", () => {
  it("seals records into per-flush immutable segments keyed by filespace+day+seq-range", async () => {
    const r2 = new FakeR2();
    const archive = new R2AuditArchive(r2, "acme::space-7");
    const recs = await buildChain(4, [DAY1, DAY1, DAY2, DAY2]); // 2 on day1, 2 on day2

    const through = await archive.seal(recs);
    expect(through).toBe(3); // last seq sealed

    // Finding 2: segments are keyed by day-prefix + the flush's seq range (not a
    // single per-day file), so a flush never re-reads/rewrites a prior segment.
    expect(r2.store.has("audit/acme::space-7/2026-06-01/0-1.ndjson")).toBe(true);
    expect(r2.store.has("audit/acme::space-7/2026-06-02/2-3.ndjson")).toBe(true);
    expect(r2.store.has("audit/acme::space-7/index.json")).toBe(true);

    const index = await archive.loadIndex();
    expect(index.filespaceId).toBe("acme::space-7");
    expect(index.segments.map((s) => s.date)).toEqual(["2026-06-01", "2026-06-02"]);
    expect(index.ringStartsAtSeq).toBe(4);
    // each segment carries first prevHash + last hash for chain continuity
    expect(index.segments[0].firstPrevHash).toBe(GENESIS_HASH);
    expect(index.segments[0].firstSeq).toBe(0);
    expect(index.segments[1].firstSeq).toBe(2);
  });

  it("keeps the manifest's chain continuous across segment boundaries", async () => {
    const r2 = new FakeR2();
    const archive = new R2AuditArchive(r2, "acme::space-7");
    const recs = await buildChain(6, [DAY1, DAY1, DAY1, DAY2, DAY2, DAY2]);
    await archive.seal(recs);

    const index = await archive.loadIndex();
    // invariant: segments[i].firstPrevHash === segments[i-1].lastHash
    for (let i = 1; i < index.segments.length; i++) {
      expect(index.segments[i].firstPrevHash).toBe(index.segments[i - 1].lastHash);
    }
    const cont = await archive.verifyManifestContinuity();
    expect(cont.ok).toBe(true);
  });

  it("verifyChain spans the concatenated R2 segments unbroken", async () => {
    const r2 = new FakeR2();
    const archive = new R2AuditArchive(r2, "acme::space-7");
    const recs = await buildChain(5, [DAY1, DAY1, DAY2, DAY2, DAY2]);
    await archive.seal(recs);

    const allArchived = await archive.allArchived();
    expect(allArchived.map((r) => r.seq)).toEqual([0, 1, 2, 3, 4]);
    const res = await verifyChain(allArchived);
    expect(res.ok).toBe(true);
    expect(res.checked).toBe(5);
  });

  it("writes a NEW immutable segment per same-day flush (no rewrite; idempotent on retry)", async () => {
    const r2 = new FakeR2();
    const archive = new R2AuditArchive(r2, "acme::space-7");
    const recs = await buildChain(4, [DAY1, DAY1, DAY1, DAY1]); // all day1

    await archive.seal(recs.slice(0, 2)); // flush 0,1 → segment 0-1
    const t = await archive.seal(recs.slice(2, 4)); // flush 2,3 → a SEPARATE same-day segment 2-3
    expect(t).toBe(3);

    // Finding 2: a busy day becomes MULTIPLE ascending-seq segments — the prior
    // segment is never re-read or rewritten (no O(day^2) read-modify-write).
    const index = await archive.loadIndex();
    expect(index.segments).toHaveLength(2);
    expect(index.segments[0].firstSeq).toBe(0);
    expect(index.segments[0].lastSeq).toBe(1);
    expect(index.segments[0].count).toBe(2);
    expect(index.segments[1].firstSeq).toBe(2);
    expect(index.segments[1].lastSeq).toBe(3);
    expect(index.segments[1].count).toBe(2);
    // both same-day segments coexist under the day prefix, keyed by seq range
    expect(r2.store.has("audit/acme::space-7/2026-06-01/0-1.ndjson")).toBe(true);
    expect(r2.store.has("audit/acme::space-7/2026-06-01/2-3.ndjson")).toBe(true);

    // re-flushing an already-sealed batch is a no-op: no new segment, no duplicate
    // lines — seal returns the existing high-water seq.
    const again = await archive.seal(recs.slice(0, 2));
    expect(again).toBe(3);
    const index2 = await archive.loadIndex();
    expect(index2.segments).toHaveLength(2);
    expect(index2.segments.reduce((n, s) => n + s.count, 0)).toBe(4);

    const all = await archive.allArchived();
    expect(all.map((r) => r.seq)).toEqual([0, 1, 2, 3]);
    expect((await verifyChain(all)).ok).toBe(true);
  });

  it("query() returns only archived records below ringStartSeq, field-filtered", async () => {
    const r2 = new FakeR2();
    const archive = new R2AuditArchive(r2, "acme::space-7");
    const log = new AuditLog(new InMemoryAuditStore());
    const recs: AuditRecord[] = [];
    recs.push(await log.write(evt({ actorSub: "alice", action: "x" }), DAY1));
    recs.push(await log.write(evt({ actorSub: "bob", action: "y" }), DAY1 + 1));
    recs.push(await log.write(evt({ actorSub: "alice", action: "z" }), DAY1 + 2));
    await archive.seal(recs);

    // ring takes over at seq 3 (everything archived) → all 3 visible from R2,
    // NEWEST-FIRST (seq DESC).
    const alice = await archive.query({ actorSub: "alice" }, 3);
    expect(alice.map((r) => r.seq)).toEqual([2, 0]);

    // a ringStart of 2 means seq 2 is owned by the ring → archive returns only
    // 1,0 (newest-first).
    const below2 = await archive.query({}, 2);
    expect(below2.map((r) => r.seq)).toEqual([1, 0]);
  });
});

describe("utcDay", () => {
  it("partitions by UTC calendar day", () => {
    expect(utcDay(Date.UTC(2026, 5, 1, 23, 59, 59))).toBe("2026-06-01");
    expect(utcDay(Date.UTC(2026, 5, 2, 0, 0, 0))).toBe("2026-06-02");
  });
});

describe("archive failure and concurrency boundaries", () => {
  it("publishes competing batches without losing the earlier index update", async () => {
    const r2 = new FakeR2(), archive = new R2AuditArchive(r2, "acme::space-7");
    const records = await buildChain(4, [DAY1]);
    await Promise.all([archive.seal(records.slice(0, 2)), archive.seal(records.slice(2))]);
    expect((await archive.allArchived()).map(record => record.seq)).toEqual([0, 1, 2, 3]);
    expect(await archive.verifyContinuity([])).toEqual({ ok: true, checked: 4 });
  });

  it("preserves sequence order when timestamps cross UTC days backwards", async () => {
    const archive = new R2AuditArchive(new FakeR2(), "acme::space-7");
    const records = await buildChain(4, [DAY1, DAY2, DAY1, DAY2]);
    await archive.seal(records);
    expect((await archive.loadIndex()).segments.map(segment => segment.firstSeq)).toEqual([0, 1, 2, 3]);
    expect(await archive.verifyContinuity([])).toEqual({ ok: true, checked: 4 });
  });

  it("fails closed for a missing final segment instead of verifying a shorter chain", async () => {
    const r2 = new FakeR2(), archive = new R2AuditArchive(r2, "acme::space-7");
    const records = await buildChain(4, [DAY1]);
    await archive.seal(records.slice(0, 2)); await archive.seal(records.slice(2));
    r2.store.delete((await archive.loadIndex()).segments.at(-1)!.key);
    expect((await archive.verifyContinuity([])).ok).toBe(false);
    await expect(archive.query({}, 4)).rejects.toThrow("segment missing");
    await expect(archive.lastRecord()).rejects.toThrow("segment missing");
  });

  it("refuses reused sequence numbers from a different chain", async () => {
    const archive = new R2AuditArchive(new FakeR2(), "acme::space-7");
    await archive.seal(await buildChain(2, [DAY1]));
    const other = await new AuditLog(new InMemoryAuditStore()).write(evt({ action: "new-event-reused-zero" }), DAY2);
    await expect(archive.seal([other])).rejects.toThrow("sequence was reused");
    expect(await archive.verifyContinuity([])).toEqual({ ok: true, checked: 2 });
  });

  it("verifies a captured ring against its captured archive boundary during publication", async () => {
    const archive = new R2AuditArchive(new FakeR2(), "acme::space-7");
    const records = await buildChain(4, [DAY1]);
    await archive.seal(records); // publication advanced after the reader captured its ring
    expect(await archive.verifyContinuity(records.slice(2), 1)).toEqual({ ok: true, checked: 4 });
  });
});
