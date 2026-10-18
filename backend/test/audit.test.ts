// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
  AuditLog,
  InMemoryAuditStore,
  verifyChain,
  hashRecord,
  toNdjson,
  GENESIS_HASH,
  type AuditEvent,
} from "../src/security/audit";

function presignEvent(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    actorSub: "member-123",
    actorType: "session",
    orgId: "acme",
    spaceId: "active-edit",
    sessionId: "jti-1",
    sourceIp: "203.0.113.7",
    action: "presign.mint",
    decision: "allow",
    targetInodeId: "projectA/A001.mov",
    levelChecked: "read",
    mintedObjectKeys: ["chunks/ab/abcdef0123"],
    verb: "GET",
    urlTtlSeconds: 300,
    ...over,
  };
}

describe("append-only write + chaining", () => {
  it("seals records with monotonic seq and chains prevHash", async () => {
    const store = new InMemoryAuditStore();
    const log = new AuditLog(store);

    const r0 = await log.write(presignEvent(), 1000);
    const r1 = await log.write(presignEvent({ action: "item.create", decision: "allow" }), 2000);

    expect(r0.seq).toBe(0);
    expect(r0.prevHash).toBe(GENESIS_HASH);
    expect(r0.ts).toBe(1000);
    expect(r1.seq).toBe(1);
    expect(r1.prevHash).toBe(r0.hash); // chained
    expect(r1.hash).not.toBe(r0.hash);
  });

  it("hash is deterministic and independent of key ordering", async () => {
    const base = { ...presignEvent(), seq: 0, ts: 1000, prevHash: GENESIS_HASH };
    const reordered = {
      prevHash: GENESIS_HASH,
      ts: 1000,
      seq: 0,
      decision: "allow" as const,
      action: "presign.mint",
      orgId: "acme",
      actorType: "session" as const,
      actorSub: "member-123",
      spaceId: "active-edit",
      sessionId: "jti-1",
      sourceIp: "203.0.113.7",
      targetInodeId: "projectA/A001.mov",
      levelChecked: "read",
      mintedObjectKeys: ["chunks/ab/abcdef0123"],
      verb: "GET" as const,
      urlTtlSeconds: 300,
    };
    expect(await hashRecord(base)).toBe(await hashRecord(reordered));
  });
});

describe("tamper-evidence (verifyChain)", () => {
  it("validates an intact chain", async () => {
    const store = new InMemoryAuditStore();
    const log = new AuditLog(store);
    await log.write(presignEvent(), 1000);
    await log.write(presignEvent({ action: "lock.acquire" }), 2000);
    await log.write(presignEvent({ action: "acl.grant", levelChecked: "admin" }), 3000);

    const res = await verifyChain(store.all());
    expect(res.ok).toBe(true);
    expect(res.checked).toBe(3);
  });

  it("detects an edited record (e.g. flipping a deny to allow)", async () => {
    const store = new InMemoryAuditStore();
    const log = new AuditLog(store);
    await log.write(presignEvent(), 1000);
    await log.write(presignEvent({ action: "presign.mint", decision: "deny" }), 2000);

    const records = store.all();
    // attacker rewrites the denied access into an allow, leaving the hash untouched
    records[1] = { ...records[1], decision: "allow" };

    const res = await verifyChain(records);
    expect(res.ok).toBe(false);
    expect(res.brokenAtSeq).toBe(1);
    expect(res.reason).toMatch(/hash mismatch/);
  });

  it("detects a deleted record (chain gap)", async () => {
    const store = new InMemoryAuditStore();
    const log = new AuditLog(store);
    await log.write(presignEvent(), 1000);
    await log.write(presignEvent({ action: "a" }), 2000);
    await log.write(presignEvent({ action: "b" }), 3000);

    const records = store.all();
    records.splice(1, 1); // delete the middle record

    const res = await verifyChain(records);
    expect(res.ok).toBe(false);
    // after removing seq 1, the record now at index 1 has seq 2 -> seq gap
    expect(res.brokenAtSeq).toBe(2);
  });

  it("detects reordering", async () => {
    const store = new InMemoryAuditStore();
    const log = new AuditLog(store);
    await log.write(presignEvent({ action: "first" }), 1000);
    await log.write(presignEvent({ action: "second" }), 2000);

    const records = store.all();
    const swapped = [records[1], records[0]];

    const res = await verifyChain(swapped);
    expect(res.ok).toBe(false);
    expect(res.brokenAtSeq).toBe(1); // first record now has seq 1, expected 0
  });
});

describe("query API", () => {
  it("filters by actor, action, decision, time, and space", async () => {
    const store = new InMemoryAuditStore();
    const log = new AuditLog(store);
    await log.write(presignEvent({ actorSub: "alice", action: "presign.mint", decision: "allow" }), 1000);
    await log.write(presignEvent({ actorSub: "bob", action: "presign.mint", decision: "deny" }), 2000);
    await log.write(presignEvent({ actorSub: "alice", action: "item.create", spaceId: "archive" }), 3000);

    const log2 = new AuditLog(store);
    expect((await log2.query({ actorSub: "alice" })).length).toBe(2);
    expect((await log2.query({ decision: "deny" })).length).toBe(1);
    expect((await log2.query({ action: "presign.mint" })).length).toBe(2);
    expect((await log2.query({ spaceId: "archive" })).length).toBe(1);
    expect((await log2.query({ since: 1500, until: 2500 })).length).toBe(1);
    expect((await log2.query({ limit: 1 })).length).toBe(1);
  });
});

describe("NDJSON output (SIEM shipping)", () => {
  it("emits one JSON object per line", async () => {
    const store = new InMemoryAuditStore();
    const log = new AuditLog(store);
    await log.write(presignEvent(), 1000);
    await log.write(presignEvent({ action: "x" }), 2000);
    const lines = toNdjson(store.all()).split("\n");
    expect(lines).toHaveLength(2);
    expect(() => lines.map((l) => JSON.parse(l))).not.toThrow();
  });
});
