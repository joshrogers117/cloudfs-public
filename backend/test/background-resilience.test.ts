// SPDX-License-Identifier: AGPL-3.0-or-later
import { abortAllDurableObjects, env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { Env } from "../src/env";
import { DoAuditStore } from "../src/metadata/audit-store";
import { R2AuditArchive, type AuditR2 } from "../src/metadata/audit-archive";
import { NamespaceStore } from "../src/metadata/namespace";
import { SnapshotStore, isValidScheduleSpec } from "../src/metadata/snapshots";
import type { AuditEvent, AuditRecord } from "../src/security/audit";

const bindings = env as Env;
function fixture() {
  const space = `maintenance-${crypto.randomUUID()}`;
  return { space, key: `org1::${space}`, stub: bindings.FILESPACE.getByName(`org1::${space}`) };
}
function event(space: string, action = "item.create"): AuditEvent {
  return { orgId: "org1", spaceId: space, actorSub: "owner", actorType: "session", action, decision: "allow" };
}
class TestArchiveBucket implements AuditR2 {
  objects = new Map<string, string>();
  failIndexOnce = false;
  async get(key: string) {
    const value = this.objects.get(key);
    return value === undefined ? null : { text: async () => value };
  }
  async put(key: string, value: string) {
    if (key.endsWith("/index.json") && this.failIndexOnce) {
      this.failIndexOnce = false;
      throw new Error("injected archive manifest outage");
    }
    this.objects.set(key, value);
  }
}

describe("background audit durability", () => {
  it("continues the exact hash chain after fully trimming and restarting", async () => {
    const { space, key, stub } = fixture();
    for (let i = 0; i < 6; i++) await stub.appendAudit(event(space, `before-${i}`));
    expect((await stub.archiveAuditRing(Date.now(), { maxEvents: 0, windowMs: 1e12 })).deleted).toBe(6);
    await abortAllDurableObjects();
    const cold = bindings.FILESPACE.getByName(key);
    expect((await cold.appendAudit(event(space, "after-restart"))).seq).toBe(6);
    await cold.archiveAuditRing(Date.now(), { maxEvents: 0, windowMs: 1e12 });
    expect((await cold.queryAudit({}) as AuditRecord[]).map(record => record.seq)).toEqual([6, 5, 4, 3, 2, 1, 0]);
    expect(await cold.verifyAuditContinuity()).toEqual({ ok: true, checked: 7 });
  });

  it("recovers a legacy empty ring's missing tail checkpoint from verified R2 history", async () => {
    const { space, key, stub } = fixture();
    for (let i = 0; i < 3; i++) await stub.appendAudit(event(space));
    await stub.archiveAuditRing(Date.now(), { maxEvents: 0, windowMs: 1e12 });
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(`DELETE FROM meta_text WHERE key='audit_chain_tail';`);
    });
    await abortAllDurableObjects();
    const cold = bindings.FILESPACE.getByName(key);
    expect((await cold.appendAudit(event(space))).seq).toBe(3);
    expect(await cold.verifyAuditContinuity()).toEqual({ ok: true, checked: 4 });
  });

  it("keeps all resident rows on manifest failure and retries without orphaning history", async () => {
    const { space, key, stub } = fixture();
    for (let i = 0; i < 4; i++) await stub.appendAudit(event(space));
    await runInDurableObject(stub, async (instance, state) => {
      const bucket = new TestArchiveBucket(); bucket.failIndexOnce = true;
      Object.assign(instance, { auditArchive: new R2AuditArchive(bucket, key), filespaceKey: key });
      const store = new DoAuditStore(state.storage.sql);
      let failed = false;
      try { await instance.archiveAuditRing(Date.now(), { maxEvents: 0, windowMs: 1e12 }); }
      catch { failed = true; }
      expect(failed).toBe(true); expect(store.count()).toBe(4); expect(store.archivedThroughSeq()).toBe(-1);
      await instance.archiveAuditRing(Date.now(), { maxEvents: 0, windowMs: 1e12 });
      expect(store.count()).toBe(0); expect(store.archivedThroughSeq()).toBe(3);
      expect(await instance.verifyAuditContinuity()).toEqual({ ok: true, checked: 4 });
    });
  });

  it("serializes competing archive publication while ordinary audit appends still progress", async () => {
    const { space, key, stub } = fixture();
    for (let i = 0; i < 6; i++) await stub.appendAudit(event(space));
    await runInDurableObject(stub, async (instance, state) => {
      const bucket = new TestArchiveBucket();
      Object.assign(instance, { auditArchive: new R2AuditArchive(bucket, key), filespaceKey: key });
      const first = instance.archiveAuditRing(Date.now(), { maxEvents: 3, windowMs: 1e12 });
      const second = instance.archiveAuditRing(Date.now(), { maxEvents: 0, windowMs: 1e12 });
      await instance.appendAudit(event(space, "during-publication"));
      await Promise.all([first, second]);
      expect(new DoAuditStore(state.storage.sql).archivedThroughSeq()).toBeGreaterThanOrEqual(5);
      expect(await instance.verifyAuditContinuity()).toEqual({ ok: true, checked: 7 });
    });
  });

  it("bounds each archival pass and schedules backlog promptly instead of waiting another hour", async () => {
    const { space, stub } = fixture();
    for (let i = 0; i < 520; i++) await stub.appendAudit(event(space));
    const first = await stub.archiveAuditRing(Date.now(), { maxEvents: 0, windowMs: 1e12 });
    expect(first.deleted).toBe(512);
    await runInDurableObject(stub, (_instance, state) => {
      const next = Number(state.storage.sql.exec(`SELECT value FROM meta WHERE key='audit_next_at';`).one().value);
      expect(next).toBeLessThan(Date.now() + 2000);
    });
    expect((await stub.archiveAuditRing(Date.now(), { maxEvents: 0, windowMs: 1e12 })).deleted).toBe(8);
    expect(await stub.verifyAuditContinuity()).toEqual({ ok: true, checked: 520 });
  });
});

describe("background snapshot maintenance", () => {
  it("rejects invalid timer values and disables already-persisted corrupt timers", async () => {
    for (const intervalMs of [0, -1, Infinity, NaN, 1.5]) expect(isValidScheduleSpec({ id: "x", tier: "hourly", retain: 1, intervalMs })).toBe(false);
    const { stub } = fixture();
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql, ns = new NamespaceStore(sql), snapshots = new SnapshotStore(sql, () => ns.currentSeq(), ns);
      expect(() => snapshots.setSchedule({ id: "invalid", tier: "hourly", retain: 1, intervalMs: 0 })).toThrow("invalid snapshot schedule");
      sql.exec(`INSERT INTO snapshot_schedules(id,scope,tier,interval_ms,retain,enabled,next_run_at) VALUES ('legacy','root','hourly',0,1,1,0);`);
      expect(snapshots.runDue().created).toEqual([]);
      expect(Number(sql.exec(`SELECT enabled FROM snapshot_schedules WHERE id='legacy';`).one().enabled)).toBe(0);
    });
  });

  it("skips trillions of missed ticks in one calculation and bounds schedules per pass", async () => {
    const { stub } = fixture();
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql, ns = new NamespaceStore(sql), snapshots = new SnapshotStore(sql, () => ns.currentSeq(), ns);
      snapshots.setSchedule({ id: "old", tier: "hourly", retain: 1, intervalMs: 1 });
      sql.exec(`UPDATE snapshot_schedules SET next_run_at=1 WHERE id='old';`);
      const now = Date.now();
      expect(snapshots.runDue(now).created).toHaveLength(1);
      expect(Number(sql.exec(`SELECT next_run_at FROM snapshot_schedules WHERE id='old';`).one().next_run_at)).toBe(now + 1);
      snapshots.setScheduleEnabled("old", false);
      for (let i = 0; i < 10; i++) snapshots.setSchedule({ id: `batch-${i}`, tier: "daily", retain: 1, intervalMs: 3600000 });
      sql.exec(`UPDATE snapshot_schedules SET next_run_at=? WHERE enabled=1;`, now - 1);
      expect(snapshots.runDue(now).created).toHaveLength(8);
      expect(snapshots.runDue(now).created).toHaveLength(2);
    });
  });

  it("preserves useful recovery points while their scheduled folder is deleted", async () => {
    const { stub } = fixture();
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql, ns = new NamespaceStore(sql), snapshots = new SnapshotStore(sql, () => ns.currentSeq(), ns);
      const folder = ns.put("root", "Saved", true, 0);
      const item = ns.put(folder.id, "important.txt", false, 0);
      snapshots.setSchedule({ id: "folder", scope: folder.id, tier: "hourly", retain: 1, intervalMs: 1000 });
      const saved = snapshots.create({ id: "good", scope: folder.id, scheduleId: "folder" });
      ns.removeSubtree(folder.id);
      sql.exec(`UPDATE snapshot_schedules SET next_run_at=0 WHERE id='folder';`);
      expect(snapshots.runDue().created).toEqual([]);
      expect(snapshots.get(saved.id)?.id).toBe("good");
      expect(snapshots.itemAt(saved.id, item.id)?.name).toBe("important.txt");
    });
  });

  it("never re-freezes an existing manual snapshot whose ID matches a schedule slot", async () => {
    const { stub } = fixture();
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql, ns = new NamespaceStore(sql), snapshots = new SnapshotStore(sql, () => ns.currentSeq(), ns);
      const item = ns.put("root", "earlier.txt", false, 0);
      snapshots.create({ id: "hourly-0" });
      ns.rename(item.id, { name: "current.txt" });
      snapshots.setSchedule({ id: "hourly", tier: "hourly", retain: 2, intervalMs: 3600000 });
      sql.exec(`UPDATE snapshot_schedules SET next_run_at=0 WHERE id='hourly';`);
      const result = snapshots.runDue();
      expect(result.created[0].id).not.toBe("hourly-0");
      expect(snapshots.itemAt("hourly-0", item.id)?.name).toBe("earlier.txt");
      expect(snapshots.itemAt(result.created[0].id, item.id)?.name).toBe("current.txt");
    });
  });

  it("rolls back a partial snapshot failure and retains a future retry alarm", async () => {
    const { stub } = fixture();
    await stub.setSnapshotSchedule({ id: "retry", tier: "hourly", retain: 1, intervalMs: 3600000 });
    await runInDurableObject(stub, async (instance, state) => {
      const sql = state.storage.sql;
      sql.exec(`UPDATE snapshot_schedules SET next_run_at=0 WHERE id='retry';`);
      const snapshots = Object.getOwnPropertyDescriptor(instance, "snapshots")!.value as SnapshotStore;
      const original = snapshots.runDue.bind(snapshots);
      snapshots.runDue = () => { sql.exec(`INSERT INTO meta(key,value) VALUES ('partial_snapshot',1);`); throw new Error("injected snapshot failure"); };
      await state.storage.deleteAlarm();
      const before = Date.now();
      await instance.alarm();
      expect(sql.exec(`SELECT 1 FROM meta WHERE key='partial_snapshot';`).toArray()).toHaveLength(0);
      expect(await state.storage.getAlarm()).toBeGreaterThanOrEqual(before + 29000);
      snapshots.runDue = original;
      sql.exec(`UPDATE meta SET value=0 WHERE key='snapshot_retry_at';`);
      await state.storage.deleteAlarm();
      await instance.alarm();
      expect(snapshots.list().some(snapshot => snapshot.scheduleId === "retry")).toBe(true);
      expect(await state.storage.getAlarm()).toBeGreaterThan(Date.now());
    });
  });

  it("does not cancel a purge alarm when another maintenance caller finds no ordinary deadlines", async () => {
    const { stub } = fixture();
    await runInDurableObject(stub, async (instance, state) => {
      await instance.startPurge({ orgId: "org1", spaceId: "disposable-purge-probe" });
      const before = await state.storage.getAlarm();
      await instance.setSnapshotScheduleEnabled("absent", false);
      expect(await state.storage.getAlarm()).toBe(before);
    });
  });
});

describe("purge preserves audit evidence", () => {
  const emptyBucket: typeof fetch = async () => new Response('<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>');

  it("retries an unavailable archive without wiping recent history or metadata", async () => {
    const { space, key, stub } = fixture();
    for (let i = 0; i < 4; i++) await stub.appendAudit(event(space));
    await runInDurableObject(stub, async (instance, state) => {
      const bucket = new TestArchiveBucket(); bucket.failIndexOnce = true;
      const archive = new R2AuditArchive(bucket, key);
      Object.assign(instance, { auditArchive: archive, filespaceKey: key });
      await instance.startPurge({ orgId: "org1", spaceId: space });
      let failed = false;
      try { await instance.purgeStep(emptyBucket); } catch { failed = true; }
      expect(failed).toBe(true);
      expect(instance.purgeStatus().purging).toBe(true);
      expect(new DoAuditStore(state.storage.sql).count()).toBe(4);
      expect((await instance.purgeStep(emptyBucket)).done).toBe(true);
      expect(await archive.verifyContinuity([])).toEqual({ ok: true, checked: 4 });
    });
  });

  it("drains large audit rings in bounded resumable batches before the final wipe", async () => {
    const { space, key, stub } = fixture();
    for (let i = 0; i < 513; i++) await stub.appendAudit(event(space));
    await runInDurableObject(stub, async (instance, state) => {
      const archive = new R2AuditArchive(new TestArchiveBucket(), key);
      Object.assign(instance, { auditArchive: archive, filespaceKey: key });
      await instance.startPurge({ orgId: "org1", spaceId: space });
      expect(await instance.purgeStep(emptyBucket)).toEqual({ deletedThisStep: 0, done: false, remaining: true });
      expect(new DoAuditStore(state.storage.sql).count()).toBe(1);
      expect(await state.storage.getAlarm()).not.toBeNull();
      expect((await instance.purgeStep(emptyBucket)).done).toBe(true);
      expect(await archive.verifyContinuity([])).toEqual({ ok: true, checked: 513 });
      expect(await state.storage.getAlarm()).toBeNull();
      await instance.alarm(); // a previously delivered alarm after the wipe is harmless
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });

  it("retains its retry state if the final atomic metadata wipe fails", async () => {
    const { space, stub } = fixture();
    await runInDurableObject(stub, async (instance, state) => {
      await instance.startPurge({ orgId: "org1", spaceId: space });
      const original = state.storage.deleteAll.bind(state.storage);
      state.storage.deleteAll = async () => { throw new Error("injected metadata wipe failure"); };
      try {
        let failed = false;
        try { await instance.purgeStep(emptyBucket); } catch { failed = true; }
        expect(failed).toBe(true);
        expect(instance.purgeStatus().purging).toBe(true);
        expect(instance.purgeStatus().done).toBe(false);
        expect(await state.storage.getAlarm()).toBeGreaterThan(Date.now());
      } finally { state.storage.deleteAll = original; }
      expect((await instance.purgeStep(emptyBucket)).done).toBe(true);
    });
  });
});
