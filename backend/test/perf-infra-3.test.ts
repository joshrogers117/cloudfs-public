// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { filespaceDoName } from "../src/security/auth";
import { NamespaceStore } from "../src/metadata/namespace";
import type { Block } from "../src/metadata/types";

// Regression suite for two PERFORMANCE findings:
//   P1 — `blocks(object_key)` had no index, so `itemForObjectKey` (run on EVERY
//        presign GET mint) full-scanned the largest table on the single-threaded
//        DO. schema.ts v10 adds `blocks_object_key`.
//   P3 — AuthDO `sessions` was never pruned: the revoked/expired set grew without
//        bound and was serialized across the RPC boundary on every authed request.
//        auth-do.ts now arms a prune alarm that DELETEs truly-dead rows while
//        keeping every jti a live JWS could still present.

// ===========================================================================
// P1 — blocks(object_key) index
// ===========================================================================

const ORG_P1 = "org-perf-p1";

/// A migrated FilespaceDO SqlStorage + a NamespaceStore on it (mirrors the
/// metadata-datamodel harness). Each test gets its own space (own DO instance).
async function withNamespace<T>(
  space: string,
  fn: (s: { sql: SqlStorage; ns: NamespaceStore }) => T | Promise<T>,
): Promise<T> {
  const stub = (env as any).FILESPACE.get(
    (env as any).FILESPACE.idFromName(filespaceDoName(ORG_P1, space)),
  );
  return runInDurableObject(stub, async (_inst: unknown, state: DurableObjectState) => {
    const sql = state.storage.sql;
    const ns = new NamespaceStore(sql);
    return fn({ sql, ns });
  });
}

const block = (objectKey: string, hash: string, length = 100, idx = 0): Block => ({
  chunkIdx: 0,
  blockIdx: idx,
  blockHash: hash,
  objectKey,
  offset: idx * length,
  length,
});

describe("P1 — blocks(object_key) index", () => {
  it("creates the blocks_object_key index after migration", async () => {
    await withNamespace("idx-exists", ({ sql }) => {
      const idx = sql
        .exec(`PRAGMA index_list(blocks);`)
        .toArray()
        .map((r) => String(r.name));
      expect(idx).toContain("blocks_object_key");

      // And it is actually keyed on object_key (the column the hot lookup filters on).
      const cols = sql
        .exec(`PRAGMA index_info(blocks_object_key);`)
        .toArray()
        .map((r) => String(r.name));
      expect(cols).toEqual(["object_key"]);
    });
  });

  it("records the v10 migration exactly once and is idempotent", async () => {
    await withNamespace("idx-migration-row", ({ sql }) => {
      const rows = sql
        .exec(`SELECT id FROM _schema_migrations WHERE id = 10;`)
        .toArray();
      expect(rows.length).toBe(1);
    });
  });

  it("itemForObjectKey still returns the correct owning item (now index-served)", async () => {
    await withNamespace("idx-lookup", ({ ns }) => {
      // Build two files, each with its own block / object_key.
      ns.put(null, "root", true, 0, { id: "r" });
      ns.setBlockMap("fileA", [block("ok-A", "hash-A")], { upsert: { parent: "r", name: "fileA" } });
      ns.setBlockMap("fileB", [block("ok-B", "hash-B")], { upsert: { parent: "r", name: "fileB" } });

      expect(ns.itemForObjectKey("ok-A")).toBe("fileA");
      expect(ns.itemForObjectKey("ok-B")).toBe("fileB");
      expect(ns.itemForObjectKey("ok-missing")).toBeNull();
    });
  });

  it("the lookup uses the index (query plan references blocks_object_key)", async () => {
    await withNamespace("idx-plan", ({ sql, ns }) => {
      ns.put(null, "root", true, 0, { id: "r" });
      ns.setBlockMap("f", [block("ok-plan", "hash-plan")], { upsert: { parent: "r", name: "f" } });

      const plan = sql
        .exec(`EXPLAIN QUERY PLAN SELECT item_id FROM blocks WHERE object_key = ? LIMIT 1;`, "ok-plan")
        .toArray()
        .map((r) => String(r.detail))
        .join(" | ");
      // The planner should use the index, not SCAN the table.
      expect(plan).toContain("blocks_object_key");
      expect(plan).not.toMatch(/SCAN (TABLE )?blocks\b/);
    });
  });
});

// ===========================================================================
// P3 — AuthDO session prune alarm
// ===========================================================================

const ORG_P3 = "org-perf-p3";
const HOUR = 60 * 60 * 1000;

/// Drive a real AuthDO. We seed rows via the public createSession RPC, then patch
/// expires_at / revoked_at directly on the DO's SqlStorage (the same store the DO
/// uses) so we can place rows precisely relative to the prune cutoff.
async function withAuthDO(
  space: string,
  fn: (a: { stub: any; sql: SqlStorage; instance: any; state: DurableObjectState }) => Promise<void>,
): Promise<void> {
  const stub = (env as any).AUTH_DO.get((env as any).AUTH_DO.idFromName(`${ORG_P3}-${space}`));
  await (runInDurableObject as any)(stub, async (instance: any, state: DurableObjectState) => {
    await fn({ stub, sql: state.storage.sql, instance, state });
  });
}

async function seedSession(
  sql: SqlStorage,
  instance: any,
  opts: { id?: string; expiresAt: number; revokedAt?: number | null },
): Promise<string> {
  const sess = await instance.createSession({
    accountId: "acc-1",
    userId: "user-1",
    orgId: ORG_P3,
    scopes: ["fs:read"],
    csrfToken: "csrf",
    expiresAt: opts.expiresAt,
  });
  // Patch expires_at / revoked_at into the exact state we want to test the cutoff against.
  sql.exec(
    `UPDATE sessions SET expires_at = ?, revoked_at = ? WHERE id = ?;`,
    opts.expiresAt,
    opts.revokedAt ?? null,
    sess.id,
  );
  return sess.id;
}

function sessionExists(sql: SqlStorage, id: string): boolean {
  return sql.exec(`SELECT id FROM sessions WHERE id = ?;`, id).toArray().length > 0;
}

describe("P3 — AuthDO session prune alarm", () => {
  it("alarm deletes only truly-dead rows; keeps revoked-unexpired and live rows", async () => {
    await withAuthDO("prune", async ({ sql, instance }) => {
      const t = Date.now();

      // (a) expired long ago — well past TTL+grace → MUST be deleted.
      const expiredOld = await seedSession(sql, instance, { expiresAt: t - 2 * HOUR });
      // (b) expired recently, still within the grace window → MUST remain (a residual
      //     ≤15-min JWS could still name it).
      const expiredRecent = await seedSession(sql, instance, { expiresAt: t - 5 * 60 * 1000 });
      // (c) revoked but NOT yet expired → MUST remain (the revocation gate needs it).
      const revokedActive = await seedSession(sql, instance, {
        expiresAt: t + HOUR,
        revokedAt: t - 60 * 1000,
      });
      // (d) live, far-future expiry → MUST remain.
      const live = await seedSession(sql, instance, { expiresAt: t + 24 * HOUR });

      // Run the prune via the alarm entrypoint (drives the same code path production uses).
      await instance.alarm();

      expect(sessionExists(sql, expiredOld)).toBe(false); // pruned
      expect(sessionExists(sql, expiredRecent)).toBe(true); // within grace
      expect(sessionExists(sql, revokedActive)).toBe(true); // revoked-but-unexpired
      expect(sessionExists(sql, live)).toBe(true); // live

      // revokedSessionJtis still flags the revoked-active session (security unchanged),
      // and no longer carries the pruned ancient id.
      const jtis = await instance.revokedSessionJtis();
      expect(jtis).toContain(revokedActive);
      expect(jtis).not.toContain(expiredOld);
      // The recently-expired (within-grace) row is still expired, so it is still returned
      // by the revocation gate until it is finally pruned.
      expect(jtis).toContain(expiredRecent);
    });
  });

  it("arms an alarm once a session exists; none when the table is empty", async () => {
    await withAuthDO("arm", async ({ sql, instance, state }) => {
      // Fresh DO with no sessions → constructor's armPruneAlarm() must NOT schedule anything.
      expect(await state.storage.getAlarm()).toBeNull();

      await seedSession(sql, instance, { expiresAt: Date.now() + HOUR });
      // createSession arms the prune alarm.
      const armed = await state.storage.getAlarm();
      expect(armed).not.toBeNull();
      expect(armed!).toBeGreaterThan(Date.now());
    });
  });

  it("re-arms after an alarm tick while sessions remain", async () => {
    await withAuthDO("rearm", async ({ sql, instance, state }) => {
      await seedSession(sql, instance, { expiresAt: Date.now() + 24 * HOUR }); // survives prune
      await instance.alarm();
      const next = await state.storage.getAlarm();
      expect(next).not.toBeNull();
      expect(next!).toBeGreaterThan(Date.now());
    });
  });

  it("stops scheduling once the table drains to empty", async () => {
    await withAuthDO("drain", async ({ sql, instance, state }) => {
      // Only a long-dead session → it gets pruned, leaving the table empty.
      await seedSession(sql, instance, { expiresAt: Date.now() - 2 * HOUR });
      await instance.alarm();
      expect(sql.exec(`SELECT COUNT(*) AS n FROM sessions;`).one().n).toBe(0);
      // Empty table → re-arm no-ops → no future alarm scheduled.
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });
});
