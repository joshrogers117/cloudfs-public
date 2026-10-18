// SPDX-License-Identifier: AGPL-3.0-or-later
// org-schema.test.ts — audit B20: OrgDO migration table + email canonicalization.
import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";

function orgStub(orgId: string) {
  return (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
}

describe("B20: OrgDO has a versioned _schema_migrations table", () => {
  it("records migration versions (≥2) so a backfill can be expressed", async () => {
    const stub = orgStub(`org-schema-${crypto.randomUUID().slice(0, 8)}`);
    // Touch the DO so migrate() runs.
    await stub.countUsers();
    await runInDurableObject(stub, async (_inst: unknown, state: DurableObjectState) => {
      const rows = state.storage.sql.exec(`SELECT id FROM _schema_migrations ORDER BY id;`).toArray();
      const ids = rows.map((r) => Number((r as any).id));
      expect(ids).toContain(1);
      expect(ids).toContain(2); // the email-canonicalization migration
    });
  });
});

describe("B20: OrgDO canonicalizes emails to lowercase", () => {
  it("createUser stores a lowercased email; lookups by mixed case resolve", async () => {
    const orgId = `org-email-${crypto.randomUUID().slice(0, 8)}`;
    const stub = orgStub(orgId);
    const u = await stub.createUser({ orgId, email: "Mixed.Case@Studio.Example", displayName: "M", role: "standard" });
    expect(u.email).toBe("mixed.case@studio.example");
    // A lookup by the ORIGINAL (mixed) case finds the canonicalized row.
    const got = await stub.getUserByEmail("MIXED.CASE@studio.example");
    expect(got?.id).toBe(u.id);
  });

  it("a case-variant create collides with the existing (canonicalized) user", async () => {
    const orgId = `org-email2-${crypto.randomUUID().slice(0, 8)}`;
    const stub = orgStub(orgId);
    await stub.createUser({ orgId, email: "dup@studio.example", displayName: "A", role: "standard" });
    // Await RPC once: Vitest's rejects matcher can consume the RPC thenable twice.
    let failure: unknown;
    try { await stub.createUser({ orgId, email: "DUP@Studio.Example", displayName: "B", role: "standard" }); }
    catch (error) { failure = error; }
    expect(String(failure)).toMatch(/already exists/);
  });
});
