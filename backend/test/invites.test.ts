// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import {
  mintInviteToken,
  parseInviteToken,
  validateInvite,
  createInvite,
  redeemInvite,
  sha256Hex,
  DEFAULT_INVITE_TTL_MS,
  type InviteRecord,
} from "../src/invites";
import { InMemoryPermissionStore, canAccess, type Principal, type Grant } from "../src/permissions";

// These tests exercise the PURE invite-token logic (mint / parse / validate),
// which runs in the workerd runtime (Web Crypto available) without needing the
// OrgDO binding. The DO-backed create/redeem flow is wired + documented in
// multiuser-INTEGRATION.md; its persistence is just SQLite around these primitives.

function makeRecord(over: Partial<InviteRecord> = {}): InviteRecord {
  const t = Date.now();
  return {
    id: "inv-1",
    orgId: "acme",
    email: "new@acmepost.com",
    role: "standard",
    tokenHash: "hash",
    spaceId: null,
    inodeId: null,
    level: null,
    status: "pending",
    createdByMemberId: "usr-dana",
    createdAt: t,
    expiresAt: t + DEFAULT_INVITE_TTL_MS,
    acceptedByUserId: null,
    acceptedAt: null,
    ...over,
  };
}

describe("invite token mint + parse (single-use credential)", () => {
  it("mints a token whose parse reproduces the stored hash", async () => {
    const { rawToken, inviteId, tokenHash } = await mintInviteToken();
    expect(rawToken.startsWith("inv-")).toBe(true);
    expect(rawToken).toContain(".");
    const parsed = await parseInviteToken(rawToken);
    expect(parsed).not.toBeNull();
    expect(parsed!.inviteId).toBe(inviteId);
    // the hash recomputed from the raw token equals what we'd persist
    expect(parsed!.tokenHash).toBe(tokenHash);
  });

  it("stores only a hash, never the secret (irreversible)", async () => {
    const { rawToken, tokenHash } = await mintInviteToken();
    expect(tokenHash).not.toContain(rawToken.split(".")[1]); // hash != secret
    expect(tokenHash).toMatch(/^[0-9a-f]{64}$/); // sha-256 hex
  });

  it("rejects malformed tokens", async () => {
    expect(await parseInviteToken("garbage")).toBeNull();
    expect(await parseInviteToken("nopfx.secret")).toBeNull();
    expect(await parseInviteToken("")).toBeNull();
  });

  it("two mints produce different tokens", async () => {
    const a = await mintInviteToken();
    const b = await mintInviteToken();
    expect(a.tokenHash).not.toBe(b.tokenHash);
    expect(a.inviteId).not.toBe(b.inviteId);
  });
});

describe("validateInvite — expiry / single-use / revoke (SPEC §4.3/§4.5)", () => {
  const HASH = "deadbeef";

  it("accepts a live, pending, matching invite", () => {
    const rec = makeRecord({ tokenHash: HASH });
    expect(validateInvite(rec, HASH, Date.now())).toEqual({ ok: true });
  });

  it("rejects a missing record", () => {
    expect(validateInvite(null, HASH, Date.now())).toEqual({ ok: false, error: "not_found" });
  });

  it("rejects a token-hash mismatch (wrong/forged token)", () => {
    const rec = makeRecord({ tokenHash: HASH });
    expect(validateInvite(rec, "not-the-hash", Date.now())).toEqual({ ok: false, error: "token_mismatch" });
  });

  it("rejects an expired invite (past expires_at)", () => {
    const t = Date.now();
    const rec = makeRecord({ tokenHash: HASH, expiresAt: t - 1 });
    expect(validateInvite(rec, HASH, t)).toEqual({ ok: false, error: "expired" });
  });

  it("rejects an already-accepted invite (single-use)", () => {
    const rec = makeRecord({ tokenHash: HASH, status: "accepted", acceptedByUserId: "usr-x" });
    expect(validateInvite(rec, HASH, Date.now())).toEqual({ ok: false, error: "already_used" });
  });

  it("rejects a revoked invite", () => {
    const rec = makeRecord({ tokenHash: HASH, status: "revoked" });
    expect(validateInvite(rec, HASH, Date.now())).toEqual({ ok: false, error: "revoked" });
  });

  it("rejects a record already marked expired regardless of clock", () => {
    const rec = makeRecord({ tokenHash: HASH, status: "expired" });
    expect(validateInvite(rec, HASH, Date.now())).toEqual({ ok: false, error: "expired" });
  });
});

describe("scoped invite (filespace/folder + role) carried on the record", () => {
  it("preserves space/folder/level scope for the gateway to apply as a grant", () => {
    const rec = makeRecord({
      tokenHash: "h",
      role: "standard",
      spaceId: "active-edit",
      inodeId: "color",
      level: "edit",
    });
    // validation is scope-agnostic; the scope rides along to redeem
    expect(validateInvite(rec, "h", Date.now()).ok).toBe(true);
    expect(rec.spaceId).toBe("active-edit");
    expect(rec.inodeId).toBe("color");
    expect(rec.level).toBe("edit");
  });
});

describe("sha256Hex helper", () => {
  it("is deterministic and 64 hex chars", async () => {
    const a = await sha256Hex("abc");
    const b = await sha256Hex("abc");
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(await sha256Hex("abc")).not.toBe(await sha256Hex("abd"));
  });
});

// DO-backed end-to-end: redeeming a SCOPED invite must durably write the promised
// ACL grant (OrgDO.grants), so the redeemed user actually gets access at the invited
// level. Uses the real ORG_DO binding (cloudflare:test env). Proves redeem -> canAccess.
describe("invite redeem -> permission grant (durable, SPEC §4.10)", () => {
  function storeFromGrants(rows: Grant[], inodeId: string): InMemoryPermissionStore {
    // mirror the gateway: load the space tree + the OrgDO-written grants into the
    // pure evaluator's store (GrantRow is structurally a permissions.Grant).
    const s = new InMemoryPermissionStore();
    s.addInode({ id: "root", parentId: null, type: "folder" });
    s.addInode({ id: inodeId, parentId: "root", type: "folder" });
    for (const g of rows) s.putGrant(g);
    return s;
  }

  it("a redeemed scoped invite yields canAccess at the granted level", async () => {
    const orgId = `org-redeem-${crypto.randomUUID().slice(0, 8)}`;
    const { rawToken, invite } = await createInvite(env as any, orgId, "usr-dana", {
      email: "priya@acmepost.com",
      role: "standard",
      scope: { spaceId: "active-edit", inodeId: "color", level: "edit" },
    });
    expect(invite.level).toBe("edit");

    const result = await redeemInvite(env as any, orgId, rawToken, "Priya");
    expect(result.ok).toBe(true);
    expect(result.userId).toBeTruthy();
    expect(result.grantId).toBeTruthy(); // a scoped invite writes a grant

    // read the grant back from the DURABLE OrgDO store
    const stub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    const grants = (await stub.grantsForPrincipal("user", result.userId)) as Grant[];
    expect(grants.length).toBe(1);
    expect(grants[0]).toMatchObject({ spaceId: "active-edit", inodeId: "color", level: "edit" });

    // now the redeemed user can actually access /color at edit, but not admin
    const priya: Principal = { type: "user", id: result.userId!, groupIds: [] };
    const store = storeFromGrants(grants, "color");
    expect(canAccess(store, priya, "color", "read").effectiveLevel).toBe("edit");
    expect(canAccess(store, priya, "color", "write").allow).toBe(true);
    expect(canAccess(store, priya, "color", "manage_acl").allow).toBe(false); // edit < admin
  });

  it("an UNSCOPED invite writes no grant (grantId undefined)", async () => {
    const orgId = `org-noscope-${crypto.randomUUID().slice(0, 8)}`;
    const { rawToken } = await createInvite(env as any, orgId, "usr-dana", {
      email: "bob@acmepost.com",
      role: "standard",
    });
    const result = await redeemInvite(env as any, orgId, rawToken, "Bob");
    expect(result.ok).toBe(true);
    expect(result.grantId).toBeUndefined();
    const stub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    expect(((await stub.grantsForPrincipal("user", result.userId)) as Grant[]).length).toBe(0);
  });
});
