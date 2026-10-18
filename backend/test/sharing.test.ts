// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import {
  buildDeepLink,
  parseDeepLink,
  mintShareToken,
  parseShareToken,
  validateShareLink,
  createShareLink,
  resolveShareLink,
  revokeShareLink,
  InMemoryShareLinkStore,
  OrgDOShareLinkStore,
  type ShareLinkRecord,
} from "../src/sharing";

// Pure share-link logic runs in the workerd runtime (Web Crypto) with no DO. The
// DO-backed ShareLinkStore columns are documented in multiuser-INTEGRATION.md; here
// we use the in-memory store that mirrors them.

describe("internal cloudfs:// deep links (SPEC §3.7 R10 — opens in recipient's Finder)", () => {
  it("round-trips space + path", () => {
    const link = buildDeepLink({ spaceId: "active-edit", path: "/ShowA/Edit/timeline.prproj" });
    expect(link.startsWith("cloudfs://active-edit/")).toBe(true);
    const back = parseDeepLink(link);
    expect(back).toEqual({ spaceId: "active-edit", path: "/ShowA/Edit/timeline.prproj", select: true });
  });

  it("encodes spaces and special chars in path segments", () => {
    const link = buildDeepLink({ spaceId: "sp", path: "/Project A/A001 take 2.mov" });
    expect(link).toContain("Project%20A");
    const back = parseDeepLink(link);
    expect(back!.path).toBe("/Project A/A001 take 2.mov");
  });

  it("honors the select=0 hint (reveal folder, don't select)", () => {
    const link = buildDeepLink({ spaceId: "sp", path: "/ShowA", select: false });
    expect(parseDeepLink(link)!.select).toBe(false);
  });

  it("rejects non-cloudfs and malformed links", () => {
    expect(parseDeepLink("https://example.com/x")).toBeNull();
    expect(parseDeepLink("not a url")).toBeNull();
  });

  it("a deep link carries NO credential (it is navigation-only)", () => {
    // structural property: the link is just space+path; no token, secret, or signature
    const link = buildDeepLink({ spaceId: "sp", path: "/a/b" });
    expect(link).not.toMatch(/token|secret|signature|sig=/i);
  });
});

describe("external share token mint + validate (SPEC §4.3/§4.10 GuestLink)", () => {
  it("mints a token whose parse reproduces the stored hash", async () => {
    const { rawToken, shareId, tokenHash } = await mintShareToken();
    expect(rawToken.startsWith("shr-")).toBe(true);
    const parsed = await parseShareToken(rawToken);
    expect(parsed!.shareId).toBe(shareId);
    expect(parsed!.tokenHash).toBe(tokenHash);
  });

  it("rejects malformed share tokens", async () => {
    expect(await parseShareToken("inv-123.secret")).toBeNull(); // wrong prefix
    expect(await parseShareToken("nope")).toBeNull();
  });

  function rec(over: Partial<ShareLinkRecord> = {}): ShareLinkRecord {
    const t = Date.now();
    return {
      id: "shr-1",
      orgId: "acme",
      spaceId: "active-edit",
      inodeId: "deliverables",
      audience: "public",
      level: "read",
      tokenHash: "h",
      email: "client@studio.com",
      createdByMemberId: "usr-dana",
      createdAt: t,
      expiresAt: t + 1000,
      revoked: false,
      ...over,
    };
  }

  it("validates live, rejects expired/revoked/mismatch/missing", () => {
    const t = Date.now();
    expect(validateShareLink(rec({ tokenHash: "h", expiresAt: t + 1000 }), "h", t)).toEqual({ ok: true });
    expect(validateShareLink(rec({ tokenHash: "h", expiresAt: t - 1 }), "h", t)).toEqual({ ok: false, error: "expired" });
    expect(validateShareLink(rec({ tokenHash: "h", revoked: true }), "h", t)).toEqual({ ok: false, error: "revoked" });
    expect(validateShareLink(rec({ tokenHash: "h" }), "wrong", t)).toEqual({ ok: false, error: "token_mismatch" });
    expect(validateShareLink(null, "h", t)).toEqual({ ok: false, error: "not_found" });
  });
});

describe("share-link lifecycle over the store (create -> resolve -> revoke)", () => {
  it("creates a public link forced to read-only, resolves it to a presign grant", async () => {
    const store = new InMemoryShareLinkStore();
    const { share, rawToken, shareUrl } = await createShareLink(store, "acme", "usr-dana", {
      spaceId: "active-edit",
      inodeId: "deliverables",
      audience: "public",
      level: "admin", // requested high, but public is forced to read (preview/download only)
      email: "client@studio.com",
    });
    expect(share.level).toBe("read");
    expect(shareUrl).toContain(encodeURIComponent(rawToken));

    const resolved = await resolveShareLink(store, rawToken);
    expect(resolved.ok).toBe(true);
    expect(resolved.grant).toEqual({
      spaceId: "active-edit",
      inodeId: "deliverables",
      level: "read",
      audience: "public",
    });
  });

  it("an internal share can carry a higher level", async () => {
    const store = new InMemoryShareLinkStore();
    const { rawToken } = await createShareLink(store, "acme", "usr-dana", {
      spaceId: "sp",
      inodeId: "edit",
      audience: "internal",
      level: "edit",
    });
    const resolved = await resolveShareLink(store, rawToken);
    expect(resolved.grant!.level).toBe("edit");
    expect(resolved.grant!.audience).toBe("internal");
  });

  it("revoking a link makes it unresolvable", async () => {
    const store = new InMemoryShareLinkStore();
    const { share, rawToken } = await createShareLink(store, "acme", "usr-dana", {
      spaceId: "sp",
      inodeId: "deliverables",
    });
    expect((await resolveShareLink(store, rawToken)).ok).toBe(true);
    expect(await revokeShareLink(store, share.id)).toBe(true);
    const after = await resolveShareLink(store, rawToken);
    expect(after.ok).toBe(false);
    expect(after.error).toBe("revoked");
    // double-revoke is a no-op
    expect(await revokeShareLink(store, share.id)).toBe(false);
  });

  it("resolving an unknown token fails not_found", async () => {
    const store = new InMemoryShareLinkStore();
    const fake = await mintShareToken();
    expect((await resolveShareLink(store, fake.rawToken)).error).toBe("not_found");
  });

  it("listActive excludes revoked and expired links", async () => {
    const store = new InMemoryShareLinkStore();
    const a = await createShareLink(store, "acme", "usr-dana", { spaceId: "sp", inodeId: "x" });
    await createShareLink(store, "acme", "usr-dana", { spaceId: "sp", inodeId: "y", ttlMs: -1 }); // already expired
    await revokeShareLink(store, a.share.id);
    const active = await store.listActive("sp");
    expect(active.length).toBe(0);
  });
});

// DO-backed durability: share links persist in OrgDO's share_links table and survive
// across distinct store instances (i.e. real storage, not in-process memory). Uses the
// real ORG_DO binding (cloudflare:test env).
describe("durable share links over OrgDO (create -> resolve -> list -> revoke)", () => {
  it("persists a share link and resolves it through a FRESH store instance", async () => {
    const orgId = `org-share-${crypto.randomUUID().slice(0, 8)}`;
    const writeStore = new OrgDOShareLinkStore(env as any, orgId);
    const { share, rawToken } = await createShareLink(writeStore, orgId, "usr-dana", {
      spaceId: "active-edit",
      inodeId: "deliverables",
      audience: "public",
      email: "client@studio.com",
    });
    expect(share.level).toBe("read"); // public forced read-only

    // a brand-new store instance (new stub) must see the persisted row
    const readStore = new OrgDOShareLinkStore(env as any, orgId);
    const resolved = await resolveShareLink(readStore, rawToken);
    expect(resolved.ok).toBe(true);
    expect(resolved.grant).toMatchObject({
      spaceId: "active-edit",
      inodeId: "deliverables",
      level: "read",
      audience: "public",
    });

    const active = await readStore.listActive("active-edit");
    expect(active.map((s) => s.id)).toContain(share.id);

    // revoke is durable too
    expect(await revokeShareLink(readStore, share.id)).toBe(true);
    const after = await new OrgDOShareLinkStore(env as any, orgId).getById(share.id);
    expect(after!.revoked).toBe(true);
    expect((await resolveShareLink(new OrgDOShareLinkStore(env as any, orgId), rawToken)).error).toBe("revoked");
  });

  it("expired durable links are excluded from listActive and resolve", async () => {
    const orgId = `org-share-exp-${crypto.randomUUID().slice(0, 8)}`;
    const store = new OrgDOShareLinkStore(env as any, orgId);
    const { rawToken } = await createShareLink(store, orgId, "usr-dana", {
      spaceId: "sp",
      inodeId: "x",
      ttlMs: -1, // already expired
    });
    expect((await store.listActive("sp")).length).toBe(0);
    expect((await resolveShareLink(store, rawToken)).error).toBe("expired");
  });
});
