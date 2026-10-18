// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
  mintToken,
  verifyToken,
  verifyRequest,
  bearerFromRequest,
  hasScope,
  requireScope,
  assertTenant,
  filespaceDoName,
  AuthError,
  DEFAULT_TTL_SECONDS,
  type Principal,
} from "../src/security/auth";

const SECRET = "test-signing-secret-at-least-16-chars-long";

function req(headers: Record<string, string>): Request {
  return new Request("https://gw.local/v1/filespaces/fs1/items", { headers });
}

describe("token mint + verify (round trip)", () => {
  it("mints a session token and verifies it back to a Principal", async () => {
    const t = await mintToken(SECRET, {
      sub: "member-123",
      type: "session",
      orgId: "acme",
      spaceId: "active-edit",
      scopes: ["fs:read", "fs:write"],
      ttlSeconds: 900,
    });
    expect(t.split(".")).toHaveLength(3); // compact JWS
    const p = await verifyToken(SECRET, t);
    expect(p.sub).toBe("member-123");
    expect(p.type).toBe("session");
    expect(p.orgId).toBe("acme");
    expect(p.spaceId).toBe("active-edit");
    expect(p.scopes).toEqual(["fs:read", "fs:write"]);
    expect(p.jti).toBeTruthy();
  });

  it("mints a scoped service-account token (CLI/render-farm)", async () => {
    const t = await mintToken(SECRET, {
      sub: "svc-renderfarm",
      type: "service",
      orgId: "acme",
      scopes: ["fs:read"],
      ttlSeconds: DEFAULT_TTL_SECONDS.service,
    });
    const p = await verifyToken(SECRET, t);
    expect(p.type).toBe("service");
    expect(p.spaceId).toBeUndefined(); // org-scoped, any space
    expect(hasScope(p, "fs:read")).toBe(true);
    expect(hasScope(p, "fs:write")).toBe(false);
  });
});

describe("signature + tampering", () => {
  it("rejects a token signed with a different secret", async () => {
    const t = await mintToken("another-secret-16+chars-aaaa", {
      sub: "m", type: "session", orgId: "acme", scopes: [], ttlSeconds: 60,
    });
    await expect(verifyToken(SECRET, t)).rejects.toMatchObject({ code: "bad_signature" });
  });

  it("rejects a tampered payload", async () => {
    const t = await mintToken(SECRET, {
      sub: "m", type: "session", orgId: "acme", scopes: ["fs:read"], ttlSeconds: 60,
    });
    const [h, , s] = t.split(".");
    // forge a payload claiming fs:admin
    const forged = btoa(JSON.stringify({ sub: "m", typ: "session", org: "acme", scp: ["fs:admin"], jti: "x", iat: 1, exp: 9_999_999_999 }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    await expect(verifyToken(SECRET, `${h}.${forged}.${s}`)).rejects.toMatchObject({ code: "bad_signature" });
  });

  it("rejects alg:none / algorithm confusion", async () => {
    const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" })).replace(/=+$/, "");
    const payload = btoa(JSON.stringify({ sub: "m", typ: "session", org: "acme", scp: [], jti: "x", iat: 1, exp: 9_999_999_999 })).replace(/=+$/, "");
    await expect(verifyToken(SECRET, `${header}.${payload}.`)).rejects.toMatchObject({ code: "bad_alg" });
  });

  it("rejects a malformed token", async () => {
    await expect(verifyToken(SECRET, "not-a-jwt")).rejects.toBeInstanceOf(AuthError);
  });

  it("refuses to mint/verify with a weak secret", async () => {
    await expect(
      mintToken("short", { sub: "m", type: "session", orgId: "a", scopes: [], ttlSeconds: 60 }),
    ).rejects.toMatchObject({ code: "bad_secret" });
  });
});

describe("expiry + not-before (token lifecycle)", () => {
  it("rejects an expired token", async () => {
    const now = 1_000_000_000_000;
    const t = await mintToken(SECRET, { sub: "m", type: "session", orgId: "a", scopes: [], ttlSeconds: 60 }, now);
    // 61s + skew later
    await expect(verifyToken(SECRET, t, {}, now + 95_000)).rejects.toMatchObject({ code: "expired" });
  });

  it("accepts a token still within TTL", async () => {
    const now = 1_000_000_000_000;
    const t = await mintToken(SECRET, { sub: "m", type: "session", orgId: "a", scopes: [], ttlSeconds: 60 }, now);
    const p = await verifyToken(SECRET, t, {}, now + 30_000);
    expect(p.sub).toBe("m");
  });

  it("rejects a not-yet-valid token (nbf)", async () => {
    const now = 1_000_000_000_000;
    const t = await mintToken(SECRET, { sub: "m", type: "session", orgId: "a", scopes: [], ttlSeconds: 600, notBeforeSeconds: 300 }, now);
    await expect(verifyToken(SECRET, t, {}, now)).rejects.toMatchObject({ code: "not_yet_valid" });
    const p = await verifyToken(SECRET, t, {}, now + 301_000);
    expect(p.sub).toBe("m");
  });
});

describe("revocation / rotation", () => {
  it("rejects a token whose jti is revoked", async () => {
    const t = await mintToken(SECRET, { sub: "svc", type: "service", orgId: "a", scopes: ["fs:read"], ttlSeconds: 3600, jti: "rot-1" });
    const p = await verifyToken(SECRET, t); // valid before revocation
    expect(p.jti).toBe("rot-1");
    await expect(
      verifyToken(SECRET, t, { revokedJtis: new Set(["rot-1"]) }),
    ).rejects.toMatchObject({ code: "revoked" });
  });
});

describe("scope + tenant guards", () => {
  const p: Principal = {
    sub: "m", type: "session", orgId: "acme", spaceId: "active-edit",
    scopes: ["fs:read", "fs:write"], jti: "j", iat: 1, exp: 9_999_999_999,
  };

  it("requireScope throws 403 on missing scope", () => {
    expect(() => requireScope(p, "fs:read")).not.toThrow();
    try {
      requireScope(p, "fs:admin");
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(AuthError);
      expect((e as AuthError).status).toBe(403);
    }
  });

  it("assertTenant blocks cross-org access", () => {
    expect(() => assertTenant(p, "acme", "active-edit")).not.toThrow();
    expect(() => assertTenant(p, "evilcorp", "active-edit")).toThrow(/cross-tenant/);
  });

  it("assertTenant blocks a space-pinned token addressing the wrong space", () => {
    expect(() => assertTenant(p, "acme", "archive")).toThrow(/this filespace/);
  });

  it("filespaceDoName namespaces by org so two orgs never collide", () => {
    expect(filespaceDoName("acme", "edit")).toBe("acme::edit");
    expect(filespaceDoName("acme", "edit")).not.toBe(filespaceDoName("evilcorp", "edit"));
  });
});

describe("verifyRequest middleware", () => {
  const env = { AUTH_SIGNING_SECRET: SECRET };

  it("extracts a bearer token from the header", () => {
    expect(bearerFromRequest(req({ authorization: "Bearer abc.def.ghi" }))).toBe("abc.def.ghi");
    expect(bearerFromRequest(req({}))).toBeNull();
  });

  it("verifies a real request and returns a Principal", async () => {
    const t = await mintToken(SECRET, { sub: "m", type: "session", orgId: "acme", scopes: ["fs:read"], ttlSeconds: 60 });
    const p = await verifyRequest(req({ authorization: `Bearer ${t}` }), env);
    expect(p.sub).toBe("m");
  });

  it("throws 401 when the token is missing", async () => {
    await expect(verifyRequest(req({}), env)).rejects.toMatchObject({ code: "no_token", status: 401 });
  });
});
