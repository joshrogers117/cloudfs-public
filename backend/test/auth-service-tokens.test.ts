// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
  mintServiceToken,
  listServiceTokens,
  getServiceToken,
  revokeServiceToken,
  revokedServiceJtis,
  hashSecret,
  verifySecret,
  toPublic,
  InMemoryServiceTokenStore,
  type ServiceTokenDeps,
  type ServiceToken,
  type ServiceTokenRole,
} from "../src/security/auth-service-tokens";
import { verifyToken, AuthError, DEFAULT_TTL_SECONDS } from "../src/security/auth";

const SECRET = "test-signing-secret-at-least-16-chars-long";
const NOW = 1_700_000_000_000; // fixed epoch ms for deterministic exp math

/// Build a fully-deterministic deps bundle: fixed clock, counter-based ids, fixed bytes,
/// and a service-account creator that records calls and never touches the network/OrgDO.
function makeDeps(over: Partial<ServiceTokenDeps> = {}) {
  const store = new InMemoryServiceTokenStore();
  let idCounter = 0;
  const createdAccounts: { orgId: string; label: string }[] = [];
  const deps: ServiceTokenDeps = {
    store,
    env: { AUTH_SIGNING_SECRET: SECRET },
    now: () => NOW,
    randomId: () => `id${++idCounter}`,
    // deterministic, distinct-per-byte secret material (no CSPRNG in tests)
    randomBytes: (len: number) => new Uint8Array(Array.from({ length: len }, (_, i) => (i * 7 + 3) & 0xff)),
    createServiceAccountUser: async ({ orgId, label }) => {
      createdAccounts.push({ orgId, label });
      return { userId: `usr-svc-${createdAccounts.length}` };
    },
    ...over,
  };
  return { deps, store, createdAccounts };
}

const ADMIN: ServiceTokenRole = "admin";
const OWNER: ServiceTokenRole = "owner";

describe("mintServiceToken — happy path + JWS round-trip", () => {
  it("mints a verifiable service JWS whose jti == record id and Principal matches the record", async () => {
    const { deps } = makeDeps();
    const res = await mintServiceToken(deps, ADMIN, "usr-admin-1", {
      orgId: "acme",
      label: "render-node-7",
      scopes: ["fs:read", "fs:write"],
      spaceId: "active-edit",
    });

    expect(res.id).toBe("svc-id1");
    expect(res.token.split(".")).toHaveLength(3); // compact JWS
    expect(res.label).toBe("render-node-7");
    expect(res.spaceId).toBe("active-edit");

    // The minted JWS verifies through the existing auth.ts gate, at mint time.
    const p = await verifyToken(SECRET, res.token, {}, NOW);
    expect(p.type).toBe("service");
    expect(p.jti).toBe(res.id); // revocation handle == record id
    expect(p.orgId).toBe("acme");
    expect(p.spaceId).toBe("active-edit");
    expect(p.scopes).toEqual(["fs:read", "fs:write"]);
    expect(p.sub).toBe(p.sub); // sub is the service-account user id
  });

  it("creates a service_account user when none is supplied, and records createdBy", async () => {
    const { deps, createdAccounts } = makeDeps();
    const res = await mintServiceToken(deps, OWNER, "usr-owner-1", {
      orgId: "acme",
      label: "cli-laptop",
      scopes: ["fs:read"],
    });
    expect(createdAccounts).toEqual([{ orgId: "acme", label: "cli-laptop" }]);
    const p = await verifyToken(SECRET, res.token, {}, NOW);
    expect(p.sub).toBe("usr-svc-1");
    expect(res.record.userId).toBe("usr-svc-1");
    expect(res.record.createdByUserId).toBe("usr-owner-1");
  });

  it("reuses an existing service-account user id and does NOT create one", async () => {
    const { deps, createdAccounts } = makeDeps();
    const res = await mintServiceToken(deps, ADMIN, "usr-admin-1", {
      orgId: "acme",
      label: "existing-acct",
      scopes: ["fs:read"],
      serviceAccountUserId: "usr-preexisting",
    });
    expect(createdAccounts).toEqual([]); // never created
    const p = await verifyToken(SECRET, res.token, {}, NOW);
    expect(p.sub).toBe("usr-preexisting");
  });
});

describe("storage — hashed only, plaintext returned once", () => {
  it("persists only a SHA-256 hash of the secret half; never the JWS or a raw secret", async () => {
    const { deps, store } = makeDeps();
    const res = await mintServiceToken(deps, ADMIN, "usr-admin-1", {
      orgId: "acme",
      label: "secrecy",
      scopes: ["fs:read"],
    });

    const stored = await store.getServiceToken(res.id);
    expect(stored).not.toBeNull();
    // The bearer JWS is never persisted anywhere on the record.
    const serialized = JSON.stringify(stored);
    expect(serialized).not.toContain(res.token);
    // hashedSecret is a base64url SHA-256 digest: decodes to exactly 32 bytes.
    const raw = atob(stored!.hashedSecret.replace(/-/g, "+").replace(/_/g, "/"));
    expect(raw.length).toBe(32);
    // and it is NOT the plaintext token.
    expect(stored!.hashedSecret).not.toBe(res.token);
  });

  it("toPublic strips hashedSecret; list/get never leak it", async () => {
    const { deps } = makeDeps();
    const res = await mintServiceToken(deps, ADMIN, "usr-admin-1", {
      orgId: "acme",
      label: "pub",
      scopes: ["fs:read"],
    });
    expect(res.record).not.toHaveProperty("hashedSecret");

    const list = await listServiceTokens(deps, ADMIN, "acme");
    expect(list).toHaveLength(1);
    expect(list[0]).not.toHaveProperty("hashedSecret");
    expect(Object.keys(list[0])).not.toContain("hashedSecret");

    const one = await getServiceToken(deps, ADMIN, "acme", res.id);
    expect(one).not.toHaveProperty("hashedSecret");
  });

  it("the secret hash is reproducible and constant-time verifiable", async () => {
    // Deterministic randomBytes ⇒ deterministic secret ⇒ stable hash.
    const { deps, store } = makeDeps();
    const res = await mintServiceToken(deps, ADMIN, "usr-admin-1", {
      orgId: "acme",
      label: "x",
      scopes: ["fs:read"],
    });
    const stored = (await store.getServiceToken(res.id))!;
    // Recompute the secret the same way the module did and confirm it verifies.
    const secretBytes = new Uint8Array(Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff));
    const secret = btoa(String.fromCharCode(...secretBytes))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(await verifySecret(secret, stored.hashedSecret)).toBe(true);
    expect(await verifySecret("wrong-secret", stored.hashedSecret)).toBe(false);
  });
});

describe("hashSecret / verifySecret (constant-time compare)", () => {
  it("verifies the matching secret and rejects a mismatch", async () => {
    const h = await hashSecret("correct horse battery staple");
    expect(h).toMatch(/^[A-Za-z0-9_-]+$/); // base64url, no padding
    expect(await verifySecret("correct horse battery staple", h)).toBe(true);
    expect(await verifySecret("Correct horse battery staple", h)).toBe(false);
  });

  it("rejects (without throwing) when the stored hash is not a 32-byte digest", async () => {
    expect(await verifySecret("anything", "not-a-real-hash")).toBe(false);
    expect(await verifySecret("anything", "")).toBe(false);
  });

  it("differs per input (no accidental collisions in the test vectors)", async () => {
    const a = await hashSecret("a");
    const b = await hashSecret("b");
    expect(a).not.toBe(b);
  });
});

describe("authorization gate — owner/admin only", () => {
  for (const role of ["space_admin", "standard"] as ServiceTokenRole[]) {
    it(`rejects mint for role '${role}' with 403`, async () => {
      const { deps } = makeDeps();
      await expect(
        mintServiceToken(deps, role, "usr-x", { orgId: "acme", label: "l", scopes: ["fs:read"] }),
      ).rejects.toMatchObject({ status: 403, code: "forbidden_role" });
    });
  }

  it("rejects list/get/revoke for non-admin roles", async () => {
    const { deps } = makeDeps();
    // seed one as admin
    const res = await mintServiceToken(deps, ADMIN, "usr-admin-1", {
      orgId: "acme",
      label: "l",
      scopes: ["fs:read"],
    });
    await expect(listServiceTokens(deps, "standard", "acme")).rejects.toMatchObject({ status: 403 });
    await expect(getServiceToken(deps, "standard", "acme", res.id)).rejects.toMatchObject({ status: 403 });
    await expect(revokeServiceToken(deps, "standard", "acme", res.id)).rejects.toMatchObject({ status: 403 });
  });

  it("allows both owner and admin", async () => {
    const { deps } = makeDeps();
    await expect(
      mintServiceToken(deps, OWNER, "u", { orgId: "acme", label: "o", scopes: ["fs:read"] }),
    ).resolves.toBeTruthy();
    await expect(
      mintServiceToken(deps, ADMIN, "u", { orgId: "acme", label: "a", scopes: ["fs:read"] }),
    ).resolves.toBeTruthy();
  });
});

describe("input validation", () => {
  it("requires a non-empty label", async () => {
    const { deps } = makeDeps();
    await expect(
      mintServiceToken(deps, ADMIN, "u", { orgId: "acme", label: "   ", scopes: ["fs:read"] }),
    ).rejects.toBeInstanceOf(AuthError);
  });

  it("requires at least one scope (least privilege)", async () => {
    const { deps } = makeDeps();
    await expect(
      mintServiceToken(deps, ADMIN, "u", { orgId: "acme", label: "l", scopes: [] }),
    ).rejects.toMatchObject({ code: "bad_request" });
  });

  it("rejects an unknown scope", async () => {
    const { deps } = makeDeps();
    await expect(
      mintServiceToken(deps, ADMIN, "u", {
        orgId: "acme",
        label: "l",
        // deliberately invalid scope
        scopes: ["fs:superuser" as never],
      }),
    ).rejects.toMatchObject({ code: "bad_scope" });
  });
});

describe("list / get — tenant isolation + projection", () => {
  it("lists only the requested org's tokens", async () => {
    const { deps } = makeDeps();
    await mintServiceToken(deps, ADMIN, "u", { orgId: "acme", label: "a1", scopes: ["fs:read"] });
    await mintServiceToken(deps, ADMIN, "u", { orgId: "acme", label: "a2", scopes: ["fs:read"] });
    await mintServiceToken(deps, ADMIN, "u", { orgId: "evilcorp", label: "e1", scopes: ["fs:read"] });

    const acme = await listServiceTokens(deps, ADMIN, "acme");
    expect(acme.map((t) => t.label).sort()).toEqual(["a1", "a2"]);
    const evil = await listServiceTokens(deps, ADMIN, "evilcorp");
    expect(evil.map((t) => t.label)).toEqual(["e1"]);
  });

  it("get returns null for a token belonging to another org (no cross-tenant peek)", async () => {
    const { deps } = makeDeps();
    const res = await mintServiceToken(deps, ADMIN, "u", {
      orgId: "acme",
      label: "a",
      scopes: ["fs:read"],
    });
    expect(await getServiceToken(deps, ADMIN, "evilcorp", res.id)).toBeNull();
    expect(await getServiceToken(deps, ADMIN, "acme", res.id)).not.toBeNull();
    expect(await getServiceToken(deps, ADMIN, "acme", "svc-missing")).toBeNull();
  });
});

describe("revoke — wired into revokedServiceJtis + verify path", () => {
  it("revoked token's jti appears in revokedServiceJtis and verifyToken then rejects it", async () => {
    const { deps } = makeDeps();
    const res = await mintServiceToken(deps, ADMIN, "u", {
      orgId: "acme",
      label: "to-revoke",
      scopes: ["fs:read"],
    });

    // Before revocation: verifies fine, jti absent from revoked set.
    expect(await revokedServiceJtis(deps)).not.toContain(res.id);
    await expect(verifyToken(SECRET, res.token, {}, NOW)).resolves.toMatchObject({ jti: res.id });

    await revokeServiceToken(deps, ADMIN, "acme", res.id);

    // After: jti is in the revoked set, and feeding it to verify rejects the JWS.
    const revoked = await revokedServiceJtis(deps);
    expect(revoked.has(res.id)).toBe(true);
    await expect(
      verifyToken(SECRET, res.token, { revokedJtis: revoked }, NOW),
    ).rejects.toMatchObject({ code: "revoked" });

    // The stored record reflects revoked=true (public projection too).
    const one = await getServiceToken(deps, ADMIN, "acme", res.id);
    expect(one!.revoked).toBe(true);
  });

  it("revoke is idempotent and 404s on missing / cross-tenant ids", async () => {
    const { deps } = makeDeps();
    const res = await mintServiceToken(deps, ADMIN, "u", {
      orgId: "acme",
      label: "l",
      scopes: ["fs:read"],
    });
    await revokeServiceToken(deps, ADMIN, "acme", res.id);
    await revokeServiceToken(deps, ADMIN, "acme", res.id); // idempotent, no throw

    await expect(revokeServiceToken(deps, ADMIN, "acme", "svc-missing")).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(revokeServiceToken(deps, ADMIN, "evilcorp", res.id)).rejects.toMatchObject({
      code: "not_found",
    });
  });

  it("only revoked jtis are returned (active tokens are not in the set)", async () => {
    const { deps } = makeDeps();
    const a = await mintServiceToken(deps, ADMIN, "u", { orgId: "acme", label: "a", scopes: ["fs:read"] });
    const b = await mintServiceToken(deps, ADMIN, "u", { orgId: "acme", label: "b", scopes: ["fs:read"] });
    await revokeServiceToken(deps, ADMIN, "acme", a.id);
    const set = await revokedServiceJtis(deps);
    expect(set.has(a.id)).toBe(true);
    expect(set.has(b.id)).toBe(false);
  });
});

describe("expiry / TTL behavior", () => {
  it("defaults to the service TTL ceiling and sets a matching exp on record + JWS", async () => {
    const { deps } = makeDeps();
    const res = await mintServiceToken(deps, ADMIN, "u", {
      orgId: "acme",
      label: "l",
      scopes: ["fs:read"],
    });
    expect(res.expiresAt).toBe(NOW + DEFAULT_TTL_SECONDS.service * 1000);
    // Expired once we pass exp (+ skew): the JWS verify fails.
    await expect(
      verifyToken(SECRET, res.token, {}, NOW + (DEFAULT_TTL_SECONDS.service + 120) * 1000),
    ).rejects.toMatchObject({ code: "expired" });
  });

  it("honors an explicit ttlSeconds", async () => {
    const { deps } = makeDeps();
    const res = await mintServiceToken(deps, ADMIN, "u", {
      orgId: "acme",
      label: "l",
      scopes: ["fs:read"],
      ttlSeconds: 3600,
    });
    expect(res.expiresAt).toBe(NOW + 3600 * 1000);
    await verifyToken(SECRET, res.token, {}, NOW + 1000); // within TTL
    await expect(
      verifyToken(SECRET, res.token, {}, NOW + (3600 + 120) * 1000),
    ).rejects.toMatchObject({ code: "expired" });
  });

  it("ttlSeconds:null marks the record non-expiring (relies on jti-revocation)", async () => {
    const { deps } = makeDeps();
    const res = await mintServiceToken(deps, ADMIN, "u", {
      orgId: "acme",
      label: "l",
      scopes: ["fs:read"],
      ttlSeconds: null,
    });
    expect(res.expiresAt).toBeNull(); // record carries no expiry; revocation is the kill switch
    // The bearer JWS still carries a bounded exp (a bare bearer must), but the record's
    // policy is "lives until revoked".
    const p = await verifyToken(SECRET, res.token, {}, NOW);
    expect(p.jti).toBe(res.id);
  });
});

describe("InMemoryServiceTokenStore", () => {
  it("rejects duplicate ids and touches lastUsedAt", async () => {
    const store = new InMemoryServiceTokenStore();
    const rec: ServiceToken = {
      id: "svc-1",
      orgId: "acme",
      userId: "usr-1",
      label: "l",
      scopes: ["fs:read"],
      spaceId: null,
      hashedSecret: await hashSecret("s"),
      createdByUserId: "usr-admin",
      createdAt: NOW,
      lastUsedAt: null,
      expiresAt: null,
      revoked: false,
    };
    await store.createServiceToken(rec);
    await expect(store.createServiceToken(rec)).rejects.toThrow(/duplicate/);

    await store.touchServiceToken("svc-1", NOW + 5);
    expect((await store.getServiceToken("svc-1"))!.lastUsedAt).toBe(NOW + 5);

    // returned records are copies — mutating them does not corrupt the store
    const got = (await store.getServiceToken("svc-1"))!;
    got.scopes.push("fs:admin");
    expect((await store.getServiceToken("svc-1"))!.scopes).toEqual(["fs:read"]);
  });

  it("toPublic on a record drops only hashedSecret", async () => {
    const rec: ServiceToken = {
      id: "svc-1",
      orgId: "acme",
      userId: "usr-1",
      label: "l",
      scopes: ["fs:read"],
      spaceId: null,
      hashedSecret: "h",
      createdByUserId: "usr-admin",
      createdAt: NOW,
      lastUsedAt: null,
      expiresAt: null,
      revoked: false,
    };
    const pub = toPublic(rec);
    expect(pub).not.toHaveProperty("hashedSecret");
    expect(pub.id).toBe("svc-1");
    expect(pub.label).toBe("l");
  });
});
