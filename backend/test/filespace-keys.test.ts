// SPDX-License-Identifier: AGPL-3.0-or-later
// filespace-keys.test.ts — server-held filespace master-key service (ONBOARDING.md "Key
// model", build step 2: filespace-keys.ts + org-do.ts storage/routes + index.ts delivery).
//
// Covers:
//   1. Crypto unit tests (filespace-keys.ts): generate/seal round-trips, keyId is deterministic
//      + non-reversible, import validates the exact 32-byte length, fail-closed on a bad/missing
//      STORAGE_ENC_KEY.
//   2. OrgDO storage round-trip: putFilespaceKey/getFilespaceKey persist + read back the sealed
//      columns; absent space → null.
//   3. End-to-end through the real worker (SELF.fetch):
//      - creating a filespace auto-generates + seals a key; the key NEVER appears in the create
//        response or the space list.
//      - GET /v1/filespaces/:fs/key: owner/admin succeeds; a standard user with NO grant is
//        403; a standard user with a ROOT grant succeeds; a real device-minted daemon token
//        (§2.7) succeeds; a wrong-org token is refused (assertTenant).
//      - the delivered envelope has the exact `{ keyId, format:"plain-v1", material }` shape and
//        decodes to 32 bytes.
//      - a space that predates the key service (registered directly on the DO, bypassing the
//        gateway's auto-generate) has no key yet → 404 no_master_key.
//      - POST …/spaces/:id/key/import: non-admin → 403; unknown space → 404; missing/bad-length
//        material → 400; happy path → 201 + the imported bytes are exactly what GET …/key later
//        returns; a second import without replace → 409 key_exists; with replace:true → 200 +
//        a warning field, and the NEW key is what's served afterward.

import { SELF, env } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { mintToken, verifyToken, type Scope } from "../src/security/auth";
import {
  generateSealedMasterKey,
  sealImportedMasterKey,
  openMasterKeyEnvelope,
  keyIdFor,
  MasterKeyError,
  MASTER_KEY_BYTES,
} from "../src/filespace-keys";
import { bytesToB64, b64ToBytes } from "../src/security/storage-crypto";

const ORIGIN = "https://gw.local";
const ENC_KEY = (env as any).STORAGE_ENC_KEY as string;
const ALL_SCOPES: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];

function jsonHeaders(extra?: Record<string, string>): Record<string, string> {
  return { "content-type": "application/json", ...(extra ?? {}) };
}

// =========================================================================================
// 1. Crypto unit tests
// =========================================================================================

describe("filespace-keys.ts — generate/seal/open (unit)", () => {
  it("generateSealedMasterKey produces a sealed envelope that openMasterKeyEnvelope recovers", async () => {
    const sealed = await generateSealedMasterKey(ENC_KEY);
    expect(sealed.keyId).toMatch(/^[0-9a-f]{16}$/);
    const opened = await openMasterKeyEnvelope(ENC_KEY, { keyId: sealed.keyId, keyIv: sealed.iv, keyCiphertext: sealed.ciphertext });
    expect(opened.format).toBe("plain-v1");
    expect(opened.keyId).toBe(sealed.keyId);
    expect(b64ToBytes(opened.material).length).toBe(MASTER_KEY_BYTES);
  });

  it("keyId is deterministic for the same key bytes and different for different keys", async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const id1 = await keyIdFor(raw);
    const id2 = await keyIdFor(raw);
    expect(id1).toBe(id2);
    const other = crypto.getRandomValues(new Uint8Array(32));
    expect(await keyIdFor(other)).not.toBe(id1);
  });

  it("two independently generated keys never collide and are actually random", async () => {
    const a = await generateSealedMasterKey(ENC_KEY);
    const b = await generateSealedMasterKey(ENC_KEY);
    expect(a.keyId).not.toBe(b.keyId);
    const openedA = await openMasterKeyEnvelope(ENC_KEY, { keyId: a.keyId, keyIv: a.iv, keyCiphertext: a.ciphertext });
    const openedB = await openMasterKeyEnvelope(ENC_KEY, { keyId: b.keyId, keyIv: b.iv, keyCiphertext: b.ciphertext });
    expect(openedA.material).not.toBe(openedB.material);
  });

  it("sealImportedMasterKey round-trips EXACT caller-supplied bytes (migration correctness)", async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const materialB64 = bytesToB64(raw);
    const sealed = await sealImportedMasterKey(ENC_KEY, materialB64);
    const opened = await openMasterKeyEnvelope(ENC_KEY, { keyId: sealed.keyId, keyIv: sealed.iv, keyCiphertext: sealed.ciphertext });
    expect(opened.material).toBe(materialB64);
  });

  it("sealImportedMasterKey rejects the wrong byte length (400-mapped MasterKeyError)", async () => {
    const tooShort = bytesToB64(new Uint8Array(16));
    await expect(sealImportedMasterKey(ENC_KEY, tooShort)).rejects.toThrow(MasterKeyError);
    const tooLong = bytesToB64(new Uint8Array(64));
    await expect(sealImportedMasterKey(ENC_KEY, tooLong)).rejects.toThrow(MasterKeyError);
    try {
      await sealImportedMasterKey(ENC_KEY, tooShort);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(MasterKeyError);
      expect((e as MasterKeyError).code).toBe("bad_key_length");
    }
  });

  it("sealImportedMasterKey rejects invalid base64", async () => {
    await expect(sealImportedMasterKey(ENC_KEY, "not valid base64 !!! \0")).rejects.toThrow(MasterKeyError);
  });

  it("fails closed (plain Error, not MasterKeyError) when STORAGE_ENC_KEY is unset", async () => {
    await expect(generateSealedMasterKey(undefined)).rejects.toThrow(/STORAGE_ENC_KEY/);
    const raw = bytesToB64(crypto.getRandomValues(new Uint8Array(32)));
    await expect(sealImportedMasterKey(undefined, raw)).rejects.toThrow(/STORAGE_ENC_KEY/);
  });

  it("openMasterKeyEnvelope throws on a tampered ciphertext (GCM auth tag)", async () => {
    const sealed = await generateSealedMasterKey(ENC_KEY);
    const tampered = sealed.ciphertext.slice(0, -4) + (sealed.ciphertext.slice(-4) === "AAAA" ? "BBBB" : "AAAA");
    await expect(openMasterKeyEnvelope(ENC_KEY, { keyId: sealed.keyId, keyIv: sealed.iv, keyCiphertext: tampered })).rejects.toThrow();
  });
});

// =========================================================================================
// 2. OrgDO storage round-trip
// =========================================================================================

describe("OrgDO.putFilespaceKey / getFilespaceKey (DO storage round-trip)", () => {
  it("persists the sealed columns and reads them back; unknown space → null", async () => {
    const orgId = `fk-do-${crypto.randomUUID().slice(0, 8)}`;
    const org = (env as any).ORG_DO.getByName(orgId);
    expect(await org.getFilespaceKey("fs-nope")).toBeNull();

    const sealed = await generateSealedMasterKey(ENC_KEY);
    const row = await org.putFilespaceKey({
      spaceId: "fs-a", orgId, keyId: sealed.keyId, keyIv: sealed.iv, keyCiphertext: sealed.ciphertext,
    });
    expect(row.spaceId).toBe("fs-a");
    expect(row.keyId).toBe(sealed.keyId);

    const got = await org.getFilespaceKey("fs-a");
    expect(got).not.toBeNull();
    expect(got.keyId).toBe(sealed.keyId);
    expect(got.keyIv).toBe(sealed.iv);
    expect(got.keyCiphertext).toBe(sealed.ciphertext);

    // upsert-by-spaceId: putting again with a NEW sealed key replaces the row (the gateway's
    // key/import route relies on this for the `replace:true` path).
    const sealed2 = await generateSealedMasterKey(ENC_KEY);
    await org.putFilespaceKey({
      spaceId: "fs-a", orgId, keyId: sealed2.keyId, keyIv: sealed2.iv, keyCiphertext: sealed2.ciphertext,
    });
    const got2 = await org.getFilespaceKey("fs-a");
    expect(got2.keyId).toBe(sealed2.keyId);
    expect(got2.keyId).not.toBe(sealed.keyId);
  });
});

// =========================================================================================
// 3. End-to-end through the real worker
// =========================================================================================

async function bootstrapOwner(orgId: string): Promise<{ token: string; userId: string }> {
  const res = await SELF.fetch(`${ORIGIN}/v1/bootstrap`, {
    method: "POST",
    headers: jsonHeaders({ "x-bootstrap-secret": (env as any).BOOTSTRAP_SECRET }),
    body: JSON.stringify({ orgId, email: `owner@${orgId}.test`, displayName: "Owner", allowTokenOnly: true }),
  });
  expect(res.status).toBe(201);
  return (await res.json()) as { token: string; userId: string };
}

async function standardUser(orgId: string): Promise<{ userId: string; token: string }> {
  const org = (env as any).ORG_DO.getByName(orgId);
  const u = await org.createUser({ orgId, email: `std-${crypto.randomUUID()}@${orgId}.test`, displayName: "Std", role: "standard" });
  const token = await mintToken((env as any).AUTH_SIGNING_SECRET, { sub: u.id, type: "session", orgId, scopes: ALL_SCOPES, ttlSeconds: 900 });
  return { userId: u.id, token };
}

function authOf(token: string): Record<string, string> {
  return jsonHeaders({ Authorization: `Bearer ${token}` });
}

describe("filespace master-key delivery + provisioning (end-to-end, real OrgDO/FilespaceDO)", () => {
  const ORG = `fk-org-${Date.now()}`;
  const SPACE = "fk-space";
  let ownerAuth: Record<string, string>;
  let ownerUserId: string;

  beforeAll(async () => {
    const boot = await bootstrapOwner(ORG);
    ownerUserId = boot.userId;
    ownerAuth = authOf(boot.token);
  });

  it("creating a filespace auto-provisions a key that NEVER appears in the create response or the space list", async () => {
    const created = await SELF.fetch(`${ORIGIN}/v1/orgs/${ORG}/spaces`, {
      method: "POST", headers: ownerAuth,
      body: JSON.stringify({ spaceId: SPACE, name: "FK Space", bucketProvider: "r2", bucketName: "b", keyPrefix: `blocks/${ORG}::${SPACE}/` }),
    });
    expect(created.status).toBe(201);
    const createdText = await created.clone().text();
    const org = (env as any).ORG_DO.getByName(ORG);
    const row = await org.getFilespaceKey(SPACE);
    expect(row).not.toBeNull();
    // The raw sealed columns (and obviously not the plaintext key) never leak into the response.
    expect(createdText).not.toContain(row.keyIv);
    expect(createdText).not.toContain(row.keyCiphertext);
    expect(createdText).not.toContain(row.keyId);

    const listed = await SELF.fetch(`${ORIGIN}/v1/orgs/${ORG}/spaces`, { headers: ownerAuth });
    const listText = await listed.text();
    expect(listText).not.toContain(row.keyIv);
    expect(listText).not.toContain(row.keyCiphertext);
  });

  it("re-registering the SAME spaceId (idempotent create) does NOT rotate the key (revive safety)", async () => {
    const org = (env as any).ORG_DO.getByName(ORG);
    const before = await org.getFilespaceKey(SPACE);
    const again = await SELF.fetch(`${ORIGIN}/v1/orgs/${ORG}/spaces`, {
      method: "POST", headers: ownerAuth,
      body: JSON.stringify({ spaceId: SPACE, name: "FK Space Renamed", bucketProvider: "r2", bucketName: "b", keyPrefix: `blocks/${ORG}::${SPACE}/` }),
    });
    expect(again.status).toBe(201);
    const after = await org.getFilespaceKey(SPACE);
    expect(after.keyId).toBe(before.keyId);
    expect(after.keyCiphertext).toBe(before.keyCiphertext);
  });

  it("GET …/key: owner succeeds with the exact wrapped envelope shape", async () => {
    const res = await SELF.fetch(`${ORIGIN}/v1/filespaces/${SPACE}/key`, { headers: ownerAuth });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { keyId: string; format: string; material: string };
    expect(body.format).toBe("plain-v1");
    expect(typeof body.keyId).toBe("string");
    expect(b64ToBytes(body.material).length).toBe(MASTER_KEY_BYTES);
    // matches what's actually stored (decrypted) — not some other/stale key.
    const org = (env as any).ORG_DO.getByName(ORG);
    const row = await org.getFilespaceKey(SPACE);
    expect(body.keyId).toBe(row.keyId);
  });

  it("GET …/key: a standard user with NO grant is 403 forbidden", async () => {
    const std = await standardUser(ORG);
    const res = await SELF.fetch(`${ORIGIN}/v1/filespaces/${SPACE}/key`, { headers: authOf(std.token) });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("forbidden");
  });

  it("GET …/key: a standard user GRANTED read on root succeeds (same authority as reading file content)", async () => {
    const std = await standardUser(ORG);
    const grant = await SELF.fetch(`${ORIGIN}/v1/filespaces/${SPACE}/grants`, {
      method: "POST", headers: ownerAuth,
      body: JSON.stringify({ inodeId: "root", principalType: "user", principalId: std.userId, level: "read" }),
    });
    expect(grant.status).toBe(201);
    const res = await SELF.fetch(`${ORIGIN}/v1/filespaces/${SPACE}/key`, { headers: authOf(std.token) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { format: string };
    expect(body.format).toBe("plain-v1");
  });

  it("GET …/key: a token scoped to a DIFFERENT filespace is refused (assertTenant wrong_space)", async () => {
    const wrongSpaceToken = await mintToken((env as any).AUTH_SIGNING_SECRET, {
      sub: ownerUserId, type: "session", orgId: ORG, spaceId: "some-other-space", scopes: ALL_SCOPES, ttlSeconds: 900,
    });
    const res = await SELF.fetch(`${ORIGIN}/v1/filespaces/${SPACE}/key`, { headers: authOf(wrongSpaceToken) });
    expect(res.status).toBe(403);
  });

  it("GET …/key: without fs:read scope → 403 forbidden_scope", async () => {
    const std = await standardUser(ORG);
    const noReadToken = await mintToken((env as any).AUTH_SIGNING_SECRET, {
      sub: std.userId, type: "session", orgId: ORG, scopes: ["fs:write"], ttlSeconds: 900,
    });
    const res = await SELF.fetch(`${ORIGIN}/v1/filespaces/${SPACE}/key`, { headers: authOf(noReadToken) });
    expect(res.status).toBe(403);
  });

  it("a space that predates the key service (registered directly on the DO) has no key → 404 no_master_key", async () => {
    const legacySpace = "fk-legacy";
    const org = (env as any).ORG_DO.getByName(ORG);
    // Bypass the gateway's auto-generate-on-create by calling registerSpace DIRECTLY on the DO —
    // this is exactly how an operator-provisioned filespace from before this feature looks today.
    await org.registerSpace({
      spaceId: legacySpace, orgId: ORG, name: "Legacy", bucketProvider: "r2", bucketName: "b",
      keyPrefix: `blocks/${ORG}::${legacySpace}/`,
    });
    expect(await org.getFilespaceKey(legacySpace)).toBeNull();

    const res = await SELF.fetch(`${ORIGIN}/v1/filespaces/${legacySpace}/key`, { headers: ownerAuth });
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("no_master_key");
  });

  describe("POST /v1/orgs/:org/spaces/:id/key/import (migration path)", () => {
    const LEGACY = "fk-import-space";

    beforeAll(async () => {
      const org = (env as any).ORG_DO.getByName(ORG);
      await org.registerSpace({
        spaceId: LEGACY, orgId: ORG, name: "Import Me", bucketProvider: "r2", bucketName: "b",
        keyPrefix: `blocks/${ORG}::${LEGACY}/`,
      });
    });

    it("non-admin caller → 403", async () => {
      const std = await standardUser(ORG);
      const res = await SELF.fetch(`${ORIGIN}/v1/orgs/${ORG}/spaces/${LEGACY}/key/import`, {
        method: "POST", headers: authOf(std.token),
        body: JSON.stringify({ material: bytesToB64(new Uint8Array(32)) }),
      });
      expect(res.status).toBe(403);
    });

    it("unknown space id → 404", async () => {
      const res = await SELF.fetch(`${ORIGIN}/v1/orgs/${ORG}/spaces/fk-does-not-exist/key/import`, {
        method: "POST", headers: ownerAuth,
        body: JSON.stringify({ material: bytesToB64(new Uint8Array(32)) }),
      });
      expect(res.status).toBe(404);
    });

    it("missing material → 400", async () => {
      const res = await SELF.fetch(`${ORIGIN}/v1/orgs/${ORG}/spaces/${LEGACY}/key/import`, {
        method: "POST", headers: ownerAuth, body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
    });

    it("wrong-length material → 400 bad_key_length", async () => {
      const res = await SELF.fetch(`${ORIGIN}/v1/orgs/${ORG}/spaces/${LEGACY}/key/import`, {
        method: "POST", headers: ownerAuth,
        body: JSON.stringify({ material: bytesToB64(new Uint8Array(16)) }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("bad_key_length");
    });

    it("happy path (201): the EXACT uploaded key is what GET …/key serves afterward", async () => {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      const materialB64 = bytesToB64(raw);
      const res = await SELF.fetch(`${ORIGIN}/v1/orgs/${ORG}/spaces/${LEGACY}/key/import`, {
        method: "POST", headers: ownerAuth, body: JSON.stringify({ material: materialB64 }),
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as { keyId: string; replaced: boolean; warning?: string };
      expect(body.replaced).toBe(false);
      expect(body.warning).toBeUndefined();

      const fetched = await SELF.fetch(`${ORIGIN}/v1/filespaces/${LEGACY}/key`, { headers: ownerAuth });
      expect(fetched.status).toBe(200);
      const envelope = (await fetched.json()) as { keyId: string; material: string };
      expect(envelope.keyId).toBe(body.keyId);
      expect(envelope.material).toBe(materialB64); // EXACT operator-provisioned bytes, unchanged
    });

    it("importing again WITHOUT replace → 409 key_exists (never silently clobbers)", async () => {
      const res = await SELF.fetch(`${ORIGIN}/v1/orgs/${ORG}/spaces/${LEGACY}/key/import`, {
        method: "POST", headers: ownerAuth,
        body: JSON.stringify({ material: bytesToB64(crypto.getRandomValues(new Uint8Array(32))) }),
      });
      expect(res.status).toBe(409);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("key_exists");
    });

    it("importing with replace:true → 200 + a warning field, and the NEW key is served afterward", async () => {
      const org = (env as any).ORG_DO.getByName(ORG);
      const before = await org.getFilespaceKey(LEGACY);
      const raw = crypto.getRandomValues(new Uint8Array(32));
      const materialB64 = bytesToB64(raw);
      const res = await SELF.fetch(`${ORIGIN}/v1/orgs/${ORG}/spaces/${LEGACY}/key/import`, {
        method: "POST", headers: ownerAuth, body: JSON.stringify({ material: materialB64, replace: true }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { keyId: string; replaced: boolean; warning?: string };
      expect(body.replaced).toBe(true);
      expect(typeof body.warning).toBe("string");
      expect(body.warning!.length).toBeGreaterThan(0);

      const after = await org.getFilespaceKey(LEGACY);
      expect(after.keyId).not.toBe(before.keyId);

      const fetched = await SELF.fetch(`${ORIGIN}/v1/filespaces/${LEGACY}/key`, { headers: ownerAuth });
      const envelope = (await fetched.json()) as { material: string };
      expect(envelope.material).toBe(materialB64);
    });
  });

  // =======================================================================================
  // Daemon-token path (§2.7 device-minted 30-day service token) — reuses the real device
  // pairing flow so this proves the ACTUAL cloudfsd credential, not a hand-minted stand-in.
  // =======================================================================================
  describe("daemon token (§2.7) can fetch the master key", () => {
    function b64url(bytes: Uint8Array): string {
      let bin = "";
      for (const b of bytes) bin += String.fromCharCode(b);
      return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }
    async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
      const raw = new Uint8Array(32);
      crypto.getRandomValues(raw);
      const verifier = b64url(raw);
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
      return { verifier, challenge: b64url(new Uint8Array(digest)) };
    }
    function sessionCookie(res: Response): string {
      const sc = res.headers.get("set-cookie")!;
      return /cfs_session=([^;]+)/.exec(sc)![1];
    }

    it("a real device-minted daemon token fetches the wrapped envelope", async () => {
      // Fresh org (own signup) so this test is self-contained re: rate limits.
      const email = `daemon-${Date.now()}@example.test`;
      const signup = await SELF.fetch(`${ORIGIN}/v1/auth/signup`, {
        method: "POST",
        headers: jsonHeaders({ "cf-connecting-ip": `198.51.60.${Date.now() % 250}` }),
        body: JSON.stringify({ orgName: "Daemon Org", email, password: "correct horse battery staple", displayName: "Owner" }),
      });
      expect(signup.status).toBe(201);
      const signupBody = (await signup.json()) as any;
      const authDo = (env as any).AUTH_DO.get((env as any).AUTH_DO.idFromName(signupBody.orgId));
      await authDo.setEmailVerified(signupBody.accountId, true);
      const cookie = sessionCookie(signup);
      const csrf = signupBody.csrf;

      // Register a filespace in this fresh org (auto-provisions a key).
      const orgId = signupBody.orgId;
      const daemonSpace = "daemon-space";
      const ownerSessionToken = await mintToken((env as any).AUTH_SIGNING_SECRET, {
        sub: signupBody.userId, type: "session", orgId, scopes: ALL_SCOPES, ttlSeconds: 900,
      });
      const created = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/spaces`, {
        method: "POST", headers: authOf(ownerSessionToken),
        body: JSON.stringify({ spaceId: daemonSpace, name: "Daemon Space", bucketProvider: "r2", bucketName: "b", keyPrefix: `blocks/${orgId}::${daemonSpace}/` }),
      });
      expect(created.status).toBe(201);

      // Device approve → exchange → daemon-token mint (§2.2/§2.3/§2.7).
      const { verifier, challenge } = await pkcePair();
      const approveRes = await SELF.fetch(`${ORIGIN}/v1/auth/device/approve`, {
        method: "POST",
        headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf, "cf-connecting-ip": `198.51.61.${Date.now() % 250}` }),
        body: JSON.stringify({ state: "S".repeat(43), codeChallenge: challenge, codeChallengeMethod: "S256", deviceName: "Test Daemon Mac" }),
      });
      expect(approveRes.status).toBe(201);
      const { code } = (await approveRes.json()) as { code: string };
      const exchangeRes = await SELF.fetch(`${ORIGIN}/v1/auth/device/token`, {
        method: "POST",
        headers: jsonHeaders({ "cf-connecting-ip": `198.51.62.${Date.now() % 250}` }),
        body: JSON.stringify({ code, codeVerifier: verifier }),
      });
      expect(exchangeRes.status).toBe(200);
      const exchangeBody = (await exchangeRes.json()) as { accessToken: string };
      const daemonMint = await SELF.fetch(`${ORIGIN}/v1/auth/device/daemon-token`, {
        method: "POST",
        headers: jsonHeaders({ Authorization: `Bearer ${exchangeBody.accessToken}`, "cf-connecting-ip": `198.51.63.${Date.now() % 250}` }),
        body: JSON.stringify({}),
      });
      expect(daemonMint.status).toBe(201);
      const daemonBody = (await daemonMint.json()) as { token: string };
      const principal = await verifyToken((env as any).AUTH_SIGNING_SECRET, daemonBody.token);
      expect(principal.type).toBe("service");
      expect(principal.scopes).toContain("fs:read");

      // THE daemon token fetches the master key over the SAME data-plane channel it uses to
      // read file content — no separate/blessed auth path.
      const keyRes = await SELF.fetch(`${ORIGIN}/v1/filespaces/${daemonSpace}/key`, {
        headers: { Authorization: `Bearer ${daemonBody.token}` },
      });
      expect(keyRes.status).toBe(200);
      const envelope = (await keyRes.json()) as { format: string; material: string };
      expect(envelope.format).toBe("plain-v1");
      expect(b64ToBytes(envelope.material).length).toBe(MASTER_KEY_BYTES);
    });
  });
});
