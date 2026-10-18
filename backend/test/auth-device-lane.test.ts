// SPDX-License-Identifier: AGPL-3.0-or-later
// auth-device-lane.test.ts — UNIT coverage of the device-session lane (auth-spec §2.2–§2.4)
// against in-memory stores with an injected clock, so the time-sensitive behaviours (code
// expiry, the 60s rotation race grace, reuse-after-grace revocation, the 400-day sliding
// expiry) are tested deterministically. Wire/HTTP behaviour is covered by
// auth-device-integration.test.ts; this file pins the state machine itself.

import { describe, it, expect } from "vitest";
import {
  approveDevice,
  exchangeDeviceCode,
  refreshDeviceSession,
  computeS256Challenge,
  InMemoryDeviceStore,
  DeviceAuthError,
  DEVICE_CODE_TTL_MS,
  DEVICE_SESSION_LIFETIME_MS,
  REFRESH_ROTATION_GRACE_MS,
  type DeviceAuthDeps,
} from "../src/security/auth-device";
import { verifyToken } from "../src/security/auth";
import { scopesForRole } from "../src/security/oidc";
import type { Account } from "../src/security/auth-types";

const SIGNING_SECRET = "unit-test-signing-secret-32-chars!!";

// A 43-char base64url verifier (RFC 7636 minimum) — deterministic for the tests.
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

interface Harness {
  deps: DeviceAuthDeps;
  store: InMemoryDeviceStore;
  accounts: Map<string, Account>;
  account: Account;
  clock: { now: number };
}

function makeHarness(role: Account["role"] = "standard"): Harness {
  const store = new InMemoryDeviceStore();
  const accounts = new Map<string, Account>();
  const account: Account = {
    id: "acc-1",
    userId: "usr-1",
    orgId: "org1",
    email: "editor@org1.test",
    displayName: "Editor",
    role,
    status: "active",
    emailVerified: true,
    createdAt: 0,
  };
  accounts.set(account.id, account);
  const clock = { now: 1_000_000_000 };
  const deps: DeviceAuthDeps = {
    store,
    accounts: { getAccount: async (id) => accounts.get(id) ?? null },
    env: { AUTH_SIGNING_SECRET: SIGNING_SECRET },
    now: () => clock.now,
  };
  return { deps, store, accounts, account, clock };
}

async function approve(h: Harness, challenge?: string) {
  return approveDevice(
    h.deps,
    { accountId: h.account.id, userId: h.account.userId, orgId: h.account.orgId },
    {
      codeChallenge: challenge ?? (await computeS256Challenge(VERIFIER)),
      codeChallengeMethod: "S256",
      deviceName: "Test MacBook Pro",
      deviceModel: "MacBookPro18,3",
    },
  );
}

async function expectDeviceError(p: Promise<unknown>, code: string, status?: number): Promise<void> {
  try {
    await p;
    expect.fail(`expected DeviceAuthError ${code}, got success`);
  } catch (e) {
    expect(e).toBeInstanceOf(DeviceAuthError);
    expect((e as DeviceAuthError).code).toBe(code);
    if (status !== undefined) expect((e as DeviceAuthError).status).toBe(status);
  }
}

// =========================================================================================
// §2.2 approve — validation matrix + code minting
// =========================================================================================

describe("device approve (§2.2)", () => {
  it("mints a 5-minute single-use code 'dac-<id>.<secret>'", async () => {
    const h = makeHarness();
    const res = await approve(h);
    expect(res.code).toMatch(/^dac-[0-9a-f-]+\.[A-Za-z0-9_-]{43}$/);
    expect(res.expiresInSeconds).toBe(300);
    // The stored row binds account + challenge and hashes the secret (never plaintext).
    const row = [...h.store.codes.values()][0];
    expect(row.accountId).toBe("acc-1");
    expect(row.codeChallenge).toBe(await computeS256Challenge(VERIFIER));
    expect(res.code).not.toContain(row.secretHash);
    expect(row.expiresAt).toBe(h.clock.now + DEVICE_CODE_TTL_MS);
  });

  it("rejects any codeChallengeMethod except the literal 'S256' (bad_method)", async () => {
    const h = makeHarness();
    for (const method of ["plain", "s256", "S512", "", undefined]) {
      await expectDeviceError(
        approveDevice(h.deps, { accountId: "acc-1", userId: "usr-1", orgId: "org1" }, {
          codeChallenge: await computeS256Challenge(VERIFIER),
          codeChallengeMethod: method,
          deviceName: "Mac",
        }),
        "bad_method",
        400,
      );
    }
  });

  it("rejects a malformed challenge: too short, too long, or non-base64url (bad_challenge)", async () => {
    const h = makeHarness();
    const bad = [
      "tooshort",
      "a".repeat(42), // one under the RFC 7636 minimum
      "a".repeat(129), // one over the maximum
      `${"a".repeat(42)}+`, // '+' is base64, not base64url
      `${"a".repeat(42)}=`, // padding is not allowed
      42,
      null,
    ];
    for (const challenge of bad) {
      await expectDeviceError(
        approveDevice(h.deps, { accountId: "acc-1", userId: "usr-1", orgId: "org1" }, {
          codeChallenge: challenge,
          codeChallengeMethod: "S256",
          deviceName: "Mac",
        }),
        "bad_challenge",
        400,
      );
    }
    // …and exactly 43 / 128 chars are accepted (boundary check).
    for (const ok of ["a".repeat(43), "a".repeat(128)]) {
      const res = await approveDevice(h.deps, { accountId: "acc-1", userId: "usr-1", orgId: "org1" }, {
        codeChallenge: ok,
        codeChallengeMethod: "S256",
        deviceName: "Mac",
      });
      expect(res.code).toMatch(/^dac-/);
    }
  });

  it("rejects an empty / whitespace / over-64-char device name (bad_device_name); strips control chars", async () => {
    const h = makeHarness();
    for (const name of ["", "   ", "x".repeat(65), 7, undefined, "\u0007\u0008"]) {
      await expectDeviceError(
        approveDevice(h.deps, { accountId: "acc-1", userId: "usr-1", orgId: "org1" }, {
          codeChallenge: await computeS256Challenge(VERIFIER),
          codeChallengeMethod: "S256",
          deviceName: name,
        }),
        "bad_device_name",
        400,
      );
    }
    await approveDevice(h.deps, { accountId: "acc-1", userId: "usr-1", orgId: "org1" }, {
      codeChallenge: await computeS256Challenge(VERIFIER),
      codeChallengeMethod: "S256",
      deviceName: "Josh's\u0000 MacBook\u001b Pro", // control chars stripped, not fatal
    });
    const row = [...h.store.codes.values()].at(-1)!;
    expect(row.deviceName).toBe("Josh's MacBook Pro");
  });
});

// =========================================================================================
// §2.3 exchange — PKCE verification + single use + expiry
// =========================================================================================

describe("device code exchange (§2.3)", () => {
  it("happy path: code + verifier → device session + access JWS (jti == session id, fresh role scopes)", async () => {
    const h = makeHarness("standard");
    const { code } = await approve(h);
    const res = await exchangeDeviceCode(h.deps, { codeHandle: code, codeVerifier: VERIFIER });

    expect(res.refreshToken).toMatch(/^dvt-dev-[0-9a-f-]+\.[A-Za-z0-9_-]{43}$/);
    expect(res.accessTtlSeconds).toBe(900);
    expect(res.session.deviceName).toBe("Test MacBook Pro");
    expect(res.session.expiresAt).toBe(h.clock.now + DEVICE_SESSION_LIFETIME_MS);

    const principal = await verifyToken(SIGNING_SECRET, res.accessToken, {}, h.clock.now);
    expect(principal.jti).toBe(res.session.id);
    expect(principal.sub).toBe("usr-1");
    expect(principal.type).toBe("session");
    expect(principal.orgId).toBe("org1");
    expect(principal.scopes).toEqual(scopesForRole("standard"));
  });

  it("a code is SINGLE-USE: the second exchange gets invalid_code", async () => {
    const h = makeHarness();
    const { code } = await approve(h);
    await exchangeDeviceCode(h.deps, { codeHandle: code, codeVerifier: VERIFIER });
    await expectDeviceError(
      exchangeDeviceCode(h.deps, { codeHandle: code, codeVerifier: VERIFIER }),
      "invalid_code",
      400,
    );
  });

  it("an expired code is refused with the SAME opaque invalid_code", async () => {
    const h = makeHarness();
    const { code } = await approve(h);
    h.clock.now += DEVICE_CODE_TTL_MS + 1;
    await expectDeviceError(
      exchangeDeviceCode(h.deps, { codeHandle: code, codeVerifier: VERIFIER }),
      "invalid_code",
      400,
    );
  });

  it("a wrong code secret is refused (invalid_code) — and that attempt burns the code", async () => {
    const h = makeHarness();
    const { code } = await approve(h);
    const [id] = code.split(".");
    await expectDeviceError(
      exchangeDeviceCode(h.deps, { codeHandle: `${id}.${"x".repeat(43)}`, codeVerifier: VERIFIER }),
      "invalid_code",
    );
    // consume-first: even the failed attempt destroyed it.
    await expectDeviceError(
      exchangeDeviceCode(h.deps, { codeHandle: code, codeVerifier: VERIFIER }),
      "invalid_code",
    );
  });

  it("a PKCE mismatch is pkce_mismatch AND burns the code (a later correct verifier is too late)", async () => {
    const h = makeHarness();
    const { code } = await approve(h);
    await expectDeviceError(
      exchangeDeviceCode(h.deps, { codeHandle: code, codeVerifier: "B".repeat(43) }),
      "pkce_mismatch",
      400,
    );
    await expectDeviceError(
      exchangeDeviceCode(h.deps, { codeHandle: code, codeVerifier: VERIFIER }),
      "invalid_code", // deliberately: the failed PKCE attempt destroyed the code (§5.1)
    );
  });

  it("verifier length bounds: <43 or >128 chars is pkce_mismatch (still burns)", async () => {
    const h = makeHarness();
    for (const verifier of ["a".repeat(42), "a".repeat(129), 9, undefined]) {
      const { code } = await approve(h);
      await expectDeviceError(
        exchangeDeviceCode(h.deps, { codeHandle: code, codeVerifier: verifier }),
        "pkce_mismatch",
        400,
      );
    }
  });

  it("a suspended account cannot exchange (account_inactive)", async () => {
    const h = makeHarness();
    const { code } = await approve(h);
    h.account.status = "suspended";
    await expectDeviceError(
      exchangeDeviceCode(h.deps, { codeHandle: code, codeVerifier: VERIFIER }),
      "account_inactive",
      401,
    );
  });

  it("garbage handles collapse to invalid_code (no shape oracle)", async () => {
    const h = makeHarness();
    for (const handle of ["", "dac-x", "nodot", "svc-1.abc", ".leading", "trailing.", 5, null]) {
      await expectDeviceError(
        exchangeDeviceCode(h.deps, { codeHandle: handle, codeVerifier: VERIFIER }),
        "invalid_code",
      );
    }
  });
});

// =========================================================================================
// §2.4 refresh — the rotation state machine
// =========================================================================================

async function freshSession(h: Harness) {
  const { code } = await approve(h);
  return exchangeDeviceCode(h.deps, { codeHandle: code, codeVerifier: VERIFIER });
}

describe("device refresh rotation (§2.4)", () => {
  it("rotates on use: new refresh token, new access JWS, counter bumped, lastSeen advanced", async () => {
    const h = makeHarness();
    const first = await freshSession(h);
    h.clock.now += 60 * 60 * 1000; // an hour later
    const second = await refreshDeviceSession(h.deps, { refreshHandle: first.refreshToken });
    expect(second.refreshToken).not.toBe(first.refreshToken);
    expect(second.session.rotationCounter).toBe(1);
    expect(second.session.lastSeenAt).toBe(h.clock.now);
    const principal = await verifyToken(SIGNING_SECRET, second.accessToken, {}, h.clock.now);
    expect(principal.jti).toBe(first.session.id); // same session, same jti
  });

  it("SLIDES the expiry: every rotation re-arms now+400d", async () => {
    const h = makeHarness();
    const first = await freshSession(h);
    const initialExpiry = first.session.expiresAt;
    h.clock.now += 30 * 24 * 60 * 60 * 1000; // 30 days later
    const second = await refreshDeviceSession(h.deps, { refreshHandle: first.refreshToken });
    expect(second.session.expiresAt).toBe(h.clock.now + DEVICE_SESSION_LIFETIME_MS);
    expect(second.session.expiresAt).toBeGreaterThan(initialExpiry);
  });

  it("prev-secret WITHIN the 60s grace re-rotates (lost-response retry race) — no revocation", async () => {
    const h = makeHarness();
    const first = await freshSession(h);
    h.clock.now += 1000;
    await refreshDeviceSession(h.deps, { refreshHandle: first.refreshToken }); // rotation; response "lost"
    h.clock.now += REFRESH_ROTATION_GRACE_MS - 2000; // still inside the grace window
    const retry = await refreshDeviceSession(h.deps, { refreshHandle: first.refreshToken });
    expect(retry.refreshToken).not.toBe(first.refreshToken);
    const row = await h.store.getDeviceSession(first.session.id);
    expect(row!.revokedAt).toBeNull();
    expect(row!.rotationCounter).toBe(2);
    // …and the retry's NEW token keeps working.
    h.clock.now += 1000;
    await refreshDeviceSession(h.deps, { refreshHandle: retry.refreshToken });
  });

  it("prev-secret AFTER the grace ⇒ reuse detected ⇒ the WHOLE session is revoked (refresh_reused)", async () => {
    const h = makeHarness();
    const first = await freshSession(h);
    h.clock.now += 1000;
    const second = await refreshDeviceSession(h.deps, { refreshHandle: first.refreshToken });
    h.clock.now += REFRESH_ROTATION_GRACE_MS + 1000; // grace passed
    await expectDeviceError(
      refreshDeviceSession(h.deps, { refreshHandle: first.refreshToken }),
      "refresh_reused",
      401,
    );
    // Both the thief's and the victim's copies are dead: the CURRENT token is refused too.
    const row = await h.store.getDeviceSession(first.session.id);
    expect(row!.revokedAt).not.toBeNull();
    expect(row!.revokeReason).toBe("refresh_reuse");
    await expectDeviceError(
      refreshDeviceSession(h.deps, { refreshHandle: second.refreshToken }),
      "device_revoked",
      401,
    );
  });

  it("an unknown secret on a live session is invalid_refresh (no rotation, no revocation)", async () => {
    const h = makeHarness();
    const first = await freshSession(h);
    await expectDeviceError(
      refreshDeviceSession(h.deps, { refreshHandle: `dvt-${first.session.id}.${"z".repeat(43)}` }),
      "invalid_refresh",
      401,
    );
    const row = await h.store.getDeviceSession(first.session.id);
    expect(row!.revokedAt).toBeNull();
    expect(row!.rotationCounter).toBe(0);
  });

  it("a revoked session refuses with device_revoked; an expired one with device_expired", async () => {
    const h = makeHarness();
    const first = await freshSession(h);
    await h.store.revokeDeviceSession(first.session.id, "user_revoked", h.clock.now);
    await expectDeviceError(
      refreshDeviceSession(h.deps, { refreshHandle: first.refreshToken }),
      "device_revoked",
      401,
    );

    const h2 = makeHarness();
    const s2 = await freshSession(h2);
    h2.clock.now += DEVICE_SESSION_LIFETIME_MS + 1; // 400 days of silence
    await expectDeviceError(
      refreshDeviceSession(h2.deps, { refreshHandle: s2.refreshToken }),
      "device_expired",
      401,
    );
  });

  it("scopes are RECOMPUTED from the live role on every rotation (role change propagates)", async () => {
    const h = makeHarness("standard");
    const first = await freshSession(h);
    expect((await verifyToken(SIGNING_SECRET, first.accessToken, {}, h.clock.now)).scopes)
      .toEqual(scopesForRole("standard"));
    h.account.role = "admin"; // promoted
    h.clock.now += 1000;
    const second = await refreshDeviceSession(h.deps, { refreshHandle: first.refreshToken });
    expect((await verifyToken(SIGNING_SECRET, second.accessToken, {}, h.clock.now)).scopes)
      .toEqual(scopesForRole("admin"));
    expect(second.session.scopes).toEqual(scopesForRole("admin")); // persisted too
  });

  it("a suspended account ⇒ account_inactive, session REVOKED, and NO rotation", async () => {
    const h = makeHarness();
    const first = await freshSession(h);
    h.account.status = "suspended";
    h.clock.now += 1000;
    await expectDeviceError(
      refreshDeviceSession(h.deps, { refreshHandle: first.refreshToken }),
      "account_inactive",
      401,
    );
    const row = await h.store.getDeviceSession(first.session.id);
    expect(row!.revokedAt).not.toBeNull();
    expect(row!.revokeReason).toBe("account_inactive");
    expect(row!.rotationCounter).toBe(0); // the rotation was NOT persisted
  });

  it("malformed refresh handles collapse to invalid_refresh", async () => {
    const h = makeHarness();
    for (const handle of ["", "dvt-", "nodot", "dac-1.abc", 5, null, "dvt-dev-unknown.aaaa"]) {
      await expectDeviceError(refreshDeviceSession(h.deps, { refreshHandle: handle }), "invalid_refresh", 401);
    }
  });
});
