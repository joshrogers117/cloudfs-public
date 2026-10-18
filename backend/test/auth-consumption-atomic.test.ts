// SPDX-License-Identifier: AGPL-3.0-or-later
import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import type { Env } from "../src/env";
import { authStoresFor } from "../src/auth-stores";
import { base32Encode, totp, verifyLoginTotp } from "../src/security/auth-totp";

const bindings = env as Env;

describe("AuthDO single-use artifacts", () => {
  it("confirms one enrollment and preserves its recovery codes against stale enrollment/confirmation", async () => {
    const auth = bindings.AUTH_DO.getByName(`enroll-${crypto.randomUUID()}`), now = Date.now();
    const pending = { accountId: "account", secret: "original", confirmed: false, createdAt: now, confirmedAt: null };
    expect(await auth.beginTotpEnrollment(pending)).toBe(true);
    const results = await Promise.all([
      auth.completeTotpEnrollment("account", "original", now, 100, now + 60_000, ["first-recovery"]),
      auth.completeTotpEnrollment("account", "original", now, 100, now + 60_000, ["second-recovery"]),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await auth.beginTotpEnrollment({ ...pending, secret: "stale-overwrite" })).toBe(false);
    expect((await auth.getTotp("account"))?.secret).toBe("original");
    const winner = results[0] ? "first-recovery" : "second-recovery";
    expect(await auth.consumeRecoveryCode("account", winner, now)).toBe(true);
    expect(await auth.consumeRecoveryCode("account", results[0] ? "second-recovery" : "first-recovery", now)).toBe(false);
    expect(await auth.claimTotpStep("account", "original", 100, now + 60_000)).toBe(false);
    await auth.deleteTotp("account");
    expect(await auth.beginTotpEnrollment({ ...pending, secret: "replacement" })).toBe(true);
    expect(await auth.completeTotpEnrollment("account", "original", now, 101, now + 60_000, ["stale-code"])).toBe(false);
    expect((await auth.getTotp("account"))?.confirmed).toBe(false);
  });
  it("accepts one TOTP completion while concurrent and later replays remain denied", async () => {
    const orgId = `totp-${crypto.randomUUID()}`, auth = bindings.AUTH_DO.getByName(orgId);
    const now = Date.now(), bytes = new TextEncoder().encode("12345678901234567890");
    await auth.putTotp({ accountId: "account", secret: base32Encode(bytes), confirmed: true, createdAt: now, confirmedAt: now });
    const store = authStoresFor(bindings, orgId).credentials;
    const code = totp(bytes, Math.floor(now / 1000));
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => verifyLoginTotp("account", code, { store, now: () => now })));
    expect(results.filter(r => r.status === "fulfilled")).toHaveLength(1);
    await expect(verifyLoginTotp("account", code, { store, now: () => now })).rejects.toMatchObject({ code: "code_replayed" });
  });
  it("consumes an email token exactly once even when all callers share the same millisecond", async () => {
    const orgId = `consume-${crypto.randomUUID()}`;
    const auth = bindings.AUTH_DO.getByName(orgId);
    const now = Date.now();
    await auth.putEmailToken({ id: "token", orgId, accountId: "account", email: "owner@example.test",
      purpose: "password_reset", tokenHash: "hash", createdAt: now, expiresAt: now + 60_000, consumedAt: null });
    const results = await Promise.all(Array.from({ length: 8 }, () => auth.consumeEmailToken("token", now)));
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await auth.consumeEmailToken("token", now)).toBe(false);
  });

  it("consumes a recovery code exactly once for simultaneous MFA completions", async () => {
    const auth = bindings.AUTH_DO.getByName(`recovery-${crypto.randomUUID()}`);
    const now = Date.now();
    await auth.putRecoveryCodes("account", ["hash"]);
    const results = await Promise.all(Array.from({ length: 8 }, () => auth.consumeRecoveryCode("account", "hash", now)));
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await auth.consumeRecoveryCode("account", "hash", now)).toBe(false);
  });
});
