// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import type { Env } from "../src/env";
import { hashPassword, verifyPassword } from "../src/security/auth-password";
import type { DeviceCodeRecord, DeviceSessionRecord } from "../src/security/auth-device";

const bindings = env as Env;

describe("password replacement authorization boundary", () => {
  it("retires browser/device credentials and rejects completions admitted before replacement", async () => {
    const orgId = `retire-${crypto.randomUUID()}`, auth = bindings.AUTH_DO.getByName(orgId);
    const account = await auth.createAccount({ orgId, userId: "user", email: "owner@example.test", displayName: "Owner", role: "owner", emailVerified: true });
    const oldPassword = await hashPassword(account.id, "old correct password", { cost: { N: 2 } });
    await auth.putPassword(oldPassword);
    const t = Date.now(), session = { accountId: account.id, userId: account.userId, orgId, scopes: ["fs:read" as const],
      csrfToken: "csrf", expiresAt: t + 60_000, authEpoch: 0 };
    const kept = await auth.createSession(session), other = await auth.createSession(session);
    const code: DeviceCodeRecord = { id: "code", accountId: account.id, userId: account.userId, orgId,
      secretHash: "secret", codeChallenge: "challenge", deviceName: "Mac", deviceModel: null,
      createdAt: t, expiresAt: t + 60_000, consumedAt: null, authEpoch: 0 };
    await auth.createDeviceCode(code);
    const device: DeviceSessionRecord = { id: "device", accountId: account.id, userId: account.userId, orgId,
      scopes: ["fs:read"], deviceName: "Mac", deviceModel: null, refreshHash: "refresh", prevRefreshHash: null,
      prevGraceUntil: null, rotationCounter: 0, createdAt: t, lastSeenAt: t, expiresAt: t + 60_000,
      revokedAt: null, revokeReason: null, authEpoch: 0 };
    await auth.createDeviceSession(device);
    const token = { id: "daemon", orgId, userId: account.userId, label: "daemon", scopes: ["fs:read" as const],
      spaceId: null, hashedSecret: "hash", createdByUserId: account.userId, createdAt: t, lastUsedAt: null,
      expiresAt: t + 60_000, revoked: false, deviceSessionId: device.id };
    await auth.createServiceToken(token);
    await auth.createServiceToken({ ...token, id: "automation", deviceSessionId: null });
    await auth.putChallenge({ id: "mfa", accountId: account.id, purpose: "login_mfa", value: orgId,
      expiresAt: t + 60_000, authEpoch: 0 });
    const replacement = await hashPassword(account.id, "new correct password", { cost: { N: 2 } });
    const retired = await auth.replacePasswordAndRetireSessions(replacement, 0, kept.id);
    expect(new Set(retired)).toEqual(new Set([other.id, device.id, token.id]));
    expect((await auth.getSession(kept.id))?.revokedAt).toBeNull();
    expect(await auth.isJtiRevoked(other.id)).toBe(true);
    expect(await auth.isJtiRevoked(device.id)).toBe(true);
    expect(await auth.isJtiRevoked(token.id)).toBe(true);
    expect(await auth.isJtiRevoked("automation")).toBe(false);
    expect(await auth.consumeDeviceCode(code.id, t + 1)).toBeNull();
    expect(await auth.takeChallenge("mfa")).toBeNull();
    const rejected = await runInDurableObject(auth, async instance => {
      const caught = async (op: () => Promise<unknown>) => { try { await op(); return "accepted"; } catch (e) { return (e as Error).message; } };
      return Promise.all([
        caught(() => instance.createSession(session)),
        caught(() => instance.createDeviceCode({ ...code, id: "late-code" })),
        caught(() => instance.createDeviceSession({ ...device, id: "late-device" })),
        caught(() => instance.putChallenge({ id: "late-mfa", accountId: account.id, purpose: "login_mfa", value: orgId,
          expiresAt: t + 60_000, authEpoch: 0 })),
        caught(() => instance.putPasswordAtEpoch(oldPassword, 0)),
        caught(() => instance.createServiceToken({ ...token, id: "late-token" })),
      ]);
    });
    expect(rejected).toEqual(["authentication_changed", "authentication_changed", "authentication_changed",
      "authentication_changed", "authentication_changed", "device_revoked"]);
    expect(await auth.rotateDeviceSession(device.id, { refreshHash: "late", prevRefreshHash: "refresh",
      prevGraceUntil: t + 1000, scopes: ["fs:read"], lastSeenAt: t, expiresAt: t + 60_000 })).toBe(false);
    expect(await verifyPassword((await auth.getPassword(account.id))!, "new correct password")).toBe(true);
    expect((await auth.getAccount(account.id))?.authEpoch).toBe(1);
    expect((await auth.createSession({ ...session, authEpoch: 1 })).revokedAt).toBeNull();
    expect(await runInDurableObject(auth, instance => {
      try { instance.replacePasswordAndRetireSessions(oldPassword, 0); return "accepted"; }
      catch (e) { return (e as Error).message; }
    })).toBe("authentication_changed");
    expect(await verifyPassword((await auth.getPassword(account.id))!, "new correct password")).toBe(true);
  });

  it("upgrades an existing v2 auth database without replacing accounts or live sessions", async () => {
    const orgId = `auth-upgrade-${crypto.randomUUID()}`, auth = bindings.AUTH_DO.getByName(orgId);
    const account = await auth.createAccount({ orgId, userId: "user", email: "owner@example.test", displayName: "Owner", role: "owner" });
    const session = await auth.createSession({ accountId: account.id, userId: account.userId, orgId,
      scopes: ["fs:read"], csrfToken: "csrf", expiresAt: Date.now() + 60_000 });
    await runInDurableObject(auth, (instance, state) => {
      state.storage.sql.exec("ALTER TABLE accounts DROP COLUMN auth_epoch;");
      state.storage.sql.exec("ALTER TABLE accounts DROP COLUMN legacy_enrollment_pending;");
      state.storage.sql.exec("ALTER TABLE device_codes DROP COLUMN auth_epoch;");
      state.storage.sql.exec("ALTER TABLE challenges DROP COLUMN auth_epoch;");
      state.storage.sql.exec("ALTER TABLE sessions DROP COLUMN auth_epoch;");
      state.storage.sql.exec("DELETE FROM _schema_migrations WHERE id >= 3;");
      instance["migrate"]();
      instance["migrate"]();
    });
    expect((await auth.readiness()).schemaVersion).toBe(5);
    expect((await auth.getAccount(account.id))?.authEpoch).toBe(0);
    expect(await auth.getSession(session.id)).toEqual(session);
  });

  it("repairs an already-applied v3 database while preserving only its retained live session generation", async () => {
    const orgId = `auth-v3-${crypto.randomUUID()}`, auth = bindings.AUTH_DO.getByName(orgId);
    const account = await auth.createAccount({ orgId, userId: "user", email: "owner@example.test", displayName: "Owner", role: "owner" });
    const args = { accountId: account.id, userId: account.userId, orgId, scopes: ["fs:read" as const], csrfToken: "csrf", expiresAt: Date.now() + 60_000 };
    const kept = await auth.createSession(args), retired = await auth.createSession(args);
    const password = await hashPassword(account.id, "new correct password", { cost: { N: 2 } });
    await auth.replacePasswordAndRetireSessions(password, 0, kept.id);
    await runInDurableObject(auth, (instance, state) => {
      state.storage.sql.exec("ALTER TABLE sessions DROP COLUMN auth_epoch;");
      state.storage.sql.exec("ALTER TABLE accounts DROP COLUMN legacy_enrollment_pending;");
      state.storage.sql.exec("DELETE FROM _schema_migrations WHERE id >= 4;");
      instance["migrate"]();
      instance["migrate"]();
    });
    expect((await auth.getSession(kept.id))?.authEpoch).toBe(1);
    expect((await auth.getSession(kept.id))?.revokedAt).toBeNull();
    expect((await auth.getSession(retired.id))?.authEpoch).toBe(0);
    expect(await auth.isJtiRevoked(retired.id)).toBe(true);
  });

  it("binds verification and reset completion to the current email even after a token was consumed", async () => {
    const orgId = `email-bind-${crypto.randomUUID()}`, auth = bindings.AUTH_DO.getByName(orgId);
    const account = await auth.createAccount({ orgId, userId: "user", email: "old@example.test", displayName: "Owner", role: "owner" });
    const password = await hashPassword(account.id, "original correct password", { cost: { N: 2 } });
    await auth.putPassword(password);
    const now = Date.now();
    await auth.putEmailToken({ id: "pending", orgId, accountId: account.id, email: account.email,
      purpose: "password_reset", tokenHash: "hash", createdAt: now, expiresAt: now + 60_000, consumedAt: null });
    await auth.setAccountProfile(account.id, { email: "new@example.test" });
    expect(await auth.consumeEmailToken("pending", now)).toBe(false);
    expect(await auth.confirmEmailAddress(account.id, "old@example.test")).toBe(false);
    expect((await auth.getAccount(account.id))?.emailVerified).toBe(false);
    expect(await runInDurableObject(auth, instance => {
      try { instance.replacePasswordAndRetireSessions(password, 0, undefined, "old@example.test"); return "accepted"; }
      catch (e) { return (e as Error).message; }
    })).toBe("authentication_changed");
    expect((await auth.getAccount(account.id))?.authEpoch).toBe(0);
    expect(await auth.confirmEmailAddress(account.id, "new@example.test")).toBe(true);
  });
});
