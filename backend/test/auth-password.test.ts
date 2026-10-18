// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
  hashPassword,
  verifyPassword,
  needsRehash,
  setPassword,
  changePassword,
  resetPassword,
  verifyAccountPassword,
  timingSafeEqual,
  scryptCostFromEnv,
  isPasswordBreached,
  assertPasswordNotBreached,
  SCRYPT_PARAMS,
  SALT_BYTES,
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
  PasswordError,
  passwordCodec,
  type PasswordCredential,
  type PasswordStore,
} from "../src/security/auth-password";

// Cheap scrypt cost for fast, deterministic tests. We never test the *strength* of scrypt —
// only that params round-trip and verification is correct/constant-time-shaped. The frozen
// production default (N=32768) is exercised once, separately, to prove it works at all.
const FAST = { N: 8, r: 1, p: 1, dkLen: 32 } as const;

/// Minimal in-memory CredentialStore (password subset) for deterministic unit tests.
class FakePasswordStore implements PasswordStore {
  private rows = new Map<string, PasswordCredential>();
  async getPassword(accountId: string): Promise<PasswordCredential | null> {
    return this.rows.get(accountId) ?? null;
  }
  async putPassword(cred: PasswordCredential): Promise<void> {
    this.rows.set(cred.accountId, { ...cred });
  }
  async deletePassword(accountId: string): Promise<void> {
    this.rows.delete(accountId);
  }
}

describe("hashPassword + verifyPassword (round trip)", () => {
  it("hashes into a self-describing credential and verifies the right password", async () => {
    const cred = await hashPassword("acc-1", "correct horse battery", { cost: FAST, now: 1000 });
    expect(cred.accountId).toBe("acc-1");
    expect(cred.algo).toBe("scrypt");
    expect(cred.N).toBe(FAST.N);
    expect(cred.r).toBe(FAST.r);
    expect(cred.p).toBe(FAST.p);
    expect(cred.dkLen).toBe(FAST.dkLen);
    expect(cred.updatedAt).toBe(1000);
    // salt is base64url of SALT_BYTES bytes; hash is base64url of dkLen bytes
    expect(passwordCodec.b64urlDecode(cred.salt).length).toBe(SALT_BYTES);
    expect(passwordCodec.b64urlDecode(cred.hash).length).toBe(FAST.dkLen);

    expect(await verifyPassword(cred, "correct horse battery")).toBe(true);
  });

  it("rejects the wrong password", async () => {
    const cred = await hashPassword("acc-1", "right-password-1", { cost: FAST });
    expect(await verifyPassword(cred, "wrong-password-1")).toBe(false);
  });

  it("rejects an empty password without matching anything", async () => {
    const cred = await hashPassword("acc-1", "some-password-x", { cost: FAST });
    expect(await verifyPassword(cred, "")).toBe(false);
  });

  it("uses a fresh random salt per hash (two hashes of same password differ)", async () => {
    const a = await hashPassword("acc-1", "same-password-yy", { cost: FAST });
    const b = await hashPassword("acc-1", "same-password-yy", { cost: FAST });
    expect(a.salt).not.toBe(b.salt);
    expect(a.hash).not.toBe(b.hash);
    // ...but both still verify
    expect(await verifyPassword(a, "same-password-yy")).toBe(true);
    expect(await verifyPassword(b, "same-password-yy")).toBe(true);
  });

  it("verifies using the credential's OWN stored params, not the global default", async () => {
    // Hash at FAST cost; ensure verify re-derives at N=8 (not the frozen 32768) and matches.
    const cred = await hashPassword("acc-1", "param-bound-pw", { cost: FAST });
    expect(cred.N).toBe(FAST.N);
    expect(await verifyPassword(cred, "param-bound-pw")).toBe(true);
    // Tampering with the stored params breaks verification (proves params are load-bearing).
    const tampered: PasswordCredential = { ...cred, N: 16 };
    expect(await verifyPassword(tampered, "param-bound-pw")).toBe(false);
  });

  // Full-strength scrypt (N=2^17) is intentionally CPU-heavy; give it a generous timeout so the
  // smoke test isn't flaky under the workerd test pool. (The other tests use a tiny FAST cost.)
  it("works at the frozen production scrypt params (smoke)", async () => {
    const cred = await hashPassword("acc-prod", "prod-strength-password");
    expect(cred.N).toBe(SCRYPT_PARAMS.N);
    expect(cred.r).toBe(SCRYPT_PARAMS.r);
    expect(cred.p).toBe(SCRYPT_PARAMS.p);
    expect(cred.dkLen).toBe(SCRYPT_PARAMS.dkLen);
    expect(await verifyPassword(cred, "prod-strength-password")).toBe(true);
    expect(await verifyPassword(cred, "prod-strength-passwerd")).toBe(false);
  }, 30_000);

  it("throws on an unsupported algo in the stored credential", async () => {
    const cred = await hashPassword("acc-1", "algo-test-pwxx", { cost: FAST });
    const bad = { ...cred, algo: "bcrypt" as unknown as "scrypt" };
    await expect(verifyPassword(bad, "algo-test-pwxx")).rejects.toBeInstanceOf(PasswordError);
  });
});

describe("password policy", () => {
  it("rejects passwords shorter than the minimum", async () => {
    const short = "a".repeat(MIN_PASSWORD_LENGTH - 1);
    await expect(hashPassword("acc-1", short, { cost: FAST })).rejects.toMatchObject({
      code: "weak_password",
      status: 400,
    });
  });

  it("accepts a password exactly at the minimum length", async () => {
    const exact = "a".repeat(MIN_PASSWORD_LENGTH);
    const cred = await hashPassword("acc-1", exact, { cost: FAST });
    expect(await verifyPassword(cred, exact)).toBe(true);
  });

  it("rejects an over-long password at hash time", async () => {
    const huge = "a".repeat(MAX_PASSWORD_LENGTH + 1);
    await expect(hashPassword("acc-1", huge, { cost: FAST })).rejects.toMatchObject({
      code: "password_too_long",
    });
  });

  it("verify returns false (never throws) for an over-long candidate", async () => {
    const cred = await hashPassword("acc-1", "normal-length-pw", { cost: FAST });
    expect(await verifyPassword(cred, "a".repeat(MAX_PASSWORD_LENGTH + 1))).toBe(false);
  });
});

describe("needsRehash", () => {
  it("flags a credential weaker than the target cost", async () => {
    const weak = await hashPassword("acc-1", "rehash-me-please", { cost: { N: 8, r: 8, p: 1, dkLen: 32 } });
    // default target is the frozen N=2^15=32768, so N=8 must need a rehash
    expect(needsRehash(weak)).toBe(true);
  });

  it("does not flag a credential already at the target", async () => {
    const strong = await hashPassword("acc-1", "rehash-me-please", { cost: FAST });
    expect(needsRehash(strong, FAST)).toBe(false);
  });

  it("flags a non-scrypt credential", () => {
    const cred = {
      accountId: "acc-1",
      algo: "argon2" as unknown as "scrypt",
      N: 99999,
      r: 8,
      p: 1,
      dkLen: 32,
      salt: "x",
      hash: "y",
      updatedAt: 0,
    };
    expect(needsRehash(cred, FAST)).toBe(true);
  });

  it("flags when r/p/dkLen differ from target even if N is fine", async () => {
    const cred = await hashPassword("acc-1", "rehash-me-please", { cost: { N: 8, r: 2, p: 1, dkLen: 32 } });
    expect(needsRehash(cred, { N: 8, r: 1, p: 1, dkLen: 32 })).toBe(true);
  });
});

describe("scrypt cost — workerd-safe default + env override", () => {
  it("the frozen default is N=2^15 (32768), r=8, p=1, dkLen=32 (audit B14: under the 128 MB cap)", () => {
    expect(SCRYPT_PARAMS.N).toBe(2 ** 15);
    expect(SCRYPT_PARAMS.N).toBe(32768);
    expect(SCRYPT_PARAMS.r).toBe(8);
    expect(SCRYPT_PARAMS.p).toBe(1);
    expect(SCRYPT_PARAMS.dkLen).toBe(32);
  });

  it("a new hash (no cost override) uses the 2^15 default", async () => {
    const cred = await hashPassword("acc-new", "fresh-default-pw");
    expect(cred.N).toBe(2 ** 15);
  }, 30_000);

  it("a HIGHER-cost (2^17) hash from the prior default still verifies and is NOT downgraded", async () => {
    // A credential hashed under the PRIOR (stronger) default (N=2^17=131072) must still verify
    // with its own stored params. needsRehash only flags WEAKER-than-target hashes (cred.N < N),
    // so a stronger hash is LEFT ALONE — lowering the default never weakens an existing credential.
    const old = await hashPassword("acc-old", "legacy-cost-pw", { cost: { N: 2 ** 17, r: 8, p: 1, dkLen: 32 } });
    expect(old.N).toBe(131072);
    expect(await verifyPassword(old, "legacy-cost-pw")).toBe(true);
    expect(needsRehash(old)).toBe(false); // stronger than the new default ⇒ not re-hashed (no downgrade)
  }, 60_000);

  it("a WEAKER (2^14) hash is flagged for upgrade to the 2^15 default", async () => {
    const weak = await hashPassword("acc-weak", "weak-cost-pw", { cost: { N: 2 ** 14, r: 8, p: 1, dkLen: 32 } });
    expect(weak.N).toBe(16384);
    expect(needsRehash(weak)).toBe(true); // 2^14 < 2^15 target ⇒ upgrade on next login
  }, 30_000);

  it("scryptCostFromEnv: SCRYPT_COST_N overrides N (power of two)", () => {
    expect(scryptCostFromEnv({ SCRYPT_COST_N: "65536" })).toEqual({ N: 65536 });
    expect(scryptCostFromEnv({ SCRYPT_COST_N: "262144" })).toEqual({ N: 2 ** 18 });
  });

  it("scryptCostFromEnv: ignores missing / blank / non-numeric / non-power-of-two / out-of-range", () => {
    expect(scryptCostFromEnv({})).toBeUndefined();
    expect(scryptCostFromEnv({ SCRYPT_COST_N: "" })).toBeUndefined();
    expect(scryptCostFromEnv({ SCRYPT_COST_N: "  " })).toBeUndefined();
    expect(scryptCostFromEnv({ SCRYPT_COST_N: "notanumber" })).toBeUndefined();
    expect(scryptCostFromEnv({ SCRYPT_COST_N: "100000" })).toBeUndefined(); // not a power of two
    expect(scryptCostFromEnv({ SCRYPT_COST_N: "1" })).toBeUndefined(); // below min
    expect(scryptCostFromEnv({ SCRYPT_COST_N: String(2 ** 23) })).toBeUndefined(); // above cap
  });

  it("env override is respected by hashPassword via the resolved cost", async () => {
    const cost = scryptCostFromEnv({ SCRYPT_COST_N: "16" }); // tiny but valid power of two (fast)
    expect(cost).toEqual({ N: 16 });
    const cred = await hashPassword("acc-env", "env-cost-pw", { cost });
    expect(cred.N).toBe(16);
    // r/p/dkLen stay frozen defaults (env only tunes N).
    expect(cred.r).toBe(SCRYPT_PARAMS.r);
    expect(cred.p).toBe(SCRYPT_PARAMS.p);
    expect(cred.dkLen).toBe(SCRYPT_PARAMS.dkLen);
  });
});

describe("breached-password check (HIBP k-anonymity)", () => {
  // SHA-1("password123") = CBFDAC6008F9CAB4083784CBD1874F76618D2A97. Prefix CBFDA, suffix C6008F9...
  const SHA1_PASSWORD123_SUFFIX = "C6008F9CAB4083784CBD1874F76618D2A97";

  it("breached → reject (isPasswordBreached true; assert throws password_breached)", async () => {
    const calls: string[] = [];
    const fakeFetch = (url: string) => {
      calls.push(String(url));
      // Range response: the offending suffix WITH a positive count, plus some noise.
      const body = `00000000000000000000000000000000000:3\r\n${SHA1_PASSWORD123_SUFFIX}:42\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1`;
      return Promise.resolve(new Response(body, { status: 200 }));
    };
    const opts = { enabled: true, fetchImpl: fakeFetch as unknown as typeof fetch, endpoint: "https://hibp.test/range/" };
    expect(await isPasswordBreached("password123", opts)).toBe(true);
    // Only the 5-char prefix is ever sent (k-anonymity): URL ends with the prefix, not the full hash.
    expect(calls[0]).toBe("https://hibp.test/range/CBFDA");
    await expect(assertPasswordNotBreached("password123", opts)).rejects.toMatchObject({
      code: "password_breached",
      status: 400,
    });
  });

  it("clean → allow (suffix absent from the range response)", async () => {
    const fakeFetch = () =>
      Promise.resolve(new Response(`00000000000000000000000000000000000:3\r\nABCDEF0123456789ABCDEF0123456789ABC:9`, { status: 200 }));
    const opts = { enabled: true, fetchImpl: fakeFetch as unknown as typeof fetch };
    expect(await isPasswordBreached("a-unique-unbreached-passphrase-xyz", opts)).toBe(false);
    await expect(assertPasswordNotBreached("a-unique-unbreached-passphrase-xyz", opts)).resolves.toBeUndefined();
  });

  it("service-down → allow (FAIL OPEN on network error and on non-2xx)", async () => {
    const throwing = () => Promise.reject(new Error("network down"));
    expect(await isPasswordBreached("password123", { enabled: true, fetchImpl: throwing as unknown as typeof fetch })).toBe(false);

    const serverError = () => Promise.resolve(new Response("oops", { status: 503 }));
    expect(await isPasswordBreached("password123", { enabled: true, fetchImpl: serverError as unknown as typeof fetch })).toBe(false);
  });

  it("flag-off → skip (never calls fetch, always allows)", async () => {
    let called = false;
    const fakeFetch = () => {
      called = true;
      return Promise.resolve(new Response(`${SHA1_PASSWORD123_SUFFIX}:42`, { status: 200 }));
    };
    // enabled omitted/false: must short-circuit BEFORE any fetch, even for a known-breached password.
    expect(await isPasswordBreached("password123", { fetchImpl: fakeFetch as unknown as typeof fetch })).toBe(false);
    expect(await isPasswordBreached("password123", { enabled: false, fetchImpl: fakeFetch as unknown as typeof fetch })).toBe(false);
    expect(called).toBe(false);
  });

  it("treats a padding row (count 0) for the matching suffix as NOT breached", async () => {
    const fakeFetch = () => Promise.resolve(new Response(`${SHA1_PASSWORD123_SUFFIX}:0`, { status: 200 }));
    expect(await isPasswordBreached("password123", { enabled: true, fetchImpl: fakeFetch as unknown as typeof fetch })).toBe(false);
  });
});

describe("setPassword / store integration", () => {
  it("persists a credential retrievable from the store", async () => {
    const store = new FakePasswordStore();
    const cred = await setPassword(store, "acc-1", "set-this-password", { cost: FAST, now: 42 });
    const got = await store.getPassword("acc-1");
    expect(got).not.toBeNull();
    expect(got!.hash).toBe(cred.hash);
    expect(got!.updatedAt).toBe(42);
    expect(await verifyPassword(got!, "set-this-password")).toBe(true);
  });

  it("replaces an existing credential (set is idempotent on accountId)", async () => {
    const store = new FakePasswordStore();
    await setPassword(store, "acc-1", "first-password-a", { cost: FAST });
    await setPassword(store, "acc-1", "second-password-b", { cost: FAST });
    const got = await store.getPassword("acc-1");
    expect(await verifyPassword(got!, "first-password-a")).toBe(false);
    expect(await verifyPassword(got!, "second-password-b")).toBe(true);
  });
});

describe("changePassword", () => {
  it("changes the password when the current one is correct", async () => {
    const store = new FakePasswordStore();
    await setPassword(store, "acc-1", "old-password-aa", { cost: FAST });
    await changePassword(store, "acc-1", "old-password-aa", "new-password-bb", { cost: FAST });
    const got = await store.getPassword("acc-1");
    expect(await verifyPassword(got!, "old-password-aa")).toBe(false);
    expect(await verifyPassword(got!, "new-password-bb")).toBe(true);
  });

  it("rejects with bad_current_password when the current password is wrong", async () => {
    const store = new FakePasswordStore();
    await setPassword(store, "acc-1", "old-password-aa", { cost: FAST });
    await expect(
      changePassword(store, "acc-1", "WRONG-current", "new-password-bb", { cost: FAST }),
    ).rejects.toMatchObject({ code: "bad_current_password", status: 401 });
    // unchanged
    const got = await store.getPassword("acc-1");
    expect(await verifyPassword(got!, "old-password-aa")).toBe(true);
  });

  it("rejects with no_password when the account has no credential", async () => {
    const store = new FakePasswordStore();
    await expect(
      changePassword(store, "acc-missing", "whatever-now", "new-password-bb", { cost: FAST }),
    ).rejects.toMatchObject({ code: "no_password", status: 401 });
  });

  it("validates the NEW password before verifying the current one (fails fast + cheap)", async () => {
    const store = new FakePasswordStore();
    await setPassword(store, "acc-1", "old-password-aa", { cost: FAST });
    // weak new password rejected even though we never check the (correct) current one
    await expect(
      changePassword(store, "acc-1", "old-password-aa", "short", { cost: FAST }),
    ).rejects.toMatchObject({ code: "weak_password" });
  });
});

describe("resetPassword", () => {
  it("sets a new password without needing the current one", async () => {
    const store = new FakePasswordStore();
    await setPassword(store, "acc-1", "forgotten-password", { cost: FAST });
    await resetPassword(store, "acc-1", "reset-to-this-pw", { cost: FAST });
    const got = await store.getPassword("acc-1");
    expect(await verifyPassword(got!, "forgotten-password")).toBe(false);
    expect(await verifyPassword(got!, "reset-to-this-pw")).toBe(true);
  });

  it("can establish a first password on an account that had none", async () => {
    const store = new FakePasswordStore();
    await resetPassword(store, "acc-new", "brand-new-password", { cost: FAST });
    const got = await store.getPassword("acc-new");
    expect(await verifyPassword(got!, "brand-new-password")).toBe(true);
  });
});

describe("verifyAccountPassword", () => {
  it("returns ok=true for the right password, with no rehash needed at matching cost", async () => {
    const store = new FakePasswordStore();
    await setPassword(store, "acc-1", "login-password-x", { cost: FAST });
    const res = await verifyAccountPassword(store, "acc-1", "login-password-x", FAST);
    expect(res.ok).toBe(true);
    expect(res.rehash).toBe(false);
  });

  it("returns ok=false for a wrong password (no throw)", async () => {
    const store = new FakePasswordStore();
    await setPassword(store, "acc-1", "login-password-x", { cost: FAST });
    const res = await verifyAccountPassword(store, "acc-1", "nope-nope-nope", FAST);
    expect(res.ok).toBe(false);
    expect(res.rehash).toBe(false);
  });

  it("signals rehash=true when the password is right but stored cost is below target", async () => {
    const store = new FakePasswordStore();
    await setPassword(store, "acc-1", "login-password-x", { cost: { N: 8, r: 8, p: 1, dkLen: 32 } });
    // target is the frozen N=32768
    const res = await verifyAccountPassword(store, "acc-1", "login-password-x");
    expect(res.ok).toBe(true);
    expect(res.rehash).toBe(true);
  });

  it("throws no_password when the account has no credential", async () => {
    const store = new FakePasswordStore();
    await expect(verifyAccountPassword(store, "acc-missing", "anything-here")).rejects.toMatchObject({
      code: "no_password",
    });
  });
});

describe("timingSafeEqual", () => {
  it("is true for identical byte arrays", () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });
  it("is false for differing arrays of equal length", () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });
  it("is false for arrays of differing length", () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2]))).toBe(false);
  });
  it("is true for two empty arrays", () => {
    expect(timingSafeEqual(new Uint8Array([]), new Uint8Array([]))).toBe(true);
  });
});

describe("base64url codec helpers", () => {
  it("round-trips arbitrary bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const s = passwordCodec.b64urlEncode(bytes);
    expect(s).not.toMatch(/[+/=]/); // url-safe, unpadded
    expect([...passwordCodec.b64urlDecode(s)]).toEqual([...bytes]);
  });
  it("randomBytes returns the requested length and varies", () => {
    const a = passwordCodec.randomBytes(16);
    const b = passwordCodec.randomBytes(16);
    expect(a.length).toBe(16);
    expect(b.length).toBe(16);
    expect([...a].join(",")).not.toBe([...b].join(","));
  });
});
