// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
  // RFC 6238 / 4226 core
  hotp,
  totp,
  timeStep,
  verifyTotpCode,
  // encoding
  base32Encode,
  base32Decode,
  timingSafeEqualBytes,
  // otpauth URI
  buildOtpauthUri,
  // recovery
  generateRecoveryCodes,
  hashRecoveryCode,
  // handlers
  enrollTotp,
  confirmTotp,
  verifyLoginTotp,
  verifyRecoveryCode,
  disableTotp,
  TotpError,
  // params
  TOTP_PERIOD_SECONDS,
  TOTP_DIGITS,
  RECOVERY_CODE_COUNT,
  RECOVERY_CODE_LENGTH,
  type TotpCredential,
  type TotpCredentialStore,
  type TotpDeps,
} from "../src/security/auth-totp";

// ---------------------------------------------------------------------------------------
// In-memory CredentialStore fake (no DO, no network). Mirrors the contract method shapes.
// ---------------------------------------------------------------------------------------

interface RecRow {
  codeHash: string;
  usedAt: number | null;
}
interface ChallRow {
  accountId: string | null;
  purpose: string;
  value: string;
  expiresAt: number;
}

class FakeStore implements TotpCredentialStore {
  totps = new Map<string, TotpCredential>();
  recovery = new Map<string, RecRow[]>();
  challenges = new Map<string, ChallRow>();

  async getTotp(accountId: string) {
    return this.totps.get(accountId) ?? null;
  }
  async putTotp(cred: TotpCredential) {
    this.totps.set(cred.accountId, { ...cred });
  }
  async confirmTotp(accountId: string, confirmedAt: number) {
    const t = this.totps.get(accountId);
    if (t) {
      t.confirmed = true;
      t.confirmedAt = confirmedAt;
    }
  }
  async deleteTotp(accountId: string) {
    this.totps.delete(accountId);
    this.recovery.delete(accountId);
  }
  async putRecoveryCodes(accountId: string, codeHashes: string[]) {
    this.recovery.set(
      accountId,
      codeHashes.map((codeHash) => ({ codeHash, usedAt: null })),
    );
  }
  async consumeRecoveryCode(accountId: string, codeHash: string, usedAt: number) {
    const rows = this.recovery.get(accountId) ?? [];
    const row = rows.find((r) => r.codeHash === codeHash && r.usedAt === null);
    if (!row) return false;
    row.usedAt = usedAt;
    return true;
  }
  beginTotpEnrollment(cred: TotpCredential): Promise<boolean> {
    if (this.totps.get(cred.accountId)?.confirmed) return Promise.resolve(false);
    this.totps.set(cred.accountId, { ...cred });
    return Promise.resolve(true);
  }
  completeTotpEnrollment(accountId: string, secret: string, confirmedAt: number, step: number,
      expiresAt: number, recoveryHashes: string[]): Promise<boolean> {
    const cred = this.totps.get(accountId);
    if (!cred || cred.confirmed || cred.secret !== secret) return Promise.resolve(false);
    cred.confirmed = true; cred.confirmedAt = confirmedAt;
    this.recovery.set(accountId, recoveryHashes.map(codeHash => ({ codeHash, usedAt: null })));
    this.challenges.set(`totp_used:${accountId}:${step}`, { accountId, purpose: "totp_used", value: String(step), expiresAt });
    return Promise.resolve(true);
  }
  claimTotpStep(accountId: string, _secret: string, step: number, expiresAt: number): Promise<boolean> {
    const id = `totp_used:${accountId}:${step}`;
    if (this.challenges.has(id)) return Promise.resolve(false);
    this.challenges.set(id, { accountId, purpose: "totp_used", value: String(step), expiresAt });
    return Promise.resolve(true);
  }
  async putChallenge(c: { id: string; accountId: string | null; purpose: string; value: string; expiresAt: number }) {
    this.challenges.set(c.id, { accountId: c.accountId, purpose: c.purpose, value: c.value, expiresAt: c.expiresAt });
  }
  async takeChallenge(id: string) {
    const c = this.challenges.get(id);
    if (!c) return null;
    this.challenges.delete(id); // single-use
    return c;
  }
}

// Deterministic byte source for reproducible secrets/recovery codes.
function seededRandom(seed: number): (n: number) => Uint8Array {
  let state = seed >>> 0;
  return (n: number) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      // xorshift32
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      out[i] = state & 0xff;
    }
    return out;
  };
}

const SECRET_ASCII = "12345678901234567890"; // RFC 6238/4226 SHA-1 seed (20 bytes)
const SECRET_BYTES = new TextEncoder().encode(SECRET_ASCII);

function depsAt(store: FakeStore, nowMs: number, rnd = seededRandom(0xC0FFEE)): TotpDeps {
  return { store, now: () => nowMs, randomBytes: rnd, issuer: "cloud-fs" };
}

// =======================================================================================
// RFC 4226 — HOTP test vectors (Appendix D, key = "12345678901234567890")
// =======================================================================================

describe("RFC 4226 HOTP test vectors", () => {
  const VECTORS = [
    "755224", "287082", "359152", "969429", "338314",
    "254676", "287922", "162583", "399871", "520489",
  ];
  it.each(VECTORS.map((v, c) => [c, v] as const))("HOTP(counter=%i) == %s", (counter, expected) => {
    expect(hotp(SECRET_BYTES, counter)).toBe(expected);
  });
});

// =======================================================================================
// RFC 6238 — TOTP test vectors (Appendix B, SHA-1 column). period=30, 6 digits.
// =======================================================================================

describe("RFC 6238 TOTP test vectors (SHA-1)", () => {
  // [unixSeconds, expected 8-digit, expected 6-digit]
  const VECTORS: Array<[number, string, string]> = [
    [59, "94287082", "287082"],
    [1111111109, "07081804", "081804"],
    [1111111111, "14050471", "050471"],
    [1234567890, "89005924", "005924"],
    [2000000000, "69279037", "279037"],
    [20000000000, "65353130", "353130"], // exercises the 64-bit counter path
  ];

  it.each(VECTORS)("TOTP(t=%i) 6-digit == %s", (t, _eight, six) => {
    expect(totp(SECRET_BYTES, t)).toBe(six);
  });

  it.each(VECTORS)("TOTP(t=%i) 8-digit == %s", (t, eight) => {
    expect(totp(SECRET_BYTES, t, 8)).toBe(eight);
  });

  it("time-step matches floor(unix/period)", () => {
    expect(timeStep(59)).toBe(1);
    expect(timeStep(1111111109)).toBe(37037036);
    expect(timeStep(0)).toBe(0);
    expect(timeStep(29)).toBe(0);
    expect(timeStep(30)).toBe(1);
  });
});

// =======================================================================================
// verifyTotpCode — window / skew behavior
// =======================================================================================

describe("verifyTotpCode window + skew (±1 step)", () => {
  it("accepts the current-step code and returns its step number", () => {
    const t = 1111111111;
    const code = totp(SECRET_BYTES, t);
    expect(verifyTotpCode(SECRET_BYTES, code, t)).toBe(timeStep(t));
  });

  it("accepts the PREVIOUS step's code (clock drift behind)", () => {
    const t = 1111111111;
    const prevCode = totp(SECRET_BYTES, t - TOTP_PERIOD_SECONDS);
    expect(verifyTotpCode(SECRET_BYTES, prevCode, t)).toBe(timeStep(t) - 1);
  });

  it("accepts the NEXT step's code (clock drift ahead)", () => {
    const t = 1111111111;
    const nextCode = totp(SECRET_BYTES, t + TOTP_PERIOD_SECONDS);
    expect(verifyTotpCode(SECRET_BYTES, nextCode, t)).toBe(timeStep(t) + 1);
  });

  it("REJECTS a code two steps away (outside ±1 window)", () => {
    const t = 1111111111;
    const farCode = totp(SECRET_BYTES, t + 2 * TOTP_PERIOD_SECONDS);
    expect(verifyTotpCode(SECRET_BYTES, farCode, t)).toBeNull();
  });

  it("rejects malformed codes without throwing (wrong length / non-digit)", () => {
    const t = 1111111111;
    expect(verifyTotpCode(SECRET_BYTES, "12345", t)).toBeNull(); // too short
    expect(verifyTotpCode(SECRET_BYTES, "1234567", t)).toBeNull(); // too long
    expect(verifyTotpCode(SECRET_BYTES, "abcdef", t)).toBeNull(); // non-digit
    expect(verifyTotpCode(SECRET_BYTES, "", t)).toBeNull();
  });

  it("rejects a wrong-but-well-formed code", () => {
    const t = 1111111111;
    const wrong = totp(SECRET_BYTES, t) === "000000" ? "111111" : "000000";
    expect(verifyTotpCode(SECRET_BYTES, wrong, t)).toBeNull();
  });
});

// =======================================================================================
// base32 (RFC 4648) round-trips
// =======================================================================================

describe("base32 encode/decode (RFC 4648)", () => {
  it("encodes the RFC 6238 ASCII seed to its known base32 form", () => {
    // "12345678901234567890" -> GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    expect(base32Encode(SECRET_BYTES)).toBe("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  });

  it("round-trips arbitrary bytes", () => {
    for (const len of [1, 5, 7, 8, 16, 20, 32]) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = (i * 37 + 11) & 0xff;
      expect(base32Decode(base32Encode(bytes))).toEqual(bytes);
    }
  });

  it("decode tolerates lowercase, padding, and spaces", () => {
    const canonical = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    expect(base32Decode("gezdgnbvgy3tqojqgezdgnbvgy3tqojq")).toEqual(base32Decode(canonical));
    expect(base32Decode("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ")).toEqual(base32Decode(canonical));
  });

  it("decode throws TotpError on invalid characters", () => {
    expect(() => base32Decode("GEZD0189")).toThrow(TotpError); // 0,1,8,9 not in base32
  });
});

// =======================================================================================
// otpauth:// URI
// =======================================================================================

describe("otpauth URI", () => {
  it("builds a spec-shaped otpauth://totp URI", () => {
    const uri = buildOtpauthUri({
      secretBase32: "GEZDGNBVGY3TQOJQ",
      accountName: "alice@example.com",
      issuer: "cloud-fs",
    });
    const u = new URL(uri);
    expect(u.protocol).toBe("otpauth:");
    expect(u.host).toBe("totp");
    expect(decodeURIComponent(u.pathname.slice(1))).toBe("cloud-fs:alice@example.com");
    expect(u.searchParams.get("secret")).toBe("GEZDGNBVGY3TQOJQ");
    expect(u.searchParams.get("issuer")).toBe("cloud-fs");
    expect(u.searchParams.get("algorithm")).toBe("SHA1");
    expect(u.searchParams.get("digits")).toBe(String(TOTP_DIGITS));
    expect(u.searchParams.get("period")).toBe(String(TOTP_PERIOD_SECONDS));
  });

  it("encodes spaces as %20 (not '+') in the label", () => {
    const uri = buildOtpauthUri({
      secretBase32: "AAAA",
      accountName: "bob@x.io",
      issuer: "cloud fs",
    });
    expect(uri).toContain("cloud%20fs:bob%40x.io");
    expect(uri).not.toContain("+");
  });
});

// =======================================================================================
// constant-time compare
// =======================================================================================

describe("timingSafeEqualBytes", () => {
  it("true for equal arrays", () => {
    expect(timingSafeEqualBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });
  it("false for different contents of same length", () => {
    expect(timingSafeEqualBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });
  it("false for different lengths", () => {
    expect(timingSafeEqualBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2]))).toBe(false);
  });
  it("true for two empty arrays", () => {
    expect(timingSafeEqualBytes(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

// =======================================================================================
// recovery codes
// =======================================================================================

describe("recovery codes", () => {
  it("generates the configured count and length of base32 codes", () => {
    const codes = generateRecoveryCodes(RECOVERY_CODE_COUNT, RECOVERY_CODE_LENGTH, seededRandom(1));
    expect(codes).toHaveLength(RECOVERY_CODE_COUNT);
    for (const c of codes) {
      expect(c).toHaveLength(RECOVERY_CODE_LENGTH);
      expect(c).toMatch(/^[A-Z2-7]+$/); // base32 alphabet
    }
  });

  it("codes are unique under a CSPRNG", () => {
    const codes = generateRecoveryCodes(RECOVERY_CODE_COUNT, RECOVERY_CODE_LENGTH, seededRandom(42));
    expect(new Set(codes).size).toBe(codes.length);
  });

  it("hashRecoveryCode is stable and case/space-insensitive on entry", () => {
    const h = hashRecoveryCode("ABCDE23456");
    expect(hashRecoveryCode("abcde23456")).toBe(h);
    expect(hashRecoveryCode("ABCDE 23456")).toBe(h);
    expect(hashRecoveryCode("ABCDE23457")).not.toBe(h);
  });
});

// =======================================================================================
// enrollment handler
// =======================================================================================

describe("enrollTotp", () => {
  it("creates an UNCONFIRMED secret + otpauth URI and persists it", async () => {
    const store = new FakeStore();
    const res = await enrollTotp("acc-1", "alice@example.com", depsAt(store, 1_000_000));
    expect(res.secret).toMatch(/^[A-Z2-7]+$/);
    expect(res.otpauthUri).toContain("otpauth://totp/");
    expect(res.otpauthUri).toContain(`secret=${res.secret}`);
    const stored = await store.getTotp("acc-1");
    expect(stored?.confirmed).toBe(false);
    expect(stored?.secret).toBe(res.secret);
    expect(stored?.confirmedAt).toBeNull();
  });

  it("re-enroll overwrites a prior UNCONFIRMED secret", async () => {
    const store = new FakeStore();
    const a = await enrollTotp("acc-1", "alice@example.com", depsAt(store, 1, seededRandom(1)));
    const b = await enrollTotp("acc-1", "alice@example.com", depsAt(store, 2, seededRandom(2)));
    expect(b.secret).not.toBe(a.secret);
    expect((await store.getTotp("acc-1"))?.secret).toBe(b.secret);
  });

  it("refuses to re-enroll over a CONFIRMED credential (409)", async () => {
    const store = new FakeStore();
    store.totps.set("acc-1", {
      accountId: "acc-1",
      secret: base32Encode(SECRET_BYTES),
      confirmed: true,
      createdAt: 1,
      confirmedAt: 2,
    });
    await expect(enrollTotp("acc-1", "alice@example.com", depsAt(store, 5))).rejects.toMatchObject({
      code: "totp_exists",
      status: 409,
    });
  });
});

// =======================================================================================
// confirm handler
// =======================================================================================

describe("confirmTotp", () => {
  // Use the known seed so we can compute the expected code deterministically.
  function seedConfirmed(store: FakeStore) {
    store.totps.set("acc-1", {
      accountId: "acc-1",
      secret: base32Encode(SECRET_BYTES),
      confirmed: false,
      createdAt: 0,
      confirmedAt: null,
    });
  }

  it("confirms on a valid code and returns recovery codes ONCE", async () => {
    const store = new FakeStore();
    seedConfirmed(store);
    const tSec = 1111111111;
    const code = totp(SECRET_BYTES, tSec);
    const res = await confirmTotp("acc-1", code, depsAt(store, tSec * 1000));
    expect(res.confirmed).toBe(true);
    expect(res.recoveryCodes).toHaveLength(RECOVERY_CODE_COUNT);
    expect((await store.getTotp("acc-1"))?.confirmed).toBe(true);
    expect((await store.getTotp("acc-1"))?.confirmedAt).toBe(tSec * 1000);
    // recovery codes stored hashed
    const stored = store.recovery.get("acc-1")!;
    expect(stored).toHaveLength(RECOVERY_CODE_COUNT);
    expect(stored.map((r) => r.codeHash)).toEqual(res.recoveryCodes.map(hashRecoveryCode));
  });

  it("rejects an invalid code (401) and stays unconfirmed", async () => {
    const store = new FakeStore();
    seedConfirmed(store);
    const tSec = 1111111111;
    const wrong = totp(SECRET_BYTES, tSec) === "999999" ? "000000" : "999999";
    await expect(confirmTotp("acc-1", wrong, depsAt(store, tSec * 1000))).rejects.toMatchObject({
      code: "bad_code",
      status: 401,
    });
    expect((await store.getTotp("acc-1"))?.confirmed).toBe(false);
  });

  it("404 when no enrollment in progress", async () => {
    const store = new FakeStore();
    await expect(confirmTotp("acc-x", "000000", depsAt(store, 1000))).rejects.toMatchObject({
      code: "no_totp",
      status: 404,
    });
  });

  it("409 when already confirmed (recovery codes not re-shown)", async () => {
    const store = new FakeStore();
    store.totps.set("acc-1", {
      accountId: "acc-1",
      secret: base32Encode(SECRET_BYTES),
      confirmed: true,
      createdAt: 0,
      confirmedAt: 1,
    });
    const tSec = 1111111111;
    await expect(confirmTotp("acc-1", totp(SECRET_BYTES, tSec), depsAt(store, tSec * 1000))).rejects.toMatchObject({
      code: "totp_exists",
      status: 409,
    });
  });
});

// =======================================================================================
// login verification + replay guard
// =======================================================================================

describe("verifyLoginTotp + replay guard", () => {
  function seedActive(store: FakeStore) {
    store.totps.set("acc-1", {
      accountId: "acc-1",
      secret: base32Encode(SECRET_BYTES),
      confirmed: true,
      createdAt: 0,
      confirmedAt: 1,
    });
  }

  it("accepts a valid code for a confirmed account", async () => {
    const store = new FakeStore();
    seedActive(store);
    const tSec = 1234567890;
    await expect(verifyLoginTotp("acc-1", totp(SECRET_BYTES, tSec), depsAt(store, tSec * 1000))).resolves.toBeUndefined();
  });

  it("REPLAY: the same code cannot be used twice within its window", async () => {
    const store = new FakeStore();
    seedActive(store);
    const tSec = 1234567890;
    const code = totp(SECRET_BYTES, tSec);
    // first use a few seconds in, second use later but same step
    await verifyLoginTotp("acc-1", code, depsAt(store, tSec * 1000));
    await expect(
      verifyLoginTotp("acc-1", code, depsAt(store, (tSec + 5) * 1000)),
    ).rejects.toMatchObject({ code: "code_replayed", status: 401 });
  });

  it("REPLAY: a code accepted at confirm cannot be replayed at the next login", async () => {
    const store = new FakeStore();
    store.totps.set("acc-1", {
      accountId: "acc-1",
      secret: base32Encode(SECRET_BYTES),
      confirmed: false,
      createdAt: 0,
      confirmedAt: null,
    });
    const tSec = 1234567890;
    const code = totp(SECRET_BYTES, tSec);
    await confirmTotp("acc-1", code, depsAt(store, tSec * 1000));
    // immediately try to log in with the same code in the same step
    await expect(verifyLoginTotp("acc-1", code, depsAt(store, (tSec + 1) * 1000))).rejects.toMatchObject({
      code: "code_replayed",
    });
  });

  it("a DIFFERENT step's code still works after one is consumed", async () => {
    const store = new FakeStore();
    seedActive(store);
    const tSec = 1234567890;
    await verifyLoginTotp("acc-1", totp(SECRET_BYTES, tSec), depsAt(store, tSec * 1000));
    // advance two periods => fresh step, fresh code
    const t2 = tSec + 2 * TOTP_PERIOD_SECONDS;
    await expect(verifyLoginTotp("acc-1", totp(SECRET_BYTES, t2), depsAt(store, t2 * 1000))).resolves.toBeUndefined();
  });

  it("rejects an invalid code (401 bad_code)", async () => {
    const store = new FakeStore();
    seedActive(store);
    const tSec = 1234567890;
    const wrong = totp(SECRET_BYTES, tSec) === "111111" ? "222222" : "111111";
    await expect(verifyLoginTotp("acc-1", wrong, depsAt(store, tSec * 1000))).rejects.toMatchObject({
      code: "bad_code",
    });
  });

  it("rejects login when TOTP is not enabled / unconfirmed", async () => {
    const store = new FakeStore();
    await expect(verifyLoginTotp("acc-x", "000000", depsAt(store, 1000))).rejects.toMatchObject({
      code: "no_totp",
      status: 401,
    });
    // unconfirmed credential is also rejected
    store.totps.set("acc-1", {
      accountId: "acc-1",
      secret: base32Encode(SECRET_BYTES),
      confirmed: false,
      createdAt: 0,
      confirmedAt: null,
    });
    await expect(verifyLoginTotp("acc-1", "000000", depsAt(store, 1000))).rejects.toMatchObject({
      code: "no_totp",
    });
  });
});

// =======================================================================================
// recovery-code login + disable
// =======================================================================================

describe("verifyRecoveryCode (single-use) + disableTotp", () => {
  async function enrollAndConfirm(store: FakeStore) {
    store.totps.set("acc-1", {
      accountId: "acc-1",
      secret: base32Encode(SECRET_BYTES),
      confirmed: false,
      createdAt: 0,
      confirmedAt: null,
    });
    const tSec = 1111111111;
    const res = await confirmTotp("acc-1", totp(SECRET_BYTES, tSec), depsAt(store, tSec * 1000));
    return res.recoveryCodes;
  }

  it("accepts a valid recovery code and consumes it (single-use)", async () => {
    const store = new FakeStore();
    const codes = await enrollAndConfirm(store);
    await expect(verifyRecoveryCode("acc-1", codes[0], depsAt(store, 2_000_000))).resolves.toBeUndefined();
    // second use of the same code fails
    await expect(verifyRecoveryCode("acc-1", codes[0], depsAt(store, 2_000_001))).rejects.toMatchObject({
      code: "bad_recovery_code",
      status: 401,
    });
  });

  it("accepts recovery codes case-insensitively (display vs typed)", async () => {
    const store = new FakeStore();
    const codes = await enrollAndConfirm(store);
    await expect(
      verifyRecoveryCode("acc-1", codes[1].toLowerCase(), depsAt(store, 2_000_000)),
    ).resolves.toBeUndefined();
  });

  it("rejects an unknown recovery code", async () => {
    const store = new FakeStore();
    await enrollAndConfirm(store);
    await expect(verifyRecoveryCode("acc-1", "ZZZZZZZZZZ", depsAt(store, 2_000_000))).rejects.toMatchObject({
      code: "bad_recovery_code",
    });
  });

  it("rejects recovery login when TOTP is not enabled", async () => {
    const store = new FakeStore();
    await expect(verifyRecoveryCode("acc-x", "ABCDE23456", depsAt(store, 1000))).rejects.toMatchObject({
      code: "no_totp",
    });
  });

  it("disableTotp removes the credential and its recovery codes", async () => {
    const store = new FakeStore();
    await enrollAndConfirm(store);
    await disableTotp("acc-1", depsAt(store, 3_000_000));
    expect(await store.getTotp("acc-1")).toBeNull();
    expect(store.recovery.get("acc-1")).toBeUndefined();
  });
});

// =======================================================================================
// full enroll -> confirm -> login happy path (end-to-end through the handlers)
// =======================================================================================

describe("end-to-end enroll/confirm/login", () => {
  it("walks the full lifecycle with an injected clock", async () => {
    const store = new FakeStore();
    // enroll (random secret)
    const t0 = 1_700_000_000;
    const enroll = await enrollTotp("acc-9", "carol@example.com", depsAt(store, t0 * 1000, seededRandom(7)));
    const secretBytes = base32Decode(enroll.secret);

    // confirm with a code derived from the issued secret
    const t1 = t0 + 31; // next step
    const confirmCode = totp(secretBytes, t1);
    const confirmRes = await confirmTotp("acc-9", confirmCode, depsAt(store, t1 * 1000));
    expect(confirmRes.confirmed).toBe(true);

    // login at a later, fresh step
    const t2 = t1 + 2 * TOTP_PERIOD_SECONDS;
    await expect(
      verifyLoginTotp("acc-9", totp(secretBytes, t2), depsAt(store, t2 * 1000)),
    ).resolves.toBeUndefined();

    // recovery code still works once
    await expect(
      verifyRecoveryCode("acc-9", confirmRes.recoveryCodes[0], depsAt(store, (t2 + 5) * 1000)),
    ).resolves.toBeUndefined();
  });
});
