// SPDX-License-Identifier: AGPL-3.0-or-later
/// Tests for the WebAuthn / passkeys lane (CONTRACTS-AUTH.md §1.4, §4.4).
///
/// TEST-VECTOR STRATEGY
///   Rather than mock @simplewebauthn's verifier, these tests stand up a REAL
///   in-process software authenticator built on WebCrypto (ES256 / P-256). It
///   produces genuine, signature-valid attestation (`fmt:"none"`) and assertion
///   responses against a fixed challenge / origin / rpID, then runs them through
///   the actual library verification path (CBOR decode, COSE-key parse, rpIdHash
///   check, UP/UV flag checks, ECDSA signature verify). So every assertion below
///   exercises real crypto end-to-end — deterministic (we control the key + the
///   injected challenge), no network, no mocking of the security-critical path.
///
///   This mirrors how @simplewebauthn's own test fixtures are generated; the
///   authenticator here is the canonical "known vector" for our config.

import { describe, it, expect, beforeEach } from "vitest";
import { isoCBOR, isoBase64URL, cose } from "@simplewebauthn/server/helpers";

import {
  startRegistration,
  finishRegistration,
  startAuthentication,
  finishAuthentication,
  handleWebAuthn,
  toPublicCredential,
  WebAuthnError,
  type WebAuthnDeps,
  type WebAuthnConfig,
  type WebAuthnCredential,
  type WebAuthnCredentialStore,
  type WebAuthnAccountStore,
  type SessionMinter,
} from "../src/security/auth-webauthn";

// ============================================================================
// Test config + deterministic injectables.
// ============================================================================

const RP_ID = "localhost";
const ORIGIN = "http://localhost:5173";
const FIXED_NOW = 1_700_000_000_000;

const CONFIG: WebAuthnConfig = {
  rpID: RP_ID,
  rpName: "cloud-fs (test)",
  expectedOrigin: ORIGIN,
  requireUserVerification: true,
  challengeTtlMs: 5 * 60 * 1000,
};

// ============================================================================
// In-memory fakes for the injected stores (CONTRACTS-AUTH.md §2).
// ============================================================================

class FakeCredentialStore implements WebAuthnCredentialStore {
  creds = new Map<string, WebAuthnCredential>(); // id -> cred
  challenges = new Map<string, { accountId: string | null; purpose: string; value: string; expiresAt: number }>();

  async listWebAuthn(accountId: string): Promise<WebAuthnCredential[]> {
    return [...this.creds.values()].filter((c) => c.accountId === accountId);
  }
  async getWebAuthnByCredentialId(credentialId: string): Promise<WebAuthnCredential | null> {
    return [...this.creds.values()].find((c) => c.credentialId === credentialId) ?? null;
  }
  async putWebAuthn(cred: WebAuthnCredential): Promise<void> {
    this.creds.set(cred.id, { ...cred });
  }
  async updateWebAuthnSignCount(id: string, signCount: number, lastUsedAt: number): Promise<void> {
    const c = this.creds.get(id);
    if (c) this.creds.set(id, { ...c, signCount, lastUsedAt });
  }
  async deleteWebAuthn(id: string): Promise<void> {
    this.creds.delete(id);
  }
  async putChallenge(c: { id: string; accountId: string | null; purpose: string; value: string; expiresAt: number }): Promise<void> {
    this.challenges.set(c.id, { accountId: c.accountId, purpose: c.purpose, value: c.value, expiresAt: c.expiresAt });
  }
  async takeChallenge(id: string) {
    const c = this.challenges.get(id);
    if (!c) return null;
    this.challenges.delete(id); // single-use
    return c;
  }
}

class FakeAccountStore implements WebAuthnAccountStore {
  byEmail = new Map<string, { orgId: string; accountId: string }>();
  byId = new Map<string, { id: string; userId: string; orgId: string; role: string; status: string }>();

  async resolveEmail(emailLower: string) {
    return this.byEmail.get(emailLower) ?? null;
  }
  async getAccount(accountId: string) {
    return this.byId.get(accountId) ?? null;
  }
}

const fakeSession: SessionMinter = {
  async mintForAccount(input) {
    return {
      setCookie: `cfs_session=jws-for-${input.accountId}; HttpOnly; Secure; SameSite=Lax; Path=/`,
      body: { userId: input.userId, orgId: input.orgId, role: input.role, scopes: ["fs:read", "fs:write"], csrf: "csrf-token" },
    };
  },
};

const ACCOUNT = {
  id: "acc-1",
  userId: "usr-1",
  orgId: "org-1",
  email: "editor@example.com",
  displayName: "Ed Editor",
  role: "standard",
  status: "active",
};

function makeDeps(overrides: Partial<WebAuthnDeps> = {}): {
  deps: WebAuthnDeps;
  store: FakeCredentialStore;
  accounts: FakeAccountStore;
  setChallenge: (bytes: Uint8Array) => void;
} {
  const store = new FakeCredentialStore();
  const accounts = new FakeAccountStore();
  accounts.byEmail.set(ACCOUNT.email, { orgId: ACCOUNT.orgId, accountId: ACCOUNT.id });
  accounts.byId.set(ACCOUNT.id, { id: ACCOUNT.id, userId: ACCOUNT.userId, orgId: ACCOUNT.orgId, role: ACCOUNT.role, status: ACCOUNT.status });

  // deterministic, controllable challenge source
  let challengeBytes: Uint8Array = new Uint8Array(32).fill(7);
  let idCounter = 0;

  const deps: WebAuthnDeps = {
    store,
    accounts,
    config: CONFIG,
    session: fakeSession,
    now: () => FIXED_NOW,
    randomChallenge: () => challengeBytes,
    newId: () => `id${++idCounter}`,
    ...overrides,
  };
  return {
    deps,
    store,
    accounts,
    setChallenge: (b: Uint8Array) => {
      challengeBytes = b;
    },
  };
}

// ============================================================================
// A REAL software authenticator (ES256 / P-256) over WebCrypto.
// Produces signature-valid attestation + assertion responses.
// ============================================================================

const te = new TextEncoder();

/** Allocate an ArrayBuffer-backed Uint8Array (the strict variance the lib helpers want). */
function bytes(n: number): Uint8Array<ArrayBuffer> {
  return new Uint8Array(new ArrayBuffer(n));
}
/** Copy any Uint8Array into a fresh ArrayBuffer-backed one. */
function asBytes(src: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = bytes(src.length);
  out.set(src);
  return out;
}

function b64url(b: Uint8Array): string {
  return isoBase64URL.fromBuffer(asBytes(b));
}

async function sha256(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const d = await crypto.subtle.digest("SHA-256", asBytes(data));
  return new Uint8Array(d);
}

function concat(...arrs: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = bytes(len);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** Convert a raw fixed-length integer to a minimal DER INTEGER. */
function derInteger(b: Uint8Array): Uint8Array<ArrayBuffer> {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  let v: Uint8Array = b.slice(i);
  if (v[0] & 0x80) v = concat(new Uint8Array([0]), v); // positive sign
  return concat(new Uint8Array([0x02, v.length]), v);
}

/** WebCrypto ECDSA produces raw r||s; WebAuthn authenticators emit DER. Wrap it. */
function rawSigToDer(raw: Uint8Array): Uint8Array {
  const r = derInteger(raw.slice(0, 32));
  const s = derInteger(raw.slice(32, 64));
  const seq = concat(r, s);
  return concat(new Uint8Array([0x30, seq.length]), seq);
}

interface SoftAuthenticator {
  credentialId: Uint8Array;
  makeAttestationResponse(challengeB64: string): Promise<{
    id: string;
    rawId: string;
    type: "public-key";
    clientExtensionResults: Record<string, never>;
    transports: string[];
    response: { clientDataJSON: string; attestationObject: string; transports: string[] };
  }>;
  makeAssertionResponse(
    challengeB64: string,
    opts?: { signCount?: number; origin?: string; rpId?: string; up?: boolean; uv?: boolean },
  ): Promise<{
    id: string;
    rawId: string;
    type: "public-key";
    clientExtensionResults: Record<string, never>;
    response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string };
  }>;
}

/**
 * Build a software authenticator with a fresh P-256 keypair. The COSE public key
 * is embedded into the attestation's authData exactly as a real authenticator
 * would (fmt:"none"), so verifyRegistrationResponse extracts + stores it, and
 * subsequent assertions are verified against it.
 */
async function makeAuthenticator(opts?: { signCount?: number }): Promise<SoftAuthenticator> {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
  const x = isoBase64URL.toBuffer(jwk.x!, "base64url");
  const y = isoBase64URL.toBuffer(jwk.y!, "base64url");

  // COSE EC2 public key map (ES256 / P-256).
  const coseKey = new Map<number, number | Uint8Array>();
  coseKey.set(cose.COSEKEYS.kty, cose.COSEKTY.EC2);
  coseKey.set(cose.COSEKEYS.alg, cose.COSEALG.ES256);
  coseKey.set(cose.COSEKEYS.crv, cose.COSECRV.P256);
  coseKey.set(cose.COSEKEYS.x, x);
  coseKey.set(cose.COSEKEYS.y, y);
  const cosePublicKey = isoCBOR.encode(coseKey as never);

  const credentialId = crypto.getRandomValues(new Uint8Array(16));
  const rpIdHashBytes = await sha256(te.encode(RP_ID));
  const aaguid = new Uint8Array(16); // zeroes for fmt:"none"

  function flags(up: boolean, uv: boolean, at: boolean): number {
    let f = 0;
    if (up) f |= 0x01; // user present
    if (uv) f |= 0x04; // user verified
    if (at) f |= 0x40; // attested credential data included
    return f;
  }

  function counterBytes(n: number): Uint8Array {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, false);
    return b;
  }

  async function buildAuthData(args: {
    up: boolean;
    uv: boolean;
    includeAttestedCred: boolean;
    signCount: number;
    rpIdHash?: Uint8Array;
  }): Promise<Uint8Array> {
    const rpHash = args.rpIdHash ?? rpIdHashBytes;
    const head = concat(rpHash, new Uint8Array([flags(args.up, args.uv, args.includeAttestedCred)]), counterBytes(args.signCount));
    if (!args.includeAttestedCred) return head;
    const credIdLen = new Uint8Array(2);
    new DataView(credIdLen.buffer).setUint16(0, credentialId.length, false);
    return concat(head, aaguid, credIdLen, credentialId, new Uint8Array(cosePublicKey));
  }

  async function clientData(type: string, challengeB64: string, origin: string): Promise<Uint8Array> {
    return te.encode(JSON.stringify({ type, challenge: challengeB64, origin, crossOrigin: false }));
  }

  async function sign(authData: Uint8Array, clientDataJSON: Uint8Array): Promise<Uint8Array> {
    const clientHash = await sha256(clientDataJSON);
    const signed = concat(authData, clientHash);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, signed));
    return rawSigToDer(raw);
  }

  return {
    credentialId,
    async makeAttestationResponse(challengeB64: string) {
      const cdj = await clientData("webauthn.create", challengeB64, ORIGIN);
      const authData = await buildAuthData({ up: true, uv: true, includeAttestedCred: true, signCount: opts?.signCount ?? 0 });
      // fmt:"none" attestation object: { fmt:"none", attStmt:{}, authData }
      const attObj = isoCBOR.encode(
        new Map<string, unknown>([
          ["fmt", "none"],
          ["attStmt", new Map()],
          ["authData", authData],
        ]) as never,
      );
      const credIdB64 = b64url(credentialId);
      return {
        id: credIdB64,
        rawId: credIdB64,
        type: "public-key" as const,
        clientExtensionResults: {},
        transports: ["internal", "hybrid"],
        response: {
          clientDataJSON: b64url(cdj),
          attestationObject: b64url(new Uint8Array(attObj)),
          transports: ["internal", "hybrid"],
        },
      };
    },
    async makeAssertionResponse(challengeB64, o) {
      const origin = o?.origin ?? ORIGIN;
      const rpId = o?.rpId ?? RP_ID;
      const rpHash = await sha256(te.encode(rpId));
      const cdj = await clientData("webauthn.get", challengeB64, origin);
      const authData = await buildAuthData({
        up: o?.up ?? true,
        uv: o?.uv ?? true,
        includeAttestedCred: false,
        signCount: o?.signCount ?? 1,
        rpIdHash: rpHash,
      });
      const sig = await sign(authData, cdj);
      const credIdB64 = b64url(credentialId);
      return {
        id: credIdB64,
        rawId: credIdB64,
        type: "public-key" as const,
        clientExtensionResults: {},
        response: {
          clientDataJSON: b64url(cdj),
          authenticatorData: b64url(authData),
          signature: b64url(sig),
        },
      };
    },
  };
}

/** End-to-end: register a passkey, return the stored credential + the authenticator. */
async function registerPasskey(
  deps: WebAuthnDeps,
  setChallenge: (b: Uint8Array) => void,
  initialSignCount = 0,
): Promise<{ auth: SoftAuthenticator; cred: WebAuthnCredential }> {
  const auth = await makeAuthenticator({ signCount: initialSignCount });
  const { options, challengeId } = await startRegistration(deps, ACCOUNT);
  const attestation = await auth.makeAttestationResponse(options.challenge);
  const cred = await finishRegistration(deps, {
    accountId: ACCOUNT.id,
    challengeId,
    response: attestation as never,
    label: "Test Passkey",
  });
  return { auth, cred };
}

// ============================================================================
// REGISTRATION CEREMONY
// ============================================================================

describe("webauthn registration ceremony", () => {
  let ctx: ReturnType<typeof makeDeps>;
  beforeEach(() => {
    ctx = makeDeps();
  });

  it("startRegistration emits creation options with our rpID and stores a single-use challenge", async () => {
    const { options, challengeId } = await startRegistration(ctx.deps, ACCOUNT);
    expect(options.rp.id).toBe(RP_ID);
    expect(options.rp.name).toBe(CONFIG.rpName);
    expect(options.user.name).toBe(ACCOUNT.email);
    expect(options.challenge).toBeTruthy();
    expect(options.pubKeyCredParams.some((p) => p.alg === -7)).toBe(true); // ES256 offered
    // challenge persisted under the returned id, scoped to the account + purpose
    const stored = ctx.store.challenges.get(challengeId)!;
    expect(stored.accountId).toBe(ACCOUNT.id);
    expect(stored.purpose).toBe("webauthn.register");
    expect(stored.value).toBe(options.challenge);
  });

  it("excludes already-registered credentials so the same authenticator can't double-enrol", async () => {
    const { cred } = await registerPasskey(ctx.deps, ctx.setChallenge);
    const { options } = await startRegistration(ctx.deps, ACCOUNT);
    expect(options.excludeCredentials?.some((c) => c.id === cred.credentialId)).toBe(true);
  });

  it("verifies a real attestation and persists credentialId + COSE public key + signCount + transports", async () => {
    const { cred } = await registerPasskey(ctx.deps, ctx.setChallenge);
    expect(cred.id).toMatch(/^wac-/);
    expect(cred.accountId).toBe(ACCOUNT.id);
    expect(cred.credentialId).toBeTruthy();
    expect(cred.publicKey).toBeTruthy(); // base64url COSE key
    expect(cred.signCount).toBe(0);
    expect(cred.transports).toEqual(["internal", "hybrid"]);
    expect(cred.label).toBe("Test Passkey");
    // actually in the store, looked up by credentialId (unique index)
    const fetched = await ctx.store.getWebAuthnByCredentialId(cred.credentialId);
    expect(fetched?.id).toBe(cred.id);
  });

  it("consumes the challenge (single-use): replaying the same challengeId fails", async () => {
    const auth = await makeAuthenticator();
    const { options, challengeId } = await startRegistration(ctx.deps, ACCOUNT);
    const attestation = await auth.makeAttestationResponse(options.challenge);
    await finishRegistration(ctx.deps, { accountId: ACCOUNT.id, challengeId, response: attestation as never });
    await expect(
      finishRegistration(ctx.deps, { accountId: ACCOUNT.id, challengeId, response: attestation as never }),
    ).rejects.toMatchObject({ code: "challenge_unknown" });
  });

  it("rejects a registration whose challenge belongs to a different account", async () => {
    const auth = await makeAuthenticator();
    const { options, challengeId } = await startRegistration(ctx.deps, ACCOUNT);
    const attestation = await auth.makeAttestationResponse(options.challenge);
    await expect(
      finishRegistration(ctx.deps, { accountId: "acc-OTHER", challengeId, response: attestation as never }),
    ).rejects.toMatchObject({ code: "challenge_mismatch" });
  });

  it("rejects an attestation built against a different challenge (challenge match enforced)", async () => {
    const auth = await makeAuthenticator();
    const { challengeId } = await startRegistration(ctx.deps, ACCOUNT);
    const attestation = await auth.makeAttestationResponse(b64url(new Uint8Array(32).fill(99)));
    await expect(
      finishRegistration(ctx.deps, { accountId: ACCOUNT.id, challengeId, response: attestation as never }),
    ).rejects.toBeTruthy();
  });

  it("rejects an expired challenge", async () => {
    const auth = await makeAuthenticator();
    const { options, challengeId } = await startRegistration(ctx.deps, ACCOUNT);
    const attestation = await auth.makeAttestationResponse(options.challenge);
    // advance time past TTL
    const lateDeps: WebAuthnDeps = { ...ctx.deps, now: () => FIXED_NOW + 6 * 60 * 1000 };
    await expect(
      finishRegistration(lateDeps, { accountId: ACCOUNT.id, challengeId, response: attestation as never }),
    ).rejects.toMatchObject({ code: "challenge_expired" });
  });

  it("rejects re-registering an identical credentialId (duplicate)", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge);
    const { options, challengeId } = await startRegistration(ctx.deps, ACCOUNT);
    const attestation = await auth.makeAttestationResponse(options.challenge);
    await expect(
      finishRegistration(ctx.deps, { accountId: ACCOUNT.id, challengeId, response: attestation as never }),
    ).rejects.toMatchObject({ code: "credential_exists" });
  });
});

// ============================================================================
// AUTHENTICATION CEREMONY
// ============================================================================

describe("webauthn authentication ceremony", () => {
  let ctx: ReturnType<typeof makeDeps>;
  beforeEach(() => {
    ctx = makeDeps();
  });

  it("startAuthentication (email mode) narrows allowCredentials to the account's passkeys", async () => {
    const { cred } = await registerPasskey(ctx.deps, ctx.setChallenge);
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: ACCOUNT.email });
    expect(options.rpId).toBe(RP_ID);
    expect(options.allowCredentials?.map((c) => c.id)).toContain(cred.credentialId);
    const stored = ctx.store.challenges.get(challengeId)!;
    expect(stored.accountId).toBe(ACCOUNT.id);
    expect(stored.purpose).toBe("webauthn.authenticate");
  });

  it("startAuthentication (discoverable / usernameless) emits an empty allow-list + null-account challenge", async () => {
    const { options, challengeId } = await startAuthentication(ctx.deps, {});
    expect(options.allowCredentials ?? []).toHaveLength(0);
    expect(ctx.store.challenges.get(challengeId)!.accountId).toBeNull();
  });

  it("does NOT enumerate: unknown email still returns options (empty allow-list)", async () => {
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: "nobody@example.com" });
    expect(options.allowCredentials ?? []).toHaveLength(0);
    expect(ctx.store.challenges.get(challengeId)!.accountId).toBeNull();
  });

  it("verifies a real assertion, advances signCount, and returns the resolved account", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: ACCOUNT.email });
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 5 });
    const result = await finishAuthentication(ctx.deps, { challengeId, response: assertion as never });
    expect(result.account.userId).toBe(ACCOUNT.userId);
    expect(result.account.orgId).toBe(ACCOUNT.orgId);
    expect(result.credential.signCount).toBe(5); // advanced
    // persisted
    const fetched = await ctx.store.getWebAuthnByCredentialId(result.credential.credentialId);
    expect(fetched?.signCount).toBe(5);
    expect(fetched?.lastUsedAt).toBe(FIXED_NOW);
  });

  it("works in discoverable mode (challenge not bound to an account)", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const { options, challengeId } = await startAuthentication(ctx.deps, {});
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 2 });
    const result = await finishAuthentication(ctx.deps, { challengeId, response: assertion as never });
    expect(result.account.userId).toBe(ACCOUNT.userId);
  });

  it("REJECTS a signCount regression (cloned-authenticator detection)", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 10);
    // stored signCount is 10; an assertion claiming 10 (no advance) must be rejected
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: ACCOUNT.email });
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 10 });
    await expect(
      finishAuthentication(ctx.deps, { challengeId, response: assertion as never }),
    ).rejects.toMatchObject({ code: "signcount_regression", status: 401 });
  });

  it("REJECTS a strictly lower signCount (replay of an older assertion)", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 10);
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: ACCOUNT.email });
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 3 });
    await expect(
      finishAuthentication(ctx.deps, { challengeId, response: assertion as never }),
    ).rejects.toMatchObject({ code: "signcount_regression" });
  });

  it("allows a 0/0 counter pair (authenticators that never increment) without false-positive clone alarm", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: ACCOUNT.email });
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 0 });
    const result = await finishAuthentication(ctx.deps, { challengeId, response: assertion as never });
    expect(result.credential.signCount).toBe(0);
  });

  it("REJECTS an assertion with a mismatched origin", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: ACCOUNT.email });
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 1, origin: "https://evil.example.com" });
    await expect(
      finishAuthentication(ctx.deps, { challengeId, response: assertion as never }),
    ).rejects.toBeTruthy();
  });

  it("REJECTS an assertion signed over the wrong rpIdHash", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: ACCOUNT.email });
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 1, rpId: "attacker.example" });
    await expect(
      finishAuthentication(ctx.deps, { challengeId, response: assertion as never }),
    ).rejects.toBeTruthy();
  });

  it("REJECTS an assertion missing the user-present flag", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: ACCOUNT.email });
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 1, up: false });
    await expect(
      finishAuthentication(ctx.deps, { challengeId, response: assertion as never }),
    ).rejects.toBeTruthy();
  });

  it("REJECTS an assertion missing user-verification when UV is required (passwordless)", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: ACCOUNT.email });
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 1, uv: false });
    await expect(
      finishAuthentication(ctx.deps, { challengeId, response: assertion as never }),
    ).rejects.toBeTruthy();
  });

  it("REJECTS a forged signature (real ECDSA verification, not a mock)", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: ACCOUNT.email });
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 1 });
    // flip a byte in the signature
    const sigBytes = isoBase64URL.toBuffer(assertion.response.signature, "base64url");
    sigBytes[sigBytes.length - 1] ^= 0xff;
    assertion.response.signature = isoBase64URL.fromBuffer(sigBytes);
    await expect(
      finishAuthentication(ctx.deps, { challengeId, response: assertion as never }),
    ).rejects.toBeTruthy();
  });

  it("REJECTS an assertion from an unknown credential id", async () => {
    await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const stranger = await makeAuthenticator();
    const { options, challengeId } = await startAuthentication(ctx.deps, {});
    const assertion = await stranger.makeAssertionResponse(options.challenge, { signCount: 1 });
    await expect(
      finishAuthentication(ctx.deps, { challengeId, response: assertion as never }),
    ).rejects.toMatchObject({ code: "unknown_credential" });
  });

  it("REJECTS using a registration challenge for authentication (purpose binding)", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const { options, challengeId } = await startRegistration(ctx.deps, ACCOUNT); // wrong purpose
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 1 });
    await expect(
      finishAuthentication(ctx.deps, { challengeId, response: assertion as never }),
    ).rejects.toMatchObject({ code: "challenge_purpose" });
  });

  it("REJECTS when the asserting credential belongs to a different account than the email-bound challenge", async () => {
    // account A registers a passkey; account B starts an email-bound challenge; A's
    // credential must not satisfy B's challenge.
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    ctx.accounts.byEmail.set("other@example.com", { orgId: "org-1", accountId: "acc-2" });
    ctx.accounts.byId.set("acc-2", { id: "acc-2", userId: "usr-2", orgId: "org-1", role: "standard", status: "active" });
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: "other@example.com" });
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 1 });
    await expect(
      finishAuthentication(ctx.deps, { challengeId, response: assertion as never }),
    ).rejects.toMatchObject({ code: "challenge_mismatch" });
  });

  it("REJECTS authentication for a suspended account", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    ctx.accounts.byId.set(ACCOUNT.id, { ...ctx.accounts.byId.get(ACCOUNT.id)!, status: "suspended" });
    const { options, challengeId } = await startAuthentication(ctx.deps, { email: ACCOUNT.email });
    const assertion = await auth.makeAssertionResponse(options.challenge, { signCount: 1 });
    await expect(
      finishAuthentication(ctx.deps, { challengeId, response: assertion as never }),
    ).rejects.toMatchObject({ code: "account_inactive", status: 403 });
  });
});

// ============================================================================
// HTTP DISPATCH (handleWebAuthn) — the §4.4 route surface
// ============================================================================

function req(method: string, body?: unknown): Request {
  return new Request("https://gw.local/v1/auth/webauthn/x", {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

describe("handleWebAuthn dispatch", () => {
  let ctx: ReturnType<typeof makeDeps>;
  const routeCtx = { account: ACCOUNT };
  beforeEach(() => {
    ctx = makeDeps();
  });

  it("POST register/options returns creation options + challengeId for a session", async () => {
    const res = await handleWebAuthn(req("POST"), ctx.deps, ["register", "options"], routeCtx);
    expect(res!.status).toBe(200);
    const body = (await res!.json()) as { rp: { id: string }; challengeId: string };
    expect(body.rp.id).toBe(RP_ID);
    expect(body.challengeId).toBeTruthy();
  });

  it("POST register/options without a session is 401", async () => {
    const res = await handleWebAuthn(req("POST"), ctx.deps, ["register", "options"], {});
    expect(res!.status).toBe(401);
    expect((await res!.json()) as { error: string }).toMatchObject({ error: expect.any(String) });
  });

  it("full register -> verify over HTTP stores the credential (201)", async () => {
    const optsRes = await handleWebAuthn(req("POST"), ctx.deps, ["register", "options"], routeCtx);
    const opts = (await optsRes!.json()) as { challenge: string; challengeId: string };
    const auth = await makeAuthenticator();
    const attestation = await auth.makeAttestationResponse(opts.challenge);
    const verifyRes = await handleWebAuthn(
      req("POST", { challengeId: opts.challengeId, response: attestation, label: "My Mac" }),
      ctx.deps,
      ["register", "verify"],
      routeCtx,
    );
    expect(verifyRes!.status).toBe(201);
    const body = (await verifyRes!.json()) as { credentialId: string; label: string };
    expect(body.label).toBe("My Mac");
    expect(await ctx.store.getWebAuthnByCredentialId(body.credentialId)).toBeTruthy();
  });

  it("full authenticate -> verify over HTTP mints a session + sets cfs_session cookie", async () => {
    const { auth } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const optsRes = await handleWebAuthn(req("POST", { email: ACCOUNT.email }), ctx.deps, ["authenticate", "options"]);
    const opts = (await optsRes!.json()) as { challenge: string; challengeId: string };
    const assertion = await auth.makeAssertionResponse(opts.challenge, { signCount: 3 });
    const verifyRes = await handleWebAuthn(
      req("POST", { challengeId: opts.challengeId, response: assertion }),
      ctx.deps,
      ["authenticate", "verify"],
    );
    expect(verifyRes!.status).toBe(200);
    expect(verifyRes!.headers.get("set-cookie")).toContain("cfs_session=");
    const body = (await verifyRes!.json()) as { userId: string; orgId: string; csrf: string };
    expect(body.userId).toBe(ACCOUNT.userId);
    expect(body.orgId).toBe(ACCOUNT.orgId);
    expect(body.csrf).toBeTruthy();
  });

  it("GET credentials lists the caller's passkeys (public shape, no publicKey field)", async () => {
    await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const res = await handleWebAuthn(req("GET"), ctx.deps, ["credentials"], routeCtx);
    expect(res!.status).toBe(200);
    const list = (await res!.json()) as Array<Record<string, unknown>>;
    expect(list).toHaveLength(1);
    expect(list[0]).not.toHaveProperty("publicKey");
    expect(list[0]).not.toHaveProperty("accountId");
    expect(list[0]).toHaveProperty("credentialId");
  });

  it("DELETE credentials/:id removes a passkey the caller owns (204)", async () => {
    const { cred } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const res = await handleWebAuthn(req("DELETE"), ctx.deps, ["credentials", cred.id], routeCtx);
    expect(res!.status).toBe(204);
    expect(await ctx.store.getWebAuthnByCredentialId(cred.credentialId)).toBeNull();
  });

  it("DELETE credentials/:id for a credential the caller does NOT own is 404 (no IDOR)", async () => {
    const { cred } = await registerPasskey(ctx.deps, ctx.setChallenge, 0);
    const otherCtx = { account: { ...ACCOUNT, id: "acc-2", userId: "usr-2" } };
    const res = await handleWebAuthn(req("DELETE"), ctx.deps, ["credentials", cred.id], otherCtx);
    expect(res!.status).toBe(404);
    // still present
    expect(await ctx.store.getWebAuthnByCredentialId(cred.credentialId)).toBeTruthy();
  });

  it("returns null for an unmatched route so integration can 404", async () => {
    const res = await handleWebAuthn(req("POST"), ctx.deps, ["bogus"], routeCtx);
    expect(res).toBeNull();
  });

  it("surfaces ceremony failures as JSON errors with the right status", async () => {
    const res = await handleWebAuthn(
      req("POST", { challengeId: "nope", response: {} }),
      ctx.deps,
      ["authenticate", "verify"],
    );
    expect(res!.status).toBe(400);
    expect((await res!.json()) as { error: string }).toHaveProperty("error");
  });
});

// ============================================================================
// helpers / unit edges
// ============================================================================

describe("toPublicCredential", () => {
  it("omits the secret publicKey + internal accountId, keeps display fields", () => {
    const c: WebAuthnCredential = {
      id: "wac-1",
      accountId: "acc-1",
      credentialId: "cred-abc",
      publicKey: "SECRET-COSE",
      signCount: 9,
      transports: ["internal"],
      label: "Phone",
      createdAt: 1,
      lastUsedAt: 2,
    };
    const pub = toPublicCredential(c) as Record<string, unknown>;
    expect(pub).not.toHaveProperty("publicKey");
    expect(pub).not.toHaveProperty("accountId");
    expect(pub).not.toHaveProperty("signCount");
    expect(pub.credentialId).toBe("cred-abc");
    expect(pub.label).toBe("Phone");
  });
});

describe("WebAuthnError", () => {
  it("carries an arbitrary status + code (escape hatch from AuthError's 401/403)", () => {
    const e = new WebAuthnError("dup", 409, "credential_exists");
    expect(e.status).toBe(409);
    expect(e.code).toBe("credential_exists");
    expect(e).toBeInstanceOf(Error);
  });
});
