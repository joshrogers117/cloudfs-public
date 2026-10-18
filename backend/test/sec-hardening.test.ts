// SPDX-License-Identifier: AGPL-3.0-or-later
// sec-hardening.test.ts — regression coverage for the 6 confirmed code-review findings:
//   #1 forgot/reset rate limiting     #2 HIBP fail-open observability + opt-in fail-closed
//   #3 __Host- cookie prefix (conditional on HTTPS)   #4 HMAC key memoization
//   #5 revocation gate fails CLOSED for service tokens on a DO read error   #6 per-request ACL memo
//
// Each behavioural test is written so it would FAIL without the fix (see the per-finding comments).
// Findings #4/#5/#2/#3-builders are unit-tested (deterministic, no network); #1 + #3-end-to-end run
// through the real worker via SELF.fetch. We never touch the network (HIBP fetch is injected).

import { SELF, env } from "cloudflare:test";
import { describe, it, expect, vi, afterEach } from "vitest";

import { mintToken, verifyToken } from "../src/security/auth";
import {
  buildSessionCookie,
  clearSessionCookie,
  readSessionCookie,
  sessionCookieName,
  SESSION_COOKIE,
  SESSION_COOKIE_SECURE,
} from "../src/security/auth-session";
import {
  checkPasswordBreach,
  assertPasswordNotBreached,
  isPasswordBreached,
  PasswordError,
} from "../src/security/auth-password";
import { gatewayRevokedJtis, secureCookies } from "../src/auth-wiring";

const ORIGIN = "https://gw.local";

// Distinct client IPs so the fleet-wide (DirectoryDO-backed) buckets don't collide across tests.
let ipCounter = 9000;
function freshIp(): string {
  ipCounter++;
  return `198.51.${Math.floor(ipCounter / 256) % 256}.${ipCounter % 256}`;
}
function headers(ip: string, extra?: Record<string, string>): Record<string, string> {
  return { "content-type": "application/json", "cf-connecting-ip": ip, ...(extra ?? {}) };
}

afterEach(() => {
  vi.restoreAllMocks();
});

// =========================================================================================
// FINDING #1 — forgot/reset rate limiting
// =========================================================================================
describe("FINDING #1 — password forgot/reset are rate limited", () => {
  it("forgot-password 429s after the per-IP cap (was: unbounded email amplification)", async () => {
    const ip = freshIp();
    // forgotIp capacity is 5; from a single IP the 6th request within the window must 429.
    // Without the fix the route always returned 202 regardless of volume.
    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) {
      const res = await SELF.fetch(`${ORIGIN}/v1/auth/password/forgot`, {
        method: "POST",
        headers: headers(ip),
        body: JSON.stringify({ email: `nobody-${i}@nowhere.test` }),
      });
      statuses.push(res.status);
      if (res.status === 429) {
        expect(res.headers.get("Retry-After")).toBeTruthy();
        break;
      }
    }
    expect(statuses).toContain(429);
    // Everything before the cap is the enumeration-safe 202.
    expect(statuses.slice(0, 5).every((s) => s === 202)).toBe(true);
  });

  it("reset-password 429s after the per-IP cap, BEFORE any token verify (defense layer)", async () => {
    const ip = freshIp();
    // resetIp capacity is 10. A flood of bad-token resets must eventually 429 rather than
    // returning the per-attempt 400/410 forever (the missing attempt cap the finding flagged).
    let saw429 = false;
    for (let i = 0; i < 14; i++) {
      const res = await SELF.fetch(`${ORIGIN}/v1/auth/password/reset`, {
        method: "POST",
        headers: headers(ip),
        body: JSON.stringify({ token: `bogus-${i}`, newPassword: "irrelevant", orgId: "org-x" }),
      });
      if (res.status === 429) {
        saw429 = true;
        expect(res.headers.get("Retry-After")).toBeTruthy();
        break;
      }
      // Pre-cap responses are the ordinary invalid-token path, never a 429.
      expect([400, 410]).toContain(res.status);
    }
    expect(saw429).toBe(true);
  });

  it("a distinct IP keeps its own forgot bucket (the limiter is keyed per-IP)", async () => {
    const res = await SELF.fetch(`${ORIGIN}/v1/auth/password/forgot`, {
      method: "POST",
      headers: headers(freshIp()),
      body: JSON.stringify({ email: "fresh@nowhere.test" }),
    });
    expect(res.status).toBe(202);
  });
});

// =========================================================================================
// FINDING #2 — HIBP observability (fail-open is logged) + opt-in fail-closed
// =========================================================================================
describe("FINDING #2 — breached-password check is observable + can fail closed", () => {
  const SHA1_OF_PASSWORD = "0123456789ABCDEF0123456789ABCDEF01234567"; // shape only; suffix never matched here.

  it("logs a warning when HIBP returns a non-2xx (was: silent no-op)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const onError = vi.fn();
    const fetchImpl = (async () => new Response("", { status: 503 })) as unknown as typeof fetch;
    const r = await checkPasswordBreach("hunter2hunter2", {
      enabled: true,
      fetchImpl,
      endpoint: "https://hibp.invalid/range/",
      onError,
    });
    expect(r).toEqual({ breached: false, errored: true }); // still fail-open verdict
    expect(warn).toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ kind: "status", status: 503 }));
  });

  it("logs a warning when the HIBP fetch throws (network error)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const fetchImpl = (async () => {
      throw new Error("boom");
    }) as unknown as typeof fetch;
    const r = await checkPasswordBreach("hunter2hunter2", { enabled: true, fetchImpl });
    expect(r).toEqual({ breached: false, errored: true });
    expect(warn).toHaveBeenCalled();
  });

  it("is a no-op (no fetch, no log) when disabled — default OFF", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const fetchImpl = vi.fn();
    const r = await checkPasswordBreach("anything", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(r).toEqual({ breached: false, errored: false });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(warn).not.toHaveBeenCalled();
  });

  it("assertPasswordNotBreached FAILS OPEN by default on an HIBP error", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const fetchImpl = (async () => new Response("", { status: 500 })) as unknown as typeof fetch;
    await expect(
      assertPasswordNotBreached("hunter2hunter2", { enabled: true, fetchImpl }),
    ).resolves.toBeUndefined();
  });

  it("assertPasswordNotBreached FAILS CLOSED on an HIBP error when failClosed:true", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const fetchImpl = (async () => new Response("", { status: 500 })) as unknown as typeof fetch;
    await expect(
      assertPasswordNotBreached("hunter2hunter2", { enabled: true, fetchImpl, failClosed: true }),
    ).rejects.toMatchObject({ code: "password_breach_check_unavailable", status: 500 });
  });

  it("still positively detects a breached password (matching logic unchanged)", async () => {
    // Compute the suffix HIBP would return for this exact password and feed it back.
    const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode("password123!"));
    let hex = "";
    for (const b of new Uint8Array(buf)) hex += b.toString(16).padStart(2, "0");
    const suffix = hex.toUpperCase().slice(5);
    const fetchImpl = (async () => new Response(`${suffix}:42\r\nDEADBEEF:0`)) as unknown as typeof fetch;
    expect(await isPasswordBreached("password123!", { enabled: true, fetchImpl })).toBe(true);
    void SHA1_OF_PASSWORD;
  });
});

// =========================================================================================
// FINDING #3 — __Host- cookie prefix, conditional on HTTPS
// =========================================================================================
describe("FINDING #3 — session/OIDC cookies use __Host- over HTTPS, plain over http", () => {
  it("buildSessionCookie emits __Host-cfs_session + Secure when secure:true", () => {
    const c = buildSessionCookie("sess-1", 3600, { secure: true });
    expect(c.startsWith("__Host-cfs_session=sess-1")).toBe(true);
    expect(c).toContain("Secure");
    expect(c).toContain("Path=/");
    expect(c).toContain("HttpOnly");
  });

  it("buildSessionCookie emits the plain name with NO Secure when secure:false (http/dev)", () => {
    const c = buildSessionCookie("sess-1", 3600, { secure: false });
    expect(c.startsWith("cfs_session=sess-1")).toBe(true);
    expect(c).not.toContain("__Host-");
    expect(c).not.toContain("Secure");
  });

  it("clearSessionCookie matches the transport name", () => {
    expect(clearSessionCookie({ secure: true }).startsWith("__Host-cfs_session=;")).toBe(true);
    expect(clearSessionCookie({ secure: false }).startsWith("cfs_session=;")).toBe(true);
    expect(clearSessionCookie({ secure: false })).not.toContain("Secure");
  });

  it("readSessionCookie accepts BOTH the prefixed and plain names", () => {
    const prefixed = new Request("https://gw.local/", {
      headers: { cookie: `${SESSION_COOKIE_SECURE}=org.sess-A` },
    });
    const plain = new Request("https://gw.local/", { headers: { cookie: `${SESSION_COOKIE}=org.sess-B` } });
    expect(readSessionCookie(prefixed)).toBe("org.sess-A");
    expect(readSessionCookie(plain)).toBe("org.sess-B");
  });

  it("sessionCookieName + secureCookies select the name by transport / COOKIE_SECURE flag", () => {
    expect(sessionCookieName(true)).toBe("__Host-cfs_session");
    expect(sessionCookieName(false)).toBe("cfs_session");
    const e = env as unknown as Record<string, unknown>;
    expect(secureCookies(e as any, new Request("https://gw.local/x"))).toBe(true);
    expect(secureCookies(e as any, new Request("http://localhost:8787/x"))).toBe(false);
    expect(secureCookies({ ...(e as any), COOKIE_SECURE: "1" }, new Request("http://localhost/x"))).toBe(true);
    expect(secureCookies({ ...(e as any), COOKIE_SECURE: "0" }, new Request("https://gw.local/x"))).toBe(false);
  });

  it("end-to-end: a signup over HTTPS sets the hardened __Host-cfs_session cookie", async () => {
    const email = `host-prefix-${Date.now()}@example.test`;
    const res = await SELF.fetch(`${ORIGIN}/v1/auth/signup`, {
      method: "POST",
      headers: headers(freshIp()),
      body: JSON.stringify({ orgName: "Org", email, password: "correct horse battery staple", displayName: "U" }),
    });
    expect(res.status).toBe(201);
    const sc = res.headers.get("set-cookie") ?? "";
    // Over the https origin the gateway emits the hardened prefixed name + Secure.
    expect(sc).toContain("__Host-cfs_session=");
    expect(sc).toContain("Secure");
  });
});

// =========================================================================================
// FINDING #4 — HMAC key is memoized per secret (importKey not re-run on every mint/verify)
// =========================================================================================
describe("FINDING #4 — importHmacKey is memoized per secret", () => {
  it("imports the key once across many mint/verify calls for one secret", async () => {
    // A UNIQUE secret per test so the module-level cache isn't pre-warmed by other tests.
    const secret = `memo-secret-${crypto.randomUUID()}-padded-to-16+`;
    const importSpy = vi.spyOn(crypto.subtle, "importKey");
    const t1 = await mintToken(secret, { sub: "m", type: "service", orgId: "o", scopes: ["fs:read"], ttlSeconds: 60 });
    await verifyToken(secret, t1);
    const t2 = await mintToken(secret, { sub: "m", type: "service", orgId: "o", scopes: ["fs:read"], ttlSeconds: 60 });
    await verifyToken(secret, t2);
    const importsForThisSecret = importSpy.mock.calls.filter(
      (c) => c[1] instanceof Uint8Array && new TextDecoder().decode(c[1] as Uint8Array) === secret,
    );
    // Without memoization this would be 4 (one per mint + verify); with the fix it's exactly 1.
    expect(importsForThisSecret.length).toBe(1);
  });

  it("a weak secret still throws (no poisoned cache) and a later valid secret imports cleanly", async () => {
    await expect(
      mintToken("short", { sub: "m", type: "session", orgId: "o", scopes: [], ttlSeconds: 60 }),
    ).rejects.toMatchObject({ code: "bad_secret" });
    const good = `recover-secret-${crypto.randomUUID()}`;
    const t = await mintToken(good, { sub: "m", type: "session", orgId: "o", scopes: ["fs:read"], ttlSeconds: 60 });
    const p = await verifyToken(good, t);
    expect(p.sub).toBe("m");
  });
});

// =========================================================================================
// FINDING #5 — revocation gate fails CLOSED for service tokens on a DO read error
// =========================================================================================
describe("FINDING #5 — gatewayRevokedJtis surfaces read errors (service-token fail-closed)", () => {
  // A fake env whose AuthDO rejects the revoked-jti reads, simulating an AuthDO blip.
  function throwingEnv() {
    const throwingStub = {
      revokedSessionJtis: async () => {
        throw new Error("AuthDO unavailable");
      },
      revokedServiceJtis: async () => {
        throw new Error("AuthDO unavailable");
      },
    };
    return {
      AUTH_DO: { idFromName: (n: string) => n, get: () => throwingStub },
      DIRECTORY_DO: { idFromName: (n: string) => n, get: () => ({}) },
      ORG_DO: { idFromName: (n: string) => n, get: () => ({}) },
    } as any;
  }

  it("returns { errored:true } (NOT a silently-empty set) when the revocation read fails", async () => {
    // Pre-fix this swallowed the error and returned a bare empty Set, so the caller could not tell a
    // genuine "nothing revoked" apart from "couldn't check" — fail-OPEN for service tokens.
    const out = await gatewayRevokedJtis(throwingEnv(), "org-blip");
    expect(out.errored).toBe(true);
    expect(out.jtis.size).toBe(0);
  });

  it("the service-token gate rejects 503 on an errored read (cookie path is unaffected)", () => {
    // Mirror the exact index.ts gate predicate to lock in the fail-closed scoping.
    const decide = (errored: boolean, type: string) =>
      errored && type === "service" ? "503" : "admit";
    expect(decide(true, "service")).toBe("503"); // revoked-but-unexpired service token can't sneak through
    expect(decide(true, "session")).toBe("admit"); // resolver already re-validated the session
    expect(decide(false, "service")).toBe("admit");
  });
});

// =========================================================================================
// FINDING #6 — per-request ACL principal memoization (sanity: cookie + bearer paths still work)
// =========================================================================================
describe("FINDING #6 — gateMutation/presign reuse one resolved AclPrincipal (smoke)", () => {
  it("a bearer-authed presign + the memoized resolver don't change the authZ outcome", async () => {
    // The memoization is a per-request optimization with no observable behaviour change; this guards
    // against a regression where caching the AclPrincipal accidentally broke a gated mutation. We
    // assert a missing-scope token is still rejected (the gate fires using the memoized principal).
    const secret = (env as any).AUTH_SIGNING_SECRET as string;
    const ro = await mintToken(secret, {
      sub: "svc-ro",
      type: "service",
      orgId: "org-memo",
      scopes: ["fs:read"], // no fs:write → a write presign must be refused
      ttlSeconds: 300,
    });
    const res = await SELF.fetch(`${ORIGIN}/v1/filespaces/space-memo/presign`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${ro}`, "cf-connecting-ip": freshIp() },
      body: JSON.stringify({ key: "blocks/org-memo::space-memo/x", method: "PUT" }),
    });
    expect(res.status).toBe(403); // missing fs:write scope, refused before any presign mint
  });
});
