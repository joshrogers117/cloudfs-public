// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
  createBrowserSession,
  verifySession,
  enforceCsrf,
  rotateSession,
  revokeBrowserSession,
  sessionInvalidReason,
  listSessionsPublic,
  sessionLoginResponse,
  buildSessionCookie,
  clearSessionCookie,
  readSessionCookie,
  generateCsrfToken,
  timingSafeEqualStr,
  SessionError,
  SESSION_COOKIE,
  CSRF_HEADER,
  CSRF_TOKEN_BYTES,
  ABSOLUTE_LIFETIME_MS,
  IDLE_TIMEOUT_MS,
  type BrowserSession,
  type SessionStore,
} from "../src/security/auth-session";
import { verifyToken, type Scope } from "../src/security/auth";

const SECRET = "test-session-signing-secret-32-chars-min";
const ENV = { AUTH_SIGNING_SECRET: SECRET };
const SCOPES: Scope[] = ["fs:read", "fs:write"];

/// In-memory SessionStore for deterministic unit tests. Mirrors the AuthDO `sessions` table:
/// PK id, index account_id. `revokedSessionJtis()` returns ids of revoked-or-dead rows.
class FakeSessionStore implements SessionStore {
  rows = new Map<string, BrowserSession>();
  private seq = 0;

  async createSession(input: {
    accountId: string;
    userId: string;
    orgId: string;
    scopes: Scope[];
    csrfToken: string;
    expiresAt: number;
  }): Promise<BrowserSession> {
    const id = `sess-${++this.seq}`;
    const now = input.expiresAt - ABSOLUTE_LIFETIME_MS;
    const s: BrowserSession = {
      id,
      accountId: input.accountId,
      userId: input.userId,
      orgId: input.orgId,
      scopes: input.scopes,
      csrfToken: input.csrfToken,
      issuedAt: now,
      expiresAt: input.expiresAt,
      lastSeenAt: now,
      revokedAt: null,
    };
    this.rows.set(id, s);
    return { ...s };
  }
  async getSession(sessionId: string): Promise<BrowserSession | null> {
    const s = this.rows.get(sessionId);
    return s ? { ...s } : null;
  }
  async touchSession(sessionId: string, lastSeenAt: number): Promise<void> {
    const s = this.rows.get(sessionId);
    if (s) s.lastSeenAt = lastSeenAt;
  }
  async revokeSession(sessionId: string): Promise<void> {
    const s = this.rows.get(sessionId);
    if (s && s.revokedAt === null) s.revokedAt = Date.now();
  }
  async listSessions(accountId: string): Promise<BrowserSession[]> {
    return [...this.rows.values()].filter((s) => s.accountId === accountId).map((s) => ({ ...s }));
  }
  async revokedSessionJtis(): Promise<Set<string>> {
    return new Set([...this.rows.values()].filter((s) => s.revokedAt !== null).map((s) => s.id));
  }
}

function cookieReq(sessionId: string | null, csrf?: string): Request {
  const headers: Record<string, string> = {};
  if (sessionId !== null) headers["cookie"] = `${SESSION_COOKIE}=${sessionId}; other=1`;
  if (csrf !== undefined) headers[CSRF_HEADER] = csrf;
  return new Request("https://gw.local/v1/auth/me", { headers });
}

const ACCOUNT = { accountId: "acc-1", userId: "usr-1", orgId: "org-1", scopes: SCOPES };

describe("createBrowserSession", () => {
  it("creates a session bound to account+org+scopes with a 12h absolute expiry + CSRF", async () => {
    const store = new FakeSessionStore();
    const s = await createBrowserSession(store, ACCOUNT, 10_000);
    expect(s.id).toMatch(/^sess-/);
    expect(s.userId).toBe("usr-1");
    expect(s.orgId).toBe("org-1");
    expect(s.scopes).toEqual(SCOPES);
    expect(s.expiresAt).toBe(10_000 + ABSOLUTE_LIFETIME_MS);
    expect(s.revokedAt).toBeNull();
    // CSRF token is 32 random bytes base64url -> non-empty, url-safe
    expect(s.csrfToken.length).toBeGreaterThan(0);
    expect(s.csrfToken).not.toMatch(/[+/=]/);
  });
});

describe("sessionInvalidReason (policy)", () => {
  const base: BrowserSession = {
    id: "sess-x",
    accountId: "acc-1",
    userId: "usr-1",
    orgId: "org-1",
    scopes: SCOPES,
    csrfToken: "csrf",
    issuedAt: 0,
    expiresAt: ABSOLUTE_LIFETIME_MS,
    lastSeenAt: 0,
    revokedAt: null,
  };

  it("null session => not_found", () => {
    expect(sessionInvalidReason(null, 1000)).toBe("not_found");
  });
  it("live session within bounds => null (valid)", () => {
    expect(sessionInvalidReason(base, 1000)).toBeNull();
  });
  it("revoked session => revoked", () => {
    expect(sessionInvalidReason({ ...base, revokedAt: 500 }, 1000)).toBe("revoked");
  });
  it("past absolute expiry => expired", () => {
    expect(sessionInvalidReason(base, ABSOLUTE_LIFETIME_MS + 1)).toBe("expired");
  });
  it("idle beyond the idle timeout => idle", () => {
    // lastSeenAt=0, now = IDLE_TIMEOUT_MS exactly => idle (>=)
    expect(sessionInvalidReason(base, IDLE_TIMEOUT_MS)).toBe("idle");
  });
  it("active just under the idle timeout => valid", () => {
    expect(sessionInvalidReason(base, IDLE_TIMEOUT_MS - 1)).toBeNull();
  });
});

describe("verifySession (verify + rotate the JWS)", () => {
  it("verifies a live session cookie, mints a session JWS with jti==session.id, slides idle", async () => {
    const store = new FakeSessionStore();
    const s = await createBrowserSession(store, ACCOUNT, 1_000);
    const later = 1_000 + 5 * 60 * 1000; // 5 min later
    const req = cookieReq(s.id);
    const res = await verifySession(req, store, ENV, { now: later });

    expect(res.session.id).toBe(s.id);
    expect(res.session.lastSeenAt).toBe(later); // slid forward
    // persisted
    expect((await store.getSession(s.id))!.lastSeenAt).toBe(later);

    // The minted JWS verifies back to a Principal bound to the session's identity, jti==id.
    const principal = await verifyToken(SECRET, res.jws, {}, later);
    expect(principal.sub).toBe("usr-1");
    expect(principal.orgId).toBe("org-1");
    expect(principal.type).toBe("session");
    expect(principal.jti).toBe(s.id);
    expect(principal.scopes).toEqual(SCOPES);

    // remaining seconds is the absolute window minus elapsed
    expect(res.remainingSeconds).toBe(Math.floor((s.expiresAt - later) / 1000));
  });

  it("throws no_session when the cookie is absent", async () => {
    const store = new FakeSessionStore();
    await expect(verifySession(cookieReq(null), store, ENV, { now: 1 })).rejects.toMatchObject({
      code: "no_session",
      status: 401,
    });
  });

  it("throws not_found for an unknown session id", async () => {
    const store = new FakeSessionStore();
    await expect(verifySession(cookieReq("sess-nope"), store, ENV, { now: 1 })).rejects.toMatchObject({
      code: "not_found",
    });
  });

  it("rejects a revoked session", async () => {
    const store = new FakeSessionStore();
    const s = await createBrowserSession(store, ACCOUNT, 1_000);
    await store.revokeSession(s.id);
    await expect(verifySession(cookieReq(s.id), store, ENV, { now: 2_000 })).rejects.toMatchObject({
      code: "revoked",
    });
  });

  it("rejects a session past its absolute lifetime", async () => {
    const store = new FakeSessionStore();
    const s = await createBrowserSession(store, ACCOUNT, 1_000);
    await expect(
      verifySession(cookieReq(s.id), store, ENV, { now: s.expiresAt + 1 }),
    ).rejects.toMatchObject({ code: "expired" });
  });

  it("rejects an idle session (unused beyond the idle timeout)", async () => {
    const store = new FakeSessionStore();
    const s = await createBrowserSession(store, ACCOUNT, 1_000);
    await expect(
      verifySession(cookieReq(s.id), store, ENV, { now: 1_000 + IDLE_TIMEOUT_MS }),
    ).rejects.toMatchObject({ code: "idle" });
  });

  it("clamps the JWS TTL to the remaining absolute lifetime near the cap", async () => {
    const store = new FakeSessionStore();
    const s = await createBrowserSession(store, ACCOUNT, 1_000);
    // 10s before absolute expiry: residual JWS must not outlive the absolute window.
    // The session must be recently active (not idle), so touch it just before the check.
    const near = s.expiresAt - 10_000;
    await store.touchSession(s.id, near - 1_000); // active 1s ago -> not idle
    const res = await verifySession(cookieReq(s.id), store, ENV, { now: near });
    const principal = await verifyToken(SECRET, res.jws, {}, near);
    // exp - iat <= 10s (clamped), well below the 15-min default
    expect(principal.exp - principal.iat).toBeLessThanOrEqual(10);
    expect(principal.exp - principal.iat).toBeGreaterThan(0);
  });

  it("uses an injected mintFn (no real signing secret needed)", async () => {
    const store = new FakeSessionStore();
    const s = await createBrowserSession(store, ACCOUNT, 1_000);
    let captured: unknown = null;
    const fakeMint = (async (_secret: string, opts: unknown) => {
      captured = opts;
      return "fake.jws.token";
    }) as unknown as typeof import("../src/security/auth").mintToken;
    const res = await verifySession(cookieReq(s.id), store, ENV, { now: 2_000, mintFn: fakeMint });
    expect(res.jws).toBe("fake.jws.token");
    expect(captured).toMatchObject({ sub: "usr-1", type: "session", jti: s.id });
  });
});

describe("enforceCsrf (double-submit)", () => {
  it("passes when the header matches the session CSRF token", async () => {
    const store = new FakeSessionStore();
    const s = await createBrowserSession(store, ACCOUNT, 1_000);
    expect(() => enforceCsrf(cookieReq(s.id, s.csrfToken), s)).not.toThrow();
  });

  it("rejects when the header is missing", async () => {
    const store = new FakeSessionStore();
    const s = await createBrowserSession(store, ACCOUNT, 1_000);
    expect(() => enforceCsrf(cookieReq(s.id), s)).toThrow(SessionError);
    try {
      enforceCsrf(cookieReq(s.id), s);
    } catch (e) {
      expect((e as SessionError).code).toBe("csrf");
      expect((e as SessionError).status).toBe(403);
    }
  });

  it("rejects when the header does not match", async () => {
    const store = new FakeSessionStore();
    const s = await createBrowserSession(store, ACCOUNT, 1_000);
    expect(() => enforceCsrf(cookieReq(s.id, "wrong-token"), s)).toThrow(SessionError);
  });
});

describe("rotateSession (anti-fixation)", () => {
  it("revokes the old session and issues a new one with the same binding + new CSRF", async () => {
    const store = new FakeSessionStore();
    const old = await createBrowserSession(store, ACCOUNT, 1_000);
    const fresh = await rotateSession(store, old.id, 5_000);

    expect(fresh.id).not.toBe(old.id);
    expect(fresh.csrfToken).not.toBe(old.csrfToken);
    expect(fresh.userId).toBe(old.userId);
    expect(fresh.orgId).toBe(old.orgId);
    expect(fresh.scopes).toEqual(old.scopes);
    expect(fresh.expiresAt).toBe(5_000 + ABSOLUTE_LIFETIME_MS);

    // old is revoked; it now fails verification
    await expect(verifySession(cookieReq(old.id), store, ENV, { now: 6_000 })).rejects.toMatchObject({
      code: "revoked",
    });
  });

  it("throws not_found rotating an unknown session", async () => {
    const store = new FakeSessionStore();
    await expect(rotateSession(store, "sess-nope", 1)).rejects.toMatchObject({ code: "not_found" });
  });
});

describe("revoke + revokedSessionJtis", () => {
  it("revoking a session adds its id to the revoked-jti set", async () => {
    const store = new FakeSessionStore();
    const s = await createBrowserSession(store, ACCOUNT, 1_000);
    expect(await store.revokedSessionJtis()).not.toContain(s.id);
    await revokeBrowserSession(store, s.id);
    const revoked = await store.revokedSessionJtis();
    expect(revoked.has(s.id)).toBe(true);
  });

  it("revoke is idempotent / safe for an absent session", async () => {
    const store = new FakeSessionStore();
    await expect(revokeBrowserSession(store, "sess-missing")).resolves.toBeUndefined();
  });
});

describe("listSessionsPublic", () => {
  it("lists the account's sessions, strips CSRF, and marks the current one", async () => {
    const store = new FakeSessionStore();
    const a = await createBrowserSession(store, ACCOUNT, 1_000);
    const b = await createBrowserSession(store, ACCOUNT, 2_000);
    // a different account's session must not appear
    await createBrowserSession(store, { ...ACCOUNT, accountId: "acc-2", userId: "usr-2" }, 3_000);

    const list = await listSessionsPublic(store, "acc-1", b.id);
    expect(list.map((s) => s.id).sort()).toEqual([a.id, b.id].sort());
    // no csrf field on the public projection
    expect(JSON.stringify(list)).not.toContain("csrf");
    const current = list.find((s) => s.id === b.id)!;
    const other = list.find((s) => s.id === a.id)!;
    expect(current.current).toBe(true);
    expect(other.current).toBe(false);
  });
});

describe("cookie helpers", () => {
  it("buildSessionCookie sets HttpOnly, Secure, SameSite=Lax, Path=/, and Max-Age", () => {
    const c = buildSessionCookie("sess-abc", 3600);
    expect(c).toContain(`${SESSION_COOKIE}=sess-abc`);
    expect(c).toContain("HttpOnly");
    expect(c).toContain("Secure");
    expect(c).toContain("SameSite=Lax");
    expect(c).toContain("Path=/");
    expect(c).toContain("Max-Age=3600");
  });

  it("buildSessionCookie floors and clamps Max-Age to >= 0", () => {
    expect(buildSessionCookie("x", -50)).toContain("Max-Age=0");
    expect(buildSessionCookie("x", 12.9)).toContain("Max-Age=12");
  });

  it("clearSessionCookie expires the cookie with Max-Age=0", () => {
    const c = clearSessionCookie();
    expect(c).toContain(`${SESSION_COOKIE}=;`);
    expect(c).toContain("Max-Age=0");
    expect(c).toContain("HttpOnly");
  });

  it("readSessionCookie extracts the session id among other cookies", () => {
    const req = new Request("https://gw.local/", {
      headers: { cookie: `foo=bar; ${SESSION_COOKIE}=sess-xyz; baz=qux` },
    });
    expect(readSessionCookie(req)).toBe("sess-xyz");
  });

  it("readSessionCookie returns null when absent", () => {
    expect(readSessionCookie(new Request("https://gw.local/"))).toBeNull();
    const req = new Request("https://gw.local/", { headers: { cookie: "foo=bar" } });
    expect(readSessionCookie(req)).toBeNull();
  });
});

describe("sessionLoginResponse", () => {
  it("returns a Set-Cookie with the opaque id and the CSRF token in the body", async () => {
    const store = new FakeSessionStore();
    const s = await createBrowserSession(store, ACCOUNT, 1_000);
    const out = sessionLoginResponse(s, 1_000);
    expect(out.setCookie).toContain(`${SESSION_COOKIE}=${s.id}`);
    expect(out.csrf).toBe(s.csrfToken);
    expect(out.body.csrf).toBe(s.csrfToken);
    // Max-Age reflects the full 12h window at issue time
    expect(out.setCookie).toContain(`Max-Age=${Math.floor(ABSOLUTE_LIFETIME_MS / 1000)}`);
  });
});

describe("generateCsrfToken + timingSafeEqualStr", () => {
  it("generateCsrfToken yields a unique url-safe token of the configured entropy", () => {
    const a = generateCsrfToken();
    const b = generateCsrfToken();
    expect(a).not.toBe(b);
    expect(a).not.toMatch(/[+/=]/);
    // 32 bytes base64url -> ceil(32*4/3) = 43 chars (unpadded)
    expect(a.length).toBe(Math.ceil((CSRF_TOKEN_BYTES * 4) / 3));
  });

  it("timingSafeEqualStr compares equal strings true, unequal/length-mismatch false", () => {
    expect(timingSafeEqualStr("abc123", "abc123")).toBe(true);
    expect(timingSafeEqualStr("abc123", "abc124")).toBe(false);
    expect(timingSafeEqualStr("abc", "abcd")).toBe(false);
    expect(timingSafeEqualStr("", "")).toBe(true);
  });
});
