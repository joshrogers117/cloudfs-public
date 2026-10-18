// SPDX-License-Identifier: AGPL-3.0-or-later
// signup-mode.test.ts — SIGNUP_MODE deployment gate (src/signup-mode.ts + auth-wiring).
//
// Part 1 (pure): the gate function over every mode/branch.
// Part 2 (integration): drive POST /v1/auth/signup through the REAL worker for each mode by
//   flipping env.SIGNUP_MODE per test (the gate reads env at request time). Asserts the typed
//   403 codes (signup_disabled / domain_not_allowed) and that a valid path still 201s.

import { SELF, env } from "cloudflare:test";
import { describe, it, expect, afterEach } from "vitest";
import {
  evaluateSignupGate,
  resolveSignupMode,
  parseAllowedDomains,
  parseInviteTokens,
  isValidInviteToken,
  constantTimeEqual,
  emailDomain,
  shouldRefuseOpenSignupOnHttps,
  DEFAULT_SIGNUP_MODE,
} from "../src/signup-mode";

// ---------------------------------------------------------------------------------------
// Audit B7 — insecure-open-signup tripwire (the committed dev config ships SIGNUP_MODE=open)
// ---------------------------------------------------------------------------------------
describe("B7: refuse SIGNUP_MODE=open on an https deployment without explicit opt-in", () => {
  it("REFUSES open signup over https when SIGNUP_OPEN_ON_HTTPS is unset", () => {
    expect(shouldRefuseOpenSignupOnHttps({ SIGNUP_MODE: "open" }, true)).toBe(true);
  });
  it("ALLOWS open signup over https when explicitly opted in", () => {
    expect(shouldRefuseOpenSignupOnHttps({ SIGNUP_MODE: "open", SIGNUP_OPEN_ON_HTTPS: "1" }, true)).toBe(false);
    expect(shouldRefuseOpenSignupOnHttps({ SIGNUP_MODE: "open", SIGNUP_OPEN_ON_HTTPS: "true" }, true)).toBe(false);
  });
  it("ALLOWS open signup over http (localhost dev) regardless of opt-in", () => {
    expect(shouldRefuseOpenSignupOnHttps({ SIGNUP_MODE: "open" }, false)).toBe(false);
  });
  it("does not interfere with non-open modes (invite/domain/closed never tripped)", () => {
    expect(shouldRefuseOpenSignupOnHttps({ SIGNUP_MODE: "invite" }, true)).toBe(false);
    expect(shouldRefuseOpenSignupOnHttps({ SIGNUP_MODE: "domain" }, true)).toBe(false);
    expect(shouldRefuseOpenSignupOnHttps({}, true)).toBe(false); // default = invite
  });
});

// ---------------------------------------------------------------------------------------
// Part 1 — pure gate
// ---------------------------------------------------------------------------------------

describe("resolveSignupMode", () => {
  it("defaults to 'invite' when unset or unrecognized (fail closed)", () => {
    expect(resolveSignupMode({})).toBe("invite");
    expect(resolveSignupMode({ SIGNUP_MODE: "" })).toBe("invite");
    expect(resolveSignupMode({ SIGNUP_MODE: "garbage" })).toBe("invite");
    expect(DEFAULT_SIGNUP_MODE).toBe("invite");
  });
  it("accepts the four valid modes case-insensitively", () => {
    expect(resolveSignupMode({ SIGNUP_MODE: "closed" })).toBe("closed");
    expect(resolveSignupMode({ SIGNUP_MODE: "INVITE" })).toBe("invite");
    expect(resolveSignupMode({ SIGNUP_MODE: " Domain " })).toBe("domain");
    expect(resolveSignupMode({ SIGNUP_MODE: "open" })).toBe("open");
  });
});

describe("helpers", () => {
  it("parseAllowedDomains normalizes, splits, and tolerates a leading @", () => {
    const set = parseAllowedDomains(" Acme.com, @example.org\nfoo.io ");
    expect([...set].sort()).toEqual(["acme.com", "example.org", "foo.io"]);
    expect(parseAllowedDomains(undefined).size).toBe(0);
  });
  it("emailDomain extracts the part after the last @", () => {
    expect(emailDomain("a@b.com")).toBe("b.com");
    expect(emailDomain("weird@x@host.io")).toBe("host.io");
    expect(emailDomain("nope")).toBe("");
  });
  it("parseInviteTokens splits on commas/space/newlines and drops blanks", () => {
    expect(parseInviteTokens("a, b\nc  d")).toEqual(["a", "b", "c", "d"]);
    expect(parseInviteTokens("")).toEqual([]);
  });
  it("constantTimeEqual compares correctly", () => {
    expect(constantTimeEqual("hunter2", "hunter2")).toBe(true);
    expect(constantTimeEqual("hunter2", "hunter3")).toBe(false);
    expect(constantTimeEqual("short", "longerstring")).toBe(false);
  });
  it("isValidInviteToken matches any configured token, false when none/empty", () => {
    expect(isValidInviteToken("t2", ["t1", "t2", "t3"])).toBe(true);
    expect(isValidInviteToken("nope", ["t1", "t2"])).toBe(false);
    expect(isValidInviteToken("t1", [])).toBe(false);
    expect(isValidInviteToken(undefined, ["t1"])).toBe(false);
  });
});

describe("evaluateSignupGate — per mode", () => {
  it("open: anyone may sign up", () => {
    expect(evaluateSignupGate({ SIGNUP_MODE: "open" }, { email: "x@y.com" })).toEqual({ allowed: true, mode: "open" });
  });

  it("closed: always blocked with signup_disabled", () => {
    expect(evaluateSignupGate({ SIGNUP_MODE: "closed" }, { email: "x@y.com", inviteToken: "anything" })).toEqual({
      allowed: false,
      mode: "closed",
      status: 403,
      code: "signup_disabled",
    });
  });

  it("invite: allows a valid token, blocks a missing/bad one with signup_disabled", () => {
    const env = { SIGNUP_MODE: "invite", SIGNUP_INVITE_TOKENS: "good-1, good-2" };
    expect(evaluateSignupGate(env, { email: "x@y.com", inviteToken: "good-2" })).toEqual({ allowed: true, mode: "invite" });
    expect(evaluateSignupGate(env, { email: "x@y.com", inviteToken: "bad" })).toMatchObject({ allowed: false, code: "signup_disabled" });
    expect(evaluateSignupGate(env, { email: "x@y.com" })).toMatchObject({ allowed: false, code: "signup_disabled" });
  });

  it("invite: with NO configured tokens, everyone is blocked (fail closed)", () => {
    expect(evaluateSignupGate({ SIGNUP_MODE: "invite" }, { email: "x@y.com", inviteToken: "whatever" })).toMatchObject({
      allowed: false,
      code: "signup_disabled",
    });
  });

  it("domain: allows an allowed domain, blocks others with domain_not_allowed", () => {
    const env = { SIGNUP_MODE: "domain", SIGNUP_ALLOWED_DOMAINS: "acme.com, example.org" };
    expect(evaluateSignupGate(env, { email: "alice@acme.com" })).toEqual({ allowed: true, mode: "domain" });
    expect(evaluateSignupGate(env, { email: "bob@EXAMPLE.ORG" })).toEqual({ allowed: true, mode: "domain" });
    expect(evaluateSignupGate(env, { email: "mallory@evil.com" })).toMatchObject({ allowed: false, code: "domain_not_allowed" });
  });

  it("domain: with NO allowed domains configured, everyone is blocked (fail closed)", () => {
    expect(evaluateSignupGate({ SIGNUP_MODE: "domain" }, { email: "x@y.com" })).toMatchObject({
      allowed: false,
      code: "domain_not_allowed",
    });
  });

  it("default (unset SIGNUP_MODE) behaves as invite", () => {
    expect(evaluateSignupGate({}, { email: "x@y.com" })).toMatchObject({ allowed: false, mode: "invite", code: "signup_disabled" });
    expect(evaluateSignupGate({ SIGNUP_INVITE_TOKENS: "tok" }, { email: "x@y.com", inviteToken: "tok" })).toEqual({
      allowed: true,
      mode: "invite",
    });
  });
});

// ---------------------------------------------------------------------------------------
// Part 2 — integration through the real worker (flip env.SIGNUP_MODE per test)
// ---------------------------------------------------------------------------------------

const ORIGIN = "https://gw.local";
const e = env as unknown as Record<string, string | undefined>;
const ORIGINAL = {
  SIGNUP_MODE: e.SIGNUP_MODE,
  SIGNUP_ALLOWED_DOMAINS: e.SIGNUP_ALLOWED_DOMAINS,
  SIGNUP_INVITE_TOKENS: e.SIGNUP_INVITE_TOKENS,
};

afterEach(() => {
  // Restore so other suites (which expect the wrangler.jsonc "open" default) are unaffected.
  e.SIGNUP_MODE = ORIGINAL.SIGNUP_MODE;
  e.SIGNUP_ALLOWED_DOMAINS = ORIGINAL.SIGNUP_ALLOWED_DOMAINS;
  e.SIGNUP_INVITE_TOKENS = ORIGINAL.SIGNUP_INVITE_TOKENS;
});

let ipCounter = 0;
function freshIp(): string {
  ipCounter++;
  return `198.51.${Math.floor(ipCounter / 256) % 256}.${ipCounter % 256}`;
}
let emailCounter = 0;
function uniqueEmail(domain = "example.test"): string {
  return `signup-${Date.now()}-${emailCounter++}@${domain}`;
}

async function signup(body: Record<string, unknown>): Promise<Response> {
  return SELF.fetch(`${ORIGIN}/v1/auth/signup`, {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": freshIp() },
    body: JSON.stringify({
      orgName: "Mode Org",
      password: "correct horse battery staple",
      displayName: "Mode User",
      ...body,
    }),
  });
}

describe("POST /v1/auth/signup — SIGNUP_MODE gate (real worker)", () => {
  it("open: signup succeeds (201)", async () => {
    e.SIGNUP_MODE = "open";
    const res = await signup({ email: uniqueEmail() });
    expect(res.status).toBe(201);
  });

  it("closed: signup is blocked with 403 signup_disabled", async () => {
    e.SIGNUP_MODE = "closed";
    const res = await signup({ email: uniqueEmail() });
    expect(res.status).toBe(403);
    expect((await res.json() as any).error).toBe("signup_disabled");
  });

  it("invite: blocked without a token, succeeds with a valid token", async () => {
    e.SIGNUP_MODE = "invite";
    e.SIGNUP_INVITE_TOKENS = "alpha-invite, beta-invite";

    const blocked = await signup({ email: uniqueEmail() });
    expect(blocked.status).toBe(403);
    expect((await blocked.json() as any).error).toBe("signup_disabled");

    const bad = await signup({ email: uniqueEmail(), inviteToken: "wrong" });
    expect(bad.status).toBe(403);

    const ok = await signup({ email: uniqueEmail(), inviteToken: "beta-invite" });
    expect(ok.status).toBe(201);
  });

  it("domain: blocks a disallowed domain, allows an allowed one", async () => {
    e.SIGNUP_MODE = "domain";
    e.SIGNUP_ALLOWED_DOMAINS = "allowed-co.test";

    const blocked = await signup({ email: uniqueEmail("evil.test") });
    expect(blocked.status).toBe(403);
    expect((await blocked.json() as any).error).toBe("domain_not_allowed");

    const ok = await signup({ email: uniqueEmail("allowed-co.test") });
    expect(ok.status).toBe(201);
  });

  it("the gate runs BEFORE provisioning: a blocked signup does not create the org/email", async () => {
    e.SIGNUP_MODE = "closed";
    const email = uniqueEmail();
    const blocked = await signup({ email });
    expect(blocked.status).toBe(403);
    // The same email can now sign up once the mode opens (it was never claimed).
    e.SIGNUP_MODE = "open";
    const ok = await signup({ email });
    expect(ok.status).toBe(201);
  });
});
