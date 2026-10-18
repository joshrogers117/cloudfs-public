// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, beforeEach } from "vitest";
import {
  handleSignup,
  handleLogin,
  handleLoginTotp,
  handleLoginRecovery,
  assertEmailVerified,
  signupErrorResponse,
  canonicalEmail,
  SignupError,
  SIGNUP_IP_LIMIT,
  SIGNUP_EMAIL_LIMIT,
  LOGIN_IP_LIMIT,
  LOGIN_EMAIL_LIMIT,
  MFA_CHALLENGE_TTL_SECONDS,
  MFA_MAX_ATTEMPTS,
  type SignupDeps,
  type SignupLimiters,
  type AccountStore,
  type OrgProvisioner,
  type Account,
  type AccountRole,
} from "../src/security/auth-signup";
import {
  type PasswordStore,
  type PasswordCredential,
  setPassword,
} from "../src/security/auth-password";
import {
  type SessionStore,
  type BrowserSession,
} from "../src/security/auth-session";
import {
  FakeEmailSender,
  type EmailTokenStore,
  type EmailTokenRecord,
} from "../src/security/auth-email";
import {
  type TotpCredentialStore,
  type TotpCredential,
  base32Encode,
  totp,
  hashRecoveryCode,
} from "../src/security/auth-totp";
import {
  RateLimiter,
  InMemoryRateLimitStore,
  type RateLimitConfig,
} from "../src/security/ratelimit";

// =======================================================================================
// In-memory fakes (deterministic; no DO, no network)
// =======================================================================================

let uuidCounter = 0;
function nextUuid(): string {
  return `uuid-${(uuidCounter++).toString().padStart(4, "0")}`;
}

class MemAccountStore implements AccountStore {
  accounts = new Map<string, Account>();
  /// global directory: emailLower -> {orgId, accountId}
  directory = new Map<string, { orgId: string; accountId: string }>();
  /// fault injection: throw this on the next createAccount.
  createFault: Error | null = null;

  resolveEmail(emailLower: string): Promise<{ orgId: string; accountId: string } | null> {
    return Promise.resolve(this.directory.get(emailLower) ?? null);
  }
  createAccount(input: {
    orgId: string;
    userId: string;
    email: string;
    displayName: string;
    role: AccountRole;
    emailVerified?: boolean;
  }): Promise<Account> {
    if (this.createFault) {
      const e = this.createFault;
      this.createFault = null;
      return Promise.reject(e);
    }
    // Authoritative dedupe: claim the email globally or throw.
    if (this.directory.has(input.email)) {
      return Promise.reject(new Error("email_taken"));
    }
    const account: Account = {
      id: `acc-${nextUuid()}`,
      userId: input.userId,
      orgId: input.orgId,
      email: input.email,
      displayName: input.displayName,
      role: input.role,
      status: "active",
      emailVerified: input.emailVerified ?? false,
      createdAt: 0,
    };
    this.accounts.set(account.id, account);
    this.directory.set(input.email, { orgId: input.orgId, accountId: account.id });
    return Promise.resolve({ ...account });
  }
  getAccount(accountId: string): Promise<Account | null> {
    const a = this.accounts.get(accountId);
    return Promise.resolve(a ? { ...a } : null);
  }
  getAccountByUserId(userId: string): Promise<Account | null> {
    for (const a of this.accounts.values()) {
      if (a.userId === userId) return Promise.resolve({ ...a });
    }
    return Promise.resolve(null);
  }
}

class MemOrgProvisioner implements OrgProvisioner {
  created: Array<{ orgName: string; ownerEmail: string; ownerDisplayName: string }> = [];
  createOrgWithOwner(input: {
    orgName: string;
    ownerEmail: string;
    ownerDisplayName: string;
  }): Promise<{ orgId: string; userId: string }> {
    this.created.push(input);
    return Promise.resolve({ orgId: `org-${nextUuid()}`, userId: `usr-${nextUuid()}` });
  }
}

class MemPasswordStore implements PasswordStore {
  rows = new Map<string, PasswordCredential>();
  getPassword(accountId: string): Promise<PasswordCredential | null> {
    const r = this.rows.get(accountId);
    return Promise.resolve(r ? { ...r } : null);
  }
  putPassword(cred: PasswordCredential): Promise<void> {
    this.rows.set(cred.accountId, { ...cred });
    return Promise.resolve();
  }
  deletePassword(accountId: string): Promise<void> {
    this.rows.delete(accountId);
    return Promise.resolve();
  }
}

class MemSessionStore implements SessionStore {
  rows = new Map<string, BrowserSession>();
  createSession(input: {
    accountId: string;
    userId: string;
    orgId: string;
    scopes: BrowserSession["scopes"];
    csrfToken: string;
    expiresAt: number;
  }): Promise<BrowserSession> {
    const s: BrowserSession = {
      id: `sess-${nextUuid()}`,
      accountId: input.accountId,
      userId: input.userId,
      orgId: input.orgId,
      scopes: input.scopes,
      csrfToken: input.csrfToken,
      issuedAt: 0,
      expiresAt: input.expiresAt,
      lastSeenAt: 0,
      revokedAt: null,
    };
    this.rows.set(s.id, { ...s });
    return Promise.resolve({ ...s });
  }
  getSession(id: string): Promise<BrowserSession | null> {
    const s = this.rows.get(id);
    return Promise.resolve(s ? { ...s } : null);
  }
  touchSession(id: string, lastSeenAt: number): Promise<void> {
    const s = this.rows.get(id);
    if (s) s.lastSeenAt = lastSeenAt;
    return Promise.resolve();
  }
  revokeSession(id: string): Promise<void> {
    const s = this.rows.get(id);
    if (s) s.revokedAt = 1;
    return Promise.resolve();
  }
  listSessions(accountId: string): Promise<BrowserSession[]> {
    return Promise.resolve([...this.rows.values()].filter((s) => s.accountId === accountId).map((s) => ({ ...s })));
  }
  revokedSessionJtis(): Promise<Set<string>> {
    return Promise.resolve(new Set([...this.rows.values()].filter((s) => s.revokedAt !== null).map((s) => s.id)));
  }
}

class MemEmailTokenStore implements EmailTokenStore {
  rows = new Map<string, EmailTokenRecord>();
  put(rec: EmailTokenRecord): Promise<void> {
    this.rows.set(rec.id, { ...rec });
    return Promise.resolve();
  }
  get(id: string): Promise<EmailTokenRecord | null> {
    const r = this.rows.get(id);
    return Promise.resolve(r ? { ...r } : null);
  }
  consume(id: string, consumedAt: number): Promise<boolean> {
    const r = this.rows.get(id);
    if (!r || r.consumedAt !== null) return Promise.resolve(false);
    r.consumedAt = consumedAt;
    return Promise.resolve(true);
  }
  invalidateOutstanding(): Promise<void> {
    return Promise.resolve();
  }
}

class MemTotpStore implements TotpCredentialStore {
  creds = new Map<string, TotpCredential>();
  recovery = new Map<string, Array<{ codeHash: string; usedAt: number | null }>>();
  challenges = new Map<string, { accountId: string | null; purpose: string; value: string; expiresAt: number }>();

  getTotp(accountId: string): Promise<TotpCredential | null> {
    const c = this.creds.get(accountId);
    return Promise.resolve(c ? { ...c } : null);
  }
  putTotp(cred: TotpCredential): Promise<void> {
    this.creds.set(cred.accountId, { ...cred });
    return Promise.resolve();
  }
  confirmTotp(accountId: string, confirmedAt: number): Promise<void> {
    const c = this.creds.get(accountId);
    if (c) {
      c.confirmed = true;
      c.confirmedAt = confirmedAt;
    }
    return Promise.resolve();
  }
  deleteTotp(accountId: string): Promise<void> {
    this.creds.delete(accountId);
    return Promise.resolve();
  }
  putRecoveryCodes(accountId: string, codeHashes: string[]): Promise<void> {
    this.recovery.set(accountId, codeHashes.map((codeHash) => ({ codeHash, usedAt: null })));
    return Promise.resolve();
  }
  consumeRecoveryCode(accountId: string, codeHash: string, usedAt: number): Promise<boolean> {
    const list = this.recovery.get(accountId) ?? [];
    const match = list.find((r) => r.codeHash === codeHash && r.usedAt === null);
    if (!match) return Promise.resolve(false);
    match.usedAt = usedAt;
    return Promise.resolve(true);
  }
  beginTotpEnrollment(cred: TotpCredential): Promise<boolean> {
    if (this.creds.get(cred.accountId)?.confirmed) return Promise.resolve(false);
    this.creds.set(cred.accountId, { ...cred });
    return Promise.resolve(true);
  }
  completeTotpEnrollment(accountId: string, secret: string, confirmedAt: number, step: number,
      expiresAt: number, recoveryHashes: string[]): Promise<boolean> {
    const cred = this.creds.get(accountId);
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
  putChallenge(c: { id: string; accountId: string | null; purpose: string; value: string; expiresAt: number }): Promise<void> {
    this.challenges.set(c.id, { accountId: c.accountId, purpose: c.purpose, value: c.value, expiresAt: c.expiresAt });
    return Promise.resolve();
  }
  takeChallenge(id: string): Promise<{ accountId: string | null; purpose: string; value: string; expiresAt: number } | null> {
    const c = this.challenges.get(id);
    if (!c) return Promise.resolve(null);
    this.challenges.delete(id); // single-use
    return Promise.resolve({ ...c });
  }
}

/// Minimal passkey-read fake satisfying the login lane's `LoginWebAuthnStore` slice.
class MemWebAuthnStore {
  creds = new Map<string, unknown[]>();
  listWebAuthn(accountId: string): Promise<unknown[]> {
    return Promise.resolve(this.creds.get(accountId) ?? []);
  }
  /// Register N fake passkeys for an account (only the count matters to login).
  addPasskeys(accountId: string, n = 1): void {
    this.creds.set(accountId, Array.from({ length: n }, (_v, i) => ({ id: `wac-${accountId}-${i}` })));
  }
}

// =======================================================================================
// Test harness: build a SignupDeps with generous limits (so non-rate-limit tests pass) and a
// frozen clock. Individual tests can swap limiters/clock.
// =======================================================================================

const NOW = 1_700_000_000_000; // fixed epoch ms.
const FAST_PASSWORD = { N: 2, r: 8, p: 1, dkLen: 32 }; // cheap scrypt for test speed.

function generousLimiters(): SignupLimiters {
  const big: RateLimitConfig = { capacity: 1000, refillPerSec: 1000 };
  return {
    signupIp: new RateLimiter(new InMemoryRateLimitStore(), big),
    signupEmail: new RateLimiter(new InMemoryRateLimitStore(), big),
    loginIp: new RateLimiter(new InMemoryRateLimitStore(), big),
    loginEmail: new RateLimiter(new InMemoryRateLimitStore(), big),
  };
}

interface Harness {
  deps: SignupDeps;
  accounts: MemAccountStore;
  org: MemOrgProvisioner;
  passwords: MemPasswordStore;
  sessions: MemSessionStore;
  emailTokens: MemEmailTokenStore;
  emailSender: FakeEmailSender;
  totp: MemTotpStore;
  webauthn: MemWebAuthnStore;
  verifyUrls: string[];
}

function makeHarness(over: Partial<SignupDeps> = {}): Harness {
  const accounts = new MemAccountStore();
  const org = new MemOrgProvisioner();
  const passwords = new MemPasswordStore();
  const sessions = new MemSessionStore();
  const emailTokens = new MemEmailTokenStore();
  // delivers:true — this fake stands in for a REAL provider so the happy path reports
  // emailSent:true (the production no-op fake defaults to delivers:false; B11).
  const emailSender = new FakeEmailSender({ delivers: true });
  const totp = new MemTotpStore();
  const webauthn = new MemWebAuthnStore();
  const verifyUrls: string[] = [];
  const deps: SignupDeps = {
    accounts,
    org,
    passwords,
    sessions,
    emailTokens,
    emailSender,
    totp,
    webauthn,
    limiters: generousLimiters(),
    buildVerifyUrl: (token) => {
      const url = `https://app.cloud-fs.test/verify?token=${token}`;
      verifyUrls.push(url);
      return url;
    },
    productName: "cloud-fs",
    // Cheap scrypt cost for the signup/login FLOW (mirrors seedAccount's FAST_PASSWORD) so these
    // unit tests don't pay the full OWASP default (N=2^17) per hash. Exercises the `scryptCost`
    // injection seam too. Override-able via `over`.
    scryptCost: FAST_PASSWORD,
    now: () => NOW,
    ...over,
  };
  return { deps, accounts, org, passwords, sessions, emailTokens, emailSender, totp, webauthn, verifyUrls };
}

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("https://gw.cloud-fs.test/v1/auth/x", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.7", ...headers },
    body: JSON.stringify(body),
  });
}

const VALID_SIGNUP = {
  orgName: "Acme Editorial",
  email: "Owner@Acme.example",
  password: "correct horse battery staple",
  displayName: "Acme Owner",
};

/// Seed an account + password directly with cheap scrypt (FAST_PASSWORD) for login tests. The
/// harness's signup/login FLOW also runs at FAST cost via deps.scryptCost (see makeHarness), so the
/// seeded credential's params match the flow's rehash target (no spurious rehash on login).
async function seedAccount(
  h: Harness,
  opts: {
    email?: string;
    password?: string;
    role?: AccountRole;
    status?: Account["status"];
    emailVerified?: boolean;
  } = {},
): Promise<Account> {
  const email = canonicalEmail(opts.email ?? "user@example.com");
  const account = await h.accounts.createAccount({
    orgId: "org-seed",
    userId: "usr-seed",
    email,
    displayName: "Seed User",
    role: opts.role ?? "standard",
    emailVerified: opts.emailVerified ?? true,
  });
  if (opts.status) {
    h.accounts.accounts.get(account.id)!.status = opts.status;
  }
  await setPassword(h.passwords, account.id, opts.password ?? "hunter2hunter2", { cost: FAST_PASSWORD, now: NOW });
  return account;
}

/// Attach a confirmed TOTP credential to an account; return its base32 secret.
function seedTotp(h: Harness, accountId: string): string {
  const secretBytes = new Uint8Array(20).fill(7); // deterministic.
  const secret = base32Encode(secretBytes);
  h.totp.creds.set(accountId, { accountId, secret, confirmed: true, createdAt: NOW, confirmedAt: NOW });
  return secret;
}

function currentTotpCode(secretBase32: string, now: number): string {
  // Mirror auth-totp's base32 -> bytes; we re-derive the code at `now`.
  const bytes = base32Decode(secretBase32);
  return totp(bytes, Math.floor(now / 1000));
}

// local base32 decode mirroring the module (kept tiny; the module's decode is also exported but
// we want zero coupling to its error type here).
function base32Decode(input: string): Uint8Array {
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.toUpperCase().replace(/=+$/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    value = (value << 5) | ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

beforeEach(() => {
  uuidCounter = 0;
});

// =======================================================================================
// SIGNUP
// =======================================================================================

describe("handleSignup", () => {
  it("creates org + owner account (unverified), hashes password, sends verification, sets session cookie", async () => {
    const h = makeHarness();
    const res = await handleSignup(req(VALID_SIGNUP), h.deps);

    expect(res.status).toBe(201);
    expect(res.body.state).toBe("verify_email");
    expect(res.body.emailSent).toBe(true);
    expect(res.body.orgId).toBeTruthy();
    expect(res.body.accountId).toBeTruthy();
    expect(res.body.userId).toBeTruthy();
    expect(res.body.csrf).toBeTruthy();

    // Org provisioned with canonical (lowercased) email.
    expect(h.org.created).toHaveLength(1);
    expect(h.org.created[0].ownerEmail).toBe("owner@acme.example");
    expect(h.org.created[0].orgName).toBe("Acme Editorial");

    // Account is owner + unverified.
    const account = h.accounts.accounts.get(res.body.accountId)!;
    expect(account.role).toBe("owner");
    expect(account.emailVerified).toBe(false);
    expect(account.email).toBe("owner@acme.example");

    // Email claimed in the directory.
    expect(await h.accounts.resolveEmail("owner@acme.example")).toEqual({
      orgId: res.body.orgId,
      accountId: res.body.accountId,
    });

    // Password hashed (scrypt, not plaintext).
    const cred = h.passwords.rows.get(account.id)!;
    expect(cred.algo).toBe("scrypt");
    expect(cred.hash).not.toContain(VALID_SIGNUP.password);

    // Verification email sent with a link.
    expect(h.emailSender.sent).toHaveLength(1);
    expect(h.emailSender.last!.subject).toContain("Verify your email");
    expect(h.verifyUrls).toHaveLength(1);
    expect(h.verifyUrls[0]).toContain("token=");

    // Session cookie set (signed-in but gated).
    expect(res.setCookie).toContain("cfs_session=");
    expect(res.setCookie).toContain("HttpOnly");
    expect(res.setCookie).toContain("Secure");
    expect(h.sessions.rows.size).toBe(1);
  });

  it("the new owner's session scopes are REDUCED (read-only) while email is unverified (gate, approach b)", async () => {
    const h = makeHarness();
    await handleSignup(req(VALID_SIGNUP), h.deps);
    const session = [...h.sessions.rows.values()][0];
    // Unverified at signup => reduced read-only scopes only; no write/admin until verified.
    expect(session.scopes).toEqual(["fs:read", "snapshot:read"]);
    expect(session.scopes).not.toContain("fs:admin");
    expect(session.scopes).not.toContain("fs:write");
    expect(session.scopes).not.toContain("audit:read");
  });

  it("rejects a duplicate email with 409 email_taken (pre-check)", async () => {
    const h = makeHarness();
    await handleSignup(req(VALID_SIGNUP), h.deps);
    await expect(handleSignup(req(VALID_SIGNUP), h.deps)).rejects.toMatchObject({
      status: 409,
      code: "email_taken",
    });
  });

  it("rejects a duplicate email even when resolveEmail misses but createAccount races (authoritative dedupe)", async () => {
    const h = makeHarness();
    // Simulate a concurrent claim: directory pre-check passes but createAccount throws.
    h.accounts.directory.set("owner@acme.example", { orgId: "other", accountId: "acc-other" });
    // Make resolveEmail lie (return null) to force the race path, then createAccount rejects.
    h.accounts.resolveEmail = () => Promise.resolve(null);
    await expect(handleSignup(req(VALID_SIGNUP), h.deps)).rejects.toMatchObject({
      status: 409,
      code: "email_taken",
    });
  });

  it("maps an unknown createAccount failure to 500 account_create_failed", async () => {
    const h = makeHarness();
    h.accounts.resolveEmail = () => Promise.resolve(null);
    h.accounts.createFault = new Error("DO unavailable");
    await expect(handleSignup(req(VALID_SIGNUP), h.deps)).rejects.toMatchObject({
      status: 500,
      code: "account_create_failed",
    });
  });

  it("validates body: missing/blank orgName, email, displayName, password", async () => {
    const h = makeHarness();
    await expect(handleSignup(req({ ...VALID_SIGNUP, orgName: "  " }), h.deps)).rejects.toMatchObject({ code: "invalid_org_name" });
    await expect(handleSignup(req({ ...VALID_SIGNUP, email: "not-an-email" }), h.deps)).rejects.toMatchObject({ code: "invalid_email" });
    await expect(handleSignup(req({ ...VALID_SIGNUP, displayName: "" }), h.deps)).rejects.toMatchObject({ code: "invalid_display_name" });
    await expect(handleSignup(req({ ...VALID_SIGNUP, password: 123 as unknown as string }), h.deps)).rejects.toMatchObject({ code: "weak_password" });
  });

  it("rejects a too-short password with 400 weak_password BEFORE provisioning an org", async () => {
    const h = makeHarness();
    await expect(handleSignup(req({ ...VALID_SIGNUP, password: "short" }), h.deps)).rejects.toMatchObject({
      status: 400,
      code: "weak_password",
    });
    // No org orphaned, no email claimed.
    expect(h.org.created).toHaveLength(0);
    expect(h.accounts.directory.size).toBe(0);
  });

  it("rejects malformed JSON with 400 invalid_json", async () => {
    const h = makeHarness();
    const bad = new Request("https://gw/x", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.7" },
      body: "{not json",
    });
    await expect(handleSignup(bad, h.deps)).rejects.toMatchObject({ status: 400, code: "invalid_json" });
  });

  it("enforces per-IP signup rate limit (429 with Retry-After)", async () => {
    const limiters = generousLimiters();
    limiters.signupIp = new RateLimiter(new InMemoryRateLimitStore(), SIGNUP_IP_LIMIT);
    const h = makeHarness({ limiters });
    // Burst capacity is 3; the 4th from the same IP (different emails) is denied.
    for (let i = 0; i < SIGNUP_IP_LIMIT.capacity; i++) {
      await handleSignup(req({ ...VALID_SIGNUP, email: `u${i}@acme.example` }), h.deps);
    }
    await expect(
      handleSignup(req({ ...VALID_SIGNUP, email: "u99@acme.example" }), h.deps),
    ).rejects.toMatchObject({ status: 429, code: "rate_limited" });
  });

  it("enforces per-EMAIL signup rate limit independent of IP", async () => {
    const limiters = generousLimiters();
    limiters.signupEmail = new RateLimiter(new InMemoryRateLimitStore(), SIGNUP_EMAIL_LIMIT);
    const h = makeHarness({ limiters });
    // capacity 2 for the same email; vary the IP so the IP bucket never trips.
    // First attempt succeeds (creates account); subsequent attempts hit the email bucket.
    await handleSignup(req(VALID_SIGNUP, { "cf-connecting-ip": "1.1.1.1" }), h.deps);
    // Second attempt: email bucket has 1 token left, but the account already exists -> 409 (not 429).
    await expect(handleSignup(req(VALID_SIGNUP, { "cf-connecting-ip": "2.2.2.2" }), h.deps)).rejects.toMatchObject({ status: 409 });
    // Third attempt: email bucket now empty -> 429 before the dedupe check.
    await expect(handleSignup(req(VALID_SIGNUP, { "cf-connecting-ip": "3.3.3.3" }), h.deps)).rejects.toMatchObject({ status: 429, code: "rate_limited" });
  });

  it("the issued email token is a valid verify_email record bound to the account", async () => {
    const h = makeHarness();
    const res = await handleSignup(req(VALID_SIGNUP), h.deps);
    const tokens = [...h.emailTokens.rows.values()];
    expect(tokens).toHaveLength(1);
    expect(tokens[0].purpose).toBe("verify_email");
    expect(tokens[0].accountId).toBe(res.body.accountId);
    expect(tokens[0].email).toBe("owner@acme.example");
    expect(tokens[0].consumedAt).toBeNull();
    // The clear secret is in the link but NOT stored (only the hash).
    expect(h.verifyUrls[0]).toContain(tokens[0].id);
  });
});

// =======================================================================================
// LOGIN (password -> session)
// =======================================================================================

describe("handleLogin (no MFA)", () => {
  it("verifies password and mints a session", async () => {
    const h = makeHarness();
    await seedAccount(h, { email: "a@b.com", password: "hunter2hunter2", role: "admin" });

    const res = await handleLogin(req({ email: "A@B.com", password: "hunter2hunter2" }), h.deps);
    expect(res.kind).toBe("session");
    if (res.kind !== "session") throw new Error("unreachable");
    expect(res.status).toBe(200);
    expect(res.body.role).toBe("admin");
    expect(res.body.scopes).toContain("fs:admin");
    expect(res.body.csrf).toBeTruthy();
    expect(res.setCookie).toContain("cfs_session=");
    expect(h.sessions.rows.size).toBe(1);
  });

  it("login succeeds even when the account email is unverified (verification gates privileged actions, not login)", async () => {
    const h = makeHarness();
    await seedAccount(h, { email: "u@x.com", password: "hunter2hunter2", emailVerified: false });
    const res = await handleLogin(req({ email: "u@x.com", password: "hunter2hunter2" }), h.deps);
    expect(res.kind).toBe("session");
  });

  // ---- fix #2: unverified email => reduced (read-only) session scopes ------------------

  it("an UNVERIFIED account gets REDUCED read-only scopes (no write/admin) — the gate", async () => {
    const h = makeHarness();
    await seedAccount(h, { email: "unv@x.com", password: "hunter2hunter2", role: "admin", emailVerified: false });
    const res = await handleLogin(req({ email: "unv@x.com", password: "hunter2hunter2" }), h.deps);
    if (res.kind !== "session") throw new Error("expected session");
    expect(res.body.scopes).toEqual(["fs:read", "snapshot:read"]);
    expect(res.body.scopes).not.toContain("fs:write");
    expect(res.body.scopes).not.toContain("fs:admin");
  });

  it("a VERIFIED account gets its FULL role scopes (gate lifts after verification)", async () => {
    const h = makeHarness();
    await seedAccount(h, { email: "v@x.com", password: "hunter2hunter2", role: "admin", emailVerified: true });
    const res = await handleLogin(req({ email: "v@x.com", password: "hunter2hunter2" }), h.deps);
    if (res.kind !== "session") throw new Error("expected session");
    expect(res.body.scopes).toContain("fs:admin");
    expect(res.body.scopes).toContain("fs:write");
  });

  it("wrong password -> generic 401 invalid_credentials", async () => {
    const h = makeHarness();
    await seedAccount(h, { email: "a@b.com", password: "hunter2hunter2" });
    await expect(handleLogin(req({ email: "a@b.com", password: "WRONG" }), h.deps)).rejects.toMatchObject({
      status: 401,
      code: "invalid_credentials",
    });
    expect(h.sessions.rows.size).toBe(0);
  });

  it("unknown email -> the SAME generic 401 invalid_credentials (no enumeration)", async () => {
    const h = makeHarness();
    await expect(handleLogin(req({ email: "ghost@nowhere.com", password: "hunter2hunter2" }), h.deps)).rejects.toMatchObject({
      status: 401,
      code: "invalid_credentials",
    });
  });

  it("suspended / deprovisioned account -> generic 401 invalid_credentials", async () => {
    const h = makeHarness();
    await seedAccount(h, { email: "s@b.com", password: "hunter2hunter2", status: "suspended" });
    await expect(handleLogin(req({ email: "s@b.com", password: "hunter2hunter2" }), h.deps)).rejects.toMatchObject({
      status: 401,
      code: "invalid_credentials",
    });
  });

  it("account with no password credential -> generic 401 (does not leak passkey-only accounts)", async () => {
    const h = makeHarness();
    // Create an account in the directory but never set a password.
    await h.accounts.createAccount({ orgId: "o", userId: "u", email: "np@b.com", displayName: "n", role: "standard", emailVerified: true });
    await expect(handleLogin(req({ email: "np@b.com", password: "whatever12345" }), h.deps)).rejects.toMatchObject({
      status: 401,
      code: "invalid_credentials",
    });
  });

  it("missing email/password fields -> 400 invalid_request", async () => {
    const h = makeHarness();
    await expect(handleLogin(req({ email: "a@b.com" }), h.deps)).rejects.toMatchObject({ status: 400, code: "invalid_request" });
    await expect(handleLogin(req({ password: "x" }), h.deps)).rejects.toMatchObject({ status: 400, code: "invalid_request" });
  });

  it("enforces per-IP login rate limit", async () => {
    const limiters = generousLimiters();
    limiters.loginIp = new RateLimiter(new InMemoryRateLimitStore(), LOGIN_IP_LIMIT);
    const h = makeHarness({ limiters });
    await seedAccount(h, { email: "a@b.com", password: "hunter2hunter2" });
    for (let i = 0; i < LOGIN_IP_LIMIT.capacity; i++) {
      await handleLogin(req({ email: "a@b.com", password: "WRONG" }), h.deps).catch(() => {});
    }
    await expect(handleLogin(req({ email: "a@b.com", password: "hunter2hunter2" }), h.deps)).rejects.toMatchObject({
      status: 429,
      code: "rate_limited",
    });
  });

  it("enforces per-EMAIL login rate limit (credential-stuffing one account)", async () => {
    const limiters = generousLimiters();
    limiters.loginEmail = new RateLimiter(new InMemoryRateLimitStore(), LOGIN_EMAIL_LIMIT);
    const h = makeHarness({ limiters });
    await seedAccount(h, { email: "a@b.com", password: "hunter2hunter2" });
    // Vary IP so only the email bucket trips. capacity 5.
    for (let i = 0; i < LOGIN_EMAIL_LIMIT.capacity; i++) {
      await handleLogin(req({ email: "a@b.com", password: "WRONG" }, { "cf-connecting-ip": `9.9.9.${i}` }), h.deps).catch(() => {});
    }
    await expect(handleLogin(req({ email: "a@b.com", password: "hunter2hunter2" }, { "cf-connecting-ip": "9.9.9.250" }), h.deps)).rejects.toMatchObject({
      status: 429,
    });
  });
});

// =======================================================================================
// LOGIN with MFA (TOTP challenge)
// =======================================================================================

describe("handleLogin (MFA required)", () => {
  it("returns an mfa challenge instead of a session when TOTP is confirmed", async () => {
    const h = makeHarness();
    const account = await seedAccount(h, { email: "m@b.com", password: "hunter2hunter2" });
    seedTotp(h, account.id);

    const res = await handleLogin(req({ email: "m@b.com", password: "hunter2hunter2" }), h.deps);
    expect(res.kind).toBe("mfa");
    if (res.kind !== "mfa") throw new Error("unreachable");
    expect(res.body.mfaRequired).toBe(true);
    expect(res.body.methods).toEqual(["totp", "recovery"]);
    expect(res.body.challengeId).toMatch(/^mfa-/);
    // No session minted yet.
    expect(h.sessions.rows.size).toBe(0);
    // Challenge persisted, bound to the account, with the right TTL.
    const ch = h.totp.challenges.get(res.body.challengeId)!;
    expect(ch.accountId).toBe(account.id);
    expect(ch.purpose).toBe("login_mfa");
    expect(ch.expiresAt).toBe(NOW + MFA_CHALLENGE_TTL_SECONDS * 1000);
  });

  it("does NOT require MFA when a TOTP credential exists but is UNCONFIRMED", async () => {
    const h = makeHarness();
    const account = await seedAccount(h, { email: "u@b.com", password: "hunter2hunter2" });
    const secretBytes = new Uint8Array(20).fill(3);
    h.totp.creds.set(account.id, { accountId: account.id, secret: base32Encode(secretBytes), confirmed: false, createdAt: NOW, confirmedAt: null });
    const res = await handleLogin(req({ email: "u@b.com", password: "hunter2hunter2" }), h.deps);
    expect(res.kind).toBe("session");
  });

  // ---- fix #1: passkey second factor must NOT be bypassed at password login -----------

  it("a PASSKEY-ONLY account (no TOTP) requires the second factor — password alone does NOT mint a session", async () => {
    const h = makeHarness();
    const account = await seedAccount(h, { email: "pk@b.com", password: "hunter2hunter2" });
    h.webauthn.addPasskeys(account.id, 1); // one registered passkey, NO TOTP

    const res = await handleLogin(req({ email: "pk@b.com", password: "hunter2hunter2" }), h.deps);
    expect(res.kind).toBe("mfa");
    if (res.kind !== "mfa") throw new Error("unreachable");
    expect(res.body.mfaRequired).toBe(true);
    expect(res.body.methods).toEqual(["webauthn"]); // only passkey available
    expect(res.body.methods).not.toContain("totp");
    // CRITICAL: no session before the second factor.
    expect(h.sessions.rows.size).toBe(0);
    // Challenge persisted, bound to the account, with the right purpose + TTL.
    const ch = h.totp.challenges.get(res.body.challengeId)!;
    expect(ch.accountId).toBe(account.id);
    expect(ch.purpose).toBe("login_mfa");
  });

  it("a TOTP-only account is unchanged: methods are ['totp','recovery'] (no webauthn)", async () => {
    const h = makeHarness();
    const account = await seedAccount(h, { email: "t@b.com", password: "hunter2hunter2" });
    seedTotp(h, account.id); // confirmed TOTP, no passkeys
    const res = await handleLogin(req({ email: "t@b.com", password: "hunter2hunter2" }), h.deps);
    expect(res.kind).toBe("mfa");
    if (res.kind !== "mfa") throw new Error("unreachable");
    expect(res.body.methods).toEqual(["totp", "recovery"]);
    expect(res.body.methods).not.toContain("webauthn");
    expect(h.sessions.rows.size).toBe(0);
  });

  it("an account with BOTH TOTP and a passkey offers both factor families", async () => {
    const h = makeHarness();
    const account = await seedAccount(h, { email: "both@b.com", password: "hunter2hunter2" });
    seedTotp(h, account.id);
    h.webauthn.addPasskeys(account.id, 2);
    const res = await handleLogin(req({ email: "both@b.com", password: "hunter2hunter2" }), h.deps);
    expect(res.kind).toBe("mfa");
    if (res.kind !== "mfa") throw new Error("unreachable");
    expect(res.body.methods).toEqual(["totp", "recovery", "webauthn"]);
    expect(h.sessions.rows.size).toBe(0);
  });

  it("an account with NEITHER factor still logs straight in (no regression)", async () => {
    const h = makeHarness();
    await seedAccount(h, { email: "none@b.com", password: "hunter2hunter2" });
    const res = await handleLogin(req({ email: "none@b.com", password: "hunter2hunter2" }), h.deps);
    expect(res.kind).toBe("session");
    expect(h.sessions.rows.size).toBe(1);
  });
});

// =======================================================================================
// LOGIN /totp (complete the challenge)
// =======================================================================================

describe("handleLoginTotp", () => {
  async function startMfa(h: Harness): Promise<{ account: Account; secret: string; challengeId: string }> {
    const account = await seedAccount(h, { email: "m@b.com", password: "hunter2hunter2" });
    const secret = seedTotp(h, account.id);
    const res = await handleLogin(req({ email: "m@b.com", password: "hunter2hunter2" }), h.deps);
    if (res.kind !== "mfa") throw new Error("expected mfa");
    return { account, secret, challengeId: res.body.challengeId };
  }

  it("completes the challenge with a valid TOTP code and mints a session", async () => {
    const h = makeHarness();
    const { challengeId, secret } = await startMfa(h);
    const code = currentTotpCode(secret, NOW);
    const res = await handleLoginTotp(req({ challengeId, code }), h.deps);
    expect(res.kind).toBe("session");
    expect(res.body.csrf).toBeTruthy();
    expect(res.setCookie).toContain("cfs_session=");
    expect(h.sessions.rows.size).toBe(1);
  });

  it("rejects a bad TOTP code (propagates 401 from the totp lane)", async () => {
    const h = makeHarness();
    const { challengeId } = await startMfa(h);
    await expect(handleLoginTotp(req({ challengeId, code: "000000" }), h.deps)).rejects.toMatchObject({ status: 401 });
    expect(h.sessions.rows.size).toBe(0);
  });

  it("rejects an unknown/expired challenge with 401 invalid_challenge", async () => {
    const h = makeHarness();
    await startMfa(h);
    await expect(handleLoginTotp(req({ challengeId: "mfa-nope", code: "123456" }), h.deps)).rejects.toMatchObject({
      status: 401,
      code: "invalid_challenge",
    });
  });

  it("B13: the challenge is BURNED after MFA_MAX_ATTEMPTS wrong codes (brute-force cap)", async () => {
    const h = makeHarness();
    const { challengeId, secret } = await startMfa(h);
    // Grind wrong codes up to the cap. Each wrong attempt restores the challenge UNTIL the
    // cap, at which point it is burned (not restored) — independent of source IP.
    for (let i = 0; i < MFA_MAX_ATTEMPTS - 1; i++) {
      await expect(handleLoginTotp(req({ challengeId, code: "000000" }), h.deps)).rejects.toMatchObject({ status: 401 });
    }
    // The final wrong attempt burns the challenge.
    await expect(handleLoginTotp(req({ challengeId, code: "000000" }), h.deps)).rejects.toMatchObject({ status: 401 });
    // Now even the CORRECT current code can't complete — the challenge is gone (invalid_challenge),
    // forcing a fresh password login. Pre-fix the challenge was restored on EVERY wrong code, so an
    // attacker with distributed IPs could grind the 6-digit space across the 5-minute window.
    const good = currentTotpCode(secret, NOW);
    await expect(handleLoginTotp(req({ challengeId, code: good }), h.deps)).rejects.toMatchObject({
      status: 401,
      code: "invalid_challenge",
    });
    expect(h.sessions.rows.size).toBe(0);
  });

  it("the challenge is single-use: replaying the same challengeId fails", async () => {
    const h = makeHarness();
    const { challengeId, secret } = await startMfa(h);
    const code = currentTotpCode(secret, NOW);
    await handleLoginTotp(req({ challengeId, code }), h.deps); // consumes the challenge
    // Even a fresh valid code can't reuse the consumed challenge.
    const code2 = currentTotpCode(secret, NOW + 31_000);
    await expect(handleLoginTotp(req({ challengeId, code: code2 }), { ...h.deps, now: () => NOW + 31_000 })).rejects.toMatchObject({
      status: 401,
      code: "invalid_challenge",
    });
  });

  it("rejects an expired challenge by clock", async () => {
    const h = makeHarness();
    const { challengeId, secret } = await startMfa(h);
    const later = NOW + (MFA_CHALLENGE_TTL_SECONDS + 1) * 1000;
    const code = currentTotpCode(secret, later);
    await expect(handleLoginTotp(req({ challengeId, code }), { ...h.deps, now: () => later })).rejects.toMatchObject({
      status: 401,
      code: "invalid_challenge",
    });
  });

  it("missing code -> 400 invalid_request", async () => {
    const h = makeHarness();
    const { challengeId } = await startMfa(h);
    await expect(handleLoginTotp(req({ challengeId }), h.deps)).rejects.toMatchObject({ status: 400, code: "invalid_request" });
  });

  // ---- fix #4: a WRONG code must NOT burn the single-use challenge ---------------------

  it("a wrong TOTP code leaves the challenge USABLE for a retry; the correct code then consumes it", async () => {
    const h = makeHarness();
    const { challengeId, secret } = await startMfa(h);

    // First attempt with a wrong code -> 401, but the challenge must survive.
    await expect(handleLoginTotp(req({ challengeId, code: "000000" }), h.deps)).rejects.toMatchObject({ status: 401 });
    expect(h.totp.challenges.has(challengeId)).toBe(true); // NOT burned
    expect(h.sessions.rows.size).toBe(0);

    // Retry the SAME challenge with the correct code -> success, and now it IS consumed.
    const code = currentTotpCode(secret, NOW);
    const ok = await handleLoginTotp(req({ challengeId, code }), h.deps);
    expect(ok.kind).toBe("session");
    expect(h.totp.challenges.has(challengeId)).toBe(false); // consumed on success
    expect(h.sessions.rows.size).toBe(1);
  });

  it("a missing-code 400 also leaves the challenge usable (bad request must not burn it)", async () => {
    const h = makeHarness();
    const { challengeId, secret } = await startMfa(h);
    await expect(handleLoginTotp(req({ challengeId }), h.deps)).rejects.toMatchObject({ status: 400 });
    expect(h.totp.challenges.has(challengeId)).toBe(true);
    // The challenge is still completable.
    const ok = await handleLoginTotp(req({ challengeId, code: currentTotpCode(secret, NOW) }), h.deps);
    expect(ok.kind).toBe("session");
  });

  it("replay after a SUCCESSFUL completion still fails (single-use on success holds)", async () => {
    const h = makeHarness();
    const { challengeId, secret } = await startMfa(h);
    await handleLoginTotp(req({ challengeId, code: currentTotpCode(secret, NOW) }), h.deps); // consume
    // A fresh valid code can't reuse the consumed challenge.
    const later = NOW + 31_000;
    await expect(
      handleLoginTotp(req({ challengeId, code: currentTotpCode(secret, later) }), { ...h.deps, now: () => later }),
    ).rejects.toMatchObject({ status: 401, code: "invalid_challenge" });
  });
});

// =======================================================================================
// LOGIN /recovery (complete the challenge with a recovery code)
// =======================================================================================

describe("handleLoginRecovery", () => {
  it("completes the challenge with a valid one-time recovery code and mints a session", async () => {
    const h = makeHarness();
    const account = await seedAccount(h, { email: "r@b.com", password: "hunter2hunter2" });
    seedTotp(h, account.id);
    const recoveryCode = "ABCDE12345";
    await h.totp.putRecoveryCodes(account.id, [hashRecoveryCode(recoveryCode)]);

    const login = await handleLogin(req({ email: "r@b.com", password: "hunter2hunter2" }), h.deps);
    if (login.kind !== "mfa") throw new Error("expected mfa");

    const res = await handleLoginRecovery(req({ challengeId: login.body.challengeId, recoveryCode }), h.deps);
    expect(res.kind).toBe("session");
    expect(h.sessions.rows.size).toBe(1);
  });

  it("a recovery code is single-use", async () => {
    const h = makeHarness();
    const account = await seedAccount(h, { email: "r2@b.com", password: "hunter2hunter2" });
    seedTotp(h, account.id);
    const recoveryCode = "ZZZZZ99999";
    await h.totp.putRecoveryCodes(account.id, [hashRecoveryCode(recoveryCode)]);

    const login1 = await handleLogin(req({ email: "r2@b.com", password: "hunter2hunter2" }), h.deps);
    if (login1.kind !== "mfa") throw new Error("expected mfa");
    await handleLoginRecovery(req({ challengeId: login1.body.challengeId, recoveryCode }), h.deps);

    // Second login + same recovery code is rejected (code consumed).
    const login2 = await handleLogin(req({ email: "r2@b.com", password: "hunter2hunter2" }), h.deps);
    if (login2.kind !== "mfa") throw new Error("expected mfa");
    await expect(handleLoginRecovery(req({ challengeId: login2.body.challengeId, recoveryCode }), h.deps)).rejects.toMatchObject({ status: 401 });
  });

  it("missing recoveryCode -> 400 invalid_request", async () => {
    const h = makeHarness();
    const account = await seedAccount(h, { email: "r3@b.com", password: "hunter2hunter2" });
    seedTotp(h, account.id);
    const login = await handleLogin(req({ email: "r3@b.com", password: "hunter2hunter2" }), h.deps);
    if (login.kind !== "mfa") throw new Error("expected mfa");
    await expect(handleLoginRecovery(req({ challengeId: login.body.challengeId }), h.deps)).rejects.toMatchObject({ status: 400 });
  });
});

// =======================================================================================
// Email verification gate + helpers
// =======================================================================================

describe("assertEmailVerified gate", () => {
  it("throws 403 email_unverified for an unverified account", () => {
    expect(() => assertEmailVerified({ emailVerified: false })).toThrowError(SignupError);
    try {
      assertEmailVerified({ emailVerified: false });
    } catch (e) {
      expect((e as SignupError).status).toBe(403);
      expect((e as SignupError).code).toBe("email_unverified");
    }
  });
  it("passes for a verified account", () => {
    expect(() => assertEmailVerified({ emailVerified: true })).not.toThrow();
  });
});

describe("helpers", () => {
  it("canonicalEmail trims + lowercases", () => {
    expect(canonicalEmail("  Owner@Acme.COM ")).toBe("owner@acme.com");
  });

  it("signupErrorResponse builds the {error} JSON with status; Retry-After on 429", async () => {
    const r1 = signupErrorResponse(new SignupError("x", 409, "email_taken"));
    expect(r1.status).toBe(409);
    expect(await r1.json()).toEqual({ error: "email_taken" });

    const r2 = signupErrorResponse(new SignupError("x", 429, "rate_limited", 42));
    expect(r2.status).toBe(429);
    expect(r2.headers.get("Retry-After")).toBe("42");
  });
});
