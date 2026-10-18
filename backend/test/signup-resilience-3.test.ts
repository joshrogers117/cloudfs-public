// SPDX-License-Identifier: AGPL-3.0-or-later
//
// R1 (RESILIENCE) — signup email-send failure must NOT strand a half-created account.
//
// Before the fix, `handleSignup` committed org+account+global-email-claim+password+token and then
// `await sendVerificationEmail(...)` LAST. Any provider error (the real Resend/Postmark/SES senders
// throw on a non-2xx / network failure) propagated out -> a generic 500 with NO session cookie. The
// account was fully created and the email globally claimed, so a retry created a fresh org whose
// `DirectoryDO.claim` saw the email owned elsewhere -> 409. The user was stranded.
//
// The fix makes a send failure NON-FATAL: signup still completes (201 + session cookie + csrf) and
// signals `emailSent:false`. The verification TOKEN is still issued (before/inside the send), so the
// existing session-gated resend flow works. This suite proves:
//   1. a THROWING sender still yields a valid 201 + session cookie + csrf (user authenticated),
//      the account/org/claim exist, and `emailSent:false` is signaled;
//   2. the verify token is persisted so a subsequent resend-verification succeeds;
//   3. a normal (succeeding) signup is unchanged: 201 with emailSent:true (no regression).
//
// All deterministic, in-memory, zero network — mirrors test/auth-signup.test.ts's harness.

import { describe, it, expect, beforeEach } from "vitest";
import {
  handleSignup,
  type SignupDeps,
  type SignupLimiters,
  type AccountStore,
  type OrgProvisioner,
  type Account,
  type AccountRole,
} from "../src/security/auth-signup";
import { type PasswordStore, type PasswordCredential } from "../src/security/auth-password";
import { type SessionStore, type BrowserSession } from "../src/security/auth-session";
import {
  FakeEmailSender,
  sendVerificationEmail,
  type EmailTokenStore,
  type EmailTokenRecord,
} from "../src/security/auth-email";
import { type TotpCredentialStore, type TotpCredential } from "../src/security/auth-totp";
import { RateLimiter, InMemoryRateLimitStore, type RateLimitConfig } from "../src/security/ratelimit";

// =======================================================================================
// In-memory fakes (deterministic; no DO, no network) — compact copies of auth-signup.test.ts.
// =======================================================================================

let uuidCounter = 0;
function nextUuid(): string {
  return `uuid-${(uuidCounter++).toString().padStart(4, "0")}`;
}

class MemAccountStore implements AccountStore {
  accounts = new Map<string, Account>();
  directory = new Map<string, { orgId: string; accountId: string }>();

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
    if (this.directory.has(input.email)) return Promise.reject(new Error("email_taken"));
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
    for (const a of this.accounts.values()) if (a.userId === userId) return Promise.resolve({ ...a });
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
    this.challenges.delete(id);
    return Promise.resolve({ ...c });
  }
}

class MemWebAuthnStore {
  creds = new Map<string, unknown[]>();
  listWebAuthn(accountId: string): Promise<unknown[]> {
    return Promise.resolve(this.creds.get(accountId) ?? []);
  }
}

// =======================================================================================
// Harness (frozen clock + generous limiters + cheap scrypt) — mirrors auth-signup.test.ts.
// =======================================================================================

const NOW = 1_700_000_000_000;
const FAST_PASSWORD = { N: 2, r: 8, p: 1, dkLen: 32 };

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
  verifyUrls: string[];
}

function makeHarness(over: Partial<SignupDeps> = {}): Harness {
  const accounts = new MemAccountStore();
  const org = new MemOrgProvisioner();
  const passwords = new MemPasswordStore();
  const sessions = new MemSessionStore();
  const emailTokens = new MemEmailTokenStore();
  const emailSender = new FakeEmailSender({ delivers: true }); // stands in for a real provider (B11)
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
    scryptCost: FAST_PASSWORD,
    now: () => NOW,
    ...over,
  };
  return { deps, accounts, org, passwords, sessions, emailTokens, emailSender, verifyUrls };
}

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("https://gw.cloud-fs.test/v1/auth/signup", {
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

beforeEach(() => {
  uuidCounter = 0;
});

// =======================================================================================
// R1: email-send failure is non-fatal — signup still completes + authenticates the user.
// =======================================================================================

describe("R1 — signup email-send failure is non-fatal", () => {
  it("completes signup (201 + session cookie + csrf, emailSent:false) when the sender THROWS", async () => {
    const h = makeHarness();
    // Inject a transient provider outage: the very next send throws (as the real Resend/Postmark/SES
    // senders do on a non-2xx / network failure).
    h.emailSender.failNext = new Error("resend send failed: 503 upstream unavailable");

    const res = await handleSignup(req(VALID_SIGNUP), h.deps);

    // Signup STILL succeeds: same 201 success shape, with a session the user is authenticated by.
    expect(res.status).toBe(201);
    expect(res.body.state).toBe("verify_email");
    expect(res.body.orgId).toBeTruthy();
    expect(res.body.accountId).toBeTruthy();
    expect(res.body.userId).toBeTruthy();

    // Session cookie + csrf present (the user lands authenticated on the verify-email screen).
    expect(res.setCookie).toContain("cfs_session=");
    expect(res.setCookie).toContain("HttpOnly");
    expect(res.body.csrf).toBeTruthy();
    expect(h.sessions.rows.size).toBe(1);

    // Delivery failure is SIGNALED, not swallowed.
    expect(res.body.emailSent).toBe(false);

    // The account/org/global-email-claim are all committed and consistent.
    expect(h.org.created).toHaveLength(1);
    const account = h.accounts.accounts.get(res.body.accountId)!;
    expect(account.role).toBe("owner");
    expect(account.email).toBe("owner@acme.example");
    expect(await h.accounts.resolveEmail("owner@acme.example")).toEqual({
      orgId: res.body.orgId,
      accountId: res.body.accountId,
    });
    // Password was hashed before the send, so login works as a recovery path too.
    expect(h.passwords.rows.get(account.id)).toBeTruthy();

    // The failing send recorded nothing (the throw fired before the record).
    expect(h.emailSender.sent).toHaveLength(0);
  });

  it("still issues the verify token on send failure, so a subsequent resend-verification succeeds", async () => {
    const h = makeHarness();
    h.emailSender.failNext = new Error("postmark send failed: 500");
    const res = await handleSignup(req(VALID_SIGNUP), h.deps);
    expect(res.body.emailSent).toBe(false);

    // The verification token is persisted BEFORE the send, so it survives the delivery failure.
    const tokens = [...h.emailTokens.rows.values()];
    expect(tokens).toHaveLength(1);
    expect(tokens[0].purpose).toBe("verify_email");
    expect(tokens[0].accountId).toBe(res.body.accountId);
    expect(tokens[0].consumedAt).toBeNull();

    // Now the provider recovers and the user hits the existing session-gated resend flow (the same
    // `sendVerificationEmail` primitive runResendVerification calls). It must deliver successfully.
    const account = h.accounts.accounts.get(res.body.accountId)!;
    await sendVerificationEmail(
      {
        store: h.emailTokens,
        sender: h.emailSender,
        buildUrl: h.deps.buildVerifyUrl,
        tokenDeps: { now: () => NOW },
      },
      { orgId: account.orgId, accountId: account.id, email: account.email, displayName: account.displayName, productName: "cloud-fs" },
    );

    // The resend delivered exactly one verification email.
    expect(h.emailSender.sent).toHaveLength(1);
    expect(h.emailSender.last!.subject).toContain("Verify your email");
  });

  it("does not strand the account: a retry signup with the SAME email returns 409 (account already exists), not a fresh-org 500/stranding", async () => {
    const h = makeHarness();
    h.emailSender.failNext = new Error("ses send failed: 500");
    const first = await handleSignup(req(VALID_SIGNUP), h.deps);
    expect(first.status).toBe(201);
    expect(first.body.emailSent).toBe(false);

    // A retry now sees the email already claimed -> a clean, recoverable 409 (the user should
    // resend/login instead of re-signing-up). The point of the fix: the FIRST attempt already
    // returned a usable session, so the user never NEEDS this retry — but if they do, it's a
    // deterministic 409, not a stranded account.
    await expect(handleSignup(req(VALID_SIGNUP), h.deps)).rejects.toMatchObject({ status: 409, code: "email_taken" });
    // No second org orphaned.
    expect(h.org.created).toHaveLength(1);
  });

  // =====================================================================================
  // Regression: the happy path is unchanged.
  // =====================================================================================

  it("a normal (succeeding) signup still returns 201 with emailSent:true and a delivered email", async () => {
    const h = makeHarness(); // sender does NOT fail.
    const res = await handleSignup(req(VALID_SIGNUP), h.deps);

    expect(res.status).toBe(201);
    expect(res.body.emailSent).toBe(true);
    expect(res.body.state).toBe("verify_email");
    expect(res.setCookie).toContain("cfs_session=");
    expect(res.body.csrf).toBeTruthy();

    // Email actually delivered (no regression to the dispatch).
    expect(h.emailSender.sent).toHaveLength(1);
    expect(h.emailSender.last!.subject).toContain("Verify your email");
    expect(h.verifyUrls).toHaveLength(1);
    expect(h.verifyUrls[0]).toContain("token=");
  });

  // Audit B11 — a non-delivering (no-op/console) sender must report emailSent:FALSE, not a
  // phantom true. Pre-fix the fake resolved successfully and signup said emailSent:true
  // while the mail was silently dropped, stranding the user at 403 email_unverified forever.
  it("a NON-delivering sender (no-op fake) returns emailSent:false even though the send 'succeeds'", async () => {
    const h = makeHarness({ emailSender: new FakeEmailSender({ delivers: false }) });
    const res = await handleSignup(req(VALID_SIGNUP), h.deps);
    expect(res.status).toBe(201);
    expect(res.body.emailSent).toBe(false);
    expect(res.body.state).toBe("verify_email");
  });
});
