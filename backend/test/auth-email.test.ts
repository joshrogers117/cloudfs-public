// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, beforeEach } from "vitest";
import {
  // tokens
  issueEmailToken,
  verifyEmailToken,
  confirmEmailToken,
  sendVerificationEmail,
  EMAIL_TOKEN_TTL_SECONDS,
  type EmailTokenStore,
  type EmailTokenRecord,
  type EmailTokenPurpose,
  type TokenDeps,
  // senders + rendering
  FakeEmailSender,
  MessageEmailSender,
  CloudflareRawEmailSender,
  cloudflareEmailSender,
  ResendRawEmailSender,
  resendEmailSender,
  PostmarkRawEmailSender,
  postmarkEmailSender,
  SesRawEmailSender,
  sesEmailSender,
  ConsoleEmailSender,
  renderVerificationEmail,
  renderInviteEmail,
  type RawEmailSender,
  type EmailMessageInput,
  type EmailSender,
  type SendEmailBinding,
  type SesSigner,
} from "../src/security/auth-email";

// ---- in-memory EmailTokenStore fake (atomic single-use consume) ----------------------

class MemTokenStore implements EmailTokenStore {
  rows = new Map<string, EmailTokenRecord>();
  invalidated: Array<{ accountId: string; purpose: EmailTokenPurpose }> = [];

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
    if (!r || r.consumedAt !== null) return Promise.resolve(false); // already used / gone
    r.consumedAt = consumedAt;
    return Promise.resolve(true);
  }
  invalidateOutstanding(accountId: string, purpose: EmailTokenPurpose): Promise<void> {
    this.invalidated.push({ accountId, purpose });
    for (const r of this.rows.values()) {
      if (r.accountId === accountId && r.purpose === purpose && r.consumedAt === null) {
        r.consumedAt = -1; // mark superseded
      }
    }
    return Promise.resolve();
  }
}

// Deterministic deps: fixed clock + counter-based randomness + sequential ids.
const T0 = 1_700_000_000_000; // fixed epoch ms
function fixedDeps(overrides: Partial<TokenDeps> = {}): TokenDeps {
  let idN = 0;
  let rndN = 1;
  return {
    now: () => T0,
    randomBytes: (n: number) => {
      const b = new Uint8Array(n);
      for (let i = 0; i < n; i++) b[i] = (rndN + i) & 0xff;
      rndN += 7;
      return b;
    },
    newId: () => `evt-${++idN}`,
    ...overrides,
  };
}

const ISSUE = {
  orgId: "acme",
  accountId: "acc-1",
  email: "Alice@Example.com",
  purpose: "verify_email" as EmailTokenPurpose,
};

// ---- token issue ---------------------------------------------------------------------

describe("issueEmailToken — scheme: signed, single-use, expiring", () => {
  let store: MemTokenStore;
  beforeEach(() => {
    store = new MemTokenStore();
  });

  it("returns a `<id>.<secret>` clear token and persists ONLY the hash", async () => {
    const { token, record } = await issueEmailToken(store, ISSUE, fixedDeps());
    expect(token).toMatch(/^evt-1\.[A-Za-z0-9_-]+$/);
    const [id, secret] = token.split(".");
    expect(id).toBe("evt-1");
    expect(secret.length).toBeGreaterThan(20); // 32 bytes b64url

    const stored = await store.get("evt-1");
    expect(stored).not.toBeNull();
    // the clear secret is NEVER stored
    expect(stored!.tokenHash).not.toBe(secret);
    expect(JSON.stringify(stored)).not.toContain(secret);
    expect(record.consumedAt).toBeNull();
  });

  it("canonicalizes the email (trim + lowercase) and sets per-purpose TTL", async () => {
    const { record } = await issueEmailToken(store, ISSUE, fixedDeps());
    expect(record.email).toBe("alice@example.com");
    expect(record.expiresAt).toBe(T0 + EMAIL_TOKEN_TTL_SECONDS.verify_email * 1000);
    expect(record.createdAt).toBe(T0);
  });

  it("honors an explicit ttlSeconds override", async () => {
    const { record } = await issueEmailToken(store, { ...ISSUE, ttlSeconds: 60 }, fixedDeps());
    expect(record.expiresAt).toBe(T0 + 60_000);
  });

  it("password_reset and invite get their own default TTLs", async () => {
    const reset = await issueEmailToken(store, { ...ISSUE, purpose: "password_reset" }, fixedDeps());
    expect(reset.record.expiresAt).toBe(T0 + EMAIL_TOKEN_TTL_SECONDS.password_reset * 1000);
    const inv = await issueEmailToken(store, { ...ISSUE, purpose: "invite" }, fixedDeps());
    expect(inv.record.expiresAt).toBe(T0 + EMAIL_TOKEN_TTL_SECONDS.invite * 1000);
  });

  it("supersedes outstanding tokens by default; can be disabled", async () => {
    await issueEmailToken(store, ISSUE, fixedDeps());
    expect(store.invalidated).toHaveLength(1);
    expect(store.invalidated[0]).toEqual({ accountId: "acc-1", purpose: "verify_email" });

    await issueEmailToken(store, { ...ISSUE, supersede: false }, fixedDeps());
    expect(store.invalidated).toHaveLength(1); // not called again
  });

  it("two issues produce DIFFERENT secrets + hashes (randomness is consumed)", async () => {
    const a = await issueEmailToken(store, { ...ISSUE, supersede: false }, fixedDeps());
    // fresh deps would repeat; share one deps instance so randomness advances
    const deps = fixedDeps();
    const b1 = await issueEmailToken(store, { ...ISSUE, supersede: false }, deps);
    const b2 = await issueEmailToken(store, { ...ISSUE, supersede: false }, deps);
    expect(b1.token).not.toBe(b2.token);
    expect(b1.record.tokenHash).not.toBe(b2.record.tokenHash);
    expect(a.record.tokenHash).toBeTruthy();
  });
});

// ---- verify --------------------------------------------------------------------------

describe("verifyEmailToken — happy path + single-use", () => {
  let store: MemTokenStore;
  beforeEach(() => {
    store = new MemTokenStore();
  });

  it("verifies a freshly issued token and returns the record", async () => {
    const { token } = await issueEmailToken(store, ISSUE, fixedDeps());
    const res = await verifyEmailToken(store, token, "verify_email", fixedDeps());
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.record.accountId).toBe("acc-1");
      expect(res.record.email).toBe("alice@example.com");
      expect(res.record.consumedAt).toBe(T0);
    }
  });

  it("is SINGLE-USE: a second verify of the same token fails 'consumed'", async () => {
    const { token } = await issueEmailToken(store, ISSUE, fixedDeps());
    const first = await verifyEmailToken(store, token, "verify_email", fixedDeps());
    expect(first.ok).toBe(true);
    const second = await verifyEmailToken(store, token, "verify_email", fixedDeps());
    expect(second).toEqual({ ok: false, error: "consumed" });
  });

  it("concurrent verifies: exactly one wins, the loser gets 'consumed'", async () => {
    const { token } = await issueEmailToken(store, ISSUE, fixedDeps());
    const [a, b] = await Promise.all([
      verifyEmailToken(store, token, "verify_email", fixedDeps()),
      verifyEmailToken(store, token, "verify_email", fixedDeps()),
    ]);
    const wins = [a, b].filter((r) => r.ok).length;
    const losses = [a, b].filter((r) => !r.ok && r.error === "consumed").length;
    expect(wins).toBe(1);
    expect(losses).toBe(1);
  });
});

describe("verifyEmailToken — rejection paths", () => {
  let store: MemTokenStore;
  beforeEach(() => {
    store = new MemTokenStore();
  });

  it("rejects an expired token", async () => {
    const { token } = await issueEmailToken(store, { ...ISSUE, ttlSeconds: 60 }, fixedDeps());
    const later = fixedDeps({ now: () => T0 + 61_000 });
    const res = await verifyEmailToken(store, token, "verify_email", later);
    expect(res).toEqual({ ok: false, error: "expired" });
  });

  it("rejects a purpose mismatch (verify link replayed as reset)", async () => {
    const { token } = await issueEmailToken(store, ISSUE, fixedDeps());
    const res = await verifyEmailToken(store, token, "password_reset", fixedDeps());
    expect(res).toEqual({ ok: false, error: "purpose_mismatch" });
  });

  it("rejects an unknown id as coarse 'invalid' (no enumeration)", async () => {
    const res = await verifyEmailToken(store, "evt-nope.AAAA", "verify_email", fixedDeps());
    expect(res).toEqual({ ok: false, error: "invalid" });
  });

  it("rejects a wrong secret for a real id (constant-time hash compare) as 'invalid'", async () => {
    const { token } = await issueEmailToken(store, ISSUE, fixedDeps());
    const id = token.split(".")[0];
    const forged = `${id}.${"A".repeat(43)}`; // valid b64url shape, wrong secret
    const res = await verifyEmailToken(store, forged, "verify_email", fixedDeps());
    expect(res).toEqual({ ok: false, error: "invalid" });
    // and the real token still works afterwards (forged attempt didn't consume it)
    const ok = await verifyEmailToken(store, token, "verify_email", fixedDeps());
    expect(ok.ok).toBe(true);
  });

  it("rejects malformed shapes (no dot, empty secret, non-b64url secret)", async () => {
    for (const bad of ["nodot", "evt-1.", ".secret", "evt-1.has spaces", "evt-1.has+plus"]) {
      const res = await verifyEmailToken(store, bad, "verify_email", fixedDeps());
      expect(res).toEqual({ ok: false, error: "invalid" });
    }
  });
});

// ---- high-level flows ----------------------------------------------------------------

describe("sendVerificationEmail + confirmEmailToken (route-layer flows)", () => {
  let store: MemTokenStore;
  let sender: FakeEmailSender;
  beforeEach(() => {
    store = new MemTokenStore();
    sender = new FakeEmailSender();
  });

  it("issues a token, builds the link, and sends exactly one verification email", async () => {
    const rec = await sendVerificationEmail(
      {
        store,
        sender,
        buildUrl: (t) => `https://app.cloud-fs.test/verify?token=${encodeURIComponent(t)}`,
        tokenDeps: fixedDeps(),
      },
      { orgId: "acme", accountId: "acc-1", email: "Alice@Example.com", displayName: "Alice" },
    );
    expect(rec.purpose).toBe("verify_email");
    expect(sender.sent).toHaveLength(1);
    expect(sender.last!.to).toBe("alice@example.com");
    expect(sender.last!.subject).toContain("Verify");
    // the link in the email must carry the clear token (id.secret).
    // Stop at any whitespace/quote so we don't capture the trailing newline.
    const m = /token=([^\s&"]+)/.exec(sender.last!.text);
    expect(m).not.toBeNull();
    const clear = decodeURIComponent(m![1]);
    // and that exact emailed token round-trips through confirm
    const confirmed = await confirmEmailToken(store, clear, fixedDeps());
    expect(confirmed).toEqual({ ok: true, accountId: "acc-1", orgId: "acme", email: "alice@example.com" });
  });

  it("confirmEmailToken surfaces verify errors (expired) unchanged", async () => {
    const { token } = await issueEmailToken(store, { ...ISSUE, ttlSeconds: 30 }, fixedDeps());
    const res = await confirmEmailToken(store, token, fixedDeps({ now: () => T0 + 31_000 }));
    expect(res).toEqual({ ok: false, error: "expired" });
  });
});

// ---- EmailSender interface: fake, composition, cloudflare ----------------------------

describe("FakeEmailSender (test double)", () => {
  it("records sends across the whole EmailSender surface and sends nothing", async () => {
    const s = new FakeEmailSender();
    await s.sendVerification({ to: "a@b.com", verifyUrl: "https://x/y" });
    await s.sendInvite({ to: "c@d.com", acceptUrl: "https://x/z", orgName: "Acme" });
    await s.sendTransactional({ to: "e@f.com", subject: "Hi", text: "body" });
    expect(s.sent).toHaveLength(3);
    expect(s.sent[0].subject).toContain("Verify");
    expect(s.sent[1].subject).toContain("Acme");
    expect(s.sent[2].text).toBe("body");
    s.reset();
    expect(s.sent).toHaveLength(0);
  });

  it("can inject a one-shot failure for retry/error tests", async () => {
    const s = new FakeEmailSender();
    s.failNext = new Error("boom");
    await expect(s.sendTransactional({ to: "a@b.com", subject: "s", text: "t" })).rejects.toThrow("boom");
    // recovers on the next send
    await s.sendTransactional({ to: "a@b.com", subject: "s", text: "t" });
    expect(s.sent).toHaveLength(1);
  });
});

describe("MessageEmailSender — composes a RawEmailSender into the rich interface", () => {
  it("renders verification + invite through one one-method primitive", async () => {
    const captured: EmailMessageInput[] = [];
    const raw: RawEmailSender = {
      send: (m) => {
        captured.push(m);
        return Promise.resolve();
      },
    };
    const sender: EmailSender = new MessageEmailSender(raw);
    await sender.sendVerification({ to: "a@b.com", verifyUrl: "https://app/v?t=1", displayName: "Al" });
    await sender.sendInvite({ to: "c@d.com", acceptUrl: "https://app/i?t=2", orgName: "Acme", invitedByName: "Bob" });
    await sender.sendTransactional({ to: "e@f.com", subject: "Generic", text: "reusable" });
    expect(captured).toHaveLength(3);
    expect(captured[0].html).toContain("https://app/v?t=1");
    expect(captured[0].text).toContain("Al");
    expect(captured[1].text).toContain("Bob invited you");
    expect(captured[2].subject).toBe("Generic");
  });
});

describe("CloudflareRawEmailSender — wraps the send_email binding", () => {
  it("calls the binding with from/to/subject/text/html and uses EMAIL_FROM_NAME", async () => {
    const calls: any[] = [];
    const EMAIL: SendEmailBinding = {
      send: (msg) => {
        calls.push(msg);
        // The binding resolves with a message id when Cloudflare accepts the message for
        // processing (including when final delivery is queued for a later attempt).
        return Promise.resolve({ messageId: "cf-message-1" });
      },
    };
    const sender = cloudflareEmailSender({
      EMAIL,
      EMAIL_FROM: "noreply@cloud-fs.test",
      EMAIL_FROM_NAME: "cloud-fs",
    });
    await sender.sendVerification({ to: "a@b.com", verifyUrl: "https://app/v" });
    expect(calls).toHaveLength(1);
    expect(calls[0].from).toEqual({ email: "noreply@cloud-fs.test", name: "cloud-fs" });
    expect(calls[0].to).toBe("a@b.com");
    expect(typeof calls[0].subject).toBe("string");
    expect(calls[0].text).toBeTruthy();
    expect(calls[0].html).toBeTruthy();
  });

  it("omits html when not rendered and uses a bare from when no name", async () => {
    const calls: any[] = [];
    const raw = new CloudflareRawEmailSender({
      EMAIL: {
        send: (msg) => {
          calls.push(msg);
          return Promise.resolve({ messageId: "cf-message-2" });
        },
      },
      EMAIL_FROM: "noreply@cloud-fs.test",
    });
    await raw.send({ to: "a@b.com", subject: "Plain", text: "just text" });
    expect(calls[0].from).toBe("noreply@cloud-fs.test");
    expect(calls[0].html).toBeUndefined();
    expect(calls[0].text).toBe("just text");
  });

  it("propagates a permanent delivery error instead of silently treating it as sent", async () => {
    const deliveryError = Object.assign(new Error("delivery failed"), { code: "E_DELIVERY_FAILED" });
    const raw = new CloudflareRawEmailSender({
      EMAIL: { send: async () => { throw deliveryError; } },
      EMAIL_FROM: "noreply@cloud-fs.test",
    });

    await expect(raw.send({ to: "a@b.com", subject: "Plain", text: "just text" })).rejects.toBe(deliveryError);
  });
});

describe("ResendRawEmailSender — POSTs to the Resend API via fetch", () => {
  it("posts from/to/subject/text/html with the API key as a bearer; 'Name <email>' from", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fakeFetch = (url: string, init?: RequestInit) => {
      calls.push({ url, init: init ?? {} });
      return Promise.resolve(new Response("{}", { status: 200 }));
    };
    const sender = resendEmailSender(
      { RESEND_API_KEY: "re_test_key", EMAIL_FROM: "noreply@cloud-fs.test", EMAIL_FROM_NAME: "cloud-fs" },
      fakeFetch as unknown as typeof fetch,
    );
    await sender.sendVerification({ to: "a@b.com", verifyUrl: "https://app/v?t=abc" });

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://api.resend.com/emails");
    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer re_test_key");
    expect(headers["content-type"]).toBe("application/json");
    const sent = JSON.parse(String(calls[0].init.body));
    expect(sent.from).toBe("cloud-fs <noreply@cloud-fs.test>");
    expect(sent.to).toEqual(["a@b.com"]);
    expect(sent.subject).toContain("Verify your email");
    expect(sent.text).toContain("https://app/v?t=abc");
    expect(sent.html).toContain("https://app/v?t=abc");
  });

  it("uses a bare from when no display name and omits html when not rendered", async () => {
    const calls: Array<{ init: RequestInit }> = [];
    const fakeFetch = (_url: string, init?: RequestInit) => {
      calls.push({ init: init ?? {} });
      return Promise.resolve(new Response("{}", { status: 200 }));
    };
    const raw = new ResendRawEmailSender(
      { RESEND_API_KEY: "k", EMAIL_FROM: "noreply@cloud-fs.test" },
      fakeFetch as unknown as typeof fetch,
    );
    await raw.send({ to: "a@b.com", subject: "Plain", text: "just text" });
    const sent = JSON.parse(String(calls[0].init.body));
    expect(sent.from).toBe("noreply@cloud-fs.test");
    expect(sent.html).toBeUndefined();
    expect(sent.text).toBe("just text");
  });

  it("throws on a non-2xx Resend response (without leaking the key)", async () => {
    const fakeFetch = () => Promise.resolve(new Response("invalid from", { status: 422 }));
    const raw = new ResendRawEmailSender(
      { RESEND_API_KEY: "secretkey", EMAIL_FROM: "noreply@cloud-fs.test" },
      fakeFetch as unknown as typeof fetch,
    );
    await expect(raw.send({ to: "a@b.com", subject: "x", text: "y" })).rejects.toThrow(/resend send failed: 422/);
    // The thrown message must not contain the API key.
    await raw.send({ to: "a@b.com", subject: "x", text: "y" }).catch((e: Error) => {
      expect(e.message).not.toContain("secretkey");
    });
  });
});

describe("PostmarkRawEmailSender — POSTs to the Postmark API via fetch", () => {
  it("posts From/To/Subject/TextBody/HtmlBody with the X-Postmark-Server-Token header", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fakeFetch = (url: string, init?: RequestInit) => {
      calls.push({ url, init: init ?? {} });
      return Promise.resolve(new Response("{}", { status: 200 }));
    };
    const sender = postmarkEmailSender(
      { POSTMARK_SERVER_TOKEN: "pm-test-token", EMAIL_FROM: "noreply@cloud-fs.test", EMAIL_FROM_NAME: "cloud-fs" },
      fakeFetch as unknown as typeof fetch,
    );
    await sender.sendVerification({ to: "a@b.com", verifyUrl: "https://app/v?t=abc" });

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://api.postmark.com/email");
    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers["x-postmark-server-token"]).toBe("pm-test-token");
    expect(headers["content-type"]).toBe("application/json");
    expect(headers.accept).toBe("application/json");
    // No bearer auth — Postmark uses the server-token header.
    expect(headers.authorization).toBeUndefined();
    const sent = JSON.parse(String(calls[0].init.body));
    expect(sent.From).toBe("cloud-fs <noreply@cloud-fs.test>");
    expect(sent.To).toBe("a@b.com");
    expect(sent.Subject).toContain("Verify your email");
    expect(sent.TextBody).toContain("https://app/v?t=abc");
    expect(sent.HtmlBody).toContain("https://app/v?t=abc");
    expect(sent.MessageStream).toBe("outbound");
  });

  it("uses a bare From when no display name and omits HtmlBody when not rendered", async () => {
    const calls: Array<{ init: RequestInit }> = [];
    const fakeFetch = (_url: string, init?: RequestInit) => {
      calls.push({ init: init ?? {} });
      return Promise.resolve(new Response("{}", { status: 200 }));
    };
    const raw = new PostmarkRawEmailSender(
      { POSTMARK_SERVER_TOKEN: "k", EMAIL_FROM: "noreply@cloud-fs.test" },
      fakeFetch as unknown as typeof fetch,
    );
    await raw.send({ to: "a@b.com", subject: "Plain", text: "just text" });
    const sent = JSON.parse(String(calls[0].init.body));
    expect(sent.From).toBe("noreply@cloud-fs.test");
    expect(sent.HtmlBody).toBeUndefined();
    expect(sent.TextBody).toBe("just text");
  });

  it("throws on a non-2xx Postmark response without leaking the token", async () => {
    const fakeFetch = () => Promise.resolve(new Response("inactive recipient", { status: 422 }));
    const raw = new PostmarkRawEmailSender(
      { POSTMARK_SERVER_TOKEN: "secrettoken", EMAIL_FROM: "noreply@cloud-fs.test" },
      fakeFetch as unknown as typeof fetch,
    );
    await expect(raw.send({ to: "a@b.com", subject: "x", text: "y" })).rejects.toThrow(/postmark send failed: 422/);
    await raw.send({ to: "a@b.com", subject: "x", text: "y" }).catch((e: Error) => {
      expect(e.message).not.toContain("secrettoken");
    });
  });
});

describe("SesRawEmailSender — SigV4-signed POST to the SES v2 SendEmail endpoint", () => {
  // An injected signer stands in for aws4fetch's AwsClient: it records the request without any
  // real AWS creds or network, so the test asserts only the SES request SHAPE.
  function recordingSigner(): { signer: SesSigner; calls: Array<{ url: string; init: RequestInit }> } {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const signer: SesSigner = {
      fetch: (url, init) => {
        calls.push({ url: String(url), init: init ?? {} });
        return Promise.resolve(new Response("{}", { status: 200 }));
      },
    };
    return { signer, calls };
  }

  it("POSTs the SES v2 Simple content shape to the regional /v2/email/outbound endpoint", async () => {
    const { signer, calls } = recordingSigner();
    const sender = sesEmailSender(
      {
        SES_ACCESS_KEY_ID: "AKIA_TEST",
        SES_SECRET_ACCESS_KEY: "secret",
        SES_REGION: "us-east-1",
        EMAIL_FROM: "noreply@cloud-fs.test",
        EMAIL_FROM_NAME: "cloud-fs",
      },
      signer,
    );
    await sender.sendVerification({ to: "a@b.com", verifyUrl: "https://app/v?t=abc" });

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://email.us-east-1.amazonaws.com/v2/email/outbound");
    expect(calls[0].init.method).toBe("POST");
    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers["content-type"]).toBe("application/json");
    const body = JSON.parse(String(calls[0].init.body));
    expect(body.FromEmailAddress).toBe("cloud-fs <noreply@cloud-fs.test>");
    expect(body.Destination.ToAddresses).toEqual(["a@b.com"]);
    expect(body.Content.Simple.Subject.Data).toContain("Verify your email");
    expect(body.Content.Simple.Body.Text.Data).toContain("https://app/v?t=abc");
    expect(body.Content.Simple.Body.Html.Data).toContain("https://app/v?t=abc");
  });

  it("uses a bare From when no display name and omits Html when not rendered", async () => {
    const { signer, calls } = recordingSigner();
    const raw = new SesRawEmailSender(
      { SES_ACCESS_KEY_ID: "k", SES_SECRET_ACCESS_KEY: "s", SES_REGION: "eu-west-1", EMAIL_FROM: "noreply@cloud-fs.test" },
      signer,
    );
    await raw.send({ to: "a@b.com", subject: "Plain", text: "just text" });
    expect(calls[0].url).toBe("https://email.eu-west-1.amazonaws.com/v2/email/outbound");
    const body = JSON.parse(String(calls[0].init.body));
    expect(body.FromEmailAddress).toBe("noreply@cloud-fs.test");
    expect(body.Content.Simple.Body.Html).toBeUndefined();
    expect(body.Content.Simple.Body.Text.Data).toBe("just text");
  });

  it("throws on a non-2xx SES response without leaking the secret key", async () => {
    const signer: SesSigner = { fetch: () => Promise.resolve(new Response("MessageRejected", { status: 400 })) };
    const raw = new SesRawEmailSender(
      { SES_ACCESS_KEY_ID: "k", SES_SECRET_ACCESS_KEY: "topsecretkey", SES_REGION: "us-east-1", EMAIL_FROM: "noreply@cloud-fs.test" },
      signer,
    );
    await expect(raw.send({ to: "a@b.com", subject: "x", text: "y" })).rejects.toThrow(/ses send failed: 400/);
    await raw.send({ to: "a@b.com", subject: "x", text: "y" }).catch((e: Error) => {
      expect(e.message).not.toContain("topsecretkey");
    });
  });
});

describe("ConsoleEmailSender (dev) — logs the recipient + subject + LINK", () => {
  it("records + logs the verification link so signup can be exercised with no real email", async () => {
    const lines: string[] = [];
    const sender = new ConsoleEmailSender((line) => lines.push(line));
    await sender.sendVerification({ to: "dev@b.com", verifyUrl: "https://app/v?token=abc123" });

    // Recorded for assertions.
    expect(sender.logs).toHaveLength(1);
    expect(sender.last).toMatchObject({ to: "dev@b.com", link: "https://app/v?token=abc123" });
    expect(sender.last!.subject).toContain("Verify your email");
    // And logged to the injected sink with the link.
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("dev@b.com");
    expect(lines[0]).toContain("https://app/v?token=abc123");
  });

  it("records a null link for a body with no URL", async () => {
    const sender = new ConsoleEmailSender(() => {});
    await sender.sendTransactional({ to: "x@b.com", subject: "no link here", text: "plain body, no url" });
    expect(sender.last).toMatchObject({ to: "x@b.com", link: null });
  });
});

describe("email rendering — copy + HTML escaping", () => {
  it("verification email includes the link in both text and html", () => {
    const msg = renderVerificationEmail({ to: "a@b.com", verifyUrl: "https://app/v?t=abc", displayName: "Alice" });
    expect(msg.text).toContain("https://app/v?t=abc");
    expect(msg.html).toContain("https://app/v?t=abc");
    expect(msg.text).toContain("Alice");
    expect(msg.html).toContain("Alice");
    expect(msg.text).toBeTruthy(); // always a plain-text part (deliverability)
  });

  it("escapes HTML-significant characters in caller-supplied names to prevent injection", () => {
    const msg = renderVerificationEmail({
      to: "a@b.com",
      verifyUrl: "https://app/v",
      displayName: "<script>alert(1)</script>",
    });
    expect(msg.html).not.toContain("<script>");
    expect(msg.html).toContain("&lt;script&gt;");
    // plain-text part is not escaped (it's not markup)
    expect(msg.text).toContain("<script>");
  });

  it("invite email renders inviter + org and the accept link", () => {
    const msg = renderInviteEmail({
      to: "c@d.com",
      acceptUrl: "https://app/i?t=xyz",
      orgName: "Acme Post",
      invitedByName: "Bob",
    });
    expect(msg.subject).toContain("Acme Post");
    expect(msg.text).toContain("Bob invited you to join Acme Post");
    expect(msg.html).toContain("https://app/i?t=xyz");
  });
});
