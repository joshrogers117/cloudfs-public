// SPDX-License-Identifier: AGPL-3.0-or-later
/// cloud-fs email verification + transactional email sending (CONTRACT §1.7, §2 EmailSender, §4.5).
///
/// This lane owns two related concerns:
///
///   1. SIGNED, SINGLE-USE, EXPIRING email tokens (issue + verify) used to prove control of
///      an email address (`verify_email`) and — reusing the exact same scheme — password
///      reset (`password_reset`) and invite-accept (`invite`) later. A token is the opaque
///      string `"<id>.<secret>"`:
///        - `id`      — a public, unguessable row id ("evt-<uuid>") used to look the row up.
///        - `secret`  — 32 random bytes (base64url). NEVER stored. We persist only
///                      `sha256(secret)` (the `token_hash` in CONTRACT §1.7's `email_tokens`
///                      table). Verification rehashes the presented secret and compares in
///                      CONSTANT TIME, so the stored row is useless to an attacker who reads
///                      the DB, and a timing oracle can't recover the secret.
///      Tokens are SINGLE-USE (a `consumedAt` stamp is set atomically on first successful
///      verify) and EXPIRING (`expiresAt`, default 24h for verify, 1h for reset).
///
///   2. An `EmailSender` abstraction so verification logic is testable with NO real email,
///      and the real provider is swappable via env. The contract's low-level primitive is
///      `RawEmailSender.send({to,subject,text,html})`; this lane layers a richer
///      `EmailSender` ({sendVerification, sendInvite}) on top of it, plus a generic
///      `sendTransactional` helper invites can reuse. Three things implement / consume it:
///        - `CloudflareEmailSender` — wraps the Workers `send_email` binding (workerd native,
///          no Node built-ins; see cloudflare-email-service skill).
///        - `FakeEmailSender`       — an in-memory test double; records every send, no network.
///        - `MessageEmailSender`    — composes any `RawEmailSender` into the rich interface so
///          a future provider only has to implement the one-method primitive.
///
/// WORKERS-CORRECTNESS (workers-best-practices skill):
///   - No Node built-ins. Randomness via `crypto.getRandomValues`; hashing via WebCrypto
///     `crypto.subtle.digest` (SHA-256); constant-time compare via the workerd global
///     `crypto.subtle.timingSafeEqual`. `@noble/hashes` is available too but WebCrypto keeps
///     this module dependency-light and is the platform-blessed path here.
///   - Provider binding arrives via `env` (structural subset, mirroring auth.ts's `AuthEnv`),
///     never imported as a concrete DO/`Env`.
///   - Time, randomness, id generation and the email transport are ALL injectable so unit
///     tests are deterministic with no real network and no wall-clock dependence.

import { AwsClient } from "aws4fetch";

// ---- token purposes ------------------------------------------------------------------

/// Why a token exists. The same issue/verify machinery serves all three; `verifyToken`
/// refuses to honour a token presented for the wrong purpose (defence in depth — a leaked
/// verify-email link can't be replayed as a password reset).
export type EmailTokenPurpose = "verify_email" | "password_reset" | "invite" | "legacy_enrollment";

/// Default lifetimes per purpose (seconds). Frozen, but overridable per-issue for tests/policy.
export const EMAIL_TOKEN_TTL_SECONDS: Record<EmailTokenPurpose, number> = {
  verify_email: 24 * 60 * 60, // 24h — email confirmation link
  password_reset: 60 * 60, //     1h — reset links are short so a leaked inbox is low-blast-radius
  invite: 7 * 24 * 60 * 60, // 7d — onboarding window
  legacy_enrollment: 30 * 60,
};

/// A persisted token row (CONTRACT §1.7 `email_tokens`: PK `id`, index `token_hash`).
/// Stored in `AuthDO(orgId)` by the integration agent's adapter; this lane talks only to the
/// `EmailTokenStore` interface below.
export interface EmailTokenRecord {
  id: string; //          "evt-<uuid>"; the public, lookup half of the token.
  orgId: string;
  accountId: string;
  email: string; //       the address being proved / targeted (lowercased canonical form).
  purpose: EmailTokenPurpose;
  tokenHash: string; //   base64url(sha256(secret)). The secret itself is NEVER stored.
  createdAt: number; //   epoch ms.
  expiresAt: number; //   epoch ms; token is invalid at/after this instant.
  consumedAt: number | null; // null = unused; set ONCE on first successful verify (single-use).
}

// ---- store interface (impl provided by the integration agent's AuthDO adapter) -------

/// The persistence surface this lane needs. Unit tests pass an in-memory fake; integration
/// passes the `AuthDO`-backed adapter. No DO import here (CONTRACT §2).
export interface EmailTokenStore {
  /// Persist a freshly-issued token row.
  put(rec: EmailTokenRecord): Promise<void>;
  /// Fetch by the public id half. Returns null if unknown.
  get(id: string): Promise<EmailTokenRecord | null>;
  /// Atomically mark a token consumed. Returns false if it was ALREADY consumed (lost the
  /// single-use race) or no longer exists — callers treat false as "token already used".
  consume(id: string, consumedAt: number): Promise<boolean>;
  /// Best-effort: drop any still-outstanding tokens for (account, purpose) before issuing a
  /// fresh one, so a resend invalidates older links. Optional for fakes/tests.
  invalidateOutstanding?(accountId: string, purpose: EmailTokenPurpose): Promise<void>;
}

// ---- email sender abstraction (CONTRACT §2 EmailSender) ------------------------------

/// A single rendered message. The lowest-level contract primitive.
export interface EmailMessageInput {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

/// The contract's minimal primitive (§2): one method, send a rendered message. Real
/// providers implement THIS; everything richer composes it. (Named `RawEmailSender` so the
/// rich `EmailSender` below can own the friendlier `sendVerification`/`sendInvite` surface.)
export interface RawEmailSender {
  send(msg: EmailMessageInput): Promise<void>;
}

/// Inputs for the two transactional emails this lane renders. Links are built by the caller
/// (integration knows the public base URL); this keeps URL/origin policy out of the lane.
export interface VerificationEmailInput {
  to: string;
  /// Fully-qualified link the recipient clicks (carries the token). Caller-built.
  verifyUrl: string;
  /// Optional friendly name for the greeting + product name in the body.
  displayName?: string;
  productName?: string;
}

export interface InviteEmailInput {
  to: string;
  acceptUrl: string;
  /// Who/what they're being invited to (org/space name) and by whom.
  orgName?: string;
  invitedByName?: string;
  productName?: string;
}

/// The rich sender the rest of the auth system depends on. `sendTransactional` is the generic
/// escape hatch invites (and future flows) reuse without re-rendering boilerplate.
export interface EmailSender {
  sendVerification(input: VerificationEmailInput): Promise<void>;
  sendInvite(input: InviteEmailInput): Promise<void>;
  /// Generic transactional send (subject + body) — the reusable helper.
  sendTransactional(msg: EmailMessageInput): Promise<void>;
  /// Audit B11: does this sender actually DELIVER mail to a real inbox? `false` for the
  /// no-op fake and the console-dev senders (which record/log but don't deliver), so the
  /// signup/reset flow can report `emailSent:false` instead of a phantom `true`.
  /// `undefined`/`true` ⇒ a real delivering provider.
  readonly delivers?: boolean;
}

const DEFAULT_PRODUCT_NAME = "cloud-fs";

/// Escape the five XML/HTML-significant chars so caller-supplied names/URLs can't inject
/// markup into the HTML body. The `text` part is never escaped (it's plain text).
function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/// Render the verification email (text + html). Exported so tests can assert copy without a
/// transport, and so the integration agent can reuse the rendering if it sends differently.
export function renderVerificationEmail(input: VerificationEmailInput): EmailMessageInput {
  const product = input.productName ?? DEFAULT_PRODUCT_NAME;
  const greetingName = input.displayName?.trim();
  const hello = greetingName ? `Hi ${greetingName},` : "Hi,";
  const text =
    `${hello}\n\n` +
    `Confirm your email address for ${product} by opening this link:\n\n` +
    `${input.verifyUrl}\n\n` +
    `This link expires soon and can only be used once. ` +
    `If you didn't request this, you can ignore this email.\n`;
  const html =
    `<p>${escapeHtml(hello)}</p>` +
    `<p>Confirm your email address for ${escapeHtml(product)} by clicking the button below.</p>` +
    `<p><a href="${escapeHtml(input.verifyUrl)}">Verify email</a></p>` +
    `<p>This link expires soon and can only be used once. ` +
    `If you didn't request this, you can ignore this email.</p>`;
  return { to: input.to, subject: `Verify your email for ${product}`, text, html };
}

/// Render the invite email (text + html).
export function renderInviteEmail(input: InviteEmailInput): EmailMessageInput {
  const product = input.productName ?? DEFAULT_PRODUCT_NAME;
  const org = input.orgName ?? product;
  const by = input.invitedByName?.trim();
  const intro = by ? `${by} invited you to join ${org} on ${product}.` : `You've been invited to join ${org} on ${product}.`;
  const text =
    `Hi,\n\n` +
    `${intro}\n\n` +
    `Accept your invitation by opening this link:\n\n` +
    `${input.acceptUrl}\n\n` +
    `This invitation expires soon and can only be used once.\n`;
  const html =
    `<p>Hi,</p>` +
    `<p>${escapeHtml(intro)}</p>` +
    `<p><a href="${escapeHtml(input.acceptUrl)}">Accept invitation</a></p>` +
    `<p>This invitation expires soon and can only be used once.</p>`;
  return { to: input.to, subject: `You're invited to ${org}`, text, html };
}

/// Compose any `RawEmailSender` (the contract's one-method primitive) into the rich
/// `EmailSender`. A future provider only implements `RawEmailSender.send`; rendering lives
/// here so every provider produces identical copy.
export class MessageEmailSender implements EmailSender {
  constructor(private readonly raw: RawEmailSender) {}

  sendVerification(input: VerificationEmailInput): Promise<void> {
    return this.raw.send(renderVerificationEmail(input));
  }
  sendInvite(input: InviteEmailInput): Promise<void> {
    return this.raw.send(renderInviteEmail(input));
  }
  sendTransactional(msg: EmailMessageInput): Promise<void> {
    return this.raw.send(msg);
  }
}

// ---- Cloudflare Email Sending implementation -----------------------------------------

/// Structural subset of the Workers `send_email` binding (workerd `SendEmail`). We accept the
/// builder-style overload only — `{from,to,subject,text,html}` — which is all this lane needs.
export interface SendEmailBinding {
  send(message: {
    from: string | { email: string; name?: string };
    to: string | { email: string; name?: string } | (string | { email: string; name?: string })[];
    subject: string;
    text?: string;
    html?: string;
  }): Promise<{ messageId: string }>;
}

/// The env subset the Cloudflare sender needs (mirrors auth.ts's `AuthEnv` decoupling).
/// `EMAIL` is the `send_email` binding (added to wrangler by the integration agent);
/// `EMAIL_FROM` / `EMAIL_FROM_NAME` are non-secret vars choosing the verified `from` address.
export interface EmailEnv {
  EMAIL: SendEmailBinding;
  EMAIL_FROM: string;
  EMAIL_FROM_NAME?: string;
}

/// The real provider: Cloudflare Email Sending via the Workers binding (no API keys, no Node
/// built-ins). A resolved send returns a message ID after Cloudflare accepts the message; the
/// binding does not report eventual queued/bounce status per recipient. Delivery errors are
/// thrown by the binding and intentionally propagate to the caller. The `from` domain must be
/// onboarded. Implements only the low-level primitive; wrap it in `MessageEmailSender` (or
/// `cloudflareEmailSender`) to get the rich interface.
export class CloudflareRawEmailSender implements RawEmailSender {
  constructor(private readonly env: EmailEnv) {}

  async send(msg: EmailMessageInput): Promise<void> {
    const from = this.env.EMAIL_FROM_NAME
      ? { email: this.env.EMAIL_FROM, name: this.env.EMAIL_FROM_NAME }
      : this.env.EMAIL_FROM;
    // Always include `text`; add `html` only when rendered (better deliverability per skill).
    await this.env.EMAIL.send({
      from,
      to: msg.to,
      subject: msg.subject,
      text: msg.text,
      ...(msg.html !== undefined ? { html: msg.html } : {}),
    });
  }
}

/// Convenience: a ready-to-use rich `EmailSender` backed by the Cloudflare binding.
export function cloudflareEmailSender(env: EmailEnv): EmailSender {
  return new MessageEmailSender(new CloudflareRawEmailSender(env));
}

// ---- Resend (https://resend.com) implementation --------------------------------------

/// The env subset the Resend sender needs. `RESEND_API_KEY` is a SECRET (never hard-coded —
/// provision via `wrangler secret put RESEND_API_KEY`); `EMAIL_FROM` / `EMAIL_FROM_NAME` choose
/// the verified `from` (the domain must be verified in the Resend dashboard).
export interface ResendEnv {
  RESEND_API_KEY: string;
  EMAIL_FROM: string;
  EMAIL_FROM_NAME?: string;
}

/// Default Resend REST endpoint (overridable for tests via the constructor's `endpoint`).
const RESEND_ENDPOINT = "https://api.resend.com/emails";

/// The real provider when a `RESEND_API_KEY` is configured: POSTs the rendered message to
/// Resend's `/emails` API via `fetch` (no Node built-ins, workerd-native). Implements only the
/// low-level `RawEmailSender.send`; wrap in `MessageEmailSender` (or `resendEmailSender`) for the
/// rich interface. The `from` is `"Name <email>"` (RFC 5322) when a display name is set.
export class ResendRawEmailSender implements RawEmailSender {
  constructor(
    private readonly env: ResendEnv,
    /// Injectable fetch + endpoint so unit tests assert the request with zero network.
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly endpoint: string = RESEND_ENDPOINT,
  ) {}

  async send(msg: EmailMessageInput): Promise<void> {
    const from = this.env.EMAIL_FROM_NAME
      ? `${this.env.EMAIL_FROM_NAME} <${this.env.EMAIL_FROM}>`
      : this.env.EMAIL_FROM;
    const res = await this.fetchImpl(this.endpoint, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.env.RESEND_API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: [msg.to],
        subject: msg.subject,
        text: msg.text,
        ...(msg.html !== undefined ? { html: msg.html } : {}),
      }),
    });
    if (!res.ok) {
      // Surface a concise error; the caller logs + the route maps it to a 500 (or, for the
      // resend route, the user can retry). We don't leak the API key or full provider body.
      const detail = await res.text().catch(() => "");
      throw new Error(`resend send failed: ${res.status}${detail ? ` ${detail.slice(0, 200)}` : ""}`);
    }
  }
}

/// Convenience: a ready-to-use rich `EmailSender` backed by Resend.
export function resendEmailSender(
  env: ResendEnv,
  fetchImpl: typeof fetch = fetch,
  endpoint: string = RESEND_ENDPOINT,
): EmailSender {
  return new MessageEmailSender(new ResendRawEmailSender(env, fetchImpl, endpoint));
}

// ---- Postmark (https://postmarkapp.com) implementation -------------------------------

/// The env subset the Postmark sender needs. `POSTMARK_SERVER_TOKEN` is a SECRET (provision via
/// `wrangler secret put POSTMARK_SERVER_TOKEN`); `EMAIL_FROM` / `EMAIL_FROM_NAME` choose the
/// verified `From` (the sender signature / domain must be confirmed in the Postmark dashboard).
export interface PostmarkEnv {
  POSTMARK_SERVER_TOKEN: string;
  EMAIL_FROM: string;
  EMAIL_FROM_NAME?: string;
}

/// Default Postmark single-send endpoint (overridable for tests via the constructor's `endpoint`).
const POSTMARK_ENDPOINT = "https://api.postmark.com/email";

/// Postmark provider: POSTs the rendered message to Postmark's `/email` API via `fetch`. Auth is
/// the `X-Postmark-Server-Token` header (NOT a bearer). Postmark's JSON uses PascalCase fields
/// (`From`/`To`/`Subject`/`TextBody`/`HtmlBody`). Workerd-native; injectable fetch for tests.
export class PostmarkRawEmailSender implements RawEmailSender {
  constructor(
    private readonly env: PostmarkEnv,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly endpoint: string = POSTMARK_ENDPOINT,
  ) {}

  async send(msg: EmailMessageInput): Promise<void> {
    const from = this.env.EMAIL_FROM_NAME
      ? `${this.env.EMAIL_FROM_NAME} <${this.env.EMAIL_FROM}>`
      : this.env.EMAIL_FROM;
    const res = await this.fetchImpl(this.endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "x-postmark-server-token": this.env.POSTMARK_SERVER_TOKEN,
      },
      body: JSON.stringify({
        From: from,
        To: msg.to,
        Subject: msg.subject,
        TextBody: msg.text,
        ...(msg.html !== undefined ? { HtmlBody: msg.html } : {}),
        MessageStream: "outbound",
      }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`postmark send failed: ${res.status}${detail ? ` ${detail.slice(0, 200)}` : ""}`);
    }
  }
}

/// Convenience: a ready-to-use rich `EmailSender` backed by Postmark.
export function postmarkEmailSender(
  env: PostmarkEnv,
  fetchImpl: typeof fetch = fetch,
  endpoint: string = POSTMARK_ENDPOINT,
): EmailSender {
  return new MessageEmailSender(new PostmarkRawEmailSender(env, fetchImpl, endpoint));
}

// ---- AWS SES v2 implementation (SigV4 via aws4fetch) ---------------------------------

/// The env subset the SES sender needs. `SES_ACCESS_KEY_ID` / `SES_SECRET_ACCESS_KEY` are SECRETS
/// (IAM creds with `ses:SendEmail`); `SES_REGION` is the SES region (e.g. "us-east-1"). The
/// `EMAIL_FROM` address must be a verified SES identity (or under a verified domain).
export interface SesEnv {
  SES_ACCESS_KEY_ID: string;
  SES_SECRET_ACCESS_KEY: string;
  SES_REGION: string;
  EMAIL_FROM: string;
  EMAIL_FROM_NAME?: string;
}

/// The minimal SigV4 signer surface this lane needs (a structural subset of aws4fetch's
/// `AwsClient`). Injectable so tests assert the signed request shape WITHOUT real AWS creds or
/// network — they pass a fake whose `fetch` records the URL/headers/body.
export interface SesSigner {
  fetch(input: string, init?: RequestInit): Promise<Response>;
}

/// Build the regional SES v2 SendEmail endpoint. SES v2 SendEmail is `POST` to
/// `https://email.<region>.amazonaws.com/v2/email/outbound`.
function sesEndpoint(region: string): string {
  return `https://email.${region}.amazonaws.com/v2/email/outbound`;
}

/// AWS SES v2 provider: POSTs the rendered message to the SES `SendEmail` endpoint, signed with
/// SigV4 by `aws4fetch` (already a dependency; WebCrypto-backed, no Node built-ins). Body is the
/// SES v2 `Simple` content shape. The signer is injectable so unit tests assert the request with
/// no AWS creds and no network; production constructs an `AwsClient` (service "ses").
export class SesRawEmailSender implements RawEmailSender {
  private readonly endpoint: string;
  constructor(
    private readonly env: SesEnv,
    /// Injectable SigV4 signer (defaults to a real aws4fetch `AwsClient` for the SES service).
    private readonly signer: SesSigner = new AwsClient({
      accessKeyId: env.SES_ACCESS_KEY_ID,
      secretAccessKey: env.SES_SECRET_ACCESS_KEY,
      region: env.SES_REGION,
      service: "ses",
    }),
    endpoint: string = sesEndpoint(env.SES_REGION),
  ) {
    this.endpoint = endpoint;
  }

  async send(msg: EmailMessageInput): Promise<void> {
    const from = this.env.EMAIL_FROM_NAME
      ? `${this.env.EMAIL_FROM_NAME} <${this.env.EMAIL_FROM}>`
      : this.env.EMAIL_FROM;
    const body = JSON.stringify({
      FromEmailAddress: from,
      Destination: { ToAddresses: [msg.to] },
      Content: {
        Simple: {
          Subject: { Data: msg.subject, Charset: "UTF-8" },
          Body: {
            Text: { Data: msg.text, Charset: "UTF-8" },
            ...(msg.html !== undefined ? { Html: { Data: msg.html, Charset: "UTF-8" } } : {}),
          },
        },
      },
    });
    const res = await this.signer.fetch(this.endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`ses send failed: ${res.status}${detail ? ` ${detail.slice(0, 200)}` : ""}`);
    }
  }
}

/// Convenience: a ready-to-use rich `EmailSender` backed by AWS SES v2.
export function sesEmailSender(env: SesEnv, signer?: SesSigner, endpoint?: string): EmailSender {
  return new MessageEmailSender(new SesRawEmailSender(env, signer, endpoint));
}

// ---- Console (dev) implementation ----------------------------------------------------

/// A line emitted by the console dev sender (also returned/recorded for tests).
export interface ConsoleEmailLog {
  to: string;
  subject: string;
  /// The first http(s) link found in the message body (the verification / invite / reset link),
  /// or null if the message carries none. This is what a developer copy-pastes to exercise signup
  /// locally with no real email.
  link: string | null;
}

/// Dev sender: logs the recipient + subject + the action LINK to the console instead of sending
/// real mail, so signup/verify/invite can be exercised locally with no provider configured. Select
/// it with `EMAIL_DEV_CONSOLE=1`. Records every log in-memory too, for tests. NEVER use in prod
/// (it does not deliver mail).
export class ConsoleEmailSender implements EmailSender, RawEmailSender {
  readonly logs: ConsoleEmailLog[] = [];
  readonly delivers = false; // logs the link; does NOT deliver to an inbox (B11)

  constructor(
    /// Injectable sink (defaults to `console.log`) so tests capture output deterministically.
    private readonly log: (line: string) => void = (line) => console.log(line),
  ) {}

  /// Extract the first http(s) URL from a message body (text preferred; html as fallback).
  private extractLink(msg: EmailMessageInput): string | null {
    const m = /(https?:\/\/[^\s"'<>)]+)/.exec(msg.text) ?? /(https?:\/\/[^\s"'<>)]+)/.exec(msg.html ?? "");
    return m ? m[1] : null;
  }

  private record(msg: EmailMessageInput): Promise<void> {
    const link = this.extractLink(msg);
    this.logs.push({ to: msg.to, subject: msg.subject, link });
    this.log(`[email:dev] to=${msg.to} subject=${JSON.stringify(msg.subject)} link=${link ?? "(none)"}`);
    return Promise.resolve();
  }

  send(msg: EmailMessageInput): Promise<void> {
    return this.record(msg);
  }
  sendTransactional(msg: EmailMessageInput): Promise<void> {
    return this.record(msg);
  }
  sendVerification(input: VerificationEmailInput): Promise<void> {
    return this.record(renderVerificationEmail(input));
  }
  sendInvite(input: InviteEmailInput): Promise<void> {
    return this.record(renderInviteEmail(input));
  }

  /// The last log recorded, or undefined if none.
  get last(): ConsoleEmailLog | undefined {
    return this.logs[this.logs.length - 1];
  }
}

/// Test double: records every message in-memory, sends nothing. Deterministic, no network.
export class FakeEmailSender implements EmailSender, RawEmailSender {
  readonly sent: EmailMessageInput[] = [];
  /// Audit B11: the PRODUCTION fallback fake does NOT deliver (default false), so signup
  /// reports emailSent:false. Tests that stand this in for a REAL delivering provider
  /// (to exercise the happy path) pass `delivers:true`.
  readonly delivers: boolean;
  /// Optional fault injection: if set, the NEXT send throws this and clears the field.
  failNext: Error | null = null;

  constructor(opts: { delivers?: boolean } = {}) {
    this.delivers = opts.delivers ?? false;
  }

  private record(msg: EmailMessageInput): Promise<void> {
    if (this.failNext) {
      const e = this.failNext;
      this.failNext = null;
      return Promise.reject(e);
    }
    this.sent.push(msg);
    return Promise.resolve();
  }

  send(msg: EmailMessageInput): Promise<void> {
    return this.record(msg);
  }
  sendTransactional(msg: EmailMessageInput): Promise<void> {
    return this.record(msg);
  }
  sendVerification(input: VerificationEmailInput): Promise<void> {
    return this.record(renderVerificationEmail(input));
  }
  sendInvite(input: InviteEmailInput): Promise<void> {
    return this.record(renderInviteEmail(input));
  }

  /// The last message recorded, or undefined if none. Handy in assertions.
  get last(): EmailMessageInput | undefined {
    return this.sent[this.sent.length - 1];
  }
  reset(): void {
    this.sent.length = 0;
    this.failNext = null;
  }
}

// ---- crypto helpers (WebCrypto / workerd globals; no Node built-ins) ------------------

const B64URL_ALPHABET_RE = /^[A-Za-z0-9_-]+$/;

function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // `BufferSource` wants an ArrayBuffer-backed view; copy to a fresh buffer to satisfy types
  // regardless of the input view's backing (e.g. SharedArrayBuffer).
  const buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return b64urlEncode(new Uint8Array(digest));
}

/// Constant-time equality of two base64url strings (the stored vs computed token hash).
/// Uses the workerd global `crypto.subtle.timingSafeEqual` when present (the platform-blessed
/// path), falling back to a length-independent XOR scan otherwise. Decode failures or length
/// mismatch return false WITHOUT short-circuiting on content.
function timingSafeEqualB64url(a: string, b: string): boolean {
  let ab: Uint8Array;
  let bb: Uint8Array;
  try {
    ab = b64urlDecode(a);
    bb = b64urlDecode(b);
  } catch {
    return false;
  }
  if (ab.length !== bb.length) return false;
  const subtle = crypto.subtle as SubtleCrypto & {
    timingSafeEqual?: (x: ArrayBufferView, y: ArrayBufferView) => boolean;
  };
  if (typeof subtle.timingSafeEqual === "function") {
    return subtle.timingSafeEqual(ab, bb);
  }
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

// ---- dependency injection seams (deterministic tests) --------------------------------

/// Injectable clock + randomness + id generation so issue/verify are fully deterministic in
/// tests. Production callers pass nothing and get the real WebCrypto-backed defaults.
export interface TokenDeps {
  now?: () => number; //                    epoch ms; default Date.now.
  randomBytes?: (n: number) => Uint8Array; // default crypto.getRandomValues.
  newId?: () => string; //                  default "evt-" + crypto.randomUUID().
}

function defaultRandomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

const SECRET_BYTES = 32; // 256-bit token secret.

// ---- issue / verify ------------------------------------------------------------------

export interface IssueTokenInput {
  orgId: string;
  accountId: string;
  email: string; //         stored lowercased+trimmed (canonical form, per CONTRACT §1.1).
  purpose: EmailTokenPurpose;
  /// Override the per-purpose default TTL (seconds). Useful for policy/tests.
  ttlSeconds?: number;
  /// If true (default), invalidate the account's outstanding tokens for this purpose first,
  /// so a resend supersedes older links. No-op if the store doesn't support it.
  supersede?: boolean;
}

export interface IssuedToken {
  /// The clear token to embed in the email link: `"<id>.<secret>"`. NEVER persisted.
  token: string;
  /// The persisted row (secret already discarded; only `tokenHash` survives).
  record: EmailTokenRecord;
}

function canonicalEmail(email: string): string {
  return email.trim().toLowerCase();
}

/// Issue a signed (hash-bound), single-use, expiring token and persist its hash. Returns the
/// CLEAR token (caller emails it) plus the stored record. The clear secret never touches the
/// store. Deterministic under injected `deps`.
export async function issueEmailToken(
  store: EmailTokenStore,
  input: IssueTokenInput,
  deps: TokenDeps = {},
): Promise<IssuedToken> {
  const now = (deps.now ?? Date.now)();
  const rnd = deps.randomBytes ?? defaultRandomBytes;
  const id = (deps.newId ?? (() => `evt-${crypto.randomUUID()}`))();
  const ttl = input.ttlSeconds ?? EMAIL_TOKEN_TTL_SECONDS[input.purpose];

  if (input.supersede !== false && store.invalidateOutstanding) {
    await store.invalidateOutstanding(input.accountId, input.purpose);
  }

  const secretBytes = rnd(SECRET_BYTES);
  const secret = b64urlEncode(secretBytes);
  const tokenHash = await sha256Hex(secretBytes);

  const record: EmailTokenRecord = {
    id,
    orgId: input.orgId,
    accountId: input.accountId,
    email: canonicalEmail(input.email),
    purpose: input.purpose,
    tokenHash,
    createdAt: now,
    expiresAt: now + Math.max(1, Math.floor(ttl)) * 1000,
    consumedAt: null,
  };
  await store.put(record);

  return { token: `${id}.${secret}`, record };
}

/// Why a verification failed. Callers map these to HTTP responses; the strings stay stable
/// so route handlers / tests can switch on them. `invalid` is deliberately coarse for
/// malformed/unknown/bad-secret so we don't leak which part was wrong.
export type EmailTokenError = "invalid" | "expired" | "consumed" | "purpose_mismatch";

export type VerifyResult =
  | { ok: true; record: EmailTokenRecord }
  | { ok: false; error: EmailTokenError };

/// Verify a clear token against the store for an EXPECTED purpose. On success the token is
/// atomically consumed (single-use) and the record returned. Order of checks is chosen so a
/// caller can't distinguish "wrong secret" from "no such token" (both -> `invalid`):
///   1. shape parse                              -> invalid
///   2. row exists                               -> invalid
///   3. purpose matches the caller's expectation -> purpose_mismatch
///   4. not expired                              -> expired
///   5. not already consumed                     -> consumed
///   6. secret hash matches (CONSTANT TIME)      -> invalid
///   7. atomic single-use consume                -> consumed (lost the race)
/// `now` is injected via `deps` for deterministic expiry tests.
export async function verifyEmailToken(
  store: EmailTokenStore,
  clearToken: string,
  expectedPurpose: EmailTokenPurpose,
  deps: TokenDeps = {},
): Promise<VerifyResult> {
  const result = await inspectEmailToken(store, clearToken, expectedPurpose, deps);
  if (!result.ok) return result;
  const now = (deps.now ?? Date.now)();
  if (!await store.consume(result.record.id, now)) return { ok: false, error: "consumed" };
  return { ok: true, record: { ...result.record, consumedAt: now } };
}

/** Non-consuming validation for operations that commit the token and credential atomically. */
export async function inspectEmailToken(
  store: EmailTokenStore,
  clearToken: string,
  expectedPurpose: EmailTokenPurpose,
  deps: TokenDeps = {},
): Promise<VerifyResult> {
  const now = (deps.now ?? Date.now)();

  const dot = clearToken.indexOf(".");
  if (dot <= 0 || dot >= clearToken.length - 1) return { ok: false, error: "invalid" };
  const id = clearToken.slice(0, dot);
  const secret = clearToken.slice(dot + 1);
  if (!B64URL_ALPHABET_RE.test(secret)) return { ok: false, error: "invalid" };

  const rec = await store.get(id);
  if (!rec) return { ok: false, error: "invalid" };
  if (rec.purpose !== expectedPurpose) return { ok: false, error: "purpose_mismatch" };
  if (now >= rec.expiresAt) return { ok: false, error: "expired" };
  if (rec.consumedAt !== null) return { ok: false, error: "consumed" };

  let presentedHash: string;
  try {
    presentedHash = await sha256Hex(b64urlDecode(secret));
  } catch {
    return { ok: false, error: "invalid" };
  }
  if (!timingSafeEqualB64url(presentedHash, rec.tokenHash)) {
    return { ok: false, error: "invalid" };
  }

  return { ok: true, record: rec };
}

// ---- high-level flows (issue + send) used by the route layer -------------------------

/// Build + send a verification email and persist its token in one call. The caller supplies a
/// `buildUrl(token)` that turns the clear token into the public link (origin/path policy lives
/// in integration, not here). Returns the issued record (no secret). Used by
/// `POST /v1/auth/verify-email/send` (CONTRACT §4.5).
export async function sendVerificationEmail(
  deps: {
    store: EmailTokenStore;
    sender: EmailSender;
    buildUrl: (token: string) => string;
    tokenDeps?: TokenDeps;
  },
  input: { orgId: string; accountId: string; email: string; displayName?: string; productName?: string },
): Promise<EmailTokenRecord> {
  const issued = await issueEmailToken(
    deps.store,
    { orgId: input.orgId, accountId: input.accountId, email: input.email, purpose: "verify_email" },
    deps.tokenDeps,
  );
  await deps.sender.sendVerification({
    to: issued.record.email,
    verifyUrl: deps.buildUrl(issued.token),
    displayName: input.displayName,
    productName: input.productName,
  });
  return issued.record;
}

/// Consume a `verify_email` token. On success the caller marks the account verified via
/// `AccountStore.setEmailVerified` (owned by the accounts adapter / integration). Backs
/// `POST /v1/auth/verify-email` (CONTRACT §4.5). Returns the verified account/email on success.
export async function confirmEmailToken(
  store: EmailTokenStore,
  clearToken: string,
  deps: TokenDeps = {},
): Promise<
  | { ok: true; accountId: string; orgId: string; email: string }
  | { ok: false; error: EmailTokenError }
> {
  const res = await verifyEmailToken(store, clearToken, "verify_email", deps);
  if (!res.ok) return res;
  return { ok: true, accountId: res.record.accountId, orgId: res.record.orgId, email: res.record.email };
}
