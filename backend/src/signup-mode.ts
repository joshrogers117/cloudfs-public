// SPDX-License-Identifier: AGPL-3.0-or-later
// signup-mode.ts — deployment policy gate for self-serve signup (POST /v1/auth/signup).
//
// cloud-fs is self-hosted now (not an open public SaaS), so org self-creation must be
// gateable. `SIGNUP_MODE` selects one of four policies; the gate runs BEFORE any org is
// provisioned (cheapest, fail-closed). A blocked signup returns a clear 403 with a typed
// code the SPA/CLI can branch on — never a generic error.
//
//   closed  — signup disabled entirely. Orgs are created out-of-band (bootstrap / admin
//             invite). 403 `signup_disabled`.
//   invite  — signup only with a valid invite token in the body (`inviteToken`), compared
//             CONSTANT-TIME against the SIGNUP_INVITE_TOKENS secret set. Missing/bad token
//             → 403 `signup_disabled`. (Self-host default: an operator hands out tokens.)
//   domain  — open, but only emails whose domain ∈ SIGNUP_ALLOWED_DOMAINS may sign up.
//             403 `domain_not_allowed` otherwise.
//   open    — anyone may sign up (legacy public-SaaS behaviour).
//
// DEFAULT = "invite" (safe for self-host). Any unrecognized value also resolves to "invite"
// (fail closed) rather than silently opening signup.

export type SignupMode = "closed" | "invite" | "domain" | "open";

export const SIGNUP_MODES: readonly SignupMode[] = ["closed", "invite", "domain", "open"];

export const DEFAULT_SIGNUP_MODE: SignupMode = "invite";

/// The env slice this gate reads. Mirrors the fields on `Env` so the gate is independently
/// testable with a plain object.
export interface SignupModeEnv {
  SIGNUP_MODE?: string;
  SIGNUP_ALLOWED_DOMAINS?: string;
  SIGNUP_INVITE_TOKENS?: string;
}

/// Resolve the effective mode. Unknown / unset → the safe default ("invite").
export function resolveSignupMode(env: SignupModeEnv): SignupMode {
  const raw = (env.SIGNUP_MODE ?? "").trim().toLowerCase();
  return (SIGNUP_MODES as readonly string[]).includes(raw) ? (raw as SignupMode) : DEFAULT_SIGNUP_MODE;
}

/// Parse the comma/space/newline-separated allowed-domain list into a normalized lowercase set
/// (leading "@" tolerated, blanks dropped).
export function parseAllowedDomains(raw?: string): Set<string> {
  const out = new Set<string>();
  for (const part of (raw ?? "").split(/[\s,]+/)) {
    const d = part.trim().toLowerCase().replace(/^@+/, "");
    if (d) out.add(d);
  }
  return out;
}

/// Parse the invite-token secret set (comma/space/newline-separated).
export function parseInviteTokens(raw?: string): string[] {
  return (raw ?? "").split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
}

/// Extract the email domain (the part after the last "@"), lowercased. "" if malformed.
export function emailDomain(email: string): string {
  const at = email.lastIndexOf("@");
  return at >= 0 ? email.slice(at + 1).trim().toLowerCase() : "";
}

/// Constant-time string equality (UTF-8 bytes). Uses the workerd-blessed
/// `crypto.subtle.timingSafeEqual` when present, else a length-independent XOR scan. Returns
/// false on length mismatch WITHOUT short-circuiting on content.
export function constantTimeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  const subtle = crypto.subtle as SubtleCrypto & {
    timingSafeEqual?: (x: ArrayBufferView, y: ArrayBufferView) => boolean;
  };
  if (typeof subtle.timingSafeEqual === "function") return subtle.timingSafeEqual(ab, bb);
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

/// Is `presented` one of the configured invite tokens? Constant-time per candidate; scans ALL
/// candidates (no early exit) so timing doesn't leak which token matched. Empty/missing config
/// or token → false (fail closed).
export function isValidInviteToken(presented: string | undefined, configured: string[]): boolean {
  if (!presented || configured.length === 0) return false;
  let ok = false;
  for (const cand of configured) {
    if (constantTimeEqual(presented, cand)) ok = true;
  }
  return ok;
}

/// Audit B7 — the insecure-open-signup tripwire decision (pure, unit-testable).
/// Returns true when signup MUST be refused because SIGNUP_MODE="open" on an https
/// deployment without the explicit `SIGNUP_OPEN_ON_HTTPS` opt-in. Localhost/http dev
/// is unaffected (isHttps=false), and a deployer who genuinely wants public signup
/// sets the opt-in. This stops the committed dev default ("open") from silently
/// handing strangers self-serve orgs when deployed verbatim.
export function shouldRefuseOpenSignupOnHttps(
  env: { SIGNUP_MODE?: string; SIGNUP_OPEN_ON_HTTPS?: string },
  isHttps: boolean,
): boolean {
  if (resolveSignupMode(env) !== "open") return false;
  if (!isHttps) return false;
  const optIn = /^(1|true|yes|on)$/i.test((env.SIGNUP_OPEN_ON_HTTPS ?? "").trim());
  return !optIn;
}

export interface SignupGateInput {
  /// Canonical (lowercased) email of the prospective owner.
  email: string;
  /// The invite token presented in the signup body (only meaningful for mode="invite").
  inviteToken?: string;
}

export type SignupGateResult =
  | { allowed: true; mode: SignupMode }
  | { allowed: false; mode: SignupMode; status: 403; code: "signup_disabled" | "domain_not_allowed" };

/// THE gate. Returns whether this signup may proceed under the deployment's SIGNUP_MODE, and a
/// typed 403 code when blocked. Pure + side-effect-free so the wiring layer can call it before
/// provisioning anything and the unit tests can exercise every branch directly.
export function evaluateSignupGate(env: SignupModeEnv, input: SignupGateInput): SignupGateResult {
  const mode = resolveSignupMode(env);
  switch (mode) {
    case "open":
      return { allowed: true, mode };
    case "closed":
      return { allowed: false, mode, status: 403, code: "signup_disabled" };
    case "invite": {
      const ok = isValidInviteToken(input.inviteToken, parseInviteTokens(env.SIGNUP_INVITE_TOKENS));
      return ok
        ? { allowed: true, mode }
        : { allowed: false, mode, status: 403, code: "signup_disabled" };
    }
    case "domain": {
      const allowed = parseAllowedDomains(env.SIGNUP_ALLOWED_DOMAINS);
      const domain = emailDomain(input.email);
      // No domains configured under "domain" mode = nobody allowed (fail closed).
      return domain && allowed.has(domain)
        ? { allowed: true, mode }
        : { allowed: false, mode, status: 403, code: "domain_not_allowed" };
    }
  }
}
