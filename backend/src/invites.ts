// SPDX-License-Identifier: AGPL-3.0-or-later
// invites.ts — invite tokens: create / redeem / expiry / single-use / revoke / list.
//
// An invite is a one-time, expiring token (emailed to a prospective member) that,
// when redeemed, provisions a User with a given org role and optionally grants a
// scoped ACL on a filespace/folder (SPEC §4.5 onboarding; §4.10 — guest links are a
// SEPARATE external-share concept handled in sharing.ts).
//
// SPLIT for testability + ownership:
//   - PURE token logic (this file's top half): mint/hash/validate. No DO, no env —
//     so invites.test.ts exercises it directly. We do the hashing ourselves with
//     Web Crypto SHA-256 (a one-way digest for storage, NOT a JWT/auth token — the
//     security agent owns session crypto; this is just so a leaked DB row can't be
//     redeemed). The raw token is shown exactly once, at create time.
//   - DO-backed handler (bottom half): persists InviteRecord rows in OrgDO and, on
//     redeem, provisions the user + (optionally) the scoped grant.

import type { OrgDOEnv, AuthedContext, InviteRecord, InviteStatus } from "./org-do";
import type { OrgRole, Level } from "./permissions";
import { evaluateRoleAssignment } from "./permissions";
import type { EmailSender } from "./security/auth-email";

// ---- pure token logic ------------------------------------------------------

export interface InviteScope {
  spaceId?: string | null;
  inodeId?: string | null;
  level?: Level | null;
}

export interface NewInviteToken {
  /** The raw token to email — shown ONCE, never stored. Format: `inv_<id>.<secret>`. */
  rawToken: string;
  /** The id embedded in the token (also the InviteRecord id). */
  inviteId: string;
  /** SHA-256 hex of the raw secret — this is what we persist. */
  tokenHash: string;
}

/** Generate a cryptographically-random invite token + its storage hash. */
export async function mintInviteToken(): Promise<NewInviteToken> {
  const inviteId = `inv-${crypto.randomUUID()}`;
  const secretBytes = new Uint8Array(32);
  crypto.getRandomValues(secretBytes);
  const secret = toHex(secretBytes);
  const rawToken = `${inviteId}.${secret}`;
  const tokenHash = await sha256Hex(rawToken);
  return { rawToken, inviteId, tokenHash };
}

/** Parse a raw token presented at redeem time into its (id, hash) pair. */
export async function parseInviteToken(rawToken: string): Promise<{ inviteId: string; tokenHash: string } | null> {
  const dot = rawToken.indexOf(".");
  if (dot <= 0) return null;
  const inviteId = rawToken.slice(0, dot);
  if (!inviteId.startsWith("inv-")) return null;
  const tokenHash = await sha256Hex(rawToken);
  return { inviteId, tokenHash };
}

export type RedeemError = "not_found" | "expired" | "revoked" | "already_used" | "token_mismatch";

/** Pure validation of a stored record against a presented token hash + clock. */
export function validateInvite(
  record: InviteRecord | null,
  presentedHash: string,
  nowMs: number,
): { ok: true } | { ok: false; error: RedeemError } {
  if (!record) return { ok: false, error: "not_found" };
  if (record.tokenHash !== presentedHash) return { ok: false, error: "token_mismatch" };
  if (record.status === "revoked") return { ok: false, error: "revoked" };
  if (record.status === "accepted") return { ok: false, error: "already_used" };
  if (record.status === "expired" || record.expiresAt <= nowMs) return { ok: false, error: "expired" };
  return { ok: true };
}

export const DEFAULT_INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// ---- DO-backed operations --------------------------------------------------

export interface CreateInviteInput {
  email: string;
  role?: OrgRole;
  scope?: InviteScope;
  ttlMs?: number;
}

export interface CreateInviteResult {
  invite: InviteRecord;
  /** Raw token to email the recipient — shown ONCE. Org-scoped: valid on the
   *  `/v1/orgs/:org/invites/redeem` route (which already knows the org from the path). */
  rawToken: string;
  /** ORG-QUALIFIED form of `rawToken` (`"<orgId>.<rawToken>"`), following the device-code
   *  precedent (`auth-wiring.ts` `qualify`/`split`). The join lane (`POST /v1/auth/join`) is
   *  public and mounted OUTSIDE any `/v1/orgs/:org` path, so it has no other way to learn
   *  which org's AuthDO/OrgDO a bare token belongs to — the join link MUST be self-contained.
   *  `rawToken` above is kept unqualified for back-compat with the existing admin-facing
   *  create response / org-scoped redeem route. */
  joinToken: string;
}

/** Create + persist an invite. Returns the raw token (caller emails it). */
export async function createInvite(
  env: OrgDOEnv,
  orgId: string,
  createdByMemberId: string,
  input: CreateInviteInput,
): Promise<CreateInviteResult> {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  const { rawToken, inviteId, tokenHash } = await mintInviteToken();
  const t = Date.now();
  const record: InviteRecord = {
    id: inviteId,
    orgId,
    email: input.email,
    role: input.role ?? "standard",
    tokenHash,
    spaceId: input.scope?.spaceId ?? null,
    inodeId: input.scope?.inodeId ?? null,
    level: input.scope?.level ?? null,
    status: "pending",
    createdByMemberId,
    createdAt: t,
    expiresAt: t + (input.ttlMs ?? DEFAULT_INVITE_TTL_MS),
    acceptedByUserId: null,
    acceptedAt: null,
  };
  await stub.putInvite(record);
  return { invite: record, rawToken, joinToken: `${orgId}.${rawToken}` };
}

export interface RedeemResult {
  ok: boolean;
  error?: RedeemError;
  userId?: string;
  /** Id of the ACL grant written on redeem (present iff the invite was scoped). */
  grantId?: string;
  /** Echoes the scope so the gateway can sync the grant into the space's store. */
  scope?: InviteScope & { role: OrgRole };
}

/**
 * Redeem an invite: validate the token (single-use, unexpired, not revoked),
 * provision/find the User, write the scoped ACL grant the invite promised (durably,
 * in OrgDO), then mark the invite accepted. Returns the new user id + grant id. The
 * gateway syncs the OrgDO grant into the space's enforcement store (see INTEGRATION §5).
 */
export async function redeemInvite(
  env: OrgDOEnv,
  orgId: string,
  rawToken: string,
  displayName: string,
): Promise<RedeemResult> {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  const parsed = await parseInviteToken(rawToken);
  if (!parsed) return { ok: false, error: "not_found" };

  const record = await stub.getInvite(parsed.inviteId);
  const check = validateInvite(record, parsed.tokenHash, Date.now());
  if (!check.ok) {
    // lazily flip an expired-but-still-pending record so listPending is accurate
    if (check.error === "expired" && record && record.status === "pending") {
      await stub.updateInviteStatus(record.id, "expired");
    }
    return { ok: false, error: check.error };
  }
  const rec = record!; // validated non-null

  // provision (or reuse) the member
  let user = await stub.getUserByEmail(rec.email);
  if (!user) {
    user = await stub.createUser({ orgId, email: rec.email, displayName, role: rec.role });
  }

  // Apply the scoped permission the invite promised: if the invite named a
  // filespace folder + level, durably write the ACL grant so the redeemed user
  // actually has access (SPEC §4.10 Grant; see multiuser-INTEGRATION.md §5).
  let grantId: string | undefined;
  if (rec.spaceId && rec.inodeId && rec.level) {
    grantId = `grant-${rec.spaceId}-${rec.inodeId}-user-${user.id}-${crypto.randomUUID().slice(0, 8)}`;
    await stub.putGrant({
      id: grantId,
      spaceId: rec.spaceId,
      inodeId: rec.inodeId,
      principalType: "user",
      principalId: user.id,
      level: rec.level,
      mountAsRoot: false,
      expiresAt: null,
      grantedByMemberId: rec.createdByMemberId,
      grantedAt: Date.now(),
    });
  }

  // single-use: mark accepted (a second redeem now fails "already_used")
  await stub.updateInviteStatus(rec.id, "accepted", user.id);

  return {
    ok: true,
    userId: user.id,
    grantId,
    scope: { spaceId: rec.spaceId, inodeId: rec.inodeId, level: rec.level, role: rec.role },
  };
}

export async function revokeInvite(env: OrgDOEnv, orgId: string, inviteId: string): Promise<boolean> {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  const rec = await stub.getInvite(inviteId);
  if (!rec || rec.status !== "pending") return false;
  await stub.updateInviteStatus(inviteId, "revoked");
  return true;
}

export async function listPendingInvites(env: OrgDOEnv, orgId: string): Promise<InviteRecord[]> {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  return stub.listPendingInvites();
}

// ---- HTTP handler ----------------------------------------------------------

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/// Exported so the `POST /v1/auth/join` composition lane (auth-wiring.ts) — which validates an
/// invite BEFORE calling `redeemInvite` and again maps `RedeemResult.error` — maps identically to
/// this org-scoped redeem route, one source of truth for the status codes.
export const REDEEM_HTTP_STATUS: Record<RedeemError, number> = {
  not_found: 404,
  expired: 410,
  revoked: 410,
  already_used: 409,
  token_mismatch: 401,
};

/// Injected email-notification deps for invite creation (DI seam, mirroring `SignupDeps` in
/// auth-signup.ts) — kept OUT of this file's own imports so invites.ts never has to import the
/// auth-wiring/auth-stores integration layer (which would create a module cycle: auth-wiring.ts
/// imports invite-redeem primitives FROM this file for the join lane). The caller (index.ts)
/// builds the concrete sender/URL-builder from `env`/`req` and passes a THUNK so the (fairly
/// expensive: an OrgDO email-config read) resolution only happens for an actual create call, not
/// on every GET/DELETE.
export interface InviteNotifyDeps {
  emailSender: EmailSender;
  /** Turn the ORG-QUALIFIED join token into the public `/join?token=…` link a human clicks. */
  buildJoinUrl: (joinToken: string) => string;
  productName?: string;
}

/**
 * Mounted at /v1/orgs/:orgId/invites/**.
 *   POST   /invites                  create (admin/space_admin; emails the join link when a
 *                                    delivering provider is configured — see `notify`)
 *   GET    /invites                  list pending (admin)
 *   POST   /invites/redeem           redeem { token, displayName } (PUBLIC — no session;
 *                                    the token IS the credential, like a guest code)
 *   DELETE /invites/:id              revoke (admin)
 * `pathParts` is the path AFTER /v1/orgs/:orgId. `notify` is an optional thunk the integration
 * layer supplies so a successful create can email the invitee their join link (Build step 1 of
 * ONBOARDING.md); omitted (e.g. in unit tests) the create response just reports
 * `emailSent: false` and sends nothing.
 */
export async function handleInvitesRequest(
  req: Request,
  env: OrgDOEnv,
  ctx: AuthedContext | null, // null is allowed ONLY for the public redeem route
  pathParts: string[],
  orgId: string,
  notify?: () => Promise<InviteNotifyDeps>,
): Promise<Response> {
  const sub = pathParts[1];
  const isAdmin = ctx?.orgRole === "owner" || ctx?.orgRole === "admin";

  try {
    // PUBLIC redeem — the invite token is the credential, no prior session needed.
    if (sub === "redeem" && req.method === "POST") {
      const b = (await req.json()) as { token: string; displayName?: string };
      if (!b.token) return json({ error: "token required" }, 400);
      const result = await redeemInvite(env, orgId, b.token, b.displayName ?? b.token);
      if (!result.ok) return json({ error: result.error }, REDEEM_HTTP_STATUS[result.error!]);
      return json(result, 200);
    }

    // Inviting or inspecting workspace accounts requires owner/admin.
    if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);

    if (!sub && req.method === "POST") {
      const b = (await req.json()) as CreateInviteInput;
      if (!b.email) return json({ error: "email required" }, 400);
      // Audit B12: an invite mints a User with a role on redeem, so cap the INVITABLE role
      // by the creator's role — a non-owner can NEVER invite an owner, and no one can invite
      // a role above their own tier. (`redeem` provisions the user, so this is the only place
      // the role is gated.) The target is "new" so the self-role-change rule never trips.
      if (b.role) {
        const decision = evaluateRoleAssignment({
          actorRole: ctx!.orgRole, actorUserId: ctx!.principalUserId,
          targetUserId: "<invite>", requestedRole: b.role,
        });
        if (!decision.allowed) return json({ error: "forbidden_role_assignment", reason: decision.code }, 403);
      }
      const out = await createInvite(env, orgId, ctx!.principalUserId, b);
      // Send the invite email (Build step 1 of ONBOARDING.md — invites previously provisioned
      // membership on redeem but were NEVER emailed). Best-effort + non-fatal: a delivery
      // failure (or no provider configured at all) must not fail the create — the admin still
      // gets the invite row + a copy-able link; `emailSent` tells the web UI whether to show
      // "sent" or honest copy-link fallback copy (mirrors the signup B11 pattern).
      let emailSent = false;
      if (notify) {
        try {
          const deps = await notify();
          const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
          const [orgName, inviter] = await Promise.all([
            stub.getOrgName().catch(() => null),
            stub.getUser(ctx!.principalUserId).catch(() => null),
          ]);
          await deps.emailSender.sendInvite({
            to: out.invite.email,
            acceptUrl: deps.buildJoinUrl(out.joinToken),
            orgName: orgName ?? undefined,
            invitedByName: inviter?.displayName,
            productName: deps.productName,
          });
          // Audit B11 pattern: a no-op/console sender resolves "successfully" but drops the
          // mail — report that honestly rather than a phantom `emailSent:true`.
          emailSent = deps.emailSender.delivers !== false;
          if (!emailSent) {
            console.warn(
              `invite: NO delivering email provider configured — invite mail for invite=${out.invite.id} org=${orgId} was NOT delivered (copy-link fallback applies).`,
            );
          }
        } catch (e) {
          emailSent = false;
          console.warn(
            `invite: email delivery failed for invite=${out.invite.id} org=${orgId} (invite still created; admin can copy the link): ${
              e instanceof Error ? e.message : String(e)
            }`,
          );
        }
      }
      return json({ ...out, emailSent }, 201);
    }
    if (!sub && req.method === "GET") {
      return json(await listPendingInvites(env, orgId));
    }
    if (sub && req.method === "DELETE") {
      const ok = await revokeInvite(env, orgId, decodeURIComponent(sub));
      return ok ? json({ revoked: true }) : json({ error: "not a pending invite" }, 404);
    }

    return json({ error: "not found" }, 404);
  } catch (e: any) {
    return json({ error: String(e?.message ?? e) }, 500);
  }
}

// ---- crypto utils (one-way digest only; not auth tokens) -------------------

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toHex(new Uint8Array(digest));
}

export type { InviteRecord, InviteStatus };
