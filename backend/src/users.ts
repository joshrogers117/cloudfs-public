// SPDX-License-Identifier: AGPL-3.0-or-later
// users.ts — user lifecycle + service accounts + group CRUD (SPEC §4.5 / §4.10).
//
// Thin, gateway-mountable handler over OrgDO. It owns the USER-facing surface:
//   - human users: create / list / get / disable / role assignment
//   - service accounts: create (CLI & render-farm identities, SPEC §3.8)
//   - groups: create / list / delete / membership add-remove
//
// All persistence lives in OrgDO (org-do.ts). This module is the routing + policy
// layer the gateway calls. It does NOT verify tokens — the security agent's auth
// middleware resolves an `AuthedContext` and passes it in (SPEC ownership rule).

import type { OrgDOEnv, AuthedContext, User, Group, UserStatus } from "./org-do";
import type { OrgRole } from "./permissions";
import { evaluateRoleAssignment } from "./permissions";
import type { Env } from "./env";
import { propagateAccountOffboarding } from "./auth-wiring";
import { invalidateUser, invalidateOrgAcl } from "./gate-cache";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function requireAdmin(ctx: AuthedContext): Response | null {
  return ctx.orgRole === "owner" || ctx.orgRole === "admin"
    ? null
    : json({ error: "forbidden: admin required" }, 403);
}

// ---- service-layer helpers (also reusable by invites.ts) -------------------

export interface CreateUserInput {
  email: string;
  displayName: string;
  role?: OrgRole;
  idpSubject?: string | null;
}

export async function createUser(env: OrgDOEnv, orgId: string, input: CreateUserInput): Promise<User> {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  return stub.createUser({ orgId, ...input });
}

export async function createServiceAccount(
  env: OrgDOEnv,
  orgId: string,
  name: string,
  role: OrgRole = "standard",
): Promise<User> {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  return stub.createServiceAccount({ orgId, name, role });
}

export async function disableUser(env: OrgDOEnv, orgId: string, userId: string): Promise<User> {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  return stub.setUserStatus(userId, "deprovisioned");
}

export async function setUserRole(env: OrgDOEnv, orgId: string, userId: string, role: OrgRole): Promise<User> {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  return stub.setUserRole(userId, role);
}

export async function listGroupsForUser(env: OrgDOEnv, orgId: string, userId: string): Promise<string[]> {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  return stub.groupsForUser(userId);
}

// ---- HTTP handler ----------------------------------------------------------

/**
 * Mounted at /v1/orgs/:orgId/users/** and /v1/orgs/:orgId/groups/**.
 * `pathParts` is the path AFTER /v1/orgs/:orgId — e.g. ["users"], ["users","usr-x"],
 * ["groups","grp-y","members"].
 */
export async function handleUsersRequest(
  req: Request,
  env: Env,
  ctx: AuthedContext,
  pathParts: string[],
  orgId: string,
): Promise<Response> {
  const stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  const resource = pathParts[0];
  // The workspace directory is an administration surface, including CLI reads.
  // Delegated folder administrators use the scoped access-management endpoint.
  const denied = requireAdmin(ctx);
  if (denied) return denied;

  try {
    if (resource === "users") {
      // reads and writes: workspace administrators only
      if (req.method === "GET" && !pathParts[1]) return json(await stub.listUsers());
      if (req.method === "GET" && pathParts[1]) {
        const u = await stub.getUser(decodeURIComponent(pathParts[1]));
        return u ? json(u) : json({ error: "no such user" }, 404);
      }
      // writes: admin only
      const deny = requireAdmin(ctx);
      if (deny) return deny;

      if (req.method === "POST") {
        const b = (await req.json()) as any;
        // Audit B12: a created user/service-account's role is bounded by the actor's role
        // (no minting an owner unless the actor is an owner; no role above the actor's tier;
        // unknown roles rejected). The target id is "new" so the self-role-change rule never
        // trips.
        if (b.role) {
          const decision = evaluateRoleAssignment({
            actorRole: ctx.orgRole, actorUserId: ctx.principalUserId,
            targetUserId: "<new>", requestedRole: b.role,
          });
          if (!decision.allowed) return json({ error: "forbidden_role_assignment", reason: decision.code }, 403);
        }
        if (b.kind === "service_account") {
          if (!b.name) return json({ error: "service account requires name" }, 400);
          return json(await stub.createServiceAccount({ orgId, name: b.name, role: b.role }), 201);
        }
        if (!b.email || !b.displayName) return json({ error: "email and displayName required" }, 400);
        return json(await stub.createUser({ orgId, email: b.email, displayName: b.displayName, role: b.role }), 201);
      }
      if (req.method === "PATCH" && pathParts[1]) {
        const id = decodeURIComponent(pathParts[1]);
        const b = (await req.json()) as { status?: UserStatus; role?: OrgRole };
        if (b.status) {
          try {
            const u = await stub.setUserStatus(id, b.status);
            // FINDING 1+11: propagate the status change into the AuthDO so a suspended/deprovisioned
            // user can't log in or keep using a live session/service token (OrgDO alone wouldn't bite).
            await propagateAccountOffboarding(env, orgId, id, b.status);
            // Audit B21: drop this user's cached account-status + ACL principal so the gate sees the
            // new status on the NEXT request (the TTL is a ceiling, not the authority).
            invalidateUser(orgId, id);
            return json(u);
          } catch (e) {
            if ((e as Error)?.name === "LastOwnerError") return json({ error: "last_owner", reason: (e as Error).message }, 409);
            throw e;
          }
        }
        if (b.role) {
          // Audit B12: enforce the role-transition policy BEFORE the write — only an owner
          // may assign `owner`, no elevation above the actor, no self-role-change, no
          // unknown roles. Closes the admin→owner privilege-escalation hole.
          const decision = evaluateRoleAssignment({
            actorRole: ctx.orgRole, actorUserId: ctx.principalUserId,
            targetUserId: id, requestedRole: b.role,
          });
          if (!decision.allowed) return json({ error: "forbidden_role_assignment", reason: decision.code }, 403);
          try {
            const u = await stub.setUserRole(id, b.role);
            // Audit B21: a role change must take effect immediately — drop the user's cached ACL
            // principal (groups+role) so the next gated op re-resolves the live role.
            invalidateUser(orgId, id);
            return json(u);
          } catch (e) {
            if ((e as Error)?.name === "LastOwnerError") return json({ error: "last_owner", reason: (e as Error).message }, 409);
            throw e;
          }
        }
        return json({ error: "nothing to update (status|role)" }, 400);
      }
      if (req.method === "DELETE" && pathParts[1]) {
        // soft-delete: deprovision (SCIM also drives this)
        const id = decodeURIComponent(pathParts[1]);
        const u = await stub.setUserStatus(id, "deprovisioned");
        // FINDING 1+11: revoke credentials/sessions + release the email in the AuthDO/DirectoryDO.
        await propagateAccountOffboarding(env, orgId, id, "deprovisioned");
        // Audit B21: offboarding must bite on the next request — drop the user's cached authz.
        invalidateUser(orgId, id);
        return json(u);
      }
    }

    if (resource === "groups") {
      if (req.method === "GET" && !pathParts[1]) return json(await stub.listGroups());

      const deny = requireAdmin(ctx);
      if (deny) return deny;

      if (req.method === "POST" && !pathParts[1]) {
        const b = (await req.json()) as { name: string; source?: "manual" | "scim" };
        if (!b.name) return json({ error: "group name required" }, 400);
        return json(await stub.createGroup({ orgId, name: b.name, source: b.source }), 201);
      }
      if (pathParts[1] && pathParts[2] === "members") {
        const groupId = decodeURIComponent(pathParts[1]);
        if (req.method === "GET") return json(await stub.membersOfGroup(groupId));
        if (req.method === "POST") {
          const b = (await req.json()) as { userId: string };
          await stub.addGroupMember(groupId, b.userId);
          // Audit B21: group membership feeds the group-union ACL — drop this user's cached principal.
          invalidateUser(orgId, b.userId);
          return json({ ok: true });
        }
        if (req.method === "DELETE") {
          const userId = new URL(req.url).searchParams.get("userId") ?? "";
          await stub.removeGroupMember(groupId, userId);
          invalidateUser(orgId, userId);
          return json({ ok: true });
        }
      }
      if (req.method === "DELETE" && pathParts[1]) {
        const groupId = decodeURIComponent(pathParts[1]);
        await stub.deleteGroup(groupId);
        // Audit B21: a deleted group can change the effective grants of ALL its (former) members and
        // we don't enumerate them here — conservatively drop the whole org's ACL-principal cache.
        invalidateOrgAcl(orgId);
        return json({ ok: true });
      }
    }

    return json({ error: "not found" }, 404);
  } catch (e: any) {
    return json({ error: String(e?.message ?? e) }, 500);
  }
}

export type { User, Group };
