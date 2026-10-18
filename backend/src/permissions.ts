// SPDX-License-Identifier: AGPL-3.0-or-later
// permissions.ts — per-folder ACL model for cloud-fs (SPEC §4.3 / §4.10 Grant).
//
// This is the access-control CORE. It is deliberately a PURE module with no
// Cloudflare/DO/crypto dependencies, so it can be unit-tested in isolation and
// called from anywhere the gateway needs an authorization decision — most
// importantly at presigned-URL mint time (SPEC §4.4: the gateway is the sole
// enforcement point) and before any metadata mutation in FilespaceDO.
//
// Fine-grained permissions model, preserved deliberately:
//   - grants attach to FOLDER nodes; files inherit from their folder (per-file
//     overrides are schema-supported but discouraged)
//   - access levels are a strict ladder: read < edit < admin
//   - NO explicit deny verb — absence of a grant == no access
//   - recursive inheritance: a node with no explicit ACL inherits its parent's
//   - GROUP UNION: a principal holds the union of all its groups' grants + direct;
//     highest level wins (safe because there is no deny)
//   - mutation (rename/move/delete) requires write on BOTH the item AND its parent
//   - sub-path mount (`mountAsRoot`) confines a principal to a subtree
//   - optional `expiresAt` on a grant (expiring member grant, §4.3)

// ---- principals & levels ---------------------------------------------------

export type PrincipalType = "user" | "group" | "service_account";

/** The authenticated caller, resolved by the security/auth layer (injected — we
 *  never mint/verify tokens here, SPEC ownership rule). `groupIds` is the caller's
 *  full group membership (incl. SCIM-synced groups) so we can evaluate group-union. */
export interface Principal {
  type: PrincipalType;
  id: string;
  /** Group ids this principal belongs to (empty for groups themselves). */
  groupIds?: string[];
  /** Org role short-circuit: owner/admin (and space_admin — see OrgRole) see everything. */
  orgRole?: OrgRole;
}

// CHANGE E: `space_admin` has ORG-WIDE admin authority — it is NOT scoped per-space.
// It is treated identically to `admin` everywhere data access is concerned. The ONE
// capability reserved to `owner` alone is repointing a space's storage backend
// (enforced in org-do.ts, not here). owner ⊇ admin ≈ space_admin ⊃ standard.
export type OrgRole = "owner" | "admin" | "space_admin" | "standard";

/** The known org roles, in ascending privilege order. */
export const ORG_ROLES: readonly OrgRole[] = ["standard", "space_admin", "admin", "owner"];

/** Privilege rank for a role (higher = more privileged). Unknown ⇒ -1 (rejected). */
export function orgRoleRank(role: string): number {
  const i = (ORG_ROLES as readonly string[]).indexOf(role);
  return i;
}

/// Audit B12 — the role-assignment policy, enforced at the gateway BEFORE any role write.
/// Closes the privilege-escalation hole where any admin could PATCH themselves (or anyone)
/// to `owner` and then repoint the filespace's storage backend. Rules:
///   • the requested role must be a KNOWN role (no arbitrary strings);
///   • only an OWNER may assign or revoke the `owner` role (admins can't mint/demote owners);
///   • an actor may not assign a role STRICTLY ABOVE their own (no self/other elevation past
///     the actor's tier — an admin can't create another admin's superior);
///   • an actor may not change THEIR OWN role (no self-elevation; an owner stepping down is a
///     deliberate, separately-gated action — and the last-owner guard still applies).
export type RoleAssignmentDecision =
  | { allowed: true }
  | { allowed: false; code: "unknown_role" | "owner_requires_owner" | "exceeds_actor_role" | "no_self_role_change" };

export function evaluateRoleAssignment(input: {
  actorRole: OrgRole;
  actorUserId: string;
  targetUserId: string;
  requestedRole: string;
}): RoleAssignmentDecision {
  const rank = orgRoleRank(input.requestedRole);
  if (rank < 0) return { allowed: false, code: "unknown_role" };
  // Only an owner may grant/revoke the owner role.
  if (input.requestedRole === "owner" && input.actorRole !== "owner") {
    return { allowed: false, code: "owner_requires_owner" };
  }
  // No assigning a role above the actor's own tier.
  if (rank > orgRoleRank(input.actorRole)) {
    return { allowed: false, code: "exceeds_actor_role" };
  }
  // No changing your own role through this path (self-elevation guard).
  if (input.actorUserId === input.targetUserId) {
    return { allowed: false, code: "no_self_role_change" };
  }
  return { allowed: true };
}

/** Strict access ladder. Higher number ⊇ lower. */
export type Level = "read" | "edit" | "admin";

export const LEVEL_RANK: Record<Level, number> = { read: 1, edit: 2, admin: 3 };

/** What the caller wants to do, mapped to the minimum level it requires. */
export type Action =
  | "list" // read a folder's children
  | "read" // fetch file bytes (mint GET)
  | "write" // create/modify file bytes (mint PUT) within a folder
  | "create" // create a child node
  | "delete" // remove a node (also needs write on parent — see decision)
  | "rename" // rename/move a node (also needs write on parent)
  | "manage_acl"; // grant/revoke ACLs on this subtree

const ACTION_MIN_LEVEL: Record<Action, Level> = {
  list: "read",
  read: "read",
  write: "edit",
  create: "edit",
  delete: "edit",
  rename: "edit",
  manage_acl: "admin",
};

/** Actions that, per rule §4.3(4), additionally require write on the PARENT. */
const REQUIRES_PARENT_WRITE: ReadonlySet<Action> = new Set<Action>(["delete", "rename"]);

// ---- the ACL grant ---------------------------------------------------------

/** One ACL row (SPEC §4.10 Grant). Targets an inode (folder usually, file override). */
export interface Grant {
  id: string;
  spaceId: string;
  /** inode id the grant attaches to (a folder node, or a file for an override). */
  inodeId: string;
  principalType: PrincipalType;
  principalId: string;
  level: Level;
  /** RootPoint: this grant roots the principal's mount at `inodeId` (sub-path mount). */
  mountAsRoot?: boolean;
  /** epoch ms; grant is ignored once `Date.now() >= expiresAt`. */
  expiresAt?: number | null;
  grantedByMemberId: string;
  grantedAt: number;
  /** Delegated read/edit grants remain bound to a live, original admin grant. */
  authorityGrantId?: string | null;
  authorityInodeId?: string | null;
}

/** Minimal inode shape the evaluator needs to walk the tree to the root. */
export interface InodeNode {
  id: string;
  parentId: string | null; // null == space root
  type: "folder" | "file";
}

/** The evaluator reads from this — backed by the OrgDO/FilespaceDO in production,
 *  by an in-memory map in tests. Pure read interface keeps canAccess() pure. */
export interface PermissionStore {
  /** Resolve an inode to its node (for parent-walk). null if missing. */
  getInode(inodeId: string): InodeNode | null;
  /** All grants on a single inode (any principal). */
  grantsForInode(inodeId: string): Grant[];
}

// ---- the decision ----------------------------------------------------------

export interface Decision {
  allow: boolean;
  /** Effective level the principal holds at the target inode (null = no access). */
  effectiveLevel: Level | null;
  /** Why — for audit logging (SPEC §4.8: the audit log is authoritative). */
  reason: string;
  /** The inode whose grant produced the decision (nearest explicit ACL), for audit. */
  decidedAtInodeId?: string;
  /** If a mountAsRoot grant applies on the path, the inode it roots at (RootPoint). */
  rootInodeId?: string;
}

// ---- effective-level evaluation (the heart) --------------------------------

export function principalMatches(g: Grant, p: Principal): boolean {
  // Auth-spec §2.7 / B11: `user` and `service_account` grants match by ID across BOTH types.
  // A device-minted daemon token verifies as a `service`-type JWS (mapped to a
  // `service_account` ACL principal) but ACTS AS the human user — Principal.sub/id IS the
  // user's id — so a grant targeting user U must be honored when that daemon token presents
  // id U. The converse (a service_account grant matching a `user` principal with the same id)
  // is equally sound: OrgDO user ids are globally unique per row, so an id can only ever name
  // ONE identity — the type tag distinguishes how the caller authenticated, not who they are.
  if (
    (g.principalType === "user" || g.principalType === "service_account") &&
    (p.type === "user" || p.type === "service_account") &&
    g.principalId === p.id
  ) {
    return true;
  }
  // group-union: a user/service-account picks up grants targeting any of its groups
  if (g.principalType === "group") {
    if (p.type === "group" && p.id === g.principalId) return true;
    return !!p.groupIds?.includes(g.principalId);
  }
  return false;
}

function isLive(g: Grant, now: number): boolean {
  return !g.expiresAt || now < g.expiresAt;
}

/** Current namespace containment, bounded and fail-closed on missing nodes/cycles. */
export function isWithinSubtree(store: PermissionStore, inodeId: string, rootId: string): boolean {
  let current: string | null = inodeId;
  const seen = new Set<string>();
  while (current && seen.size < 4096 && !seen.has(current)) {
    seen.add(current);
    const node = store.getInode(current);
    if (!node) return false;
    if (current === rootId) return true;
    current = node.parentId;
  }
  return false;
}

/** Workspace-issued overrides define an authority's boundary. Never recurse
 * through delegated grants or borrow an issuing user's other groups. */
export function originalAuthorityLevel(store: PermissionStore, principal: Principal, inodeId: string, now = Date.now()): Level | null {
  let current: string | null = inodeId;
  const seen = new Set<string>();
  while (current && seen.size < 4096 && !seen.has(current)) {
    seen.add(current);
    const node = store.getInode(current);
    if (!node) return null;
    const matching = store.grantsForInode(current).filter(row => !row.authorityGrantId && !row.authorityInodeId
      && principalMatches(row, principal) && isLive(row, now));
    if (matching.length) return matching.reduce<Level>((best, row) => LEVEL_RANK[row.level] > LEVEL_RANK[best] ? row.level : best, "read");
    current = node.parentId;
  }
  return null;
}

/** One-level delegation deliberately cannot create further administrators. A moved
 * child, revoked/expired authority, or deleted authority root never widens access.
 * Snapshot callers must validate this against the LIVE store before projecting it. */
export function isGrantLive(store: PermissionStore, g: Grant, now = Date.now()): boolean {
  if (!isLive(g, now)) return false;
  if (!g.authorityGrantId && !g.authorityInodeId) return true;
  if (!g.authorityGrantId || !g.authorityInodeId || g.level === "admin") return false;
  const source = store.grantsForInode(g.authorityInodeId).find(row => row.id === g.authorityGrantId);
  return !!source && source.level === "admin" && !source.authorityGrantId && !source.authorityInodeId
    && isLive(source, now) && store.getInode(source.inodeId)?.type === "folder"
    && isWithinSubtree(store, g.inodeId, source.inodeId)
    && originalAuthorityLevel(store, { type: source.principalType, id: source.principalId }, g.inodeId, now) === "admin";
}

/**
 * Walk from the target inode up to the space root, collecting the principal's
 * effective level. Implements these semantics:
 *   - nearest explicit ACL wins; if a node has any matching live grant, that node's
 *     grants determine the level (MAX over matching grants = group-union) and we stop.
 *   - otherwise inherit the parent recursively.
 *   - empty all the way up => NO ACCESS (null).
 * Also surfaces a RootPoint (mountAsRoot) if any matching grant on the path sets it.
 */
function effectiveLevelAt(
  store: PermissionStore,
  principal: Principal,
  inodeId: string,
  now: number,
): { level: Level | null; decidedAt?: string; rootInodeId?: string } {
  let current: string | null = inodeId;
  let rootInodeId: string | undefined;
  let guard = 0;

  while (current) {
    if (++guard > 4096) break; // cycle guard — metadata corruption defense
    const node = store.getInode(current);
    if (!node) break;

    const matching = store.grantsForInode(current).filter(
      (g) => principalMatches(g, principal) && isGrantLive(store, g, now),
    );

    if (matching.length > 0) {
      if (matching.some((g) => g.mountAsRoot)) rootInodeId = current;
      const best = matching.reduce<Level>((acc, g) => {
        return LEVEL_RANK[g.level] > LEVEL_RANK[acc] ? g.level : acc;
      }, "read");
      // recompute MAX honestly (reduce seed "read" could over-report a deny-less set)
      const maxRank = Math.max(...matching.map((g) => LEVEL_RANK[g.level]));
      const level = (Object.keys(LEVEL_RANK) as Level[]).find((l) => LEVEL_RANK[l] === maxRank) ?? best;
      return { level, decidedAt: current, rootInodeId };
    }

    current = node.parentId; // inherit from parent
  }

  return { level: null, rootInodeId };
}

/** Public helper: the effective level a principal holds at an inode (null = none). */
export function effectiveLevel(store: PermissionStore, principal: Principal, inodeId: string, now = Date.now()): Level | null {
  // CHANGE E: space_admin is an org-wide admin — same full-access short-circuit as admin.
  if (isOrgAdmin(principal.orgRole)) return "admin";
  return effectiveLevelAt(store, principal, inodeId, now).level;
}

/** CHANGE E: the org roles that carry full org-wide admin authority (data access).
 *  owner, admin, and space_admin all see everything; space_admin is NOT per-space scoped. */
export function isOrgAdmin(role: OrgRole | undefined): boolean {
  return role === "owner" || role === "admin" || role === "space_admin";
}

// ---- canAccess — THE pure evaluator the gateway calls ----------------------

/**
 * The single authorization decision point (SPEC §4.4). PURE: no IO, no crypto.
 * Call this (a) before minting a presigned GET/PUT and (b) before any metadata
 * mutation in FilespaceDO. See multiuser-INTEGRATION.md for the exact hook points.
 */
export function canAccess(
  store: PermissionStore,
  principal: Principal,
  inodeId: string,
  action: Action,
  now = Date.now(),
): Decision {
  // Org-role short-circuit: owner, admin AND space_admin have full data access
  // (SPEC §4.2/§4.11 "admins see all"). CHANGE E: space_admin is an ORG-WIDE admin,
  // not a per-space-scoped role — it gets the SAME full-access short-circuit, not an
  // ACL fall-through. (The single owner-only capability — repointing a space's
  // storage backend — is gated in org-do.ts, not here.)
  if (isOrgAdmin(principal.orgRole)) {
    return {
      allow: true,
      effectiveLevel: "admin",
      reason: `org role ${principal.orgRole} has full access`,
      decidedAtInodeId: inodeId,
    };
  }

  const target = store.getInode(inodeId);
  if (!target) {
    return { allow: false, effectiveLevel: null, reason: "inode not found" };
  }

  const required = ACTION_MIN_LEVEL[action];
  const { level, decidedAt, rootInodeId } = effectiveLevelAt(store, principal, inodeId, now);

  if (level === null) {
    // absence of a grant == no access (no deny verb). Invisible to the user.
    return { allow: false, effectiveLevel: null, reason: "no grant (no-access = invisible)", rootInodeId };
  }

  if (LEVEL_RANK[level] < LEVEL_RANK[required]) {
    return {
      allow: false,
      effectiveLevel: level,
      reason: `requires ${required}, principal holds ${level}`,
      decidedAtInodeId: decidedAt,
      rootInodeId,
    };
  }

  // Rule §4.3(4): rename/move/delete needs write on BOTH item and parent.
  if (REQUIRES_PARENT_WRITE.has(action) && target.parentId) {
    const parent = effectiveLevelAt(store, principal, target.parentId, now);
    if (parent.level === null || LEVEL_RANK[parent.level] < LEVEL_RANK["edit"]) {
      return {
        allow: false,
        effectiveLevel: level,
        reason: `${action} requires edit on parent folder; principal lacks it`,
        decidedAtInodeId: decidedAt,
        rootInodeId,
      };
    }
  }

  return {
    allow: true,
    effectiveLevel: level,
    reason: `granted ${level} >= required ${required}`,
    decidedAtInodeId: decidedAt,
    rootInodeId,
  };
}

/** Resolve a principal's RootPoint (sub-path mount) for a space, if any grant sets
 *  mountAsRoot on a node the principal can reach. Returns the highest such inode on
 *  the path — used by the client to root its mount (SPEC §4.3 RootPoint). */
export function resolveMountRoot(
  store: PermissionStore,
  principal: Principal,
  inodeId: string,
  now = Date.now(),
): string | null {
  return effectiveLevelAt(store, principal, inodeId, now).rootInodeId ?? null;
}

// ---- grant / revoke helpers ------------------------------------------------

/** A writable ACL store (the OrgDO/FilespaceDO implements this on top of SQLite). */
export interface MutablePermissionStore extends PermissionStore {
  putGrant(g: Grant): void;
  deleteGrant(grantId: string): boolean;
  /** All grants for an inode whose principal == (type,id) — for revoke-by-principal. */
  findGrants(inodeId: string, principalType: PrincipalType, principalId: string): Grant[];
}

export interface GrantInput {
  spaceId: string;
  inodeId: string;
  principalType: PrincipalType;
  principalId: string;
  level: Level;
  mountAsRoot?: boolean;
  expiresAt?: number | null;
}

/**
 * Grant access. The CALLER must already hold `admin` on `inodeId` (or be org
 * owner/admin) — enforce that with canAccess(..., "manage_acl") before calling.
 * This helper performs the write only; it returns the persisted Grant.
 */
export function grant(store: MutablePermissionStore, input: GrantInput, grantedByMemberId: string): Grant {
  if (!store.getInode(input.inodeId)) throw new Error("cannot grant on a non-existent inode");
  const g: Grant = {
    id: `grant-${input.spaceId}-${input.inodeId}-${input.principalType}-${input.principalId}-${cryptoRandom()}`,
    spaceId: input.spaceId,
    inodeId: input.inodeId,
    principalType: input.principalType,
    principalId: input.principalId,
    level: input.level,
    mountAsRoot: !!input.mountAsRoot,
    expiresAt: input.expiresAt ?? null,
    grantedByMemberId,
    grantedAt: Date.now(),
  };
  store.putGrant(g);
  return g;
}

/** Revoke a specific grant by id. */
export function revokeGrantById(store: MutablePermissionStore, grantId: string): boolean {
  return store.deleteGrant(grantId);
}

/** Revoke ALL grants for a principal on an inode (the common "remove access" path). */
export function revokePrincipal(
  store: MutablePermissionStore,
  inodeId: string,
  principalType: PrincipalType,
  principalId: string,
): number {
  const rows = store.findGrants(inodeId, principalType, principalId);
  let n = 0;
  for (const g of rows) if (store.deleteGrant(g.id)) n++;
  return n;
}

// ---- a small in-memory store (reference impl + test fixture) ---------------

/** Reference in-memory implementation of MutablePermissionStore. Used by unit tests
 *  and as the canonical shape the DO's SQLite-backed store must mirror. */
export class InMemoryPermissionStore implements MutablePermissionStore {
  private inodes = new Map<string, InodeNode>();
  private grants = new Map<string, Grant>();

  addInode(node: InodeNode): void {
    this.inodes.set(node.id, node);
  }

  getInode(inodeId: string): InodeNode | null {
    return this.inodes.get(inodeId) ?? null;
  }

  grantsForInode(inodeId: string): Grant[] {
    return [...this.grants.values()].filter((g) => g.inodeId === inodeId);
  }

  putGrant(g: Grant): void {
    this.grants.set(g.id, g);
  }

  deleteGrant(grantId: string): boolean {
    return this.grants.delete(grantId);
  }

  findGrants(inodeId: string, principalType: PrincipalType, principalId: string): Grant[] {
    return this.grantsForInode(inodeId).filter(
      (g) => g.principalType === principalType && g.principalId === principalId,
    );
  }
}

// ---- util ------------------------------------------------------------------

function cryptoRandom(): string {
  // Workers + Node both expose crypto.getRandomValues / randomUUID.
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID().slice(0, 8);
  return Math.random().toString(36).slice(2, 10);
}
