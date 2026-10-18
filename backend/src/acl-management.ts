// SPDX-License-Identifier: AGPL-3.0-or-later
import { canAccess, isGrantLive, isOrgAdmin, principalMatches, originalAuthorityLevel, type Grant, type GrantInput, type PermissionStore, type Principal } from './permissions';

/** Only an original workspace-issued administrator grant can authorize delegation. */
export function delegationAuthority(store: PermissionStore, actor: Principal, inodeId: string): Grant | null {
  const decision = canAccess(store, actor, inodeId, 'manage_acl');
  if (!decision.allow || !decision.decidedAtInodeId) return null;
  return store.grantsForInode(decision.decidedAtInodeId)
    .filter(g => g.level === 'admin' && !g.authorityGrantId && !g.authorityInodeId && principalMatches(g, actor) && isGrantLive(store, g))
    .sort((a, b) => (b.expiresAt || Infinity) - (a.expiresAt || Infinity))[0] ?? null;
}

export function grantMutationPolicy(store: PermissionStore, actor: Principal, input: Pick<GrantInput, 'inodeId' | 'principalType' | 'principalId'> & { level?: string }, protectedPrincipal: boolean): { error: string } | { authority: Grant | null } {
  const target = store.getInode(input.inodeId);
  if (!target) return { error: 'folder_not_found' };
  if (isOrgAdmin(actor.orgRole)) return { authority: null };
  if (target.type !== 'folder') return { error: 'folder_not_found' };
  const authority = delegationAuthority(store, actor, input.inodeId);
  if (!authority) return { error: 'folder_admin_required' };
  if (protectedPrincipal || (input.principalType !== 'group' && input.principalId === actor.id)) return { error: 'protected_principal' };
  if (input.level === 'admin') return { error: 'only_workspace_admin_can_delegate' };
  if (originalAuthorityLevel(store, { type: input.principalType, id: input.principalId }, input.inodeId) === 'admin') return { error: 'protected_grant' };
  const existing = store.grantsForInode(input.inodeId).filter(g => g.principalType === input.principalType && g.principalId === input.principalId);
  // An administrator's direct grant is a protected policy boundary, including a
  // lower child override. Delegates can manage only grants under their authority.
  if (existing.some(g => g.level === 'admin' || g.authorityGrantId !== authority.id)) return { error: 'protected_grant' };
  return { authority };
}
