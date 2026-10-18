// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { InMemoryPermissionStore, canAccess, grant, type PrincipalType } from '../src/permissions';

// Independent review: an original grant's existence is not sufficient when the
// owner has subsequently cut off its inherited authority inside the subtree.
describe('delegation authority follows current inherited permission', () => {
  for (const principalType of ['user', 'group'] as PrincipalType[]) {
    it(`a weaker descendant override stops access issued under ${principalType} authority`, () => {
      const store = new InMemoryPermissionStore();
      for (const [id, parentId] of [['root', null], ['shared', 'root'], ['restricted', 'shared'], ['child', 'restricted']] as const) {
        store.addInode({ id, parentId, type: 'folder' });
      }
      const authority = grant(store, { spaceId: 'space', inodeId: 'shared', principalType,
        principalId: 'manager', level: 'admin' }, 'owner');
      const issued = grant(store, { spaceId: 'space', inodeId: 'child', principalType: 'user',
        principalId: 'recipient', level: 'edit' }, 'manager');
      store.putGrant({ ...issued, authorityGrantId: authority.id, authorityInodeId: 'shared' });
      const recipient = { type: 'user' as const, id: 'recipient' };
      expect(canAccess(store, recipient, 'child', 'write').allow).toBe(true);
      grant(store, { spaceId: 'space', inodeId: 'restricted', principalType,
        principalId: 'manager', level: 'read' }, 'owner');
      expect(canAccess(store, { type: principalType, id: 'manager' }, 'child', 'manage_acl').allow).toBe(false);
      expect(canAccess(store, recipient, 'child', 'read').allow).toBe(false);
    });
  }
});
