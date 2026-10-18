// SPDX-License-Identifier: AGPL-3.0-or-later
import { canAccess, isGrantLive, type Grant, type InodeNode, type PermissionStore, type Principal } from "../permissions";
import { DoAclStore } from "./acl-store";
import { SnapshotStore } from "./snapshots";
import type { Item } from "./types";

/** A snapshot never freezes authorization. Every operation evaluates live grants
 * against both frozen ancestry and the item's current/last-known location. */
export class SnapshotAccess {
  private readonly frozenItems = new Map<string, Item | null>();
  private readonly frozen: PermissionStore;
  private readonly lastKnown: PermissionStore;
  constructor(private readonly snapshots: SnapshotStore, private readonly acl: DoAclStore,
              private readonly principal: Principal, private readonly snapshotId: string) {
    const grants = (id: string): Grant[] => {
      // A deleted grant root cannot continue conferring historical access.
      if (!acl.getInode(id)) return [];
      return acl.grantsForInode(id).filter(grant => isGrantLive(acl, grant, Date.now())).map(grant => {
        // Delegation was checked against the real live authority above. Replaying
        // that check against frozen ancestry would grant/deny the wrong subtree.
        const { authorityGrantId: _source, authorityInodeId: _root, ...validated } = grant;
        return validated;
      });
    };
    this.frozen = { getInode: id => this.node(this.item(id)) ?? acl.getInode(id), grantsForInode: grants };
    this.lastKnown = { getInode: id => acl.getRawInode(id), grantsForInode: grants };
  }
  item(id: string): Item | null {
    if (!this.frozenItems.has(id)) this.frozenItems.set(id, this.snapshots.itemAt(this.snapshotId, id));
    return this.frozenItems.get(id) ?? null;
  }
  canRead(id: string): boolean {
    if (!this.item(id)) return false;
    if (["owner", "admin", "space_admin"].includes(this.principal.orgRole ?? "")) return true;
    return canAccess(this.frozen, this.principal, id, "read").allow
      && canAccess(this.lastKnown, this.principal, id, "read").allow;
  }
  canRestore(id: string, destinationParent: string | null): boolean {
    return this.canRead(id) && canAccess(this.lastKnown, this.principal, id, "write").allow
      && (destinationParent === null
        || (this.acl.getInode(id)?.parentId === destinationParent)
        || canAccess(this.lastKnown, this.principal, destinationParent, "write").allow);
  }
  roots(): { id: string; name: string; mountAsRoot: boolean }[] {
    const snapshot = this.snapshots.get(this.snapshotId);
    if (!snapshot) return [];
    const scope = this.item(snapshot.scope);
    if (scope && this.canRead(scope.id)) {
      return [{ id: scope.id, name: scope.name, mountAsRoot: scope.id !== "root" }];
    }
    return this.acl.matchingLiveInodes(this.principal).flatMap(root => {
      const item = this.item(root.id);
      if (!item?.isDir || !this.canRead(item.id) || (item.parent && this.canRead(item.parent))) return [];
      return [{ id: item.id, name: item.name, mountAsRoot: root.mountAsRoot }];
    });
  }
  private node(item: Item | null): InodeNode | null {
    return item ? { id: item.id, parentId: item.parent, type: item.isDir ? "folder" : "file" } : null;
  }
}
