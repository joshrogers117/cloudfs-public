// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Domain types shared by the GatewayClient interface and its mock.
 * These mirror the entities in SPEC §4 (org / space / folder / member / group /
 * guest) and the resources the backend Worker exposes (items, locks, changes).
 */

export interface AuthStatus {
  authenticated: boolean;
  principal?: string; // member email or service-account id
  kind?: "user" | "service-account";
  org?: string;
  scopes?: string[];
  expiresAt?: string | null; // ISO; null = non-expiring service token
  gateway: string; // base URL
}

export interface Filespace {
  id: string;
  name: string;
  status: "connected" | "disconnected" | "connecting";
  role?: string; // caller's effective role on this space
  bucket?: string;
  rootPoint?: string | null; // sub-path mount (RootPoint, SPEC §4.3)
  mountPath?: string | null;
}

export interface Item {
  id: string;
  name: string;
  path: string;
  isDir: boolean;
  size: number;
  modified: string; // ISO
  pinned?: boolean;
}

export interface ShareLink {
  id: string;
  path: string;
  url: string;
  kind: "guest" | "direct";
  expiresAt: string | null;
  createdBy: string;
  createdAt: string;
}

export interface User {
  id: string;
  email: string;
  role: "owner" | "admin" | "space-admin" | "standard";
  groups: string[];
  status: "active" | "invited" | "suspended";
}

export interface Group {
  id: string;
  name: string;
  members: string[];
}

export interface Grant {
  principal: string; // user email or group:name
  path: string;
  level: "read" | "read-write" | "admin";
  mountAsRoot?: boolean;
  expiresAt?: string | null;
}

export interface Invite {
  id: string;
  email: string;
  role: User["role"];
  status: "pending" | "accepted" | "revoked";
  expiresAt: string | null;
  url: string;
}

export interface Snapshot {
  id: string;
  label: string | null;
  scope: string; // path/subtree the snapshot covers
  createdAt: string;
  immutableUntil: string | null;
  schedule?: string | null; // schedule name that produced it, if any
}

/**
 * Result of `POST /v1/filespaces/:fs/snapshots/:id/restore` (backend/API.md).
 * Restore is non-destructive: each item is re-written as a new current version;
 * items present now but not in the snapshot are never deleted (only reported).
 */
export interface RestoreResult {
  snapshotId: string;
  restored: string[]; // items rewritten to their as-of-snapshot content
  recreated: string[]; // items deleted-since-snapshot that were re-created
  conflicts: { id: string; heldBy: string }[]; // skipped — exclusively leased by another owner
  newerThanSnapshot: string[]; // exist now but not in the snapshot — left untouched
}

export interface ChangeEvent {
  seq: number;
  type: "create" | "modify" | "delete" | "rename" | "lock" | "unlock" | "upload";
  path: string;
  actor: string;
  ts: string; // ISO
}

export interface SyncState {
  path: string;
  inSync: boolean;
  pendingUploads: number;
  pendingBytes: number;
}

/**
 * Per-pinned-path cache state (CONTROL-API.md §3 / §5.4, CONTRACTS.md §4.1).
 * Two states only:
 *   pinned  — fully materialized & non-evictable (cachedBytes == totalBytes)
 *   pinning — pin set but still materializing (0 <= cachedBytes < totalBytes)
 * An unpinned/evicted path holds no pin record, so it never appears in pin.list.
 */
export type PinCacheState = "pinned" | "pinning";

/**
 * A pinned item as the engine reports it (`pin.list` → PinState[]) projected for
 * display: path + recursive flag + per-item byte accounting + cache state. Powers
 * the GUI Pinned Items view and `cloudfs cache pin-list`.
 */
export interface PinnedItem {
  path: string;
  recursive: boolean;
  /** RESIDENT bytes for this pin (0 when an older engine omits the field). */
  cachedBytes: number;
  /** Full byte size the pin covers (0 when an older engine omits the field). */
  totalBytes: number;
  /** Count of resident blocks the pin covers. */
  blocks: number;
  state: PinCacheState;
}
