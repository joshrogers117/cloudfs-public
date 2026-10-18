// SPDX-License-Identifier: AGPL-3.0-or-later
/// Shared types for the metadata plane. Kept dependency-free so the Worker, the
/// DO, and tests can all import them without pulling in SQLite.

/// A namespace node (directory or file). `version` increments on every metadata
/// write and is the token for optimistic concurrency (see `expectedVersion`).
export interface Item {
  id: string;
  parent: string | null;
  name: string;
  isDir: boolean;
  size: number;
  /// Per-write monotonic version tag of the form `cv-<size>-<seq>` (see
  /// namespace.ts) — NOT a content hash/address. It bumps on every write, so
  /// re-uploading byte-identical content yields a DIFFERENT contentVersion;
  /// cv equality does NOT imply content equality. (Block-level dedup is keyed on
  /// block_hash, not this field.)
  contentVersion: string;
  /// S3/R2 ETag of the assembled object (null until first upload completes).
  etag: string | null;
  /// Optimistic-concurrency token; bumps on every metadata mutation.
  version: number;
  updatedSeq: number;
  /// Tombstone flag — deleted items remain for the change feed, then GC.
  deleted: boolean;
  /// Wall-clock create/modify times (ms epoch). Null on rows created before the
  /// v13 migration; the client falls back to hash-of-contentVersion synthesis.
  createdAt: number | null;
  modifiedAt: number | null;
  accessedAt?: number | null;
  changedAt?: number | null;
  fileAttributes?: number;
  /// AAPL readdir-attr enrichment (v14): byte length of the resource-fork stream
  /// (AFP_Resource) and the base64 32-byte FinderInfo, so the SMB mount can pack
  /// them into directory entries without a per-file stream probe. Undefined when
  /// not enriched (single-item stat may omit them).
  rsrcForkSize?: number;
  finderInfo?: string | null;
  /// Opaque bounded AFP_AfpInfo ciphertext; only the daemon can decrypt it.
  finderInfoCiphertext?: string | null;
}

/// A named stream's identity (list result). `size` is the byte length.
export interface StreamInfo {
  name: string;
  size: number;
}

/// One immutable, content-addressed block in a file's block map (SPEC §3.2).
export interface Block {
  chunkIdx: number;
  blockIdx: number;
  blockHash: string;
  objectKey: string;
  offset: number;
  length: number;
}

/// A page of a directory listing. `cursor` is opaque; pass it back to continue.
export interface Page<T> {
  items: T[];
  cursor: string | null;
}

export type LockMode = "exclusive" | "shared";
export type LockPurpose = "advisory" | "publication";

export interface LockResult {
  granted: boolean;
  path: string;
  owner?: string;
  mode?: LockMode;
  purpose?: LockPurpose;
  /// Fencing token (SPEC §5.5 hardening): monotonic per-filespace counter handed
  /// to the holder. Stale holders present an old fence and are rejected by the
  /// data plane / writer, defeating the "zombie lease writes after expiry" race.
  fence?: number;
  heldBy?: string;
  expiresAt?: number;
  /// Set when granted === false to disambiguate the conflict for the client.
  reason?: "held-by-other" | "fence-stale" | "not-found" | "forbidden" | "range-already-held" | "lock-capacity" | "purpose-mismatch";
}

export interface UploadSession {
  uploadId: string;
  itemId: string;
  key: string;
  totalSize: number;
  partSize: number;
  state: "in_progress" | "completed" | "aborted";
  /// Parts already durably uploaded — lets a resuming client skip them.
  uploadedParts: { partNumber: number; etag: string; size: number }[];
}

export interface Snapshot {
  id: string;
  label: string | null;
  scope: string;
  seqAnchor: number;
  tier: string;
  createdAt: number;
  immutableUntil: number | null;
  scheduleId: string | null;
}
