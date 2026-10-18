// SPDX-License-Identifier: AGPL-3.0-or-later
// filespace-keys.ts — server-held filespace master-key service (ONBOARDING.md "Key model",
// build step 2: "generate at creation, encrypted storage, wrapped-blob delivery endpoint,
// daemon fetch + Keychain cache, migration for existing keys").
//
// WHY: filespace content is encrypted client-side by cloudfsd under a per-filespace 32-byte
// master key. Until now that key was operator-provisioned by hand (a `key.hex` file or a
// Keychain item `com.cloudfs.masterkey`, account = filespace id) with NO distribution
// mechanism — a fresh device's daemon mounted fine but every read/write FATALed for want of a
// key. This module:
//   1. generates a fresh random master key at filespace creation and seals it at rest under the
//      deployment `STORAGE_ENC_KEY`, following the EXACT AES-256-GCM envelope pattern
//      storage-credentials.ts uses for BYO S3 secret keys (security/storage-crypto.ts);
//   2. serves it to an AUTHENTICATED, AUTHORIZED daemon as an OPAQUE wrapped-key envelope
//      (never a bare key) — a hard forward-compatibility requirement: v1 envelopes are
//      server-decryptable (`format: "plain-v1"`), so a LATER zero-knowledge mode can add a new
//      `format` (e.g. `"device-wrapped-v1"`, per-device-keypair-wrapped) without a protocol
//      break. Daemons MUST switch on `format` and reject anything they don't recognize.
//   3. accepts an operator-uploaded EXISTING key (the migration path for filespaces that
//      predate this feature) via `sealImportedMasterKey`.
//
// The plaintext key is NEVER returned by filespace registration, listing, or any response
// other than the delivery/import endpoints (index.ts / org-do.ts), both of which require real
// authorization (data access to the filespace; owner/admin for import), never bare org
// membership.
//
// Trust model (accepted for v1, ONBOARDING.md): whoever controls the Worker deployment can
// derive data access — encryption protects bucket contents from the storage provider and makes
// a leaked bucket/S3-credential expose ciphertext only.

import { sealSecret, openSecret, bytesToB64, b64ToBytes } from "./security/storage-crypto";

/// A raw cloud-fs filespace master key is always exactly 32 bytes (AES-256).
export const MASTER_KEY_BYTES = 32;

/// The wire envelope returned by the delivery endpoint (`GET /v1/filespaces/:fs/key`). This is
/// the OPAQUE, forward-compatible shape ONBOARDING.md requires: `format` is a closed-but-
/// extensible tag the daemon switches on. v1 ("plain-v1") is server-decrypted and handed over
/// TLS as raw base64 key bytes; a future `"device-wrapped-v1"` would carry a per-device-wrapped
/// blob here instead of `material` (or alongside it) without breaking this envelope shape.
export interface FilespaceKeyEnvelope {
  /// Stable, non-secret identifier for this key (a SHA-256 prefix — never reversible to the key
  /// material). Lets a future rotation flow name "which key" without exposing it.
  keyId: string;
  format: "plain-v1";
  /// Base64, MASTER_KEY_BYTES (32) raw bytes. Present for "plain-v1"; a future wrapped format
  /// would define its own payload field(s) instead.
  material: string;
}

/// Typed validation failure for the import/migration path (mapped to 400 by the gateway) —
/// distinct from a thrown plain `Error` (STORAGE_ENC_KEY misconfiguration, mapped to 500).
export class MasterKeyError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "MasterKeyError";
  }
}

/// Deterministic, non-secret identifier for a key: the first 8 bytes (16 hex chars) of
/// SHA-256(rawKey). One-way (never reveals the key), stable across fetch/delivery calls, and
/// the handle a future rotation flow would reference ("keyId X is now retired").
export async function keyIdFor(rawKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", rawKey));
  let hex = "";
  for (let i = 0; i < 8; i++) hex += digest[i].toString(16).padStart(2, "0");
  return hex;
}

/// The sealed-at-rest shape both the generate and import paths produce — exactly the columns
/// `OrgDO.putFilespaceKey` persists (mirrors `StorageCredentialRow`'s secretIv/secretCiphertext).
export interface SealedMasterKey {
  keyId: string;
  iv: string; // base64 (12 bytes) — security/storage-crypto.ts SealedSecret.iv
  ciphertext: string; // base64 — SealedSecret.ciphertext (AES-256-GCM ct || tag)
}

/// Generate a fresh random 32-byte master key and seal it under `STORAGE_ENC_KEY`. Throws (fail
/// closed) if the deployment key is unset/malformed — mirrors storage-credentials.ts's "seal the
/// secret BEFORE it touches the DO" rule, so a filespace is never created with unsealable key
/// material sitting in memory with nowhere durable to go.
export async function generateSealedMasterKey(encKeyB64: string | undefined): Promise<SealedMasterKey> {
  const raw = crypto.getRandomValues(new Uint8Array(MASTER_KEY_BYTES));
  const [sealed, keyId] = await Promise.all([sealSecret(encKeyB64, bytesToB64(raw)), keyIdFor(raw)]);
  return { keyId, iv: sealed.iv, ciphertext: sealed.ciphertext };
}

/// Seal OPERATOR-SUPPLIED key material (the import/migration path: an admin uploads an existing
/// `key.hex` / Keychain-exported key from before this service existed). Validates the EXACT
/// byte length before sealing — throws `MasterKeyError` (400) on bad input, or a plain `Error`
/// (500, STORAGE_ENC_KEY misconfigured) from the underlying seal.
export async function sealImportedMasterKey(
  encKeyB64: string | undefined,
  materialB64: string,
): Promise<SealedMasterKey> {
  let raw: Uint8Array;
  try {
    raw = b64ToBytes(materialB64);
  } catch {
    throw new MasterKeyError("invalid_base64", "material must be valid base64");
  }
  if (raw.length !== MASTER_KEY_BYTES) {
    throw new MasterKeyError(
      "bad_key_length",
      `master key must be exactly ${MASTER_KEY_BYTES} bytes (got ${raw.length})`,
    );
  }
  const [sealed, keyId] = await Promise.all([sealSecret(encKeyB64, bytesToB64(raw)), keyIdFor(raw)]);
  return { keyId, iv: sealed.iv, ciphertext: sealed.ciphertext };
}

/// The minimal sealed-row shape this module needs to open (matches `FilespaceKeyRow` in
/// org-do.ts, kept structural here so this module stays decoupled from the DO's row type).
export interface SealedMasterKeyRow {
  keyId: string;
  keyIv: string;
  keyCiphertext: string;
}

/// Decrypt a stored row back into the delivery envelope (server-side only — this is what the
/// gateway hands back over TLS to an authorized daemon). Throws if `STORAGE_ENC_KEY` can't open
/// it (bad/rotated deployment key, tampered row) — callers must treat any throw as "key
/// unavailable" (map to 500, never guess/substitute).
export async function openMasterKeyEnvelope(
  encKeyB64: string | undefined,
  row: SealedMasterKeyRow,
): Promise<FilespaceKeyEnvelope> {
  const material = await openSecret(encKeyB64, { iv: row.keyIv, ciphertext: row.keyCiphertext });
  return { keyId: row.keyId, format: "plain-v1", material };
}
