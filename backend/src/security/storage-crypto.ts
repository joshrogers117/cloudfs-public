// SPDX-License-Identifier: AGPL-3.0-or-later
/// storage-crypto.ts — AES-256-GCM envelope for UI-managed object-storage secrets.
///
/// cloud-fs lets owners/admins store S3-compatible credentials through the web UI instead of
/// `wrangler secret put`. The access-key id is non-sensitive (stored plaintext for display),
/// but the SECRET access key must never sit in the DO in the clear. This module encrypts the
/// secret with AES-256-GCM (authenticated encryption) using WebCrypto — Workers-native, no
/// Node polyfills — keyed off a SINGLE deployment secret `STORAGE_ENC_KEY` (32 random bytes,
/// base64). Each record gets a fresh random 96-bit IV; we persist `iv + ciphertext` (the GCM
/// auth tag is appended to the ciphertext by WebCrypto). The plaintext secret is recovered ONLY
/// at presign time (server-side) and is NEVER returned by any API after creation.
///
/// FAIL CLOSED: if `STORAGE_ENC_KEY` is unset or malformed, encrypt/decrypt throw — a managed
/// credential cannot be created or used, rather than silently storing/serving a plaintext or
/// undecryptable secret.

const IV_BYTES = 12; // 96-bit nonce — the GCM standard; never reuse with the same key.

/// Decode a base64 (standard or url-safe) string to bytes. We accept both alphabets so an
/// operator pasting a key from any tool works. Exported: filespace-keys.ts reuses this to
/// validate/encode raw master-key bytes before/after sealing under the SAME envelope.
export function b64ToBytes(s: string): Uint8Array {
  const norm = s.trim().replace(/-/g, "+").replace(/_/g, "/");
  const pad = norm.length % 4 === 0 ? "" : "=".repeat(4 - (norm.length % 4));
  const bin = atob(norm + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Match the deployment validator: operators may supply 32 bytes as hex or base64. */
export function storageKeyBytes(value: string): Uint8Array {
  const normalized = value.trim();
  return /^[a-f0-9]{64}$/i.test(normalized)
    ? Uint8Array.from(normalized.match(/../g)!, byte => parseInt(byte, 16))
    : b64ToBytes(normalized);
}

/// Import the deployment `STORAGE_ENC_KEY` as a non-extractable AES-GCM CryptoKey. Throws a
/// clear error (fail closed) when the secret is missing or not exactly 32 bytes after base64
/// decoding — a 256-bit key is required.
export async function importStorageKey(encKeyB64: string | undefined): Promise<CryptoKey> {
  if (!encKeyB64 || !encKeyB64.trim()) {
    throw new Error("storage-crypto: STORAGE_ENC_KEY is not configured (managed credentials disabled)");
  }
  let raw: Uint8Array;
  try {
    raw = storageKeyBytes(encKeyB64);
  } catch {
    throw new Error("storage-crypto: STORAGE_ENC_KEY is not valid base64");
  }
  if (raw.length !== 32) {
    throw new Error(`storage-crypto: STORAGE_ENC_KEY must decode to 32 bytes (got ${raw.length})`);
  }
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/// The persisted ciphertext envelope. `iv` + `ciphertext` are independent base64 strings; the
/// GCM auth tag is part of `ciphertext` (WebCrypto appends it). Stored as two columns in the DO.
export interface SealedSecret {
  iv: string; // base64 (12 bytes)
  ciphertext: string; // base64 (ciphertext || 16-byte GCM tag)
}

const enc = new TextEncoder();
const dec = new TextDecoder();

/// Encrypt a plaintext secret under the deployment key. A fresh random IV is generated per call.
export async function sealSecret(encKeyB64: string | undefined, plaintext: string): Promise<SealedSecret> {
  const key = await importStorageKey(encKeyB64);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  return { iv: bytesToB64(iv), ciphertext: bytesToB64(new Uint8Array(ct)) };
}

/// Decrypt a sealed secret. Throws on a bad key, tampered ciphertext (GCM tag mismatch), or a
/// malformed envelope — callers must treat any throw as "credential unusable" (fail closed).
export async function openSecret(encKeyB64: string | undefined, sealed: SealedSecret): Promise<string> {
  const key = await importStorageKey(encKeyB64);
  const iv = b64ToBytes(sealed.iv);
  const ct = b64ToBytes(sealed.ciphertext);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return dec.decode(pt);
}
