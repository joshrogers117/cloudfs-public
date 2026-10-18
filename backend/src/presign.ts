// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Env } from "./env";
import {
  resolveStorageConfig,
  resolveStorageConfigAsync,
  presignWith,
  presignManyWith,
  type PresignEntry,
  type PresignResult,
  type SpaceStorageDescriptor,
  type ManagedCredentialResolver,
} from "./storage";

/// Mint a short-lived S3-compatible presigned URL so the macOS client streams bytes
/// DIRECTLY from the bucket (never proxied through the Worker — that's what keeps egress
/// free and throughput high). Works against MinIO locally and Cloudflare R2 in prod.
///
/// Back-compat entry: signs against the deployment-DEFAULT backend (the `S3_*` env). For a
/// per-filespace bring-your-own backend (R2 / AWS S3 / Backblaze B2 / MinIO / Wasabi / Ceph)
/// use `presignForSpace` with the space's registry storage descriptor.
export async function presign(env: Env, key: string, method: string, expiresIn: number): Promise<string> {
  return presignWith(resolveStorageConfig(env, null), key, method, expiresIn);
}

/// Mint a presigned URL against the storage backend a SPECIFIC filespace is configured with.
/// `descriptor` is the (secret-free) per-space storage row from the registry; access keys are
/// resolved at call time (never persisted). A space's `credentialRef` is resolved via the
/// UI-MANAGED encrypted store FIRST (decrypting the secret), then the env `S3_*__<REF>` scheme
/// (back-compat); an unresolvable ref fails closed. A descriptor that omits its backend inherits
/// the deployment default, so single-backend deployments are unaffected. `managed` is injected by
/// the gateway (it owns the OrgDO + STORAGE_ENC_KEY); when omitted, only the env scheme applies.
export async function presignForSpace(
  env: Env,
  descriptor: SpaceStorageDescriptor | null | undefined,
  key: string,
  method: string,
  expiresIn: number,
  managed?: ManagedCredentialResolver,
  contentLength?: number,
): Promise<string> {
  const config = managed
    ? await resolveStorageConfigAsync(env, descriptor ?? null, managed)
    : resolveStorageConfig(env, descriptor ?? null);
  // Audit B16: a pinned content length is signed into the PUT (the client MUST send exactly that
  // many bytes or the bucket rejects the upload). Only meaningful on PUT; ignored otherwise.
  return presignWith(config, key, method, expiresIn, contentLength);
}

/** Resolve/decrypt credentials once for an authorized batch, never once per block. */
export async function presignBatchForSpace(
  env: Env, descriptor: SpaceStorageDescriptor | null | undefined,
  entries: PresignEntry[], expiresIn: number, managed?: ManagedCredentialResolver,
): Promise<PresignResult[]> {
  const config = managed
    ? await resolveStorageConfigAsync(env, descriptor ?? null, managed)
    : resolveStorageConfig(env, descriptor ?? null);
  const results = await presignManyWith(config, entries, expiresIn);
  const puts = entries.flatMap((entry,index) => entry.method.toUpperCase() === "PUT" && results[index].url ? [{index,key:entry.key,method:"GET"}] : []);
  const verification = await presignManyWith(config, puts, expiresIn);
  for (let i=0;i<puts.length;i++) {
    const result = results[puts[i].index];
    if (!verification[i].url) { delete result.url; result.error = "verification presign failed"; }
    else result.verificationUrl = verification[i].url;
  }
  return results;
}
