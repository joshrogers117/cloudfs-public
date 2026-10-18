// SPDX-License-Identifier: AGPL-3.0-or-later
// Shared builders for the multi-client / multi-filespace correctness tests.
import { SELF, env } from 'cloudflare:test';
import { sha256 } from '@noble/hashes/sha256';
import type { Env } from '../src/env';
import type { Block, Item } from '../src/metadata/types';
import { filespaceDoName, mintToken, type Scope } from '../src/security/auth';
import { seedOwnerFixture } from './setup-fixture';

export const e = env as Env;
export const origin = 'https://gw.local';
export const memberScopes: Scope[] = ['fs:read', 'fs:write', 'fs:lock'];

export const hex = (bytes: Uint8Array): string => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
/** Deterministic content-addressed block under the filespace's key prefix. */
export function blockFor(orgId: string, spaceId: string, n: number, tag = 'blk', offset = 0): Block {
  const blockHash = hex(sha256(new TextEncoder().encode(`${tag}-${n}`)));
  return { chunkIdx: 0, blockIdx: n, objectKey: `blocks/${orgId}::${spaceId}/${blockHash}`, blockHash, offset, length: 4 };
}
/** A valid contiguous manifest of `count` distinct 4-byte blocks. */
export const manifestFor = (orgId: string, spaceId: string, tag: string, count = 1): Block[] =>
  Array.from({ length: count }, (_, i) => blockFor(orgId, spaceId, i, tag, i * 4));
export function itemOf(result: unknown): Item {
  if (!result || typeof result !== 'object' || !('item' in result)) throw new Error('fixture item creation failed');
  return (result as { item: Item }).item;
}

export async function makeOrg(spaceIds: string[] = ['team'], label = 'mc') {
  const orgId = `${label}-${crypto.randomUUID().slice(0, 12)}`;
  const owner = await seedOwnerFixture(orgId);
  const org = e.ORG_DO.get(e.ORG_DO.idFromName(orgId));
  for (const spaceId of spaceIds) {
    await org.registerSpace({ orgId, spaceId, name: spaceId, bucketProvider: 'r2', bucketName: 'bucket', keyPrefix: '' });
  }
  const fs = (spaceId: string) => e.FILESPACE.get(e.FILESPACE.idFromName(filespaceDoName(orgId, spaceId)));
  const user = async (name: string, role: 'standard' | 'admin' = 'standard') =>
    org.createUser({ orgId, email: `${name.replace(/\W/g, '')}-${crypto.randomUUID().slice(0, 6)}@${orgId}.test`, displayName: name, role });
  const tokenFor = (sub: string, opts: { scopes?: Scope[]; spaceId?: string } = {}) =>
    mintToken(e.AUTH_SIGNING_SECRET, { sub, type: 'session', orgId, scopes: opts.scopes ?? memberScopes, spaceId: opts.spaceId, ttlSeconds: 900 });
  const call = (token: string, spaceId: string, method: string, path: string, body?: unknown, client?: string) =>
    SELF.fetch(`${origin}/v1/filespaces/${spaceId}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(client ? { 'X-CloudFS-Client-ID': client } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  return { orgId, owner, org, fs, user, tokenFor, call };
}
