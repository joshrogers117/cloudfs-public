// SPDX-License-Identifier: AGPL-3.0-or-later
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { Env } from "../src/env";
import { describeDefaultStorage, resolveStorageConfigAsync } from "../src/storage";
import { handleOrgRequest } from "../src/org-do";
import { handleStorageCredentialsRequest } from "../src/storage-credentials";
const e = env as Env;
const configured: Env = { ...e, S3_ENDPOINT: 'https://abc.r2.cloudflarestorage.com', S3_BUCKET: 'team-data', S3_REGION: 'auto', S3_ACCESS_KEY_ID: 'configured-id', S3_SECRET_ACCESS_KEY: 'never-exposed-secret', S3_SESSION_TOKEN: 'never-exposed-session' };
const owner = { orgRole: 'owner' as const, principalUserId: 'owner' };

describe('deployment-default storage', () => {
  it('discovery is secret-free, distinguishes configuration from probing, and is admin-only', async () => {
    const req = new Request('https://gateway.test/v1/orgs/team/storage/default');
    const deps = { org: e.ORG_DO.get(e.ORG_DO.idFromName('default-storage')) };
    const res = await handleStorageCredentialsRequest(req, configured, owner, ['storage', 'default'], 'team', deps);
    expect(res!.status).toBe(200);
    const text = await res!.text();
    expect(text).not.toContain('never-exposed-secret');
    expect(text).not.toContain('never-exposed-session');
    expect(text).not.toContain('configured-id');
    expect(JSON.parse(text)).toMatchObject({ configured: true, provider: 'r2', bucket: 'team-data' });
    const denied = await handleStorageCredentialsRequest(req, configured, { ...owner, orgRole: 'standard' }, ['storage', 'default'], 'team', deps);
    expect(denied!.status).toBe(403);
  });

  it('does not treat dev defaults or missing credentials as production-ready', () => {
    expect(describeDefaultStorage({ ...configured, S3_ENDPOINT: 'http://127.0.0.1:9000', STORAGE_PROBE_ALLOW_PRIVATE: undefined }, true).configured).toBe(false);
    expect(describeDefaultStorage({ ...configured, S3_SECRET_ACCESS_KEY: '' }).configured).toBe(false);
    expect(describeDefaultStorage({ ...configured, S3_BUCKET: 'CHANGE-ME' }).configured).toBe(false);
  });

  it('creates a ready-to-mount filespace without copying credentials into its registry', async () => {
    const orgId = 'default-create';
    const req = new Request(`https://gateway.test/v1/orgs/${orgId}/spaces`, { method: 'POST', body: JSON.stringify({ name: 'Editorial', storageMode: 'deployment' }) });
    const res = await handleOrgRequest(req, configured, owner, ['spaces'], orgId);
    expect(res.status).toBe(201);
    const row = await res.json() as { id: string; storageCredentialRef: string | null; storageBucket: string };
    expect(row.storageBucket).toBe('team-data');
    expect(row.storageCredentialRef).toBeNull();
    expect(await e.ORG_DO.get(e.ORG_DO.idFromName(orgId)).getFilespaceKey(row.id)).not.toBeNull();
  });

  it('a missing encryption key does not leave an unusable filespace visible', async () => {
    const orgId = 'default-no-key';
    const req = new Request(`https://gateway.test/v1/orgs/${orgId}/spaces`, { method: 'POST', body: JSON.stringify({ name: 'Editorial', storageMode: 'deployment' }) });
    const res = await handleOrgRequest(req, { ...configured, STORAGE_ENC_KEY: undefined }, owner, ['spaces'], orgId);
    expect(res.status).toBe(503);
    expect(await e.ORG_DO.get(e.ORG_DO.idFromName(orgId)).listSpaces()).toEqual([]);
  });

  it('a fully configured separate backend works without deployment-default credentials', async () => {
    const config = await resolveStorageConfigAsync({ ...configured, S3_ACCESS_KEY_ID: '', S3_SECRET_ACCESS_KEY: '' }, { endpoint: 'https://storage.test', region: 'us-east-1', bucket: 'another-team', credentialRef: 'saved' }, async () => ({ accessKeyId: 'separate-id', secretAccessKey: 'separate-secret' }));
    expect(config.bucket).toBe('another-team');
    expect(config.accessKeyId).toBe('separate-id');
  });
});

it('concurrent create retries cannot replace an existing filespace master key', async () => {
  const orgId = 'key-create-race';
  const org = e.ORG_DO.get(e.ORG_DO.idFromName(orgId));
  const base = { orgId, spaceId: 'race', keyIv: 'sealed-iv', keyCiphertext: 'sealed-key', ifAbsent: true };
  const keys = await Promise.all(['key-a', 'key-b'].map(keyId => org.putFilespaceKey({ ...base, keyId })));
  expect(keys[0].keyId).toBe(keys[1].keyId);
  expect((await org.getFilespaceKey('race'))!.keyId).toBe(keys[0].keyId);
});
