// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { cloudflareAPI, resolveAccount, assertFreshInstallTargets, ensureBucket, createStorageCredential, mayInitializeSecrets, credentialRequestDefinitelyRejected } from './cloudflare-provision.mjs';

test('fresh setup rejects resource collisions and unknown permission outcomes before writes', async () => {
  for (const collision of ['settings', 'demo-data', 'demo-audit']) {
    await assert.rejects(assertFreshInstallTargets(async (path, method) => {
      assert.equal(method, undefined);
      if (path.endsWith(collision)) return {};
      throw Object.assign(new Error('missing'), { status:404 });
    }, 'account', 'demo'), /already exists/);
  }
  await assert.rejects(assertFreshInstallTargets(async () => { throw Object.assign(new Error('denied'), {status:403}); }, 'account', 'demo'), /denied/);
  let reads=0;
  await assertFreshInstallTargets(async () => { reads++; throw Object.assign(new Error('missing'), {status:404}); }, 'account', 'demo');
  assert.equal(reads,3);
});

test('setup never replaces missing encryption keys after initialization or a completed install', () => {
  assert.equal(mayInitializeSecrets({ phase: 'before-secrets' }, false), true);
  for (const state of [{}, { complete: true }, { phase: 'configured' }, { phase: 'before-secrets', complete: true }, { phase: 'before-secrets', creatingCredential: true }]) {
    assert.equal(mayInitializeSecrets(state, false), false);
  }
  assert.equal(mayInitializeSecrets({ phase: 'before-secrets' }, true), false);
});

test('only definitive client rejection permits another storage-token request', () => {
  assert.equal(credentialRequestDefinitelyRejected({ status: 403 }), true);
  assert.equal(credentialRequestDefinitelyRejected({ status: 429 }), true);
  for (const error of [new Error('timeout'), { status: 500 }, { status: 408 }, { status: 200 }, { status: '403' }, undefined]) {
    assert.equal(credentialRequestDefinitelyRejected(error), false);
  }
});

test('completed setup refuses missing secrets without deploying or replacing configuration', t => {
  const dir = mkdtempSync(join(tmpdir(), 'cloudfs-setup-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const varsPath = join(dir, 'vars'), secretsPath = join(dir, 'secrets');
  const original = 'PUBLIC_BASE_URL=https://custom.example.test\nAPP_DOWNLOAD_URL=https://download.example.test/app.dmg\n';
  writeFileSync(varsPath, original);
  writeFileSync(`${secretsPath}.setup-state`, JSON.stringify({ varsPath, secretsPath, complete: true, origin: 'https://first.example.test' }));
  const env = { ...process.env, CLOUDFLARE_API_TOKEN: 'test-must-not-be-used', CLOUDFS_PROD_VARS: varsPath, CLOUDFS_PROD_SECRETS: secretsPath };
  const script = fileURLToPath(new URL('./setup-cloudflare.mjs', import.meta.url));
  const failed = spawnSync(process.execPath, [script], { env, encoding: 'utf8', timeout: 5000 });
  assert.equal(failed.status, 1);
  assert.match(failed.stderr, /never generate replacement encryption keys/);
  assert.equal(existsSync(secretsPath), false);
  assert.equal(readFileSync(varsPath, 'utf8'), original);
  writeFileSync(secretsPath, '{"STORAGE_ENC_KEY":"existing-key"}');
  const completed = spawnSync(process.execPath, [script], { env, encoding: 'utf8', timeout: 5000 });
  assert.equal(completed.status, 0);
  assert.match(completed.stdout, /already completed/);
  assert.equal(readFileSync(varsPath, 'utf8'), original);
  assert.equal(readFileSync(secretsPath, 'utf8'), '{"STORAGE_ENC_KEY":"existing-key"}');
});

test('permission discovery failure is safe to retry but an uncertain token POST is not', async () => {
  let calls = 0;
  await assert.rejects(createStorageCredential(async () => { calls++; throw new Error('GET timeout'); }, 'account', 'data', 'app'), error => credentialRequestDefinitelyRejected(error));
  assert.equal(calls, 1);
  await assert.rejects(createStorageCredential(async (_, method) => {
    if (method !== 'POST') return [{ id: 'write', name: 'Workers R2 Storage Bucket Item Write' }];
    throw new Error('POST timeout');
  }, 'account', 'data', 'app'), error => !credentialRequestDefinitelyRejected(error));
});

test('account selection never guesses among multiple accounts', async () => {
  await assert.rejects(resolveAccount(async () => [{ id: 'a' }, { id: 'b' }]), /choose/);
  assert.equal(await resolveAccount(async () => [{ id: 'a' }]), 'a');
});
test('existing buckets are retained and only a confirmed missing bucket is created', async () => {
  const calls = [];
  assert.equal(await ensureBucket(async (...args) => calls.push(args), 'a', 'data-bucket'), false);
  assert.equal(calls.length, 1);
  const api = async (...args) => { calls.push(args); if (args[1] !== 'POST') throw Object.assign(new Error(), { status: 404 }); };
  assert.equal(await ensureBucket(api, 'a', 'data-bucket'), true);
  assert.deepEqual(calls.at(-1), ['/accounts/a/r2/buckets', 'POST', { name: 'data-bucket' }]);
  await assert.rejects(ensureBucket(async () => { throw Object.assign(new Error('forbidden'), { status: 403 }); }, 'a', 'data-bucket'), /forbidden/);
});
test('storage credentials are restricted to the one data bucket and derived without retaining raw token', async () => {
  let policy;
  const result = await createStorageCredential(async (path, method, body) => {
    if (method !== 'POST') return [{ id: 'write-id', name: 'Workers R2 Storage Bucket Item Write' }];
    policy = body;
    return { id: 'access-id', value: 'secret-test-value' };
  }, 'account', 'media', 'cloudfs');
  assert.deepEqual(policy.policies[0].resources, { 'com.cloudflare.edge.r2.bucket.account_default_media': '*' });
  assert.deepEqual(policy.policies[0].permission_groups, [{ id: 'write-id' }]);
  assert.deepEqual(result, { S3_ACCESS_KEY_ID: 'access-id', S3_SECRET_ACCESS_KEY: createHash('sha256').update('secret-test-value').digest('hex') });
});
test('API failures do not print server responses that might contain a token', async () => {
  const api = cloudflareAPI('local-secret', async () => new Response(JSON.stringify({ success: false, errors: [{ message: 'sensitive-server-response' }] }), { status: 403 }));
  await assert.rejects(api('/accounts'), error => !error.message.includes('sensitive-server-response') && !error.message.includes('local-secret'));
  const malformed = cloudflareAPI('local-secret', async () => new Response('one-time-sensitive-token', { status: 200 }));
  await assert.rejects(malformed('/accounts/test/tokens', 'POST', {}), error => !error.message.includes('one-time-sensitive-token') && !credentialRequestDefinitelyRejected(error));
});
