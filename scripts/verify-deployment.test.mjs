// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyDeployment } from './verify-deployment.mjs';
const names = ['storage_integrity', 'upload_verification', 'auth_signing_secret', 'storage_enc_key', 'default_storage_backend', 'audit_storage_backend', 'metadata_directory_do', 'metadata_auth_do', 'metadata_org_do', 'metadata_filespace'];
const doctor = { ok: true, checks: names.map(name => ({ name, status: 'ok' })) };
const healthy = async url => Response.json(url.pathname.endsWith('/health') ? { ok: true, apiVersion: 3 } : doctor);
test('only reports readiness after data, audit and all metadata checks pass', async () => {
  const seen = [];
  const report = await verifyDeployment('https://cloudfs.test', 'private-bootstrap', { fetcher: async (url, opts) => {
    seen.push([url.pathname, opts]); return healthy(url);
  } });
  assert.equal(report.readinessVerified, true);
  assert.equal(seen[0][1].headers['x-bootstrap-secret'], undefined);
  assert.equal(seen[1][1].headers['x-bootstrap-secret'], 'private-bootstrap');
  assert.equal(seen[1][1].redirect, 'error');
});
test('an SPA HTML fallback is not a healthy gateway', async () => {
  await assert.rejects(verifyDeployment('https://cloudfs.test', 'private', { attempts: 1, fetcher: async () => new Response('<html>OK</html>') }), /did not return JSON/);
});
test('a healthy but incompatible gateway cannot pass deployment verification', async () => {
  for (const apiVersion of [1, 2, 4, '3', undefined]) {
    await assert.rejects(verifyDeployment('https://cloudfs.test', 'private', {
      attempts: 1, fetcher: async url => url.pathname.endsWith('/health')
        ? Response.json({ ok: true, apiVersion }) : Response.json(doctor),
    }), /gateway did not pass/);
  }
});
test('a healthy liveness response never masks a missing audit/database readiness check', async () => {
  await assert.rejects(verifyDeployment('https://cloudfs.test', 'private', { attempts: 1, fetcher: async url => {
    return url.pathname.endsWith('/health') ? healthy(url) : Response.json({ ok: true, checks: doctor.checks.slice(0, 3) });
  } }), /audit_storage_backend.*metadata_directory_do/);
});
test('retries propagation failures but never leaks an upstream secret', async () => {
  let count = 0;
  const result = await verifyDeployment('https://cloudfs.test', 'private', { wait: async () => {}, fetcher: async url => {
    if (++count === 1) throw new Error('private-secret-in-upstream-url'); return healthy(url);
  } });
  assert.equal(result.readinessVerified, true);
  await assert.rejects(verifyDeployment('https://cloudfs.test', 'private', { attempts: 1, fetcher: async () => { throw new Error('private-secret'); } }), error => !error.message.includes('private-secret'));
});
test('existing-secret deployments explicitly report unverified readiness', async () => {
  const result = await verifyDeployment('https://cloudfs.test', undefined, { fetcher: healthy });
  assert.equal(result.readinessVerified, false);
});
test('maintenance deployment requires a protected status and closed ordinary traffic', async () => {
  const good = await verifyDeployment('https://cloudfs.test', 'private', { maintenanceMode: 'restore', fetcher: async url => {
    return url.pathname === '/v1/admin/restore/status' ? Response.json({mode: 'restore'}) : Response.json({error: 'maintenance'}, {status: 503});
  } });
  assert.equal(good.maintenanceVerified, true);
  assert.equal(good.readinessVerified, false);
  await assert.rejects(verifyDeployment('https://cloudfs.test', 'private', { maintenanceMode: 'export', attempts: 1,
    fetcher: async () => Response.json({mode: 'export', ok: true}),
  }), /did not enter/);
  await assert.rejects(verifyDeployment('https://cloudfs.test', undefined, {maintenanceMode: 'restore', attempts: 1, fetcher: healthy}), /requires its operator secret/);
});
