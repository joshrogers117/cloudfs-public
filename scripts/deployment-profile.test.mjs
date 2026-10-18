// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deploymentProfile, prepareProfileVars } from './deployment-profile.mjs';
import { parseVars } from './deploy-config.mjs';

test('profiles isolate secrets and never target the default production files', () => {
 const trial = deploymentProfile('/repo', 'trial');
 const prod = deploymentProfile('/repo', 'production');
 assert.equal(trial.varsPath, '/repo/.deployments/trial/deployment.vars');
 assert.equal(trial.secretsPath, '/repo/.deployments/trial/secrets.json');
 assert.notEqual(trial.secretsPath, prod.secretsPath);
 for (const invalid of ['', '.', '..', '../backend', '/tmp/x', 'a/b', 'ab\\cd', 'UPPER', 'x'.repeat(32)]) {
  assert.throws(() => deploymentProfile('/repo', invalid), /Profile names/);
 }
});

test('prepared profiles use distinct worker, data and audit names instead of production defaults', () => {
 const vars = parseVars(prepareProfileVars('S3_BUCKET=cloudfs-data\nSIGNUP_MODE=closed\n', 'cloudfs-trial'));
 assert.deepEqual(vars, {S3_BUCKET:'cloudfs-trial-data',SIGNUP_MODE:'closed',CLOUDFS_WORKER_NAME:'cloudfs-trial',CLOUDFS_AUDIT_BUCKET:'cloudfs-trial-audit'});
 assert.throws(()=>prepareProfileVars('', 'worker\nPUBLIC_BASE_URL=https://wrong.test'),/Invalid/);
});
