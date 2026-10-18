// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { installationPlan, requireInstallerNode, buildEnvironment, provisioningEnvironment } from './installer-plan.mjs';
import { isReleaseFile, assertReleaseSourceCoverage } from './release-files.mjs';
const input = { profile: 'demo', account: 'a'.repeat(32), worker: 'cloudfs-demo', emailFrom: 'files@sample.test', installer: '/tmp/CloudFS.dmg' };

test('installer rejects invalid targets and config injection before provisioning', () => {
  const plan = installationPlan('/tmp/project', input);
  assert.equal(plan.dataBucket, 'cloudfs-demo-data');
  assert.equal(plan.secretsPath, '/tmp/project/.deployments/demo/secrets.json');
  for (const override of [{ profile: '../prod' }, { account: 'bad' }, { worker: 'bad\nKEY=value' }, { emailFrom: 'x@y.test\nSIGNUP_MODE=open' }, { emailFrom: '$sender@example.org' }, { installer: '/tmp/a\nEMAIL_FROM=x' }]) {
    assert.throws(() => installationPlan('/tmp/project', { ...input, ...override }));
  }
});
test('Node check matches the shipped build tool requirement', () => {
  for (const version of ['20.19.0', '22.0.0', '22.11.9']) assert.throws(() => requireInstallerNode(version));
  for (const version of ['22.12.0', '24.0.0']) requireInstallerNode(version);
});
test('package/build children never inherit Cloudflare provisioning credentials', () => {
  const env = { PATH: '/bin', CLOUDFLARE_API_TOKEN: 'private-token', CF_API_KEY: 'private-key', CLOUDFS_PROD_SECRETS: '/private/keyfile' };
  assert.deepEqual(buildEnvironment(env), { PATH: '/bin' });
  const provision = provisioningEnvironment(env, installationPlan('/tmp/project', input), 'provided-token');
  assert.equal(provision.CLOUDFLARE_API_TOKEN, 'provided-token');
  assert.equal(provision.CF_API_KEY, undefined);
  assert.equal(provision.CLOUDFS_EMAIL_FROM, input.emailFrom);
});
test('release allowlist excludes credentials, captures and generated artifacts even inside source trees', () => {
  for (const path of ['backend/.prod.secrets.json', 'backend/.dev.vars', '.deployments/trial/secrets.json', 'docs/validation/report.json', 'client-app/dist/private.dmg', 'web/public/invite.png', 'research/source.ts', '../backend/src/main.ts', '/backend/src/main.ts', 'backend/src/../secret.ts', 'backend/node_modules/private.ts', 'site/assets/shot-mac-app.jpg']) {
    assert.equal(isReleaseFile(path), false, path);
  }
  for (const path of ['backend/src/index.ts', 'web/src/pages/Join.tsx', 'backend/.prod.vars.example', 'client-app/Sources/CloudFSApp/App/CloudFSApp.swift', 'client-app/Sources/CloudFSApp/ViewModels/AppModel+Dashboard.swift', 'cloudfsd/Sources/cloudfsd/Engine+Snapshots.swift', 'scripts/backup/archive.mjs', 'INSTALL.md']) assert.equal(isReleaseFile(path), true, path);
});
test('packaging rejects silently omitted build inputs', () => {
  assertReleaseSourceCoverage(['cloudfsd/Sources/cloudfsd/Engine+Snapshots.swift', 'backend/src/security-INTEGRATION.md']);
  for (const path of ['cloudfsd/Sources/cloudfsd/New Feature.swift', 'web/src/assets/texture.webp']) {
    assert.throws(() => assertReleaseSourceCoverage([path]), /omits build inputs/);
  }
});
test('offline installer check is noninteractive and does not touch Cloudflare', () => {
  const script = fileURLToPath(new URL('./install-cloudflare.mjs', import.meta.url));
  const r = spawnSync(process.execPath, [script, '--check', '--profile', 'offline-test'], { encoding: 'utf8', env: { ...process.env, CLOUDFLARE_API_TOKEN: 'must-not-print-this' }, timeout: 10000 });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /No changes made/);
  assert.doesNotMatch(r.stdout + r.stderr, /must-not-print-this/);
  const bad = spawnSync(process.execPath, [script, '--profile', '--check'], { encoding: 'utf8', timeout: 10000 });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /requires a name/);
});
