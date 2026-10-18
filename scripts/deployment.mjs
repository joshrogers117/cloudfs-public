#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Named local configurations keep trial and production keys/resources separate.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { deploymentProfile, prepareProfileVars } from './deployment-profile.mjs';
import { parseVars } from './deploy-config.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
try {
  const [name, action, ...extra] = process.argv.slice(2);
  if (extra.length || !['prepare', 'setup', 'check', 'deploy'].includes(action)) throw new Error('Usage: node scripts/deployment.mjs <profile> <prepare|setup|check|deploy>');
  const profile = deploymentProfile(root, name);
  const worker = process.env.CLOUDFS_WORKER_NAME || `cloudfs-${name}`;
  prepareProfileVars('', worker); // Validate before creating local configuration.
  if (action === 'check' || action === 'deploy') {
    const vars = parseVars(readFileSync(profile.varsPath, 'utf8'));
    if (!vars.CLOUDFS_WORKER_NAME || !vars.CLOUDFS_AUDIT_BUCKET) throw new Error('Named profiles require explicit CLOUDFS_WORKER_NAME and CLOUDFS_AUDIT_BUCKET; refusing the default production resources.');
  }
  mkdirSync(profile.directory, { recursive: true, mode: 0o700 });
  const script = action === 'setup' ? 'setup-cloudflare.mjs' : 'deploy-prod.mjs';
  const flags = action === 'prepare' ? ['--prepare'] : action === 'check' ? ['--dry-run'] : [];
  console.log(`Deployment profile: ${name} (${profile.directory})`);
  const child = spawnSync(process.execPath, [resolve(root, 'scripts', script), ...flags], {
    cwd: root, stdio: 'inherit', env: {
      ...process.env,
      CLOUDFS_PROD_VARS: profile.varsPath, CLOUDFS_PROD_SECRETS: profile.secretsPath,
      CLOUDFS_WORKER_NAME: worker,
    },
  });
  if (child.error) throw child.error;
  if (child.status === 0 && action === 'prepare') {
    writeFileSync(profile.varsPath, prepareProfileVars(readFileSync(profile.varsPath, 'utf8'), worker), { mode: 0o600 });
  }
  process.exitCode = child.status ?? 1;
} catch (error) { console.error(error.message); process.exitCode = 1; }
