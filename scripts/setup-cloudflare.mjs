#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fresh installs only. Checkpoint each step so a retry never rotates encryption keys.
import { readFileSync, existsSync, mkdirSync, openSync, writeSync, fsyncSync, closeSync, renameSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { cloudflareAPI, resolveAccount, assertFreshInstallTargets, ensureBucket, createStorageCredential, mayInitializeSecrets, credentialRequestDefinitelyRejected } from './cloudflare-provision.mjs';
import { productionEmailBindings } from './deploy-config.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const backend = resolve(root, 'backend');
const varsPath = resolve(backend, process.env.CLOUDFS_PROD_VARS || '.prod.vars');
const secretsPath = resolve(backend, process.env.CLOUDFS_PROD_SECRETS || '.prod.secrets.json');
const checkpoint = `${secretsPath}.setup-state`;
function save(path, value, exclusive = false) {
  mkdirSync(dirname(path), { recursive: true });
  const temp = exclusive ? path : `${path}.tmp-${process.pid}`;
  const fd = openSync(temp, 'wx', 0o600);
  try { writeSync(fd, typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n'); fsyncSync(fd); }
  finally { closeSync(fd); }
  if (!exclusive) renameSync(temp, path);
  const directoryFD = openSync(dirname(path), 'r');
  try { fsyncSync(directoryFD); } finally { closeSync(directoryFD); }
}
try {
  if (process.argv.length > 2) throw new Error('Usage: node scripts/setup-cloudflare.mjs. Configure CLOUDFLARE_API_TOKEN and optional CLOUDFLARE_ACCOUNT_ID / CLOUDFS_WORKER_NAME environment variables.');
  console.log('Production requires Workers Paid and R2 enabled. This script does not change your Cloudflare plan.');
  const emailFrom = process.env.CLOUDFS_EMAIL_FROM || '';
  const installer = process.env.CLOUDFS_MAC_INSTALLER || '';
  if (/[`$]/.test(emailFrom)) throw new Error('CLOUDFS_EMAIL_FROM must not contain backticks or dollar signs in the literal deployment configuration.');
  productionEmailBindings(emailFrom ? { EMAIL_PROVIDER: 'cloudflare', EMAIL_FROM: emailFrom } : {});
  if (/[\r\n`$]/.test(installer)) throw new Error('CLOUDFS_MAC_INSTALLER must be a literal path without line breaks, backticks or dollar signs.');
  if (!existsSync(checkpoint) && (existsSync(varsPath) || existsSync(secretsPath))) throw new Error('An existing deployment configuration was found. Use scripts/deploy-prod.sh to update it; automatic setup never replaces existing keys.');
  const api = cloudflareAPI(process.env.CLOUDFLARE_API_TOKEN);
  let state;
  if (existsSync(checkpoint)) {
    state = JSON.parse(readFileSync(checkpoint, 'utf8'));
    if (state.varsPath !== varsPath || state.secretsPath !== secretsPath) throw new Error('Setup checkpoint paths do not match this install.');
    if (state.complete) {
      if (!existsSync(secretsPath)) throw new Error(`The existing install's secrets file is missing. Restore ${secretsPath} from backup. Setup will never generate replacement encryption keys for an existing install.`);
      if (!existsSync(varsPath)) throw new Error('The existing install configuration is missing. Restore its vars file from backup; automatic setup cannot reconstruct later configuration changes.');
      console.log(`Setup already completed for ${state.origin}. Use scripts/deploy-prod.sh to update it with the existing configuration and keys.`);
      process.exit(0);
    }
  } else {
    const account = await resolveAccount(api, process.env.CLOUDFLARE_ACCOUNT_ID);
    const worker = process.env.CLOUDFS_WORKER_NAME || 'cloudfs';
    if (!/^[a-z][a-z0-9-]{1,40}$/.test(worker)) throw new Error('CLOUDFS_WORKER_NAME must be 2–41 lowercase letters, numbers or hyphens.');
    const subdomain = await api(`/accounts/${account}/workers/subdomain`);
    if (!subdomain.subdomain) throw new Error('First choose a workers.dev subdomain in your Cloudflare dashboard.');
    await assertFreshInstallTargets(api, account, worker);
    state = { account, worker, bucket: `${worker}-data`, audit: `${worker}-audit`, origin: `https://${worker}.${subdomain.subdomain}.workers.dev`, varsPath, secretsPath, phase: 'before-secrets' };
    save(checkpoint, state, true);
  }
  let secrets;
  if (existsSync(secretsPath)) secrets = JSON.parse(readFileSync(secretsPath, 'utf8'));
  else {
    if (!mayInitializeSecrets(state, existsSync(varsPath))) throw new Error(`The existing install's secrets file is missing. Restore ${secretsPath} from backup before retrying. Setup will never generate replacement encryption keys for an existing install.`);
    secrets = { AUTH_SIGNING_SECRET: randomBytes(32).toString('hex'), BOOTSTRAP_SECRET: randomBytes(32).toString('hex'), STORAGE_ENC_KEY: randomBytes(32).toString('base64') };
    save(secretsPath, secrets, true);
  }
  state.phase = 'configured'; save(checkpoint, state);
  for (const bucket of [state.bucket, state.audit]) {
    const created = await ensureBucket(api, state.account, bucket);
    console.log(`${created ? 'Created' : 'Using'} R2 bucket ${bucket}.`);
  }
  if (!secrets.S3_ACCESS_KEY_ID || !secrets.S3_SECRET_ACCESS_KEY) {
    // A lost token-creation response cannot be safely retried automatically.
    if (state.creatingCredential) throw new Error('A previous storage-token request was interrupted. Inspect Cloudflare Account API Tokens and fill the S3 key pair in the protected secrets file before retrying.');
    state.creatingCredential = true; save(checkpoint, state);
    try {
      Object.assign(secrets, await createStorageCredential(api, state.account, state.bucket, state.worker));
    } catch (error) {
      if (credentialRequestDefinitelyRejected(error)) {
        state.creatingCredential = false; save(checkpoint, state);
      }
      throw error;
    }
    save(secretsPath, secrets);
    state.creatingCredential = false; save(checkpoint, state);
  }
  if (!existsSync(varsPath)) save(varsPath, `# Generated CloudFS install. Secrets are stored separately.\nCLOUDFLARE_ACCOUNT_ID=${state.account}\nCLOUDFS_WORKER_NAME=${state.worker}\nCLOUDFS_AUDIT_BUCKET=${state.audit}\nS3_BUCKET=${state.bucket}\nPUBLIC_BASE_URL=${state.origin}\nSIGNUP_MODE=closed\n${emailFrom ? `EMAIL_PROVIDER=cloudflare\nEMAIL_FROM=${emailFrom}\n` : ''}${installer ? `CLOUDFS_MAC_INSTALLER=${installer}\n` : ''}`, true);
  console.log('Deploying the console and gateway. Application secrets are saved in the protected secrets file.');
  const deployed = spawnSync(process.execPath, [resolve(root, 'scripts/deploy-prod.mjs')], { cwd: root, stdio: 'inherit', env: { ...process.env, CLOUDFS_PROD_VARS: varsPath, CLOUDFS_PROD_SECRETS: secretsPath } });
  if (deployed.error) throw deployed.error;
  if (deployed.status !== 0) throw new Error('Deployment failed. Rerun this command to resume with the same keys.');
  state.complete = true; save(checkpoint, state);
  console.log(`Ready: ${state.origin}/setup. Use BOOTSTRAP_SECRET from ${secretsPath} once to create your workspace owner.`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
