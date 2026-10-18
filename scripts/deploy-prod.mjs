#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync, writeFileSync, existsSync, chmodSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { parseVars, productionVars, productionR2Bindings, productionEmailBindings, validateSecrets } from './deploy-config.mjs';
import { packageMacInstaller } from './package-mac-installer.mjs';
import { verifyDeployment } from './verify-deployment.mjs';
import { buildEnvironment } from './installer-plan.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const backend = resolve(root, 'backend');
const varsPath = resolve(backend, process.env.CLOUDFS_PROD_VARS || '.prod.vars');
const secretsPath = resolve(backend, process.env.CLOUDFS_PROD_SECRETS || '.prod.secrets.json');
const flags = new Set(process.argv.slice(2));
const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, { cwd: backend, stdio: 'inherit', ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed (${result.status}).`);
};

try {
  if ([...flags].some(f => !['--prepare', '--dry-run'].includes(f))) throw new Error('Usage: scripts/deploy-prod.sh [--prepare | --dry-run]');
  if (flags.has('--prepare')) {
    // A fresh install only: never invent replacement keys for an existing configuration.
    if (existsSync(varsPath) || existsSync(secretsPath)) throw new Error('Configuration already exists. Keep its keys; prepare only initializes a fresh deployment.');
    writeFileSync(varsPath, readFileSync(resolve(backend, '.prod.vars.example')), { mode: 0o600, flag: 'wx' });
    writeFileSync(secretsPath, JSON.stringify({
      AUTH_SIGNING_SECRET: randomBytes(32).toString('hex'),
      BOOTSTRAP_SECRET: randomBytes(32).toString('hex'),
      STORAGE_ENC_KEY: randomBytes(32).toString('base64'),
      S3_ACCESS_KEY_ID: '', S3_SECRET_ACCESS_KEY: '',
    }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    console.log(`Created ${varsPath} and ${secretsPath}. Fill your account, bucket, public origin and R2 access keys. Keep the generated application keys unchanged and backed up. No cloud resources were changed.`);
    process.exit(0);
  }
  if (!existsSync(varsPath)) throw new Error('Missing deployment configuration. For a fresh install, run scripts/deploy-prod.sh --prepare.');
  const vars = productionVars(parseVars(readFileSync(varsPath, 'utf8')));
  // The guided installer already owns the interaction. Keep Wrangler from
  // inserting unrelated agent-skill update prompts after a successful deploy.
  const env = { ...process.env, WRANGLER_NO_SKILLS_UPDATE_PROMPTS: 'true' };
  if (vars.CLOUDFLARE_ACCOUNT_ID) env.CLOUDFLARE_ACCOUNT_ID = vars.CLOUDFLARE_ACCOUNT_ID;
  const args = ['deploy', '--env', 'production'];
  let bootstrapSecret;
  let generatedConfig;
  {
    const require = createRequire(resolve(backend, 'package.json'));
    const { rawConfig } = require('wrangler').experimental_readRawConfig({ config: resolve(backend, 'wrangler.jsonc') });
    // Production vars are explicit below. Development-only vars are not inherited
    // by Wrangler; omit them from this temporary config to avoid misleading setup
    // warnings about optional local OIDC/email/demo configuration.
    delete rawConfig.vars;
    if (vars.CLOUDFS_WORKER_NAME) {
      if (!/^[a-z][a-z0-9-]{1,40}$/.test(vars.CLOUDFS_WORKER_NAME)) throw new Error('Invalid CLOUDFS_WORKER_NAME.');
      rawConfig.env.production.name = vars.CLOUDFS_WORKER_NAME;
    }
    rawConfig.env.production.r2_buckets = productionR2Bindings(vars, rawConfig.env.production.r2_buckets);
    rawConfig.env.production.send_email = productionEmailBindings(vars, rawConfig.env.production.send_email);
    generatedConfig = resolve(backend, `.deploy-${process.pid}.json`);
    writeFileSync(generatedConfig, JSON.stringify(rawConfig), { mode: 0o600, flag: 'wx' });
    process.on('exit', () => rmSync(generatedConfig, { force: true }));
    args.push('--config', generatedConfig);
  }
  if (existsSync(secretsPath)) {
    const secrets = JSON.parse(readFileSync(secretsPath, 'utf8'));
    validateSecrets(secrets);
    bootstrapSecret = secrets.BOOTSTRAP_SECRET;
    chmodSync(secretsPath, 0o600);
    args.push('--secrets-file', secretsPath);
  } else {
    console.log('Using existing Worker secrets. Fresh deployments need five configured secrets; see docs/SELF-HOSTING.md.');
  }
  if (flags.has('--dry-run')) args.push('--dry-run');
  const wrangler = resolve(backend, 'node_modules/.bin/wrangler');
  if (!existsSync(wrangler)) throw new Error('Install dependencies first: npm ci in backend and web.');
  if (process.env.SKIP_WEB_BUILD !== '1') run('npm', ['run', 'build'], { cwd: resolve(root, 'web'), env: { ...buildEnvironment(env), VITE_USE_MOCK: '0', VITE_API_BASE: '' } });
  if (!existsSync(resolve(root, 'web/dist/index.html'))) throw new Error('The web console build is missing. Run without SKIP_WEB_BUILD.');
  if (env.CLOUDFS_MAC_INSTALLER || vars.CLOUDFS_MAC_INSTALLER) {
    const installer = packageMacInstaller(env.CLOUDFS_MAC_INSTALLER || vars.CLOUDFS_MAC_INSTALLER, resolve(root, 'web/dist'), vars.PUBLIC_BASE_URL);
    vars.APP_DOWNLOAD_URL = installer.url;
    console.log(`Including the Mac installer and checksum in the console's download page (${installer.bytes} bytes).`);
  }
  for (const [key, value] of Object.entries(vars)) if (!key.startsWith('CLOUDFLARE_') && !key.startsWith('CLOUDFS_')) args.push('--var', `${key}:${value}`);
  rmSync(resolve(root, 'web/dist/_redirects'), { force: true });
  console.log(flags.has('--dry-run') ? 'Validating the production bundle without deploying…' : 'Deploying the console and gateway together…');
  run(wrangler, args, { env });
  if (!flags.has('--dry-run')) {
    console.log('Checking the deployed API, metadata databases and storage…');
    const verified = await verifyDeployment(vars.PUBLIC_BASE_URL, bootstrapSecret, { maintenanceMode: vars.BACKUP_MODE });
    if (verified.maintenanceVerified) console.log(`Backup maintenance verified (${verified.maintenanceMode}). Complete the coordinated operation before removing BACKUP_MODE. Ordinary client traffic is unavailable.`);
    else if (verified.readinessVerified) console.log('Deployment verified: all metadata authorities and both storage paths are ready.');
    else console.warn('API is responding. Full readiness was NOT verified because the local secrets file is absent. Run Health check from the signed-in admin console.');
    if (verified.warnings.length) console.warn(`Review optional configuration in Health check: ${verified.warnings.join(', ')}.`);
    if (!verified.maintenanceVerified) console.log(`Existing workspaces: sign in at ${vars.PUBLIC_BASE_URL}/signin. For a fresh deployment only, use /setup. Pre-password deployments can migrate with scripts/migrate-legacy-account.mjs; see docs/SELF-HOSTING.md.`);
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
