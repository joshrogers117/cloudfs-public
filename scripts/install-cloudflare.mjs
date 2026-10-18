#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Interactive entry point. Provisioning remains in the resumable setup script.
import { existsSync, readFileSync, mkdirSync, writeFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
import { deploymentProfile } from './deployment-profile.mjs';
import { parseVars } from './deploy-config.mjs';
import { requireInstallerNode, installationPlan, buildEnvironment, provisioningEnvironment } from './installer-plan.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
let readline;
const run = (command, argv, env = buildEnvironment(process.env)) => {
  const result = spawnSync(command, argv, { cwd: root, env, stdio: 'inherit' });
  if (result.error || result.status !== 0) throw new Error(`${command} did not complete. Correct the reported problem, then rerun the same setup command.`);
};
async function ask(label, fallback = '') {
  const answer = await readline.question(`${label}${fallback ? ` [${fallback}]` : ''}: `);
  return answer.trim() || fallback;
}
async function secret() {
  // Readline consumes pasted input without echoing it or putting it in shell history.
  readline.close();
  const sink = new Writable({ write(_chunk, _encoding, done) { done(); } });
  const hidden = createInterface({ input: process.stdin, output: sink, terminal: true });
  process.stdout.write('Provisioning API token (hidden): ');
  try { return (await hidden.question('')).trim(); }
  finally { hidden.close(); process.stdout.write('\n'); readline = createInterface({ input: process.stdin, output: process.stdout }); }
}
async function finish(paths, profile) {
  const vars = parseVars(readFileSync(paths.varsPath, 'utf8'));
  const origin = new URL(vars.PUBLIC_BASE_URL);
  if (origin.protocol !== 'https:' || origin.origin !== vars.PUBLIC_BASE_URL) throw new Error('The saved public address must be an HTTPS origin.');
  console.log(`\nServer ready: ${origin.origin}/setup\nKeep a secure backup of ${paths.directory}.\nIt contains the encryption key needed to recover this server. A local cache or snapshot is not an independent backup.\nLater updates: node scripts/deployment.mjs ${profile} deploy\nRevoke the temporary provisioning token in Cloudflare when setup is complete. Keep the separate bucket storage credential.`);
  if (process.platform === 'darwin' && await ask('Copy the setup secret to the clipboard? It is sensitive; paste only into your server setup page (y/N)') === 'y') {
    const key = JSON.parse(readFileSync(paths.secretsPath, 'utf8')).BOOTSTRAP_SECRET;
    if (typeof key !== 'string' || key.length < 32) throw new Error('The saved setup secret is missing. Restore the protected secrets file.');
    const copy = spawnSync('/usr/bin/pbcopy', [], { input: key, env: buildEnvironment(process.env) });
    if (copy.status !== 0) throw new Error('Could not copy. Open the protected secrets file locally to obtain BOOTSTRAP_SECRET.');
    console.log('Copied. After pasting it, copy something else to replace it in your clipboard.');
  } else console.log(`Find BOOTSTRAP_SECRET in ${paths.secretsPath}. Do not send that file to teammates or support.`);
  if (process.platform === 'darwin' && await ask('Open browser setup now (Y/n)', 'y') === 'y') run('/usr/bin/open', [`${origin.origin}/setup`]);
  console.log('In the browser: create your owner account, configure email delivery, create a filespace, then invite teammates with file access.');
}

try {
  if (args.includes('--help')) {
    console.log('Usage: node scripts/install-cloudflare.mjs [--profile NAME] [--check | --finish]\n--check checks local prerequisites only, without credentials, network calls or writes.\n--finish returns to browser setup for a completed install.\nDefault: guided fresh Cloudflare/R2 installation or resume the selected profile.\nRead INSTALL.md before creating a provisioning token.');
  } else {
    const options = new Map();
    for (let i = 0; i < args.length; i++) {
      if (!['--profile', '--check', '--finish'].includes(args[i]) || options.has(args[i])) throw new Error('Unknown or repeated option. Use --help.');
      if (args[i] === '--profile' && (!args[i + 1] || args[i + 1].startsWith('--'))) throw new Error('--profile requires a name.');
      options.set(args[i], args[i] === '--profile' ? args[++i] : true);
    }
    requireInstallerNode();
    const profile = options.get('--profile') || 'cloudfs';
    const paths = deploymentProfile(root, profile);
    if (options.has('--check')) {
      if (options.has('--finish')) throw new Error('Choose --check or --finish.');
      for (const file of ['backend/package-lock.json', 'web/package-lock.json', 'backend/wrangler.jsonc', 'scripts/setup-cloudflare.mjs']) if (!existsSync(resolve(root, file))) throw new Error(`Missing release file: ${file}. Extract the complete server package.`);
      const npm = spawnSync('npm', ['--version'], { env: buildEnvironment(process.env), encoding: 'utf8' });
      if (npm.status !== 0) throw new Error('npm is missing. Install Node.js with npm, then retry.');
      console.log(`Local prerequisites ready (Node ${process.versions.node}, npm ${npm.stdout.trim()}).\nTarget profile: ${paths.directory}\nCloudflare plan, permissions, R2 and email have not been checked. No changes made.`);
    } else {
      if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('Guided setup needs an interactive terminal. Use --check for offline checks or scripts/setup-cloudflare.mjs for automation.');
      readline = createInterface({ input: process.stdin, output: process.stdout });
      console.log('\nCloudFS server setup\nThis installs the server in YOUR Cloudflare account. Teammates only install the Mac app.\nCloudflare bills your account for Workers, storage, operations and email. Workers Paid and R2 must already be enabled.\nThis installer does not change your plan or DNS. See INSTALL.md for permissions and recovery.');
      const checkpoint = `${paths.secretsPath}.setup-state`;
      const state = existsSync(checkpoint) ? JSON.parse(readFileSync(checkpoint, 'utf8')) : null;
      if (state?.complete || options.has('--finish')) {
        if (!state?.complete || !existsSync(paths.varsPath) || !existsSync(paths.secretsPath)) throw new Error('No complete installation with intact configuration and keys exists in this profile. Restore missing files before continuing.');
        await finish(paths, profile);
      } else {
        const choicesPath = resolve(paths.directory, 'installer.json');
        const saved = existsSync(choicesPath) ? JSON.parse(readFileSync(choicesPath, 'utf8')) : null;
        if (!saved && (state || existsSync(paths.varsPath) || existsSync(paths.secretsPath))) throw new Error('This profile was created with another setup path. Resume its original command; use deployment.mjs to update an existing server.');
        const bundled = resolve(root, 'macos/CloudFS.dmg');
        const plan = installationPlan(root, saved ? { ...saved, profile } : {
          profile,
          account: await ask('Cloudflare account ID'),
          worker: await ask('Unique server name', `cloudfs-${profile}`),
          emailFrom: await ask('Sender address on an onboarded Cloudflare Email Sending domain (blank to configure later)'),
          installer: await ask('Path to the signed, notarized CloudFS Mac DMG', existsSync(bundled) ? bundled : ''),
        });
        if (state && (state.account !== plan.account || state.worker !== plan.worker)) throw new Error('Saved setup choices differ from the provisioning checkpoint. Restore the original installer.json before resuming.');
        if (!plan.installer || !existsSync(plan.installer) || !statSync(plan.installer).isFile() || !plan.installer.toLowerCase().endsWith('.dmg')) throw new Error('Provide an existing CloudFS release DMG file so new teammates have a working download.');
        console.log(`\nReview installation\nAccount: ${plan.account}\nWorker: ${plan.worker}\nR2 data: ${plan.dataBucket}\nR2 audit: ${plan.auditBucket}\nStorage location: automatic R2 placement. Use the manual guide for existing or jurisdiction-restricted buckets.\nEmail: ${plan.emailFrom || 'not configured; use manual invitation links, password-reset email unavailable'}\nMac download: ${plan.installer}\nPrivate configuration: ${paths.directory}\nCreates application keys and a separate read/write storage credential scoped to the data bucket.\nAn interrupted setup resumes with the same keys. Existing Workers are never replaced by fresh setup.`);
        if (await ask('Install dependencies and create these Cloudflare resources (type install to proceed)') !== 'install') console.log('Cancelled. No changes made.');
        else {
          // Install from lockfiles before obtaining the provisioning credential.
          for (const part of ['backend', 'web']) run('npm', ['ci', '--prefix', part]);
          mkdirSync(paths.directory, { recursive: true, mode: 0o700 });
          if (!saved) writeFileSync(choicesPath, JSON.stringify({ profile, account: plan.account, worker: plan.worker, emailFrom: plan.emailFrom, installer: plan.installer }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
          console.log('Use a temporary account-scoped token with Workers Scripts Write, Workers R2 Storage Write, and Account API Tokens Write. It is not saved by this installer.');
          let token = process.env.CLOUDFLARE_API_TOKEN || await secret();
          if (!token) throw new Error('No token provided. Rerun to resume.');
          run(process.execPath, [resolve(root, 'scripts/setup-cloudflare.mjs')], provisioningEnvironment(process.env, plan, token));
          token = '';
          await finish(paths, profile);
        }
      }
    }
  }
} catch (error) { console.error(error.message); process.exitCode = 1; }
finally { readline?.close(); }
