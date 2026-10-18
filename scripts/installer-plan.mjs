// SPDX-License-Identifier: AGPL-3.0-or-later
import { deploymentProfile } from './deployment-profile.mjs';

export function requireInstallerNode(version = process.versions.node) {
  const [major, minor] = version.split('.').map(Number);
  if (major < 22 || (major === 22 && minor < 12)) throw new Error('Install Node.js 22.12 or newer from https://nodejs.org, then run setup again.');
}

export function installationPlan(root, { profile, account, worker, emailFrom = '', installer = '' }) {
  const paths = deploymentProfile(root, profile);
  if (!/^[a-f0-9]{32}$/.test(account)) throw new Error('Use the 32-character Cloudflare account ID shown in your account dashboard.');
  if (!/^[a-z][a-z0-9-]{1,40}$/.test(worker)) throw new Error('Server name must be 2–41 lowercase letters, numbers or hyphens.');
  if (emailFrom && (!/^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/.test(emailFrom) || /[`$]/.test(emailFrom))) throw new Error('Use a plain sender address without backticks or dollar signs, such as files@example.org, on an onboarded Email Sending domain.');
  if (/[\r\n`$]/.test(installer)) throw new Error('The installer path must be a literal path without line breaks, backticks or dollar signs.');
  return { ...paths, profile, account, worker, emailFrom, installer,
    dataBucket: `${worker}-data`, auditBucket: `${worker}-audit` };
}

// Package install hooks and frontend builds do not need provisioning credentials.
export function buildEnvironment(environment) {
  return Object.fromEntries(Object.entries(environment).filter(([key]) => !/^(CLOUDFLARE_|CF_|CLOUDFS_PROD_|CLOUDFS_EMAIL_|CLOUDFS_MAC_INSTALLER$)/.test(key)));
}

export function provisioningEnvironment(environment, plan, token) {
  return { ...buildEnvironment(environment), CLOUDFLARE_API_TOKEN: token,
    CLOUDFLARE_ACCOUNT_ID: plan.account, CLOUDFS_WORKER_NAME: plan.worker,
    CLOUDFS_PROD_VARS: plan.varsPath, CLOUDFS_PROD_SECRETS: plan.secretsPath,
    CLOUDFS_EMAIL_FROM: plan.emailFrom, CLOUDFS_MAC_INSTALLER: plan.installer };
}
