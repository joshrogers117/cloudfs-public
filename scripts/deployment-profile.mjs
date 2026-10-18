// SPDX-License-Identifier: AGPL-3.0-or-later
import { resolve } from 'node:path';

export function deploymentProfile(root, name) {
  if (!/^[a-z][a-z0-9-]{1,30}$/.test(name ?? '')) throw new Error('Profile names must be 2–31 lowercase letters, numbers or hyphens.');
  const directory = resolve(root, '.deployments', name);
  return { directory, varsPath: resolve(directory, 'deployment.vars'), secretsPath: resolve(directory, 'secrets.json') };
}

export function prepareProfileVars(template, worker) {
  if (!/^[a-z][a-z0-9-]{1,40}$/.test(worker)) throw new Error('Invalid CLOUDFS_WORKER_NAME.');
  return template.replace(/^S3_BUCKET=.*$/m, `S3_BUCKET=${worker}-data`)
    + `\nCLOUDFS_WORKER_NAME=${worker}\nCLOUDFS_AUDIT_BUCKET=${worker}-audit\n`;
}
