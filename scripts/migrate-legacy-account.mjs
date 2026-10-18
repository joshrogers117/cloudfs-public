#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Operator-only bridge for pre-password deployments. Never accepts or generates a password.
import { readFileSync, writeFileSync, statSync } from 'node:fs';
import { createHmac, randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';

const { values } = parseArgs({ options: {
  gateway: { type: 'string' }, org: { type: 'string' }, 'owner-id': { type: 'string' },
  'signing-key-file': { type: 'string' }, 'owner-token-file': { type: 'string' }, output: { type: 'string' },
  'recover-password': { type: 'boolean' },
} });
try {
  const gateway = new URL(values.gateway ?? '');
  if (gateway.protocol !== 'https:' || gateway.username || gateway.password || gateway.search || gateway.hash || gateway.pathname !== '/') throw new Error('Use an HTTPS gateway origin.');
  if (!values.org || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(values.org) || !values.output) throw new Error('--org and --output are required.');
  if (Boolean(values['owner-token-file']) === Boolean(values['signing-key-file'])) throw new Error('Choose --owner-token-file or --signing-key-file (existing deployment key).');
  if (values['recover-password'] && !values['signing-key-file']) throw new Error('Password recovery requires the original deployment signing key; a login token is insufficient.');
  const credentialFile = values['owner-token-file'] ?? values['signing-key-file'];
  if ((statSync(credentialFile).mode & 0o077) !== 0) throw new Error('Credential file must be private (chmod 600).');
  const credential = readFileSync(credentialFile, 'utf8').trim();
  let token = credential;
  if (values['signing-key-file']) {
    if (!values['owner-id'] || credential.length < 16) throw new Error('--owner-id and the original deployment signing key are required.');
    const iat = Math.floor(Date.now() / 1000);
    const encode = v => Buffer.from(JSON.stringify(v)).toString('base64url');
    const signed = `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode({ sub: values['owner-id'], typ: 'session', org: values.org,
      scp: ['fs:read'], jti: `legacy-migration-${randomUUID()}`, iat, exp: iat + 120,
      ...(values['recover-password'] ? { aud: `${gateway.origin}/v1/operator/legacy-password-recovery`, act: 'legacy-password-recovery' } : {}) })}`;
    token = `${signed}.${createHmac('sha256', credential).update(signed).digest('base64url')}`;
  }
  const response = await fetch(new URL(`/v1/orgs/${values.org}/legacy-account`, gateway), {
    method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ recoverPassword: !!values['recover-password'] }), redirect: 'error',
  });
  const result = await response.json();
  if (!response.ok) throw new Error(`Migration refused (${response.status}): ${result.error ?? 'unknown error'}`);
  writeFileSync(values.output, JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log(result.status === 'ready' ? 'Existing account indexed. Sign in normally; no credentials changed.' : 'A single-use, 30-minute password link was saved privately. The owner must choose and submit their password in the browser.');
  console.log('Result saved to the requested output file. No credentials were printed.');
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
