// SPDX-License-Identifier: AGPL-3.0-or-later
// Pure production configuration parser: never source a configuration file as shell code.
export function parseVars(source) {
  const vars = {};
  for (const [index, raw] of source.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
    if (!match) throw new Error(`Invalid configuration on line ${index + 1}; use KEY=value.`);
    const [, key] = match;
    let value = match[2].trim();
    if (/^(".*"|'.*')$/.test(value)) value = value.slice(1, -1);
    if (/(SECRET|TOKEN|PASSWORD|PRIVATE_KEY|ACCESS_KEY|ENC_KEY|API_KEY)/.test(key)) {
      throw new Error(`${key} belongs in the secrets file, never .prod.vars.`);
    }
    if (/[`$]/.test(value)) throw new Error(`Use a literal value for ${key}; shell expansion is not supported.`);
    if (Object.hasOwn(vars, key)) throw new Error(`Duplicate configuration key: ${key}.`);
    vars[key] = value;
  }
  return vars;
}

export function productionVars(input) {
  const vars = { ...input };
  if (vars.EMAIL_PROVIDER !== undefined) vars.EMAIL_PROVIDER = vars.EMAIL_PROVIDER.trim().toLowerCase();
  if (vars.BACKUP_MODE !== undefined && !['export', 'restore'].includes(vars.BACKUP_MODE)) throw new Error('BACKUP_MODE must be export or restore; remove it to reopen the service after a completed recovery operation.');
  if (vars.CLOUDFLARE_ACCOUNT_ID && !vars.S3_ENDPOINT) vars.S3_ENDPOINT = `https://${vars.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  vars.WEB_BASE_URL ||= vars.PUBLIC_BASE_URL;
  vars.S3_REGION ||= 'auto';
  vars.SIGNUP_MODE ||= 'closed';
  if (vars.STORAGE_VERIFY_UPLOADS !== undefined && vars.STORAGE_VERIFY_UPLOADS !== '1') throw new Error('Production requires storage upload verification.');
  vars.STORAGE_VERIFY_UPLOADS = '1';
  if (vars.EMAIL_PROVIDER === 'console' || ['1', 'true'].includes(vars.EMAIL_DEV_CONSOLE)) throw new Error('Production must not log private email verification/reset links. Configure a delivering email provider.');
  for (const key of ['S3_ENDPOINT', 'S3_BUCKET', 'PUBLIC_BASE_URL', 'WEB_BASE_URL']) {
    const value = vars[key];
    if (!value || /change-me|your[_-]|placeholder|example\.com/i.test(value)) throw new Error(`Set ${key} to your deployment value before deploying.`);
  }
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(vars.S3_BUCKET)) throw new Error('S3_BUCKET must be a valid S3 bucket name.');
  for (const key of ['S3_ENDPOINT', 'PUBLIC_BASE_URL', 'WEB_BASE_URL']) {
    const url = new URL(vars[key]);
    const host = url.hostname;
    if (url.protocol !== 'https:' || /^(localhost|127\.|0\.|10\.|192\.168\.|\[::1\])/.test(host) || host.endsWith('.local') || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
      throw new Error(`${key} must be a public HTTPS origin without a path or credentials.`);
    }
    vars[key] = url.origin;
  }
  if (vars.SIGNUP_MODE === 'open' && vars.SIGNUP_OPEN_ON_HTTPS !== '1') throw new Error('Open public signup requires explicit SIGNUP_OPEN_ON_HTTPS=1. Closed signup is recommended.');
  if (vars.CLOUDFLARE_ACCOUNT_ID && !/^[a-f0-9]{32}$/.test(vars.CLOUDFLARE_ACCOUNT_ID)) throw new Error('CLOUDFLARE_ACCOUNT_ID must be the 32-character account ID.');
  // The binding belongs to the account receiving this Worker. Never infer it
  // from just a bucket name or attach another account/provider's data bucket.
  const nativeR2 = vars.CLOUDFLARE_ACCOUNT_ID && vars.S3_ENDPOINT === `https://${vars.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  if (vars.DATA_BUCKET_ENDPOINT !== undefined || vars.DATA_BUCKET_NAME !== undefined) {
    if (!nativeR2 || vars.DATA_BUCKET_ENDPOINT !== vars.S3_ENDPOINT || vars.DATA_BUCKET_NAME !== vars.S3_BUCKET) {
      throw new Error('DATA_BUCKET mapping must exactly match this account’s deployment-default R2 endpoint and bucket.');
    }
  }
  if (nativeR2) {
    vars.DATA_BUCKET_ENDPOINT = vars.S3_ENDPOINT;
    vars.DATA_BUCKET_NAME = vars.S3_BUCKET;
  }
  return vars;
}

/** Generated production bindings; preserve unrelated operator bindings. */
export function productionR2Bindings(vars, existing = []) {
  const bindings = existing.filter(value => value.binding !== 'DATA_BUCKET'
    && !(vars.CLOUDFS_AUDIT_BUCKET && value.binding === 'AUDIT_BUCKET'));
  if (vars.CLOUDFS_AUDIT_BUCKET) {
    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(vars.CLOUDFS_AUDIT_BUCKET)) throw new Error('Invalid CLOUDFS_AUDIT_BUCKET.');
    bindings.push({binding:'AUDIT_BUCKET',bucket_name:vars.CLOUDFS_AUDIT_BUCKET});
  }
  if (vars.DATA_BUCKET_ENDPOINT && vars.DATA_BUCKET_NAME) {
    bindings.push({binding:'DATA_BUCKET',bucket_name:vars.DATA_BUCKET_NAME});
  }
  return bindings;
}

/** Only enable native email for an operator-selected sender, never a repository default. */
export function productionEmailBindings(vars, existing = []) {
  const bindings = existing.filter(value => value.name !== 'EMAIL');
  const provider = vars.EMAIL_PROVIDER?.trim().toLowerCase();
  const sender = vars.EMAIL_FROM?.trim();
  if (provider === 'cloudflare' && !sender) throw new Error('Cloudflare email requires EMAIL_FROM from an onboarded domain.');
  if (sender && (!provider || provider === 'cloudflare')) {
    if (!/^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/.test(sender)) throw new Error('EMAIL_FROM must be a plain sender address from an onboarded domain.');
    bindings.push({ name: 'EMAIL', allowed_sender_addresses: [sender] });
  }
  return bindings;
}

export function validateSecrets(secrets) {
  if (!secrets || typeof secrets !== 'object' || Array.isArray(secrets)) throw new Error('The secrets file must contain a JSON object.');
  for (const key of ['AUTH_SIGNING_SECRET', 'BOOTSTRAP_SECRET', 'STORAGE_ENC_KEY', 'S3_ACCESS_KEY_ID', 'S3_SECRET_ACCESS_KEY']) {
    if (typeof secrets[key] !== 'string' || !secrets[key].trim()) throw new Error(`Fill ${key} in the secrets file before deploying.`);
  }
  for (const key of ['AUTH_SIGNING_SECRET', 'BOOTSTRAP_SECRET']) if (secrets[key].length < 32) throw new Error(`${key} must be at least 32 characters.`);
  const key = secrets.STORAGE_ENC_KEY;
  const valid = /^[a-f0-9]{64}$/i.test(key) || (/^[A-Za-z0-9+/_-]+={0,2}$/.test(key) && Buffer.from(key, 'base64').length === 32);
  if (!valid) throw new Error('STORAGE_ENC_KEY must encode exactly 32 random bytes.');
}
