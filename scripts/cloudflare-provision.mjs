// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from 'node:crypto';

// Missing configuration is not proof of a fresh install. Only the checkpoint
// written immediately before the first key generation may authorize it.
export function mayInitializeSecrets(state, hasVars) {
  return state.phase === 'before-secrets' && !state.complete && !state.creatingCredential && !hasVars;
}

export function credentialRequestDefinitelyRejected(error) {
  // An explicit client rejection cannot have created a token. A timeout, 5xx,
  // invalid response, or lost connection has an unknown outcome and stays parked.
  return error?.tokenNotCreated === true || [400, 401, 403, 404, 405, 409, 422, 429].includes(error?.status);
}

export function cloudflareAPI(token, fetcher = fetch) {
  if (!token) throw new Error('Set CLOUDFLARE_API_TOKEN to a Cloudflare token with Workers, R2 and Account API Tokens write permissions.');
  return async (path, method = 'GET', body) => {
    const response = await fetcher(`https://api.cloudflare.com/client/v4${path}`, {
      method, headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30_000),
    });
    let result;
    try { result = await response.json(); }
    catch {
      // JSON parser errors may quote the response, including a one-time token.
      const error = new Error(`Cloudflare ${method} ${path} returned an unreadable response (${response.status}). No application keys were rotated.`);
      error.status = response.status;
      throw error;
    }
    if (!response.ok || !result?.success) {
      const error = new Error(`Cloudflare ${method} ${path} failed (${response.status}). Check the token permissions and that R2 is enabled. No application keys were rotated.`);
      error.status = response.status;
      throw error;
    }
    return result.result;
  };
}

export async function resolveAccount(api, requested) {
  if (requested) {
    if (!/^[a-f0-9]{32}$/.test(requested)) throw new Error('CLOUDFLARE_ACCOUNT_ID must be a 32-character account ID.');
    return requested;
  }
  const accounts = await api('/accounts?per_page=50');
  if (accounts.length !== 1) throw new Error('Set CLOUDFLARE_ACCOUNT_ID to choose the account for this install.');
  return accounts[0].id;
}

// A new profile may not silently adopt another application's resources. The
// saved checkpoint is the authority for resuming resources this setup created.
export async function assertFreshInstallTargets(api, account, worker) {
  const targets = [
    [`/accounts/${account}/workers/scripts/${worker}/settings`, `Worker ${worker}`],
    ...[`${worker}-data`, `${worker}-audit`].map(bucket => [`/accounts/${account}/r2/buckets/${bucket}`, `R2 bucket ${bucket}`]),
  ];
  for (const [path, label] of targets) {
    try { await api(path); }
    catch (error) { if (error.status === 404) continue; throw error; }
    throw new Error(`${label} already exists. Choose a different server name, or use the manual guide to connect existing storage. Fresh setup will not adopt it.`);
  }
}

export async function ensureBucket(api, account, bucket) {
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket)) throw new Error('Use a valid R2 bucket name.');
  try {
    await api(`/accounts/${account}/r2/buckets/${bucket}`);
    return false;
  } catch (error) {
    if (error.status !== 404) throw error;
  }
  await api(`/accounts/${account}/r2/buckets`, 'POST', { name: bucket });
  return true;
}

export async function createStorageCredential(api, account, bucket, name) {
  let write;
  try {
    const groups = await api(`/accounts/${account}/tokens/permission_groups`);
    write = groups.find(group => group.name === 'Workers R2 Storage Bucket Item Write' && group.is_selectable !== false);
    if (!write) throw new Error('Cloudflare did not expose bucket-scoped R2 write permission. No broad account credential will be substituted.');
  } catch (error) {
    // Discovery never creates a credential, even if this GET times out.
    error.tokenNotCreated = true;
    throw error;
  }
  const token = await api(`/accounts/${account}/tokens`, 'POST', {
    name: `${name} storage`,
    policies: [{ effect: 'allow', resources: { [`com.cloudflare.edge.r2.bucket.${account}_default_${bucket}`]: '*' }, permission_groups: [{ id: write.id }] }],
  });
  if (typeof token.id !== 'string' || typeof token.value !== 'string' || !token.value) throw new Error('Cloudflare returned no storage credential. Inspect account API tokens before retrying.');
  return { S3_ACCESS_KEY_ID: token.id, S3_SECRET_ACCESS_KEY: createHash('sha256').update(token.value).digest('hex') };
}
