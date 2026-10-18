// SPDX-License-Identifier: AGPL-3.0-or-later
// Operator-only, offline, whole-organization recovery. No normal request uses this coordinator.
import { AwsClient } from 'aws4fetch';
import { sha256 } from '@noble/hashes/sha256';
import type { Env } from './env';
import { API_VERSION } from './api-version';
import { filespaceDoName } from './security/auth';
import { timingSafeEqualStr } from './security/auth-session';
import { b64ToBytes, openSecret, storageKeyBytes } from './security/storage-crypto';
import { validateBackupCoherence } from './backup-coherence';
import { validateRestoredAuditStep, type AuditValidationProgress } from './backup-audit';
import { defaultStorageConfig, objectUrl, presignWith, requiredUploadHeaders, resolveStorageConfigAsync,
  type SpaceStorageDescriptor, type StorageConfig } from './storage';

type Kind = 'directory' | 'org' | 'auth' | 'filespace';
type ObjectKind = 'data' | 'audit';
type JsonRecord = Record<string, unknown>;
interface Schema { format: number; kind: Kind; schemaVersion: number; tables: Array<{name: string; columns: unknown[]; rowCount: number}>; excludedTables: string[]; pristine: boolean }
interface Target { id: string; kind: Kind; name: string; orgId?: string; filespaceId?: string; schema: Schema; expectedObjectCount?: number }
interface ObjectEntry { kind: ObjectKind; key: string; sha256: string; bytes: number }
interface Coordinator {
  backupId: string; archiveId?: string; revision?: number; releaseOutcome?: 'complete' | 'aborted'; mode: 'export' | 'restore'; phase: 'freezing' | 'exporting' | 'importing' | 'committing' | 'releasing' | 'complete' | 'aborted';
  auditValidation?: AuditValidationProgress;
  format: 1; apiVersion: number; scope: 'operator-declared-organizations'; organizations: string[];
  discoveredOrganizations: string[]; targets: Target[]; encryptionKeyFingerprint: string;
  signingSecretFingerprint: string; bootstrapSecretFingerprint: string; startedAt: number;
}
// A single contract keeps orchestration independent of each authority's application methods.
interface BackupStub {
  backupDescribe(): Promise<Schema>;
  backupFreeze(input: {backupId: string; mode: 'export' | 'restore'}): Promise<unknown>;
  backupRelease(input: {backupId: string}): Promise<unknown>;
  backupExportPage(input: {backupId: string; table: string; afterRowId?: number}): Promise<unknown>;
  backupRestoreBegin(input: {backupId: string; manifest: Schema}): Promise<unknown>;
  backupRestorePage(input: JsonRecord): Promise<unknown>;
  backupRestoreCommit(input: {backupId: string; pageCount: number; remapStorageToDefault?: boolean}): Promise<unknown>;
  backupRestoreStatus(): Promise<unknown>;
  backupInventory(): Promise<unknown>;
  backupStorageCredential(ref: string): Promise<{accessKeyId: string; secretIv: string; secretCiphertext: string} | null>;
  backupCoordinatorGet(): Promise<Coordinator | null>;
  backupCoordinatorSet(input: {backupId: string; state: Coordinator; expectedRevision: number; expectedPreviousBackupId?: string}): Promise<unknown>;
  backupObjectsPage(input: {backupId: string; cursor?: string}): Promise<{entries: Array<{key: string; sha256: string}>; nextCursor: string | null}>;
  backupExpectObjects(input: {backupId: string; pageIndex: number; entries: ObjectEntry[]}): Promise<unknown>;
  backupExpectedObject(input: {backupId: string; kind: ObjectKind; key: string}): Promise<ObjectEntry | null>;
  backupRecordObject(input: {backupId: string} & ObjectEntry): Promise<unknown>;
  backupVerifyObjects(input: {backupId: string; expectedCount: number}): Promise<unknown>;
  backupValidateCatalog(input: {backupId: string; organizations: string[]; orgId?: string; filespaceIds?: string[]}): Promise<unknown>;
}
const MAX_TARGETS = 512;
const MAX_AUDIT_BYTES = 8 * 1024 * 1024;
const SAFE_BACKUP_FAILURES = new Set(['setup_incomplete', 'reference_missing', 'local_reference_missing',
  'schema_mismatch', 'row_count', 'objects_unverified', 'referenced_object_missing', 'purge_in_progress',
  'target_not_pristine', 'page_count', 'page_digest', 'page_order', 'page_conflict', 'object_page_conflict',
  'hold_required', 'coordinator_revision', 'already_frozen', 'unknown_table', 'catalog_mismatch',
  'catalog_unvalidated', 'generation_released'].map(code => `backup_${code}`));
const encoder = new TextEncoder();
const hex = (value: Uint8Array) => [...sha256(value)].map(byte => byte.toString(16).padStart(2, '0')).join('');
const json = (value: unknown, status = 200) => Response.json(value === undefined ? {ok: true} : value, {status, headers: {'cache-control': 'no-store'}});
class BackupError extends Error { constructor(readonly code: string, readonly status = 409) { super(code); } }
function requireValue(condition: unknown, code: string, status = 400): asserts condition { if (!condition) throw new BackupError(code, status); }
function record(value: unknown): JsonRecord { requireValue(value && typeof value === 'object' && !Array.isArray(value), 'invalid_backup_request'); return value as JsonRecord; }
function directory(env: Env): BackupStub { return env.DIRECTORY_DO.get(env.DIRECTORY_DO.idFromName('global')) as unknown as BackupStub; }
function stub(env: Env, target: Pick<Target, 'kind' | 'name'>): BackupStub {
  const namespace = target.kind === 'directory' ? env.DIRECTORY_DO : target.kind === 'org' ? env.ORG_DO : target.kind === 'auth' ? env.AUTH_DO : env.FILESPACE;
  return namespace.get(namespace.idFromName(target.name)) as unknown as BackupStub;
}
function identity(kind: Kind, orgId?: string, filespaceId?: string): Omit<Target, 'schema'> {
  const name = kind === 'directory' ? 'global' : kind === 'filespace' ? filespaceDoName(orgId!, filespaceId!) : orgId!;
  return {id: `${kind}:${name}`, kind, name, ...(orgId ? {orgId} : {}), ...(filespaceId ? {filespaceId} : {})};
}
function orgList(value: unknown): string[] {
  requireValue(Array.isArray(value) && value.length > 0 && value.length <= 100, 'explicit_organizations_required');
  requireValue(value.every(v => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/.test(v)), 'invalid_organization');
  requireValue(new Set(value).size === value.length, 'duplicate_organization');
  return [...value].sort();
}
function fingerprints(env: Env) {
  requireValue(env.STORAGE_ENC_KEY && env.AUTH_SIGNING_SECRET && env.BOOTSTRAP_SECRET, 'backup_secrets_missing', 503);
  const key = storageKeyBytes(env.STORAGE_ENC_KEY);
  requireValue(key.byteLength === 32, 'backup_encryption_key_invalid', 503);
  return {encryptionKeyFingerprint: hex(key), signingSecretFingerprint: hex(encoder.encode(env.AUTH_SIGNING_SECRET)), bootstrapSecretFingerprint: hex(encoder.encode(env.BOOTSTRAP_SECRET))};
}
function targetIn(session: Coordinator, value: unknown, filespace = false): Target {
  const target = session.targets.find(t => t.id === value);
  requireValue(target && (!filespace || target.kind === 'filespace'), 'unknown_backup_target', 404);
  return target;
}
async function sessionFor(env: Env, id: string, mode: 'export' | 'restore'): Promise<Coordinator> {
  const session = await directory(env).backupCoordinatorGet();
  requireValue(session?.backupId === id && session.mode === mode, 'unknown_backup_session', 404);
  return session;
}
async function save(env: Env, session: Coordinator, expectedPreviousBackupId?: string) {
  const expectedRevision = session.revision ?? 0;
  const state = {...session, revision: expectedRevision + 1};
  await directory(env).backupCoordinatorSet({backupId: session.backupId, state, expectedRevision, expectedPreviousBackupId});
  session.revision = state.revision;
}
function objectKey(target: Target, kind: unknown, key: unknown): asserts kind is ObjectKind {
  requireValue((kind === 'data' || kind === 'audit') && typeof key === 'string', 'invalid_backup_object');
  const prefix = `${kind === 'data' ? 'blocks' : 'audit'}/${filespaceDoName(target.orgId!, target.filespaceId!)}/`;
  requireValue(key.startsWith(prefix) && !key.includes('..') && key.length <= 2048 && !/[\u0000-\u001f\\]/.test(key), 'backup_object_outside_filespace');
}
async function inventory(env: Env, organizations: string[]): Promise<Omit<Target, 'schema'>[]> {
  const targets: Omit<Target, 'schema'>[] = [identity('directory')];
  for (const orgId of organizations) {
    const org = identity('org', orgId);
    targets.push(org, identity('auth', orgId));
    const result = await stub(env, org).backupInventory() as {spaces: Array<{id: string; purgeState?: string | null}>};
    requireValue(Array.isArray(result.spaces), 'invalid_filespace_inventory', 503);
    for (const space of result.spaces) {
      requireValue(!space.purgeState, 'filespace_purge_in_progress', 409);
      targets.push(identity('filespace', orgId, space.id));
    }
    requireValue(targets.length <= MAX_TARGETS, 'backup_target_limit', 413);
  }
  return targets;
}
async function startExport(env: Env, body: JsonRecord): Promise<Response> {
  const organizations = orgList(body.organizations);
  requireValue(body.scope === 'operator-declared-organizations', 'explicit_backup_scope_required');
  const existing = await directory(env).backupCoordinatorGet();
  if (existing && !['complete', 'aborted'].includes(existing.phase)) {
    requireValue(existing.mode === 'export' && JSON.stringify(existing.organizations) === JSON.stringify(organizations), 'backup_already_active', 409);
    if (existing.phase === 'exporting') return json(existing);
    requireValue(existing.phase === 'freezing', 'backup_release_pending', 409);
    // A failed freeze retains its identity and can be safely retried.
    return continueExport(env, existing);
  }
  const targets = [identity('directory'), ...organizations.flatMap(orgId => [identity('org', orgId), identity('auth', orgId)])];
  const session: Coordinator = {backupId: crypto.randomUUID(), mode: 'export', phase: 'freezing', format: 1, apiVersion: API_VERSION,
    scope: 'operator-declared-organizations', organizations, discoveredOrganizations: [], targets: targets.map(t => ({...t, schema: undefined as unknown as Schema})), ...fingerprints(env), startedAt: Date.now()};
  await save(env, session, existing?.backupId);
  return continueExport(env, session);
}
async function continueExport(env: Env, session: Coordinator): Promise<Response> {
  // Freeze the registries first: a concurrent space/account creation must not
  // slip between discovery and the freeze and disappear from the archive.
  for (const target of session.targets.filter(t => t.kind !== 'filespace')) await stub(env, target).backupFreeze({backupId: session.backupId, mode: 'export'});
  const found = await directory(env).backupInventory() as {orgIds: string[]};
  requireValue(Array.isArray(found.orgIds), 'invalid_organization_inventory', 503);
  requireValue(found.orgIds.every(id => session.organizations.includes(id)), 'known_organization_omitted', 409);
  const targets = await inventory(env, session.organizations);
  session.discoveredOrganizations = [...found.orgIds].sort();
  session.targets = targets.map(t => ({...t, schema: undefined as unknown as Schema}));
  await save(env, session);
  // No rows or object catalog are read until every authority has durably frozen.
  for (const target of session.targets) await stub(env, target).backupFreeze({backupId: session.backupId, mode: 'export'});
  for (const target of session.targets) target.schema = await stub(env, target).backupDescribe();
  await validateBackupCoherence(env, session);
  session.phase = 'exporting'; await save(env, session); return json(session);
}
function validateTargets(value: unknown, organizations: string[]): Target[] {
  requireValue(Array.isArray(value) && value.length > 0 && value.length <= MAX_TARGETS, 'invalid_backup_targets');
  const targets = value.map(raw => {
    const target = record(raw) as unknown as Target;
    requireValue(['directory', 'org', 'auth', 'filespace'].includes(target.kind), 'invalid_backup_target_kind');
    requireValue(target.kind === 'directory' || organizations.includes(target.orgId!), 'backup_target_organization_mismatch');
    if (target.kind === 'filespace') requireValue(typeof target.filespaceId === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(target.filespaceId), 'invalid_backup_filespace');
    const expected = identity(target.kind, target.orgId, target.filespaceId);
    requireValue(target.id === expected.id && target.name === expected.name, 'backup_target_identity_mismatch');
    requireValue(target.schema?.kind === target.kind && target.schema.format === 1 && Array.isArray(target.schema.tables), 'invalid_backup_schema');
    if (target.kind === 'filespace') requireValue(Number.isSafeInteger(target.expectedObjectCount) && target.expectedObjectCount! >= 0, 'expected_object_count_required');
    return {...expected, schema: target.schema, ...(target.kind === 'filespace' ? {expectedObjectCount: target.expectedObjectCount} : {})};
  });
  requireValue(new Set(targets.map(t => t.id)).size === targets.length, 'duplicate_backup_target');
  requireValue(targets.filter(t => t.kind === 'directory').length === 1, 'directory_target_required');
  for (const id of organizations) for (const kind of ['org', 'auth'] as const) requireValue(targets.some(t => t.kind === kind && t.orgId === id), 'organization_target_missing');
  return targets;
}
async function startRestore(env: Env, body: JsonRecord): Promise<Response> {
  requireValue(typeof body.archiveId === 'string' && /^[A-Za-z0-9_-]{8,128}$/.test(body.archiveId), 'invalid_archive_id');
  requireValue(body.scope === 'operator-declared-organizations', 'explicit_backup_scope_required');
  const organizations = orgList(body.organizations), targetKeys = fingerprints(env);
  requireValue(body.encryptionKeyFingerprint === targetKeys.encryptionKeyFingerprint, 'restore_encryption_key_mismatch', 409);
  requireValue(typeof body.signingSecretFingerprint === 'string' && /^[a-f0-9]{64}$/.test(body.signingSecretFingerprint) && body.signingSecretFingerprint !== targetKeys.signingSecretFingerprint, 'fresh_signing_secret_required', 409);
  requireValue(typeof body.bootstrapSecretFingerprint === 'string' && /^[a-f0-9]{64}$/.test(body.bootstrapSecretFingerprint) && body.bootstrapSecretFingerprint !== targetKeys.bootstrapSecretFingerprint, 'fresh_bootstrap_secret_required', 409);
  const targets = validateTargets(body.targets, organizations), existing = await directory(env).backupCoordinatorGet();
  if (existing) {
    requireValue(existing.mode === 'restore' && existing.archiveId === body.archiveId && JSON.stringify(existing.targets) === JSON.stringify(targets), 'restore_target_already_claimed', 409);
    if (existing.phase === 'freezing') return continueRestore(env, existing);
    return json({...existing, restoreId: existing.backupId});
  }
  // Probe every target before claiming any. The RPC repeats its pristine check at freeze/begin.
  for (const target of targets) requireValue((await stub(env, target).backupDescribe()).pristine, 'restore_requires_empty_target', 409);
  const session: Coordinator = {backupId: crypto.randomUUID(), archiveId: body.archiveId, mode: 'restore', phase: 'freezing',
    format: 1, apiVersion: API_VERSION, scope: 'operator-declared-organizations', organizations, discoveredOrganizations: [], targets, ...targetKeys, startedAt: Date.now()};
  await save(env, session);
  return continueRestore(env, session);
}
async function continueRestore(env: Env, session: Coordinator): Promise<Response> {
  // Freeze the complete set before populating any staging table.
  for (const target of session.targets) await stub(env, target).backupFreeze({backupId: session.backupId, mode: 'restore'});
  for (const target of session.targets) {
    const authority = stub(env, target);
    await authority.backupRestoreBegin({backupId: session.backupId, manifest: target.schema});
  }
  session.phase = 'importing'; await save(env, session); return json({...session, restoreId: session.backupId});
}
async function sourceStorage(env: Env, target: Target): Promise<StorageConfig> {
  const org = stub(env, identity('org', target.orgId));
  const {spaces} = await org.backupInventory() as {spaces: Array<{id: string; storageEndpoint?: string; storageRegion?: string; storageBucket?: string; storageForcePathStyle?: boolean; storageCredentialRef?: string}>};
  const row = spaces.find(s => s.id === target.filespaceId); requireValue(row, 'filespace_missing_from_inventory', 409);
  const descriptor: SpaceStorageDescriptor = {endpoint: row.storageEndpoint, region: row.storageRegion, bucket: row.storageBucket,
    forcePathStyle: row.storageForcePathStyle, credentialRef: row.storageCredentialRef};
  return resolveStorageConfigAsync(env, descriptor, async ref => {
    const credential = await org.backupStorageCredential(ref);
    return credential ? {accessKeyId: credential.accessKeyId, secretAccessKey: await openSecret(env.STORAGE_ENC_KEY, {iv: credential.secretIv, ciphertext: credential.secretCiphertext})} : null;
  });
}
function auditUrl(origin: string, session: Coordinator, target: Target, key: string, restore = false) {
  const url = new URL(`/v1/admin/${restore ? 'restore' : 'backup'}/${session.backupId}/audit-object`, origin);
  url.searchParams.set('target', target.id); url.searchParams.set('key', key); return url.toString();
}
async function objects(env: Env, session: Coordinator, target: Target, cursor: string | null, origin: string): Promise<Response> {
  requireValue(env.AUDIT_BUCKET, 'audit_bucket_missing', 503);
  if (!cursor?.startsWith('audit:')) {
    const page = await stub(env, target).backupObjectsPage({backupId: session.backupId, cursor: cursor?.startsWith('data:') ? cursor.slice(5) : undefined});
    const config = await sourceStorage(env, target);
    const entries = await Promise.all(page.entries.map(async object => {
      objectKey(target, 'data', object.key);
      return {...object, kind: 'data', targetId: target.id, downloadUrl: await presignWith(config, object.key, 'GET', 900)};
    }));
    return json({entries, nextCursor: page.nextCursor === null ? 'audit:' : `data:${page.nextCursor}`});
  }
  const page = await env.AUDIT_BUCKET.list({prefix: `audit/${filespaceDoName(target.orgId!, target.filespaceId!)}/`, limit: 128, cursor: cursor.slice(6) || undefined});
  const entries = page.objects.map(object => {
    requireValue(object.size <= MAX_AUDIT_BYTES, 'audit_object_exceeds_backup_limit', 413);
    return {kind: 'audit', targetId: target.id, key: object.key, bytes: object.size, downloadUrl: auditUrl(origin, session, target, object.key), requiresOperatorAuth: true};
  });
  return json({entries, nextCursor: page.truncated ? `audit:${page.cursor}` : null});
}
async function expectedObject(env: Env, session: Coordinator, target: Target, body: JsonRecord) {
  objectKey(target, body.kind, body.key);
  const expected = await stub(env, target).backupExpectedObject({backupId: session.backupId, kind: body.kind, key: body.key as string});
  requireValue(expected, 'object_not_in_restore_manifest', 409); return expected;
}
async function hashBody(body: ReadableStream<Uint8Array> | null, expectedBytes: number): Promise<string> {
  requireValue(body, 'restore_object_missing', 409); const digest = sha256.create(), reader = body.getReader(); let bytes = 0;
  try { while (true) { const chunk = await reader.read(); if (chunk.done) break; bytes += chunk.value.byteLength; requireValue(bytes <= expectedBytes, 'restore_object_size_mismatch', 409); digest.update(chunk.value); } }
  finally { await reader.cancel().catch(() => {}); }
  requireValue(bytes === expectedBytes, 'restore_object_size_mismatch', 409);
  return [...digest.digest()].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
async function verifyObject(env: Env, expected: ObjectEntry): Promise<void> {
  if (expected.kind === 'audit') {
    requireValue(env.AUDIT_BUCKET, 'audit_bucket_missing', 503);
    const result = await env.AUDIT_BUCKET.get(expected.key); requireValue(result?.size === expected.bytes, 'restore_object_size_mismatch', 409);
    requireValue(await hashBody(result.body, expected.bytes) === expected.sha256, 'restore_object_checksum_mismatch', 409); return;
  }
  const config = defaultStorageConfig(env), aws = new AwsClient({...config, service: 's3'});
  const signed = await aws.sign(objectUrl(config, expected.key), {method: 'HEAD', headers: {'x-amz-checksum-mode': 'ENABLED'}});
  const response = await fetch(signed.url, {method: 'HEAD', headers: signed.headers, redirect: 'manual', signal: AbortSignal.timeout(30_000)});
  requireValue(response.ok && response.headers.get('content-length') === String(expected.bytes), 'restore_object_size_mismatch', 409);
  const checksum = response.headers.get('x-amz-checksum-sha256');
  if (checksum) { requireValue([...b64ToBytes(checksum)].map(byte => byte.toString(16).padStart(2, '0')).join('') === expected.sha256, 'restore_object_checksum_mismatch', 409); return; }
  const read = await aws.sign(objectUrl(config, expected.key), {method: 'GET'});
  const result = await fetch(read.url, {headers: read.headers, redirect: 'manual', signal: AbortSignal.timeout(30_000)});
  requireValue(result.ok, 'restore_object_read_failed', 409);
  requireValue(await hashBody(result.body, expected.bytes) === expected.sha256, 'restore_object_checksum_mismatch', 409);
}
async function finishRestore(env: Env, session: Coordinator, body: JsonRecord): Promise<Response> {
  if (session.phase === 'complete') return json({restoreId: session.backupId, complete: true, maintenance: true});
  requireValue(['importing', 'committing', 'releasing'].includes(session.phase), 'restore_not_ready', 409);
  requireValue(Array.isArray(body.targets) && body.targets.length === session.targets.length, 'restore_page_counts_required');
  const counts = new Map<string, number>();
  for (const input of body.targets) { const value = record(input), target = targetIn(session, value.id);
    requireValue(Number.isSafeInteger(value.pageCount) && Number(value.pageCount) >= 0 && !counts.has(target.id), 'invalid_restore_page_count'); counts.set(target.id, Number(value.pageCount)); }
  // Directory last: no login/ownership mapping is exposed before the other authorities exist.
  const ordered = [...session.targets].sort((a, b) => Number(a.kind === 'directory') - Number(b.kind === 'directory'));
  if (session.phase !== 'releasing') {
    for (const target of session.targets.filter(t => t.kind === 'filespace')) await stub(env, target).backupVerifyObjects({backupId: session.backupId, expectedCount: target.expectedObjectCount!});
    for (const target of session.targets) await stub(env, target).backupValidateCatalog({backupId: session.backupId,
    organizations: session.organizations, orgId: target.orgId,
    filespaceIds: session.targets.filter(t => t.kind === 'filespace' && t.orgId === target.orgId).map(t => t.filespaceId!)});
    await validateBackupCoherence(env, session);
    const audit = await validateRestoredAuditStep(env, session, session.auditValidation);
    session.auditValidation = audit.progress;
    if (!audit.complete) {
      await save(env, session);
      return json({restoreId: session.backupId, complete: false, maintenance: true, phase: 'validating', revision: session.revision}, 202);
    }
    session.phase = 'committing'; await save(env, session);
    for (const target of ordered) await stub(env, target).backupRestoreCommit({backupId: session.backupId, pageCount: counts.get(target.id)!, remapStorageToDefault: target.kind === 'org'});
    session.phase = 'releasing'; session.releaseOutcome = 'complete'; await save(env, session);
  }
  for (const target of ordered) await stub(env, target).backupRelease({backupId: session.backupId});
  session.phase = 'complete'; await save(env, session);
  return json({restoreId: session.backupId, complete: true, maintenance: true, note: 'Verify restored permissions and redeploy without BACKUP_MODE to reopen the service.'});
}

export async function handleBackupRequest(req: Request, env: Env): Promise<Response | null> {
  const url = new URL(req.url), parts = url.pathname.split('/').filter(Boolean);
  if (parts[0] !== 'v1' || parts[1] !== 'admin' || !['backup', 'restore'].includes(parts[2])) return null;
  if (!['export', 'restore'].includes(env.BACKUP_MODE ?? '')) return json({error: 'backup_disabled'}, 404);
  if (!env.BOOTSTRAP_SECRET || env.BOOTSTRAP_SECRET.length < 16 || !timingSafeEqualStr(req.headers.get('x-bootstrap-secret') ?? '', env.BOOTSTRAP_SECRET)) return json({error: 'unauthorized'}, 401);
  try {
    const mode = parts[2] === 'backup' ? 'export' : 'restore';
    requireValue(env.BACKUP_MODE === mode, 'wrong_backup_mode', 409);
    if (parts.length === 4 && parts[3] === 'status' && req.method === 'GET') return json({mode, ...fingerprints(env), session: await directory(env).backupCoordinatorGet()});
    if (parts.length === 4 && parts[3] === 'start' && req.method === 'POST') return await (mode === 'export' ? startExport(env, record(await req.json())) : startRestore(env, record(await req.json())));
    requireValue(parts.length === 5, 'backup_route_not_found', 404);
    const session = await sessionFor(env, parts[3], mode), action = parts[4];
    if (mode === 'export' && ['finish', 'abort'].includes(action) && req.method === 'POST') {
      if (!['complete', 'aborted'].includes(session.phase)) {
        if (session.phase !== 'releasing') {
          session.releaseOutcome = action === 'finish' ? 'complete' : 'aborted';
          session.phase = 'releasing'; await save(env, session);
        }
        for (const target of [...session.targets].reverse()) await stub(env, target).backupRelease({backupId: session.backupId});
        session.phase = session.releaseOutcome!; await save(env, session);
      }
      return json({backupId: session.backupId, complete: session.phase === 'complete', maintenance: true});
    }
    if (mode === 'restore' && action === 'finish' && req.method === 'POST') return await finishRestore(env, session, record(await req.json()));
    requireValue(session.phase === (mode === 'export' ? 'exporting' : 'importing'), 'backup_session_not_active', 409);
    if (action === 'audit-object') {
      const target = targetIn(session, url.searchParams.get('target'), true), key = url.searchParams.get('key'); objectKey(target, 'audit', key);
      requireValue(env.AUDIT_BUCKET, 'audit_bucket_missing', 503);
      if (mode === 'export' && req.method === 'GET') {
        const object = await env.AUDIT_BUCKET.get(key!); requireValue(object && object.size <= MAX_AUDIT_BYTES, 'audit_object_unavailable', 409);
        return new Response(object.body, {headers: {'content-type': 'application/octet-stream', 'content-length': String(object.size), 'cache-control': 'no-store'}});
      }
      if (mode === 'restore' && req.method === 'PUT') {
        const expected = await expectedObject(env, session, target, {kind: 'audit', key});
        requireValue(expected.bytes <= MAX_AUDIT_BYTES, 'audit_object_exceeds_backup_limit', 413);
        const bytes = new Uint8Array(await req.arrayBuffer()); requireValue(bytes.byteLength === expected.bytes && hex(bytes) === expected.sha256, 'restore_object_checksum_mismatch', 409);
        const existing = await env.AUDIT_BUCKET.head(key!);
        if (existing) { await verifyObject(env, expected); return new Response(null, {status: 412}); }
        const result = await env.AUDIT_BUCKET.put(key!, bytes, {onlyIf: {etagDoesNotMatch: '*'}, sha256: expected.sha256});
        return new Response(null, {status: result ? 200 : 412});
      }
      throw new BackupError('method_not_allowed', 405);
    }
    if (mode === 'export' && req.method === 'GET') {
      const target = targetIn(session, url.searchParams.get('target'), action === 'objects');
      if (action === 'metadata') {
        const table = url.searchParams.get('table'), cursor = url.searchParams.get('afterRowId');
        requireValue(table && target.schema.tables.some(t => t.name === table), 'unknown_backup_table', 404);
        requireValue(cursor === null || /^-?\d+$/.test(cursor) && Number.isSafeInteger(Number(cursor)), 'invalid_backup_cursor');
        return json(await stub(env, target).backupExportPage({backupId: session.backupId, table, afterRowId: cursor === null ? undefined : Number(cursor)}));
      }
      if (action === 'objects') return await objects(env, session, target, url.searchParams.get('cursor'), url.origin);
    }
    if (mode === 'restore' && req.method === 'POST') {
      const body = record(await req.json()), target = targetIn(session, body.targetId, action !== 'metadata');
      if (action === 'metadata') {
        const page = record(body.page);
        requireValue(Object.keys(page).every(key => ['table', 'columns', 'rows', 'nextRowId', 'digest'].includes(key)), 'invalid_metadata_page_field');
        requireValue(Number.isSafeInteger(body.pageIndex) && Number(body.pageIndex) >= 0, 'invalid_metadata_page_index');
        return json(await stub(env, target).backupRestorePage({...page, backupId: session.backupId, pageIndex: body.pageIndex}));
      }
      if (action === 'objects') {
        requireValue(Array.isArray(body.entries) && body.entries.length <= 128 && Number.isSafeInteger(body.pageIndex) && Number(body.pageIndex) >= 0, 'invalid_object_manifest_page');
        for (const value of body.entries) { const entry = record(value); objectKey(target, entry.kind, entry.key);
          requireValue(typeof entry.sha256 === 'string' && /^[a-f0-9]{64}$/.test(entry.sha256) && Number.isSafeInteger(entry.bytes) && Number(entry.bytes) >= 0, 'invalid_object_manifest_entry');
          requireValue(entry.kind !== 'data' || String(entry.key).endsWith(`/${entry.sha256}`), 'object_key_checksum_mismatch');
          requireValue(Number(entry.bytes) <= (entry.kind === 'audit' ? MAX_AUDIT_BYTES : 64 * 1024 * 1024), 'restore_object_exceeds_limit', 413);
        }
        return json(await stub(env, target).backupExpectObjects({backupId: session.backupId, pageIndex: Number(body.pageIndex), entries: body.entries as ObjectEntry[]}));
      }
      if (action === 'object-url') {
        const expected = await expectedObject(env, session, target, body);
        if (expected.kind === 'audit') return json({url: auditUrl(url.origin, session, target, expected.key, true), headers: {}, requiresOperatorAuth: true});
        const config = defaultStorageConfig(env);
        return json({url: await presignWith(config, expected.key, 'PUT', 900), headers: requiredUploadHeaders(expected.key), verificationUrl: await presignWith(config, expected.key, 'GET', 900)});
      }
      if (action === 'object-verify') {
        const expected = await expectedObject(env, session, target, body); await verifyObject(env, expected);
        await stub(env, target).backupRecordObject({backupId: session.backupId, ...expected}); return json({verified: true});
      }
    }
    throw new BackupError('backup_route_not_found', 404);
  } catch (error) {
    if (error instanceof BackupError) return json({error: error.code}, error.status);
    // Authenticated operator errors still must not echo storage URLs, archived rows or secrets.
    const action = parts[parts.length - 1];
    const code = error instanceof Error && SAFE_BACKUP_FAILURES.has(error.message) ? error.message : 'backup_operation_failed';
    console.error({event: code, action: ['start', 'status', 'metadata', 'objects', 'object-url', 'object-verify', 'audit-object', 'finish', 'abort'].includes(action) ? action : 'invalid_route'});
    return json({error: code, note: 'Maintenance remains enabled. Inspect the backup status and retry; preserve the archive and recovery key.'}, 409);
  }
}
