// SPDX-License-Identifier: AGPL-3.0-or-later
// Typed, maintenance-only SQLite backup. Archive data is never executable SQL.
import { sha256 } from '@noble/hashes/sha256';

export type BackupKind = 'directory' | 'org' | 'auth' | 'filespace';
export interface BackupEnv { BACKUP_MODE?: string; S3_ENDPOINT?: string; S3_REGION?: string; S3_BUCKET?: string }
export type BackupCell = { type: 'null' } | { type: 'integer' | 'text' | 'blob'; value: string } | { type: 'real'; value: number };
export interface BackupColumn { name: string; type: string; notNull: boolean; pk: number }
export interface BackupTable { name: string; columns: BackupColumn[]; rowCount: number }
export interface BackupManifest { format: 1; kind: BackupKind; schemaVersion: number; tables: BackupTable[]; excludedTables: string[]; pristine: boolean }
export interface BackupPage { table: string; columns: string[]; rows: BackupCell[][]; nextRowId: number | null; digest: string }
export interface BackupObject { kind: 'data' | 'audit'; key: string; sha256: string; bytes: number }
export interface RestoreStatus { backupId: string; state: 'staging' | 'committed'; pages: number }
const TABLES: Record<BackupKind, string[]> = {
  directory: ['_schema_migrations', 'email_index', 'webauthn_index', 'auth_config', 'setup_state', 'org_registry'],
  org: ['_schema_migrations', 'users', 'groups', 'group_members', 'spaces', 'filespace_keys', 'email_config', 'grants', 'org_meta'],
  auth: ['_schema_migrations', 'accounts', 'passwords', 'totp', 'recovery_codes', 'webauthn_creds'],
  filespace: ['_schema_migrations', 'items', 'meta', 'blocks', 'block_refs', 'snapshots', 'snapshot_schedules', 'grants', 'audit', 'snapshot_items', 'snapshot_blocks', 'meta_text', 'item_streams', 'retained_blocks', 'known_objects', 'snapshot_streams', 'stream_blocks', 'snapshot_stream_blocks', 'revoked_acl_principals', 'disabled_acl_authorities', 'object_reclamation'],
};
const OMIT: Record<BackupKind, string[]> = {
  directory: ['rate_buckets', 'setup_claim'],
  org: ['invites', 'share_links', 'storage_credentials'],
  auth: ['sessions', 'service_tokens', 'email_tokens', 'challenges', 'device_codes', 'device_sessions'],
  filespace: ['locks', 'range_locks', 'read_permits', 'range_waiters', 'open_handles', 'uploads', 'upload_parts', 'rate_buckets', 'block_upload_claims', 'verified_objects'],
};
const MAX_PAGE = 1024 * 1024, MAX_ROW = 8 * 1024 * 1024;
const enc = new TextEncoder();
export function backupDigest(value: unknown): string { return Array.from(sha256(enc.encode(JSON.stringify(value))), b => b.toString(16).padStart(2, '0')).join(''); }
export function backupPageDigest(page: Omit<BackupPage, 'digest'>): string { return backupDigest({ table: page.table, columns: page.columns, rows: page.rows, nextRowId: page.nextRowId }); }
function fail(reason: string): never { throw new Error(`backup_${reason}`); }
function ident(value: string): string { if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value)) fail('invalid_identifier'); return `"${value}"`; }
function b64(value: ArrayBuffer): string { let s = ''; const bytes = new Uint8Array(value); for (let i = 0; i < bytes.length; i += 8192) s += String.fromCharCode(...bytes.subarray(i, i + 8192)); return btoa(s); }
function decode(cell: BackupCell): { value: SqlStorageValue; expression: string } {
  if (!cell || typeof cell !== 'object') return fail('invalid_cell');
  switch (cell.type) {
    case 'null': return { value: null, expression: '?' };
    case 'integer': {
      if (typeof cell.value !== 'string' || !/^-?(0|[1-9][0-9]*)$/.test(cell.value) || cell.value.length > 20) fail('invalid_integer');
      const value = BigInt(cell.value); if (value < -9223372036854775808n || value > 9223372036854775807n) fail('invalid_integer');
      return { value: cell.value, expression: 'CAST(? AS INTEGER)' };
    }
    case 'real': if (typeof cell.value !== 'number' || !Number.isFinite(cell.value)) fail('invalid_real'); return { value: cell.value, expression: '?' };
    case 'text': if (typeof cell.value !== 'string') fail('invalid_text'); return { value: cell.value, expression: '?' };
    case 'blob': {
      if (typeof cell.value !== 'string' || cell.value.length % 4 !== 0 || /[^A-Za-z0-9+/=]/.test(cell.value)) fail('invalid_blob');
      const padding=cell.value.indexOf('='); if(padding>=0 && (padding<cell.value.length-2 || /[^=]/.test(cell.value.slice(padding)))) fail('invalid_blob');
      const bytes = Uint8Array.from(atob(cell.value), c => c.charCodeAt(0)); return { value: bytes.buffer, expression: '?' };
    }
    default: return fail('invalid_cell');
  }
}

/** One instance per DO. Application stores retain only guardedSQL. The raw
 * handle is private to backup methods, with no await inside staging/promotion. */
export class BackupState {
  readonly guardedSQL: SqlStorage;
  private ready = false;
  private hold: { backupId: string; mode: 'export' | 'restore' } | null = null;
  constructor(private readonly storage: DurableObjectStorage, private readonly env: BackupEnv, readonly kind: BackupKind) {
    const raw = storage.sql;
    this.guardedSQL = new Proxy(raw, { get: (target, key) => {
      if (key === 'exec') return (...args: Parameters<SqlStorage['exec']>) => { this.assertOrdinary(); return target.exec(...args); };
      const value = Reflect.get(target, key, target); return typeof value === 'function' ? value.bind(target) : value;
    } });
  }
  initialize(): void {
    this.raw.exec(`CREATE TABLE IF NOT EXISTS _backup_control (k TEXT PRIMARY KEY, value TEXT NOT NULL);`);
    this.raw.exec(`CREATE TABLE IF NOT EXISTS _backup_released (backup_id TEXT PRIMARY KEY,mode TEXT NOT NULL);`);
    this.hold = this.getControl('hold'); this.ready = true;
  }
  private get raw(): SqlStorage { return this.storage.sql; }
  private getControl<T>(key: string): T | null { const row = this.raw.exec(`SELECT value FROM _backup_control WHERE k=?;`, key).toArray()[0]; return row ? JSON.parse(String(row.value)) as T : null; }
  private putControl(key: string, value: unknown): void { this.raw.exec(`INSERT INTO _backup_control(k,value) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET value=excluded.value;`, key, JSON.stringify(value)); }
  isBlocked(): boolean { return this.ready && (!!this.env.BACKUP_MODE || !!this.hold); }
  assertOrdinary(): void { if (this.isBlocked()) fail('maintenance'); }
  private mode(expected?: 'export' | 'restore'): void { if (!['export', 'restore'].includes(this.env.BACKUP_MODE ?? '') || (expected && this.env.BACKUP_MODE !== expected)) fail('mode_required'); }
  private requireHold(backupId: string, mode?: 'export' | 'restore', allowReleased = false): void { this.mode(mode); if(this.hold && this.hold.backupId!==backupId) fail('hold_required'); if (!this.hold || this.hold.backupId !== backupId || this.hold.mode !== this.env.BACKUP_MODE) { const released = this.raw.exec(`SELECT mode FROM _backup_released WHERE backup_id=?;`,backupId).toArray()[0]; if (!allowReleased || !released || released.mode !== this.env.BACKUP_MODE) fail('hold_required'); } }
  freeze(input: { backupId: string; mode: 'export' | 'restore' }): void {
    this.mode(input.mode);
    if (typeof input.backupId !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(input.backupId)) fail('invalid_id');
    if (this.raw.exec(`SELECT 1 FROM _backup_released WHERE backup_id=?;`,input.backupId).toArray().length) fail('generation_released');
    if (this.hold && (this.hold.backupId !== input.backupId || this.hold.mode !== input.mode)) fail('already_frozen');
    if (this.kind === 'directory' && input.mode === 'export' && this.raw.exec(`SELECT 1 FROM setup_claim LIMIT 1;`).toArray().length && Number(this.raw.exec(`SELECT v FROM setup_state WHERE k='setup_complete';`).toArray()[0]?.v ?? 0) !== 1) fail('setup_incomplete');
    if (this.kind === 'filespace' && Number(this.raw.exec(`SELECT value FROM meta WHERE key='purging';`).toArray()[0]?.value ?? 0) === 1) fail('purge_in_progress');
    if(input.mode==='export') this.checkLocalReferences('');
    this.putControl('hold', input); this.hold = input;
  }
  release(input: { backupId: string }): void {
    this.mode();
    if (typeof input.backupId!=='string' || !/^[A-Za-z0-9_-]{8,128}$/.test(input.backupId)) fail('invalid_id');
    // Aborting a partially frozen export must also cancel targets whose freeze
    // never ran. The tombstone fences a delayed freeze without touching another hold.
    if(this.env.BACKUP_MODE==='export' && this.hold?.backupId!==input.backupId) {
      this.raw.exec(`INSERT OR IGNORE INTO _backup_released VALUES (?,'export');`,input.backupId); return;
    }
    if(this.hold && this.hold.backupId!==input.backupId && this.raw.exec(`SELECT 1 FROM _backup_released WHERE backup_id=? AND mode=?;`,input.backupId,this.env.BACKUP_MODE!).toArray().length) return;
    this.requireHold(input.backupId, undefined, true);
    if (!this.hold || this.hold.backupId !== input.backupId) return;
    if (this.hold.mode === 'restore' && this.restoreStatus()?.state !== 'committed') fail('restore_incomplete');
    this.storage.transactionSync(() => { this.raw.exec(`INSERT OR IGNORE INTO _backup_released VALUES (?,?);`,this.hold!.backupId,this.hold!.mode); this.raw.exec(`DELETE FROM _backup_control WHERE k='hold';`); }); this.hold = null;
  }
  describe(): BackupManifest {
    this.mode();
    const allowed = new Set([...TABLES[this.kind], ...OMIT[this.kind]]);
    const tables = this.raw.exec(`SELECT name FROM sqlite_master WHERE type='table';`).toArray().map(row=>String(row.name));
    if (tables.some(name=>!allowed.has(name) && name !== '__miniflare_do_name' && !/^(_backup_|sqlite_|_+cf)/.test(name))) fail('unknown_table');
    return { format: 1, kind: this.kind, schemaVersion: Number(this.raw.exec(`SELECT MAX(id) AS v FROM _schema_migrations;`).one().v),
      tables: TABLES[this.kind].map(name => ({ name, columns: this.columns(name), rowCount: this.count(name) })), excludedTables: OMIT[this.kind], pristine: this.pristine() };
  }
  private columns(table: string): BackupColumn[] {
    if (!TABLES[this.kind].includes(table)) fail('table_not_allowed');
    return this.raw.exec(`PRAGMA table_info(${ident(table)});`).toArray().map(row => ({ name: String(row.name), type: String(row.type), notNull: Number(row.notnull) === 1, pk: Number(row.pk) }));
  }
  private count(table: string): number { return Number(this.raw.exec(`SELECT COUNT(*) AS n FROM ${ident(table)};`).one().n); }
  private pristine(): boolean {
    for (const table of [...TABLES[this.kind], ...OMIT[this.kind]]) {
      if (table === '_schema_migrations') continue;
      if (this.kind === 'filespace' && table === 'items') {
        if (this.raw.exec(`SELECT 1 FROM items WHERE id!='root' OR parent IS NOT NULL OR name!='' OR is_dir!=1 OR deleted!=0 OR size!=0 OR version!=1 LIMIT 1;`).toArray().length) return false;
      } else if (this.kind === 'filespace' && table === 'meta') {
        if (this.raw.exec(`SELECT 1 FROM meta WHERE NOT ((key='seq' AND value BETWEEN 0 AND 1) OR (key='fence' AND value=0) OR (key='visibility_generation' AND value=0) OR (key='archived_through_seq' AND value=-1)) LIMIT 1;`).toArray().length) return false;
      } else if (this.count(table)) return false;
    }
    return true;
  }
  exportPage(input: { backupId: string; table: string; afterRowId?: number }): BackupPage {
    this.requireHold(input.backupId, 'export');
    return this.readPage(input,'');
  }
  catalogPage(input: {backupId:string;table:string;afterRowId?:number}): BackupPage {
    this.requireHold(input.backupId,undefined,true);
    const prefix=this.env.BACKUP_MODE==='restore' && this.restoreStatus()?.state==='staging'?'_backup_stage_':'';
    return this.readPage(input,prefix);
  }
  private readPage(input:{table:string;afterRowId?:number},prefix:string): BackupPage {
    const columns = this.columns(input.table).map(column => column.name);
    const after = input.afterRowId ?? -1;
    if (!Number.isSafeInteger(after) || after < -1) fail('invalid_cursor');
    const select = columns.flatMap((column, i) => [`typeof(${ident(column)}) AS t${i}`, `CASE WHEN typeof(${ident(column)})='integer' THEN CAST(${ident(column)} AS TEXT) ELSE ${ident(column)} END AS v${i}`]);
    const rows: BackupCell[][] = []; let bytes = 0, last = after, more = false;
    // Exhaust every SQL cursor synchronously. Breaking an active cursor at the
    // JSON page budget leaves the staging table locked during later promotion.
    // Small batches also bound memory/over-read when a row contains a large
    // legacy BLOB; materializing all 4097 candidate rows could exhaust a Worker.
    pageRows: while (true) {
      const batch = this.raw.exec(`SELECT rowid AS _rowid,${select.join(',')} FROM ${ident(prefix+input.table)} WHERE rowid>? ORDER BY rowid LIMIT 8;`, last).toArray();
      for (const row of batch) {
        const cells = columns.map((_column, i): BackupCell => {
          const type = String(row[`t${i}`]), value = row[`v${i}`];
          if (type === 'null') return { type: 'null' };
          if (type === 'blob') return { type: 'blob', value: b64(value as ArrayBuffer) };
          if (type === 'integer' || type === 'text') return { type, value: String(value) };
          if (type === 'real') return { type, value: Number(value) };
          return fail('invalid_sql_type');
        });
        const size = enc.encode(JSON.stringify(cells)).length;
        if (size > MAX_ROW) fail('row_too_large');
        if (rows.length && (bytes + size > MAX_PAGE || rows.length >= 4096)) { more = true; break pageRows; }
        rows.push(cells); bytes += size; last = Number(row._rowid);
        if (!Number.isSafeInteger(last)) fail('cursor_out_of_range');
      }
      if (batch.length < 8) break;
    }
    const page = { table: input.table, columns, rows, nextRowId: more ? last : null };
    return { ...page, digest: backupPageDigest(page) };
  }
  restoreBegin(input: { backupId: string; manifest: BackupManifest }): RestoreStatus {
    this.requireHold(input.backupId, 'restore');
    const existing = this.restoreStatus();
    if (existing) { if (existing.backupId !== input.backupId || this.getControl<string>('manifestHash') !== backupDigest(input.manifest)) fail('restore_conflict'); return existing; }
    const local = this.describe(), manifest = input.manifest;
    if (manifest.format !== 1 || manifest.kind !== this.kind || manifest.schemaVersion !== local.schemaVersion || manifest.tables.length !== local.tables.length) fail('schema_mismatch');
    for (let i = 0; i < local.tables.length; i++) {
      const expected = local.tables[i], incoming = manifest.tables[i];
      if (incoming.name !== expected.name || backupDigest(incoming.columns) !== backupDigest(expected.columns) || !Number.isSafeInteger(incoming.rowCount) || incoming.rowCount < 0) fail('schema_mismatch');
    }
    if (!local.pristine) fail('target_not_pristine');
    this.storage.transactionSync(() => {
      for (const table of local.tables) this.raw.exec(`CREATE TABLE ${ident('_backup_stage_' + table.name)} AS SELECT * FROM ${ident(table.name)} WHERE 0;`);
      this.raw.exec(`CREATE TABLE _backup_pages (page_index INTEGER PRIMARY KEY, digest TEXT NOT NULL, table_name TEXT NOT NULL, row_count INTEGER NOT NULL);`);
      this.putControl('manifest', manifest); this.putControl('manifestHash', backupDigest(manifest));
      this.putControl('restore', { backupId: input.backupId, state: 'staging' });
    });
    return this.restoreStatus()!;
  }
  restoreStatus(): RestoreStatus | null {
    this.mode('restore'); const status = this.getControl<{ backupId: string; state: 'staging' | 'committed' }>('restore');
    return status ? { ...status, pages: this.count('_backup_pages') } : null;
  }
  restorePage(input: BackupPage & { backupId: string; pageIndex: number }): RestoreStatus {
    this.requireHold(input.backupId, 'restore'); const status = this.restoreStatus();
    if (!status || status.backupId !== input.backupId || status.state !== 'staging') fail('restore_not_staging');
    const manifest = this.getControl<BackupManifest>('manifest')!, table = manifest.tables.find(table => table.name === input.table);
    if (!table || JSON.stringify(input.columns) !== JSON.stringify(table.columns.map(column => column.name))) fail('schema_mismatch');
    if (!Number.isSafeInteger(input.pageIndex) || input.pageIndex < 0 || !Array.isArray(input.rows) || input.rows.length > 4096 || enc.encode(JSON.stringify(input.rows)).length > MAX_ROW) fail('invalid_page');
    if (backupPageDigest(input) !== input.digest) fail('page_digest');
    const old = this.raw.exec(`SELECT digest FROM _backup_pages WHERE page_index=?;`, input.pageIndex).toArray()[0];
    if (old) { if (old.digest !== input.digest) fail('page_conflict'); return status; }
    if (input.pageIndex !== status.pages) fail('page_order');
    this.storage.transactionSync(() => {
      for (const row of input.rows) {
        if (!Array.isArray(row) || row.length !== input.columns.length) fail('invalid_row');
        const cells = row.map(decode);
        this.raw.exec(`INSERT INTO ${ident('_backup_stage_' + table.name)} (${input.columns.map(ident).join(',')}) VALUES (${cells.map(cell => cell.expression).join(',')});`, ...cells.map(cell => cell.value));
      }
      if (this.count('_backup_stage_' + table.name) > table.rowCount) fail('row_count');
      this.raw.exec(`DELETE FROM _backup_control WHERE k='catalogValidated';`);
      this.raw.exec(`INSERT INTO _backup_pages VALUES (?,?,?,?);`, input.pageIndex, input.digest, input.table, input.rows.length);
    });
    return this.restoreStatus()!;
  }
  restoreCommit(input: { backupId: string; pageCount: number; remapStorageToDefault?: boolean }): RestoreStatus {
    this.requireHold(input.backupId, 'restore', true); const status = this.restoreStatus();
    if (!status || status.backupId !== input.backupId || status.pages !== input.pageCount) fail('page_count');
    if (status.state === 'committed') {
      // Older commits could promote rows before the DO wrapper failed to write
      // this marker through guarded SQL. Repair that interrupted generation
      // without resetting a cleanup sweep that has already completed.
      if (this.kind === 'filespace') this.raw.exec(`INSERT OR IGNORE INTO meta(key,value) VALUES ('restore_open_cleanup',1);`);
      return status;
    }
    const manifest = this.getControl<BackupManifest>('manifest')!;
    if (this.getControl<string>('catalogValidated') !== input.backupId) fail('catalog_unvalidated');
    for (const table of manifest.tables) if (this.count('_backup_stage_' + table.name) !== table.rowCount) fail('row_count');
    if (this.kind === 'org' && (!input.remapStorageToDefault || !this.env.S3_ENDPOINT || !this.env.S3_BUCKET)) fail('storage_remap_required');
    if (this.kind === 'filespace') this.verifyObjects({ backupId: input.backupId, expectedCount: this.countObjects() });
    this.storage.transactionSync(() => {
      for (const table of [...TABLES[this.kind], ...OMIT[this.kind]]) this.raw.exec(`DELETE FROM ${ident(table)};`);
      for (const table of manifest.tables) this.raw.exec(`INSERT INTO ${ident(table.name)} SELECT * FROM ${ident('_backup_stage_' + table.name)};`);
      if (this.kind === 'auth') this.raw.exec(`DELETE FROM recovery_codes;`);
      if (this.kind === 'filespace') {
        this.raw.exec(`UPDATE snapshot_schedules SET enabled=0;`);
        this.raw.exec(`DELETE FROM meta WHERE key LIKE 'purge_%' OR key='purging' OR key='snapshot_retry_at' OR key='audit_next_at';`);
        this.raw.exec(`DELETE FROM meta_text WHERE key LIKE 'purge_%';`);
        // Open handles are excluded from backup. Persist bounded tombstone
        // cleanup with promotion; ordinary SQL stays blocked until maintenance
        // ends, and the next ordinary request arms the cleanup alarm.
        this.raw.exec(`INSERT INTO meta(key,value) VALUES ('restore_open_cleanup',1) ON CONFLICT(key) DO UPDATE SET value=1;`);
      }
      if (this.kind === 'org') this.raw.exec(`UPDATE spaces SET bucket_provider='s3',bucket_name=?,storage_endpoint=?,storage_region=?,storage_bucket=?,storage_force_path_style=1,storage_credential_ref=NULL,purge_state=NULL;`, this.env.S3_BUCKET!, this.env.S3_ENDPOINT!, this.env.S3_REGION ?? 'auto', this.env.S3_BUCKET!);
      for (const table of manifest.tables) this.raw.exec(`DROP TABLE ${ident('_backup_stage_' + table.name)};`);
      this.putControl('restore', { backupId: input.backupId, state: 'committed' });
    });
    return this.restoreStatus()!;
  }
  inventory(): unknown {
    this.mode();
    const prefix = this.env.BACKUP_MODE === 'restore' && this.restoreStatus()?.state === 'staging' ? '_backup_stage_' : '';
    if (this.kind === 'directory') return { orgIds: this.raw.exec(`SELECT org_id FROM ${ident(prefix+'org_registry')} UNION SELECT org_id FROM ${ident(prefix+'email_index')} UNION SELECT org_id FROM ${ident(prefix+'webauthn_index')} ${prefix ? '' : 'UNION SELECT org_id FROM setup_claim'} ORDER BY org_id;`).toArray().map(row => String(row.org_id)), legacyDiscoveryComplete: false };
    if (this.kind === 'org') return { spaces: this.raw.exec(`SELECT * FROM ${ident(prefix+'spaces')} ORDER BY id;`).toArray().map(row => ({ id:String(row.id),orgId:String(row.org_id),name:String(row.name),storageEndpoint:row.storage_endpoint,storageRegion:row.storage_region,storageBucket:row.storage_bucket,storageForcePathStyle:row.storage_force_path_style===null?null:Number(row.storage_force_path_style)===1,storageCredentialRef:row.storage_credential_ref,purgeState:row.purge_state,deletedAt:row.deleted_at })) };
    return fail('inventory_unavailable');
  }
  storageConfig(spaceId: string): { space: Record<string, SqlStorageValue>; credential: Record<string, SqlStorageValue> | null } {
    this.mode('export'); if (this.kind !== 'org') fail('wrong_kind');
    const space = this.raw.exec(`SELECT * FROM spaces WHERE id=?;`, spaceId).toArray()[0]; if (!space) fail('space_missing');
    const credential = space.storage_credential_ref ? this.raw.exec(`SELECT * FROM storage_credentials WHERE id=?;`, space.storage_credential_ref).toArray()[0] ?? null : null;
    return { space, credential };
  }
  storageCredential(ref: string): { accessKeyId: string; secretIv: string; secretCiphertext: string } | null {
    this.mode('export'); if (this.kind !== 'org') fail('wrong_kind');
    const row = this.raw.exec(`SELECT access_key_id,secret_iv,secret_ct FROM storage_credentials WHERE id=?;`,ref).toArray()[0];
    return row ? {accessKeyId:String(row.access_key_id),secretIv:String(row.secret_iv),secretCiphertext:String(row.secret_ct)} : null;
  }
  validateCatalog(input: {backupId: string; organizations: string[]; orgId?: string; filespaceIds?: string[]}): void {
    this.requireHold(input.backupId,'restore',true);
    const status=this.restoreStatus(); if (!status) fail('restore_not_staging');
    const prefix=status.state==='staging'?'_backup_stage_':'';
    if(status.state==='staging') {
      for(const table of this.getControl<BackupManifest>('manifest')!.tables) if(this.count(prefix+table.name)!==table.rowCount) fail('row_count');
      if(this.raw.exec(`SELECT id FROM _backup_stage__schema_migrations EXCEPT SELECT id FROM _schema_migrations;`).toArray().length || this.raw.exec(`SELECT id FROM _schema_migrations EXCEPT SELECT id FROM _backup_stage__schema_migrations;`).toArray().length) fail('schema_mismatch');
    }
    const within=(table:string,column:string,allowed:string[])=>{
      const rows=this.raw.exec(`SELECT DISTINCT ${ident(column)} AS id FROM ${ident(prefix+table)};`).toArray();
      if(rows.some(row=>!allowed.includes(String(row.id)))) fail('catalog_mismatch');
    };
    if(this.kind==='directory') for(const table of ['email_index','webauthn_index','org_registry']) within(table,'org_id',input.organizations);
    if(this.kind==='org') {
      if(!input.orgId || !input.organizations.includes(input.orgId) || !Array.isArray(input.filespaceIds)) fail('catalog_mismatch');
      for(const table of ['users','groups','spaces','filespace_keys','email_config']) within(table,'org_id',[input.orgId]);
      const ids=this.raw.exec(`SELECT id FROM ${ident(prefix+'spaces')} ORDER BY id;`).toArray().map(row=>String(row.id));
      if(JSON.stringify(ids)!==JSON.stringify([...input.filespaceIds].sort())) fail('catalog_mismatch');
      // Permanent purge retains sealed keys for recovery/audit. Their org must
      // match, but an unused key does not require or recreate a filespace target.
    }
    if(this.kind==='auth') { if(!input.orgId || !input.organizations.includes(input.orgId)) fail('catalog_mismatch'); within('accounts','org_id',[input.orgId]); }
    this.checkLocalReferences(prefix);
    this.putControl('catalogValidated', input.backupId);
  }
  checkReferences(input:{backupId:string;references:{table:string;match:Record<string,string>}[]}): void {
    this.requireHold(input.backupId,undefined,true);
    if(!Array.isArray(input.references)||input.references.length>128) fail('reference_limit');
    const prefix=this.env.BACKUP_MODE==='restore'&&this.restoreStatus()?.state==='staging'?'_backup_stage_':'';
    for(const ref of input.references) {
      const names=this.columns(ref.table).map(column=>column.name), entries=Object.entries(ref.match??{});
      if(!entries.length||entries.length>16||entries.some(([name,value])=>!names.includes(name)||typeof value!=='string'||value.length>2048)) fail('invalid_reference');
      const row=this.raw.exec(`SELECT 1 FROM ${ident(prefix+ref.table)} WHERE ${entries.map(([name])=>ident(name)+'=?').join(' AND ')} LIMIT 1;`,...entries.map(([,value])=>value)).toArray();
      if(!row.length) fail('reference_missing');
    }
  }
  private checkLocalReferences(prefix:string): void {
    const q=(table:string)=>ident(prefix+table);
    const requireNone=(query:string)=>{if(this.raw.exec(query).toArray().length) fail('local_reference_missing');};
    if(this.kind==='org') {
      requireNone(`SELECT 1 FROM ${q('spaces')} s LEFT JOIN ${q('filespace_keys')} k ON k.space_id=s.id AND k.org_id=s.org_id WHERE s.purge_state IS NULL AND k.space_id IS NULL LIMIT 1;`);
      requireNone(`SELECT 1 FROM ${q('group_members')} m LEFT JOIN ${q('groups')} g ON g.id=m.group_id LEFT JOIN ${q('users')} u ON u.id=m.user_id WHERE g.id IS NULL OR u.id IS NULL LIMIT 1;`);
    }
    if(this.kind==='auth') for(const table of ['passwords','totp','recovery_codes','webauthn_creds']) requireNone(`SELECT 1 FROM ${q(table)} c LEFT JOIN ${q('accounts')} a ON a.id=c.account_id WHERE a.id IS NULL LIMIT 1;`);
    if(this.kind==='filespace') {
      if(!this.raw.exec(`SELECT 1 FROM ${q('items')} WHERE id='root' AND parent IS NULL AND is_dir=1 AND deleted=0;`).toArray().length) fail('root_missing');
      requireNone(`SELECT 1 FROM ${q('items')} i LEFT JOIN ${q('items')} p ON p.id=i.parent WHERE i.id!='root' AND (p.id IS NULL OR p.is_dir!=1 OR i.id=i.parent) LIMIT 1;`);
      requireNone(`SELECT 1 FROM ${q('blocks')} b LEFT JOIN ${q('items')} i ON i.id=b.item_id WHERE i.id IS NULL OR i.is_dir!=0 LIMIT 1;`);
      requireNone(`SELECT 1 FROM ${q('snapshots')} s LEFT JOIN ${q('snapshots')} b ON b.id=s.base_snapshot_id WHERE s.base_snapshot_id IS NOT NULL AND b.id IS NULL LIMIT 1;`);
      requireNone(`SELECT 1 FROM ${q('stream_blocks')} b LEFT JOIN ${q('item_streams')} s ON s.item_id=b.item_id AND s.name=b.name
        LEFT JOIN ${q('items')} i ON i.id=b.item_id WHERE s.storage_kind IS NOT 'blocks' OR i.id IS NULL OR i.deleted!=0 OR b.block_idx<0 OR b.length<1 OR b.length>1048576 OR b.block_idx*1048576+b.length>s.size LIMIT 1;`);
      requireNone(`SELECT 1 FROM ${q('snapshot_stream_blocks')} b LEFT JOIN ${q('snapshot_streams')} s ON s.snapshot_id=b.snapshot_id AND s.item_id=b.item_id AND s.name=b.name
        WHERE s.storage_kind IS NOT 'blocks' OR b.block_idx<0 OR b.length<1 OR b.length>1048576 OR b.block_idx*1048576+b.length>s.size LIMIT 1;`);
      for(const table of ['snapshot_items','snapshot_blocks','snapshot_streams','snapshot_stream_blocks']) requireNone(`SELECT 1 FROM ${q(table)} i LEFT JOIN ${q('snapshots')} s ON s.id=i.snapshot_id WHERE s.id IS NULL LIMIT 1;`);
    }
  }
  coordinatorGet(): unknown { this.mode(); if (this.kind !== 'directory') fail('wrong_kind'); return this.getControl<{backupId:string;state:unknown}>('coordinator')?.state ?? null; }
  coordinatorSet(input: { backupId: string; state: unknown; clear?: boolean; expectedRevision?: number; expectedPreviousBackupId?:string }): void {
    this.mode(); if (this.kind !== 'directory' || !/^[A-Za-z0-9_-]{8,128}$/.test(input.backupId)) fail('invalid_id');
    const current = this.getControl<{ backupId: string; state?: {phase?:string;revision?:number} }>('coordinator');
    if (current && current.backupId !== input.backupId && !['complete','aborted'].includes(current.state?.phase ?? '')) fail('coordinator_conflict');
    if(current && current.backupId!==input.backupId && input.expectedPreviousBackupId!==current.backupId) fail('coordinator_generation');
    const nextState=input.state as {phase?:string;revision?:number};
    const phase=nextState?.phase;
    const priorRevision=current?.backupId===input.backupId ? current.state?.revision ?? 0 : 0;
    if ((input.expectedRevision ?? 0)!==priorRevision || nextState.revision!==priorRevision+1) fail('coordinator_revision');
    if(current?.backupId===input.backupId && current.state?.phase==='releasing' && !['releasing','complete','aborted'].includes(phase??'')) fail('generation_released');
    if(current?.backupId===input.backupId && ['complete','aborted'].includes(current.state?.phase ?? '') && phase!==current.state?.phase) fail('generation_released');
    if (enc.encode(JSON.stringify(input.state)).length > MAX_PAGE) fail('coordinator_too_large');
    if (input.clear) this.raw.exec(`DELETE FROM _backup_control WHERE k='coordinator';`); else this.putControl('coordinator', { backupId: input.backupId, state: input.state });
  }
  objectsPage(input: { backupId: string; cursor?: string }): { entries: { key: string; sha256: string }[]; nextCursor: string | null } {
    this.requireHold(input.backupId, 'export'); if (this.kind !== 'filespace') fail('wrong_kind');
    const rows = this.raw.exec(`SELECT object_key, MIN(block_hash) AS hash, COUNT(DISTINCT block_hash) AS hashes FROM (SELECT object_key,block_hash FROM blocks UNION ALL SELECT object_key,block_hash FROM retained_blocks UNION ALL SELECT object_key,block_hash FROM snapshot_blocks UNION ALL SELECT object_key,block_hash FROM stream_blocks UNION ALL SELECT object_key,block_hash FROM snapshot_stream_blocks) WHERE object_key>? GROUP BY object_key ORDER BY object_key LIMIT 129;`, input.cursor ?? '').toArray();
    if (rows.some(row => Number(row.hashes) !== 1)) fail('object_hash_conflict');
    const more = rows.length > 128, entries = rows.slice(0,128).map(row => ({ key: String(row.object_key), sha256: String(row.hash) }));
    return { entries, nextCursor: more ? entries.at(-1)!.key : null };
  }
  private ensureObjects(): void { this.raw.exec(`CREATE TABLE IF NOT EXISTS _backup_objects (kind TEXT NOT NULL,key TEXT NOT NULL,sha256 TEXT NOT NULL,bytes INTEGER NOT NULL,verified INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(kind,key));`); this.raw.exec(`CREATE TABLE IF NOT EXISTS _backup_object_pages (page_index INTEGER PRIMARY KEY,digest TEXT NOT NULL);`); }
  private countObjects(): number { this.ensureObjects(); return this.count('_backup_objects'); }
  expectObjects(input: { backupId: string; pageIndex: number; entries: BackupObject[] }): void {
    this.requireHold(input.backupId, 'restore'); if (this.kind !== 'filespace') fail('wrong_kind'); this.ensureObjects();
    if (!Number.isSafeInteger(input.pageIndex) || input.pageIndex < 0 || input.entries.length > 128) fail('invalid_page');
    const digest = backupDigest(input.entries), old = this.raw.exec(`SELECT digest FROM _backup_object_pages WHERE page_index=?;`, input.pageIndex).toArray()[0];
    if (old) { if (old.digest !== digest) fail('object_page_conflict'); return; }
    if (input.pageIndex !== this.count('_backup_object_pages')) fail('page_order');
    this.storage.transactionSync(() => {
      for (const item of input.entries) {
        if (!['data','audit'].includes(item.kind) || typeof item.key !== 'string' || !item.key || item.key.length > 2048 || !/^[0-9a-f]{64}$/.test(item.sha256) || !Number.isSafeInteger(item.bytes) || item.bytes < 0) fail('invalid_object');
        const old = this.raw.exec(`SELECT sha256,bytes FROM _backup_objects WHERE kind=? AND key=?;`, item.kind,item.key).toArray()[0];
        if (old && (old.sha256 !== item.sha256 || Number(old.bytes) !== item.bytes)) fail('object_conflict');
        this.raw.exec(`INSERT OR IGNORE INTO _backup_objects(kind,key,sha256,bytes) VALUES (?,?,?,?);`, item.kind,item.key,item.sha256,item.bytes);
      }
      this.raw.exec(`INSERT INTO _backup_object_pages VALUES (?,?);`,input.pageIndex,digest);
    });
  }
  expectedObject(input: { backupId: string; kind: 'data' | 'audit'; key: string }): (BackupObject & { verified: boolean }) | null {
    this.requireHold(input.backupId,'restore'); this.ensureObjects();
    const row = this.raw.exec(`SELECT * FROM _backup_objects WHERE kind=? AND key=?;`,input.kind,input.key).toArray()[0];
    return row ? { kind: String(row.kind) as 'data'|'audit', key: String(row.key),sha256:String(row.sha256),bytes:Number(row.bytes),verified:Number(row.verified)===1 } : null;
  }
  recordObject(input: BackupObject & { backupId: string }): void {
    const expected = this.expectedObject(input); if (!expected || expected.sha256 !== input.sha256 || expected.bytes !== input.bytes) fail('object_mismatch');
    this.raw.exec(`UPDATE _backup_objects SET verified=1 WHERE kind=? AND key=?;`,input.kind,input.key);
  }
  verifyObjects(input: { backupId: string; expectedCount: number }): { verified: number } {
    this.requireHold(input.backupId,'restore',true); if (this.kind !== 'filespace') fail('wrong_kind'); this.ensureObjects();
    if (this.countObjects() !== input.expectedCount || this.raw.exec(`SELECT 1 FROM _backup_objects WHERE verified=0 LIMIT 1;`).toArray().length) fail('objects_unverified');
    const prefix = this.restoreStatus()?.state === 'staging' ? '_backup_stage_' : '';
    const rows = this.raw.exec(`SELECT 1 FROM (SELECT object_key,block_hash FROM ${ident(prefix+'blocks')} UNION ALL SELECT object_key,block_hash FROM ${ident(prefix+'retained_blocks')} UNION ALL SELECT object_key,block_hash FROM ${ident(prefix+'snapshot_blocks')} UNION ALL SELECT object_key,block_hash FROM ${ident(prefix+'stream_blocks')} UNION ALL SELECT object_key,block_hash FROM ${ident(prefix+'snapshot_stream_blocks')}) r LEFT JOIN _backup_objects o ON o.kind='data' AND o.key=r.object_key WHERE o.key IS NULL OR o.sha256!=r.block_hash OR o.verified!=1 LIMIT 1;`).toArray();
    if (rows.length) fail('referenced_object_missing');
    const archived=Number(this.raw.exec(`SELECT value FROM ${ident(prefix+'meta')} WHERE key='archived_through_seq';`).toArray()[0]?.value ?? -1);
    if(archived>=0) {
      const key=this.raw.exec(`SELECT value FROM ${ident(prefix+'meta_text')} WHERE key='filespace_key';`).toArray()[0]?.value;
      if(typeof key!=='string' || !this.raw.exec(`SELECT 1 FROM _backup_objects WHERE kind='audit' AND key=? AND verified=1;`,`audit/${key}/index.json`).toArray().length) fail('audit_index_missing');
    }
    return { verified: input.expectedCount };
  }
}
