// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { generateSealedMasterKey } from '../src/filespace-keys';
import { BackupState, type BackupPage, type BackupEnv } from '../src/backup-state';
import { NamespaceStore } from '../src/metadata/namespace';
import { OpenHandleStore, OPEN_HANDLE_READ } from '../src/metadata/open-handles';
import type { FilespaceDO } from '../src/filespace-do';
const e=env as Env, id='backup-fixture-123';
function pages(b:BackupState) {const manifest=b.describe(),pages:BackupPage[]=[];for(const t of manifest.tables){let afterRowId:number|undefined;do{const p=b.exportPage({backupId:id,table:t.name,afterRowId});pages.push(p);afterRowId=p.nextRowId??undefined;}while(afterRowId!==undefined);}return{manifest,pages};}
const target=()=>e.ORG_DO.getByName(crypto.randomUUID());

describe('maintenance SQLite backup',()=>{
 it('round trips int64, null and BLOBs exactly through private staging and atomic promotion',async()=>{
  const archive=await runInDurableObject(target(),(_i,s)=>{
   s.storage.sql.exec(`INSERT INTO email_config(k,org_id,provider,from_address,secret_iv,secret_ct,created_at,updated_at) VALUES ('email','org','ses','a@example.test','iv',?,CAST('9223372036854775807' AS INTEGER),0);`,new Uint8Array([0,255,32,65]).buffer);
   const b=new BackupState(s.storage,{BACKUP_MODE:'export'},'org');b.initialize();b.freeze({backupId:id,mode:'export'});return pages(b);
  });
  const p=archive.pages.find(p=>p.table==='email_config')!;
  expect(p.rows[0][p.columns.indexOf('created_at')]).toEqual({type:'integer',value:'9223372036854775807'});
  expect(p.rows[0][p.columns.indexOf('from_name')]).toEqual({type:'null'});
  expect(p.rows[0][p.columns.indexOf('secret_ct')]).toEqual({type:'blob',value:'AP8gQQ=='});
  await runInDurableObject(target(),(_i,s)=>{
   const b=new BackupState(s.storage,{BACKUP_MODE:'restore',S3_ENDPOINT:'https://fresh.invalid',S3_BUCKET:'fresh'},'org');b.initialize();b.freeze({backupId:id,mode:'restore'});b.restoreBegin({backupId:id,manifest:archive.manifest});
   archive.pages.forEach((p,pageIndex)=>b.restorePage({...p,pageIndex,backupId:id}));
   expect(s.storage.sql.exec('SELECT * FROM email_config;').toArray()).toEqual([]);
   expect(()=>b.restoreCommit({backupId:id,pageCount:archive.pages.length,remapStorageToDefault:true})).toThrow('catalog_unvalidated');
   b.validateCatalog({backupId:id,organizations:['org'],orgId:'org',filespaceIds:[]});
   expect(b.restoreCommit({backupId:id,pageCount:archive.pages.length,remapStorageToDefault:true}).state).toBe('committed');
   const row=s.storage.sql.exec(`SELECT CAST(created_at AS TEXT) AS exact,secret_ct,from_name FROM email_config;`).one();
   expect(row.exact).toBe('9223372036854775807');expect(row.from_name).toBeNull();expect(new Uint8Array(row.secret_ct as ArrayBuffer)).toEqual(new Uint8Array([0,255,32,65]));
  });
 });
 it('archives recovery-code state but retires codes and bearer sessions on restore; holds survive restart',async()=>{
  const archive=await runInDurableObject(e.AUTH_DO.getByName(crypto.randomUUID()),(_i,s)=>{
   s.storage.sql.exec(`INSERT INTO accounts(id,user_id,org_id,email,display_name,role,status,created_at) VALUES ('acct','u','org','a@example.test','a','owner','active',0);`);
   s.storage.sql.exec(`INSERT INTO recovery_codes VALUES ('acct','used',123),('acct','unused',NULL);`);
   const b=new BackupState(s.storage,{BACKUP_MODE:'export'},'auth');b.initialize();b.freeze({backupId:id,mode:'export'});return pages(b);
  });
  expect(archive.manifest.tables.map(t=>t.name)).not.toContain('sessions');expect(archive.manifest.excludedTables).toContain('service_tokens');
  await runInDurableObject(e.AUTH_DO.getByName(crypto.randomUUID()),(_i,s)=>{
   const config:BackupEnv={BACKUP_MODE:'restore'},b=new BackupState(s.storage,config,'auth');b.initialize();b.freeze({backupId:id,mode:'restore'});b.restoreBegin({backupId:id,manifest:archive.manifest});archive.pages.forEach((p,pageIndex)=>b.restorePage({...p,pageIndex,backupId:id}));
   b.validateCatalog({backupId:id,organizations:['org'],orgId:'org'});b.restoreCommit({backupId:id,pageCount:archive.pages.length});
   expect(s.storage.sql.exec(`SELECT * FROM recovery_codes;`).toArray()).toEqual([]);
   delete config.BACKUP_MODE;expect(()=>b.guardedSQL.exec('SELECT 1;')).toThrow('maintenance');
   const cold=new BackupState(s.storage,{},'auth');cold.initialize();expect(()=>cold.guardedSQL.exec('SELECT 1;')).toThrow('maintenance');
   config.BACKUP_MODE='restore';b.release({backupId:id});b.release({backupId:id});expect(()=>b.freeze({backupId:id,mode:'restore'})).toThrow('generation_released');
  });
 });
 it('rejects altered digests, replays exact pages idempotently and prevents omission',async()=>{
  const archive=await runInDurableObject(target(),(_i,s)=>{s.storage.sql.exec(`INSERT INTO org_meta VALUES ('name','original');`);const b=new BackupState(s.storage,{BACKUP_MODE:'export'},'org');b.initialize();b.freeze({backupId:id,mode:'export'});return pages(b);});
  await runInDurableObject(target(),(_i,s)=>{
   const b=new BackupState(s.storage,{BACKUP_MODE:'restore',S3_ENDPOINT:'https://fresh.invalid',S3_BUCKET:'fresh'},'org');b.initialize();b.freeze({backupId:id,mode:'restore'});b.restoreBegin({backupId:id,manifest:archive.manifest});const p=archive.pages[0];
   expect(()=>b.restorePage({...p,digest:'0'.repeat(64),pageIndex:0,backupId:id})).toThrow('page_digest');b.restorePage({...p,pageIndex:0,backupId:id});b.restorePage({...p,pageIndex:0,backupId:id});expect(b.restoreStatus()?.pages).toBe(1);
   expect(()=>b.validateCatalog({backupId:id,organizations:['org'],orgId:'org',filespaceIds:[]})).toThrow('row_count');
   archive.pages.slice(1).forEach((p,i)=>b.restorePage({...p,pageIndex:i+1,backupId:id}));b.validateCatalog({backupId:id,organizations:['org'],orgId:'org',filespaceIds:[]});b.restoreCommit({backupId:id,pageCount:archive.pages.length,remapStorageToDefault:true});expect(s.storage.sql.exec(`SELECT v FROM org_meta WHERE k='name';`).one().v).toBe('original');
  });
 });
 it('refuses arbitrary SQL/schema, populated targets and ordinary-mode backup',async()=>{
  await runInDurableObject(target(),(_i,s)=>{const config:BackupEnv={},b=new BackupState(s.storage,config,'org');b.initialize();expect(()=>b.describe()).toThrow('mode_required');config.BACKUP_MODE='export';b.freeze({backupId:id,mode:'export'});expect(()=>b.exportPage({backupId:id,table:'spaces; DROP TABLE users'})).toThrow('table_not_allowed');const m=b.describe();b.release({backupId:id});config.BACKUP_MODE='restore';b.freeze({backupId:'next-generation',mode:'restore'});const wrong=structuredClone(m);wrong.tables[0].columns[0].name='arbitrary';expect(()=>b.restoreBegin({backupId:'next-generation',manifest:wrong})).toThrow('schema_mismatch');s.storage.sql.exec(`INSERT INTO org_meta VALUES ('name','used');`);expect(()=>b.restoreBegin({backupId:'next-generation',manifest:m})).toThrow('target_not_pristine');});
 });
 it('blocks real application SQL after an await and keeps alarms stopped after premature mode exit',async()=>{
  await runInDurableObject(e.AUTH_DO.getByName(crypto.randomUUID()),async(i,s)=>{const b=Object.getOwnPropertyDescriptor(i,'backupState')!.value as BackupState,config=(b as unknown as{env:BackupEnv}).env,prior=config.BACKUP_MODE;try{config.BACKUP_MODE='export';await i.backupFreeze({backupId:id,mode:'export'});await Promise.resolve();delete config.BACKUP_MODE;expect(()=>i.readiness()).toThrow('maintenance');await i.alarm();expect(await s.storage.getAlarm()).toBeNull();config.BACKUP_MODE='export';i.backupRelease({backupId:id});}finally{config.BACKUP_MODE=prior;}});
 });
 it('includes rowid zero and enforces referenced object receipts even with declared count zero',async()=>{
  await runInDurableObject(e.FILESPACE.getByName(crypto.randomUUID()),(_i,s)=>{
   s.storage.sql.exec(`UPDATE meta SET value=0 WHERE key='seq';`); // integer value fixture; audit seq itself aliases rowid zero
   s.storage.sql.exec(`INSERT INTO audit(seq,ts,actor_sub,org_id,space_id,action,decision,json,prev_hash,hash) VALUES (0,0,'a','org','space','x','allow','{}',?,?);`,'0'.repeat(64),'1'.repeat(64));
   const b=new BackupState(s.storage,{BACKUP_MODE:'export'},'filespace');b.initialize();b.freeze({backupId:id,mode:'export'});const p=b.exportPage({backupId:id,table:'audit'});expect(p.rows).toHaveLength(1);expect(p.rows[0][p.columns.indexOf('seq')]).toEqual({type:'integer',value:'0'});
  });
  await runInDurableObject(e.FILESPACE.getByName(crypto.randomUUID()),(_i,s)=>{
   s.storage.sql.exec(`DELETE FROM items WHERE id!='root';`);s.storage.sql.exec(`UPDATE items SET version=1,created_seq=1,updated_seq=1 WHERE id='root'; UPDATE meta SET value=1 WHERE key='seq';`);const config:BackupEnv={BACKUP_MODE:'export'},b=new BackupState(s.storage,config,'filespace');b.initialize();b.freeze({backupId:id,mode:'export'});const a=pages(b);b.release({backupId:id});config.BACKUP_MODE='restore';const restoreId='new-restoration';b.freeze({backupId:restoreId,mode:'restore'});b.restoreBegin({backupId:restoreId,manifest:a.manifest});a.pages.forEach((p,pageIndex)=>b.restorePage({...p,pageIndex,backupId:restoreId}));s.storage.sql.exec(`INSERT INTO _backup_stage_blocks VALUES ('file',0,0,?,'blocks/org::space/old',0,1);`,'a'.repeat(64));expect(()=>b.verifyObjects({backupId:restoreId,expectedCount:0})).toThrow('referenced_object_missing');b.expectObjects({backupId:restoreId,pageIndex:0,entries:[{kind:'data',key:'blocks/org::space/old',sha256:'a'.repeat(64),bytes:70}]});expect(()=>b.verifyObjects({backupId:restoreId,expectedCount:1})).toThrow('objects_unverified');expect(()=>b.recordObject({backupId:restoreId,kind:'data',key:'blocks/org::space/old',sha256:'b'.repeat(64),bytes:70})).toThrow('object_mismatch');b.recordObject({backupId:restoreId,kind:'data',key:'blocks/org::space/old',sha256:'a'.repeat(64),bytes:70});expect(b.verifyObjects({backupId:restoreId,expectedCount:1})).toEqual({verified:1});
  });
 });
 it('uses coordinator revision CAS and permanent generation tombstones',async()=>{
  await runInDurableObject(e.DIRECTORY_DO.getByName(crypto.randomUUID()),(_i,s)=>{const b=new BackupState(s.storage,{BACKUP_MODE:'export'},'directory');b.initialize();b.release({backupId:'never-frozen-export'});expect(()=>b.freeze({backupId:'never-frozen-export',mode:'export'})).toThrow('generation_released');b.freeze({backupId:id,mode:'export'});b.release({backupId:id});b.freeze({backupId:'newer-generation',mode:'export'});b.release({backupId:id});expect(()=>b.freeze({backupId:'unrelated-generation',mode:'export'})).toThrow('already_frozen');b.release({backupId:'newer-generation'});expect(()=>b.freeze({backupId:id,mode:'export'})).toThrow('generation_released');b.coordinatorSet({backupId:id,state:{backupId:id,revision:1,phase:'freezing'}});b.coordinatorSet({backupId:id,expectedRevision:1,state:{backupId:id,revision:2,phase:'releasing'}});expect(()=>b.coordinatorSet({backupId:id,expectedRevision:1,state:{backupId:id,revision:2,phase:'exporting'}})).toThrow('coordinator_revision');expect(()=>b.coordinatorSet({backupId:id,expectedRevision:2,state:{backupId:id,revision:3,phase:'exporting'}})).toThrow('generation_released');expect(b.coordinatorGet()).toEqual({backupId:id,revision:2,phase:'releasing'});});
 });
 it('bounds deterministic pages and preserves every row at page boundaries',async()=>{
  await runInDurableObject(target(),(_i,s)=>{
   for(let n=0;n<24;n++) s.storage.sql.exec(`INSERT INTO org_meta VALUES (?,?);`,`row-${n}`,String(n).padStart(2,'0')+'x'.repeat(65536));
   const b=new BackupState(s.storage,{BACKUP_MODE:'export'},'org');b.initialize();b.freeze({backupId:id,mode:'export'});
   const first=b.exportPage({backupId:id,table:'org_meta'});expect(first.nextRowId).not.toBeNull();expect(first).toEqual(b.exportPage({backupId:id,table:'org_meta'}));
   expect(new TextEncoder().encode(JSON.stringify(first.rows)).length).toBeLessThanOrEqual(1024*1024);
   const second=b.exportPage({backupId:id,table:'org_meta',afterRowId:first.nextRowId!});expect(second.nextRowId).toBeNull();
   expect([...first.rows,...second.rows]).toHaveLength(24);expect(new Set([...first.rows,...second.rows].map(row=>JSON.stringify(row[0]))).size).toBe(24);
  });
 });
 it('fully closes bounded catalog queries before promoting staged tables',async()=>{
  const archive=await runInDurableObject(target(),(_i,s)=>{
   for(let n=0;n<24;n++) s.storage.sql.exec(`INSERT INTO org_meta VALUES (?,?);`,`row-${n}`,'x'.repeat(65536));
   const b=new BackupState(s.storage,{BACKUP_MODE:'export'},'org');b.initialize();b.freeze({backupId:id,mode:'export'});return pages(b);
  });
  await runInDurableObject(target(),(_i,s)=>{
   const b=new BackupState(s.storage,{BACKUP_MODE:'restore',S3_ENDPOINT:'https://fresh.invalid',S3_BUCKET:'fresh'},'org');b.initialize();b.freeze({backupId:id,mode:'restore'});b.restoreBegin({backupId:id,manifest:archive.manifest});
   archive.pages.forEach((p,pageIndex)=>b.restorePage({...p,pageIndex,backupId:id}));
   // Audit validation reads staged catalog pages before promotion. Stopping a
   // live SQLite cursor at the page budget leaves DROP TABLE locked until GC.
   const page=b.catalogPage({backupId:id,table:'org_meta'});expect(page.nextRowId).not.toBeNull();
   b.validateCatalog({backupId:id,organizations:['org'],orgId:'org',filespaceIds:[]});
   expect(b.restoreCommit({backupId:id,pageCount:archive.pages.length,remapStorageToDefault:true}).state).toBe('committed');
   expect(s.storage.sql.exec(`SELECT COUNT(*) AS n FROM org_meta;`).one().n).toBe(24);
  });
 });
 it('rolls back every promoted table on a late constraint failure and preserves staging for repair',async()=>{
  const archive=await runInDurableObject(target(),(_i,s)=>{s.storage.sql.exec(`INSERT INTO org_meta VALUES ('first','1'),('second','2');`);const b=new BackupState(s.storage,{BACKUP_MODE:'export'},'org');b.initialize();b.freeze({backupId:id,mode:'export'});return pages(b);});
  await runInDurableObject(target(),(_i,s)=>{
   const b=new BackupState(s.storage,{BACKUP_MODE:'restore',S3_ENDPOINT:'https://fresh.invalid',S3_BUCKET:'fresh'},'org');b.initialize();b.freeze({backupId:id,mode:'restore'});b.restoreBegin({backupId:id,manifest:archive.manifest});archive.pages.forEach((p,pageIndex)=>b.restorePage({...p,pageIndex,backupId:id}));
   s.storage.sql.exec(`UPDATE _backup_stage_org_meta SET k='collision';`);b.validateCatalog({backupId:id,organizations:['org'],orgId:'org',filespaceIds:[]});
   expect(()=>b.restoreCommit({backupId:id,pageCount:archive.pages.length,remapStorageToDefault:true})).toThrow();
   expect(s.storage.sql.exec('SELECT * FROM org_meta;').toArray()).toEqual([]);expect(s.storage.sql.exec('SELECT * FROM _schema_migrations;').toArray()).toHaveLength(2);expect(b.restoreStatus()?.state).toBe('staging');expect(s.storage.sql.exec('SELECT * FROM _backup_stage_org_meta;').toArray()).toHaveLength(2);
  });
 });

 it('round trips a large binary row exceeding the normal JSON page budget without losing bytes',async()=>{
  const archive=await runInDurableObject(target(),(_i,s)=>{
   const bytes=new Uint8Array(1536*1024+69);for(let n=0;n<bytes.length;n++)bytes[n]=n%251;
   s.storage.sql.exec(`INSERT INTO email_config(k,org_id,provider,from_address,secret_iv,secret_ct,created_at,updated_at) VALUES ('email','org','ses','a@example.test','iv',?,0,0);`,bytes.buffer);
   const b=new BackupState(s.storage,{BACKUP_MODE:'export'},'org');b.initialize();b.freeze({backupId:id,mode:'export'});return pages(b);
  });
  const blob=archive.pages.find(p=>p.table==='email_config')!;expect(blob.rows).toHaveLength(1);expect(JSON.stringify(blob.rows).length).toBeGreaterThan(1024*1024);
  await runInDurableObject(target(),(_i,s)=>{
   const b=new BackupState(s.storage,{BACKUP_MODE:'restore',S3_ENDPOINT:'https://fresh.invalid',S3_BUCKET:'fresh'},'org');b.initialize();b.freeze({backupId:id,mode:'restore'});b.restoreBegin({backupId:id,manifest:archive.manifest});archive.pages.forEach((p,pageIndex)=>b.restorePage({...p,pageIndex,backupId:id}));b.validateCatalog({backupId:id,organizations:['org'],orgId:'org',filespaceIds:[]});b.restoreCommit({backupId:id,pageCount:archive.pages.length,remapStorageToDefault:true});
   const bytes=new Uint8Array(s.storage.sql.exec('SELECT secret_ct FROM email_config;').one().secret_ct as ArrayBuffer);expect(bytes.length).toBe(1536*1024+69);expect(bytes.every((byte,index)=>byte===index%251)).toBe(true);
  });
 });

 it('retains sealed keys of permanently purged spaces without restoring their registry or requiring a filespace target',async()=>{
  const source=target(),sealed=await generateSealedMasterKey(e.STORAGE_ENC_KEY);
  await source.registerSpace({orgId:'org',spaceId:'purged',name:'Purged',bucketProvider:'r2',bucketName:'old',keyPrefix:''});
  const key=await source.putFilespaceKey({orgId:'org',spaceId:'purged',keyId:sealed.keyId,keyIv:sealed.iv,keyCiphertext:sealed.ciphertext});
  expect(await source.hardDeleteSpace('purged')).toEqual({removed:true});expect(await source.getFilespaceKey('purged')).toEqual(key);expect(await source.listSpaces()).toEqual([]);
  const archive=await runInDurableObject(source,(_i,s)=>{const b=new BackupState(s.storage,{BACKUP_MODE:'export'},'org');b.initialize();b.freeze({backupId:id,mode:'export'});return pages(b);});
  expect(archive.manifest.tables.find(t=>t.name==='spaces')?.rowCount).toBe(0);expect(archive.manifest.tables.find(t=>t.name==='filespace_keys')?.rowCount).toBe(1);
  const restored=target();
  await runInDurableObject(restored,(_i,s)=>{
   const b=new BackupState(s.storage,{BACKUP_MODE:'restore',S3_ENDPOINT:'https://fresh.invalid',S3_BUCKET:'fresh'},'org');b.initialize();b.freeze({backupId:id,mode:'restore'});b.restoreBegin({backupId:id,manifest:archive.manifest});archive.pages.forEach((p,pageIndex)=>b.restorePage({...p,pageIndex,backupId:id}));
   s.storage.sql.exec(`UPDATE _backup_stage_filespace_keys SET org_id='other-org';`);expect(()=>b.validateCatalog({backupId:id,organizations:['org'],orgId:'org',filespaceIds:[]})).toThrow('catalog_mismatch');s.storage.sql.exec(`UPDATE _backup_stage_filespace_keys SET org_id='org';`);
   b.validateCatalog({backupId:id,organizations:['org'],orgId:'org',filespaceIds:[]});expect(b.restoreCommit({backupId:id,pageCount:archive.pages.length,remapStorageToDefault:true}).state).toBe('committed');b.release({backupId:id});
  });
  expect(await restored.getFilespaceKey('purged')).toEqual(key);expect(await restored.listSpaces()).toEqual([]);expect(await restored.getSpace('purged')).toBeNull();
 });

 it('omits ephemeral range locks and read permits and never resurrects them on restore',async()=>{
  const archive=await runInDurableObject(e.FILESPACE.getByName(crypto.randomUUID()),(_instance,state)=>{
   const sql=state.storage.sql,ns=new NamespaceStore(sql),handles=new OpenHandleStore(sql);
   const hash='a'.repeat(64),item=ns.put('root','retained-at-backup',false,16,{id:'retained-at-backup'});
   ns.setBlockMap(item.id,[{chunkIdx:0,blockIdx:0,blockHash:hash,objectKey:`blocks/org::space/${hash}`,offset:0,length:16}]);
   const handleId=crypto.randomUUID();
   expect(handles.acquire({handleId,owner:'old-client',inodeId:item.id,accessMask:OPEN_HANDLE_READ,shareMask:7,
    expiresAt:Date.now()+60000}).granted).toBe(true);
   expect(ns.remove(item.id).deleted).toBe(true);
   sql.exec("INSERT INTO locks(path,owner,mode,fence,acquired_at,expires_at) VALUES('root','old-client','exclusive',1,0,?)",Date.now()+60000);
   sql.exec("INSERT INTO range_locks(path,owner,handle,fence,expires_at,ranges) VALUES('root','old-client','old-handle',2,?,?)",Date.now()+60000,JSON.stringify([{offset:'0',length:'1',exclusive:true}]));
   sql.exec("INSERT INTO read_permits(path,owner,handle,fence,expires_at) VALUES('root','reader','read-handle',3,?)",Date.now()+1000);
   sql.exec("INSERT INTO range_waiters(path,expires_at) VALUES('root',?)",Date.now()+1500);
   const backup=new BackupState(state.storage,{BACKUP_MODE:'export'},'filespace');backup.initialize();backup.freeze({backupId:id,mode:'export'});
   const archive=pages(backup);
   for(const name of ['locks','range_locks','read_permits','range_waiters','open_handles']) {
    expect(archive.manifest.excludedTables).toContain(name);
    expect(archive.manifest.tables.map(t=>t.name)).not.toContain(name);
    expect(()=>backup.exportPage({backupId:id,table:name})).toThrow('table_not_allowed');
   }
   return archive;
  });
  await runInDurableObject(e.FILESPACE.getByName(crypto.randomUUID()),async(instance,state)=>{
   // Test-mode FilespaceDO seeds demo directory entries; restore requires a
   // genuinely pristine namespace, as every existing restore test does.
   state.storage.sql.exec("DELETE FROM items WHERE id!='root'");
   state.storage.sql.exec("UPDATE items SET version=1,created_seq=1,updated_seq=1 WHERE id='root'");
   state.storage.sql.exec("UPDATE meta SET value=1 WHERE key='seq'");
   const backup=Object.getOwnPropertyDescriptor(instance,'backupState')!.value as BackupState;
   const config=(backup as unknown as {env:BackupEnv}).env, prior=config.BACKUP_MODE;
   try {
   config.BACKUP_MODE='restore';
   await instance.backupFreeze({backupId:id,mode:'restore'});
   backup.restoreBegin({backupId:id,manifest:archive.manifest});archive.pages.forEach((page,pageIndex)=>backup.restorePage({...page,pageIndex,backupId:id}));
   backup.validateCatalog({backupId:id,organizations:[]});
   const hash='a'.repeat(64),key=`blocks/org::space/${hash}`;
   backup.expectObjects({backupId:id,pageIndex:0,entries:[{kind:'data',key,sha256:hash,bytes:16}]});
   backup.recordObject({backupId:id,kind:'data',key,sha256:hash,bytes:16});
   expect(backup.verifyObjects({backupId:id,expectedCount:1})).toEqual({verified:1});
   expect((await instance.backupRestoreCommit({backupId:id,pageCount:archive.pages.length})).state).toBe('committed');
   expect(Number(state.storage.sql.exec("SELECT value FROM meta WHERE key='restore_open_cleanup'").one().value)).toBe(1);
   expect(()=>backup.guardedSQL.exec('SELECT 1')).toThrow('maintenance');
   expect(await state.storage.getAlarm()).toBeNull();
   // Resume an older interrupted commit that promoted rows before its cleanup
   // marker failed. Retrying the public RPC must repair only the missing marker.
   state.storage.sql.exec("DELETE FROM meta WHERE key='restore_open_cleanup'");
   expect((await instance.backupRestoreCommit({backupId:id,pageCount:archive.pages.length})).state).toBe('committed');
   expect(Number(state.storage.sql.exec("SELECT value FROM meta WHERE key='restore_open_cleanup'").one().value)).toBe(1);
   for(const name of ['locks','range_locks','read_permits','range_waiters','open_handles'])
    expect(Number(state.storage.sql.exec(`SELECT COUNT(*) AS n FROM ${name}`).one().n)).toBe(0);
   expect(Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM blocks WHERE item_id='retained-at-backup'").one().n)).toBe(1);
   // Cleanup waits for both the restore hold and maintenance mode to clear.
   await instance.backupRelease({backupId:id});
   expect(()=>backup.guardedSQL.exec('SELECT 1')).toThrow('maintenance');
   delete config.BACKUP_MODE;
   await (instance as unknown as FilespaceDO).alarm();
   expect(Number(state.storage.sql.exec("SELECT COUNT(*) AS n FROM blocks WHERE item_id='retained-at-backup'").one().n)).toBe(0);
   expect(Number(state.storage.sql.exec('SELECT refcount FROM block_refs WHERE block_hash=?',hash).one().refcount)).toBe(0);
   expect(state.storage.sql.exec("SELECT deleted FROM items WHERE id='retained-at-backup'").one().deleted).toBe(1);
   expect(Number(state.storage.sql.exec("SELECT value FROM meta WHERE key='restore_open_cleanup'").one().value)).toBe(0);
   config.BACKUP_MODE='restore';
   await instance.backupRestoreCommit({backupId:id,pageCount:archive.pages.length});
   expect(Number(state.storage.sql.exec("SELECT value FROM meta WHERE key='restore_open_cleanup'").one().value)).toBe(0);
   } finally { config.BACKUP_MODE=prior; }
  });
 });

});
