// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,rm,unlink,symlink,access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
import {ArchiveWriter,verifyArchive,loadKey,encryptMember,jsonBytes} from './backup/archive.mjs';

const MAGIC=Buffer.from('CFBA001\n'), HEADER=MAGIC.length+12;
async function fixture(t,{commit=true,catalog}={}) {
  const base=await mkdtemp(join(tmpdir(),'cloudfs-archive-review-'));
  t.after(()=>rm(base,{recursive:true,force:true}));
  const directory=join(base,'archive'),keyPath=join(base,'recovery.key');
  const writer=await ArchiveWriter.create(directory,keyPath);
  const secret=await writer.add({kind:'secrets'},[jsonBytes({STORAGE_ENC_KEY:'fixture-secret-stays-encrypted'})]);
  const payload=Buffer.from('independent byte-exact archived payload');
  const object=await writer.add({kind:'object',targetId:'filespace:team::files',objectKind:'audit',key:'audit/team::files/test.ndjson'},[payload]);
  const targetCatalog=catalog??{targets:[{id:'filespace:team::files',expectedObjectCount:1}]};
  const manifest=commit?await writer.commit(targetCatalog):undefined;
  return {base,directory,keyPath,key:await loadKey(keyPath),writer,manifest,secret,object,payload,targetCatalog};
}
async function rewriteManifest(f,mutate) {
  const file=join(f.directory,'manifest.enc'),raw=await readFile(file);
  const decipher=createDecipheriv('aes-256-gcm',f.key,raw.subarray(MAGIC.length,HEADER));
  decipher.setAAD(Buffer.from('cloudfs-backup-manifest-v1'));decipher.setAuthTag(raw.subarray(-16));
  const value=JSON.parse(Buffer.concat([decipher.update(raw.subarray(HEADER,-16)),decipher.final()]));
  await mutate(value);
  const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',f.key,nonce);cipher.setAAD(Buffer.from('cloudfs-backup-manifest-v1'));
  await writeFile(file,Buffer.concat([MAGIC,nonce,cipher.update(jsonBytes(value)),cipher.final(),cipher.getAuthTag()]));
}

test('independent archive completes only after exact payload and secret verification',async t=>{
  const f=await fixture(t),seen=[];
  const verified=await verifyArchive(f.directory,f.key,{onEntry:entry=>seen.push(entry)});
  assert.equal(verified.secrets.STORAGE_ENC_KEY,'fixture-secret-stays-encrypted');assert.equal(seen.length,2);
  assert.equal(verified.manifest.totalBytes,f.secret.bytes+f.payload.length);
  for(const name of ['manifest.enc','index.enc',f.secret.file,f.object.file]){
    assert.equal((await readFile(join(f.directory,name))).includes(Buffer.from('fixture-secret-stays-encrypted')),false);
  }
});

test('wrong recovery key fails authentication before entries are consumed',async t=>{
  const f=await fixture(t);let calls=0;
  await assert.rejects(verifyArchive(f.directory,randomBytes(32),{onEntry:()=>calls++}));assert.equal(calls,0);
});

test('ciphertext mutation is rejected even when encrypted member length is unchanged',async t=>{
  const f=await fixture(t),path=join(f.directory,f.object.file),bytes=await readFile(path);bytes[HEADER+2]^=0x40;await writeFile(path,bytes);
  await assert.rejects(verifyArchive(f.directory,f.key));
});

test('truncated and missing members cannot yield a complete archive',async t=>{
  const f=await fixture(t),path=join(f.directory,f.object.file),bytes=await readFile(path);await writeFile(path,bytes.subarray(0,-1));
  await assert.rejects(verifyArchive(f.directory,f.key),/wrong size/);
  await unlink(path);await assert.rejects(verifyArchive(f.directory,f.key),/ENOENT/);
});

test('a symlink to a byte-identical external member is rejected without following it',async t=>{
  const f=await fixture(t),path=join(f.directory,f.object.file),outside=join(f.base,'outside.enc');
  await writeFile(outside,await readFile(path));await unlink(path);await symlink(outside,path);
  await assert.rejects(verifyArchive(f.directory,f.key));
  assert.equal((await readFile(outside)).length,f.object.archiveBytes);
});

test('authenticated but unsafe indexed paths are rejected before file access',async t=>{
  const f=await fixture(t);
  const forged={...f.secret,file:'../outside.enc'};
  await unlink(join(f.directory,'index.enc'));
  const index=await encryptMember(f.directory,f.key,f.manifest.archiveId,'index.enc',[jsonBytes(forged),Buffer.from('\n')]);
  await rewriteManifest(f,manifest=>{manifest.index={file:'index.enc',...index};manifest.entryCount=1;});
  await assert.rejects(verifyArchive(f.directory,f.key),/Invalid archive entry/);
});

test('duplicate targets in an authenticated manifest fail closed',async t=>{
  const f=await fixture(t);
  await rewriteManifest(f,manifest=>{manifest.targets.push({...manifest.targets[0]});});
  await assert.rejects(verifyArchive(f.directory,f.key),/Duplicate archive targets/);
});

test('failed member validation prevents completion marker publication',async t=>{
  const f=await fixture(t,{commit:false}),path=join(f.directory,f.object.file);
  await unlink(path);await assert.rejects(f.writer.commit(f.targetCatalog));
  await assert.rejects(access(join(f.directory,'manifest.enc')),/ENOENT/);
  await assert.rejects(verifyArchive(f.directory,f.key),/ENOENT/);
});

test('exclusive manifest publication never replaces an existing final marker',async t=>{
  const f=await fixture(t,{commit:false}),sentinel=Buffer.from('existing completion marker');
  await writeFile(join(f.directory,'manifest.enc'),sentinel,{flag:'wx'});
  await assert.rejects(f.writer.commit(f.targetCatalog),/EEXIST/);
  assert.deepEqual(await readFile(join(f.directory,'manifest.enc')),sentinel);
});
