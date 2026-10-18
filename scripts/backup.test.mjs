// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm, stat, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createBackup, restoreArchive, OperatorAPI, operatorFailureMessage, operatorStatus, abortSourceBackup } from './backup/protocol.mjs';
import { main } from './backup.mjs';
import { ArchiveWriter, archiveEntries, verifyArchive, loadKey, exclusiveJson, sha256, jsonBytes, encryptMember } from './backup/archive.mjs';

async function fixture() {
  const directory=await mkdtemp(join(tmpdir(),'cloudfs-backup-tool-'));
  const secrets={STORAGE_ENC_KEY:randomBytes(32).toString('base64'),AUTH_SIGNING_SECRET:'source-auth-'+randomBytes(32).toString('hex'),BOOTSTRAP_SECRET:'source-bootstrap-'+randomBytes(32).toString('hex'),S3_ACCESS_KEY_ID:'private-source-id',S3_SECRET_ACCESS_KEY:'private-source-value',EMAIL_API_KEY:'protected-application-value',SIGNUP_INVITE_TOKENS:'old-deployment-signup-capability'};
  const sourceSecretsFile=join(directory,'source-secrets.json');await exclusiveJson(sourceSecretsFile,secrets);
  const bytes=randomBytes(192*1024), hash=sha256(bytes), audit=Buffer.from('{"protected-audit":"history"}');
  const objects=[{kind:'data',targetId:'fs1',key:`blocks/org::space/${hash}`,bytes:bytes.length,sha256:hash,downloadUrl:'https://source-storage.test/block'},
    {kind:'audit',targetId:'fs1',key:'audit/org::space/index.json',downloadUrl:'https://source.test/audit/download'}];
  const body={table:'items',columns:['id','data'],rows:[[{type:'text',value:'item1'},{type:'blob',value:Buffer.from('stream-bytes').toString('base64')}]],nextRowId:null};
  const page={...body,digest:sha256(jsonBytes(body))};
  const target={id:'fs1',kind:'filespace',name:'org::space',orgId:'org',filespaceId:'space',schema:{format:1,kind:'filespace',schemaVersion:21,pristine:false,tables:[{name:'items',columns:[{name:'id',type:'TEXT',notNull:true,pk:1},{name:'data',type:'BLOB',notNull:false,pk:0}],rowCount:1}],excludedTables:['tokens']}};
  const catalog={backupId:'source-generation',format:1,apiVersion:3,organizations:['org'],discoveredOrganizations:['org'],targets:[target],encryptionKeyFingerprint:sha256(Buffer.from(secrets.STORAGE_ENC_KEY,'base64')),signingSecretFingerprint:sha256(Buffer.from(secrets.AUTH_SIGNING_SECRET)),bootstrapSecretFingerprint:sha256(Buffer.from(secrets.BOOTSTRAP_SECRET))};
  let sourceFinished=0,sourceAborted=0,targetCalls=0,finished=0,failSecond=false;
  const expected=new Map(),stored=new Map(),verified=new Set(),metadata=new Map(),events=[];
  const json=value=>new Response(JSON.stringify(value),{headers:{'content-type':'application/json'}});
  const fetcher=async(input,init={})=>{
    const url=new URL(input),headers=new Headers(init.headers),body=typeof init.body==='string'?JSON.parse(init.body):null;
    if(url.origin==='https://source.test' && url.pathname!=='/audit/download') {
      assert.equal(headers.get('x-bootstrap-secret'),secrets.BOOTSTRAP_SECRET);
      if(url.pathname.endsWith('/backup/start'))return json(catalog);
      if(url.pathname.endsWith('/metadata'))return json(page);
      if(url.pathname.endsWith('/objects'))return json({entries:objects,nextCursor:null});
      if(url.pathname.endsWith('/finish')){sourceFinished++;return json({ok:true});}
      if(url.pathname.endsWith('/abort')){sourceAborted++;return json({ok:true});}
    }
    if(url.origin==='https://source-storage.test'){assert.equal(headers.get('x-bootstrap-secret'),null);return new Response(bytes);}
    if(url.pathname==='/audit/download'){assert.equal(headers.get('x-bootstrap-secret'),secrets.BOOTSTRAP_SECRET);return new Response(audit);}
    targetCalls++;
    if(url.origin==='https://target.test') {
      assert.ok(headers.get('x-bootstrap-secret'));assert.notEqual(headers.get('x-bootstrap-secret'),secrets.BOOTSTRAP_SECRET);
      if(url.pathname.endsWith('/restore/start'))return json({restoreId:'resumable-session'});
      if(url.pathname.endsWith('/objects')){for(const entry of body.entries)expected.set(entry.key,entry);events.push('register');return json({ok:true});}
      if(url.pathname.endsWith('/metadata')){metadata.set(body.pageIndex,body.page);events.push('metadata');return json({ok:true});}
      if(url.pathname.endsWith('/object-url')){assert.ok(expected.has(body.key));return json({url:`https://${body.kind==='data'?'target-storage.test':'target.test'}/upload?key=${encodeURIComponent(body.key)}`,headers:{'if-none-match':'*'},requiresOperatorAuth:body.kind==='audit'});}
      if(url.pathname.endsWith('/object-verify')){const bytes=stored.get(body.key),want=expected.get(body.key);assert.equal(sha256(bytes),want.sha256);assert.equal(bytes.length,want.bytes);verified.add(body.key);return json({verified:true});}
      if(url.pathname.endsWith('/finish')){assert.equal(verified.size,2);assert.equal(metadata.size,1);finished++;return json({complete:true,maintenance:true});}
    }
    if(url.pathname==='/upload'){
      const key=url.searchParams.get('key');assert.ok(expected.has(key));assert.equal(headers.get('if-none-match'),'*');
      if(url.origin==='https://target-storage.test')assert.equal(headers.get('x-bootstrap-secret'),null);
      events.push('upload');
      if(failSecond && key.startsWith('audit/')){failSecond=false;return new Response(null,{status:503});}
      if(stored.has(key))return new Response(null,{status:412});
      const chunks=[];for await(const bytes of init.body)chunks.push(bytes);const data=Buffer.concat(chunks);
      assert.equal(data.length,Number(headers.get('content-length')));stored.set(key,data);return new Response(null,{status:200});
    }
    throw new Error('Unexpected fake endpoint '+url.pathname);
  };
  const config={source:{origin:'https://source.test'},sourceSecretsFile,organizations:['org'],target:{origin:'https://target.test'}};
  return {directory,secrets,bytes,audit,page,config,fetcher,stored,events,counts:()=>({sourceFinished,sourceAborted,targetCalls,finished}),failSecond:()=>{failSecond=true;}};
}

test('encrypted create, independent verify and idempotent interrupted restore preserve all ciphertext and typed metadata',async()=>{
  const f=await fixture();
  try {
    const archive=join(f.directory,'archive'),keyPath=join(f.directory,'recovery.json');
    await createBackup(f.config,{directory:archive,keyPath,fetcher:f.fetcher,concurrency:2});
    assert.equal(f.counts().sourceFinished,1);assert.equal(f.counts().sourceAborted,0);
    assert.equal((await stat(keyPath)).mode&0o777,0o600);
    const key=await loadKey(keyPath),verified=await verifyArchive(archive,key);
    assert.deepEqual(verified.manifest.counts,{secrets:1,metadata:1,object:2});
    assert.equal(verified.secrets.EMAIL_API_KEY,f.secrets.EMAIL_API_KEY);
    for(const name of await readdir(archive))assert.equal((await readFile(join(archive,name))).includes(Buffer.from(f.secrets.STORAGE_ENC_KEY)),false);
    const targetStorageSecretsFile=join(f.directory,'target-storage.json');await exclusiveJson(targetStorageSecretsFile,{S3_ACCESS_KEY_ID:'target-id',S3_SECRET_ACCESS_KEY:'target-secret'});
    const targetSecretsFile=join(f.directory,'target-secrets.json');f.config.targetStorageSecretsFile=targetStorageSecretsFile;
    await restoreArchive(f.config,{directory:archive,key,prepareSecrets:targetSecretsFile,fetcher:()=>{throw new Error('No target contact during preparation');}});
    const fresh=JSON.parse(await readFile(targetSecretsFile,'utf8'));
    assert.equal(fresh.STORAGE_ENC_KEY,f.secrets.STORAGE_ENC_KEY);assert.notEqual(fresh.AUTH_SIGNING_SECRET,f.secrets.AUTH_SIGNING_SECRET);assert.notEqual(fresh.BOOTSTRAP_SECRET,f.secrets.BOOTSTRAP_SECRET);assert.equal(fresh.S3_ACCESS_KEY_ID,'target-id');
    assert.equal(Object.hasOwn(fresh,'SIGNUP_INVITE_TOKENS'),false);assert.equal(fresh.EMAIL_API_KEY,f.secrets.EMAIL_API_KEY);
    f.config.targetSecretsFile=targetSecretsFile;f.failSecond();
    await assert.rejects(restoreArchive(f.config,{directory:archive,key,fetcher:f.fetcher,concurrency:1}));assert.equal(f.counts().finished,0);
    await restoreArchive(f.config,{directory:archive,key,fetcher:f.fetcher,concurrency:2});
    assert.equal(f.counts().finished,1);assert.equal(f.stored.size,2);
    assert.ok([...f.stored.values()].some(bytes=>bytes.equals(f.bytes)));assert.ok([...f.stored.values()].some(bytes=>bytes.equals(f.audit)));
    assert.ok(f.events.indexOf('register')<f.events.indexOf('upload'));
  }finally{await rm(f.directory,{recursive:true,force:true});}
});

test('a corrupted member blocks all target requests and recovery key/target secret creation never overwrites',async()=>{
  const f=await fixture();
  try{
    const archive=join(f.directory,'archive'),keyPath=join(f.directory,'recovery.json');
    await createBackup(f.config,{directory:archive,keyPath,fetcher:f.fetcher});
    const saved=await readFile(keyPath),key=await loadKey(keyPath),{manifest}=await verifyArchive(archive,key);
    await assert.rejects(ArchiveWriter.create(join(f.directory,'another'),keyPath));assert.deepEqual(await readFile(keyPath),saved);
    let object;for await(const entry of archiveEntries(archive,key,manifest))if(entry.kind==='object'){object=entry;break;}
    const data=await readFile(join(archive,object.file));data[30]^=1;await writeFile(join(archive,object.file),data);
    let requests=0;await assert.rejects(restoreArchive(f.config,{directory:archive,key,fetcher:async()=>{requests++;throw new Error('must not run');}}));assert.equal(requests,0);
  }finally{await rm(f.directory,{recursive:true,force:true});}
});

test('parallel streaming member writes publish a stable bounded index and a failed download never commits',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'cloudfs-archive-stream-'));
  try {
    const writer=await ArchiveWriter.create(join(directory,'archive'),join(directory,'key.json'));
    await writer.add({kind:'secrets'},[jsonBytes({protected:'value'})]);
    const chunk=randomBytes(64*1024), digest=(await import('node:crypto')).createHash('sha256');for(let i=0;i<64;i++)digest.update(chunk);const hash=digest.digest('hex');
    async function* blocks(){for(let i=0;i<64;i++)yield chunk;}
    await Promise.all([writer.add({kind:'object',targetId:'fs',objectKind:'data',key:`blocks/test/${hash}`},blocks()),writer.add({kind:'object',targetId:'fs',objectKind:'audit',key:'audit/index'},[Buffer.from('index')])]);
    const manifest=await writer.commit({targets:[{id:'fs',expectedObjectCount:2}]});assert.equal(manifest.entryCount,3);
    const failed=await ArchiveWriter.create(join(directory,'failed'),join(directory,'failed-key.json'));
    async function* broken(){yield Buffer.from('prefix');throw new Error('connection lost');}
    await assert.rejects(failed.add({kind:'secrets'},broken()));await assert.rejects(failed.commit({targets:[]}));await failed.abort();
    assert.equal((await readdir(join(directory,'failed'))).includes('manifest.enc'),false);
  }finally{await rm(directory,{recursive:true,force:true});}
});

test('operator credentials never follow foreign audit URLs or supplied authorization headers',async()=>{
  const api=new OperatorAPI({origin:'https://source.test',bootstrapSecret:'s'.repeat(32)});
  assert.throws(()=>api.headersFor('https://storage.test/object',{},true));
  assert.throws(()=>api.headersFor('https://storage.test/object',{authorization:'Bearer unsafe'}));
  assert.equal(api.headersFor('https://storage.test/object',{'if-none-match':'*'}).has('x-bootstrap-secret'),false);
});

test('restart during promotion or release only finalizes, and a completed restore is not replayed',async()=>{
  const f=await fixture();
  try{
    const archive=join(f.directory,'archive'),keyPath=join(f.directory,'key.json');
    await createBackup(f.config,{directory:archive,keyPath,fetcher:f.fetcher});
    const key=await loadKey(keyPath);
    f.config.targetSecretsFile=join(f.directory,'target-secrets.json');
    await exclusiveJson(f.config.targetSecretsFile,{...f.secrets,AUTH_SIGNING_SECRET:'a'.repeat(64),BOOTSTRAP_SECRET:'b'.repeat(64)});
    for(const phase of ['committing','releasing','complete']){
      const paths=[];
      const result=await restoreArchive(f.config,{directory:archive,key,fetcher:async(input)=>{
        const path=new URL(input).pathname;paths.push(path);
        if(path.endsWith('/start'))return new Response(JSON.stringify({restoreId:'resume-generation',phase}));
        assert.equal(path,'/v1/admin/restore/resume-generation/finish');return new Response(JSON.stringify({complete:true,maintenance:true}));
      }});
      assert.equal(result.result.complete,true);assert.equal(paths.length,phase==='complete'?1:2);
    }
    let requests=0;
    await writeFile(f.config.targetSecretsFile,JSON.stringify(f.secrets));
    await assert.rejects(restoreArchive(f.config,{directory:archive,key,fetcher:async()=>{requests++;throw new Error('must not run');}}));
    assert.equal(requests,0);
  }finally{await rm(f.directory,{recursive:true,force:true});}
});

test('operator failures expose only fixed safe codes and hints, never upstream details or signed URLs',async()=>{
  for(const [body,expected] of [
    [{error:'restore_requires_empty_target',detail:'SECRET_VALUE'},'restore_requires_empty_target'],
    [{error:'https://secret.test/?token=SECRET_VALUE'},'HTTP 409'],
    [{error:'backup_schema_mismatch',url:'https://secret.test/?token=SECRET_VALUE'},'backup_schema_mismatch'],
  ]){
    const api=new OperatorAPI({origin:'https://operator.test',bootstrapSecret:'s'.repeat(32)},{fetcher:async()=>new Response(JSON.stringify(body),{status:409})});
    let message;try{await api.json('/v1/admin/restore/start',{});}catch(error){message=operatorFailureMessage(error);}
    assert.ok(message.includes(expected));assert.equal(message.includes('SECRET_VALUE'),false);assert.equal(message.includes('secret.test'),false);
  }
  assert.equal(operatorFailureMessage(new Error('SECRET_VALUE')).includes('SECRET_VALUE'),false);
});

test('status uses the selected private credential and exposes only bounded maintenance fields',async()=>{
  const f=await fixture();
  try{
    f.config.targetSecretsFile=join(f.directory,'target-secrets.json');
    await exclusiveJson(f.config.targetSecretsFile,{BOOTSTRAP_SECRET:'t'.repeat(64)});
    const before=await readdir(f.directory),saved=await readFile(f.config.sourceSecretsFile);
    for(const target of [false,true]){
      const mode=target?'restore':'export';
      const result=await operatorStatus(f.config,{target,fetcher:async(input,init)=>{
        const url=new URL(input);assert.equal(url.origin,target?'https://target.test':'https://source.test');
        assert.equal(url.pathname,`/v1/admin/${target?'restore':'backup'}/status`);assert.equal(init.method,'GET');
        assert.equal(new Headers(init.headers).get('x-bootstrap-secret'),target?'t'.repeat(64):f.secrets.BOOTSTRAP_SECRET);
        return Response.json({mode,encryptionKeyFingerprint:'SECRET_FINGERPRINT',session:{backupId:'reported-session',mode,phase:target?'importing':'exporting',organizations:['private-org'],targets:[{schema:{rows:['PRIVATE_ROWS']}}],signingSecretFingerprint:'SECRET_FINGERPRINT'}});
      }});
      assert.deepEqual(result,{mode,maintenance:true,session:{id:'reported-session',phase:target?'importing':'exporting',organizationCount:1,targetCount:1,complete:false,aborted:false}});
      assert.equal(JSON.stringify(result).includes('SECRET'),false);assert.equal(JSON.stringify(result).includes('private-org'),false);
    }
    assert.deepEqual(await operatorStatus(f.config,{fetcher:async()=>Response.json({mode:'export',session:null})}),{mode:'export',maintenance:true,session:null});
    for(const bad of [{backupId:'bad/../../id',targets:[]},{backupId:'valid-session',targets:Array(513).fill({})}]){
      await assert.rejects(operatorStatus(f.config,{fetcher:async()=>Response.json({mode:'export',session:{mode:'export',phase:'exporting',organizations:['org'],...bad}})}));
    }
    assert.deepEqual(await readdir(f.directory),before);assert.deepEqual(await readFile(f.config.sourceSecretsFile),saved);
  }finally{await rm(f.directory,{recursive:true,force:true});}
});

test('abort uses only the reported matching source session and is idempotent after termination',async()=>{
  const f=await fixture();
  try{
    f.config.organizations=['org','second'];
    let session={backupId:'server-reported-generation',mode:'export',phase:'exporting',scope:'operator-declared-organizations',organizations:['second','org'],targets:[]};
    const requests=[],before=await readdir(f.directory),saved=await readFile(f.config.sourceSecretsFile);
    const fetcher=async(input,init)=>{
      const path=new URL(input).pathname;requests.push([init.method,path]);
      if(init.method==='GET')return Response.json({mode:'export',session});
      assert.equal(path,'/v1/admin/backup/server-reported-generation/abort');assert.equal(init.body,'{}');
      session={...session,phase:'aborted'};return Response.json({maintenance:true});
    };
    const result=await abortSourceBackup(f.config,{fetcher});assert.equal(result.session.aborted,true);
    assert.deepEqual(requests,[['GET','/v1/admin/backup/status'],['POST','/v1/admin/backup/server-reported-generation/abort'],['GET','/v1/admin/backup/status']]);
    for(const phase of ['aborted','complete',null]){
      session=phase?{...session,phase}:null;requests.length=0;
      assert.equal((await abortSourceBackup(f.config,{fetcher})).alreadyTerminal,true);
      assert.deepEqual(requests,[['GET','/v1/admin/backup/status']]);
    }
    assert.deepEqual(await readdir(f.directory),before);assert.deepEqual(await readFile(f.config.sourceSecretsFile),saved);
  }finally{await rm(f.directory,{recursive:true,force:true});}
});

test('abort refuses restore sessions, changed organization scope and malformed server IDs without mutation',async()=>{
  const f=await fixture();
  try{
    const base={backupId:'reported-session',mode:'export',phase:'exporting',scope:'operator-declared-organizations',organizations:['org'],targets:[]};
    for(const [mode,session] of [
      ['restore',{...base,mode:'restore',phase:'importing'}],['export',{...base,mode:'restore'}],
      ['export',{...base,phase:'committing'}],['export',{...base,organizations:['another']}],
      ['export',{...base,organizations:['org','org']}],['export',{...base,scope:'unknown'}],
      ['export',{...base,backupId:'../../restore/cancel'}],
    ]){
      let requests=0;
      await assert.rejects(abortSourceBackup(f.config,{fetcher:async(input,init)=>{requests++;assert.equal(init.method,'GET');return Response.json({mode,session});}}));
      assert.equal(requests,1);
    }
    await assert.rejects(main(['abort','--config',f.config.sourceSecretsFile,'--mode','target']));
    await assert.rejects(main(['status','--config',f.config.sourceSecretsFile,'--archive','never-created']));
  }finally{await rm(f.directory,{recursive:true,force:true});}
});

test('restore follows bounded validation progress and refuses stalled checkpoints',async()=>{
  const f=await fixture();
  try{
    const archive=join(f.directory,'archive'),keyPath=join(f.directory,'key.json');
    await createBackup(f.config,{directory:archive,keyPath,fetcher:f.fetcher});
    const key=await loadKey(keyPath);f.config.targetSecretsFile=join(f.directory,'target-secrets.json');
    await exclusiveJson(f.config.targetSecretsFile,{...f.secrets,AUTH_SIGNING_SECRET:'a'.repeat(64),BOOTSTRAP_SECRET:'b'.repeat(64)});
    for(const stalled of [false,true]){
      let calls=0;const updates=[];
      const execute=()=>restoreArchive(f.config,{directory:archive,key,progress:p=>updates.push(p),fetcher:async(input)=>{
        if(new URL(input).pathname.endsWith('/start'))return Response.json({restoreId:'bounded-generation',phase:'committing'});
        calls++;return calls<4?Response.json({complete:false,maintenance:true,phase:'validating',revision:stalled?1:calls},{status:202}):Response.json({complete:true,maintenance:true});
      }});
      if(stalled){await assert.rejects(execute());assert.equal(calls,2);}
      else {assert.equal((await execute()).result.complete,true);assert.equal(calls,4);assert.equal(updates.length,3);}
    }
  }finally{await rm(f.directory,{recursive:true,force:true});}
});


test('a delayed archive open cannot lose an unread HTTP body to the Response finalizer',async t=>{
  const base=await mkdtemp(join(tmpdir(),'cloudfs-backup-response-owner-'));t.after(()=>rm(base,{recursive:true,force:true}));
  const payload=randomBytes(1024*1024+69),response=new Response(payload),body=response.body;
  const api=new OperatorAPI({origin:'https://operator.test',bootstrapSecret:'s'.repeat(32)},{fetcher:async()=>response});
  const source=await api.download({kind:'data',downloadUrl:'https://bucket.test/object'});
  // Model Undici's actual Response finalizer at the deterministic open-file gap.
  // A live but unlocked stream gets cancelled to clean EOF, not a thrown error.
  if(!body.locked)await body.cancel('Response object has been garbage collected');
  await new Promise(resolve=>setImmediate(resolve));
  const writer=await ArchiveWriter.create(join(base,'archive'),join(base,'key.json'));
  const entry=await writer.add({kind:'object',targetId:'fs',objectKind:'data',key:'blocks/'+sha256(payload)},source,{expectedSha256:sha256(payload),expectedBytes:payload.length});
  assert.equal(entry.bytes,payload.length);assert.equal(entry.sha256,sha256(payload));assert.equal(body.locked,false);
  await writer.abort();
});

test('archive open failure cancels an acquired download before its first read',async t=>{
  const base=await mkdtemp(join(tmpdir(),'cloudfs-backup-response-cancel-'));t.after(()=>rm(base,{recursive:true,force:true}));
  let cancelled=false;
  const body=new ReadableStream({start(controller){controller.enqueue(new Uint8Array([1,2,3]));},cancel(){cancelled=true;}});
  const api=new OperatorAPI({origin:'https://operator.test',bootstrapSecret:'s'.repeat(32)},{fetcher:async()=>new Response(body)});
  const source=await api.download({kind:'data',downloadUrl:'https://bucket.test/object'});
  await assert.rejects(encryptMember(join(base,'missing'),randomBytes(32),'archive','1-11111111-1111-1111-1111-111111111111.enc',source),/ENOENT/);
  assert.equal(cancelled,true);assert.equal(body.locked,false);
});

test('failed HTTP downloads cancel their body instead of retaining a connection',async()=>{
  let cancelled=false;const body=new ReadableStream({cancel(){cancelled=true;}});
  const api=new OperatorAPI({origin:'https://operator.test',bootstrapSecret:'s'.repeat(32)},{fetcher:async()=>new Response(body,{status:503})});
  await assert.rejects(api.download({kind:'data',downloadUrl:'https://bucket.test/object'}),/HTTP 503/);assert.equal(cancelled,true);
});
