// SPDX-License-Identifier: AGPL-3.0-or-later
import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import { handleBackupRequest } from '../src/backup-api';
import worker from '../src/index';
import type { Env } from '../src/env';
import { backupPageDigest } from '../src/backup-state';

const fingerprint=(value:string)=>[...sha256(new TextEncoder().encode(value))].map(b=>b.toString(16).padStart(2,'0')).join('');
const schema=(kind:string)=>({format:1,kind,schemaVersion:1,tables:[],excludedTables:[],pristine:true});
function fixture(mode:'export'|'restore'='restore') {
  let coordinator:any=null;
  const calls:string[]=[], objects=new Map<string,any>();
  let discovered=['team'];
  const authority=(kind:string,name:string)=>{
    const id=`${kind}:${name}`;
    if(objects.has(id))return objects.get(id);
    const object:any={
      backupDescribe:async()=>schema(kind),
      backupInventory:async()=>kind==='directory'?{orgIds:discovered}:{spaces:[]},
      backupFreeze:async()=>{calls.push(`freeze:${id}`);},
      backupRelease:async()=>{calls.push(`release:${id}`);},
      backupRestoreBegin:async()=>{calls.push(`begin:${id}`);},
      backupRestoreCommit:async()=>{calls.push(`commit:${id}`);},
      backupVerifyObjects:async()=>{calls.push(`objects:${id}`);},
      backupValidateCatalog:async(input:any)=>{
        calls.push(`validate:${id}`);
        const inventory=await object.backupInventory();
        if(kind==='directory' && inventory.orgIds.some((org:string)=>!input.organizations.includes(org))) throw new Error('catalog_directory_mismatch');
        if(kind==='org' && JSON.stringify(inventory.spaces.map((space:any)=>space.id).sort())!==JSON.stringify([...input.filespaceIds].sort())) throw new Error('catalog_filespaces_mismatch');
      },
      backupRestorePage:async(input:any)=>{calls.push(`page:${id}`);return input;},
      backupCatalogPage:async(input:any)=>{const page={table:input.table,columns:[],rows:[],nextRowId:null};return {...page,digest:backupPageDigest(page)};},
      backupCheckReferences:async()=>{},
      backupCoordinatorGet:async()=>structuredClone(coordinator),
      backupCoordinatorSet:async(input:any)=>{
        if(coordinator && coordinator.backupId!==input.backupId && (!['complete','aborted'].includes(coordinator.phase)||input.expectedPreviousBackupId!==coordinator.backupId))throw new Error('coordinator_generation');
        const revision=coordinator?.backupId===input.backupId?coordinator.revision??0:0;
        if((input.expectedRevision??0)!==revision||input.state.revision!==revision+1)throw new Error('coordinator_revision');
        coordinator=structuredClone(input.state);
      },
    };
    objects.set(id,object);return object;
  };
  const namespace=(kind:string)=>({idFromName:(name:string)=>name,get:(name:string)=>authority(kind,name)});
  const e={...env,BACKUP_MODE:mode,STORAGE_ENC_KEY:btoa('K'.repeat(32)),AUTH_SIGNING_SECRET:'new-signing-secret-for-independent-fixture',
    BOOTSTRAP_SECRET:'new-bootstrap-secret-for-independent-fixture',DIRECTORY_DO:namespace('directory'),ORG_DO:namespace('org'),AUTH_DO:namespace('auth'),FILESPACE:namespace('filespace')} as unknown as Env;
  const target=(kind:string,name:string,extra={})=>({id:`${kind}:${name}`,kind,name,schema:schema(kind),...(kind==='directory'?{}:{orgId:'team'}),...extra});
  const targets=[target('directory','global'),target('org','team'),target('auth','team')];
  const body={archiveId:'archive_fixture',scope:'operator-declared-organizations',organizations:['team'],
    encryptionKeyFingerprint:[...sha256(new TextEncoder().encode('K'.repeat(32)))].map(b=>b.toString(16).padStart(2,'0')).join(''),
    signingSecretFingerprint:fingerprint('original-signing'),bootstrapSecretFingerprint:fingerprint('original-bootstrap'),targets};
  const request=async(path:string,data?:unknown,authenticate=true)=>{
    const response=await handleBackupRequest(new Request('https://test/v1/admin/'+path,{method:data===undefined?'GET':'POST',
      headers:{...(authenticate?{'x-bootstrap-secret':e.BOOTSTRAP_SECRET}:{}),'content-type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)}),e);
    if(!response)throw new Error('request missed backup router');
    return {status:response.status,body:await response.json() as any};
  };
  return {e,body,targets,target,authority,calls,request,setDiscovered:(value:string[])=>{discovered=value;},get state(){return coordinator;},setState:(value:any)=>{coordinator=value;}};
}

describe('independent backup API security and resumability review',()=>{
  it('does not reach any backup authority without the operator secret',async()=>{
    const f=fixture();
    expect((await f.request('restore/start',f.body,false)).status).toBe(401);
    expect(f.state).toBeNull();expect(f.calls).toEqual([]);
  });

  it('closes public setup, login, device approval and ordinary file operations in maintenance',async()=>{
    const f=fixture('export');
    for(const path of ['/v1/setup/status','/v1/setup/init','/v1/auth/login','/v1/auth/signup','/v1/auth/device/approve','/v1/filespaces/files/items']){
      const ctx=createExecutionContext();
      const response=await worker.fetch(new Request('https://test'+path,{method:'POST',body:'{}'}),f.e,ctx);
      await waitOnExecutionContext(ctx);
      expect(response.status).toBe(503);expect(await response.json()).toMatchObject({error:'maintenance'});
    }
    expect(f.calls).toEqual([]);
  });

  it('retries incomplete restore freeze/begin before admitting metadata pages',async()=>{
    const f=fixture();let attempts=0;
    f.authority('auth','team').backupRestoreBegin=async()=>{attempts++;if(attempts===1)throw new Error('transient unavailable');};
    expect((await f.request('restore/start',f.body)).status).toBe(409);
    expect(f.state.phase).toBe('freezing');
    const retry=await f.request('restore/start',f.body);
    expect(retry.status).toBe(200);expect(retry.body.phase).toBe('importing');expect(attempts).toBe(2);
  });

  it('rechecks discovered organizations after freezing before advertising a complete export catalog',async()=>{
    const f=fixture('export');
    f.authority('directory','global').backupFreeze=async()=>{f.setDiscovered(['team','late-arrival']);};
    const response=await f.request('backup/start',{organizations:['team'],scope:'operator-declared-organizations'});
    expect(response.status).toBe(409);expect(response.body.error).toBe('known_organization_omitted');
    expect(f.state?.phase).not.toBe('exporting');
  });

  it('does not promote an org whose restored filespace registry names an omitted target',async()=>{
    const f=fixture();
    const started=await f.request('restore/start',f.body);expect(started.status).toBe(200);
    f.authority('org','team').backupInventory=async()=>({spaces:[{id:'omitted-filespace'}]});
    const finished=await f.request(`restore/${started.body.restoreId}/finish`,{targets:f.targets.map(t=>({id:t.id,pageCount:0}))});
    expect(finished.status).toBe(409);expect(f.calls.filter(c=>c.startsWith('release:'))).toEqual([]);expect(f.calls).toContain('validate:org:team');
  });

  it('does not promote Directory claims for an organization absent from the restore graph',async()=>{
    const f=fixture();
    const started=await f.request('restore/start',f.body);expect(started.status).toBe(200);
    f.setDiscovered(['team','foreign']);
    const finished=await f.request(`restore/${started.body.restoreId}/finish`,{targets:f.targets.map(t=>({id:t.id,pageCount:0}))});
    expect(finished.status).toBe(409);expect(f.calls.filter(c=>c.startsWith('release:'))).toEqual([]);
  });

  it('validates every authority before committing a coherent restore and releases Directory last',async()=>{
    const f=fixture();
    const started=await f.request('restore/start',f.body);expect(started.status).toBe(200);
    const finished=await f.request(`restore/${started.body.restoreId}/finish`,{targets:f.targets.map(t=>({id:t.id,pageCount:0}))});
    expect(finished.status).toBe(200);expect(finished.body.complete).toBe(true);
    const firstCommit=f.calls.findIndex(call=>call.startsWith('commit:'));
    expect(f.calls.filter(call=>call.startsWith('validate:'))).toHaveLength(3);
    expect(f.calls.lastIndexOf('validate:auth:team')).toBeLessThan(firstCommit);
    expect(f.calls.filter(call=>call.startsWith('release:')).at(-1)).toBe('release:directory:global');
  });

  it('rejects metadata fields that attempt to replace the server session or page index',async()=>{
    const f=fixture();
    const started=await f.request('restore/start',f.body);expect(started.status).toBe(200);
    const valid={table:'accounts',columns:[],rows:[],nextRowId:null,digest:'a'.repeat(64)};
    for(const extra of [{backupId:'another_archive'}, {pageIndex:999}]){
      const response=await f.request(`restore/${started.body.restoreId}/metadata`,{targetId:'auth:team',pageIndex:0,page:{...valid,...extra}});
      expect(response.status).toBe(400);expect(response.body.error).toBe('invalid_metadata_page_field');
    }
    expect(f.calls).not.toContain('page:auth:team');
    const accepted=await f.request(`restore/${started.body.restoreId}/metadata`,{targetId:'auth:team',pageIndex:0,page:valid});
    expect(accepted.status).toBe(200);expect(accepted.body.backupId).toBe(started.body.restoreId);expect(accepted.body.pageIndex).toBe(0);
  });

  it('retries only release after a transient failure partway through releasing committed authorities',async()=>{
    const f=fixture();let released=false,attempts=0;
    f.authority('org','team').backupRelease=async()=>{released=true;f.calls.push('release:org:team');};
    f.authority('org','team').backupRestoreCommit=async()=>{if(released)throw new Error('already_released');f.calls.push('commit:org:team');};
    f.authority('auth','team').backupRelease=async()=>{if(++attempts===1)throw new Error('transient_release');f.calls.push('release:auth:team');};
    const started=await f.request('restore/start',f.body);expect(started.status).toBe(200);
    const body={targets:f.targets.map(t=>({id:t.id,pageCount:0}))};
    const first=await f.request(`restore/${started.body.restoreId}/finish`,body);
    expect(first.status).toBe(409);expect(f.state.phase).toBe('releasing');expect(released).toBe(true);
    const retry=await f.request(`restore/${started.body.restoreId}/finish`,body);
    expect(retry.status).toBe(200);expect(retry.body.complete).toBe(true);expect(attempts).toBe(2);
    expect(f.calls.filter(call=>call==='commit:org:team')).toHaveLength(1);
  });

  it('does not let an old export continuation resurrect a completed abort',async()=>{
    const f=fixture('export');let announce!:()=>void,release!:()=>void;
    const parked=new Promise<void>(resolve=>{announce=resolve;}),resume=new Promise<void>(resolve=>{release=resolve;});
    f.authority('auth','team').backupDescribe=async()=>{announce();await resume;return schema('auth');};
    const start=f.request('backup/start',{organizations:['team'],scope:'operator-declared-organizations'});
    await parked;const backupId=f.state.backupId;
    const aborted=await f.request(`backup/${backupId}/abort`,{});expect(aborted.status).toBe(200);expect(f.state.phase).toBe('aborted');
    release();expect((await start).status).toBe(409);expect(f.state.phase).toBe('aborted');
  });

  it('returns valid JSON for a successful void object-manifest RPC',async()=>{
    const f=fixture();f.body.targets.push(f.target('filespace','team::files',{filespaceId:'files',expectedObjectCount:1}));
    let received:any;
    f.authority('filespace','team::files').backupExpectObjects=async(input:any)=>{received=input;};
    const started=await f.request('restore/start',f.body);expect(started.status).toBe(200);
    const response=await f.request(`restore/${started.body.restoreId}/objects`,{targetId:'filespace:team::files',pageIndex:0,
      entries:[{kind:'data',key:'blocks/team::files/'+ 'a'.repeat(64),sha256:'a'.repeat(64),bytes:41}]});
    expect(response.status).toBe(200);expect(response.body).toEqual({ok:true});
    expect(received.backupId).toBe(started.body.restoreId);expect(received.entries).toHaveLength(1);
  });

  it('rejects an object key from a different organization before object signing or lookup',async()=>{
    const f=fixture();f.body.targets.push(f.target('filespace','team::files',{filespaceId:'files',expectedObjectCount:1}));
    const started=await f.request('restore/start',f.body);expect(started.status).toBe(200);
    const response=await f.request(`restore/${started.body.restoreId}/object-url`,{targetId:'filespace:team::files',kind:'data',key:'blocks/foreign::files/'+ 'a'.repeat(64)});
    expect(response.status).toBe(400);expect(response.body.error).toBe('backup_object_outside_filespace');
  });
});
