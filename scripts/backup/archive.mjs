// SPDX-License-Identifier: AGPL-3.0-or-later
// Independent, streaming authenticated archives. No plaintext secret temp files.
import { constants } from 'node:fs';
import { open, mkdir, lstat, realpath, link, unlink } from 'node:fs/promises';
import { dirname, resolve, relative, isAbsolute, join } from 'node:path';
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';

const MAGIC = Buffer.from('CFBA001\n'), HEADER = MAGIC.length + 12, TAG = 16;
export const MAX_JSON = 16 * 1024 * 1024, MAX_ENTRY = 5 * 1024 ** 3, MAX_ENTRIES = 10_000_000;
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const jsonBytes = value => Buffer.from(JSON.stringify(value));
const safeName = name => /^(?:[1-9][0-9]{0,7}-[a-f0-9-]{36}|index|manifest(?:-pending-[a-f0-9-]{36})?)\.enc$/.test(name);
const fail = message => { throw new Error(message); };
export function inside(parent, child) { const rel = relative(resolve(parent), resolve(child)); return rel === '' || (!rel.startsWith('..' + '/') && rel !== '..' && !isAbsolute(rel)); }
export async function syncDirectory(path) { const fh = await open(path, constants.O_RDONLY); try { await fh.sync(); } finally { await fh.close(); } }
async function writeAll(fh, bytes) { let offset = 0; while (offset < bytes.length) { const {bytesWritten} = await fh.write(bytes, offset, bytes.length - offset); if (!bytesWritten) fail('Short archive write.'); offset += bytesWritten; } }
export async function privateJson(path, maxBytes = MAX_JSON) {
  const fh = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await fh.stat();
    if (!stat.isFile() || stat.size > maxBytes || (stat.mode & 0o077)) fail('Private input must be a regular file with mode 0600.');
    return JSON.parse(await fh.readFile('utf8'));
  } finally { await fh.close(); }
}
export async function exclusiveJson(path, value) {
  const fh = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await writeAll(fh, Buffer.from(JSON.stringify(value, null, 2) + '\n')); await fh.sync(); }
  finally { await fh.close(); }
  await syncDirectory(dirname(path));
}
export async function loadKey(path) {
  const value = await privateJson(path, 4096);
  if (value.format !== 1 || !/^[a-f0-9]{64}$/.test(value.key ?? '')) fail('Invalid recovery key file.');
  return Buffer.from(value.key, 'hex');
}
async function newEncryptedFile(path, key, aad) {
  const fh = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(aad));
  const plainHash = createHash('sha256'), diskHash = createHash('sha256');
  let bytes = 0, diskBytes = 0, closed = false;
  const diskWrite = async data => { diskHash.update(data); diskBytes += data.length; await writeAll(fh, data); };
  try { await diskWrite(Buffer.concat([MAGIC, nonce])); } catch(error) { await fh.close(); throw error; }
  return {
    async write(data) {
      if (closed) fail('Archive member is already closed.');
      data = Buffer.from(data); bytes += data.length;
      if (!Number.isSafeInteger(bytes) || bytes > MAX_ENTRY) fail('Archive member exceeds the supported size.');
      plainHash.update(data); await diskWrite(cipher.update(data));
    },
    async finish() {
      if (closed) fail('Archive member is already closed.');
      try { await diskWrite(cipher.final()); await diskWrite(cipher.getAuthTag()); await fh.sync();
        return {bytes, sha256:plainHash.digest('hex'), archiveBytes:diskBytes, archiveSha256:diskHash.digest('hex')};
      } finally { closed = true; await fh.close(); }
    },
    async abort() { if (!closed) { closed = true; await fh.close(); } },
  };
}
export async function encryptMember(directory, key, archiveId, name, source) {
  // Own an async source immediately, including the interval before opening the
  // destination. A downloaded response may already hold its read lock; release
  // it if opening/writing the archive fails before iteration begins.
  const iterator = source[Symbol.asyncIterator]?.();
  const owned = iterator ? {[Symbol.asyncIterator]:()=>iterator} : source;
  let writer;
  try {
    if (!safeName(name)) fail('Invalid archive member name.');
    writer = await newEncryptedFile(join(directory, name), key, `${archiveId}:${name}`);
    for await (const bytes of owned) await writer.write(bytes);
    return await writer.finish();
  } catch (error) {
    try { await iterator?.return?.(); } catch { /* retain the original failure */ }
    try { await writer?.abort(); } catch { /* retain the original failure */ }
    throw error;
  }
}
async function* decryptedMember(directory, key, archiveId, descriptor) {
  const {file, bytes, sha256:expectedHash, archiveBytes, archiveSha256} = descriptor;
  if (!safeName(file) || !Number.isSafeInteger(bytes) || bytes < 0 || bytes > MAX_ENTRY
      || archiveBytes !== bytes + HEADER + TAG || !/^[a-f0-9]{64}$/.test(expectedHash) || !/^[a-f0-9]{64}$/.test(archiveSha256)) fail('Invalid archive member descriptor.');
  const fh = await open(join(directory, file), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await fh.stat();
    if (!stat.isFile() || stat.size !== archiveBytes) fail('Archive member is missing or has the wrong size.');
    const header = Buffer.alloc(HEADER), tag = Buffer.alloc(TAG);
    if ((await fh.read(header, 0, HEADER, 0)).bytesRead !== HEADER || !header.subarray(0, MAGIC.length).equals(MAGIC)) fail('Invalid encrypted archive header.');
    if ((await fh.read(tag, 0, TAG, archiveBytes - TAG)).bytesRead !== TAG) fail('Truncated archive tag.');
    const decipher = createDecipheriv('aes-256-gcm', key, header.subarray(MAGIC.length));
    decipher.setAAD(Buffer.from(`${archiveId}:${file}`)); decipher.setAuthTag(tag);
    const digest = createHash('sha256'), diskDigest = createHash('sha256'); diskDigest.update(header);
    let count = 0;
    if (bytes) {
      const stream = fh.createReadStream({start:HEADER, end:archiveBytes - TAG - 1, autoClose:false, highWaterMark:64*1024});
      for await (const chunk of stream) { diskDigest.update(chunk); const plain = decipher.update(chunk); digest.update(plain); count += plain.length; yield plain; }
    }
    const last = decipher.final(); digest.update(last); count += last.length; if (last.length) yield last;
    diskDigest.update(tag);
    if (count !== bytes || digest.digest('hex') !== expectedHash || diskDigest.digest('hex') !== archiveSha256) fail('Archive checksum mismatch.');
  } finally { await fh.close(); }
}
async function readJsonMember(directory, key, archiveId, descriptor) {
  if (descriptor.bytes > MAX_JSON) fail('Archive JSON exceeds its size limit.');
  const chunks = []; for await (const bytes of decryptedMember(directory,key,archiveId,descriptor)) chunks.push(bytes);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
// The manifest has a fixed AAD so the recovery key alone can open it. Its small
// outer frame carries only size/hash, never secret values or object names.
async function readManifest(directory, key, name = 'manifest.enc') {
  if (!safeName(name)) fail('Invalid manifest name.');
  const fh = await open(join(directory,name), constants.O_RDONLY | constants.O_NOFOLLOW);
  let raw;
  try { const stat=await fh.stat(); if (!stat.isFile() || stat.size > MAX_JSON + 64 || stat.size < HEADER+TAG) fail('Invalid manifest size.'); raw=await fh.readFile(); }
  finally { await fh.close(); }
  if (!raw.subarray(0,MAGIC.length).equals(MAGIC)) fail('Invalid manifest header.');
  const decipher=createDecipheriv('aes-256-gcm',key,raw.subarray(MAGIC.length,HEADER));
  decipher.setAAD(Buffer.from('cloudfs-backup-manifest-v1')); decipher.setAuthTag(raw.subarray(-TAG));
  const manifest=JSON.parse(Buffer.concat([decipher.update(raw.subarray(HEADER,-TAG)),decipher.final()]).toString('utf8'));
  if (manifest.format !== 1 || !/^[a-f0-9-]{36}$/.test(manifest.archiveId) || manifest.index?.file !== 'index.enc'
      || !Number.isSafeInteger(manifest.entryCount) || manifest.entryCount < 1 || manifest.entryCount > MAX_ENTRIES
      || !Array.isArray(manifest.targets) || manifest.targets.length > 10_000) fail('Invalid archive manifest.');
  return manifest;
}
export async function* archiveEntries(directory, key, manifest) {
  let tail='', count=0;
  for await (const bytes of decryptedMember(directory,key,manifest.archiveId,manifest.index)) {
    tail += bytes.toString('utf8'); // index is ASCII JSON (escaped by writer below).
    let newline;
    while ((newline=tail.indexOf('\n'))>=0) {
      const line=tail.slice(0,newline); tail=tail.slice(newline+1);
      if (line.length > MAX_JSON || ++count > manifest.entryCount) fail('Invalid archive index.');
      const entry=JSON.parse(line);
      if (entry.sequence!==count || entry.file!==`${count}-${entry.id}.enc` || !/^[a-f0-9-]{36}$/.test(entry.id)
          || !['secrets','metadata','object'].includes(entry.kind)) fail('Invalid archive entry.');
      yield entry;
    }
    if (tail.length > MAX_JSON) fail('Oversized archive index line.');
  }
  if (tail || count!==manifest.entryCount) fail('Truncated archive index.');
}
export async function verifyArchive(directory, key, {manifestName='manifest.enc', onEntry}={}) {
  const manifest=await readManifest(directory,key,manifestName), counts={secrets:0,metadata:0,object:0}, targetCounts=new Map(), metadataCounts=new Map(), rowCounts=new Map();
  const targets=new Set(manifest.targets.map(target=>target.id));
  if (targets.size!==manifest.targets.length) fail('Duplicate archive targets.');
  // The exact filename includes its authenticated monotonic sequence, making
  // duplicate member paths impossible without retaining an unbounded name set.
  let secret, totalBytes=0;
  for await (const entry of archiveEntries(directory,key,manifest)) {
    if (entry.kind!=='secrets' && !targets.has(entry.targetId)) fail('Archive entry has an unknown target.');
    if (entry.kind==='secrets') { if (++counts.secrets!==1) fail('Duplicate secret bundle.'); secret=await readJsonMember(directory,key,manifest.archiveId,entry); }
    else {
      counts[entry.kind]++;
      if (entry.kind==='metadata') {
        const page=await readJsonMember(directory,key,manifest.archiveId,entry);
        if (page.table!==entry.table || !Array.isArray(page.columns) || !Array.isArray(page.rows)
            || sha256(jsonBytes({table:page.table,columns:page.columns,rows:page.rows,nextRowId:page.nextRowId}))!==page.digest) fail('Metadata page digest mismatch.');
        const target=manifest.targets.find(target=>target.id===entry.targetId), table=target.schema?.tables?.find(table=>table.name===entry.table);
        if(!table || JSON.stringify(page.columns)!==JSON.stringify(table.columns.map(column=>column.name))
            || entry.pageIndex!==(metadataCounts.get(entry.targetId)??0)) fail('Metadata page is outside the declared schema or order.');
        metadataCounts.set(entry.targetId,entry.pageIndex+1);
        const identity=JSON.stringify([entry.targetId,entry.table]);
        rowCounts.set(identity,(rowCounts.get(identity)??0)+page.rows.length);
      } else {
        if (!['data','audit'].includes(entry.objectKind) || typeof entry.key!=='string' || !entry.key || Buffer.byteLength(entry.key)>1024) fail('Invalid archived object identity.');
        for await (const _ of decryptedMember(directory,key,manifest.archiveId,entry)) { /* full authenticated validation */ }
        targetCounts.set(entry.targetId,(targetCounts.get(entry.targetId)??0)+1);
        const canonical=entry.key.slice(entry.key.lastIndexOf('/')+1);
        if(entry.objectKind==='data' && /^[a-f0-9]{64}$/.test(canonical) && canonical!==entry.sha256) fail('Content-addressed object checksum mismatch.');
      }
    }
    totalBytes+=entry.bytes; if (!Number.isSafeInteger(totalBytes)) fail('Archive byte count exceeds safe bounds.');
    await onEntry?.(entry);
  }
  if (counts.secrets!==1 || totalBytes!==manifest.totalBytes || JSON.stringify(counts)!==JSON.stringify(manifest.counts)) fail('Archive totals do not match its committed manifest.');
  for(const target of manifest.targets) {
    if((targetCounts.get(target.id)??0)!==target.expectedObjectCount) fail('Archive object inventory count mismatch.');
    if(target.pageCount!==undefined && (metadataCounts.get(target.id)??0)!==target.pageCount) fail('Archive metadata inventory count mismatch.');
    for(const table of target.schema?.tables??[])if((rowCounts.get(JSON.stringify([target.id,table.name]))??0)!==table.rowCount) fail('Archive metadata row count mismatch.');
  }
  return {manifest,secrets:secret};
}
export {decryptedMember,readJsonMember};

export class ArchiveWriter {
  static async create(directory, keyPath) {
    directory=resolve(directory); keyPath=resolve(keyPath);
    const parent=await realpath(dirname(directory)), keyParent=await realpath(dirname(keyPath));
    directory=join(parent,relative(dirname(directory),directory)); keyPath=join(keyParent,relative(dirname(keyPath),keyPath));
    if(inside(directory,keyPath)) fail('Keep the recovery key outside the archive directory.');
    await mkdir(directory,{mode:0o700});
    const key=randomBytes(32), archiveId=randomUUID();
    await exclusiveJson(keyPath,{format:1,key:key.toString('hex')});
    const writer=new ArchiveWriter(directory,key,archiveId);
    writer.index=await newEncryptedFile(join(directory,'index.enc'),key,`${archiveId}:index.enc`);
    return writer;
  }
  constructor(directory,key,archiveId) { Object.assign(this,{directory,key,archiveId,reservedCount:0,entryCount:0,totalBytes:0,counts:{secrets:0,metadata:0,object:0},queue:Promise.resolve()}); }
  async add(info,source,{expectedBytes,expectedSha256}={}) {
    const sequence=++this.reservedCount;
    if(sequence>MAX_ENTRIES) fail('Too many archive entries.');
    const id=randomUUID(), file=`${sequence}-${id}.enc`;
    const encrypted=encryptMember(this.directory,this.key,this.archiveId,file,source).then(value=>({value}),error=>({error}));
    const publish=async()=>{
      const result=await encrypted;
      if(this.failure) throw this.failure;
      if(result.error) throw result.error;
      const integrity=result.value;
      if(expectedBytes!==undefined && integrity.bytes!==expectedBytes) fail('Downloaded object length differs from the source inventory.');
      if(expectedSha256!==undefined && integrity.sha256!==expectedSha256) fail('Downloaded object checksum differs from the source inventory.');
      this.entryCount++;
      const entry={...info,id,file,sequence,...integrity};
      this.counts[info.kind]++; this.totalBytes+=integrity.bytes;
      const line=JSON.stringify(entry).replace(/[\u007f-\uffff]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'))+'\n';
      if(Buffer.byteLength(line)>MAX_JSON) fail('Archive entry metadata is too large.');
      await this.index.write(Buffer.from(line)); return entry;
    };
    const done=this.queue.then(publish); this.queue=done.then(()=>{},error=>{this.failure=error;}); return done;
  }
  async commit(catalog) {
    await this.queue;
    if(this.failure) throw this.failure;
    const index={file:'index.enc',...await this.index.finish()};
    const manifest={...catalog,format:1,archiveId:this.archiveId,index,entryCount:this.entryCount,totalBytes:this.totalBytes,counts:this.counts};
    const encoded=jsonBytes(manifest); if(encoded.length>MAX_JSON) fail('Archive manifest is too large.');
    const pending=`manifest-pending-${randomUUID()}.enc`;
    const writer=await newEncryptedFile(join(this.directory,pending),this.key,'cloudfs-backup-manifest-v1');
    try {await writer.write(encoded); await writer.finish();} catch(error){await writer.abort();throw error;}
    await verifyArchive(this.directory,this.key,{manifestName:pending});
    await syncDirectory(this.directory);
    await link(join(this.directory,pending),join(this.directory,'manifest.enc')); // exclusive, atomic publication
    await syncDirectory(this.directory); await unlink(join(this.directory,pending)); await syncDirectory(this.directory);
    return manifest;
  }
  async abort() { await this.queue.catch(()=>{}); await this.index?.abort(); }
}
