#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadKey, verifyArchive } from './backup/archive.mjs';
import { loadConfiguration, createBackup, restoreArchive, operatorFailureMessage, operatorStatus, abortSourceBackup } from './backup/protocol.mjs';

export const HELP = `CloudFS encrypted operator backup

  node scripts/backup.mjs create --config PRIVATE.json --archive NEW_DIRECTORY --key-file NEW_KEY.json
  node scripts/backup.mjs verify --archive DIRECTORY --key-file KEY.json
  node scripts/backup.mjs restore --config PRIVATE.json --archive DIRECTORY --key-file KEY.json --prepare-secrets NEW_TARGET_SECRETS.json
  node scripts/backup.mjs restore --config PRIVATE.json --archive DIRECTORY --key-file KEY.json
  node scripts/backup.mjs status --config PRIVATE.json [--mode source|target]
  node scripts/backup.mjs abort --config PRIVATE.json

Private configuration and secret inputs must have mode 0600. Keys, tokens and
passwords are read from files only. Keep the recovery key separately from the
archive; both are required for recovery. create refuses existing paths.

Creation freezes the explicitly declared organizations until export finishes. Restore first
verifies the entire archive, then requires a fresh deployment in maintenance
mode. Prepare secrets before deploying that target. Interrupted restoration is
safe to rerun with the same archive and target. It never overwrites unequal
existing bucket objects. Stop any running source backup before using abort.
Abort releases only the current matching source export; it never cancels a
restore. See docs/BACKUP-RESTORE.md.
`;
export async function main(args=process.argv.slice(2)) {
  const command=args.shift();
  if(!command||command==='help'||command==='--help'){console.log(HELP);return;}
  if(!['create','verify','restore','status','abort'].includes(command))throw new Error('Unknown backup command. Use help.');
  const options={};
  while(args.length){const name=args.shift(),value=args.shift();if(!['--config','--archive','--key-file','--prepare-secrets','--concurrency','--mode'].includes(name)||!value||value.startsWith('--')||options[name])throw new Error('Invalid backup options. Use help.');options[name]=value;}
  if(command==='status'||command==='abort'){
    if(!options['--config']||Object.keys(options).some(key=>!['--config','--mode'].includes(key))
      ||(options['--mode']&&!['source','target'].includes(options['--mode']))||(command==='abort'&&options['--mode']&&options['--mode']!=='source'))throw new Error('Use status --config FILE [--mode source|target] or abort --config FILE.');
    const config=await loadConfiguration(resolve(options['--config']));
    console.log(JSON.stringify(command==='status'?await operatorStatus(config,{target:options['--mode']==='target'}):await abortSourceBackup(config),null,2));return;
  }
  if(options['--mode'])throw new Error('--mode belongs to status.');
  if(!options['--archive']||!options['--key-file'])throw new Error('Both --archive and --key-file paths are required.');
  const directory=resolve(options['--archive']),keyPath=resolve(options['--key-file']);
  const concurrency=options['--concurrency']?Number(options['--concurrency']):4;
  let result;
  if(command==='verify'){
    if(options['--prepare-secrets'])throw new Error('--prepare-secrets belongs to restore.');
    const {manifest}=await verifyArchive(directory,await loadKey(keyPath));
    result={verified:true,archiveId:manifest.archiveId,entries:manifest.entryCount,bytes:manifest.totalBytes};
  }else{
    if(!options['--config'])throw new Error('A private --config file is required.');
    const config=await loadConfiguration(resolve(options['--config']));
    if(command==='create'){
      if(options['--prepare-secrets'])throw new Error('--prepare-secrets belongs to restore.');
      result=await createBackup(config,{directory,keyPath,concurrency});
    }else result=await restoreArchive(config,{directory,key:await loadKey(keyPath),concurrency,prepareSecrets:options['--prepare-secrets']});
  }
  console.log(JSON.stringify(result,null,2));
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  main().catch(error=>{console.error(operatorFailureMessage(error));console.error('No success is implied. Preserve the archive and recovery key; leave an incomplete restore in maintenance mode.');process.exitCode=1;});
}
