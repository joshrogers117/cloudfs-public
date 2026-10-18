#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Check the actual download container, not only an app beside it on disk.
import { lstatSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

try {
  const [input, ...extra] = process.argv.slice(2);
  if (!input || extra.length) throw new Error('Usage: node scripts/check-mac-distribution.mjs /absolute/CloudFS.dmg');
  if (process.platform !== 'darwin') throw new Error('Run Mac distribution verification on macOS before packaging the installer.');
  const path = resolve(input);
  if (!path.endsWith('.dmg') || !lstatSync(path).isFile()) throw new Error('Choose a regular CloudFS .dmg file.');
  for (const [command, args, failure] of [
    ['/usr/bin/codesign', ['--verify', '--verbose=2', path], 'The DMG signature is invalid.'],
    ['/usr/bin/xcrun', ['stapler', 'validate', path], 'The DMG has no valid stapled ticket. Notarize and staple the DMG itself; a notarized app inside it is not this check.'],
    ['/usr/sbin/spctl', ['--assess', '--type', 'open', '--context', 'context:primary-signature', '--verbose=2', path], 'Gatekeeper rejected the download container.'],
  ]) {
    const result = spawnSync(command, args, { stdio: 'inherit' });
    if (result.error || result.status !== 0) throw new Error(failure);
  }
  console.log('Mac download signature, stapled notarization ticket and Gatekeeper assessment passed.');
} catch (error) { console.error(error.message); process.exitCode = 1; }
