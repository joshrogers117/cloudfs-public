// SPDX-License-Identifier: AGPL-3.0-or-later
import { statSync, readFileSync, mkdirSync, copyFileSync, writeFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { createHash } from 'node:crypto';

/** Include an operator-selected Mac installer in the same-origin Worker assets. */
export function packageMacInstaller(source, destination, origin) {
  const path = resolve(source);
  const stat = statSync(path);
  if (!stat.isFile() || !basename(path).toLowerCase().endsWith('.dmg')) throw new Error('CLOUDFS_MAC_INSTALLER must name a built .dmg installer.');
  if (stat.size === 0 || stat.size > 25 * 1024 * 1024) throw new Error('The Mac installer must be nonempty and at most 25 MiB for Workers static assets.');
  const sha256 = createHash('sha256').update(readFileSync(path)).digest('hex');
  const filename = `CloudFS-${sha256.slice(0, 16)}.dmg`;
  const directory = resolve(destination, 'downloads');
  mkdirSync(directory, { recursive: true });
  copyFileSync(path, resolve(directory, filename));
  writeFileSync(resolve(directory, `${filename}.sha256`), `${sha256}  ${filename}\n`);
  return { url: new URL(`/downloads/${filename}`, origin).href, sha256, bytes: stat.size };
}
