// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { packageMacInstaller } from './package-mac-installer.mjs';

test('packages selected installer with content-addressed URL and checksum', () => {
  const root = mkdtempSync(join(tmpdir(), 'cf-installer-'));
  try {
    const source = join(root, 'CloudFS.dmg');
    writeFileSync(source, 'test installer');
    const first = packageMacInstaller(source, join(root, 'dist'), 'https://files.team.test');
    const path = new URL(first.url).pathname;
    assert.equal(new URL(first.url).origin, 'https://files.team.test');
    assert.equal(readFileSync(join(root, 'dist', path), 'utf8'), 'test installer');
    assert.match(readFileSync(join(root, 'dist', path + '.sha256'), 'utf8'), new RegExp(`^${first.sha256}  CloudFS-`));
    writeFileSync(source, 'new installer');
    assert.notEqual(packageMacInstaller(source, join(root, 'dist'), 'https://files.team.test').url, first.url);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('rejects an empty installer, other file types, and oversized assets', () => {
  const root = mkdtempSync(join(tmpdir(), 'cf-installer-'));
  try {
    for (const [name, bytes] of [['empty.dmg', 0], ['script.sh', 10], ['large.dmg', 25 * 1024 * 1024 + 1]]) {
      const source = join(root, name);
      writeFileSync(source, Buffer.alloc(bytes));
      assert.throws(() => packageMacInstaller(source, join(root, 'dist'), 'https://files.team.test'));
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
