#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import { readdirSync, lstatSync, readFileSync, mkdirSync, copyFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { isReleaseFile, assertReleaseSourceCoverage } from './release-files.mjs';
import { generateRuntimeDependencyNotices } from './release-notices.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
try {
  const args = process.argv.slice(2), options = {};
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node scripts/package-server-release.mjs --version VERSION [--mac-installer /absolute/CloudFS.dmg]\nWrites an unpublished server source/setup archive, per-file manifest and SHA-256 checksum in dist/releases.\nReview docs/PUBLISHING.md before distribution. This does not certify or publish a release.');
    process.exit(0);
  }
  for (let i = 0; i < args.length; i += 2) {
    if (!['--version', '--mac-installer'].includes(args[i]) || !args[i + 1] || options[args[i]]) throw new Error('Use --version VERSION and optional --mac-installer PATH.');
    options[args[i]] = args[i + 1];
  }
  const version = options['--version'];
  if (!/^\d+\.\d+\.\d+(?:-[a-z0-9]+(?:\.[a-z0-9]+)*)?$/.test(version || '')) throw new Error('Use a release version such as 0.1.36-preview.1.');
  const output = resolve(root, 'dist/releases'), name = `CloudFS-Server-${version}`;
  const staging = resolve(output, name), archive = `${staging}.tar.gz`;
  if (existsSync(staging) || existsSync(archive)) throw new Error('That release already exists. Choose a new version; artifacts are never overwritten.');
  const installer = options['--mac-installer'] ? resolve(options['--mac-installer']) : null;
  if (installer && (!installer.endsWith('.dmg') || !lstatSync(installer).isFile())) throw new Error('The Mac installer must be a regular .dmg file.');
  if (installer) {
    const check = spawnSync(process.execPath, [resolve(root, 'scripts/check-mac-distribution.mjs'), installer], { stdio: 'inherit' });
    if (check.error || check.status !== 0) throw new Error('Mac distribution verification failed. No candidate was created. Notarize the download container before bundling it.');
  }
  mkdirSync(staging, { recursive: true });
  const files = [];
  const hash = data => createHash('sha256').update(data).digest('hex');
  function copy(source, path) {
    const target = resolve(staging, path);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(source, target);
    const data = readFileSync(target);
    files.push({ path, bytes: data.length, sha256: hash(data) });
  }
  function visit(directory) {
    for (const item of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const source = resolve(directory, item.name), path = relative(root, source);
      if (item.isSymbolicLink()) {
        if (isReleaseFile(path)) throw new Error(`Refusing a symlink in release source: ${path}`);
        continue;
      }
      if (item.isDirectory()) {
        if (!item.name.startsWith('.') && !/\.(app|xcodeproj|xcarchive)$/.test(item.name) && !['node_modules', 'dist', 'build', 'research', 'experiments', 'OVERNIGHT', 'validation'].includes(item.name)) visit(source);
      } else {
        assertReleaseSourceCoverage([path]);
        if (isReleaseFile(path)) copy(source, path);
      }
    }
  }
  // Never traverse unrelated project folders, local profiles or historical evidence.
  for (const path of ['backend', 'web', 'scripts', 'client-app', 'cloudfsd', 'cli', 'site', 'docs']) visit(resolve(root, path));
  for (const path of ['INSTALL.md', 'CONTRIBUTING.md', 'LICENSE', 'NOTICE', 'SECURITY.md']) copy(resolve(root, path), path);
  // The repository overview is separate from the customer installation entry point.
  // Start release readers on the complete, customer-facing installation guide.
  copy(resolve(root, 'INSTALL.md'), 'README.md');
  const notices = generateRuntimeDependencyNotices(root);
  writeFileSync(resolve(staging, 'THIRD-PARTY-NOTICES.txt'), notices, { flag: 'wx' });
  files.push({ path: 'THIRD-PARTY-NOTICES.txt', bytes: Buffer.byteLength(notices), sha256: hash(notices) });
  if (installer) copy(installer, 'macos/CloudFS.dmg');

  // The allowlist includes the checker so it can validate the exact staged
  // Markdown from the candidate root without relying on Git metadata.
  const stagedChecker = resolve(staging, 'scripts/check-docs.mjs');
  const docsCheck = spawnSync(process.execPath, [stagedChecker], { cwd: staging, stdio: 'inherit' });
  if (docsCheck.error || docsCheck.status !== 0) throw new Error('Packaged Markdown link validation failed. Fix the documented paths before creating a release candidate.');

  const git = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' });
  const status = spawnSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' });
  const manifest = { version, createdAt: new Date().toISOString(), status: 'unpublished-candidate',
    nodeMinimum: '22.12.0', sourceBaseCommit: git.status === 0 ? git.stdout.trim() : null,
    sourceContainsUncommittedChanges: status.status === 0 ? !!status.stdout.trim() : null,
    macInstallerIncluded: !!installer, signingAndNotarizationVerifiedByPackager: !!installer,
    files: files.sort((a, b) => a.path.localeCompare(b.path)) };
  writeFileSync(resolve(staging, 'release-manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  const tar = spawnSync('/usr/bin/tar', ['-czf', archive, '-C', output, name], { env: { ...process.env, COPYFILE_DISABLE: '1' }, stdio: 'inherit' });
  if (tar.status !== 0) throw new Error('Archive creation failed. Inspect the staged candidate; no release was published.');
  writeFileSync(`${archive}.sha256`, `${hash(readFileSync(archive))}  ${name}.tar.gz\n`, { flag: 'wx' });
  console.log(`Prepared ${archive}\n${files.length} allowlisted files. Local credentials, validation evidence and build directories excluded.\nCandidate only: complete docs/PUBLISHING.md before sharing.`);
} catch (error) { console.error(error.message); process.exitCode = 1; }
