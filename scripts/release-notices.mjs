// SPDX-License-Identifier: AGPL-3.0-or-later
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WORKSPACES = ['backend', 'web', 'cli'];
const LEGAL_FILE_NAME = /^(license|licence|copying|notice)([-_.].*)?$/i;
const LICENSE_FILE_NAME = /^(license|licence|copying)([-_.].*)?$/i;
const compareStrings = (left, right) => left < right ? -1 : left > right ? 1 : 0;

function readJson(path, description) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`Cannot read ${description}: ${error.message}`);
  }
}

function licenseFiles(packageDirectory) {
  return readdirSync(packageDirectory)
    .filter(name => LEGAL_FILE_NAME.test(name) && statSync(join(packageDirectory, name)).isFile())
    .sort(compareStrings);
}

/**
 * Generate third-party notices for the production dependencies in the source
 * build lockfiles. The returned document contains no local source paths.
 */
export function generateRuntimeDependencyNotices(repositoryRoot = REPOSITORY_ROOT) {
  const sections = [
    'CloudFS runtime dependency licenses and notices',
    'Generated from the backend, web, and CLI source build lockfiles.',
    'This document lists installed production dependencies for those source builds.',
    '',
  ];

  for (const workspace of WORKSPACES) {
    const workspaceDirectory = resolve(repositoryRoot, workspace);
    const lockPath = join(workspaceDirectory, 'package-lock.json');
    const lock = readJson(lockPath, `${workspace}/package-lock.json`);
    if (lock.lockfileVersion !== 3 || !lock.packages) {
      throw new Error(`${workspace}/package-lock.json must be an npm lockfile version 3.`);
    }

    const packages = Object.entries(lock.packages)
      .filter(([path, metadata]) => path.startsWith('node_modules/') && metadata.dev !== true)
      .sort(([left], [right]) => compareStrings(left, right));

    sections.push(`=== ${workspace} production dependencies ===`, '');
    for (const [lockPackagePath, locked] of packages) {
      const packageDirectory = resolve(workspaceDirectory, lockPackagePath);
      const installedPackagePath = join(packageDirectory, 'package.json');
      if (!existsSync(installedPackagePath)) {
        throw new Error(`${workspace}: locked runtime package ${lockPackagePath.slice('node_modules/'.length)} is not installed.`);
      }
      const installed = readJson(installedPackagePath, `${workspace} installed package metadata`);
      if (installed.version !== locked.version) {
        throw new Error(`${workspace}: ${installed.name || lockPackagePath.slice('node_modules/'.length)} is installed at ${installed.version}, but the lockfile requires ${locked.version}.`);
      }
      if (!locked.license || typeof locked.license !== 'string') {
        throw new Error(`${workspace}: ${installed.name}@${locked.version} has no license identifier in the lockfile.`);
      }
      if (installed.license && installed.license !== locked.license) {
        throw new Error(`${workspace}: ${installed.name}@${locked.version} license metadata differs from the lockfile (${installed.license} vs ${locked.license}).`);
      }

      const legalFiles = licenseFiles(packageDirectory);
      const licenseNames = legalFiles.filter(name => LICENSE_FILE_NAME.test(name));
      if (licenseNames.length === 0) {
        throw new Error(`${workspace}: ${installed.name}@${locked.version} has no shipped LICENSE/COPYING text.`);
      }

      sections.push(`${installed.name}@${locked.version}`, `License: ${locked.license}`, '');
      for (const name of legalFiles) {
        sections.push(`--- ${name} ---`, readFileSync(join(packageDirectory, name), 'utf8').trimEnd(), '');
      }
    }
  }

  return `${sections.join('\n').trimEnd()}\n`;
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length > 1 || (args.length === 1 && args[0] !== '--help')) {
      throw new Error('Usage: node scripts/release-notices.mjs [--help]');
    }
    if (args[0] === '--help') {
      console.log('Usage: node scripts/release-notices.mjs [--help]\nWrites runtime dependency license and notice text to standard output.');
    } else {
      process.stdout.write(generateRuntimeDependencyNotices());
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
