#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, extname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ignoredDirectories = new Set([
  '.git', '.build', '.deployments', 'build', 'dist', 'node_modules',
  'archive', 'archives', 'experiments', 'fuse-spike', 'historical',
  'OVERNIGHT', 'phase0-spike', 'research', 'validation',
]);

function markdownFiles(directory, found = []) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) markdownFiles(resolve(directory, entry.name), found);
    } else if (entry.isFile() && extname(entry.name).toLowerCase() === '.md') {
      found.push(resolve(directory, entry.name));
    }
  }
  return found;
}

function withoutFencedCode(text) {
  const lines = text.split(/\r?\n/);
  let fence = null;
  const visible = lines.map(line => {
    const marker = /^\s{0,3}(`{3,}|~{3,})/.exec(line)?.[1];
    if (fence) {
      if (marker && marker[0] === fence[0] && marker.length >= fence.length) fence = null;
      return '';
    }
    if (marker) {
      fence = marker;
      return '';
    }
    return line;
  });
  return visible.join('\n');
}

function withoutCode(text) {
  return withoutFencedCode(text).replace(/(`+).*?\1/g, match => ' '.repeat(match.length));
}

function headingAnchors(text) {
  const anchors = new Set();
  const counts = new Map();
  const lines = text.split(/\r?\n/);
  const add = raw => {
    const title = raw.replace(/<[^>]*>/g, '').replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/\[([^\]]*)\]\[[^\]]*\]/g, '$1').replace(/`([^`]*)`/g, '$1');
    const base = title.toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, '').trim().replace(/\s/g, '-');
    if (!base) return;
    const count = counts.get(base) ?? 0;
    counts.set(base, count + 1);
    anchors.add(count ? `${base}-${count}` : base);
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const atx = /^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$/.exec(line);
    if (atx) add(atx[1]);
    else if (i + 1 < lines.length && /^\s{0,3}(?:=+|-+)\s*$/.test(lines[i + 1]) && line.trim()) add(line.trim());

    for (const match of line.matchAll(/<(?:a|h[1-6])\b[^>]*\b(?:id|name)=["']([^"']+)["'][^>]*>/gi)) {
      anchors.add(match[1].toLowerCase());
    }
  }
  return anchors;
}

function inlineLinks(text) {
  const links = [];
  const pattern = /!?\[[^\]]*\]\(\s*(<[^>]+>|(?:\\.|[^\s)])+)(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)/g;
  for (const match of text.matchAll(pattern)) {
    let target = match[1];
    if (target.startsWith('<') && target.endsWith('>')) target = target.slice(1, -1);
    target = target.replace(/\\([()\\<>])/g, '$1');
    links.push({ target, offset: match.index });
  }
  return links;
}

const markdown = markdownFiles(root);
const contentByPath = new Map(markdown.map(path => [path, readFileSync(path, 'utf8')]));
const anchorsByPath = new Map(markdown.map(path => [path, headingAnchors(withoutFencedCode(contentByPath.get(path)))]));
const errors = [];

for (const source of markdown) {
  const visible = withoutCode(contentByPath.get(source));
  for (const { target: rawTarget, offset } of inlineLinks(visible)) {
    if (!rawTarget || rawTarget.startsWith('//') || /^[a-z][a-z\d+.-]*:/i.test(rawTarget)) continue;

    const line = visible.slice(0, offset).split('\n').length;
    const hashAt = rawTarget.indexOf('#');
    const queryAt = rawTarget.indexOf('?');
    const pathEnd = [hashAt, queryAt].filter(index => index >= 0).reduce((a, b) => Math.min(a, b), rawTarget.length);
    const rawPath = rawTarget.slice(0, pathEnd);
    const fragment = hashAt < 0 ? '' : rawTarget.slice(hashAt + 1).split('?')[0];
    let pathPart;
    try { pathPart = decodeURIComponent(rawPath); }
    catch { errors.push(`${relative(root, source)}:${line}: malformed link path ${rawPath}`); continue; }

    const target = pathPart ? resolve(dirname(source), pathPart) : source;
    const rel = relative(root, target);
    if (rel === '..' || rel.startsWith(`..${sep}`) || !statExists(target)) {
      errors.push(`${relative(root, source)}:${line}: missing target ${rawTarget}`);
      continue;
    }

    if (!fragment || extname(target).toLowerCase() !== '.md' || !statExists(target) || !statIsFile(target)) continue;
    let decodedFragment;
    try { decodedFragment = decodeURIComponent(fragment).toLowerCase(); }
    catch { decodedFragment = fragment.toLowerCase(); }
    const headings = anchorsByPath.get(target) ?? headingAnchors(withoutFencedCode(readFileSync(target, 'utf8')));
    if (!headings.has(decodedFragment)) errors.push(`${relative(root, source)}:${line}: missing heading #${fragment} in ${relative(root, target)}`);
  }
}

if (errors.length) {
  console.error(`Markdown link check failed (${errors.length} issue${errors.length === 1 ? '' : 's'}):`);
  for (const error of errors) console.error(`  ${error}`);
  process.exitCode = 1;
} else {
  console.log(`Markdown link check passed (${markdown.length} files).`);
}

function statExists(path) {
  try { statSync(path); return true; }
  catch { return false; }
}

function statIsFile(path) {
  try { return statSync(path).isFile(); }
  catch { return false; }
}
