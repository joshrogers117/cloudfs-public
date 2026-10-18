// SPDX-License-Identifier: AGPL-3.0-or-later
// Deliberate allowlist: a working checkout is never itself a release artifact.
const top = new Set(['CONTRIBUTING.md', 'INSTALL.md', 'README.md', 'LICENSE', 'NOTICE', 'SECURITY.md']);
const docs = new Set(['SELF-HOSTING.md', 'BACKUP-RESTORE.md', 'PUBLISHING.md', 'BRANDING.md', 'BUILD.md', 'COMPATIBILITY.md', 'SERVER-OPERATIONS.md', 'security.md', 'NAMED-STREAM-STORAGE.md']);
const scripts = new Set(['install-cloudflare.mjs', 'installer-plan.mjs', 'setup-cloudflare.mjs',
  'cloudflare-provision.mjs', 'deployment.mjs', 'deployment-profile.mjs', 'deploy-prod.mjs',
  'deploy-prod.sh', 'deploy-config.mjs', 'verify-deployment.mjs', 'package-mac-installer.mjs',
  'check-brand-assets.mjs', 'check-docs.mjs', 'check-mac-distribution.mjs', 'backup.mjs', 'migrate-legacy-account.mjs']);
const icons = new Set(['brand.svg', 'cloudfs-drive-v2.svg', 'cloudfs-drive-v2.ico', 'cloudfs-drive-v2-32.png', 'cloudfs-drive-v2-180.png', 'favicon.ico']);
export function isReleaseFile(path) {
  if (path.includes('\\') || path.startsWith('/') || path.split('/').some(p => p === '..' || p === '.')) return false;
  if (/(^|\/)(node_modules|dist|build|research|experiments|\.git|\.deployments|\.wrangler|\.build|\.icon-build)(\/|$)/.test(path)) return false;
  if (top.has(path)) return true;
  if (path.startsWith('docs/')) return docs.has(path.slice(5));
  if (path.startsWith('scripts/')) return scripts.has(path.slice(8)) || /^scripts\/backup\/[a-z-]+\.mjs$/.test(path);
  if (/^backend\/(package(?:-lock)?\.json|tsconfig\.json|wrangler\.jsonc|\.prod\.vars\.example)$/.test(path)) return true;
  if (/^backend\/(API|BOOTSTRAP|README|STORAGE-INTEGRITY|HISTORICAL-RECOVERY)\.md$/.test(path)) return true;
  if (/^backend\/src\/(?:[\w-]+\/)*[\w.-]+\.(ts|sql)$/.test(path)) return true;
  if (/^web\/(package(?:-lock)?\.json|tsconfig(?:\.[a-z]+)?\.json|vite\.config\.ts|index\.html)$/.test(path)) return true;
  if (/^web\/src\/(?:[\w-]+\/)*[\w.-]+\.(tsx?|css|svg|png|woff2?)$/.test(path)) return true;
  if (path.startsWith('web/public/')) return icons.has(path.slice(11));
  if (path.startsWith('site/assets/')) return icons.has(path.slice(12));
  if (/^site\/(index\.html|styles\.css|main\.js)$/.test(path)) return true;
  if (/^cloudfsd\/(CONTROL-API|MOUNT|PINNING|RESOURCE-FORKS|DISTRIBUTED-LOCKING|WRITE-JOURNAL-V2)\.md$/.test(path)) return true;
  if (/^(client-app|cloudfsd)\/Package.swift$/.test(path)) return true;
  if (/^(client-app|cloudfsd)\/(Sources|Tests|Resources|Shared|FinderSyncExt|CloudFSApp)\/(?:[\w-]+\/)*[\w.+-]+\.(swift|c|h|modulemap|plist|entitlements|svg|png|icns)$/.test(path)) return true;
  if (/^client-app\/(project-smb.yml|scripts\/(make-app-smb.sh|make-icon.swift|make-release.sh))$/.test(path)) return true;
  if (/^cli\/(package(?:-lock)?\.json|tsconfig\.json)$/.test(path)) return true;
  if (path === 'scripts/benchmark-server.mjs' || path === 'scripts/benchmark-mounted.py') return true;
  return /^cli\/src\/(?:[\w-]+\/)*[\w.-]+\.ts$/.test(path);
}

// Fail closed if the reviewed allowlist omits build inputs. A new filename or
// extension must be explicitly reviewed, rather than silently disappearing from
// corresponding source (for example Swift's common Type+Feature.swift names).
export function assertReleaseSourceCoverage(paths) {
  const missing = paths.filter(path =>
    /^(?:(?:backend|web|cli)\/src\/|(?:client-app|cloudfsd)\/(?:Sources|Tests|Resources|Shared|FinderSyncExt|CloudFSApp)\/)/.test(path)
    && !/\.(?:md)$/.test(path) && !path.split('/').some(part => part.startsWith('.'))
    && !isReleaseFile(path));
  if (missing.length) throw new Error(`Release allowlist omits build inputs; review before packaging:\n${missing.join('\n')}`);
}
