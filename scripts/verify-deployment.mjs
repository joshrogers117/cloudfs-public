// SPDX-License-Identifier: AGPL-3.0-or-later
// HTTP acceptance gate shared by the deploy command and isolated integration tests.
// Match backend/src/api-version.ts and the installer shipped by this release.
const EXPECTED_API_VERSION = 3;
export async function verifyDeployment(origin, bootstrapSecret, { fetcher = fetch, attempts = 4, wait = ms => new Promise(resolve => setTimeout(resolve, ms)), maintenanceMode } = {}) {
  const base = new URL(origin);
  if (base.username || base.password || base.search || base.hash || base.pathname !== '/') throw new Error('Deployment verification requires an origin.');
  let lastFailure;
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      const get = async (path, secret) => {
        const response = await fetcher(new URL(path, base), {
          headers: secret ? { 'x-bootstrap-secret': secret, accept: 'application/json' } : { accept: 'application/json' },
          redirect: 'error', signal: AbortSignal.timeout(30000),
        });
        if (!(response.headers.get('content-type') || '').includes('application/json')) throw new Error(`${path} did not return JSON; check the Worker route and public origin.`);
        const report = await response.json();
        return { response, report };
      };
      if (maintenanceMode) {
        if (!['export', 'restore'].includes(maintenanceMode) || !bootstrapSecret) throw new Error('The deployed gateway maintenance check requires its operator secret and a valid backup mode.');
        const status = await get(`/v1/admin/${maintenanceMode === 'export' ? 'backup' : 'restore'}/status`, bootstrapSecret);
        const closed = await get('/v1/setup/status');
        if (!status.response.ok || status.report.mode !== maintenanceMode || closed.response.status !== 503 || closed.report.error !== 'maintenance') {
          throw new Error('The deployed gateway did not enter the requested backup maintenance mode.');
        }
        return { maintenanceVerified: true, maintenanceMode, readinessVerified: false, warnings: [] };
      }
      const health = await get('/v1/health');
      if (!health.response.ok || health.report.ok !== true || health.report.apiVersion !== EXPECTED_API_VERSION) {
        throw new Error('The deployed gateway did not pass its API health check.');
      }
      if (!bootstrapSecret) return { apiVersion: health.report.apiVersion, readinessVerified: false, warnings: [] };
      const doctor = await get('/v1/admin/doctor', bootstrapSecret);
      const required = ['storage_integrity', 'upload_verification', 'auth_signing_secret', 'storage_enc_key', 'default_storage_backend', 'audit_storage_backend',
        'metadata_directory_do', 'metadata_auth_do', 'metadata_org_do', 'metadata_filespace'];
      const checks = Array.isArray(doctor.report.checks) ? doctor.report.checks : [];
      const failed = required.filter(name => !checks.some(check => check.name === name && check.status === 'ok'));
      if (!doctor.response.ok || doctor.report.ok !== true || failed.length) {
        const failures = [...new Set([...failed, ...checks.filter(c => c.status === 'fail').map(c => c.name)])];
        throw new Error(`Deployment readiness failed (HTTP ${doctor.response.status}): ${failures.join(', ') || 'invalid readiness response'}. The Worker is deployed; fix its configuration and rerun the check. Do not replace encryption keys.`);
      }
      return { apiVersion: health.report.apiVersion, readinessVerified: true, warnings: checks.filter(c => c.status === 'warn').map(c => c.name) };
    } catch (error) {
      // Never echo upstream errors/URLs: they can include a credential or redirect target.
      lastFailure = error instanceof Error && (error.message.startsWith('Deployment readiness failed') || error.message.startsWith('The deployed gateway') || error.message.startsWith('/v1/'))
        ? error : new Error('Unable to verify the deployed gateway. Check its public origin, routing and network connectivity.');
      if (attempt + 1 < attempts) await wait(1000 * (attempt + 1));
    }
  }
  throw lastFailure ?? new Error('No deployment verification attempts were made.');
}
