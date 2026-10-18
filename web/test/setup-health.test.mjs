import assert from 'node:assert/strict'
import { test } from 'node:test'
import { buildHealthRows, healthOutcome, healthRepairSteps } from '../src/pages/setupHealth.ts'

const required = ['default_storage_backend', 'storage_integrity', 'upload_verification',
  'storage_enc_key', 'metadata_directory_do', 'metadata_org_do', 'metadata_auth_do',
  'metadata_filespace', 'auth_signing_secret', 'audit_storage_backend', 'public_urls']
const report = () => ({ ok: true, isHttps: true, checks: [
  ...required.map(name => ({ name, status: 'ok', detail: 'Ready' })),
  { name: 'email_provider', status: 'warn', detail: 'Email delivery is not configured.' },
] })

test('optional email warning does not block an otherwise ready workspace', () => {
  const rows = buildHealthRows(report())
  assert.equal(rows.some(row => !row.ok && !row.warning), false)
  assert.equal(rows.find(row => row.key === 'email_provider').warning, true)
})

test('each required service failure and missing result remains visible', () => {
  for (const name of required) {
    const failed = report()
    failed.checks.find(check => check.name === name).status = 'fail'
    failed.checks.find(check => check.name === name).detail = `Unavailable: ${name}`
    const failedRows = buildHealthRows(failed)
    assert.ok(failedRows.some(row => !row.ok && !row.warning && row.detail.includes(`Unavailable: ${name}`)))
    const missing = report()
    missing.checks = missing.checks.filter(check => check.name !== name)
    assert.ok(buildHealthRows(missing).some(row => !row.ok && !row.warning && row.detail.includes('required readiness result is missing')))
  }
})

test('new backend failures cannot be hidden by the grouped presentation', () => {
  const failed = report()
  failed.ok = false
  failed.checks.push({ name: 'future_service', status: 'fail', detail: 'Future service is unavailable.' })
  const row = buildHealthRows(failed).find(row => row.key === 'future_service')
  assert.equal(row.ok, false)
  assert.equal(row.warning, false)
  assert.equal(row.detail, 'Future service is unavailable.')
})

test('a completely healthy report skips the health screen without an alert', () => {
  const healthy = report()
  healthy.checks.forEach(check => { check.status = 'ok' })
  assert.deepEqual(healthOutcome(healthy), { issues: [], canContinue: true, autoContinue: true })
})

test('warnings stay visible but do not auto-advance or block a ready workspace', () => {
  const outcome = healthOutcome(report())
  assert.equal(outcome.issues.length, 1)
  assert.equal(outcome.issues[0].key, 'email_provider')
  assert.equal(outcome.canContinue, true)
  assert.equal(outcome.autoContinue, false)
  assert.match(outcome.issues[0].problems[0].steps.join(' '), /test email/)
})

test('all simultaneous problems in a group retain their own repair steps and details', () => {
  const failed = report()
  for (const name of ['storage_integrity', 'upload_verification', 'metadata_auth_do', 'auth_signing_secret']) {
    Object.assign(failed.checks.find(check => check.name === name), { status: 'fail', detail: `Failed ${name}` })
  }
  const outcome = healthOutcome(failed)
  assert.equal(outcome.canContinue, false)
  assert.equal(outcome.autoContinue, false)
  for (const key of ['storage_integrity', 'metadata_services']) {
    const row = outcome.issues.find(issue => issue.key === key)
    assert.equal(row.problems.length, 2)
    for (const problem of row.problems) {
      assert.match(problem.detail, /Failed/)
      assert.ok(problem.steps.length > 0)
    }
  }
})

test('missing, unknown and contradictory results cannot pass silently', () => {
  const empty = { ok: true, isHttps: true, checks: [] }
  assert.equal(healthOutcome(empty).canContinue, false)
  assert.equal(healthOutcome(empty).autoContinue, false)
  const contradictory = report()
  contradictory.ok = false
  const outcome = healthOutcome(contradictory)
  assert.equal(outcome.canContinue, false)
  assert.ok(outcome.issues.some(issue => issue.key === 'report_incomplete'))
  const unknown = report()
  unknown.checks.push({ name: 'future_service', status: 'fail', detail: 'Unavailable' })
  assert.equal(healthOutcome(unknown).canContinue, false)
  assert.ok(healthOutcome(unknown).issues.find(issue => issue.key === 'future_service').problems[0].steps.length)
})

test('all emitted checks have a repair path and encryption repairs preserve the existing key', () => {
  for (const name of [...required, 'email_provider', 'signup_mode', 'webauthn_rp_id', 'future_check']) {
    assert.ok(healthRepairSteps(name).length > 0)
  }
  assert.match(healthRepairSteps('storage_enc_key').join(' '), /original STORAGE_ENC_KEY/)
  assert.match(healthRepairSteps('storage_enc_key').join(' '), /Do not generate a replacement/)
})

test('malformed responses cannot become a false success', () => {
  for (const malformed of [null, {}, { ok: true }, { ok: true, checks: [null] }, { ok: true, checks: [{ name: 'storage', status: 'unknown', detail: '' }] }]) {
    assert.throws(() => healthOutcome(malformed), /invalid readiness report/)
  }
})
