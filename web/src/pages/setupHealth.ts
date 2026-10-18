import type { DoctorReport } from '../api/types'

interface HealthRowDef {
  name: string
  names?: string[]
  title: string
  impact: string
}

const HEALTH_ROW_DEFS: HealthRowDef[] = [
  { name: 'default_storage_backend', title: 'Storage connection', impact: 'Files cannot be uploaded or downloaded reliably.' },
  { name: 'storage_integrity', names: ['storage_integrity', 'upload_verification'], title: 'Upload safety', impact: 'Storage has not passed the checks needed to protect your files.' },
  { name: 'storage_enc_key', title: 'Encryption key', impact: 'Filespace keys and saved credentials cannot be opened safely.' },
  { name: 'metadata_services', names: ['metadata_directory_do', 'metadata_org_do', 'metadata_auth_do', 'metadata_filespace', 'auth_signing_secret'], title: 'Workspace services', impact: 'Accounts, permissions or file records are unavailable.' },
  { name: 'audit_storage_backend', title: 'Activity history', impact: 'Workspace activity cannot be saved reliably.' },
  { name: 'email_provider', title: 'Email delivery', impact: 'Invitations and password resets cannot be delivered by email. You can still invite teammates with a copied link.' },
  { name: 'public_urls', title: 'Sign-in addresses', impact: 'Browser links or Mac sign-in may not work.' },
]

const GENERIC_STEPS = [
  'Run the checks again to rule out a temporary outage.',
  'In Cloudflare, open this deployment’s Worker and check its logs for the check name shown below. Ask the person who deployed the server if you do not have access.',
  'Correct the reported configuration in your deployment files, redeploy this server, then return here and check again.',
]

/** Instructions describe real deployment controls, not nonexistent UI settings. */
export function healthRepairSteps(name: string): string[] {
  if (name.startsWith('metadata_')) return [
    'Open this deployment’s Worker in Cloudflare. Check the named Durable Object binding and the Worker logs for migration or schema errors.',
    'Restore the binding and migration configuration from this server’s deployment files and redeploy. Keep the existing namespace and data; do not delete or recreate them.',
  ]
  switch (name) {
    case 'default_storage_backend': return [
      'In your deployment configuration, check S3_ENDPOINT, S3_BUCKET and S3_REGION against the existing bucket.',
      'Check that the S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY secrets belong to that bucket and allow listing, reading, writing and deleting objects. Restore or update the credentials in your protected deployment secrets, then redeploy.',
    ]
    case 'storage_integrity': return [
      'Fix any storage connection issue first, then check again.',
      'Your storage must support signed checksums, conditional writes and verified readback. For R2, verify the endpoint and bucket credentials. For another provider, ask the operator to check these capabilities before using that bucket. Do not disable upload verification.',
    ]
    case 'upload_verification': return [
      'Set STORAGE_VERIFY_UPLOADS to 1 in this server’s deployment configuration and redeploy. A value of 0 disables the checks that protect file commits.',
    ]
    case 'storage_enc_key': return [
      'Restore the original STORAGE_ENC_KEY from this deployment’s protected secrets backup. It must decode to 32 bytes.',
      'Redeploy with that same key. Do not generate a replacement: existing filespace keys and credentials may become unreadable. If the original is lost, stop and contact the server operator to plan recovery.',
    ]
    case 'auth_signing_secret': return [
      'Restore AUTH_SIGNING_SECRET from this deployment’s protected secrets file and redeploy. It must contain at least 16 characters. Changing an existing signing secret invalidates current sign-ins.',
    ]
    case 'audit_storage_backend': return [
      'In Cloudflare, check that this Worker’s AUDIT_BUCKET binding points to the existing activity-history R2 bucket.',
      'Correct the binding in your deployment configuration and redeploy. Keep the existing bucket and its history.',
    ]
    case 'email_provider': return [
      'Open Workspace settings → Email in a new tab. Choose a delivery provider and follow its setup instructions.',
      'Send a test email to your own address, confirm it arrives, then save. Return here and check again. Copied invitation links remain available while you fix delivery.',
    ]
    case 'public_urls': return [
      'Set PUBLIC_BASE_URL to the gateway’s public HTTPS address and WEB_BASE_URL to the web console’s public HTTPS address. They can match when the console and API share a domain.',
      'Replace any localhost or development value reported below, including S3_ENDPOINT, in this deployment’s configuration. Redeploy and check again.',
    ]
    case 'signup_mode': return [
      'Set SIGNUP_MODE to invite in your deployment configuration and redeploy to use invitation-only registration. Ask the operator to review the registration policy before enabling open sign-up.',
    ]
    case 'webauthn_rp_id': return [
      'Set WEBAUTHN_RP_ID to the web console’s domain name, without https:// or a path, and redeploy. Changing the domain can require users to enroll their passkeys again.',
    ]
    default: return GENERIC_STEPS
  }
}

export interface HealthRow {
  key: string
  title: string
  ok: boolean
  warning: boolean
  impact: string
  detail: string
  problems: { name: string; detail: string; steps: string[] }[]
}

export function buildHealthRows(report: DoctorReport): HealthRow[] {
  const rows = HEALTH_ROW_DEFS.map((def) => {
    const names = def.names ?? [def.name]
    const checks = names.map(name => report.checks.find(c => c.name === name))
    const problems = names.flatMap((name, i) => checks[i]?.status === 'ok' ? [] : [{
      name,
      detail: checks[i]?.detail ?? `A required readiness result is missing: ${name}.`,
      steps: healthRepairSteps(name),
    }])
    return {
      key: def.name, title: def.title, impact: def.impact,
      ok: problems.length === 0,
      warning: problems.length > 0 && checks.every(check => check && (check.status === 'ok' || check.status === 'warn')),
      detail: problems.map(problem => problem.detail).join('\n'),
      problems,
    }
  })
  const grouped = new Set(HEALTH_ROW_DEFS.flatMap(def => def.names ?? [def.name]))
  for (const check of report.checks) {
    if (!grouped.has(check.name) && check.status !== 'ok') rows.push({
      key: check.name,
      title: check.name === 'signup_mode' ? 'Registration' : check.name === 'webauthn_rp_id' ? 'Passkeys' : 'Deployment configuration',
      impact: 'This configuration needs attention.', ok: false,
      warning: check.status === 'warn', detail: check.detail,
      problems: [{ name: check.name, detail: check.detail, steps: healthRepairSteps(check.name) }],
    })
  }
  // Never leave Continue blocked without explaining an inconsistent server result.
  if (!report.ok && !rows.some(row => !row.ok && !row.warning)) rows.push({
    key: 'report_incomplete', title: 'Checks could not confirm readiness', ok: false, warning: false,
    impact: 'The server reported a failure without identifying the affected service.',
    detail: 'The overall result did not match the individual checks.',
    problems: [{ name: 'report_incomplete', detail: 'Overall result: not ready.', steps: GENERIC_STEPS }],
  })
  return rows
}

export function healthOutcome(report: DoctorReport) {
  if (!report || typeof report.ok !== 'boolean' || !Array.isArray(report.checks) ||
    report.checks.some(check => !check || typeof check.name !== 'string' || typeof check.detail !== 'string' || !['ok', 'warn', 'fail'].includes(check.status))) {
    throw new Error('The server returned an invalid readiness report.')
  }
  const issues = buildHealthRows(report).filter(row => !row.ok)
  return {
    issues,
    canContinue: report.ok && issues.every(row => row.warning),
    autoContinue: report.ok && issues.length === 0,
  }
}
