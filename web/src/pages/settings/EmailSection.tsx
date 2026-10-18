/*
 * EmailSection — owner/admin-only transactional-email configuration. Renders
 * inside AccountSettings as a grouped settings section.
 *
 * A guided wizard built on the onboarding catalog:
 *   - Pick a provider (Cloudflare Email / Resend / Postmark / Amazon SES) — tiles.
 *   - A collapsible "How to set this up" panel shows the provider's real steps,
 *     deep links to the right console page, and the DNS records to publish.
 *   - Enter the From address (+ name) and the provider secret (write-only).
 *   - "Send test email" to your own address — verify BEFORE saving.
 *   - Save persists via PUT; "Remove" falls back to the deployment default.
 *
 * Status: "Server settings" when unset; "Configured · <provider>" when
 * a per-org override is saved. Everything goes through the getApi() seam.
 */
import { useEffect, useState } from 'react'
import { Banner, Button, LabeledField, Spinner } from '../../design'
import { IconCheck, IconLock, IconMail } from '../../design/icons'
import {
  getApi,
  type EmailConfig,
  type EmailProvider,
  type EmailTestInput,
} from '../../api'
import { EMAIL_PROVIDERS, emailProvider, type CatalogEntry } from '../../onboarding/catalog'
import { GuidedSteps, ProviderLogo } from '../../onboarding/GuidedSteps'
import { SettingsGroup, SettingsRow } from './SettingsGroup'
import { IconTrash } from './icons'
import '../../onboarding/onboarding.css'

interface Draft {
  provider: EmailProvider
  fromAddress: string
  fromName: string
  secret: string
  sesAccessKeyId: string
  sesSecretAccessKey: string
  sesRegion: string
}

function draftFromConfig(config: EmailConfig | null): Draft {
  return {
    provider: config?.provider ?? 'cloudflare',
    fromAddress: config?.fromAddress ?? '',
    fromName: config?.fromName ?? '',
    secret: '',
    sesAccessKeyId: '',
    sesSecretAccessKey: '',
    sesRegion: config?.region ?? 'us-east-1',
  }
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export function EmailSection({ org }: { org: string }) {
  const [config, setConfig] = useState<EmailConfig | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [editing, setEditing] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [draft, setDraft] = useState<Draft>(() => draftFromConfig(null))

  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [removing, setRemoving] = useState(false)

  useEffect(() => {
    let alive = true
    getApi()
      .getEmailConfig(org)
      .then((c) => {
        if (!alive) return
        setConfig(c)
        setDraft(draftFromConfig(c))
        setLoaded(true)
      })
      .catch(() => alive && setLoadError('Couldn’t load the email configuration.'))
    return () => {
      alive = false
    }
  }, [org])

  const entry = emailProvider(draft.provider)!

  function selectProvider(provider: EmailProvider) {
    if (provider === draft.provider) return
    setSaved(false)
    setSaveError(null)
    // Keep the from-address/name when switching; reset provider-specific secrets.
    setDraft((d) => ({
      ...d,
      provider,
      secret: '',
      sesAccessKeyId: '',
      sesSecretAccessKey: '',
    }))
  }

  function patch(p: Partial<Draft>) {
    setSaved(false)
    setDraft((d) => ({ ...d, ...p }))
  }

  // Cloudflare needs no secret; the others need a key unless one is already saved.
  const isSes = draft.provider === 'ses'
  const needsSecret = draft.provider !== 'cloudflare'
  const hasSavedSecretForProvider =
    config?.provider === draft.provider && config.configured
  const secretSatisfied =
    !needsSecret ||
    hasSavedSecretForProvider ||
    (isSes ? Boolean(draft.sesAccessKeyId.trim() && draft.sesSecretAccessKey.trim()) : Boolean(draft.secret.trim()))

  const fromValid = EMAIL_RE.test(draft.fromAddress.trim())
  const canSave = fromValid && secretSatisfied && !saving

  function toInput(): Omit<EmailTestInput, 'to'> {
    return {
      provider: draft.provider,
      fromAddress: draft.fromAddress.trim(),
      fromName: draft.fromName.trim() || undefined,
      secret: draft.secret.trim() || undefined,
      sesAccessKeyId: draft.sesAccessKeyId.trim() || undefined,
      sesSecretAccessKey: draft.sesSecretAccessKey.trim() || undefined,
      sesRegion: isSes ? draft.sesRegion.trim() || undefined : undefined,
    }
  }

  async function save() {
    setSaveError(null)
    setSaved(false)
    setSaving(true)
    try {
      const next = await getApi().putEmailConfig(org, {
        provider: draft.provider,
        fromAddress: draft.fromAddress.trim(),
        fromName: draft.fromName.trim() || undefined,
        secret: draft.secret.trim() || undefined,
        sesAccessKeyId: draft.sesAccessKeyId.trim() || undefined,
        sesSecretAccessKey: draft.sesSecretAccessKey.trim() || undefined,
        sesRegion: isSes ? draft.sesRegion.trim() || undefined : undefined,
      })
      setConfig(next)
      setDraft(draftFromConfig(next))
      setSaved(true)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Couldn’t save the email configuration.')
    } finally {
      setSaving(false)
    }
  }

  async function remove() {
    setSaveError(null)
    setRemoving(true)
    try {
      await getApi().deleteEmailConfig(org)
      setConfig(null)
      setDraft(draftFromConfig(null))
      setSaved(false)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Couldn’t remove the email configuration.')
    } finally {
      setRemoving(false)
    }
  }

  const status: React.ReactNode = !loaded ? (
    <span className="cfs-set-chip">Loading…</span>
  ) : config ? (
    <span className="cfs-set-chip cfs-set-chip--accent">
      <IconCheck /> Configured · {emailProvider(config.provider)?.name ?? config.provider}
    </span>
  ) : (
    <span className="cfs-set-chip">Server settings</span>
  )

  return (
    <SettingsGroup
      label="Email"
      description="Delivery settings for invitations and account emails."
    >
      <SettingsRow
        leading={<IconMail />}
        title="Sending provider"
        sublabel={
          config
            ? `Sending as ${config.fromAddress}${config.fromName ? ` (${config.fromName})` : ''}.`
            : 'Uses the email provider configured when your server was installed. Check delivery in Troubleshooting.'
        }
        trailing={status}
      />

      {loadError && (
        <SettingsRow>
          <Banner kind="error" title={loadError} />
        </SettingsRow>
      )}

      {loaded && !loadError && !editing && <SettingsRow>
        <Button variant="secondary" onClick={() => setEditing(true)}>Change email settings</Button>
      </SettingsRow>}
      {loaded && !loadError && editing && (
        <SettingsRow align="top">
          <div className="cfs-email-wizard">
            {/* Provider tiles */}
            <div className="cfs-fs-field">
              <span className="cfs-fs-field__label">Provider</span>
              <div className="cfs-email-providers" role="radiogroup" aria-label="Email provider">
                {EMAIL_PROVIDERS.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    role="radio"
                    aria-checked={p.id === draft.provider}
                    aria-pressed={p.id === draft.provider}
                    className="cfs-email-provider"
                    onClick={() => selectProvider(p.id as EmailProvider)}
                  >
                    <ProviderLogo entry={p} size={26} />
                    <span className="cfs-email-provider__text">
                      <span className="cfs-email-provider__name">{p.name}</span>
                      <span className="cfs-email-provider__blurb">{p.blurb}</span>
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Guided setup steps + deep links + DNS */}
            <GuidedSteps entry={entry} title="How to set this up" defaultOpen={false} />

            {/* Fields */}
            <ProviderFields
              entry={entry}
              draft={draft}
              patch={patch}
              isSes={isSes}
              needsSecret={needsSecret}
              hasSavedSecret={hasSavedSecretForProvider}
            />

            {/* Test */}
            <TestEmail org={org} disabled={!fromValid || !secretSatisfied} buildInput={toInput} />

            {saveError && <Banner kind="error" title="Couldn’t save" detail={saveError} />}

            <div className="cfs-set-form__actions">
              <Button variant="subtle" disabled={saving || removing} onClick={() => {
                setDraft(draftFromConfig(config)); setSaveError(null); setSaved(false); setEditing(false)
              }}>Cancel</Button>
              <Button onClick={() => void save()} disabled={!canSave}>
                {saving ? 'Saving…' : config ? 'Save changes' : 'Save configuration'}
              </Button>
              {config && (
                <Button
                  variant="destructive"
                  size="small"
                  leading={<IconTrash size={13} />}
                  onClick={() => void remove()}
                  disabled={removing}
                >
                  {removing ? 'Removing…' : 'Use server settings'}
                </Button>
              )}
              {saved && <span className="cfs-set-note cfs-set-note--ok"><IconCheck /> Saved</span>}
            </div>
          </div>
        </SettingsRow>
      )}
    </SettingsGroup>
  )
}

/* ----- Provider-specific field set ------------------------------------- */
function ProviderFields({
  entry,
  draft,
  patch,
  isSes,
  needsSecret,
  hasSavedSecret,
}: {
  entry: CatalogEntry
  draft: Draft
  patch: (p: Partial<Draft>) => void
  isSes: boolean
  needsSecret: boolean
  hasSavedSecret: boolean
}) {
  // Field labels/placeholders come from the catalog so they match the provider.
  const field = (key: string) => entry.fields.find((f) => f.key === key)
  const fromAddr = field('fromAddress')
  const fromNm = field('fromName')
  const secret = field('secret')
  const sesKeyId = field('sesAccessKeyId')
  const sesSecret = field('sesSecretAccessKey')
  const sesRegion = field('sesRegion')

  const fromValid = !draft.fromAddress.trim() || EMAIL_RE.test(draft.fromAddress.trim())

  return (
    <div className="cfs-set-form" style={{ maxWidth: 'none' }}>
      <div className="cfs-email-wizard__grid">
        <LabeledField
          label={fromAddr?.label ?? 'From address'}
          icon={<IconMail />}
          placeholder={fromAddr?.placeholder ?? 'no-reply@your-domain.com'}
          value={draft.fromAddress}
          onChange={(e) => patch({ fromAddress: e.target.value })}
          hint={!fromValid ? 'Enter a valid email address.' : undefined}
          autoComplete="off"
          spellCheck={false}
        />
        <LabeledField
          label={fromNm?.label ?? 'From name'}
          placeholder={fromNm?.placeholder ?? 'cloud-fs'}
          value={draft.fromName}
          onChange={(e) => patch({ fromName: e.target.value })}
          autoComplete="off"
        />
      </div>

      {needsSecret && !isSes && secret && (
        <LabeledField
          label={secret.label}
          type="password"
          icon={<IconLock />}
          placeholder={hasSavedSecret ? 'Saved — leave blank to keep' : secret.placeholder}
          value={draft.secret}
          onChange={(e) => patch({ secret: e.target.value })}
          hint={secret.hint}
          autoComplete="off"
          spellCheck={false}
        />
      )}

      {isSes && (
        <>
          <div className="cfs-email-wizard__grid">
            <LabeledField
              label={sesRegion?.label ?? 'SES region'}
              placeholder={sesRegion?.placeholder ?? 'us-east-1'}
              value={draft.sesRegion}
              onChange={(e) => patch({ sesRegion: e.target.value })}
              hint={sesRegion?.hint}
              autoComplete="off"
              spellCheck={false}
            />
            <LabeledField
              label={sesKeyId?.label ?? 'AWS Access Key ID'}
              placeholder={sesKeyId?.placeholder ?? 'AKIA…'}
              value={draft.sesAccessKeyId}
              onChange={(e) => patch({ sesAccessKeyId: e.target.value })}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <LabeledField
            label={sesSecret?.label ?? 'AWS Secret Access Key'}
            type="password"
            icon={<IconLock />}
            placeholder={hasSavedSecret ? 'Saved — leave blank to keep' : sesSecret?.placeholder}
            value={draft.sesSecretAccessKey}
            onChange={(e) => patch({ sesSecretAccessKey: e.target.value })}
            hint={sesSecret?.hint}
            autoComplete="off"
            spellCheck={false}
          />
        </>
      )}

      {needsSecret && (
        <p className="cfs-email-secret-note">
          <IconLock />
          The secret is stored encrypted and is never shown again.
          {hasSavedSecret ? ' A secret is already saved — leave the field blank to keep it.' : ''}
        </p>
      )}
      {!needsSecret && (
        <p className="cfs-email-secret-note">
          <IconMail />
          Cloudflare Email sends through the Worker’s binding — no API key needed. Just verify your
          domain and set the From address.
        </p>
      )}
    </div>
  )
}

/* ----- Send-test sub-panel --------------------------------------------- */
function TestEmail({
  org,
  disabled,
  buildInput,
}: {
  org: string
  disabled: boolean
  buildInput: () => Omit<EmailTestInput, 'to'>
}) {
  const [to, setTo] = useState('')
  const [testing, setTesting] = useState(false)
  const [result, setResult] = useState<{ ok: boolean; error?: string } | null>(null)

  const toValid = EMAIL_RE.test(to.trim())
  const ready = toValid && !disabled && !testing

  async function run() {
    setResult(null)
    setTesting(true)
    try {
      const res = await getApi().testEmailConfig(org, { to: to.trim(), ...buildInput() })
      setResult({ ok: res.sent, error: res.error })
    } catch (err) {
      setResult({ ok: false, error: err instanceof Error ? err.message : 'The test failed to run.' })
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className="cfs-email-test">
      <span className="cfs-fs-section-head__title">Send a test email</span>
      <div className="cfs-email-test__bar">
        <div style={{ flex: 1, minWidth: 220 }}>
          <LabeledField
            label="Send to"
            type="email"
            icon={<IconMail />}
            placeholder="you@your-domain.com"
            value={to}
            onChange={(e) => {
              setTo(e.target.value)
              setResult(null)
            }}
            autoComplete="email"
          />
        </div>
        <Button type="button" variant="secondary" onClick={() => void run()} disabled={!ready}>
          {testing ? (
            <>
              <Spinner size={14} /> Sending…
            </>
          ) : (
            'Send test'
          )}
        </Button>
      </div>
      {disabled && !result && (
        <span className="cfs-fs-field__hint">
          Fill in the From address and provider credentials above to send a test.
        </span>
      )}
      {result?.ok && (
        <Banner kind="success" title="Test email sent" detail={`Check ${to.trim()} — it should arrive shortly.`} />
      )}
      {result && !result.ok && (
        <Banner kind="error" title="Couldn’t send the test" detail={result.error ?? 'The provider rejected the request.'} />
      )}
    </div>
  )
}
