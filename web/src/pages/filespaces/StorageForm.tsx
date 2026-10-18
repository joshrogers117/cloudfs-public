/*
 * StorageForm — the S3-compatible storage backend editor shared by Create and
 * Settings. Provider preset tiles (R2 / AWS S3 / Backblaze B2 / MinIO / Wasabi)
 * + endpoint / region / bucket / credential-reference fields, matching the
 * backend's per-space storageEndpoint / storageRegion / storageBucket /
 * storageCredentialRef config. Controlled; validation lives in storage.ts.
 *
 * Now catalog-driven: picking a provider AUTO-FILLS the endpoint from the
 * catalog's endpointTemplate + the region default, and a collapsible
 * "How to get these" panel renders the provider's real, step-by-step setup
 * instructions with deep links to the right console page. R2 gets a dedicated
 * Account ID field that builds the endpoint for you.
 *
 * Owned by the Filespaces screen lane.
 */
import { LabeledInput } from './fields'
import { CredentialPicker } from './CredentialPicker'
import { DedicatedBucketNote } from './guidance'
import { ProviderLogo, GuidedSteps } from '../../onboarding/GuidedSteps'
import {
  PROVIDER_PRESETS,
  presetFor,
  catalogFor,
  autoFilledEndpoint,
  type StorageConfig,
  type StorageErrors,
  type StorageProvider,
} from './storage'

export function StorageForm({
  org,
  config,
  errors,
  onChange,
}: {
  /** Org slug — needed to load/save storage credentials in the picker. */
  org: string
  config: StorageConfig
  errors: StorageErrors
  onChange: (next: StorageConfig) => void
}) {
  const preset = presetFor(config.provider)
  const entry = catalogFor(config.provider)
  const isR2 = config.provider === 'r2'

  function selectProvider(provider: StorageProvider) {
    if (provider === config.provider) return
    const next = presetFor(provider)
    const seeded: StorageConfig = {
      ...config,
      provider,
      accountId: '',
      // Prefill the provider default region…
      region: next.defaultRegion,
      // …and auto-fill the endpoint from the catalog template where possible
      // (AWS S3 / Wasabi / B2 resolve from the region; R2 waits for an account id).
      endpoint: '',
    }
    onChange({ ...seeded, endpoint: autoFilledEndpoint(seeded) })
  }

  // Update the R2 account id and re-derive the endpoint from the catalog template.
  function setAccountId(accountId: string) {
    const next = { ...config, accountId }
    onChange({ ...next, endpoint: autoFilledEndpoint(next) || next.endpoint })
  }

  return (
    <div className="cfs-fs-form">
      <div className="cfs-fs-field">
        <span className="cfs-fs-field__label">Storage provider</span>
        <div className="cfs-fs-providers" role="radiogroup" aria-label="Storage provider">
          {PROVIDER_PRESETS.map((p) => {
            const e = catalogFor(p.provider)
            return (
              <button
                key={p.provider}
                type="button"
                role="radio"
                aria-checked={p.provider === config.provider}
                aria-pressed={p.provider === config.provider}
                className="cfs-fs-provider"
                onClick={() => selectProvider(p.provider)}
              >
                <span className="cfs-fs-provider__head">
                  <ProviderLogo entry={e} size={22} />
                  <span className="cfs-fs-provider__name">{p.label}</span>
                </span>
                <span className="cfs-fs-provider__blurb">{p.blurb}</span>
              </button>
            )
          })}
        </div>
      </div>

      {/* Provider-specific guided setup with deep links to the right console page. */}
      <GuidedSteps entry={entry} />

      {isR2 && (
        <LabeledInput
          label="Cloudflare Account ID"
          id="fs-account-id"
          placeholder="e.g. a1b2c3d4e5f6…"
          hint="Builds your endpoint automatically: https://<accountId>.r2.cloudflarestorage.com"
          value={config.accountId ?? ''}
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => setAccountId(e.target.value)}
        />
      )}

      <div className="cfs-fs-form__row">
        {!preset.endpointDerivedFromRegion && (
          <LabeledInput
            label="Endpoint"
            id="fs-endpoint"
            placeholder={preset.endpointPlaceholder}
            hint={isR2 ? 'Auto-filled from your Account ID — edit if needed.' : 'S3-compatible endpoint URL.'}
            error={errors.endpoint}
            value={config.endpoint}
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => onChange({ ...config, endpoint: e.target.value })}
          />
        )}
        <LabeledInput
          label={isR2 ? "Connection region" : "Bucket region"}
          id="fs-region"
          readOnly={isR2}
          placeholder={preset.regionPlaceholder}
          hint={
            isR2 ? 'R2 uses auto for connections. Choose the bucket’s physical location in Cloudflare when creating it.' : preset.endpointDerivedFromRegion
              ? 'Use the existing bucket’s AWS region. This sets its connection endpoint.'
              : 'Use the existing bucket’s region code; changing this does not move its data.'
          }
          error={errors.region}
          value={config.region}
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => {
            const next = { ...config, region: e.target.value }
            // Region-derived providers (AWS S3) keep the endpoint in sync.
            onChange(
              preset.endpointDerivedFromRegion
                ? { ...next, endpoint: autoFilledEndpoint(next) || next.endpoint }
                : next,
            )
          }}
        />
      </div>

      <LabeledInput
        label="Bucket"
        id="fs-bucket"
        placeholder="my-filespace-bucket"
        hint="A dedicated, empty bucket for this filespace (strongly recommended)."
        error={errors.bucket}
        value={config.bucket}
        autoComplete="off"
        spellCheck={false}
        onChange={(e) => onChange({ ...config, bucket: e.target.value })}
      />

      <CredentialPicker
        org={org}
        value={config.credentialId}
        error={errors.credentialId}
        onChange={(credentialId) => onChange({ ...config, credentialId })}
      />

      <DedicatedBucketNote />
    </div>
  )
}
