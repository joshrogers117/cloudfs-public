/*
 * AuthProviderSection — owner/admin-only "Sign-in & authentication" configuration.
 * Renders inside AccountSettings as a grouped settings section.
 *
 * A guided wizard built on the onboarding catalog's `auth` category:
 *   - Pick a provider — tiles: Built-in (default) vs Clerk / Okta / Entra / Auth0 /
 *     Google Workspace.
 *   - A collapsible "How to set this up" panel shows the provider's real steps, the
 *     exact redirect URI to register (copyable), deep links, and the docs link.
 *   - Enter issuer, clientId, clientSecret (write-only), allowed domains, the
 *     auto-provision toggle, and the sign-in MODE (oidc-only vs allow-both).
 *   - "Validate" probes the issuer's discovery document BEFORE saving.
 *   - Save persists via PUT; "Use built-in auth" falls back to the default.
 *
 * Status: "Built-in (default)" when unset; "Configured · <provider>" when an OIDC
 * override is saved. Switching to OIDC-only disables password login for EVERYONE —
 * the wizard warns clearly before that takes effect. Everything goes through the
 * getApi() seam.
 */
import { useEffect, useState } from 'react'
import { Banner, Button, LabeledField, SegmentedControl, Spinner } from '../../design'
import { IconCheck, IconLock } from '../../design/icons'
import {
  getApi,
  type AuthConfig,
  type AuthMode,
  type AuthValidateResult,
  type OidcPreset,
} from '../../api'
import {
  AUTH_PROVIDERS,
  authProvider,
  resolveRedirectUri,
  withRedirectUri,
  type CatalogEntry,
} from '../../onboarding/catalog'
import { CopyableCode, GuidedSteps, ProviderLogo } from '../../onboarding/GuidedSteps'
import { SettingsGroup, SettingsRow } from './SettingsGroup'
import { IconShield } from './icons'
import '../../onboarding/onboarding.css'

/** Map a catalog auth-provider id to the contract's OidcPreset. */
function presetForId(id: string): OidcPreset {
  switch (id) {
    case 'clerk':
      return 'clerk'
    case 'okta':
      return 'okta'
    case 'entra':
      return 'entra'
    case 'auth0':
      return 'auth0'
    case 'google':
      return 'google'
    default:
      return 'generic'
  }
}

/** Map a saved OidcPreset back to the catalog provider id (for tile selection). */
function idForPreset(preset: OidcPreset): string {
  return preset === 'generic' ? 'okta' : preset
}

interface Draft {
  /** The selected catalog provider id ('builtin' | 'clerk' | 'okta' | …). */
  providerId: string
  /** Sign-in mode for OIDC providers: allow-both (default) vs oidc-only. */
  mode: AuthMode
  issuer: string
  clientId: string
  clientSecret: string
  allowedDomains: string
  autoProvision: boolean
}

function draftFromConfig(config: AuthConfig | null): Draft {
  if (config?.oidc) {
    return {
      providerId: idForPreset(config.oidc.preset),
      mode: config.mode === 'oidc' ? 'oidc' : 'both',
      issuer: config.oidc.issuer,
      clientId: config.oidc.clientId,
      clientSecret: '',
      allowedDomains: config.oidc.allowedDomains.join(', '),
      autoProvision: config.oidc.autoProvision,
    }
  }
  return {
    providerId: 'builtin',
    mode: 'both',
    issuer: '',
    clientId: '',
    clientSecret: '',
    allowedDomains: '',
    autoProvision: false,
  }
}

function parseDomains(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean)
}

export function AuthProviderSection({ org }: { org: string }) {
  const [config, setConfig] = useState<AuthConfig | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [editing, setEditing] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [draft, setDraft] = useState<Draft>(() => draftFromConfig(null))

  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [removing, setRemoving] = useState(false)

  const [validating, setValidating] = useState(false)
  const [validation, setValidation] = useState<AuthValidateResult | null>(null)

  useEffect(() => {
    let alive = true
    getApi()
      .getAuthConfig(org)
      .then((c) => {
        if (!alive) return
        setConfig(c)
        setDraft(draftFromConfig(c))
        setLoaded(true)
      })
      .catch(() => alive && setLoadError('Couldn’t load the sign-in configuration.'))
    return () => {
      alive = false
    }
  }, [org])

  const redirectUri = resolveRedirectUri()
  const isBuiltin = draft.providerId === 'builtin'
  const baseEntry = authProvider(draft.providerId)!
  const entry = withRedirectUri(baseEntry, redirectUri)

  function selectProvider(id: string) {
    if (id === draft.providerId) return
    setSaved(false)
    setSaveError(null)
    setValidation(null)
    setDraft((d) => ({
      ...d,
      providerId: id,
      // Reset OIDC fields when switching providers; keep mode preference.
      issuer: '',
      clientId: '',
      clientSecret: '',
    }))
  }

  function patch(p: Partial<Draft>) {
    setSaved(false)
    setDraft((d) => ({ ...d, ...p }))
  }

  // A secret is already saved server-side when the saved config matches this provider.
  const hasSavedSecret =
    Boolean(config?.oidc) && idForPreset(config!.oidc!.preset) === draft.providerId

  const issuerValid = /^https:\/\/[^\s]+\.[^\s]+/.test(draft.issuer.trim())
  const secretSatisfied = isBuiltin || hasSavedSecret || draft.clientSecret.trim().length > 0
  const canSave =
    !saving && !removing && (isBuiltin ? Boolean(config?.oidc) :
    (issuerValid && draft.clientId.trim().length > 0 && secretSatisfied))

  const switchingToOidcOnly =
    !isBuiltin && draft.mode === 'oidc' && config?.mode !== 'oidc'

  async function validate() {
    setValidation(null)
    setValidating(true)
    try {
      const res = await getApi().validateAuthConfig(org, draft.issuer.trim())
      setValidation(res)
    } catch (err) {
      setValidation({
        valid: false,
        error: err instanceof Error ? err.message : 'The issuer could not be validated.',
      })
    } finally {
      setValidating(false)
    }
  }

  async function save() {
    setSaveError(null)
    setSaved(false)
    setSaving(true)
    try {
      const next = await getApi().putAuthConfig(
        org,
        isBuiltin
          ? { mode: 'builtin' }
          : {
              mode: draft.mode,
              oidc: {
                preset: presetForId(draft.providerId),
                issuer: draft.issuer.trim(),
                clientId: draft.clientId.trim(),
                clientSecret: draft.clientSecret.trim() || undefined,
                allowedDomains: parseDomains(draft.allowedDomains),
                autoProvision: draft.autoProvision,
              },
            },
      )
      setConfig(next)
      setDraft(draftFromConfig(next))
      setSaved(true)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Couldn’t save the sign-in configuration.')
    } finally {
      setSaving(false)
    }
  }

  async function remove() {
    setSaveError(null)
    setRemoving(true)
    try {
      await getApi().deleteAuthConfig(org)
      setConfig(null)
      setDraft(draftFromConfig(null))
      setValidation(null)
      setSaved(false)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Couldn’t reset to built-in auth.')
    } finally {
      setRemoving(false)
    }
  }

  const configuredLabel = config?.oidc
    ? authProvider(idForPreset(config.oidc.preset))?.name ?? config.oidc.preset
    : null

  const status: React.ReactNode = !loaded ? (
    <span className="cfs-set-chip">Loading…</span>
  ) : configuredLabel ? (
    <span className="cfs-set-chip cfs-set-chip--accent">
      <IconCheck /> Configured · {configuredLabel}
    </span>
  ) : (
    <span className="cfs-set-chip">Built-in (default)</span>
  )

  return (
    <SettingsGroup
      label="Sign-in & authentication"
      description="Choose how your team signs in to CloudFS."
    >
      <SettingsRow
        leading={<IconShield />}
        title="Identity provider"
        sublabel={
          config?.oidc
            ? `Members sign in through ${configuredLabel}${config.mode === 'oidc' ? ' (password sign-in disabled)' : ' (password sign-in still available)'}.`
            : 'Members sign in with email and password, with optional two-factor authentication.'
        }
        trailing={status}
      />

      {loadError && (
        <SettingsRow>
          <Banner kind="error" title={loadError} />
        </SettingsRow>
      )}

      {loaded && !loadError && !editing && <SettingsRow>
        <Button variant="secondary" onClick={() => setEditing(true)}>Change sign-in method</Button>
      </SettingsRow>}
      {loaded && !loadError && editing && (
        <SettingsRow align="top">
          <div className="cfs-email-wizard">
            {/* Provider tiles */}
            <div className="cfs-fs-field">
              <span className="cfs-fs-field__label">Provider</span>
              <div className="cfs-email-providers" role="radiogroup" aria-label="Authentication provider">
                {AUTH_PROVIDERS.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    role="radio"
                    aria-checked={p.id === draft.providerId}
                    aria-pressed={p.id === draft.providerId}
                    className="cfs-email-provider"
                    onClick={() => selectProvider(p.id)}
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

            {/* Guided setup steps + redirect URI + deep links */}
            <GuidedSteps entry={entry} title="How to set this up" defaultOpen={false} />

            {isBuiltin ? (
              <BuiltinPanel hasOidcSaved={Boolean(config?.oidc)} />
            ) : (
              <>
                <RedirectUriCallout redirectUri={redirectUri} />

                <OidcFields
                  entry={entry}
                  draft={draft}
                  patch={patch}
                  hasSavedSecret={hasSavedSecret}
                  issuerValid={issuerValid || !draft.issuer.trim()}
                />

                {/* Validate the issuer */}
                <ValidatePanel
                  ready={issuerValid && !validating}
                  validating={validating}
                  result={validation}
                  onValidate={() => void validate()}
                />

                {/* Sign-in mode */}
                <div className="cfs-fs-field">
                  <span className="cfs-fs-field__label">Sign-in mode</span>
                  <SegmentedControl<AuthMode>
                    value={draft.mode}
                    onChange={(mode) => patch({ mode })}
                    options={[
                      { value: 'both', label: 'Allow both (password + SSO)' },
                      { value: 'oidc', label: 'SSO only' },
                    ]}
                  />
                  <span className="cfs-fs-field__hint">
                    {draft.mode === 'oidc'
                      ? 'Only this identity provider can sign in. Password sign-in is disabled for everyone.'
                      : 'Members can sign in with their password OR through this identity provider.'}
                  </span>
                </div>

                {switchingToOidcOnly && (
                  <Banner
                    kind="warning"
                    title="This will disable password sign-in for everyone"
                    detail="Switching to SSO only means every member — including you — must sign in through this identity provider. Make sure your own account can sign in via the provider first, and that the redirect URI above is registered."
                  />
                )}
              </>
            )}

            {saveError && <Banner kind="error" title="Couldn’t save" detail={saveError} />}

            <div className="cfs-set-form__actions">
              <Button variant="subtle" disabled={saving || removing} onClick={() => {
                setDraft(draftFromConfig(config)); setValidation(null); setSaveError(null); setSaved(false); setEditing(false)
              }}>Cancel</Button>
              <Button onClick={() => void save()} disabled={!canSave}>
                {saving
                  ? 'Saving…'
                  : isBuiltin
                    ? config?.oidc
                      ? 'Switch to built-in auth'
                      : 'Built-in auth is active'
                    : config?.oidc
                      ? 'Save changes'
                      : 'Save configuration'}
              </Button>
              {config?.oidc && !isBuiltin && (
                <Button
                  variant="destructive"
                  size="small"
                  onClick={() => void remove()}
                  disabled={removing}
                >
                  {removing ? 'Resetting…' : 'Use built-in auth'}
                </Button>
              )}
              {saved && (
                <span className="cfs-set-note cfs-set-note--ok">
                  <IconCheck /> Saved
                </span>
              )}
            </div>
          </div>
        </SettingsRow>
      )}
    </SettingsGroup>
  )
}

/* ----- Built-in default panel ------------------------------------------- */
function BuiltinPanel({ hasOidcSaved }: { hasOidcSaved: boolean }) {
  return (
    <Banner
      kind={hasOidcSaved ? 'warning' : 'info'}
      title={hasOidcSaved ? 'Switch back to built-in auth' : 'Built-in authentication is active'}
      detail={
        hasOidcSaved
          ? 'Saving will remove the connected identity provider and return everyone to built-in sign-in.'
          : 'Members sign in with email and password and can enable an authenticator app. Passkeys require deployment configuration. Connect a provider above to enable single sign-on.'
      }
    />
  )
}

/* ----- Redirect URI callout (shown once, always visible) ---------------- */
function RedirectUriCallout({ redirectUri }: { redirectUri: string }) {
  return (
    <div className="cfs-auth-redirect">
      <span className="cfs-fs-field__label">Redirect URI to register</span>
      <span className="cfs-fs-field__hint">
        Add this exact URL as the allowed redirect / callback URI in your identity provider.
      </span>
      <CopyableCode value={redirectUri} label="redirect URI" />
    </div>
  )
}

/* ----- OIDC field set --------------------------------------------------- */
function OidcFields({
  entry,
  draft,
  patch,
  hasSavedSecret,
  issuerValid,
}: {
  entry: CatalogEntry
  draft: Draft
  patch: (p: Partial<Draft>) => void
  hasSavedSecret: boolean
  issuerValid: boolean
}) {
  const field = (key: string) => entry.fields.find((f) => f.key === key)
  const issuer = field('issuer')
  const clientId = field('clientId')
  const clientSecret = field('clientSecret')
  const domains = field('allowedDomains')

  return (
    <div className="cfs-set-form" style={{ maxWidth: 'none' }}>
      <LabeledField
        label={issuer?.label ?? 'Issuer URL'}
        placeholder={issuer?.placeholder}
        value={draft.issuer}
        onChange={(e) => patch({ issuer: e.target.value })}
        hint={!issuerValid ? 'Enter the HTTPS issuer URL.' : issuer?.hint}
        autoComplete="off"
        spellCheck={false}
      />
      <div className="cfs-email-wizard__grid">
        <LabeledField
          label={clientId?.label ?? 'Client ID'}
          placeholder={clientId?.placeholder}
          value={draft.clientId}
          onChange={(e) => patch({ clientId: e.target.value })}
          autoComplete="off"
          spellCheck={false}
        />
        <LabeledField
          label={clientSecret?.label ?? 'Client Secret'}
          type="password"
          icon={<IconLock />}
          placeholder={hasSavedSecret ? 'Saved — leave blank to keep' : clientSecret?.placeholder}
          value={draft.clientSecret}
          onChange={(e) => patch({ clientSecret: e.target.value })}
          hint={clientSecret?.hint}
          autoComplete="off"
          spellCheck={false}
        />
      </div>
      <LabeledField
        label={domains?.label ?? 'Allowed email domains'}
        placeholder={domains?.placeholder}
        value={draft.allowedDomains}
        onChange={(e) => patch({ allowedDomains: e.target.value })}
        hint={domains?.hint}
        autoComplete="off"
        spellCheck={false}
      />

      <label className="cfs-auth-toggle">
        <input
          type="checkbox"
          checked={draft.autoProvision}
          onChange={(e) => patch({ autoProvision: e.target.checked })}
        />
        <span className="cfs-auth-toggle__text">
          <span className="cfs-auth-toggle__title">Auto-provision new members</span>
          <span className="cfs-auth-toggle__hint">
            Create a cloud-fs account automatically the first time someone with an allowed email
            domain signs in through this provider.
          </span>
        </span>
      </label>

      <p className="cfs-email-secret-note">
        <IconLock />
        The client secret is stored encrypted and is never shown again.
        {hasSavedSecret ? ' A secret is already saved — leave the field blank to keep it.' : ''}
      </p>
    </div>
  )
}

/* ----- Validate sub-panel ----------------------------------------------- */
function ValidatePanel({
  ready,
  validating,
  result,
  onValidate,
}: {
  ready: boolean
  validating: boolean
  result: AuthValidateResult | null
  onValidate: () => void
}) {
  return (
    <div className="cfs-email-test">
      <span className="cfs-fs-section-head__title">Validate the issuer</span>
      <span className="cfs-fs-field__hint">
        Confirm cloud-fs can fetch this issuer’s OpenID configuration before you save.
      </span>
      <div className="cfs-email-test__bar">
        <Button type="button" variant="secondary" onClick={onValidate} disabled={!ready}>
          {validating ? (
            <>
              <Spinner size={14} /> Validating…
            </>
          ) : (
            'Validate'
          )}
        </Button>
      </div>
      {result?.valid && (
        <Banner
          kind="success"
          title="Issuer looks good"
          detail={
            result.endpoints?.authorization
              ? `Discovered the authorization endpoint at ${result.endpoints.authorization}.`
              : 'The OpenID configuration was reachable.'
          }
        />
      )}
      {result && !result.valid && (
        <Banner
          kind="error"
          title="Couldn’t validate the issuer"
          detail={result.error ?? 'The issuer did not return a valid OpenID configuration.'}
        />
      )}
    </div>
  )
}
