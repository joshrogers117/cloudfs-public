/*
 * Storage backend presets + per-space S3-compatible storage config.
 *
 * Mirrors the cloud-fs backend's per-space storage fields
 * (storageEndpoint / storageRegion / storageBucket / storageCredentialRef) and
 * the provider presets the Mac/web product offers (R2, AWS S3, Backblaze B2,
 * MinIO, Wasabi). The frozen API `CreateFilespaceInput` only carries the display
 * labels `region` + `storageBackend`; `toCreateInput()` projects the richer
 * config onto that shape so screens submit through the unchanged MockApi seam.
 *
 * Owned by the Filespaces screen lane.
 */
import type { CreateFilespaceInput, StorageTestInput } from '../../api'
import { storageProvider, resolveEndpoint, type CatalogEntry } from '../../onboarding/catalog'

export type StorageProvider = 'r2' | 's3' | 'b2' | 'minio' | 'wasabi'

export interface StorageConfig {
  provider: StorageProvider
  /** S3 endpoint, e.g. https://<acct>.r2.cloudflarestorage.com */
  endpoint: string
  /** Region code, e.g. auto / us-east-1 / us-west-004 */
  region: string
  /** Bucket name. */
  bucket: string
  /** Id of a SAVED storage credential (selected in the picker) — never a secret. */
  credentialId: string
  /** Cloudflare R2 account id — auto-fills the endpoint from the catalog template. */
  accountId?: string
}

export interface ProviderPreset {
  provider: StorageProvider
  /** Display name shown in the picker + as the filespace's storageBackend label. */
  label: string
  /** One-line description of the provider. */
  blurb: string
  /** Endpoint template / placeholder; {account} is a hint, not substituted. */
  endpointPlaceholder: string
  /** Default region for the provider, prefilled when the preset is chosen. */
  defaultRegion: string
  /** Region field placeholder / example. */
  regionPlaceholder: string
  /** When true the endpoint is fixed by AWS and derived from region — hidden. */
  endpointDerivedFromRegion?: boolean
}

export const PROVIDER_PRESETS: ProviderPreset[] = [
  {
    provider: 'r2',
    label: 'Cloudflare R2',
    blurb: 'Zero-egress object storage on Cloudflare.',
    endpointPlaceholder: 'https://<account-id>.r2.cloudflarestorage.com',
    defaultRegion: 'auto',
    regionPlaceholder: 'auto',
  },
  {
    provider: 's3',
    label: 'AWS S3',
    blurb: 'Amazon S3 — endpoint derived from the region.',
    endpointPlaceholder: 'https://s3.us-east-1.amazonaws.com',
    defaultRegion: 'us-east-1',
    regionPlaceholder: 'us-east-1',
    endpointDerivedFromRegion: true,
  },
  {
    provider: 'b2',
    label: 'Backblaze B2',
    blurb: 'B2 Cloud Storage via the S3-compatible API.',
    endpointPlaceholder: 'https://s3.us-west-004.backblazeb2.com',
    defaultRegion: 'us-west-004',
    regionPlaceholder: 'us-west-004',
  },
  {
    provider: 'minio',
    label: 'MinIO',
    blurb: 'Self-hosted, S3-compatible object storage.',
    endpointPlaceholder: 'https://minio.your-domain.com',
    defaultRegion: 'us-east-1',
    regionPlaceholder: 'us-east-1',
  },
  {
    provider: 'wasabi',
    label: 'Wasabi',
    blurb: 'Hot cloud storage, S3-compatible.',
    endpointPlaceholder: 'https://s3.us-east-1.wasabisys.com',
    defaultRegion: 'us-east-1',
    regionPlaceholder: 'us-east-1',
  },
]

export function presetFor(provider: StorageProvider): ProviderPreset {
  return PROVIDER_PRESETS.find((p) => p.provider === provider) ?? PROVIDER_PRESETS[0]
}

/** The catalog entry (guided steps + deep links + endpoint template) for a provider. */
export function catalogFor(provider: StorageProvider): CatalogEntry {
  // The catalog ids match the StorageProvider keys 1:1; r2 is the safe fallback.
  return storageProvider(provider) ?? storageProvider('r2')!
}

/**
 * Auto-fill the endpoint when the catalog template can be fully resolved from the
 * config — i.e. AWS S3 / Wasabi / B2 from the region, or R2 once the account id is
 * typed. Returns '' when a value is still missing so the user can complete it.
 */
export function autoFilledEndpoint(config: StorageConfig): string {
  return resolveEndpoint(catalogFor(config.provider), {
    accountId: config.accountId,
    region: config.region,
  })
}

/** A blank config seeded from a provider preset. */
export function blankConfig(provider: StorageProvider = 'r2'): StorageConfig {
  const preset = presetFor(provider)
  return {
    provider,
    endpoint: '',
    region: preset.defaultRegion,
    bucket: '',
    credentialId: '',
    accountId: '',
  }
}

/** Human-readable region label, e.g. "ENAM (us-east)" style fallbacks. */
function regionLabel(region: string): string {
  const trimmed = region.trim()
  return trimmed.length > 0 ? trimmed : 'auto'
}

/** Effective endpoint for AWS S3 (derived from region) or the typed endpoint. */
export function effectiveEndpoint(config: StorageConfig): string {
  const preset = presetFor(config.provider)
  // AWS S3: the endpoint is fully derived from the region via the catalog template.
  if (preset.endpointDerivedFromRegion && config.region.trim()) {
    return autoFilledEndpoint(config) || `https://s3.${config.region.trim()}.amazonaws.com`
  }
  return config.endpoint.trim()
}

/* ----- Validation ----- */

export interface StorageErrors {
  endpoint?: string
  region?: string
  bucket?: string
  credentialId?: string
}

const HTTPS_RE = /^https?:\/\/[^\s]+$/i
const BUCKET_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/

export function validateStorage(config: StorageConfig): StorageErrors {
  const errors: StorageErrors = {}
  const preset = presetFor(config.provider)

  if (!config.region.trim()) {
    errors.region = 'Region is required.'
  }

  if (!preset.endpointDerivedFromRegion) {
    const endpoint = config.endpoint.trim()
    if (!endpoint) {
      errors.endpoint = 'Endpoint is required.'
    } else if (!HTTPS_RE.test(endpoint)) {
      errors.endpoint = 'Enter a valid http(s):// endpoint URL.'
    }
  }

  const bucket = config.bucket.trim()
  if (!bucket) {
    errors.bucket = 'Bucket name is required.'
  } else if (!BUCKET_RE.test(bucket)) {
    errors.bucket = 'Use 3–63 lowercase letters, numbers, dots or hyphens.'
  }

  if (!config.credentialId.trim()) {
    errors.credentialId = 'Select a saved credential.'
  }

  return errors
}

export function hasErrors(errors: StorageErrors): boolean {
  return Object.values(errors).some(Boolean)
}

/**
 * Project the rich storage config onto the frozen `CreateFilespaceInput`.
 * `storageBackend` carries the provider label (shown on the list card); `region`
 * carries the region label. The full S3 config travels here so the Wire phase can
 * widen the input type without changing screens.
 */
export function toCreateInput(name: string, config: StorageConfig): CreateFilespaceInput {
  return {
    name: name.trim(),
    region: regionLabel(config.region),
    storageBackend: presetFor(config.provider).label,
    // Full per-space S3 config so the real client persists a working backend
    // (the Mock ignores these extra fields harmlessly).
    storageEndpoint: effectiveEndpoint(config) || undefined,
    storageBucket: config.bucket.trim() || undefined,
    storageForcePathStyle: config.provider === 'minio' ? true : undefined,
    credentialId: config.credentialId.trim() || undefined,
  }
}

/**
 * Project the storage config onto a `StorageTestInput` for the connection-verify
 * probe. References the selected saved credential by id (the secret never leaves
 * the backend); `forcePathStyle` is on for MinIO, which typically needs it.
 */
export function toTestInput(config: StorageConfig): StorageTestInput {
  return {
    endpoint: effectiveEndpoint(config),
    region: config.region.trim(),
    bucket: config.bucket.trim(),
    forcePathStyle: config.provider === 'minio' ? true : undefined,
    credentialId: config.credentialId || undefined,
  }
}
