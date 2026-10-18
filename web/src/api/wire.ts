/*
 * Wire <-> domain mappers for the real HttpApi.
 *
 * The backend models a "space" with per-space S3-compatible storage fields
 * (storageEndpoint / storageRegion / storageBucket / storageCredentialRef — the
 * shape the Filespaces screen's storage.ts already mirrors). The app's frozen
 * domain `Filespace` (types.ts) is a flattened display projection of that. These
 * mappers convert between the two so neither the screens nor types.ts change.
 *
 * Role vocabulary (CONTRACTS-AUTH §1.1): the backend uses
 * owner | admin | space_admin | standard. The web domain uses the display
 * labels OrgRole (Owner|Admin|Member) and FilespaceRole
 * (Filespace Admin|Standard User|Viewer).
 */
import type {
  ConnectionState,
  Filespace,
  FilespaceRole,
  OrgRole,
} from './types'

/** A space as returned by `/v1/orgs/:org/spaces` (per-space storage fields). */
export interface WireSpace {
  id: string
  name: string
  /** Per-space S3 storage config (org-do.ts SpaceRegistration). */
  storageEndpoint?: string | null
  storageRegion?: string | null
  storageBucket?: string | null
  storageForcePathStyle?: boolean | null
  storageCredentialRef?: string | null
  /** Display label for the backend, e.g. "Cloudflare R2" (when the gateway sends it). */
  storageBackend?: string
  /** Provider key the registry persists, e.g. "r2" | "s3" | "b2" (bucket_provider). */
  bucketProvider?: string
  /** Alternate provider-key field name some gateways use. */
  storageProvider?: string
  /** Live connection/health state, when the gateway tracks it. */
  state?: string
  /** Bytes stored. */
  usedBytes?: number
  /** Caller's role within this space (overrides the org-level fallback). */
  role?: string
  memberCount?: number
  mountPath?: string
}

const BACKEND_LABELS: Record<string, string> = {
  r2: 'Cloudflare R2',
  s3: 'AWS S3',
  b2: 'Backblaze B2',
  minio: 'MinIO',
  wasabi: 'Wasabi',
}

const CONNECTION_STATES: ReadonlySet<ConnectionState> = new Set<ConnectionState>([
  'connected',
  'connecting',
  'paused',
  'disconnected',
  'error',
])

/** Map the backend account/org role to the web's display OrgRole. */
export function mapOrgRole(role: string | undefined): OrgRole {
  switch ((role ?? '').toLowerCase()) {
    case 'owner':
      return 'Owner'
    case 'admin':
      return 'Admin'
    case 'space_admin':
      return 'Filespace Admin'
    default:
      return 'Member'
  }
}

/** Map a backend role to the web's per-filespace display role. */
export function mapRole(role: string | undefined): FilespaceRole {
  switch ((role ?? '').toLowerCase()) {
    case 'owner':
    case 'admin':
    case 'space_admin':
      return 'Filespace Admin'
    case 'viewer':
      return 'Viewer'
    // A standard member holding an admin-level folder grant: manages access to its folders but
    // cannot rename the filespace (backend PATCH is org admin/space_admin only), so it is shown
    // as a standard user here.
    case 'folder_admin':
      return 'Standard User'
    default:
      return 'Standard User'
  }
}

function backendLabel(s: WireSpace): string {
  if (s.storageBackend) return s.storageBackend
  const provider = s.storageProvider ?? s.bucketProvider
  if (provider) return BACKEND_LABELS[provider.toLowerCase()] ?? provider
  return 'Cloudflare R2'
}

function connectionFrom(state: string | undefined): ConnectionState {
  const v = (state ?? '').toLowerCase()
  return CONNECTION_STATES.has(v as ConnectionState) ? (v as ConnectionState) : 'disconnected'
}

/** Project a backend space onto the app's frozen `Filespace` display shape. */
export function spaceToFilespace(s: WireSpace, fallbackRole: FilespaceRole): Filespace {
  return {
    id: s.id,
    name: s.name,
    region: s.storageRegion ?? 'auto',
    storageBackend: backendLabel(s),
    connection: connectionFrom(s.state),
    role: s.role ? mapRole(s.role) : fallbackRole,
    usedBytes: s.usedBytes ?? 0,
    usageKnown: s.usedBytes !== undefined,
    memberCountKnown: s.memberCount !== undefined,
    memberCount: s.memberCount ?? 1,
    mountPath: s.mountPath,
    storageBucket: s.storageBucket ?? undefined,
    storageEndpoint: s.storageEndpoint ?? undefined,
  }
}
