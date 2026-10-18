/*
 * Storage-credential helpers shared by the Account-Settings management section,
 * the Create-Filespace credential picker, and Filespace-Settings storage editing.
 *
 * The org slug these routes are scoped to comes from the live session
 * (useAuth().session.org.slug). Validation here mirrors what the backend will
 * enforce so the forms fail fast before a round-trip.
 *
 * Owned by the Filespaces / Settings screen lanes.
 */
import type { CreateStorageCredentialInput } from '../../api'

export interface CredentialFormErrors {
  label?: string
  accessKeyId?: string
  secretAccessKey?: string
}

export function validateCredential(input: CreateStorageCredentialInput): CredentialFormErrors {
  const errors: CredentialFormErrors = {}
  if (!input.label.trim()) {
    errors.label = 'A label is required.'
  }
  if (!input.accessKeyId.trim()) {
    errors.accessKeyId = 'Access key ID is required.'
  }
  if (!input.secretAccessKey.trim()) {
    errors.secretAccessKey = 'Secret access key is required.'
  } else if (input.secretAccessKey.trim().length < 8) {
    errors.secretAccessKey = 'That secret looks too short to be valid.'
  }
  return errors
}

export function hasCredentialErrors(errors: CredentialFormErrors): boolean {
  return Object.values(errors).some(Boolean)
}

/** A short, masked preview of an access key id for dense list rows. */
export function maskAccessKeyId(accessKeyId: string): string {
  const trimmed = accessKeyId.trim()
  if (trimmed.length <= 8) return trimmed
  return `${trimmed.slice(0, 4)}…${trimmed.slice(-4)}`
}
