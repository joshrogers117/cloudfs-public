/*
 * Typed API errors the screens can branch on without parsing strings.
 *
 * The storage-credential delete contract may reject with HTTP 409
 * `credential_in_use`, carrying the filespaces (spaces) that still reference the
 * credential. Both the MockApi and the real HttpApi throw this same shape so the
 * Settings UI can name the offending filespaces regardless of which seam is live.
 */

/** Thrown when a credential can't be deleted because filespaces still use it. */
export class CredentialInUseError extends Error {
  /** Labels/names of the filespaces still referencing the credential. */
  readonly spaces: string[]

  constructor(spaces: string[]) {
    super('That credential is in use by one or more filespaces.')
    this.name = 'CredentialInUseError'
    this.spaces = spaces
  }
}
