const EMAIL_ATOM = /^[A-Z0-9!#$%&'*+/=?^_`{|}~-]+$/i
const DOMAIN_LABEL = /^[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?$/i
const EMAIL_SEPARATORS = /[,;\n\r]+/

export interface ParsedEmailTokens {
  valid: string[]
  invalid: string[]
}

/** Validate a practical dot-atom email address suitable for an invitation. */
export function isValidEmailAddress(value: string): boolean {
  const email = value.trim()
  if (email.length === 0 || email.length > 254) return false

  const at = email.indexOf('@')
  if (at <= 0 || at !== email.lastIndexOf('@') || at === email.length - 1) return false

  const local = email.slice(0, at)
  const domain = email.slice(at + 1)
  if (local.length > 64 || local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false
  if (!local.split('.').every((atom) => atom.length > 0 && EMAIL_ATOM.test(atom))) return false

  const labels = domain.split('.')
  if (labels.length < 2 || labels.some((label) => label.length > 63 || !DOMAIN_LABEL.test(label))) return false
  const topLevelDomain = labels[labels.length - 1]
  return topLevelDomain.length >= 2 && /[A-Z]/i.test(topLevelDomain)
}

/** Split delimited input and classify every non-empty token without dropping invalid text. */
export function parseEmailTokens(value: string): ParsedEmailTokens {
  const valid: string[] = []
  const invalid: string[] = []
  for (const part of value.split(EMAIL_SEPARATORS).map((token) => token.trim()).filter(Boolean)) {
    ;(isValidEmailAddress(part) ? valid : invalid).push(part)
  }
  return { valid, invalid }
}

/** Merge accepted addresses while preserving spelling and first-entry order. */
export function mergeUniqueEmails(current: string[], additions: string[]): string[] {
  const result = [...current]
  const seen = new Set(current.map((email) => email.toLowerCase()))
  for (const email of additions) {
    const key = email.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    result.push(email)
  }
  return result
}

export function formatEmailTokens(tokens: string[]): string {
  return tokens.join(', ')
}
