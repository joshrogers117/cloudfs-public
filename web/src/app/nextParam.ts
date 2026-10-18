/*
 * ?next= handling for the sign-in redirect (auth-spec §1.3 / W2).
 *
 * /device/authorize (and any future auth-required standalone page) bounces a
 * signed-out visitor to `/signin?next=<urlencoded current url>`; after the user
 * authenticates — through the password step AND any TOTP/passkey step (the URL,
 * and therefore `next`, is untouched by the in-page MFA step) — AuthLayout
 * navigates to `next` instead of /filespaces.
 *
 * `sanitizeNext` is the open-redirect guard: only LOCAL paths ("/x…", never
 * absolute URLs or protocol-relative "//host") are honored.
 */

/** Validate a ?next= target. Returns the path to navigate to, or null. */
export function sanitizeNext(raw: string | null): string | null {
  if (!raw) return null
  if (!raw.startsWith('/') || raw.startsWith('//')) return null
  // Reject whitespace (defense against smuggled / mangled targets); the
  // leading-slash checks above are the actual open-redirect guard.
  if (/\s/.test(raw)) return null
  return raw
}

/** Build the /signin redirect that returns to `pathname+search` after login. */
export function signinWithNext(pathname: string, search: string): string {
  return `/signin?next=${encodeURIComponent(`${pathname}${search}`)}`
}
