// SPDX-License-Identifier: AGPL-3.0-or-later

/** Resolve the API server used by the native app's connect handoff. */
export function gatewayOrigin(configured: string | undefined, currentOrigin: string): string {
  for (const candidate of [configured, currentOrigin]) {
    if (!candidate) continue
    try {
      const url = new URL(candidate)
      // Match LoginValidation.gatewayURLInvalid in the native app: it accepts a
      // full http(s) URL with a host. Credentials are rejected here as an extra
      // precaution before generating a shareable custom-protocol URL.
      if (
        (url.protocol === 'https:' || url.protocol === 'http:') &&
        url.hostname &&
        !url.username &&
        !url.password
      ) {
        return url.origin
      }
    } catch {
      // Try the page origin if a stale or malformed public value arrives.
    }
  }
  return ''
}

export function connectLink(configured: string | undefined, currentOrigin: string): string {
  return `cloudfs://connect?server=${encodeURIComponent(gatewayOrigin(configured, currentOrigin))}`
}
