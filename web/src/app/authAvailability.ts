// SPDX-License-Identifier: AGPL-3.0-or-later
import type { PublicAuthConfig } from '../api/types'

/** Only advertise sign-in and enrollment methods the deployment can serve. */
export function authAvailability(config: PublicAuthConfig | null) {
  return {
    sso: config?.oidcEnabled === true,
    passkey: config?.passkeysEnabled === true,
    signup: config?.signupMode === 'open' || config?.signupMode === 'domain',
  }
}
