// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { authAvailability } from '../src/app/authAvailability.ts'

test('unconfigured and closed deployments do not advertise unavailable auth methods', () => {
  assert.deepEqual(authAvailability(null), { sso: false, passkey: false, signup: false })
  assert.deepEqual(authAvailability({ mode: 'builtin', oidcEnabled: false, signupMode: 'closed', passkeysEnabled: false }), { sso: false, passkey: false, signup: false })
})
test('invited users are directed to their invitation, open enrollment is explicit', () => {
  assert.equal(authAvailability({ mode: 'builtin', signupMode: 'invite' }).signup, false)
  assert.equal(authAvailability({ mode: 'builtin', signupMode: 'open' }).signup, true)
  assert.equal(authAvailability({ mode: 'builtin', signupMode: 'domain' }).signup, true)
})
test('enabled methods remain available independently', () => {
  assert.deepEqual(authAvailability({ oidcEnabled: true, passkeysEnabled: true }), { sso: true, passkey: true, signup: false })
})
test('passkey setup is only available when configured, independently of self-service signup', () => {
  const openWithoutPasskeys = authAvailability({ mode: 'builtin', signupMode: 'open', passkeysEnabled: false })
  assert.deepEqual(openWithoutPasskeys, { sso: false, passkey: false, signup: true })
  const inviteWithPasskeys = authAvailability({ mode: 'builtin', signupMode: 'invite', passkeysEnabled: true })
  assert.deepEqual(inviteWithPasskeys, { sso: false, passkey: true, signup: false })
})
