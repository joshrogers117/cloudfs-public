// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { connectLink, gatewayOrigin } from '../src/pages/join/getTheAppLinks.ts'

test('native connect handoff uses the configured gateway origin', () => {
  assert.equal(gatewayOrigin('https://api.example.test/path', 'https://console.example.test'), 'https://api.example.test')
  assert.equal(
    connectLink('https://api.example.test', 'https://console.example.test'),
    'cloudfs://connect?server=https%3A%2F%2Fapi.example.test',
  )
})

test('older and malformed public config falls back to the current HTTP(S) origin', () => {
  assert.equal(gatewayOrigin(undefined, 'https://console.example.test'), 'https://console.example.test')
  assert.equal(gatewayOrigin('javascript:alert(1)', 'http://localhost:5173'), 'http://localhost:5173')
  assert.equal(gatewayOrigin('http://api.example.test', 'https://console.example.test'), 'http://api.example.test')
  assert.equal(gatewayOrigin('https://user:pass@evil.example.test', 'https://console.example.test'), 'https://console.example.test')
  assert.equal(gatewayOrigin('https://also-bad.example.test', 'not a URL'), 'https://also-bad.example.test')
})
