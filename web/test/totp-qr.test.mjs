// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import { test } from 'node:test'
import jsQR from 'jsqr'
import { PNG } from 'pngjs'
import { renderTotpQr } from '../src/pages/settings/totpQr.ts'

test('authenticator image decodes to the exact enrollment URI locally', async () => {
  const uri = 'otpauth://totp/CloudFS%3Aalex%2Bteam%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=CloudFS&algorithm=SHA1&digits=6&period=30'
  const dataUrl = await renderTotpQr(uri)
  assert.ok(dataUrl.startsWith('data:image/png;base64,'))
  const png = PNG.sync.read(Buffer.from(dataUrl.split(',')[1], 'base64'))
  assert.equal(png.width, 240)
  const decoded = jsQR(new Uint8ClampedArray(png.data), png.width, png.height)
  assert.equal(decoded?.data, uri)
})

test('a different secret produces a different scannable enrollment', async () => {
  const uri = 'otpauth://totp/Studio%3A%CE%91%CE%BB%CE%AD%CE%BE?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Studio'
  const png = PNG.sync.read(Buffer.from((await renderTotpQr(uri)).split(',')[1], 'base64'))
  assert.equal(jsQR(new Uint8ClampedArray(png.data), png.width, png.height)?.data, uri)
})

test('invalid enrollment cannot turn into an unrelated QR link', async () => {
  for (const uri of ['https://example.com/', 'otpauth://hotp/test?secret=TEST', 'otpauth://totp/test', 'otpauth://totp/?secret=TEST']) {
    await assert.rejects(renderTotpQr(uri), /Invalid authenticator/)
  }
})
