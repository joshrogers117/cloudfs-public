// SPDX-License-Identifier: AGPL-3.0-or-later

/** Encode locally. The enrollment secret must never reach an image service. */
export async function renderTotpQr(uri: string): Promise<string> {
  const parsed = new URL(uri)
  if (parsed.protocol !== 'otpauth:' || parsed.hostname !== 'totp' ||
      !parsed.searchParams.get('secret') || !parsed.pathname.slice(1)) {
    throw new Error('Invalid authenticator enrollment URI')
  }
  const { default: QRCode } = await import('qrcode')
  return QRCode.toDataURL(uri, {
    width: 240,
    margin: 4,
    errorCorrectionLevel: 'M',
    color: { dark: '#000000ff', light: '#ffffffff' },
  })
}
