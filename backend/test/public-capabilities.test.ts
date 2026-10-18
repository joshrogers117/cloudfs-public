// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { passkeysConfigured } from '../src/auth-wiring';
import type { Env } from '../src/env';
const e = env as Env;
describe('public sign-in capabilities', () => {
  it('reports disabled signup on HTTPS when open signup is not explicitly allowed', async () => {
    const previous = e.SIGNUP_OPEN_ON_HTTPS;
    e.SIGNUP_OPEN_ON_HTTPS = undefined;
    try {
    const res = await SELF.fetch('https://gw.local/v1/auth/config/public');
    const body = await res.json() as { signupMode: string; passkeysEnabled: boolean };
    expect(body.signupMode).toBe('closed');
    expect(body.passkeysEnabled).toBe(true);
    } finally { e.SIGNUP_OPEN_ON_HTTPS = previous; }
  });
  it('requires a usable passkey RP and browser origin', () => {
    expect(passkeysConfigured({ ...e, WEBAUTHN_RP_ID: undefined })).toBe(false);
    expect(passkeysConfigured({ ...e, WEBAUTHN_RP_ID: 'gateway.test', WEBAUTHN_ORIGIN: '' })).toBe(false);
    expect(passkeysConfigured({ ...e, WEBAUTHN_RP_ID: 'gateway.test', WEBAUTHN_ORIGIN: 'https://unrelated.test' })).toBe(false);
    expect(passkeysConfigured({ ...e, WEBAUTHN_RP_ID: 'gateway.test', WEBAUTHN_ORIGIN: 'https://console.gateway.test' })).toBe(true);
  });
});
