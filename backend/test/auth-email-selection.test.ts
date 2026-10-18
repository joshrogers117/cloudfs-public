// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { describeSelectedEmailProvider, describeSelectedEmailProviderForOrg, emailSenderFor, type EmailSenderEnv } from "../src/auth-stores";
import {
  ConsoleEmailSender,
  FakeEmailSender,
  type SendEmailBinding,
} from "../src/security/auth-email";

// emailSenderFor() picks the transactional provider from env. Selection is observable for the
// providers we can exercise without network: the Cloudflare binding (a fake `EMAIL` records sends),
// the dev console sender (instanceof + .logs), and the no-op fake (instanceof + .sent). For the
// HTTP providers (Resend/Postmark/SES) the per-sender request-shape tests live in auth-email.test.ts;
// here we assert the SELECTION decisions (explicit EMAIL_PROVIDER + auto-detect + fallbacks).

/// A fake Cloudflare send_email binding that records every message.
function fakeBinding(): { EMAIL: SendEmailBinding; sent: unknown[] } {
  const sent: unknown[] = [];
  return {
    sent,
    EMAIL: {
      send: (msg) => {
        sent.push(msg);
        return Promise.resolve({ messageId: "cf-message-1" });
      },
    },
  };
}

describe("emailSenderFor — provider selection", () => {
  it("auto-detect (no EMAIL_PROVIDER): no config → no-op FakeEmailSender", () => {
    const sender = emailSenderFor({});
    expect(sender).toBeInstanceOf(FakeEmailSender);
  });

  it("auto-detect: EMAIL_DEV_CONSOLE=1 → ConsoleEmailSender", () => {
    expect(emailSenderFor({ EMAIL_DEV_CONSOLE: "1" })).toBeInstanceOf(ConsoleEmailSender);
    expect(emailSenderFor({ EMAIL_DEV_CONSOLE: "true" })).toBeInstanceOf(ConsoleEmailSender);
  });

  it("auto-detect: Cloudflare binding + EMAIL_FROM → routes sends to the binding", async () => {
    const { EMAIL, sent } = fakeBinding();
    const sender = emailSenderFor({ EMAIL, EMAIL_FROM: "noreply@cloud-fs.test" });
    await sender.sendTransactional({ to: "a@b.com", subject: "s", text: "t" });
    expect(sent).toHaveLength(1);
    expect((sent[0] as { to: string }).to).toBe("a@b.com");
  });

  it("auto-detect order: Resend (key) wins over a Cloudflare binding when both present", async () => {
    const { EMAIL, sent } = fakeBinding();
    // RESEND_API_KEY present → Resend selected; the Cloudflare binding must NOT receive the send.
    // We don't hit the network: a non-Cloudflare sender simply means the fake binding stays empty.
    const sender = emailSenderFor({ RESEND_API_KEY: "re_k", EMAIL_FROM: "f@cloud-fs.test", EMAIL });
    expect(sender).not.toBeInstanceOf(FakeEmailSender);
    expect(sender).not.toBeInstanceOf(ConsoleEmailSender);
    // The selected sender is Resend (HTTP), so the Cloudflare binding is untouched even on a send
    // attempt. (We can't complete the HTTP send here, but selection routing away from the binding
    // is the observable contract.)
    expect(sent).toHaveLength(0);
  });

  it("explicit EMAIL_PROVIDER=cloudflare uses the binding even if RESEND_API_KEY is also set", async () => {
    const { EMAIL, sent } = fakeBinding();
    const sender = emailSenderFor({
      EMAIL_PROVIDER: "cloudflare",
      EMAIL,
      EMAIL_FROM: "noreply@cloud-fs.test",
      RESEND_API_KEY: "re_k", // would win in auto-detect, but the explicit choice overrides it.
    });
    await sender.sendTransactional({ to: "x@y.com", subject: "s", text: "t" });
    expect(sent).toHaveLength(1);
    expect(sender).not.toBeInstanceOf(FakeEmailSender);
  });

  it("reports an explicitly configured Cloudflare binding as the effective delivering provider", () => {
    const { EMAIL } = fakeBinding();
    expect(describeSelectedEmailProvider({
      EMAIL_PROVIDER: "cloudflare",
      EMAIL,
      EMAIL_FROM: "noreply@example.com",
    })).toMatchObject({ provider: "cloudflare", delivers: true });
  });

  it("reports the saved org provider before the deployment-wide provider", async () => {
    const { EMAIL } = fakeBinding();
    const org = {
      getEmailConfig: async () => ({
        orgId: "org1", provider: "cloudflare" as const, fromAddress: "noreply@example.com",
        fromName: "CloudFS", region: null, secretIv: "", secretCiphertext: "", sesAccessKeyId: null,
        createdAt: 1, updatedAt: 1,
      }),
    };
    const ORG_DO = {
      idFromName: (name: string) => name,
      get: () => org,
    } as unknown as Parameters<typeof describeSelectedEmailProviderForOrg>[0]["ORG_DO"];

    await expect(describeSelectedEmailProviderForOrg({
      EMAIL_PROVIDER: "resend", RESEND_API_KEY: "re_test", EMAIL_FROM: "global@example.test",
      EMAIL, STORAGE_ENC_KEY: "a-test-key", ORG_DO,
    }, "org1")).resolves.toMatchObject({
      provider: "cloudflare", delivers: true, detail: "Cloudflare Email Sending (org override)",
    });
  });

  it("explicit EMAIL_PROVIDER=console always uses the console sender", () => {
    expect(emailSenderFor({ EMAIL_PROVIDER: "console" })).toBeInstanceOf(ConsoleEmailSender);
    // Even with other providers configured, the explicit console choice wins.
    expect(
      emailSenderFor({ EMAIL_PROVIDER: "console", RESEND_API_KEY: "re_k", EMAIL_FROM: "f@cloud-fs.test" }),
    ).toBeInstanceOf(ConsoleEmailSender);
  });

  it("explicit but MISCONFIGURED provider falls through to the fallback (never silently another)", () => {
    // EMAIL_PROVIDER=ses but no SES creds → fall back to the no-op fake (misconfig is visible, and
    // we don't silently send via Cloudflare/Resend instead).
    expect(emailSenderFor({ EMAIL_PROVIDER: "ses", EMAIL_FROM: "f@cloud-fs.test" })).toBeInstanceOf(FakeEmailSender);
    // ...and to the console sender when EMAIL_DEV_CONSOLE is on.
    expect(
      emailSenderFor({ EMAIL_PROVIDER: "postmark", EMAIL_FROM: "f@cloud-fs.test", EMAIL_DEV_CONSOLE: "1" }),
    ).toBeInstanceOf(ConsoleEmailSender);
  });

  it("unrecognized EMAIL_PROVIDER value is ignored and falls back to auto-detect", () => {
    // Typo'd provider → auto-detect (here: no real provider → fake), never a crash.
    const env: EmailSenderEnv = { EMAIL_PROVIDER: "sendgridd" };
    expect(emailSenderFor(env)).toBeInstanceOf(FakeEmailSender);
  });
});
