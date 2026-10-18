import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-plugin";

// Cloudflare Vitest plugin API: the worker config is passed to the
// cloudflareTest() plugin. Tests run inside the real workerd runtime (Miniflare) —
// Durable Objects, SQLite, and bindings behave as in production. No account, no network.
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      // TEST-ONLY env override (merged over wrangler.jsonc `vars`): run scrypt at a tiny,
      // FAST cost so the auth flows (signup/login/change/reset) don't spend seconds per hash in
      // the workerd test pool. Production keeps the Workers-compatible default N=2^15 (32768); this
      // exercises the operator-tunable `SCRYPT_COST_N` knob end-to-end. N MUST be a power of two.
      miniflare: {
        bindings: { SCRYPT_COST_N: "2", STORAGE_VERIFY_UPLOADS: "0" },
      },
    }),
  ],
});
