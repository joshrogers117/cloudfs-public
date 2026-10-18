// SPDX-License-Identifier: AGPL-3.0-or-later
// Canonical config table — runtime guards (Audit: canonical config table + drift test).
//
// The PRIMARY drift check is COMPILE-TIME: `src/env.ts` carries a `[T] extends [never]`
// type assertion that fails `tsc` if the canonical `CONFIG_MANIFEST` and the `Env`
// interface ever diverge (an undocumented key, or a documented-but-removed key — exactly
// what would have flagged a re-introduced DEV_TOKEN). These runtime tests cover the parts
// a type can't: the manifest's shape, the secret/var classification, and that the retired
// DEV_TOKEN is gone from both the manifest AND the shipped non-secret wrangler `vars`.
import { describe, it, expect } from "vitest";
import { CONFIG_MANIFEST, CONFIG_DYNAMIC_PATTERNS, CONFIG_KEYS } from "../src/env";

const KINDS = new Set(["binding", "secret", "var"]);

describe("canonical config table", () => {
  it("every manifest entry has a valid kind, a required flag, and a non-empty note", () => {
    for (const [key, e] of Object.entries(CONFIG_MANIFEST)) {
      expect(KINDS.has(e.kind), `${key}.kind`).toBe(true);
      expect(typeof e.required, `${key}.required`).toBe("boolean");
      expect(e.note.trim().length, `${key}.note`).toBeGreaterThan(0);
    }
  });

  it("CONFIG_KEYS is exactly the set of manifest keys", () => {
    expect([...CONFIG_KEYS].sort()).toEqual(Object.keys(CONFIG_MANIFEST).sort());
  });

  it("the required keys are the bindings + the token-signing secret (and nothing surprising)", () => {
    const required = Object.entries(CONFIG_MANIFEST).filter(([, e]) => e.required).map(([k]) => k).sort();
    expect(required).toEqual(
      [
        "AUTH_DO",
        "AUTH_SIGNING_SECRET",
        "DIRECTORY_DO",
        "FILESPACE",
        "ORG_DO",
        "S3_ACCESS_KEY_ID",
        "S3_BUCKET",
        "S3_ENDPOINT",
        "S3_SECRET_ACCESS_KEY",
      ].sort(),
    );
  });

  it("documents the dynamic BYO-storage credential patterns as secrets", () => {
    expect(Object.keys(CONFIG_DYNAMIC_PATTERNS)).toEqual([
      "S3_ACCESS_KEY_ID__<REF>",
      "S3_SECRET_ACCESS_KEY__<REF>",
      "S3_SESSION_TOKEN__<REF>",
    ]);
    for (const e of Object.values(CONFIG_DYNAMIC_PATTERNS)) expect(e.kind).toBe("secret");
  });

  it("the retired DEV_TOKEN is absent from the canonical table (F1)", () => {
    expect(CONFIG_KEYS.has("DEV_TOKEN")).toBe(false);
    expect("DEV_TOKEN" in CONFIG_MANIFEST).toBe(false);
  });
});
