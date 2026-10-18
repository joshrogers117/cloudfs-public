// SPDX-License-Identifier: AGPL-3.0-or-later
// auth-config.test.ts — the PLUGGABLE deployment auth-provider config (auth-config.ts +
// security/storage-crypto.ts). Unit-level: the HTTP handler over an in-memory store fake, the
// public/owner projections, the Clerk-preset discovery in /validate + resolveOidcConfigFromRow,
// and the secret-never-leaks guarantee.
//
// Covers (from the task brief):
//   - config CRUD via the handler (GET null when unset; PUT seals; GET returns SAFE shape; DELETE 204)
//   - secret-never-leaks: clientSecret never appears in any response body; stored row keeps it
//     AES-256-GCM encrypted (iv/ct) and seal→open round-trips
//   - clerk-preset discovery: /validate fetches `.well-known/openid-configuration` (injected fetch)
//     and resolveOidcConfigFromRow derives the authorize/token/jwks endpoints from the issuer
//   - the public-config endpoint shape (`{ mode, oidcEnabled, providerLabel? }`)
//   - role gating: non-admin is 403 on every auth-config route

import { describe, it, expect } from "vitest";
import {
  handleAuthConfigRequest,
  handlePublicAuthConfig,
  toAuthConfig,
  toPublicAuthConfig,
  resolveOidcConfigFromRow,
  type AuthConfigStore,
} from "../src/auth-config";
import type { AuthConfigRow } from "../src/directory-do";
import type { FetchLike } from "../src/security/oidc";
import { openSecret } from "../src/security/storage-crypto";

const ENC_KEY = "qbQu5yxLGHtdYKJ6z84mem+Mn5vo5PdUJvawJ0T6D8E="; // 32 bytes base64 (test-only)
const CLERK_ISSUER = "https://clerk.acme.test";
const CLIENT_SECRET = "sk_test_SUPERSECRET_clerk_value";

// ---- in-memory store fake (the slice auth-config.ts needs) ----------------------------
function makeStore(): AuthConfigStore & { _row: AuthConfigRow | null } {
  const state: { row: AuthConfigRow | null } = { row: null };
  return {
    get _row() {
      return state.row;
    },
    async getAuthConfig() {
      return state.row;
    },
    async putAuthConfig(input) {
      const now = Date.now();
      state.row = {
        mode: input.mode,
        preset: input.preset,
        issuer: input.issuer,
        clientId: input.clientId,
        allowedDomains: input.allowedDomains,
        autoProvision: input.autoProvision,
        providerLabel: input.providerLabel,
        secretIv: input.secretIv,
        secretCiphertext: input.secretCiphertext,
        createdAt: state.row?.createdAt ?? now,
        updatedAt: now,
      };
      return state.row;
    },
    async deleteAuthConfig() {
      const had = state.row !== null;
      state.row = null;
      return had;
    },
  };
}

// ---- mock IdP discovery doc (Clerk shape) ---------------------------------------------
function discoveryFetch(over: { status?: number } = {}): FetchLike {
  return async (input: string) => {
    if (input.endsWith("/.well-known/openid-configuration")) {
      if (over.status && over.status >= 400) return new Response("nope", { status: over.status });
      return new Response(
        JSON.stringify({
          issuer: CLERK_ISSUER,
          authorization_endpoint: `${CLERK_ISSUER}/oauth/authorize`,
          token_endpoint: `${CLERK_ISSUER}/oauth/token`,
          jwks_uri: `${CLERK_ISSUER}/.well-known/jwks.json`,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response("not found", { status: 404 });
  };
}

function req(method: string, body?: unknown): Request {
  return new Request("https://gw.local/v1/orgs/o/auth-config", {
    method,
    headers: { "content-type": "application/json" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
}

describe("auth-config CRUD via the handler", () => {
  it("GET is null when unset; PUT (oidc/clerk) seals + returns SAFE shape; DELETE 204 reverts", async () => {
    const store = makeStore();
    // B11: an oidc PUT now runs issuer discovery first (rejects an unreachable IdP), so
    // the handler needs a discovery fetch — the mock stands in for a reachable IdP.
    const deps = { store, encKey: ENC_KEY, fetchImpl: discoveryFetch() };

    const init = await handleAuthConfigRequest(req("GET"), ["auth-config"], true, deps);
    expect(init!.status).toBe(200);
    expect(await init!.json()).toEqual({ config: null });

    const put = await handleAuthConfigRequest(
      req("PUT", {
        mode: "oidc",
        oidc: { preset: "clerk", issuer: CLERK_ISSUER, clientId: "cid-123", clientSecret: CLIENT_SECRET, allowedDomains: ["acme.test"], autoProvision: true },
      }),
      ["auth-config"],
      true,
      deps,
    );
    expect(put!.status).toBe(200);
    const putText = await put!.clone().text();
    expect(putText).not.toContain(CLIENT_SECRET); // secret never leaks
    expect(await put!.json()).toEqual({
      mode: "oidc",
      oidc: { preset: "clerk", issuer: CLERK_ISSUER, clientId: "cid-123", allowedDomains: ["acme.test"], autoProvision: true, configured: true },
    });

    // the STORED row keeps the secret AES-256-GCM encrypted, and seal→open round-trips
    expect(store._row!.secretCiphertext).not.toBe("");
    expect(store._row!.secretCiphertext).not.toContain(CLIENT_SECRET);
    expect(await openSecret(ENC_KEY, { iv: store._row!.secretIv, ciphertext: store._row!.secretCiphertext })).toBe(CLIENT_SECRET);

    const got = await handleAuthConfigRequest(req("GET"), ["auth-config"], true, deps);
    expect((await got!.clone().text())).not.toContain(CLIENT_SECRET);
    expect((await got!.json() as any).config.oidc.clientId).toBe("cid-123");

    const del = await handleAuthConfigRequest(req("DELETE"), ["auth-config"], true, deps);
    expect(del!.status).toBe(204);
    const after = await handleAuthConfigRequest(req("GET"), ["auth-config"], true, deps);
    expect(await after!.json()).toEqual({ config: null });
  });

  it("editing the same issuer/clientId without resending the secret RETAINS the stored envelope", async () => {
    const store = makeStore();
    const deps = { store, encKey: ENC_KEY, fetchImpl: discoveryFetch() };
    await handleAuthConfigRequest(
      req("PUT", { mode: "oidc", oidc: { preset: "okta", issuer: "https://acme.okta.com", clientId: "cid", clientSecret: CLIENT_SECRET } }),
      ["auth-config"], true, deps,
    );
    const iv1 = store._row!.secretIv, ct1 = store._row!.secretCiphertext;

    // edit allowedDomains only (no clientSecret) → secret retained
    const edit = await handleAuthConfigRequest(
      req("PUT", { mode: "oidc", oidc: { preset: "okta", issuer: "https://acme.okta.com", clientId: "cid", allowedDomains: ["acme.com"] } }),
      ["auth-config"], true, deps,
    );
    expect(edit!.status).toBe(200);
    expect(store._row!.secretIv).toBe(iv1);
    expect(store._row!.secretCiphertext).toBe(ct1);
    expect(await openSecret(ENC_KEY, { iv: store._row!.secretIv, ciphertext: store._row!.secretCiphertext })).toBe(CLIENT_SECRET);
  });

  it("builtin mode stores no oidc block; switching to builtin projects to { mode }", async () => {
    const store = makeStore();
    const deps = { store, encKey: ENC_KEY };
    const put = await handleAuthConfigRequest(req("PUT", { mode: "builtin" }), ["auth-config"], true, deps);
    expect(await put!.json()).toEqual({ mode: "builtin" });
    const got = await handleAuthConfigRequest(req("GET"), ["auth-config"], true, deps);
    expect(await got!.json()).toEqual({ config: { mode: "builtin" } });
  });

  it("rejects a bad mode / bad preset / missing secret / missing issuer with 400", async () => {
    const store = makeStore();
    const deps = { store, encKey: ENC_KEY };
    const badMode = await handleAuthConfigRequest(req("PUT", { mode: "saml" }), ["auth-config"], true, deps);
    expect(badMode!.status).toBe(400);
    const badPreset = await handleAuthConfigRequest(
      req("PUT", { mode: "oidc", oidc: { preset: "saml2", issuer: "https://x.test", clientId: "c", clientSecret: "s" } }),
      ["auth-config"], true, deps,
    );
    expect(badPreset!.status).toBe(400);
    const noSecret = await handleAuthConfigRequest(
      req("PUT", { mode: "oidc", oidc: { preset: "google", issuer: "https://accounts.google.com", clientId: "c" } }),
      ["auth-config"], true, deps,
    );
    expect(noSecret!.status).toBe(400);
    const badIssuer = await handleAuthConfigRequest(
      req("PUT", { mode: "oidc", oidc: { preset: "google", issuer: "ftp://nope", clientId: "c", clientSecret: "s" } }),
      ["auth-config"], true, deps,
    );
    expect(badIssuer!.status).toBe(400);
  });

  it("a non-admin caller is 403 on GET / PUT / DELETE / validate", async () => {
    const store = makeStore();
    const deps = { store, encKey: ENC_KEY };
    for (const r of [req("GET"), req("PUT", { mode: "builtin" }), req("DELETE")]) {
      const res = await handleAuthConfigRequest(r, ["auth-config"], false, deps);
      expect(res!.status).toBe(403);
    }
    const val = await handleAuthConfigRequest(
      new Request("https://gw.local/v1/orgs/o/auth-config/validate", { method: "POST", body: JSON.stringify({ issuer: CLERK_ISSUER }) }),
      ["auth-config", "validate"], false, deps,
    );
    expect(val!.status).toBe(403);
  });
});

// Audit B11 — SSO lockout guard: an oidc/both PUT whose issuer fails discovery is REJECTED
// (400), so a typo'd / dead IdP can never be persisted as the live auth mode and lock out
// every user (including the admin). Pre-fix mode='oidc' took effect immediately with no check.
describe("B11: oidc PUT rejects an unreachable issuer (lockout guard)", () => {
  it("returns 400 oidc_issuer_unreachable and does NOT persist the config", async () => {
    const store = makeStore();
    const deps = { store, encKey: ENC_KEY, fetchImpl: discoveryFetch({ status: 500 }) };
    const res = await handleAuthConfigRequest(
      req("PUT", { mode: "oidc", oidc: { preset: "clerk", issuer: CLERK_ISSUER, clientId: "cid", clientSecret: CLIENT_SECRET } }),
      ["auth-config"], true, deps,
    );
    expect(res!.status).toBe(400);
    expect((await res!.json() as any).error).toBe("oidc_issuer_unreachable");
    expect(store._row).toBeNull(); // nothing persisted — the deployment is not wedged
  });

  it("a reachable issuer is accepted (200)", async () => {
    const store = makeStore();
    const deps = { store, encKey: ENC_KEY, fetchImpl: discoveryFetch() };
    const res = await handleAuthConfigRequest(
      req("PUT", { mode: "oidc", oidc: { preset: "clerk", issuer: CLERK_ISSUER, clientId: "cid", clientSecret: CLIENT_SECRET } }),
      ["auth-config"], true, deps,
    );
    expect(res!.status).toBe(200);
  });
});

describe("auth-config /validate — clerk-preset discovery", () => {
  it("fetches the issuer discovery doc and returns the derived endpoints", async () => {
    const store = makeStore();
    const deps = { store, encKey: ENC_KEY, fetchImpl: discoveryFetch() };
    const res = await handleAuthConfigRequest(
      new Request("https://gw.local/v1/orgs/o/auth-config/validate", { method: "POST", body: JSON.stringify({ issuer: CLERK_ISSUER }) }),
      ["auth-config", "validate"], true, deps,
    );
    expect(res!.status).toBe(200);
    const body = (await res!.json()) as any;
    expect(body.valid).toBe(true);
    expect(body.endpoints).toEqual({
      issuer: CLERK_ISSUER,
      authorizationEndpoint: `${CLERK_ISSUER}/oauth/authorize`,
      tokenEndpoint: `${CLERK_ISSUER}/oauth/token`,
      jwksUri: `${CLERK_ISSUER}/.well-known/jwks.json`,
    });
  });

  it("a discovery failure maps to { valid:false, error } (never throws)", async () => {
    const store = makeStore();
    const deps = { store, encKey: ENC_KEY, fetchImpl: discoveryFetch({ status: 500 }) };
    const res = await handleAuthConfigRequest(
      new Request("https://gw.local/v1/orgs/o/auth-config/validate", { method: "POST", body: JSON.stringify({ issuer: CLERK_ISSUER }) }),
      ["auth-config", "validate"], true, deps,
    );
    expect(res!.status).toBe(200);
    expect((await res!.json() as any).valid).toBe(false);
  });

  it("a non-https issuer is rejected without any fetch", async () => {
    const store = makeStore();
    let fetched = false;
    const fetchImpl: FetchLike = async () => { fetched = true; return new Response("x"); };
    const res = await handleAuthConfigRequest(
      new Request("https://gw.local/v1/orgs/o/auth-config/validate", { method: "POST", body: JSON.stringify({ issuer: "http://insecure.test" }) }),
      ["auth-config", "validate"], true, { store, encKey: ENC_KEY, fetchImpl },
    );
    expect((await res!.json() as any).valid).toBe(false);
    expect(fetched).toBe(false);
  });
});

describe("resolveOidcConfigFromRow — Clerk preset derives endpoints from discovery", () => {
  it("decrypts the client secret + fills authorize/token/jwks from the issuer", async () => {
    const store = makeStore();
    await handleAuthConfigRequest(
      req("PUT", { mode: "both", oidc: { preset: "clerk", issuer: CLERK_ISSUER, clientId: "cid-xyz", clientSecret: CLIENT_SECRET, allowedDomains: ["acme.test"], autoProvision: true } }),
      ["auth-config"], true, { store, encKey: ENC_KEY, fetchImpl: discoveryFetch() },
    );
    const row = store._row!;
    const cfg = await resolveOidcConfigFromRow(row, {
      encKey: ENC_KEY,
      redirectUri: "https://gw.example/v1/auth/oidc/callback",
      orgId: "org1",
      fetchImpl: discoveryFetch(),
    });
    expect(cfg).not.toBeNull();
    expect(cfg!.clientId).toBe("cid-xyz");
    expect(cfg!.clientSecret).toBe(CLIENT_SECRET); // decrypted server-side
    expect(cfg!.authorizationEndpoint).toBe(`${CLERK_ISSUER}/oauth/authorize`);
    expect(cfg!.tokenEndpoint).toBe(`${CLERK_ISSUER}/oauth/token`);
    expect(cfg!.jwksUri).toBe(`${CLERK_ISSUER}/.well-known/jwks.json`);
    expect(cfg!.redirectUri).toBe("https://gw.example/v1/auth/oidc/callback");
    expect(cfg!.orgId).toBe("org1");
    expect(cfg!.allowedDomains).toEqual(["acme.test"]);
    expect(cfg!.autoProvision).toBe(true);
  });

  it("returns null for a builtin row (no OIDC)", async () => {
    const row: AuthConfigRow = {
      mode: "builtin", preset: null, issuer: null, clientId: null, allowedDomains: null,
      autoProvision: false, providerLabel: null, secretIv: "", secretCiphertext: "",
      createdAt: 1, updatedAt: 1,
    };
    const cfg = await resolveOidcConfigFromRow(row, { encKey: ENC_KEY, redirectUri: "x", orgId: "o" });
    expect(cfg).toBeNull();
  });
});

describe("public-config endpoint shape ({ mode, oidcEnabled, providerLabel? })", () => {
  it("built-in default when no row: { mode:'builtin', oidcEnabled:false }", async () => {
    const store = makeStore();
    const res = await handlePublicAuthConfig(store, null);
    expect(await res.json()).toEqual({ mode: "builtin", oidcEnabled: false });
  });

  it("oidc row → oidcEnabled:true + the preset's default providerLabel; no secret/clientId leak", async () => {
    const store = makeStore();
    await handleAuthConfigRequest(
      req("PUT", { mode: "oidc", oidc: { preset: "google", issuer: "https://accounts.google.com", clientId: "cid", clientSecret: CLIENT_SECRET } }),
      ["auth-config"], true, { store, encKey: ENC_KEY },
    );
    const res = await handlePublicAuthConfig(store, null);
    const text = await res.clone().text();
    expect(text).not.toContain(CLIENT_SECRET);
    expect(text).not.toContain("cid"); // public shape never exposes the clientId
    expect(await res.json()).toEqual({ mode: "oidc", oidcEnabled: true, providerLabel: "Google" });
  });

  it("falls back to the supplied env default when there is no row", async () => {
    const store = makeStore();
    const res = await handlePublicAuthConfig(store, { mode: "both", oidcEnabled: true, providerLabel: "Single Sign-On" });
    expect(await res.json()).toEqual({ mode: "both", oidcEnabled: true, providerLabel: "Single Sign-On" });
  });
});

describe("projection helpers", () => {
  it("toPublicAuthConfig uses an explicit providerLabel when stored", () => {
    const row: AuthConfigRow = {
      mode: "both", preset: "entra", issuer: "https://login.microsoftonline.com/x/v2.0", clientId: "c",
      allowedDomains: JSON.stringify(["acme.com"]), autoProvision: false, providerLabel: "Acme SSO",
      secretIv: "iv", secretCiphertext: "ct", createdAt: 1, updatedAt: 1,
    };
    expect(toPublicAuthConfig(row)).toEqual({ mode: "both", oidcEnabled: true, providerLabel: "Acme SSO" });
    expect(toAuthConfig(row).oidc!.preset).toBe("entra");
  });
});
