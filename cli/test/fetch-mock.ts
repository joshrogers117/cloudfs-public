// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * A tiny mocked fetch shaped per backend/API.md. It records every request and
 * returns canned responses keyed by `METHOD <path>` (no query string). No live
 * server is involved. Used to assert request shape + drive error→exit-code tests.
 */
import type { FetchLike } from "../src/gateway/http.js";

export interface RecordedRequest {
  method: string;
  url: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  body: any;
}

export interface CannedResponse {
  status?: number; // default 200
  json?: unknown; // response body (object/array)
  text?: string; // raw body override
  headers?: Record<string, string>;
}

/** A handler may be a static response or a function of the request. */
export type Handler = CannedResponse | ((req: RecordedRequest) => CannedResponse);

export interface MockFetch {
  fetch: FetchLike;
  requests: RecordedRequest[];
  /** Last request, for terse assertions. */
  last(): RecordedRequest;
}

export function makeFetch(routes: Record<string, Handler>): MockFetch {
  const requests: RecordedRequest[] = [];

  const fetch: FetchLike = async (input, init) => {
    const u = new URL(input);
    const method = (init?.method ?? "GET").toUpperCase();
    const query: Record<string, string> = {};
    u.searchParams.forEach((v, k) => (query[k] = v));
    const req: RecordedRequest = {
      method,
      url: input,
      path: u.pathname,
      query,
      headers: (init?.headers as Record<string, string>) ?? {},
      body: init?.body ? JSON.parse(init.body) : undefined,
    };
    requests.push(req);

    const key = `${method} ${u.pathname}`;
    const handler = routes[key];
    if (!handler) {
      return resp({ status: 404, json: { error: "not found", reason: `no mock for ${key}` } });
    }
    const r = typeof handler === "function" ? handler(req) : handler;
    return resp(r);
  };

  return { fetch, requests, last: () => requests[requests.length - 1] };
}

function resp(r: CannedResponse): Awaited<ReturnType<FetchLike>> {
  const status = r.status ?? 200;
  const bodyText = r.text ?? (r.json !== undefined ? JSON.stringify(r.json) : "");
  const headers = new Map(Object.entries(r.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name: string) => headers.get(name.toLowerCase()) ?? null },
    text: async () => bodyText,
    json: async () => (bodyText ? JSON.parse(bodyText) : undefined),
  };
}

/**
 * A throwaway HS256-ish token whose payload decodes to the given claims. The
 * signature is bogus (the gateway verifies; the client only decodes for display
 * and org routing), which is exactly the client-side behaviour we exercise.
 */
export function fakeToken(claims: Record<string, unknown>): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}.sig`;
}
