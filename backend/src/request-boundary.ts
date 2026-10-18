// SPDX-License-Identifier: AGPL-3.0-or-later
// Keep oversized requests and unexpected failures outside the routing/auth layer.
// File bytes normally travel directly to S3; this limit is for metadata manifests.
import { AuthError } from "./security/auth";
export const MAX_API_BODY_BYTES = 16 * 1024 * 1024;
import { MAX_STREAM_BODY_BYTES } from "./metadata/stream-limits";

function failure(error: string, status: number, extra: Record<string, unknown> = {}): Response {
  return Response.json({ error, ...extra }, { status });
}

/** Log only fixed categories. URLs, query strings, IDs, errors and credentials can
 * contain private data and must never be copied into operational logs. */
export function requestCategory(path: string): string {
  const p = path.split("/").filter(Boolean);
  if (p[0] !== "v1") return "other";
  if (["auth", "setup", "bootstrap", "health", "admin"].includes(p[1])) return p[1];
  if (p[1] === "orgs") return "workspace";
  if (p[1] === "filespaces") return "filespace";
  return "api";
}

export async function requestBoundary(
  req: Request,
  handler: (request: Request) => Promise<Response>,
): Promise<Response> {
  const started = Date.now();
  const requestId = crypto.randomUUID();
  const path = new URL(req.url).pathname;
  const limit = /^\/v1\/filespaces\/[^/]+\/items\/[^/]+\/streams\/[^/]+$/.test(path)
    ? MAX_STREAM_BODY_BYTES : MAX_API_BODY_BYTES;
  let tooLarge = false;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let response: Response;
  try {
    const declared = req.headers.get("content-length");
    if (declared !== null && (!/^\d+$/.test(declared) || !Number.isSafeInteger(Number(declared)))) {
      response = failure("invalid_content_length", 400);
    } else if (declared !== null && Number(declared) > limit) {
      response = failure("body_too_large", 413, { maxBytes: limit });
    } else {
      let bounded = req;
      if (req.body) {
        reader = req.body.getReader();
        // Consume with a ceiling before handing a body to route-specific parsers.
        // In particular, do not error a forwarded Request stream: workerd can
        // surface that transport error as an unhandled rejection after a response.
        const chunks: Uint8Array[] = [];
        let bytes = 0;
        while (true) {
          const next = await reader.read();
          if (next.done) break;
          bytes += next.value.byteLength;
          if (bytes > limit) {
            tooLarge = true;
            await reader.cancel().catch(() => {});
            throw new Error("body_too_large");
          }
          chunks.push(next.value);
        }
        const body = chunks.length === 1 ? chunks[0] : new Uint8Array(bytes);
        if (chunks.length !== 1) {
          let offset = 0;
          for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
        }
        bounded = new Request(req, { body });
      }
      response = await handler(bounded);
      // Some route parsers catch JSON errors themselves. Preserve the 413 contract.
      if (tooLarge) response = failure("body_too_large", 413, { maxBytes: limit });
    }
  } catch (error) {
    response = tooLarge ? failure("body_too_large", 413, { maxBytes: limit })
      : error instanceof AuthError ? failure(error.code, error.status)
      : error instanceof SyntaxError || error instanceof URIError ? failure("invalid_request", 400)
      : failure("internal_error", 500);
  } finally {
    if (reader) await reader.cancel().catch(() => {});
  }
  const elapsedMs = Date.now() - started;
  if (response.status >= 500 || response.status === 429 || elapsedMs >= 2000) {
    const event = { event: "gateway_request", requestId, category: requestCategory(path),
      method: req.method, status: response.status, elapsedMs };
    if (response.status >= 500) console.error(event);
    else console.warn(event);
  }
  // Upgrade responses have a runtime-owned WebSocket that must be preserved.
  if (response.status === 101) return response;
  const headers = new Headers(response.headers);
  headers.set("X-CloudFS-Request-ID", requestId);
  headers.set("X-Content-Type-Options", "nosniff");
  if (path === "/v1" || path.startsWith("/v1/")) headers.set("Cache-Control", "no-store");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
