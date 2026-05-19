import type { StagingConfig } from "./types";
import { handleFetch } from "./fetch-handler";

export interface GetFileCapabilityDeps {
  STAGING_D1: D1Database;
  STAGING_R2: R2Bucket;
  config: StagingConfig;
  /** Test seam: override the clock used by the inner `handleFetch`. */
  now?: () => number;
}

export interface SandboxFileBody {
  contentType: string;
  byteLength: number;
  filename: string | null;
  bytesBase64: string; // wire-safe; the child re-wraps as Uint8Array
}

/**
 * Host-side function called by the codemode child Worker via `__stagingHost.getFile`.
 *
 * Codemode 0.3.5 API surface — relevant findings (see report for full context):
 *
 *   - There is NO `executor.registerCapability(...)` method. The executor is a
 *     plain `DynamicWorkerExecutor` whose only public method is
 *     `execute(code, providersOrFns: ResolvedProvider[] | Record<string, fn>)`.
 *   - Host capabilities are injected at the `execute()` call-site as
 *     `ResolvedProvider[]`, each `{ name, fns, positionalArgs? }`. In the
 *     sandbox they become globals named after `name` (so `name: "__stagingHost"`
 *     yields `globalThis.__stagingHost.getFile(...)` in LLM-written code).
 *   - The `__openapiHost` capability is wired *inside* `openApiMcpServer()` —
 *     the `execute` MCP tool callback constructs the providers array
 *     `[{ name: "__openapiHost", fns: { request } }]` itself. There is no
 *     public hook on `openApiMcpServer` to append additional providers.
 *   - There is NO sandbox prelude / modules-prepend mechanism that runs before
 *     LLM code in the OpenAPI execute path (codemode's `modules` option
 *     applies only to `executor.execute` invocations the caller controls — the
 *     OpenAPI `execute` tool doesn't expose it). Consequently the sandbox
 *     cannot transparently re-wrap `bytesBase64` into a `Response`-like
 *     object; LLM code must decode it itself.
 *
 * Wire form (host → child):
 *   { ok: true, contentType, byteLength, filename, bytesBase64 }
 *   | { ok: false, status, message }
 *
 * The child code in the sandbox can wrap `bytesBase64` into bytes via:
 *   const raw = atob(out.bytesBase64);
 *   const buf = new Uint8Array(raw.length);
 *   for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
 */
export function createGetFileCapability(deps: GetFileCapabilityDeps) {
  return async function getFile(
    handle: string,
    token: string,
  ): Promise<
    | {
        ok: true;
        contentType: string;
        byteLength: number;
        filename: string | null;
        bytesBase64: string;
      }
    | { ok: false; status: number; message: string }
  > {
    if (typeof handle !== "string" || typeof token !== "string") {
      return { ok: false, status: 400, message: "handle and token must be strings" };
    }
    // Synthesize an internal request that `handleFetch` already knows how to process.
    const url = `https://internal.invalid/staging/fetch/${encodeURIComponent(handle)}`;
    const req = new Request(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });
    const res = await handleFetch(req, {
      STAGING_D1: deps.STAGING_D1,
      STAGING_R2: deps.STAGING_R2,
      config: deps.config,
      ...(deps.now ? { now: deps.now } : {}),
    });
    if (res.status !== 200) {
      return { ok: false, status: res.status, message: await res.text() };
    }
    const buf = new Uint8Array(await res.arrayBuffer());
    return {
      ok: true,
      contentType: res.headers.get("Content-Type") ?? "application/octet-stream",
      byteLength: buf.byteLength,
      filename: res.headers.get("X-Filename"),
      bytesBase64: bytesToBase64(buf),
    };
  };
}

function bytesToBase64(bytes: Uint8Array): string {
  let s = "";
  // noUncheckedIndexedAccess: bytes[i] is `number | undefined`; the loop bound
  // guarantees defined, so a non-null assertion is correct here.
  for (let i = 0; i < bytes.byteLength; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}
