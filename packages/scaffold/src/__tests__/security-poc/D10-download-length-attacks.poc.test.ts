// D10 — Length attacks on the download paths (issue #59, D9).
//
// Attacker: an upstream (or anything able to shape an upstream response —
//   a compromised account, a provider bug, an intermediary) answering a
//   `returnAs: "stage"` request or a `stageFromUpstreamJson` request.
// Precondition: an allowed operation; a staging store; the handler reads the
//   upstream body block by block.
// Payloads: `Content-Length: N` with N+1 or N−1 bytes actually sent; a
//   chunked body (no length) past maxBytes; a declared length over maxBytes;
//   a JSON envelope whose `data` string is longer than 4/3 · maxBytes.
// Control: a body that ends short of, or runs past, its declared length is
//   a 502 with the sink aborted — no R2 object, no claimed row; an unknown
//   length body is cancelled at maxBytes + 1 (413) with the reader cancelled;
//   an over-cap declaration is refused before any read; the `data` string is
//   bounded by length before any decode.
//
// Pre-v2 reasoning: v1 read the whole upstream body with `arrayBuffer()`
// and only then checked its size, and never compared it with the declared
// length; the fixed-length sink and the declared-length check are v2
// controls. Removing the end-of-stream length check in
// `blockSourceFromStream` (verified by mutation) stages the short body as if
// it were complete.
//
// FakeD1/FakeR2 only; `fetch` is stubbed. No network.
import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "../../request-handler";
import { FakeD1 } from "../../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../../staging/__tests__/__fixtures__/fake-r2";
import { createPutFileCapability } from "../../staging/putfile-capability";
import { createStageFromUpstreamJsonCapability } from "../../staging/stage-from-upstream-json";
import { BLOCK_BYTES, type StagingConfig } from "../../staging/types";
import { decodeBase64Into } from "../../staging/codec";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReview } from "@local/shared";

// `vi.spyOn` cannot wrap an ESM export, so the codec's JS decoder is wrapped
// at module load: a decode that runs before the string-length bound is then
// observable on Node 22 (no native `setFromBase64`) as well as on Node 24+.
// The wrapper passes through, so handle/token decoding (tokens.ts) is unchanged.
vi.mock("../../staging/codec", async (importOriginal) => {
  const m = await importOriginal<typeof import("../../staging/codec")>();
  return { ...m, decodeBase64Into: vi.fn(m.decodeBase64Into) };
});

const NOW = 1_700_000_000;
const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 4 * BLOCK_BYTES };

const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/download": { get: { operationId: "download", responses: { "200": { description: "OK" } } } },
    "/att": { get: { operationId: "att", responses: { "200": { description: "OK" } } } },
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;
const SR: SurfaceReview = { download: { decision: "allow" }, att: { decision: "allow" } };

function pattern(n: number, seed = 17): Uint8Array {
  const a = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    a[i] = x >>> 24;
  }
  return a;
}

/** An upstream body that yields `bytes` in `chunk`-sized pieces, recording
 *  how much was pulled and whether the consumer cancelled it. */
function upstreamBody(bytes: Uint8Array, chunk: number) {
  let off = 0;
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(c) {
        if (off >= bytes.byteLength) {
          c.close();
          return;
        }
        c.enqueue(bytes.slice(off, Math.min(bytes.byteLength, off + chunk)));
        off = Math.min(bytes.byteLength, off + chunk);
      },
      cancel() {
        cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  return { stream, pulled: () => off, cancelled: () => cancelled };
}

function world() {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const deps = {
    STAGING_D1: d1 as unknown as D1Database,
    STAGING_R2: r2 as unknown as R2Bucket,
    config: CFG,
    uploadOrigin: "https://x.test",
    now: () => NOW,
  };
  let putAborted: unknown = null;
  const realPut = r2.put.bind(r2);
  r2.put = async (key: string, body: Parameters<typeof realPut>[1]) => {
    try {
      return await realPut(key, body);
    } catch (e) {
      putAborted = e;
      throw e;
    }
  };
  let respond: () => Response = () => new Response("{}", { status: 200 });
  vi.stubGlobal("fetch", vi.fn(async () => respond()));
  vi.spyOn(console, "log").mockImplementation(() => {});
  const args = (ctx: UpstreamCtx): HandleArgs<Record<string, unknown>> => ({
    ctx,
    spec: SPEC,
    surfaceReview: SR,
    apiBaseUrl: "https://api.example.com",
    deploymentName: "poc",
    props: { refreshToken: "RT", userId: "u1" },
    server: {} as never,
    env: {},
    audit: {},
    oauth: { refreshTokenAccessor: () => "RT", userIdAccessor: () => "u1", broker: { getOrRefreshAccessToken: async () => "AT" } },
    stagingStore: deps,
  });
  return {
    d1,
    r2,
    deps,
    args,
    setResponse: (f: () => Response) => {
      respond = f;
    },
    putAborted: () => putAborted,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("D10 — returnAs:\"stage\" with a lying Content-Length", () => {
  for (const [label, delta] of [
    ["N+1", 1],
    ["N−1", -1],
    ["N+1 MiB", BLOCK_BYTES],
    ["N−1 MiB", -BLOCK_BYTES],
  ] as const) {
    it(`FIXED (#59): declared N, ${label} sent → 502 stage_failed, sink aborted, no R2 object, no row`, async () => {
      const w = world();
      const N = 2 * BLOCK_BYTES + 11;
      const body = upstreamBody(pattern(N + delta), 65_536);
      w.setResponse(
        () =>
          new Response(body.stream, {
            status: 200,
            headers: { "content-type": "application/pdf", "content-length": String(N) },
          }),
      );
      const res = (await handleUpstreamRequest(w.args({ method: "GET", path: "/download", returnAs: "stage" }))) as {
        success: boolean;
        status: number;
        result: Record<string, unknown>;
      };
      expect(res.success).toBe(false);
      expect(res.status).toBe(502);
      expect(res.result).toEqual({ error: "stage_failed", message: "body length does not match the declared length" });
      expect(w.r2.store.size).toBe(0);
      expect(w.d1.rows.size).toBe(0);
      expect(w.putAborted()).toBeInstanceOf(Error); // the fixed-length sink was aborted, never closed short
      if (delta > 0) expect(body.pulled()).toBeLessThanOrEqual(N + 65_536); // cut at the first chunk past N
    });
  }

  it("REFUTED: an honest Content-Length of N with exactly N bytes stages the file (control)", async () => {
    const w = world();
    const N = BLOCK_BYTES + 3;
    const body = upstreamBody(pattern(N), 65_536);
    w.setResponse(() => new Response(body.stream, { status: 200, headers: { "content-type": "application/pdf", "content-length": String(N) } }));
    const res = (await handleUpstreamRequest(w.args({ method: "GET", path: "/download", returnAs: "stage" }))) as {
      success: boolean;
      result: Record<string, unknown>;
    };
    expect(res.success).toBe(true);
    expect(res.result.byte_length).toBe(N);
    expect(w.r2.putKinds).toEqual(["stream"]);
    expect(w.d1.rows.size).toBe(1);
  });
});

describe("D10 — returnAs:\"stage\" with no or an oversize length", () => {
  it("FIXED (#59): a chunked body past maxBytes → 413, reader cancelled at the first byte over, no R2 object, no row", async () => {
    const w = world();
    const body = upstreamBody(new Uint8Array(CFG.maxBytes + 1), 256 * 1024);
    w.setResponse(() => new Response(body.stream, { status: 200, headers: { "content-type": "application/pdf" } }));
    const res = (await handleUpstreamRequest(w.args({ method: "GET", path: "/download", returnAs: "stage" }))) as {
      success: boolean;
      status: number;
    };
    expect(res.success).toBe(false);
    expect(res.status).toBe(413);
    expect(body.cancelled()).toBe(true);
    expect(body.pulled()).toBeLessThanOrEqual(CFG.maxBytes + 256 * 1024);
    expect(w.r2.store.size).toBe(0);
    expect(w.r2.putKinds).toEqual([]); // unknown length: no put begins before the body ends
    expect(w.d1.rows.size).toBe(0);
  });

  it("FIXED (#59): Content-Length over maxBytes → 413 without reading a byte", async () => {
    const w = world();
    const body = upstreamBody(new Uint8Array(1024), 1024);
    w.setResponse(
      () =>
        new Response(body.stream, {
          status: 200,
          headers: { "content-type": "application/pdf", "content-length": String(CFG.maxBytes + 1) },
        }),
    );
    const res = (await handleUpstreamRequest(w.args({ method: "GET", path: "/download", returnAs: "stage" }))) as { status: number };
    expect(res.status).toBe(413);
    expect(body.pulled()).toBe(0);
    expect(w.r2.store.size).toBe(0);
  });

  it("REFUTED: a Content-Length under a non-identity Content-Encoding is not trusted as the body length (no false 502 or false claim)", async () => {
    const w = world();
    const N = 3000;
    const body = upstreamBody(pattern(N), 1000);
    // A lying declaration that would be a mismatch if trusted; with gzip
    // declared, the handler treats the length as unknown and stages the
    // bytes it actually received.
    w.setResponse(
      () =>
        new Response(body.stream, {
          status: 200,
          headers: { "content-type": "application/pdf", "content-length": "5", "content-encoding": "gzip" },
        }),
    );
    const res = (await handleUpstreamRequest(w.args({ method: "GET", path: "/download", returnAs: "stage" }))) as {
      success: boolean;
      result: Record<string, unknown>;
    };
    expect(res.success).toBe(true);
    expect(res.result.byte_length).toBe(N);
  });
});

describe("D10 — stageFromUpstreamJson data-string bound", () => {
  it("FIXED (#59): a `data` string of 4/3·maxBytes + 1 chars, delivered by the real handler with bypassTruncate, → 413 before any decode", async () => {
    const w = world();
    const data = "A".repeat(Math.ceil(CFG.maxBytes / 3) * 4 + 5);
    w.setResponse(() => new Response(JSON.stringify({ data, mimeType: "application/pdf" }), { status: 200, headers: { "content-type": "application/json" } }));
    const encrypt = vi.spyOn(crypto.subtle, "encrypt");
    const atobSpy = vi.spyOn(globalThis, "atob");
    const proto = Uint8Array.prototype as unknown as { setFromBase64?: (...a: unknown[]) => unknown };
    const nativeDecode = typeof proto.setFromBase64 === "function" ? vi.spyOn(proto, "setFromBase64") : null;
    vi.mocked(decodeBase64Into).mockClear();
    const cap = createStageFromUpstreamJsonCapability({
      putFile: createPutFileCapability(w.deps),
      upstreamRequest: (ctx) => handleUpstreamRequest(w.args(ctx as unknown as UpstreamCtx)) as never,
    });
    const r = await cap({ method: "GET", path: "/att" }, "data", "base64url");
    expect(r).toEqual({ ok: false, status: 413, message: "payload too large" });
    expect(encrypt).not.toHaveBeenCalled();
    expect(atobSpy).not.toHaveBeenCalled();
    if (nativeDecode) expect(nativeDecode).not.toHaveBeenCalled();
    expect(decodeBase64Into).not.toHaveBeenCalled(); // the JS decoder too (Node 22 path)
    expect(w.r2.store.size).toBe(0);
    expect(w.d1.rows.size).toBe(0);
  });

  it("FIXED (#59): a well-formed `data` string four chars past the bound → 413 with no decoder call on either Node path", async () => {
    // Length ≡ 0 mod 4, so `decodedLength` accepts it and a length check
    // that ran only after the decode would still answer 413 (3 bytes over):
    // only the decoder spies tell the two apart. This is the case the JS
    // decoder spy (Node 22, no native `setFromBase64`) exists for.
    const w = world();
    const wellFormed = "A".repeat(Math.ceil(CFG.maxBytes / 3) * 4 + 8);
    w.setResponse(() => new Response(JSON.stringify({ data: wellFormed, mimeType: "application/pdf" }), { status: 200, headers: { "content-type": "application/json" } }));
    const encrypt = vi.spyOn(crypto.subtle, "encrypt");
    const atobSpy = vi.spyOn(globalThis, "atob");
    const proto = Uint8Array.prototype as unknown as { setFromBase64?: (...a: unknown[]) => unknown };
    const nativeDecode = typeof proto.setFromBase64 === "function" ? vi.spyOn(proto, "setFromBase64") : null;
    vi.mocked(decodeBase64Into).mockClear();
    const cap = createStageFromUpstreamJsonCapability({
      putFile: createPutFileCapability(w.deps),
      upstreamRequest: (ctx) => handleUpstreamRequest(w.args(ctx as unknown as UpstreamCtx)) as never,
    });
    expect(await cap({ method: "GET", path: "/att" }, "data", "base64url")).toEqual({ ok: false, status: 413, message: "payload too large" });
    expect(decodeBase64Into).not.toHaveBeenCalled();
    if (nativeDecode) expect(nativeDecode).not.toHaveBeenCalled();
    expect(atobSpy).not.toHaveBeenCalled();
    expect(encrypt).not.toHaveBeenCalled();
    expect(w.r2.store.size).toBe(0);
    expect(w.d1.rows.size).toBe(0);
  });

  it("REFUTED: a `data` string that decodes to exactly maxBytes is accepted; one more byte is 413 after an exact-length check", async () => {
    const w = world();
    const cap = createStageFromUpstreamJsonCapability({
      putFile: createPutFileCapability(w.deps),
      upstreamRequest: (ctx) => handleUpstreamRequest(w.args(ctx as unknown as UpstreamCtx)) as never,
    });
    const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");
    w.setResponse(() => new Response(JSON.stringify({ data: b64url(pattern(CFG.maxBytes)) }), { status: 200, headers: { "content-type": "application/json" } }));
    expect((await cap({ method: "GET", path: "/att" }, "data")).ok).toBe(true);
    w.setResponse(() => new Response(JSON.stringify({ data: b64url(pattern(CFG.maxBytes + 1)) }), { status: 200, headers: { "content-type": "application/json" } }));
    expect(await cap({ method: "GET", path: "/att" }, "data")).toMatchObject({ ok: false, status: 413 });
    expect(w.r2.store.size).toBe(1);
    expect(w.d1.rows.size).toBe(1);
  }, 30_000);
});
