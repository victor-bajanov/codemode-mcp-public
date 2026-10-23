// D1 — Memory caps on the host-assembled body channel (issue #59, plan §2, D7, D10).
//
// Attacker: sandbox code (LLM-authored or prompt-injected) holding valid
//   staged references, or a D1 writer that can edit a row's `byte_len`.
// Precondition: `composed` / `multipart[].staged` accepted on the operation;
//   the attacker wants the host to allocate file-sized memory (or open R2)
//   for a request that can never be sent.
// Payloads: the same large file referenced three times in one body; 32
//   staged multipart parts; 33 segments; a 4 MiB + 1 text segment; nested
//   junk and `__proto__` keys in segments; `getFile` on an over-cap row;
//   `stageFromUpstreamJson` with a `data` string longer than 4/3 · maxBytes.
// Control: shape validation runs before any storage access (zero D1 reads
//   for a malformed body); the exact assembled length is computed from the
//   rows' metadata and refused as `composed-too-large` before any `R2.get`;
//   `getFile` refuses from `byte_len` alone (413, no R2); `putFile` bounds
//   the base64 string length before decoding (413, no decode, no crypto).
//
// Pre-v2 reasoning (why each probe would have bitten): v1 had no
// host-assembled channel at all — a model had to pull bytes through
// `getFile` (uncapped) and push them back as `bodyBase64`, so every cap here
// is new. A probe here fails if the cap is removed or moved after the R2
// read (verified by mutation during authoring).
//
// FakeD1/FakeR2 only; `fetch` is stubbed. No network.
import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "../../request-handler";
import { ToolError } from "../../elicit";
import { FakeD1 } from "../../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../../staging/__tests__/__fixtures__/fake-r2";
import {
  blockSourceFromBytes,
  createStagedFileOpener,
  stageFromBlocks,
  type StagedRef,
} from "../../staging/staged-file";
import { createGetFileCapability } from "../../staging/getfile-capability";
import { createPutFileCapability } from "../../staging/putfile-capability";
import { createStageFromUpstreamJsonCapability } from "../../staging/stage-from-upstream-json";
import { sha256Bearer } from "../../staging/crypto";
import { COMPOSED_MAX_SEGMENTS, COMPOSED_MAX_TEXT_BYTES } from "../../compose/validate";
import { DEFAULT_COMPOSE_MAX_BYTES, type StagingConfig } from "../../staging/types";
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
const FIFTY_MIB = 50 * 1024 * 1024;
const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: FIFTY_MIB };

const op = (operationId: string) => ({ operationId, responses: { "200": { description: "OK" } } });
const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/upload/send": { post: op("sendMedia") },
    "/files": { post: op("files") },
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;
const SR: SurfaceReview = {
  sendMedia: { decision: "allow", acceptsStaged: true, inspect: () => ({ decision: "allow" }) },
  files: { decision: "allow" },
};

function world() {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  let prepares = 0;
  const origPrepare = d1.prepare.bind(d1);
  d1.prepare = (sql: string) => {
    prepares += 1;
    return origPrepare(sql);
  };
  const deps = {
    STAGING_D1: d1 as unknown as D1Database,
    STAGING_R2: r2 as unknown as R2Bucket,
    config: CFG,
    uploadOrigin: "https://x.test",
    now: () => NOW,
  };
  const opener = createStagedFileOpener(deps);
  const openCalls: StagedRef[] = [];
  const fetchSpy = vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
  vi.stubGlobal("fetch", fetchSpy);
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  const audits = () =>
    logSpy.mock.calls
      .map((c) => c[0])
      .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
      .map((s) => JSON.parse(s.slice(6)) as Record<string, unknown>);
  const args = (ctx: UpstreamCtx, extra: Partial<HandleArgs<Record<string, unknown>>> = {}): HandleArgs<Record<string, unknown>> => ({
    ctx,
    spec: SPEC,
    surfaceReview: SR,
    apiBaseUrl: "https://api.example.com",
    deploymentName: "poc",
    props: { refreshToken: "RT", userId: "u1" },
    server: {} as never,
    env: {},
    audit: {},
    oauth: {
      refreshTokenAccessor: () => "RT",
      userIdAccessor: () => "u1",
      broker: { getOrRefreshAccessToken: async () => "AT" },
    },
    openStaged: async (ref) => {
      openCalls.push(ref);
      return opener(ref);
    },
    stagingStore: deps,
    ...extra,
  });
  const stage = async (bytes: Uint8Array): Promise<StagedRef> => {
    const r = await stageFromBlocks(deps, blockSourceFromBytes(bytes), "application/pdf", "q.pdf");
    if (!r.ok) throw new Error("stage failed");
    return { file_handle: r.file_handle, token: r.token };
  };
  /** D1-writer tamper: make the row claim `byteLen` bytes without storing them. */
  const claimLength = async (ref: StagedRef, byteLen: number) => {
    const key = Buffer.from(await sha256Bearer(ref.token)).toString("hex");
    d1.rows.get(key)!.byte_len = byteLen;
  };
  return { d1, r2, deps, args, stage, claimLength, openCalls, fetchSpy, audits, prepares: () => prepares };
}

function assertNoSecrets(text: string, ref: StagedRef): void {
  expect(text).not.toContain(ref.token);
  expect(text).not.toContain(ref.token.slice(4, 24));
  expect(text).not.toContain(ref.file_handle);
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("D1 — assembled-length cap is enforced from row metadata, before any R2 read", () => {
  it("FIXED (#59): M1 the same 50 MiB file ×3 in one body → composed-too-large; zero R2.get, no fetch", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(16));
    await w.claimLength(ref, FIFTY_MIB); // the row now says 50 MiB; one copy would fit the 72 MiB cap
    const seg = { staged: ref, encoding: "base64-lines" as const };
    const err = await handleUpstreamRequest(
      w.args({
        method: "POST",
        path: "/upload/send",
        contentType: "message/rfc822",
        composed: { segments: [{ text: "To: a@b\r\n\r\n" }, seg, { text: "\r\n" }, seg, { text: "\r\n" }, seg] },
      }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/^composed-too-large/);
    expect((err as Error).message).toContain(String(DEFAULT_COMPOSE_MAX_BYTES));
    assertNoSecrets((err as Error).message, ref);
    expect(w.r2.getCalls).toBe(0);
    expect(w.fetchSpy).not.toHaveBeenCalled();
    expect(w.openCalls).toHaveLength(3); // each reference resolved (D1 only), the same file counted three times
    expect(w.audits().at(-1)).toMatchObject({ decision: "deny", reason: "composed-too-large" });
  });

  it("FIXED (#59): M2 32 staged multipart parts of a 50 MiB row → the sum is capped; zero R2.get", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(16));
    await w.claimLength(ref, FIFTY_MIB);
    const multipart = Array.from({ length: 32 }, (_, i) => ({ name: `file${i}`, staged: ref }));
    const err = await handleUpstreamRequest(w.args({ method: "POST", path: "/files", multipart })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/^composed-too-large/);
    expect(w.r2.getCalls).toBe(0);
    expect(w.fetchSpy).not.toHaveBeenCalled();
    expect(w.audits().at(-1)).toMatchObject({ decision: "deny", reason: "composed-too-large" });
  });

  it("REFUTED: a single oversize reference on a tightened cap is refused the same way, with the computed size", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(3000));
    const err = await handleUpstreamRequest(
      w.args(
        { method: "POST", path: "/files", multipart: [{ name: "f", staged: ref }] },
        { stagingLimits: { composeMaxBytes: 1000 } },
      ),
    ).catch((e: unknown) => e);
    expect((err as Error).message).toMatch(/would be \d+ bytes; the limit is 1000 bytes/);
    expect(w.r2.getCalls).toBe(0);
  });
});

describe("D1 — malformed composed bodies cost zero storage access (M3)", () => {
  const ref = (): StagedRef => ({
    file_handle: "fh_AAAAAAAAAAAAAAAAAAAAAA", // plausible shape; never resolved
    token: "stg_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  });
  const cases: Array<[string, unknown, string]> = [
    [
      "33 segments",
      { segments: Array.from({ length: COMPOSED_MAX_SEGMENTS + 1 }, () => ({ text: "x" })) },
      "composed-malformed",
    ],
    ["4 MiB + 1 of text", { segments: [{ text: "x".repeat(COMPOSED_MAX_TEXT_BYTES + 1) }] }, "composed-malformed"],
    [
      "4 MiB of text split over two segments plus one byte",
      { segments: [{ text: "x".repeat(COMPOSED_MAX_TEXT_BYTES - 1) }, { text: "yz" }] },
      "composed-malformed",
    ],
    ["a nested array segment", { segments: [[{ text: "x" }]] }, "composed-malformed"],
    ["a segment with an object text", { segments: [{ text: { toString: () => "x" } }] }, "composed-malformed"],
    ["a segment with both text and staged", { segments: [{ text: "x", staged: ref(), encoding: "base64" }] }, "composed-malformed"],
    ["a staged segment with an extra key", { segments: [{ staged: ref(), encoding: "base64", extra: 1 }] }, "composed-malformed"],
    ["a staged ref with an extra key", { segments: [{ staged: { ...ref(), range: [0, 1] }, encoding: "base64" }] }, "composed-malformed"],
    ["an unknown encoding", { segments: [{ staged: ref(), encoding: "base64url" }] }, "composed-malformed"],
    ["an empty segment list", { segments: [] }, "composed-malformed"],
    ["composed with an extra key", { segments: [{ text: "x" }], boundary: "b" }, "composed-malformed"],
    ["a string composed", "segments", "composed-malformed"],
    ["U+FFFC in text", { segments: [{ text: "a￼b" }] }, "composed-text-reserved-char"],
    ["a lone surrogate in text", { segments: [{ text: "a\uD800b" }] }, "composed-text-not-well-formed"],
  ];
  for (const [name, composed, reason] of cases) {
    it(`REFUTED: ${name} → ToolError (${reason}), zero D1 reads, opener never called`, async () => {
      const w = world();
      const before = w.prepares();
      const err = await handleUpstreamRequest(
        w.args({ method: "POST", path: "/upload/send", composed } as unknown as UpstreamCtx),
      ).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ToolError);
      expect(w.prepares() - before).toBe(0);
      expect(w.openCalls).toHaveLength(0);
      expect(w.r2.getCalls).toBe(0);
      expect(w.fetchSpy).not.toHaveBeenCalled();
      expect(w.audits().at(-1)).toMatchObject({ decision: "deny", category: "malformed", reason });
    });
  }

  it("REFUTED: `__proto__` keys cannot smuggle a segment shape past the exact-keys check", async () => {
    const w = world();
    // JSON.parse keeps "__proto__" as an own property (no prototype pollution),
    // which is what the sandbox RPC delivers.
    const composed = JSON.parse(
      '{"segments":[{"__proto__":{"text":"x"}},{"text":"ok","__proto__":{"a":1}}]}',
    ) as unknown;
    const err = await handleUpstreamRequest(
      w.args({ method: "POST", path: "/upload/send", composed } as unknown as UpstreamCtx),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/segment 0/);
    expect(w.prepares()).toBe(0);
    expect(w.openCalls).toHaveLength(0);
    // A polluted prototype would also have to pass `isPlainObject`:
    const viaProto = Object.create({ text: "x" }) as Record<string, unknown>;
    const err2 = await handleUpstreamRequest(
      w.args({ method: "POST", path: "/upload/send", composed: { segments: [viaProto] } } as unknown as UpstreamCtx),
    ).catch((e: unknown) => e);
    expect(err2).toBeInstanceOf(ToolError);
    expect(w.openCalls).toHaveLength(0);
  });
});

describe("D1 — getFile and stageFromUpstreamJson caps", () => {
  it("FIXED (#59): M6 getFile on a row over STAGING_GETFILE_MAX_BYTES → 413 from metadata alone, no R2 read, token-free message pointing at composed", async () => {
    const w = world();
    const cap = 1024;
    const ref = await w.stage(new Uint8Array(cap + 1));
    const getFile = createGetFileCapability({ ...w.deps, config: { ...CFG, getFileMaxBytes: cap } });
    const r = await getFile(ref.file_handle, ref.token);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.status).toBe(413);
    expect(r.message).toContain("composed");
    expect(r.message).toContain(String(cap + 1));
    assertNoSecrets(JSON.stringify(r), ref);
    expect(w.r2.getCalls).toBe(0);
    // The same row, at the cap, is readable: the refusal is the cap, not the row.
    const okRef = await w.stage(new Uint8Array(cap));
    expect((await getFile(okRef.file_handle, okRef.token)).ok).toBe(true);
  });

  it("FIXED (#59): M6' a D1 row whose byte_len is edited over the cap is refused before R2 (the object size is never consulted)", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(8));
    await w.claimLength(ref, 8 * 1024 * 1024 + 1); // default cap is 8 MiB
    const getFile = createGetFileCapability(w.deps);
    const r = await getFile(ref.file_handle, ref.token);
    expect(r).toMatchObject({ ok: false, status: 413 });
    expect(w.r2.getCalls).toBe(0);
  });

  it("FIXED (#59): M7 stageFromUpstreamJson with data ≥ 4/3·maxBytes → 413 before any decode, encrypt or R2 write", async () => {
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const maxBytes = 3 * 1024;
    const deps = {
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: { ...CFG, maxBytes },
      uploadOrigin: "https://x.test",
      now: () => NOW,
    };
    const putFile = createPutFileCapability(deps);
    const encrypt = vi.spyOn(crypto.subtle, "encrypt");
    const atobSpy = vi.spyOn(globalThis, "atob");
    const proto = Uint8Array.prototype as unknown as { setFromBase64?: (...a: unknown[]) => unknown };
    const nativeDecode = typeof proto.setFromBase64 === "function" ? vi.spyOn(proto, "setFromBase64") : null;
    vi.mocked(decodeBase64Into).mockClear();
    // One char past the bound putFile applies: ceil(maxBytes/3)*4 + 4.
    const data = "A".repeat(Math.ceil(maxBytes / 3) * 4 + 5);
    const cap = createStageFromUpstreamJsonCapability({
      putFile,
      upstreamRequest: async () => ({ success: true, status: 200, result: { data, mimeType: "application/pdf" } }),
    });
    const r = await cap({ method: "GET", path: "/att" }, "data", "base64url");
    expect(r).toEqual({ ok: false, status: 413, message: "payload too large" });
    expect(encrypt).not.toHaveBeenCalled();
    expect(atobSpy).not.toHaveBeenCalled();
    if (nativeDecode) expect(nativeDecode).not.toHaveBeenCalled();
    expect(decodeBase64Into).not.toHaveBeenCalled(); // the JS decoder too (Node 22 path)
    expect(r2.store.size).toBe(0);
    expect(d1.rows.size).toBe(0);
    // Just inside the string bound, one byte over maxBytes: decoded block by
    // block and refused on the exact length (413 again); nothing persisted.
    const atBound = Buffer.from(new Uint8Array(maxBytes + 1)).toString("base64").replace(/=+$/, "");
    const cap2 = createStageFromUpstreamJsonCapability({
      putFile,
      upstreamRequest: async () => ({ success: true, status: 200, result: { data: atBound } }),
    });
    expect(await cap2({ method: "GET", path: "/att" }, "data", "base64")).toMatchObject({ ok: false, status: 413 });
    expect(r2.store.size).toBe(0);
    expect(d1.rows.size).toBe(0);
  });

  it("FIXED (#59): M7' a well-formed data string four chars past the bound → 413 with no decoder call on either Node path", async () => {
    // Length ≡ 0 mod 4, so `decodedLength` accepts it and a length check
    // that ran only after the decode would still answer 413 (3 bytes over):
    // only the decoder spies tell the two apart. This is the case the JS
    // decoder spy (Node 22, no native `setFromBase64`) exists for.
    const d1 = new FakeD1();
    const r2 = new FakeR2();
    const maxBytes = 3 * 1024;
    const putFile = createPutFileCapability({
      STAGING_D1: d1 as unknown as D1Database,
      STAGING_R2: r2 as unknown as R2Bucket,
      config: { ...CFG, maxBytes },
      uploadOrigin: "https://x.test",
      now: () => NOW,
    });
    const encrypt = vi.spyOn(crypto.subtle, "encrypt");
    const atobSpy = vi.spyOn(globalThis, "atob");
    const proto = Uint8Array.prototype as unknown as { setFromBase64?: (...a: unknown[]) => unknown };
    const nativeDecode = typeof proto.setFromBase64 === "function" ? vi.spyOn(proto, "setFromBase64") : null;
    vi.mocked(decodeBase64Into).mockClear();
    const wellFormed = "A".repeat(Math.ceil(maxBytes / 3) * 4 + 8);
    const cap = createStageFromUpstreamJsonCapability({
      putFile,
      upstreamRequest: async () => ({ success: true, status: 200, result: { data: wellFormed, mimeType: "application/pdf" } }),
    });
    expect(await cap({ method: "GET", path: "/att" }, "data", "base64url")).toEqual({ ok: false, status: 413, message: "payload too large" });
    expect(decodeBase64Into).not.toHaveBeenCalled();
    if (nativeDecode) expect(nativeDecode).not.toHaveBeenCalled();
    expect(atobSpy).not.toHaveBeenCalled();
    expect(encrypt).not.toHaveBeenCalled();
    expect(r2.store.size).toBe(0);
    expect(d1.rows.size).toBe(0);
  });
});
