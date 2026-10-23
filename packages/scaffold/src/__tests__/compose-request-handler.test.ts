// handleUpstreamRequest — the host-assembled body channel (plan B5, D3a, D5–D8,
// D10a): phase order, inspection view, caps, writer/fetch coupling, audit, and
// the `returnAs: "stage"` rewrite over block sources.

import { describe, it, expect, vi, afterEach } from "vitest";
import { Buffer } from "node:buffer";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "../request-handler";
import { ToolError } from "../elicit";
import { TransferGate } from "../compose/gate";
import { sendAssembled, transferController, UPSTREAM_CLOSE_GRACE_MS } from "../compose/transfer";
import type { Segment } from "../compose/validate";
import { FakeD1 } from "../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../staging/__tests__/__fixtures__/fake-r2";
import { FakeGate } from "../staging/__tests__/__fixtures__/fake-gate";
import {
  blockSourceFromBytes,
  createStagedFileOpener,
  stageFromBlocks,
  StagedFileReadError,
  type OpenStagedFile,
  type OpenStagedResult,
  type StagedRef,
} from "../staging/staged-file";
import { BLOCK_BYTES } from "../staging/block-format";
import { tryAcquireUnknownLengthSlot } from "../staging/unknown-length-slot";
import type { StagingConfig } from "../staging/types";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { InspectRequest, InspectResult, SurfaceReview } from "@local/shared";

const NOW = 1_700_000_000;
const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };

function pattern(n: number, seed = 5): Uint8Array {
  const a = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    a[i] = x >>> 24;
  }
  return a;
}
function lines76(b64: string): string {
  let out = "";
  for (let i = 0; i < b64.length; i += 76) out += b64.slice(i, i + 76) + "\r\n";
  return out;
}

const op = (operationId: string) => ({ operationId, responses: { "200": { description: "OK" } } });
const SPEC: OpenApiSpec = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/upload/send": { post: op("sendMedia") },
    "/send": { post: op("sendJson") },
    "/attach/{name}": { put: op("attach") },
    "/drafts": { post: op("draftMedia") },
    "/approve": { post: op("approveMedia") },
    "/approve-plain": { post: op("approvePlain") },
    "/files": { post: op("files") },
    "/inspected-files": { post: op("inspectedFiles") },
    "/download": { get: op("download") },
    "/denied": { post: op("denied") },
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;

interface World {
  d1: FakeD1;
  r2: FakeR2;
  log: string[];
  inspected: InspectRequest[];
  inspectResult: InspectResult;
  fetchSpy: ReturnType<typeof vi.fn>;
  sent: Array<{ url: string; init: RequestInit; body: Uint8Array; error?: unknown }>;
  audit: () => Array<Record<string, unknown>>;
  elicitInput: ReturnType<typeof vi.fn>;
  args: (ctx: UpstreamCtx, extra?: Partial<HandleArgs<Record<string, unknown>>>) => HandleArgs<Record<string, unknown>>;
  stage: (bytes: Uint8Array, contentType?: string, filename?: string | null) => Promise<StagedRef>;
  upstream: (req: { body: ReadableStream<Uint8Array> | null; init: RequestInit }) => Promise<Response>;
}

async function drainAll(body: ReadableStream<Uint8Array> | null | undefined): Promise<Uint8Array> {
  if (!body) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  const reader = body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

function world(): World {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const log: string[] = [];
  const realGet = r2.get.bind(r2);
  r2.get = (async (key: string) => {
    log.push("r2");
    return realGet(key);
  }) as typeof r2.get;
  const stagingDeps = {
    STAGING_D1: d1 as unknown as D1Database,
    STAGING_R2: r2 as unknown as R2Bucket,
    config: CFG,
    uploadOrigin: "https://x.test",
    now: () => NOW,
  };
  const opener = createStagedFileOpener({ ...stagingDeps });
  const w: World = {
    d1,
    r2,
    log,
    inspected: [],
    inspectResult: { decision: "allow" },
    sent: [],
    fetchSpy: vi.fn(),
    audit: () => [],
    elicitInput: vi.fn(async () => {
      log.push("elicit");
      return { action: "accept", content: { confirm: true } };
    }),
    upstream: async ({ body }) => {
      await drainAll(body);
      return new Response(JSON.stringify({ id: "m1" }), { status: 200, headers: { "content-type": "application/json" } });
    },
    stage: async (bytes, contentType = "application/pdf", filename = "q.pdf") => {
      const r = await stageFromBlocks(stagingDeps, blockSourceFromBytes(bytes), contentType, filename);
      if (!r.ok) throw new Error("stage failed");
      return { file_handle: r.file_handle, token: r.token };
    },
    args: () => {
      throw new Error("unset");
    },
  };
  const inspect = (req: InspectRequest): InspectResult => {
    log.push("inspect");
    w.inspected.push(req);
    return w.inspectResult;
  };
  const SR: SurfaceReview = {
    sendMedia: { decision: "allow", acceptsStaged: true, inspect },
    sendJson: { decision: "allow", inspect },
    attach: { decision: "allow" },
    draftMedia: {
      decision: "allow",
      acceptsStaged: true,
      normalizeComposedText: (t) => (t.includes("Subject: bad") ? t.replace("Subject: bad", "Subject: good") : undefined),
    },
    approveMedia: { decision: "elicit", category: "external_data_flow", acceptsStaged: true },
    approvePlain: { decision: "elicit", category: "external_data_flow" },
    files: { decision: "allow" },
    inspectedFiles: { decision: "allow", acceptsStaged: true, inspect },
    download: { decision: "allow" },
    denied: { decision: "deny" },
  };
  w.fetchSpy = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    const u = String(url);
    if (u.includes("/token")) {
      return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
    }
    log.push("fetch");
    const rec = { url: u, init: init ?? {}, body: new Uint8Array(0) } as World["sent"][number];
    w.sent.push(rec);
    const body = (init?.body ?? null) as ReadableStream<Uint8Array> | null;
    if (body !== null && !(body instanceof ReadableStream)) {
      rec.body = typeof body === "string" ? new TextEncoder().encode(body) : new Uint8Array(body as ArrayBuffer);
      return w.upstream({ body: null, init: init ?? {} });
    }
    // Record what the upstream actually receives.
    const recorder = new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, c) {
        rec.body = Buffer.concat([rec.body, chunk]);
        c.enqueue(chunk);
      },
    });
    const piped = body ? body.pipeThrough(recorder) : null;
    return w.upstream({ body: piped, init: init ?? {} });
  });
  vi.stubGlobal("fetch", w.fetchSpy);
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  w.audit = () =>
    logSpy.mock.calls
      .map((c) => c[0])
      .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
      .map((s) => JSON.parse(s.slice(6)) as Record<string, unknown>);
  const data = new Map<string, unknown>();
  w.args = (ctx, extra = {}) => ({
    ctx,
    spec: SPEC,
    surfaceReview: SR,
    apiBaseUrl: "https://api.example.com",
    deploymentName: "test",
    props: { refreshToken: "RT-1", userId: "u1" },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    server: { server: { getClientCapabilities: () => ({ elicitation: {} }), elicitInput: w.elicitInput } } as any,
    env: {},
    audit: {},
    oauth: {
      refreshTokenAccessor: (p) => p.refreshToken as string,
      userIdAccessor: (p) => p.userId as string | undefined,
      broker: {
        getOrRefreshAccessToken: async () => {
          log.push("mint");
          void data;
          return "AT-x";
        },
      },
    },
    openStaged: async (ref) => {
      log.push("open");
      return opener(ref);
    },
    stagingStore: stagingDeps,
    ...extra,
  });
  return w;
}

afterEach(() => {
  vi.restoreAllMocks();
  // A fake-timer test that times out never reaches its own finally.
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const HEAD = 'From: a@x\r\nTo: b@x\r\nContent-Type: multipart/mixed; boundary="b1"\r\n\r\n--b1\r\nContent-Transfer-Encoding: base64\r\n\r\n';
const TAIL = "--b1--\r\n";

function gmailCtx(ref: StagedRef, path = "/upload/send"): UpstreamCtx {
  return {
    method: "POST",
    path,
    query: { uploadType: "media" },
    contentType: "message/rfc822",
    composed: {
      segments: [{ text: HEAD }, { staged: ref, encoding: "base64-lines" }, { text: TAIL }],
    },
  };
}

describe("composed — happy path and the inspection view", () => {
  it("sends the assembled RFC 822 bytes as a ReadableStream with Content-Length and redirect: manual", async () => {
    const w = world();
    const file = pattern(BLOCK_BYTES + 100);
    const ref = await w.stage(file);
    const res = (await handleUpstreamRequest(w.args(gmailCtx(ref)))) as Record<string, unknown>;
    expect(res.success).toBe(true);
    const expected = HEAD + lines76(Buffer.from(file).toString("base64")) + TAIL;
    expect(w.sent).toHaveLength(1);
    const s = w.sent[0]!;
    expect(Buffer.from(s.body).toString("latin1")).toBe(expected);
    expect(s.init.body).toBeInstanceOf(ReadableStream);
    expect(s.init.signal).toBeInstanceOf(AbortSignal);
    expect(s.init.redirect).toBe("manual");
    const headers = s.init.headers as Record<string, string>;
    expect(headers["Content-Length"]).toBe(String(expected.length));
    expect(headers["content-type"]).toBe("message/rfc822");
  });

  it("the inspector receives the U+FFFC view, staged metadata and assembledByteLength", async () => {
    const w = world();
    const file = pattern(1000);
    const ref = await w.stage(file, "application/pdf", "q\r\n.pdf");
    await handleUpstreamRequest(w.args(gmailCtx(ref)));
    expect(w.inspected).toHaveLength(1);
    const req = w.inspected[0]!;
    expect(req.rawBody).toBe(HEAD + "￼" + TAIL);
    expect(req.contentType).toBe("message/rfc822");
    expect(req.query).toEqual({ uploadType: "media" });
    expect(req.staged).toEqual([
      { index: 1, byteLength: 1000, contentType: "application/pdf", filename: "q.pdf", encoding: "base64-lines" },
    ]);
    expect(req.assembledByteLength).toBe(HEAD.length + lines76(Buffer.from(file).toString("base64")).length + TAIL.length);
    expect(Object.isFrozen(req)).toBe(true);
  });

  it("a bare-allow op accepts a sole identity segment (Xero raw-octet attachment)", async () => {
    const w = world();
    const file = pattern(3000);
    const ref = await w.stage(file);
    await handleUpstreamRequest(
      w.args({
        method: "PUT",
        path: "/attach/q.pdf",
        contentType: "application/pdf",
        composed: { segments: [{ staged: ref, encoding: "identity" }] },
      }),
    );
    expect(Buffer.from(w.sent[0]!.body).equals(Buffer.from(file))).toBe(true);
    expect((w.sent[0]!.init.headers as Record<string, string>)["content-type"]).toBe("application/pdf");
  });

  it("audit carries stagedCount/stagedBytes/assembledBytes/bodyBytesSent/bodyComplete and never a token or handle", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    await handleUpstreamRequest(
      w.args({
        method: "PUT",
        path: "/attach/x",
        composed: { segments: [{ staged: ref, encoding: "identity" }] },
      }),
    );
    const last = w.audit().at(-1)!;
    expect(last).toMatchObject({ decision: "allow", stagedCount: 1, stagedBytes: 10, assembledBytes: 10, bodyBytesSent: 10, bodyComplete: true, upstreamStatus: 200 });
    const all = JSON.stringify(w.audit());
    expect(all).not.toContain(ref.token);
    expect(all).not.toContain(ref.file_handle);
  });
});

describe("composed — phase order (D7, D10a)", () => {
  it("static deny: the opener is never called", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    await expect(handleUpstreamRequest(w.args(gmailCtx(ref, "/denied")))).rejects.toThrow(/denied/);
    expect(w.log).not.toContain("open");
  });

  it("an inspected op without acceptsStaged → staged-not-supported before the inspector and the opener", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    await expect(handleUpstreamRequest(w.args(gmailCtx(ref, "/send")))).rejects.toThrow(/staged/);
    expect(w.log).toEqual([]);
    expect(w.audit().at(-1)).toMatchObject({ decision: "deny", reason: "staged-not-supported", operationId: "sendJson" });
  });

  it("an elicit op without acceptsStaged → staged-not-supported (multipart staged too)", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    await expect(
      handleUpstreamRequest(w.args({ method: "POST", path: "/approve-plain", multipart: [{ name: "f", staged: ref }] })),
    ).rejects.toThrow(/staged/);
    expect(w.elicitInput).not.toHaveBeenCalled();
    expect(w.audit().at(-1)).toMatchObject({ reason: "staged-not-supported" });
  });

  it("order: open → inspect → mint → gate → r2 → fetch", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    const gate = new FakeGate();
    const acquire = gate.acquire.bind(gate);
    gate.acquire = async (k, s) => {
      w.log.push("gate");
      return acquire(k, s);
    };
    w.log.length = 0;
    await handleUpstreamRequest(w.args(gmailCtx(ref), { transferGate: gate, runKey: {} }));
    // The writer and fetch start together; R2 is read only once both run.
    expect(w.log.slice(0, 4)).toEqual(["open", "inspect", "mint", "gate"]);
    expect([...w.log.slice(4)].sort()).toEqual(["fetch", "r2"]);
    expect(gate.released).toBe(1);
  });

  it("elicit: no R2 read before the approval resolves; dialog shows opaque summary + attachments", async () => {
    const w = world();
    const ref = await w.stage(pattern(1000), "application/pdf", "q‮fdp.exe");
    w.log.length = 0;
    await handleUpstreamRequest(w.args(gmailCtx(ref, "/approve")));
    expect(w.log.slice(0, 3)).toEqual(["open", "elicit", "mint"]);
    expect([...w.log.slice(3)].sort()).toEqual(["fetch", "r2"]);
    const params = w.elicitInput.mock.calls[0]![0] as { message: string; requestedSchema: { properties: Record<string, unknown> } };
    expect(params.message).toMatch(/composed, 3 segments, 1 staged file, \d+ bytes/);
    expect(params.message).toContain("qfdp.exe (1000 bytes)");
    expect(params.message).not.toContain(ref.token);
  });

  it("unresolvable refs → ToolError naming the segment, no inspector, no R2, no token in the message", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    const wrong = { file_handle: ref.file_handle, token: (await w.stage(pattern(1))).token };
    const err = await handleUpstreamRequest(w.args(gmailCtx(wrong))).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/segment 1/);
    expect((err as Error).message).not.toContain(wrong.token);
    expect((err as Error).message).not.toContain(wrong.file_handle);
    expect(w.log).not.toContain("inspect");
    expect(w.log).not.toContain("r2");
  });

  it("composed-too-large is refused after resolution, before any R2 read or inspection", async () => {
    const w = world();
    const ref = await w.stage(pattern(1000));
    w.log.length = 0;
    const err = await handleUpstreamRequest(
      w.args(gmailCtx(ref), { stagingLimits: { composeMaxBytes: 500 } }),
    ).catch((e: unknown) => e);
    expect((err as Error).message).toMatch(/composed-too-large/);
    expect((err as Error).message).toContain("500");
    expect(w.log).toEqual(["open"]);
    expect(w.audit().at(-1)).toMatchObject({ decision: "deny", reason: "composed-too-large" });
  });

  it("malformed composed is refused at entry with an audit line and no storage access", async () => {
    const w = world();
    const err = await handleUpstreamRequest(
      w.args({ method: "POST", path: "/upload/send", composed: { segments: [{ text: "a￼" }] } }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect(w.log).toEqual([]);
    expect(w.audit().at(-1)).toMatchObject({ decision: "deny", category: "malformed", reason: "composed-text-reserved-char" });
  });

  it("composed + body on a plain allow op is still multiple-body-channels", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    await expect(
      handleUpstreamRequest(
        w.args({ method: "PUT", path: "/attach/x", body: { a: 1 }, composed: { segments: [{ staged: ref, encoding: "identity" }] } }),
      ),
    ).rejects.toThrow(/cannot be combined/);
    expect(w.audit().at(-1)).toMatchObject({ reason: "multiple-body-channels" });
  });

  it("binary values inside composed are refused", async () => {
    const w = world();
    await expect(
      handleUpstreamRequest(
        w.args({ method: "PUT", path: "/attach/x", composed: { segments: [{ text: new Uint8Array(2) }] } } as unknown as UpstreamCtx),
      ),
    ).rejects.toThrow(/Binary values/);
  });

  it("no openStaged dep → ToolError (staging not configured)", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    const a = w.args({ method: "PUT", path: "/attach/x", composed: { segments: [{ staged: ref, encoding: "identity" }] } });
    delete a.openStaged;
    await expect(handleUpstreamRequest(a)).rejects.toThrow(/staging/);
  });
});

describe("composed — normalizeComposedText", () => {
  it("is applied to the leading text only, and what is sent equals what was normalised", async () => {
    const w = world();
    const ref = await w.stage(pattern(5));
    await handleUpstreamRequest(
      w.args({
        method: "POST",
        path: "/drafts",
        composed: {
          segments: [
            { text: "Subject: bad\r\n" },
            { text: "\r\n" },
            { staged: ref, encoding: "base64" },
            { text: "Subject: bad" },
          ],
        },
      }),
    );
    const sent = Buffer.from(w.sent[0]!.body).toString();
    expect(sent.startsWith("Subject: good\r\n\r\n")).toBe(true);
    expect(sent.endsWith("Subject: bad")).toBe(true);
  });

  it("is a no-op for a sole identity segment", async () => {
    const w = world();
    const file = new TextEncoder().encode("Subject: bad\r\n\r\nhi");
    const ref = await w.stage(file);
    await handleUpstreamRequest(
      w.args({ method: "POST", path: "/drafts", composed: { segments: [{ staged: ref, encoding: "identity" }] } }),
    );
    expect(Buffer.from(w.sent[0]!.body).toString()).toBe("Subject: bad\r\n\r\nhi");
  });

  it("a normaliser result that breaks the text rules is ignored (fail-open)", async () => {
    const w = world();
    const ref = await w.stage(pattern(5));
    const a = w.args({
      method: "POST",
      path: "/drafts",
      composed: { segments: [{ text: "Subject: bad\r\n\r\n" }, { staged: ref, encoding: "base64" }] },
    });
    a.surfaceReview = { ...a.surfaceReview, draftMedia: { decision: "allow", acceptsStaged: true, normalizeComposedText: () => "x￼" } };
    await handleUpstreamRequest(a);
    expect(Buffer.from(w.sent[0]!.body).toString().startsWith("Subject: bad")).toBe(true);
  });
});

describe("multipart[].staged", () => {
  it("end to end: staged bytes as a part with sanitised row defaults", async () => {
    const w = world();
    const file = pattern(2000);
    const ref = await w.stage(file, "application/pdf; boundary=zz", 'q"\r\n.pdf');
    await handleUpstreamRequest(
      w.args({ method: "POST", path: "/files", multipart: [{ name: "Name", value: "q.pdf" }, { name: "file", staged: ref }] }),
    );
    const s = w.sent[0]!;
    const ct = (s.init.headers as Record<string, string>)["content-type"]!;
    const boundary = /boundary=(.+)$/.exec(ct)![1]!;
    const ref822 = Buffer.concat([
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="Name"\r\nContent-Type: text/plain\r\n\r\nq.pdf\r\n` +
          `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="q.pdf"\r\nContent-Type: application/pdf\r\n\r\n`,
      ),
      Buffer.from(file),
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]);
    expect(Buffer.from(s.body).equals(ref822)).toBe(true);
    expect((s.init.headers as Record<string, string>)["Content-Length"]).toBe(String(ref822.byteLength));
  });

  it("the inspector sees staged part metadata, never bytes", async () => {
    const w = world();
    const ref = await w.stage(pattern(20), "image/png", "a.png");
    await handleUpstreamRequest(
      w.args({ method: "POST", path: "/inspected-files", multipart: [{ name: "file", staged: ref }] }),
    );
    const req = w.inspected[0]!;
    expect(req.multipart).toEqual([
      { name: "file", filename: "a.png", contentType: "image/png", staged: { byteLength: 20, contentType: "image/png", filename: "a.png" } },
    ]);
    expect(req.contentType).toBe("multipart/form-data");
    expect(typeof req.assembledByteLength).toBe("number");
  });

  it("staged with value or bodyBase64 on the same part → multipart-part-malformed", async () => {
    const w = world();
    const ref = await w.stage(pattern(2));
    for (const extra of [{ value: "x" }, { bodyBase64: "AA==" }]) {
      await expect(
        handleUpstreamRequest(w.args({ method: "POST", path: "/files", multipart: [{ name: "f", staged: ref, ...extra }] })),
      ).rejects.toThrow(/staged/);
      expect(w.audit().at(-1)).toMatchObject({ reason: "multipart-part-malformed" });
    }
  });

  it("a non-object or implausible staged ref → multipart-part-malformed", async () => {
    const w = world();
    for (const staged of ["fh_x", [1], { file_handle: "fh_x", token: "stg_y" }, null]) {
      await expect(
        handleUpstreamRequest(
          w.args({ method: "POST", path: "/files", multipart: [{ name: "f", staged }] } as unknown as UpstreamCtx),
        ),
      ).rejects.toThrow(ToolError);
      expect(w.audit().at(-1)).toMatchObject({ reason: "multipart-part-malformed" });
    }
  });
});

describe("composed — writer/fetch coupling (D3a)", () => {
  async function bigRef(w: World, n = 3 * BLOCK_BYTES) {
    return w.stage(pattern(n));
  }
  const identityCtx = (ref: StagedRef): UpstreamCtx => ({
    method: "PUT",
    path: "/attach/x",
    composed: { segments: [{ staged: ref, encoding: "identity" }] },
  });

  it("upstream answers 413 after 4 KB: envelope returned, sink aborted, gate released, no hang", async () => {
    const w = world();
    const ref = await bigRef(w);
    let keptReader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    w.upstream = async ({ body }) => {
      const reader = body!.getReader();
      let got = 0;
      while (got < 4096) {
        const { value, done } = await reader.read();
        if (done) break;
        got += value.byteLength;
      }
      keptReader = reader;
      return new Response("too big", { status: 413 });
    };
    const gate = new TransferGate({ maxConcurrent: 1, maxWaiting: 0, perRunInFlight: 1, perRunWaiting: 1 });
    const res = (await handleUpstreamRequest(w.args(identityCtx(ref), { transferGate: gate, runKey: {} }))) as Record<string, unknown>;
    expect(res.success).toBe(false);
    expect(res.status).toBe(413);
    // The rest of the body is an error, never a clean EOF.
    let sawError = false;
    for (let i = 0; i < 10; i++) {
      try {
        const { done } = await keptReader!.read();
        expect(done).toBe(false);
      } catch {
        sawError = true;
        break;
      }
    }
    expect(sawError).toBe(true);
    // Released: an immediate acquire succeeds with a zero-length queue.
    const release = await gate.acquire({}, new AbortController().signal);
    release();
  });

  it("fetch rejecting mid-body → ToolError, gate released", async () => {
    const w = world();
    const ref = await bigRef(w);
    w.upstream = async ({ body }) => {
      const reader = body!.getReader();
      await reader.read();
      throw new TypeError("connection reset");
    };
    const gate = new FakeGate();
    const err = await handleUpstreamRequest(w.args(identityCtx(ref), { transferGate: gate, runKey: {} })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/upstream request failed/);
    expect(gate.released).toBe(1);
  });

  it("writer rejecting (corrupt block) → fetch aborted, ToolError, gate released", async () => {
    const w = world();
    const ref = await bigRef(w);
    const gate = new FakeGate();
    let fetchSignal: AbortSignal | undefined;
    w.upstream = async ({ body, init }) => {
      fetchSignal = init.signal ?? undefined;
      await drainAll(body);
      return new Response("ok");
    };
    const a = w.args(identityCtx(ref), { transferGate: gate, runKey: {} });
    a.openStaged = async (r): Promise<OpenStagedResult> => {
      const opened = await createStagedFileOpener({
        STAGING_D1: w.d1 as unknown as D1Database,
        STAGING_R2: w.r2 as unknown as R2Bucket,
        config: CFG,
        now: () => NOW,
      })(r);
      if (!opened.ok) return opened;
      const file: OpenStagedFile = {
        meta: opened.file.meta,
        readBlocks: async (onBlock) => {
          await onBlock(new Uint8Array(BLOCK_BYTES), 0);
          throw new Error("stored file is corrupt");
        },
      };
      return { ok: true, file };
    };
    const err = await handleUpstreamRequest(a).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/staged/);
    expect((err as Error).message).not.toContain(ref.token);
    expect(fetchSignal?.aborted).toBe(true);
    expect(gate.released).toBe(1);
  });

  it("host deadline mid-file → fetch aborted, body shorter than Content-Length, gate released", async () => {
    const w = world();
    const ref = await bigRef(w);
    const run = new AbortController();
    const gate = new FakeGate();
    let fetchSignal: AbortSignal | undefined;
    w.upstream = async ({ body, init }) => {
      fetchSignal = init.signal ?? undefined;
      const reader = body!.getReader();
      await reader.read();
      run.abort(new Error("host deadline"));
      for (;;) {
        const { done } = await reader.read();
        if (done) return new Response("finished");
      }
    };
    const err = await handleUpstreamRequest(
      w.args(identityCtx(ref), { transferGate: gate, runKey: {}, signal: run.signal }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/deadline/);
    expect(fetchSignal?.aborted).toBe(true);
    expect(w.sent[0]!.body.byteLength).toBeLessThan(3 * BLOCK_BYTES);
    expect(gate.released).toBe(1);
  });

  it("an already-aborted run signal refuses before any fetch", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    const run = new AbortController();
    run.abort(new Error("host deadline"));
    await expect(handleUpstreamRequest(w.args(identityCtx(ref), { signal: run.signal, transferGate: new TransferGate({ maxConcurrent: 1, maxWaiting: 1, perRunInFlight: 1, perRunWaiting: 1 }), runKey: {} }))).rejects.toThrow();
    expect(w.sent).toHaveLength(0);
  });

  it("per-transfer timeout fires → fetch aborted, ToolError, gate released", async () => {
    const w = world();
    const ref = await bigRef(w);
    const gate = new FakeGate();
    w.upstream = async ({ body, init }) => {
      const reader = body!.getReader();
      await reader.read();
      // Stop reading and wait until aborted.
      await new Promise((_, reject) => init.signal!.addEventListener("abort", () => reject(init.signal!.reason)));
      return new Response("never");
    };
    const err = await handleUpstreamRequest(
      w.args(identityCtx(ref), { transferGate: gate, runKey: {}, stagingLimits: { transferTimeoutMs: 30 } }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/timed out/);
    expect(gate.released).toBe(1);
  });

  it("a gate refusal surfaces as a ToolError before any fetch or R2 read", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    const gate = new FakeGate();
    gate.rejectWith = new ToolError("one staged transfer at a time per execution; await each before starting the next");
    w.log.length = 0;
    await expect(handleUpstreamRequest(w.args(identityCtx(ref), { transferGate: gate, runKey: {} }))).rejects.toThrow(/one staged transfer/);
    expect(w.log).not.toContain("r2");
    expect(w.sent).toHaveLength(0);
  });
});

describe("returnAs: \"stage\" over block sources", () => {
  function streamResponse(bytes: Uint8Array, headers: Record<string, string>): Response {
    let sent = false;
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        if (!sent) {
          sent = true;
          c.enqueue(bytes);
        } else c.close();
      },
    });
    const r = new Response(body, { status: 200, headers: { "content-type": "application/pdf", ...headers } });
    return r;
  }

  it("stages the body (no arrayBuffer), returns the handle envelope; the bytes round-trip", async () => {
    const w = world();
    const file = pattern(BLOCK_BYTES + 7);
    w.upstream = async () => {
      const r = streamResponse(file, { "content-disposition": 'attachment; filename="f.pdf"' });
      r.arrayBuffer = () => {
        throw new Error("arrayBuffer must not be used");
      };
      return r;
    };
    const gate = new FakeGate();
    const res = (await handleUpstreamRequest(
      w.args({ method: "GET", path: "/download", returnAs: "stage" }, { transferGate: gate, runKey: {} }),
    )) as { success: boolean; result: Record<string, unknown> };
    expect(res.success).toBe(true);
    expect(res.result).toMatchObject({ byte_length: file.byteLength, contentType: "application/pdf", filename: "f.pdf" });
    expect(gate.acquired).toHaveLength(1);
    expect(gate.released).toBe(1);
    const opened = await createStagedFileOpener({
      STAGING_D1: w.d1 as unknown as D1Database,
      STAGING_R2: w.r2 as unknown as R2Bucket,
      config: CFG,
      now: () => NOW,
    })({ file_handle: res.result.file_handle as string, token: res.result.token as string });
    expect(opened.ok).toBe(true);
    const parts: Uint8Array[] = [];
    if (opened.ok) await opened.file.readBlocks(async (b) => void parts.push(b.slice()));
    expect(Buffer.concat(parts).equals(Buffer.from(file))).toBe(true);
  });

  for (const delta of [1, -1]) {
    it(`lying Content-Length (N${delta > 0 ? "+" : "−"}1) → 502, no R2 object, no row`, async () => {
      const w = world();
      const file = pattern(5000);
      w.upstream = async () => streamResponse(file, { "content-length": String(file.byteLength + delta) });
      const res = (await handleUpstreamRequest(
        w.args({ method: "GET", path: "/download", returnAs: "stage" }),
      )) as { success: boolean; status: number; result: Record<string, unknown> };
      expect(res.success).toBe(false);
      expect(res.status).toBe(502);
      expect(res.result.error).toBe("stage_failed");
      expect(w.r2.store.size).toBe(0);
      expect(w.d1.rows.size).toBe(0);
    });
  }

  it("a declared length over maxBytes → 413 before reading", async () => {
    const w = world();
    const big = streamResponse(pattern(10), { "content-length": String(CFG.maxBytes + 1) });
    w.upstream = async () => big;
    const res = (await handleUpstreamRequest(w.args({ method: "GET", path: "/download", returnAs: "stage" }))) as {
      status: number;
    };
    expect(res.status).toBe(413);
    expect(w.r2.store.size).toBe(0);
  });

  it("no staging store → ToolError", async () => {
    const w = world();
    w.upstream = async () => streamResponse(pattern(3), {});
    const a = w.args({ method: "GET", path: "/download", returnAs: "stage" });
    delete a.stagingStore;
    await expect(handleUpstreamRequest(a)).rejects.toThrow(/staging/);
  });
});

describe("security review fixes", () => {
  it("BOM-leading text: view (U+FFFC → reference encoding) byte-equals the wire, first and non-first segment", async () => {
    const w = world();
    const file = pattern(100);
    const ref = await w.stage(file);
    await handleUpstreamRequest(
      w.args({
        method: "POST",
        path: "/upload/send",
        contentType: "message/rfc822",
        composed: {
          segments: [
            { text: "\uFEFFFrom: me@x\r\nTo: ok@allowed\r\n" },
            { text: "\uFEFF\r\nBcc: victim@external\r\n\r\n" },
            { staged: ref, encoding: "base64" },
          ],
        },
      }),
    );
    const req = w.inspected[0]!;
    const view = (req.rawBody as string).replace("\uFFFC", Buffer.from(file).toString("base64"));
    expect(Buffer.from(view, "utf8").equals(Buffer.from(w.sent[0]!.body))).toBe(true);
    expect(req.assembledByteLength).toBe(w.sent[0]!.body.byteLength);
  });

  it("BOM survives the normaliser path (draft op)", async () => {
    const w = world();
    const ref = await w.stage(pattern(5));
    await handleUpstreamRequest(
      w.args({
        method: "POST",
        path: "/drafts",
        composed: { segments: [{ text: "\uFEFFSubject: bad\r\n\r\n" }, { staged: ref, encoding: "base64" }] },
      }),
    );
    const sent = Buffer.from(w.sent[0]!.body);
    expect(sent.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))).toBe(true);
    expect(sent.subarray(3).toString().startsWith("Subject: good")).toBe(true);
  });

  const identityCtx = (ref: StagedRef): UpstreamCtx => ({
    method: "PUT",
    path: "/attach/x",
    composed: { segments: [{ staged: ref, encoding: "identity" }] },
  });

  function stalledBodyResponse(signal: AbortSignal | null | undefined): Response {
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new TextEncoder().encode('{"a":'));
        signal?.addEventListener("abort", () => c.error(signal.reason));
      },
    });
    return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
  }

  it("response body stalls after headers → transfer timeout fires, ToolError, gate released", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    const gate = new FakeGate();
    w.upstream = async ({ body, init }) => {
      await drainAll(body);
      return stalledBodyResponse(init.signal);
    };
    const err = await handleUpstreamRequest(
      w.args(identityCtx(ref), { transferGate: gate, runKey: {}, stagingLimits: { transferTimeoutMs: 40 } }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/timed out/);
    expect(gate.released).toBe(1);
  });

  it("host deadline during the response read → ToolError, gate released", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    const gate = new FakeGate();
    const run = new AbortController();
    w.upstream = async ({ body, init }) => {
      await drainAll(body);
      setTimeout(() => run.abort(new Error("deadline")), 10);
      return stalledBodyResponse(init.signal);
    };
    const err = await handleUpstreamRequest(
      w.args(identityCtx(ref), { transferGate: gate, runKey: {}, signal: run.signal }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/deadline/);
    expect(gate.released).toBe(1);
  });

  it("fetch throwing synchronously → ToolError, the writer is aborted (no block read left running)", async () => {
    const w = world();
    const ref = await w.stage(pattern(3 * BLOCK_BYTES));
    w.log.length = 0;
    vi.stubGlobal("fetch", (url: RequestInfo | URL) => {
      if (String(url).includes("/token")) return Promise.resolve(new Response("{}"));
      throw new TypeError("bad init");
    });
    const err = await handleUpstreamRequest(w.args(identityCtx(ref))).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/upstream request failed/);
    await new Promise((r) => setTimeout(r, 20));
    // The writer stopped: at most the first block was pulled from R2.
    expect(w.log.filter((x) => x === "r2").length).toBeLessThanOrEqual(1);
  });

  it("explicit Content-Length only without a platform FixedLengthStream", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    await handleUpstreamRequest(w.args(identityCtx(ref)));
    expect((w.sent[0]!.init.headers as Record<string, string>)["Content-Length"]).toBe("10");

    class FakeFls {
      readable: ReadableStream<Uint8Array>;
      writable: WritableStream<Uint8Array>;
      constructor(_n: number) {
        const ts = new TransformStream<Uint8Array, Uint8Array>();
        this.readable = ts.readable;
        this.writable = ts.writable;
      }
    }
    vi.stubGlobal("FixedLengthStream", FakeFls);
    await handleUpstreamRequest(w.args(identityCtx(ref)));
    const h = w.sent[1]!.init.headers as Record<string, string>;
    expect(Object.keys(h).some((k) => k.toLowerCase() === "content-length")).toBe(false);
  });

  it("multipart[].staged + another body channel on a gated op → multiple-body-channels with zero D1 reads", async () => {
    const w = world();
    const ref = await w.stage(pattern(2));
    const prepare = vi.spyOn(w.d1, "prepare");
    await expect(
      handleUpstreamRequest(
        w.args({ method: "POST", path: "/inspected-files", body: { a: 1 }, multipart: [{ name: "f", staged: ref }] }),
      ),
    ).rejects.toThrow(ToolError);
    expect(prepare).not.toHaveBeenCalled();
    expect(w.audit().at(-1)).toMatchObject({ reason: "multiple-body-channels" });
  });
});

describe("writer failure reason surfaces", () => {
  it("a corrupt block reports 'staged transfer failed: <reason>', not the generic abort", async () => {
    const w = world();
    const ref = await w.stage(pattern(3 * BLOCK_BYTES));
    w.upstream = async ({ body }) => {
      await drainAll(body).catch(() => {});
      return new Response("ok");
    };
    const a = w.args({ method: "PUT", path: "/attach/x", composed: { segments: [{ staged: ref, encoding: "identity" }] } });
    a.openStaged = async (): Promise<OpenStagedResult> => ({
      ok: true,
      file: {
        meta: { byteLength: 3 * BLOCK_BYTES, contentType: "application/pdf", filename: null },
        readBlocks: async (onBlock) => {
          await onBlock(new Uint8Array(BLOCK_BYTES), 0);
          throw new StagedFileReadError(410, "stored file is corrupt");
        },
      },
    });
    const err = await handleUpstreamRequest(a).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/^staged transfer failed: stored file is corrupt/);
  });
});

describe("upstream closes the connection mid-body", () => {
  const SIZE = 3 * BLOCK_BYTES;
  const identityCtx = (ref: StagedRef): UpstreamCtx => ({
    method: "PUT",
    path: "/attach/x",
    composed: { segments: [{ staged: ref, encoding: "identity" }] },
  });
  /** Records how the writer's block read ended. */
  function trackReads(a: HandleArgs<Record<string, unknown>>) {
    const t = { blocks: 0, outcome: "pending" as "pending" | "resolved" | "rejected" };
    const open = a.openStaged!;
    a.openStaged = async (r) => {
      const opened = await open(r);
      if (!opened.ok) return opened;
      const inner = opened.file;
      const file: OpenStagedFile = {
        meta: inner.meta,
        readBlocks: (onBlock) => {
          const p = inner.readBlocks(async (plain, i) => {
            t.blocks++;
            await onBlock(plain, i);
          });
          p.then(
            () => (t.outcome = "resolved"),
            () => (t.outcome = "rejected"),
          );
          return p;
        },
      };
      return { ok: true, file };
    };
    return t;
  }
  /** Waits `ms` of real time; setImmediate is never faked here. */
  async function realDelay(ms: number): Promise<void> {
    const end = performance.now() + ms;
    while (performance.now() < end) await new Promise<void>((r) => setImmediate(r));
  }
  /** Yields real event-loop turns until `cond` holds; fails after `ms` of real
   *  time, well inside the test timeout, so the test reports instead of hanging. */
  async function untilReal(what: string, cond: () => boolean, ms = 2_000): Promise<void> {
    const end = performance.now() + ms;
    while (!cond()) {
      if (performance.now() > end) throw new Error(`timed out waiting for: ${what}`);
      await new Promise<void>((r) => setImmediate(r));
    }
  }
  /** Reads `n` bytes, then closes the connection (cancels the body). */
  async function readThenClose(body: ReadableStream<Uint8Array> | null, n: number): Promise<number> {
    const reader = body!.getReader();
    let got = 0;
    while (got < n) {
      const { value, done } = await reader.read();
      if (done) break;
      got += value.byteLength;
    }
    await reader.cancel(new Error("connection closed by peer"));
    return got;
  }

  it("(a) the upstream then answers 413 → the 413 envelope, not a staged-file error; writer aborted, gate released", async () => {
    const w = world();
    const ref = await w.stage(pattern(SIZE));
    w.upstream = async ({ body }) => {
      await readThenClose(body, 4096);
      // The writer notices the closed stream before the response arrives.
      await new Promise((r) => setTimeout(r, 50));
      return new Response("Request Entity Too Large", { status: 413 });
    };
    const gate = new FakeGate();
    const a = w.args(identityCtx(ref), { transferGate: gate, runKey: {} });
    const t = trackReads(a);
    const res = (await handleUpstreamRequest(a)) as Record<string, unknown>;
    expect(res.success).toBe(false);
    expect(res.status).toBe(413);
    expect(t.outcome).toBe("rejected");
    expect(t.blocks).toBeLessThan(3);
    expect(gate.released).toBe(1);
  });

  it("the upstream stops reading after 1 MiB of 3 MiB and still answers 200 → success, the audit records the short body", async () => {
    const w = world();
    const ref = await w.stage(pattern(SIZE));
    w.upstream = async ({ body }) => {
      await readThenClose(body, BLOCK_BYTES);
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    };
    const res = (await handleUpstreamRequest(w.args(identityCtx(ref), { transferGate: new FakeGate(), runKey: {} }))) as Record<string, unknown>;
    expect(res.success).toBe(true);
    const last = w.audit().at(-1)!;
    expect(last).toMatchObject({ assembledBytes: SIZE, bodyComplete: false, upstreamStatus: 200 });
    expect(last.bodyBytesSent).toBeGreaterThan(0);
    expect(last.bodyBytesSent).toBeLessThan(SIZE);
  });

  it("(b) the upstream never answers → after the grace, 'upstream closed the connection after N of M bytes'", async () => {
    const w = world();
    const ref = await w.stage(pattern(SIZE));
    let fetchSignal: AbortSignal | undefined;
    w.upstream = async ({ body, init }) => {
      fetchSignal = init.signal ?? undefined;
      // A slow runner: the body read starts after real time has passed.
      await realDelay(100);
      await readThenClose(body, 4096);
      return new Promise<Response>((_, reject) =>
        init.signal!.addEventListener("abort", () => reject(init.signal!.reason)),
      );
    };
    const gate = new FakeGate();
    const a = w.args(identityCtx(ref), { transferGate: gate, runKey: {} });
    const t = trackReads(a);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      let settled = false;
      const p = handleUpstreamRequest(a).then(
        () => { settled = true; return undefined; },
        (e: unknown) => { settled = true; return e; },
      );
      // Advance fake time only once the grace timer exists: the body read,
      // the writer failure and the timer registration all run on real time.
      await untilReal("the upstream fetch", () => fetchSignal !== undefined);
      const base = vi.getTimerCount();
      await untilReal("the writer failure", () => t.outcome === "rejected");
      await untilReal("the grace timer", () => vi.getTimerCount() > base);
      await vi.advanceTimersByTimeAsync(UPSTREAM_CLOSE_GRACE_MS - 1);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await untilReal("the handler to settle", () => settled);
      const err = await p;
      expect(err).toBeInstanceOf(ToolError);
      const msg = (err as Error).message;
      expect(msg).toMatch(new RegExp(`upstream closed the connection after \\d+ of ${SIZE} bytes`));
      const sentN = Number(/after (\d+) of/.exec(msg)![1]);
      expect(sentN).toBeGreaterThan(0);
      expect(sentN).toBeLessThan(SIZE);
      expect(msg).not.toContain("could not be read");
      expect(msg).not.toContain(ref.token);
      expect(msg).not.toContain(ref.file_handle);
    } finally {
      vi.useRealTimers();
    }
    expect(fetchSignal?.aborted).toBe(true);
    expect(t.outcome).toBe("rejected");
    expect(gate.released).toBe(1);
  });

  it("(c) a real StagedFileReadError mid-body still reports the stored-file failure, at once", async () => {
    const w = world();
    const ref = await w.stage(pattern(SIZE));
    let fetchSignal: AbortSignal | undefined;
    w.upstream = async ({ body, init }) => {
      fetchSignal = init.signal ?? undefined;
      await drainAll(body).catch(() => {});
      return new Promise<Response>((_, reject) =>
        init.signal!.addEventListener("abort", () => reject(init.signal!.reason)),
      );
    };
    const gate = new FakeGate();
    const a = w.args(identityCtx(ref), { transferGate: gate, runKey: {} });
    let readEnded = false;
    a.openStaged = async (): Promise<OpenStagedResult> => ({
      ok: true,
      file: {
        meta: { byteLength: SIZE, contentType: "application/pdf", filename: null },
        readBlocks: async (onBlock) => {
          try {
            await onBlock(new Uint8Array(BLOCK_BYTES), 0);
            throw new StagedFileReadError(410, "stored file is corrupt");
          } finally {
            readEnded = true;
          }
        },
      },
    });
    const started = Date.now();
    const err = await handleUpstreamRequest(a).catch((e: unknown) => e);
    expect(Date.now() - started).toBeLessThan(UPSTREAM_CLOSE_GRACE_MS);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/^staged transfer failed: stored file is corrupt/);
    expect(fetchSignal?.aborted).toBe(true);
    expect(readEnded).toBe(true);
    expect(gate.released).toBe(1);
  });

  /** Fake timers on; the upstream reads 4 KiB, closes, then hangs until
   *  `fail` is called. It ignores its abort signal, so only the grace's own
   *  abort handling can end the grace early. Resolves once the grace timer
   *  exists. */
  async function startInGrace(extra: Partial<HandleArgs<Record<string, unknown>>> = {}) {
    const w = world();
    const ref = await w.stage(pattern(SIZE));
    const s = {
      fetchSignal: undefined as AbortSignal | undefined,
      settled: false,
      fail: (_err: unknown): void => {},
    };
    w.upstream = async ({ body, init }) => {
      s.fetchSignal = init.signal ?? undefined;
      await realDelay(20);
      await readThenClose(body, 4096);
      return new Promise<Response>((_, reject) => {
        s.fail = reject;
      });
    };
    const gate = new FakeGate();
    const a = w.args(identityCtx(ref), { transferGate: gate, runKey: {}, ...extra });
    const t = trackReads(a);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const result = handleUpstreamRequest(a).then(
      () => { s.settled = true; return undefined; },
      (e: unknown) => { s.settled = true; return e; },
    );
    await untilReal("the upstream fetch", () => s.fetchSignal !== undefined);
    const base = vi.getTimerCount();
    await untilReal("the writer failure", () => t.outcome === "rejected");
    await untilReal("the grace timer", () => vi.getTimerCount() > base);
    return { s, gate, ref, result };
  }

  it("the host deadline fires during the grace → the deadline error at once, fetch aborted, no timer left", async () => {
    const run = new AbortController();
    const { s, gate, result } = await startInGrace({ signal: run.signal });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(s.settled).toBe(false);
    run.abort();
    await untilReal("the handler to settle", () => s.settled);
    const err = await result;
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/host-side deadline/);
    expect(s.fetchSignal?.aborted).toBe(true);
    expect(gate.released).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("fetch rejects during the grace (ECONNRESET) → 'upstream closed the connection' at once, no wait for the grace", async () => {
    const { s, gate, ref, result } = await startInGrace();
    s.fail(new TypeError("fetch failed: ECONNRESET"));
    // No fake time passes: the grace must end on the rejection itself.
    await untilReal("the handler to settle", () => s.settled);
    const err = await result;
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(
      new RegExp(`^staged transfer failed: upstream closed the connection after \\d+ of ${SIZE} bytes were sent; the upstream request was aborted$`),
    );
    expect((err as Error).message).not.toContain(ref.token);
    expect(s.fetchSignal?.aborted).toBe(true);
    expect(gate.released).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("the transfer timeout fires during the grace → the 'timed out' error, not 'upstream closed'", async () => {
    const { s, gate, result } = await startInGrace({ stagingLimits: { transferTimeoutMs: 1_000 } });
    await vi.advanceTimersByTimeAsync(1_000);
    await untilReal("the handler to settle", () => s.settled);
    const err = await result;
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/timed out after 1000 ms/);
    expect(s.fetchSignal?.aborted).toBe(true);
    expect(gate.released).toBe(1);
  });

  it("sendAssembled itself: a deadline during the grace rejects with the deadline, not 'upstream closed'", async () => {
    // The handler reports the controller's reason anyway (transferFailure),
    // so this pins sendAssembled's own post-grace check.
    let fetchSignal: AbortSignal | undefined;
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      fetchSignal = init.signal ?? undefined;
      await readThenClose(init.body as ReadableStream<Uint8Array>, 4096);
      return new Promise<Response>(() => {}); // ignores its abort signal
    });
    let outcome: string | undefined;
    const file: OpenStagedFile = {
      meta: { byteLength: SIZE, contentType: "application/pdf", filename: null },
      readBlocks: async (onBlock) => {
        try {
          for (let i = 0; i < 3; i++) await onBlock(new Uint8Array(BLOCK_BYTES), i);
          outcome = "resolved";
        } catch (err) {
          outcome = "rejected";
          throw err;
        }
      },
    };
    const run = new AbortController();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const tc = transferController(run.signal, 60_000);
    const base = vi.getTimerCount();
    let settled = false;
    const result = sendAssembled(
      "https://api.example.com/attach/x",
      { method: "PUT" },
      { segments: [{ kind: "staged", ref: { file_handle: "h", token: "t" } as StagedRef, encoding: "identity", index: 0 } satisfies Segment], files: [file], length: SIZE },
      tc,
    ).then(
      () => { settled = true; return undefined; },
      (e: unknown) => { settled = true; return e; },
    );
    await untilReal("the writer failure", () => outcome === "rejected");
    await untilReal("the grace timer", () => vi.getTimerCount() > base);
    await vi.advanceTimersByTimeAsync(1_000);
    run.abort();
    await untilReal("sendAssembled to settle", () => settled);
    const err = await result;
    tc.dispose();
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/host-side deadline/);
    expect(fetchSignal?.aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("the upstream reads the whole body but closes before close() → grace, then its 200 is returned; the audit says the body was complete", async () => {
    const w = world();
    const ref = await w.stage(pattern(SIZE));
    let consumed = 0;
    w.upstream = async ({ body }) => {
      consumed = await readThenClose(body, SIZE);
      await realDelay(20);
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    };
    const gate = new FakeGate();
    const a = w.args(identityCtx(ref), { transferGate: gate, runKey: {} });
    const t = trackReads(a);
    const res = (await handleUpstreamRequest(a)) as Record<string, unknown>;
    expect(consumed).toBe(SIZE);
    expect(t.outcome).toBe("resolved");
    expect(res.success).toBe(true);
    expect(w.audit().at(-1)).toMatchObject({ upstreamStatus: 200, assembledBytes: SIZE, bodyBytesSent: SIZE, bodyComplete: true });
    expect(gate.released).toBe(1);
  });
});

describe("code-review gate fixes", () => {
  function lease(log: string[]) {
    return {
      acquire: vi.fn(async () => void log.push("lease")),
      release: vi.fn(),
    };
  }

  it("bypassTruncate inner request on an elicit op: no lease acquire while elicitation is pending; after accept, acquire follows the mint", async () => {
    const w = world();
    let approve: (v: unknown) => void = () => {};
    w.elicitInput.mockImplementation(async () => {
      w.log.push("elicit");
      return new Promise((r) => (approve = r));
    });
    const l = lease(w.log);
    const gate = new FakeGate();
    const p = handleUpstreamRequest(
      w.args({ method: "POST", path: "/approve-plain", bypassTruncate: true }, { gateLease: l, transferGate: gate, runKey: {} }),
    );
    await new Promise((r) => setTimeout(r, 20));
    expect(w.log).toEqual(["elicit"]);
    expect(l.acquire).not.toHaveBeenCalled();
    approve({ action: "accept", content: { confirm: true } });
    await p;
    expect(w.log).toEqual(["elicit", "mint", "lease", "fetch"]);
    expect(gate.acquired).toHaveLength(0); // the lease, not the handler's gate
    expect(l.release).not.toHaveBeenCalled(); // the capability releases
  });

  it("declined elicitation → the lease is never acquired", async () => {
    const w = world();
    w.elicitInput.mockImplementation(async () => ({ action: "decline" }));
    const l = lease(w.log);
    await expect(
      handleUpstreamRequest(w.args({ method: "POST", path: "/approve-plain", bypassTruncate: true }, { gateLease: l })),
    ).rejects.toThrow(/declined/);
    expect(l.acquire).not.toHaveBeenCalled();
  });

  it("a refused lease propagates and nothing is fetched", async () => {
    const w = world();
    const l = { acquire: vi.fn(async () => { throw new ToolError("one staged transfer at a time per execution; await each before starting the next"); }), release: vi.fn() };
    await expect(
      handleUpstreamRequest(w.args({ method: "GET", path: "/download", bypassTruncate: true }, { gateLease: l })),
    ).rejects.toThrow(/one staged transfer/);
    expect(w.sent).toHaveLength(0);
  });

  it("bypassTruncate inner request is bounded by the transfer timeout (stalled body)", async () => {
    const w = world();
    w.upstream = async ({ init }) => {
      const sig = init.signal;
      const body = new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(new TextEncoder().encode('{"data":"'));
          sig?.addEventListener("abort", () => c.error(sig.reason));
        },
      });
      return new Response(body, { status: 200 });
    };
    const err = await handleUpstreamRequest(
      w.args({ method: "GET", path: "/download", bypassTruncate: true }, { stagingLimits: { transferTimeoutMs: 40 } }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/timed out/);
  });

  it("returnAs:stage with a stalled body + 50 ms timeout → timeout ToolError, gate released, no row", async () => {
    const w = world();
    const gate = new FakeGate();
    w.upstream = async ({ init }) => {
      const sig = init.signal;
      const body = new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(new Uint8Array(10));
          sig?.addEventListener("abort", () => c.error(sig.reason));
        },
      });
      return new Response(body, { status: 200, headers: { "content-length": "1000" } });
    };
    const err = await handleUpstreamRequest(
      w.args({ method: "GET", path: "/download", returnAs: "stage" }, { transferGate: gate, runKey: {}, stagingLimits: { transferTimeoutMs: 50 } }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/timed out/);
    expect(gate.released).toBe(1);
    expect(w.d1.rows.size).toBe(0);
  });
});

describe("returnAs:stage with no usable length while the unknown-length slot is held", () => {
  it("→ 503 envelope (retry shortly), body cancelled, gate released", async () => {
    const w = world();
    const gate = new FakeGate();
    let cancelled = false;
    w.upstream = async () =>
      new Response(
        new ReadableStream<Uint8Array>({
          pull(c) { c.enqueue(new Uint8Array(10)); },
          cancel() { cancelled = true; },
        }),
        { status: 200, headers: { "content-encoding": "gzip", "content-length": "10" } },
      );
    const held = tryAcquireUnknownLengthSlot();
    expect(held).not.toBeNull();
    try {
      const res = (await handleUpstreamRequest(
        w.args({ method: "GET", path: "/download", returnAs: "stage" }, { transferGate: gate, runKey: {} }),
      )) as { success: boolean; status: number; errors: Array<{ message: string }> };
      expect(res.success).toBe(false);
      expect(res.status).toBe(503);
      expect(res.errors[0]!.message).toBe("staging busy with another unknown-length transfer; retry shortly");
      await vi.waitFor(() => expect(cancelled).toBe(true));
      expect(gate.released).toBe(1);
      expect(w.r2.store.size).toBe(0);
    } finally {
      held!();
    }
  });
});

