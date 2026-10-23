// D3 — Transfer gate (D8) and writer/fetch coupling (D3a, red-team R-1/R-2).
//
// Attacker: sandbox code in one execute run trying to pin the isolate's
//   memory (many concurrent file-sized transfers), or to starve other
//   sessions by filling the shared queue; an upstream that answers early
//   and stops reading (413 after 4 KB), resets mid-body, or never answers.
// Precondition: valid staged references; a gate wired as the factory wires
//   it (one TransferGate per isolate, keyed by the run's `runKey`).
// Payloads: Promise.all of 10 composed sends in one run; 20 × getFile and
//   20 × putFile in one run; an isolate queue filled by one run; an upstream
//   that answers 413 after 4 KB; the host deadline mid-file; a connection
//   reset mid-body; a stalled response body.
// Control: per run, at most one transfer in flight and one waiting — the
//   third rejects with the per-execution message while another run is still
//   admitted; the isolate semaphore is FIFO and bounded; getFile/putFile take
//   the same gate; the gate is released in `finally` on every failure path;
//   fetch and the writer are coupled through one controller so neither can
//   outlive the other, an aborted transfer leaves a body shorter than its
//   Content-Length, and no rejection is left unhandled.
//
// Pre-v2 reasoning: v1 had no gate (20 × getFile(8 MiB) was ≈800 MB of
// transient base64 text) and `fetch` took a preassembled buffer, so none of
// the coupling paths existed; a stalled upstream simply held the buffer.
//
// FakeD1/FakeR2 only; `fetch` is stubbed. No network.
import { describe, it, expect, vi, afterEach } from "vitest";
import { Buffer } from "node:buffer";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "../../request-handler";
import { ToolError } from "../../elicit";
import { TransferGate, PER_RUN_MESSAGE, RETRY_MESSAGE } from "../../compose/gate";
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
import { BLOCK_BYTES, type StagingConfig } from "../../staging/types";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReview } from "@local/shared";

const NOW = 1_700_000_000;
const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };

const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: { "/attach/{name}": { put: { operationId: "attach", responses: { "200": { description: "OK" } } } } },
  components: { schemas: {} },
} as unknown as OpenApiSpec;
const SR: SurfaceReview = { attach: { decision: "allow" } };

function pattern(n: number, seed = 9): Uint8Array {
  const a = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    a[i] = x >>> 24;
  }
  return a;
}

/** The factory's gate shape: isolate semaphore of 2, queue of 4, one in
 *  flight and one waiting per run. */
const FACTORY_GATE = { maxConcurrent: 2, maxWaiting: 4, perRunInFlight: 1, perRunWaiting: 1 } as const;
const factoryGate = () => new TransferGate(FACTORY_GATE);

type Upstream = (req: { body: ReadableStream<Uint8Array> | null; init: RequestInit }) => Promise<Response>;

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
  const opener = createStagedFileOpener(deps);
  const sent: Array<{ body: Uint8Array; init: RequestInit }> = [];
  let upstream: Upstream = async ({ body }) => {
    if (body) {
      const reader = body.getReader();
      for (;;) {
        const { done } = await reader.read();
        if (done) break;
      }
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };
  const fetchSpy = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
    const rec = { body: new Uint8Array(0), init: init ?? {} };
    sent.push(rec);
    const body = (init?.body ?? null) as ReadableStream<Uint8Array> | null;
    const recorder = new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, c) {
        rec.body = Buffer.concat([rec.body, chunk]);
        c.enqueue(chunk);
      },
    });
    return upstream({ body: body ? body.pipeThrough(recorder) : null, init: init ?? {} });
  });
  vi.stubGlobal("fetch", fetchSpy);
  vi.spyOn(console, "log").mockImplementation(() => {});
  const stage = async (bytes: Uint8Array): Promise<StagedRef> => {
    const r = await stageFromBlocks(deps, blockSourceFromBytes(bytes), "application/pdf", "q.pdf");
    if (!r.ok) throw new Error("stage failed");
    return { file_handle: r.file_handle, token: r.token };
  };
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
    oauth: { refreshTokenAccessor: () => "RT", userIdAccessor: () => "u1", broker: { getOrRefreshAccessToken: async () => "AT" } },
    openStaged: opener,
    stagingStore: deps,
    ...extra,
  });
  const identity = (ref: StagedRef): UpstreamCtx => ({
    method: "PUT",
    path: "/attach/x",
    composed: { segments: [{ staged: ref, encoding: "identity" }] },
  });
  return {
    d1,
    r2,
    deps,
    stage,
    args,
    identity,
    sent,
    fetchSpy,
    setUpstream: (u: Upstream) => {
      upstream = u;
    },
  };
}

/** Proof of release: every one of the semaphore's `slots` can be acquired at
 *  once by fresh, distinct runs. Acquiring a single slot would pass on a
 *  two-slot gate that had leaked one, so the caller states the gate's size. */
async function assertReleased(gate: TransferGate, slots = 1): Promise<void> {
  const sig = new AbortController().signal;
  const releases = await Promise.race([
    Promise.all(Array.from({ length: slots }, () => gate.acquire({}, sig))),
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error("gate still held")), 500)),
  ]);
  for (const release of releases) release();
}

function trackUnhandled() {
  const seen: unknown[] = [];
  const onUnhandled = (reason: unknown) => seen.push(reason);
  process.on("unhandledRejection", onUnhandled);
  return {
    seen,
    stop: () => process.off("unhandledRejection", onUnhandled),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("D3 — per-run cap (M5)", () => {
  it("FIXED (#59): M5 Promise.all(10 composed sends) in one run → 2 admitted, 8 refused with the per-execution message; a second run is still admitted", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    const gate = factoryGate();
    const runA = {};
    const runB = {};
    // Count attempts as they are made (run A's second acquire sits in the
    // per-run waiting slot until the first completes, so settle-time counting
    // would never reach ten).
    let attempts = 0;
    const allAttempted = new Promise<void>((resolve) => {
      const acquire = gate.acquire.bind(gate);
      gate.acquire = (k, s) => {
        if (++attempts === 10) queueMicrotask(resolve);
        return acquire(k, s);
      };
    });
    // The upstream holds every admitted send open until all ten have hit the gate.
    let release!: () => void;
    const held = new Promise<void>((r) => {
      release = r;
    });
    w.setUpstream(async ({ body }) => {
      await body!.getReader().read();
      await held;
      return new Response("{}", { status: 200 });
    });
    const unhandled = trackUnhandled();
    const sends = Array.from({ length: 10 }, () =>
      handleUpstreamRequest(w.args(w.identity(ref), { transferGate: gate, runKey: runA })).then(
        () => "ok",
        (e: unknown) => (e instanceof ToolError ? e.message : String(e)),
      ),
    );
    await allAttempted;
    // Another execute run on the same isolate is admitted while run A holds its slot.
    const other = handleUpstreamRequest(w.args(w.identity(ref), { transferGate: gate, runKey: runB })).then(() => "ok");
    await new Promise((r) => setTimeout(r, 20));
    expect(w.fetchSpy.mock.calls.length).toBeGreaterThanOrEqual(2); // run A's in-flight send + run B's
    release();
    const results = await Promise.all(sends);
    expect(results.filter((r) => r === "ok")).toHaveLength(2);
    expect(results.filter((r) => r === PER_RUN_MESSAGE)).toHaveLength(8);
    expect(await other).toBe("ok");
    unhandled.stop();
    expect(unhandled.seen).toEqual([]);
    await assertReleased(gate, FACTORY_GATE.maxConcurrent);
  });

  it("FIXED (#59): one run cannot fill the isolate queue — its third acquire is refused by the per-run cap before it reaches the queue", () => {
    const gate = factoryGate();
    const sig = new AbortController().signal;
    const runA = {};
    const a1 = gate.acquire(runA, sig); // in flight
    const a2 = gate.acquire(runA, sig); // waiting (per-run)
    void a2.catch(() => {});
    // Four more from the same run: all refused immediately; the queue stays
    // empty for other runs.
    const refused = Array.from({ length: 4 }, () => gate.acquire(runA, sig));
    return Promise.all([
      a1,
      ...refused.map((p) => p.then(() => "admitted", (e: Error) => e.message)),
    ]).then(async ([release, ...msgs]) => {
      expect(msgs).toEqual(Array(4).fill(PER_RUN_MESSAGE));
      // Other runs still get in: the semaphore has a second slot and a free queue.
      const b = await gate.acquire({}, sig);
      b();
      release();
      (await a2)();
    });
  });

  it("REFUTED: the isolate queue is FIFO and bounded; beyond maxWaiting the caller is told to retry", async () => {
    const gate = new TransferGate({ maxConcurrent: 1, maxWaiting: 2, perRunInFlight: 1, perRunWaiting: 1 });
    const sig = new AbortController().signal;
    const order: string[] = [];
    const holder = await gate.acquire({}, sig);
    const b = gate.acquire({}, sig).then((r) => {
      order.push("b");
      return r;
    });
    const c = gate.acquire({}, sig).then((r) => {
      order.push("c");
      return r;
    });
    await expect(gate.acquire({}, sig)).rejects.toThrow(RETRY_MESSAGE);
    holder();
    (await b)();
    (await c)();
    expect(order).toEqual(["b", "c"]);
  });
});

describe("D3 — getFile and putFile take the same gate", () => {
  it("FIXED (#59): Promise.all(20 × getFile(8 MiB)) in one run → 2 succeed sequentially, 18 → 429 per-run message; never two R2 reads at once", async () => {
    const w = world();
    const ref = await w.stage(pattern(8 * 1024 * 1024));
    const gate = factoryGate();
    const run = { runKey: {}, signal: new AbortController().signal };
    let inFlight = 0;
    let maxInFlight = 0;
    const realGet = w.r2.get.bind(w.r2);
    w.r2.get = async (key: string) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      const o = await realGet(key);
      if (!o) {
        inFlight--;
        return o;
      }
      const body = o.body;
      const counted = body.pipeThrough(
        new TransformStream<Uint8Array, Uint8Array>({
          flush() {
            inFlight--;
          },
        }),
      );
      return { ...o, size: o.size, arrayBuffer: o.arrayBuffer, body: counted };
    };
    const getFile = createGetFileCapability({ ...w.deps, transferGate: gate, currentRun: () => run });
    const results = await Promise.all(Array.from({ length: 20 }, () => getFile(ref.file_handle, ref.token)));
    const ok = results.filter((r) => r.ok);
    const refused = results.filter((r) => !r.ok);
    expect(ok).toHaveLength(2);
    expect(refused).toHaveLength(18);
    for (const r of refused) {
      expect(r).toMatchObject({ ok: false, status: 429, message: PER_RUN_MESSAGE });
    }
    expect(maxInFlight).toBe(1);
    expect(w.r2.getCalls).toBe(2);
    await assertReleased(gate, FACTORY_GATE.maxConcurrent);
  }, 60_000);

  it("FIXED (#59): Promise.all(20 × putFile) in one run → 2 stored, 18 → 429 before any decode or R2 write", async () => {
    const w = world();
    const gate = factoryGate();
    const run = { runKey: {}, signal: new AbortController().signal };
    const putFile = createPutFileCapability({ ...w.deps, transferGate: gate, currentRun: () => run });
    // Scaled from the plan's 24 MiB to 3 MiB per call: the gate semantics do
    // not depend on the size, only on the count.
    const payload = Buffer.from(pattern(3 * BLOCK_BYTES)).toString("base64");
    const encrypt = vi.spyOn(crypto.subtle, "encrypt");
    const results = await Promise.all(Array.from({ length: 20 }, () => putFile(payload, "application/pdf", "q.pdf")));
    expect(results.filter((r) => r.ok)).toHaveLength(2);
    expect(results.filter((r) => !r.ok && r.status === 429 && r.message === PER_RUN_MESSAGE)).toHaveLength(18);
    expect(w.r2.store.size).toBe(2);
    expect(encrypt).toHaveBeenCalledTimes(2 * 3); // three blocks per admitted call, none for the refused
    await assertReleased(gate, FACTORY_GATE.maxConcurrent);
  }, 60_000);
});

describe("D3 — the gate is released on every failure path", () => {
  it("REFUTED: fetch throws synchronously → ToolError, gate released", async () => {
    const w = world();
    const ref = await w.stage(pattern(BLOCK_BYTES + 1));
    const gate = new TransferGate({ maxConcurrent: 1, maxWaiting: 0, perRunInFlight: 1, perRunWaiting: 1 });
    w.fetchSpy.mockImplementation(() => {
      throw new TypeError("sync fetch failure");
    });
    const unhandled = trackUnhandled();
    const err = await handleUpstreamRequest(w.args(w.identity(ref), { transferGate: gate, runKey: {} })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/upstream request failed/);
    await assertReleased(gate);
    await new Promise((r) => setTimeout(r, 10));
    unhandled.stop();
    expect(unhandled.seen).toEqual([]);
  });

  it("REFUTED: the sink aborts (R2 read fails mid-file) → fetch aborted, ToolError, gate released", async () => {
    const w = world();
    const ref = await w.stage(pattern(3 * BLOCK_BYTES));
    const gate = new TransferGate({ maxConcurrent: 1, maxWaiting: 0, perRunInFlight: 1, perRunWaiting: 1 });
    const realGet = w.r2.get.bind(w.r2);
    w.r2.get = async (key: string) => {
      const o = await realGet(key);
      if (!o) return o;
      const full = w.r2.store.get(key)!;
      return {
        ...o,
        size: o.size,
        arrayBuffer: o.arrayBuffer,
        get body() {
          return new ReadableStream<Uint8Array>({
            start(c) {
              c.enqueue(full.slice(0, BLOCK_BYTES + 16));
              c.error(new Error("R2 transport reset"));
            },
          });
        },
      };
    };
    let fetchSignal: AbortSignal | undefined;
    w.setUpstream(async ({ body, init }) => {
      fetchSignal = init.signal ?? undefined;
      const reader = body!.getReader();
      for (;;) {
        const { done } = await reader.read();
        if (done) return new Response("finished");
      }
    });
    const err = await handleUpstreamRequest(w.args(w.identity(ref), { transferGate: gate, runKey: {} })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    // Observation (not a control): the handler's `transferFailure` reports the
    // controller's generic reason once the writer has aborted it, so the
    // writer's own "staged transfer failed: …" text may be replaced by
    // "staged transfer aborted". Both are token-free.
    expect((err as Error).message).toMatch(/staged transfer (failed|aborted)/);
    expect((err as Error).message).not.toContain(ref.token);
    expect(fetchSignal?.aborted).toBe(true);
    await assertReleased(gate);
  });

  it("REFUTED: the host deadline fires while waiting in the queue → the waiter is dropped and the queue slot freed", async () => {
    const gate = new TransferGate({ maxConcurrent: 1, maxWaiting: 1, perRunInFlight: 1, perRunWaiting: 1 });
    const holder = await gate.acquire({}, new AbortController().signal);
    const run = new AbortController();
    const waiting = gate.acquire({}, run.signal);
    run.abort(new ToolError("host deadline"));
    await expect(waiting).rejects.toThrow(/host deadline/);
    // The queue slot is free again: another waiter can queue.
    const next = gate.acquire({}, new AbortController().signal);
    holder();
    (await next)();
  });
});

describe("D3 — writer/fetch coupling (R-1)", () => {
  it("FIXED (#59): upstream answers 413 after 4 KB and stops reading → envelope returned, sink aborted (never a clean EOF), gate released, no hang, no unhandled rejection", async () => {
    const w = world();
    const ref = await w.stage(pattern(3 * BLOCK_BYTES));
    const gate = new TransferGate({ maxConcurrent: 1, maxWaiting: 0, perRunInFlight: 1, perRunWaiting: 1 });
    let keptReader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    w.setUpstream(async ({ body }) => {
      const reader = body!.getReader();
      let got = 0;
      while (got < 4096) {
        const { value, done } = await reader.read();
        if (done) break;
        got += value.byteLength;
      }
      keptReader = reader; // stop reading; never cancel
      return new Response("too big", { status: 413 });
    });
    const unhandled = trackUnhandled();
    const started = performance.now();
    const res = (await Promise.race([
      handleUpstreamRequest(w.args(w.identity(ref), { transferGate: gate, runKey: {} })),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("handler hung")), 2000)),
    ])) as { success: boolean; status: number };
    expect(performance.now() - started).toBeLessThan(2000);
    expect(res.success).toBe(false);
    expect(res.status).toBe(413);
    // What is left of the body is an error, never a clean end.
    const outcome = await keptReader!.read().then(
      (r) => (r.done ? "clean-eof" : "more-data"),
      () => "errored",
    );
    expect(outcome).toBe("errored");
    await assertReleased(gate);
    await new Promise((r) => setTimeout(r, 10));
    unhandled.stop();
    expect(unhandled.seen).toEqual([]);
  });

  it("FIXED (#59): host deadline mid-file → fetch aborted, body shorter than Content-Length, nothing completes afterwards", async () => {
    const w = world();
    const file = pattern(3 * BLOCK_BYTES);
    const ref = await w.stage(file);
    const gate = new TransferGate({ maxConcurrent: 1, maxWaiting: 0, perRunInFlight: 1, perRunWaiting: 1 });
    const run = new AbortController();
    let fetchSignal: AbortSignal | undefined;
    let upstreamOutcome = "pending";
    const upstreamDone = new Promise<void>((resolve) => {
      w.setUpstream(async ({ body, init }) => {
        fetchSignal = init.signal ?? undefined;
        const reader = body!.getReader();
        await reader.read();
        run.abort(new ToolError("staged transfer aborted: this execution passed its host-side deadline"));
        try {
          for (;;) {
            const { done } = await reader.read();
            if (done) {
              upstreamOutcome = "clean-eof";
              break;
            }
          }
        } catch {
          upstreamOutcome = "errored";
        }
        resolve();
        return new Response("finished-anyway", { status: 200 });
      });
    });
    const err = await handleUpstreamRequest(
      w.args(w.identity(ref), { transferGate: gate, runKey: {}, signal: run.signal }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/deadline/);
    expect(fetchSignal?.aborted).toBe(true);
    await upstreamDone;
    expect(upstreamOutcome).toBe("errored");
    const declared = Number((w.sent[0]!.init.headers as Record<string, string>)["Content-Length"]);
    expect(declared).toBe(file.byteLength);
    expect(w.sent[0]!.body.byteLength).toBeLessThan(declared);
    // Nothing completes later: the recorded body does not grow once the run was reported failed.
    const after = w.sent[0]!.body.byteLength;
    await new Promise((r) => setTimeout(r, 50));
    expect(w.sent[0]!.body.byteLength).toBe(after);
    await assertReleased(gate);
  });

  it("FIXED (#59): connection reset mid-body → exactly one ToolError, gate released, no unhandled rejection", async () => {
    const w = world();
    const ref = await w.stage(pattern(3 * BLOCK_BYTES));
    const gate = new TransferGate({ maxConcurrent: 1, maxWaiting: 0, perRunInFlight: 1, perRunWaiting: 1 });
    w.setUpstream(async ({ body }) => {
      await body!.getReader().read();
      throw new TypeError("fetch failed: ECONNRESET");
    });
    const unhandled = trackUnhandled();
    const err = await handleUpstreamRequest(w.args(w.identity(ref), { transferGate: gate, runKey: {} })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/upstream request failed: fetch failed: ECONNRESET/);
    await assertReleased(gate);
    await new Promise((r) => setTimeout(r, 10));
    unhandled.stop();
    expect(unhandled.seen).toEqual([]);
  });

  it("FIXED (#59): a stalled response body (review WP-B finding 2) → the per-transfer timeout ends the read and releases the gate", async () => {
    const w = world();
    const ref = await w.stage(pattern(10));
    const gate = new TransferGate({ maxConcurrent: 1, maxWaiting: 0, perRunInFlight: 1, perRunWaiting: 1 });
    w.setUpstream(async ({ body, init }) => {
      const reader = body!.getReader();
      for (;;) {
        const { done } = await reader.read();
        if (done) break;
      }
      // Headers arrive; the body never does — unless the fetch signal fires.
      const stalled = new ReadableStream<Uint8Array>({
        start(c) {
          init.signal?.addEventListener("abort", () => c.error(init.signal!.reason), { once: true });
        },
      });
      return new Response(stalled, { status: 200, headers: { "content-type": "application/json" } });
    });
    const started = performance.now();
    const err = await Promise.race([
      handleUpstreamRequest(
        w.args(w.identity(ref), { transferGate: gate, runKey: {}, stagingLimits: { transferTimeoutMs: 100 } }),
      ).catch((e: unknown) => e),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("handler hung on the stalled body")), 3000)),
    ]);
    expect(performance.now() - started).toBeLessThan(3000);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/timed out/);
    await assertReleased(gate);
  });
});
