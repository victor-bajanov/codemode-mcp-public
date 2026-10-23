// D8 — Token and handle hygiene across every staged-transfer failure path (issue #59, "Rules for every package").
//
// Attacker: anyone who can read the Worker's logs (Workers Logs, audit
//   lines, DEBUG_ELICIT output), the approval dialog text, or the error
//   string the sandbox hands back to the model — none of whom should learn
//   a bearer token or a file handle from a failed or approved transfer.
// Precondition: `DEBUG_ELICIT=true` (every debug site active), audit on,
//   `ALLOW_PII_IN_LOGS` both off and on.
// Payloads: a composed send on each failure path — 403 (cross-row), 409
//   (pending), 410 (expired, corrupt object), 413 (getFile cap), gate
//   refusal, composed-too-large, fetch throwing, host deadline — plus an
//   approved (elicit) send with attachments and a stageFromUpstreamJson
//   that fails upstream.
// Control: the token, the handle and any 20-character slice of either never
//   appear in ToolError messages, audit lines, console output, debug logs
//   or the elicitation request; the elicit preview carries the attachments
//   line (name + size) and never the reference.
//
// Pre-v2 reasoning: new failure paths (opener statuses, gate, cap, coupling)
// each format a caller-facing message from a request that carries the
// reference; a message built from `ref` would leak it (verified by
// mutation: appending the token to the opener's 403 message fails L1).
//
// FakeD1/FakeR2 only; `fetch` is stubbed. No network.
import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "../../request-handler";
import { ToolError } from "../../elicit";
import { FakeD1 } from "../../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../../staging/__tests__/__fixtures__/fake-r2";
import { TransferGate, PER_RUN_MESSAGE } from "../../compose/gate";
import { blockSourceFromBytes, createStagedFileOpener, stageFromBlocks, type StagedRef } from "../../staging/staged-file";
import { createGetFileCapability } from "../../staging/getfile-capability";
import { createPutFileCapability } from "../../staging/putfile-capability";
import { createStageFromUpstreamJsonCapability } from "../../staging/stage-from-upstream-json";
import { insertPending } from "../../staging/repo";
import { sha256Bearer } from "../../staging/crypto";
import { mintFileHandle, mintToken } from "../../staging/tokens";
import { BLOCK_BYTES, type StagingConfig } from "../../staging/types";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReview } from "@local/shared";

const NOW = 1_700_000_000;
const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024, getFileMaxBytes: 1024 };

const op = (operationId: string) => ({ operationId, responses: { "200": { description: "OK" } } });
const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/upload/send": { post: op("sendMedia") },
    "/approve": { post: op("approveMedia") },
    "/attach/{name}": { put: op("attach") },
    "/att": { get: op("att") },
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;
const SR: SurfaceReview = {
  sendMedia: { decision: "allow", acceptsStaged: true, inspect: () => ({ decision: "allow" }) },
  approveMedia: { decision: "elicit", category: "external_data_flow", acceptsStaged: true },
  attach: { decision: "allow" },
  att: { decision: "allow" },
};

function world(env: Record<string, string> = { DEBUG_ELICIT: "true", ALLOW_PII_IN_LOGS: "false" }) {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const D1 = d1 as unknown as D1Database;
  const deps = { STAGING_D1: D1, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, uploadOrigin: "https://x.test", now: () => NOW };
  const opener = createStagedFileOpener(deps);
  const sinks = ["log", "error", "warn", "info", "debug"] as const;
  const spies = sinks.map((s) => vi.spyOn(console, s).mockImplementation(() => {}));
  const consoleText = () => spies.flatMap((s) => s.mock.calls.map((c) => c.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join(" "))).join("\n");
  let upstream: (init: RequestInit) => Promise<Response> = async (init) => {
    const body = init.body as ReadableStream<Uint8Array> | undefined;
    if (body instanceof ReadableStream) {
      const reader = body.getReader();
      for (;;) {
        const { done } = await reader.read();
        if (done) break;
      }
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };
  vi.stubGlobal("fetch", vi.fn(async (_u: RequestInfo | URL, init?: RequestInit) => upstream(init ?? {})));
  const elicitCalls: unknown[] = [];
  const elicitInput = vi.fn(async (params: { requestedSchema: { properties: Record<string, { type: string }> } }) => {
    elicitCalls.push(params);
    // Accept with one value per requested field, of the requested type.
    const content = Object.fromEntries(
      Object.entries(params.requestedSchema.properties).map(([k, v]) => [k, v.type === "number" ? 1 : v.type === "boolean" ? true : "ok"]),
    );
    return { action: "accept", content };
  });
  const args = (ctx: UpstreamCtx, extra: Partial<HandleArgs<Record<string, unknown>>> = {}): HandleArgs<Record<string, unknown>> => ({
    ctx,
    spec: SPEC,
    surfaceReview: SR,
    apiBaseUrl: "https://api.example.com",
    deploymentName: "poc",
    props: { refreshToken: "RT", userId: "u1" },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    server: { server: { getClientCapabilities: () => ({ elicitation: {} }), elicitInput } } as any,
    env,
    audit: {},
    oauth: { refreshTokenAccessor: () => "RT", userIdAccessor: () => "u1", broker: { getOrRefreshAccessToken: async () => "AT" } },
    openStaged: opener,
    stagingStore: deps,
    ...extra,
  });
  const stage = async (bytes: Uint8Array, filename: string | null = "q.pdf"): Promise<StagedRef> => {
    const r = await stageFromBlocks(deps, blockSourceFromBytes(bytes), "application/pdf", filename);
    if (!r.ok) throw new Error("stage failed");
    return { file_handle: r.file_handle, token: r.token };
  };
  const rowOf = async (ref: StagedRef) => d1.rows.get(Buffer.from(await sha256Bearer(ref.token)).toString("hex"))!;
  const pending = async (): Promise<StagedRef> => {
    const ref = { file_handle: mintFileHandle(), token: mintToken() };
    await insertPending(D1, {
      token_hash: await sha256Bearer(ref.token),
      file_handle: ref.file_handle,
      content_type_hint: null,
      expected_byte_len: null,
      filename: null,
      created_at: NOW,
      expires_at: NOW + 300,
    });
    return ref;
  };
  return {
    d1,
    r2,
    deps,
    args,
    stage,
    rowOf,
    pending,
    consoleText,
    elicitCalls,
    setUpstream: (u: typeof upstream) => {
      upstream = u;
    },
  };
}

/** Every secret-bearing shape: the full values and 20-char windows of both. */
function assertClean(text: string, ...refs: StagedRef[]): void {
  for (const ref of refs) {
    expect(text).not.toContain(ref.token);
    expect(text).not.toContain(ref.file_handle);
    for (let i = 4; i + 20 <= ref.token.length; i += 7) expect(text).not.toContain(ref.token.slice(i, i + 20));
    for (let i = 3; i + 12 <= ref.file_handle.length; i += 5) expect(text).not.toContain(ref.file_handle.slice(i, i + 12));
  }
}

const composedOf = (ref: StagedRef, path = "/upload/send"): UpstreamCtx => ({
  method: "POST",
  path,
  contentType: "message/rfc822",
  composed: { segments: [{ text: "To: a@b\r\n\r\n" }, { staged: ref, encoding: "base64-lines" }] },
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("D8 — L1 failure paths never surface the reference", () => {
  type Path = { name: string; run: (w: ReturnType<typeof world>) => Promise<{ refs: StagedRef[]; message: string; extra?: string }> };
  const paths: Path[] = [
    {
      name: "403 cross-row pair",
      run: async (w) => {
        const a = await w.stage(new Uint8Array(5));
        const b = await w.stage(new Uint8Array(6));
        const mix = { file_handle: a.file_handle, token: b.token };
        const err = await handleUpstreamRequest(w.args(composedOf(mix))).catch((e: unknown) => e);
        return { refs: [a, b, mix], message: (err as Error).message };
      },
    },
    {
      name: "409 pending upload",
      run: async (w) => {
        const p = await w.pending();
        const err = await handleUpstreamRequest(w.args(composedOf(p))).catch((e: unknown) => e);
        return { refs: [p], message: (err as Error).message };
      },
    },
    {
      name: "410 expired",
      run: async (w) => {
        const ref = await w.stage(new Uint8Array(5));
        (await w.rowOf(ref)).expires_at = NOW - 1;
        const err = await handleUpstreamRequest(w.args(composedOf(ref))).catch((e: unknown) => e);
        return { refs: [ref], message: (err as Error).message };
      },
    },
    {
      name: "410 corrupt object (detected mid-transfer)",
      run: async (w) => {
        const ref = await w.stage(new Uint8Array(BLOCK_BYTES + 5));
        const key = (await w.rowOf(ref)).r2_key!;
        const obj = w.r2.store.get(key)!;
        obj[BLOCK_BYTES + 16 + 2] = obj[BLOCK_BYTES + 16 + 2]! ^ 1;
        const err = await handleUpstreamRequest(w.args(composedOf(ref))).catch((e: unknown) => e);
        return { refs: [ref], message: (err as Error).message };
      },
    },
    {
      name: "413 getFile cap",
      run: async (w) => {
        const ref = await w.stage(new Uint8Array(2048));
        const r = await createGetFileCapability(w.deps)(ref.file_handle, ref.token);
        return { refs: [ref], message: JSON.stringify(r) };
      },
    },
    {
      name: "gate refusal",
      run: async (w) => {
        const ref = await w.stage(new Uint8Array(5));
        // The real gate, shaped as the factory wires it: run K already holds
        // its one in-flight slot and its one waiting slot, so the handler's
        // acquire for K is refused with the gate's own per-run message. (No
        // natural production mutation puts a token into gate.ts; this path
        // checks the message the model actually sees.)
        const gate = new TransferGate({ maxConcurrent: 2, maxWaiting: 4, perRunInFlight: 1, perRunWaiting: 1 });
        const runKey = {};
        const sig = new AbortController().signal;
        const held = await gate.acquire(runKey, sig);
        const waiting = gate.acquire(runKey, sig);
        try {
          const err = await handleUpstreamRequest(w.args(composedOf(ref), { transferGate: gate, runKey })).catch((e: unknown) => e);
          expect(err).toBeInstanceOf(ToolError);
          expect((err as Error).message).toBe(PER_RUN_MESSAGE);
          return { refs: [ref], message: (err as Error).message };
        } finally {
          held();
          (await waiting)();
        }
      },
    },
    {
      name: "composed-too-large",
      run: async (w) => {
        const ref = await w.stage(new Uint8Array(5000));
        const err = await handleUpstreamRequest(w.args(composedOf(ref), { stagingLimits: { composeMaxBytes: 100 } })).catch((e: unknown) => e);
        return { refs: [ref], message: (err as Error).message };
      },
    },
    {
      name: "fetch throws",
      run: async (w) => {
        const ref = await w.stage(new Uint8Array(5));
        w.setUpstream(async () => {
          throw new TypeError("fetch failed");
        });
        const err = await handleUpstreamRequest(w.args(composedOf(ref))).catch((e: unknown) => e);
        return { refs: [ref], message: (err as Error).message };
      },
    },
    {
      name: "host deadline",
      run: async (w) => {
        const ref = await w.stage(new Uint8Array(5));
        const run = new AbortController();
        run.abort(new ToolError("staged transfer aborted: this execution passed its host-side deadline"));
        const err = await handleUpstreamRequest(w.args(composedOf(ref), { signal: run.signal })).catch((e: unknown) => e);
        return { refs: [ref], message: (err as Error).message };
      },
    },
    {
      name: "upstream 4xx envelope on a composed send",
      run: async (w) => {
        const ref = await w.stage(new Uint8Array(5));
        w.setUpstream(async () => new Response('{"error":"bad"}', { status: 400 }));
        const r = await handleUpstreamRequest(w.args(composedOf(ref)));
        return { refs: [ref], message: JSON.stringify(r) };
      },
    },
    {
      name: "stageFromUpstreamJson upstream failure (handler message interpolated)",
      run: async (w) => {
        const ref = await w.stage(new Uint8Array(5));
        const cap = createStageFromUpstreamJsonCapability({
          putFile: createPutFileCapability(w.deps),
          upstreamRequest: (ctx) => handleUpstreamRequest(w.args(ctx as unknown as UpstreamCtx)) as never,
        });
        // The request options smuggle the reference in undeclared fields; the
        // handler's error (no-op match) must not echo them.
        const r = await cap({ method: "GET", path: "/missing", composed: { segments: [{ staged: ref, encoding: "identity" }] } } as never, "data");
        return { refs: [ref], message: JSON.stringify(r) };
      },
    },
  ];
  for (const envName of ["ALLOW_PII_IN_LOGS=false", "ALLOW_PII_IN_LOGS=true"]) {
    for (const p of paths) {
      it(`REFUTED: ${p.name} (${envName}) — ToolError/envelope, audit, console and debug logs are reference-free`, async () => {
        const w = world({ DEBUG_ELICIT: "true", ALLOW_PII_IN_LOGS: envName.endsWith("true") ? "true" : "false" });
        const { refs, message } = await p.run(w);
        expect(message.length).toBeGreaterThan(0);
        assertClean(message, ...refs);
        const logs = w.consoleText();
        assertClean(logs, ...refs);
        assertClean(JSON.stringify(w.elicitCalls), ...refs);
      });
    }
  }
});

describe("D8 — L2 the approval dialog", () => {
  for (const pii of ["false", "true"]) {
    it(`REFUTED: an elicit op with staged attachments (ALLOW_PII_IN_LOGS=${pii}) shows name + size, never the reference; the pre-send debug preview is clean too`, async () => {
      const w = world({ DEBUG_ELICIT: "true", ALLOW_PII_IN_LOGS: pii });
      const ref = await w.stage(new Uint8Array(1234), "report‮fdp.exe");
      const r = (await handleUpstreamRequest(w.args(composedOf(ref, "/approve")))) as { success: boolean };
      expect(r.success).toBe(true);
      expect(w.elicitCalls).toHaveLength(1);
      const params = w.elicitCalls[0] as { message: string; requestedSchema: unknown };
      expect(params.message).toContain("Attachments: reportfdp.exe (1234 bytes)");
      expect(params.message).not.toContain("‮");
      assertClean(JSON.stringify(params), ref);
      assertClean(w.consoleText(), ref);
    });
  }

  it("REFUTED: the inspector-summary route to the dialog (summary fields) is primitives the inspector chose; a staged reference never rides along", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(10));
    const sr: SurfaceReview = {
      ...SR,
      sendMedia: {
        decision: "allow",
        acceptsStaged: true,
        inspect: (req) => ({
          decision: "elicit",
          category: "external_data_flow",
          reason: "mass-send",
          summary: { count: req.staged?.length ?? 0, attachments: req.staged?.map((s) => `${s.filename} (${s.byteLength} bytes)`).join(", ") ?? "" },
        }),
      },
    };
    const r = (await handleUpstreamRequest(w.args(composedOf(ref), { surfaceReview: sr }))) as { success: boolean };
    expect(r.success).toBe(true);
    const params = w.elicitCalls[0] as { message: string; requestedSchema: { properties: Record<string, unknown> } };
    expect(Object.keys(params.requestedSchema.properties).sort()).toEqual(["attachments", "count"]);
    assertClean(JSON.stringify(params), ref);
    assertClean(w.consoleText(), ref);
  });
});
