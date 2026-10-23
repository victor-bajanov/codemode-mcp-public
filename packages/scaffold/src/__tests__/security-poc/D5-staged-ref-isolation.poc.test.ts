// D5 — Staged-reference isolation and the D10a gate (issue #59, §2 host rules, red-team R-3).
//
// Attacker: sandbox code holding some valid references (its own uploads)
//   and guessing or recombining others; sandbox code aiming a `composed`
//   body at an operation whose inspector was written for JSON or inline
//   parts; sandbox code smuggling `composed`/`multipart` through
//   `__stagingHost.stageFromUpstreamJson`'s request options.
// Precondition: rows in pending / claimed / expired / corrupt states; an
//   inspected operation without `acceptsStaged`; a bare-allow operation.
// Payloads: cross-row handle/token pairs in `composed` and
//   `multipart[].staged`; references to pending, expired and corrupt rows;
//   syntactically valid unknown references; `composed` and `multipart`
//   inside stageFromUpstreamJson's requestOpts; `composed` and
//   `multipart[].staged` on an inspected op without `acceptsStaged`.
// Control: each reference resolves independently against D1 by token hash
//   plus constant-time handle compare (one SELECT, no R2); failures are
//   ToolErrors naming the segment/part and a status word, never the token
//   or handle; stageFromUpstreamJson forwards only its declared fields;
//   `staged-not-supported` is decided before the inspector runs on any
//   inspected or elicit op lacking `acceptsStaged`, while a bare-allow op
//   is unaffected.
//
// Pre-v2 reasoning: the channel is new; without the D10a rule the Gmail
// JSON inspector would be handed an empty body or a lone U+FFFC and judge
// a send it never saw (R-3). Removing the `acceptsStaged` check (verified by
// mutation) lets I6's inspector run on a staged body.
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
import { createStageFromUpstreamJsonCapability } from "../../staging/stage-from-upstream-json";
import { insertPending, lookupByHash } from "../../staging/repo";
import { sha256Bearer } from "../../staging/crypto";
import { mintFileHandle, mintToken } from "../../staging/tokens";
import type { StagingConfig } from "../../staging/types";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { InspectRequest, SurfaceReview } from "@local/shared";

const NOW = 1_700_000_000;
const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };

const op = (operationId: string) => ({ operationId, responses: { "200": { description: "OK" } } });
const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/upload/send": { post: op("sendMedia") },
    "/send": { post: op("sendJson") },
    "/approve": { post: op("approvePlain") },
    "/attach/{name}": { put: op("attach") },
    "/files": { post: op("files") },
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;

function world() {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  let prepares = 0;
  const origPrepare = d1.prepare.bind(d1);
  d1.prepare = (sql: string) => {
    prepares += 1;
    return origPrepare(sql);
  };
  const D1 = d1 as unknown as D1Database;
  const deps = { STAGING_D1: D1, STAGING_R2: r2 as unknown as R2Bucket, config: CFG, uploadOrigin: "https://x.test", now: () => NOW };
  const opener = createStagedFileOpener(deps);
  const inspected: InspectRequest[] = [];
  const inspect = (req: InspectRequest) => {
    inspected.push(req);
    return { decision: "allow" as const };
  };
  const SR: SurfaceReview = {
    sendMedia: { decision: "allow", acceptsStaged: true, inspect },
    sendJson: { decision: "allow", inspect }, // Gmail-shaped: JSON inspector, no opt-in
    approvePlain: { decision: "elicit", category: "external_data_flow" },
    attach: { decision: "allow" }, // Xero-shaped: bare allow
    files: { decision: "allow" },
  };
  const fetchSpy = vi.fn(async (_u: RequestInfo | URL, init?: RequestInit) => {
    const body = init?.body as ReadableStream<Uint8Array> | undefined;
    if (body instanceof ReadableStream) {
      const reader = body.getReader();
      for (;;) {
        const { done } = await reader.read();
        if (done) break;
      }
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchSpy);
  const elicitInput = vi.fn(async () => ({ action: "accept", content: { confirm: true } }));
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
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    server: { server: { getClientCapabilities: () => ({ elicitation: {} }), elicitInput } } as any,
    env: {},
    audit: {},
    oauth: { refreshTokenAccessor: () => "RT", userIdAccessor: () => "u1", broker: { getOrRefreshAccessToken: async () => "AT" } },
    openStaged: opener,
    stagingStore: deps,
    ...extra,
  });
  const stage = async (bytes: Uint8Array): Promise<StagedRef> => {
    const r = await stageFromBlocks(deps, blockSourceFromBytes(bytes), "application/pdf", "q.pdf");
    if (!r.ok) throw new Error("stage failed");
    return { file_handle: r.file_handle, token: r.token };
  };
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
  const rowOf = async (ref: StagedRef) => d1.rows.get(Buffer.from(await sha256Bearer(ref.token)).toString("hex"))!;
  return { d1, r2, deps, args, stage, pending, rowOf, inspected, fetchSpy, elicitInput, audits, prepares: () => prepares };
}

const composedOf = (ref: StagedRef, path = "/upload/send"): UpstreamCtx => ({
  method: "POST",
  path,
  contentType: "message/rfc822",
  composed: { segments: [{ text: "To: a@b\r\n\r\n" }, { staged: ref, encoding: "base64-lines" }] },
});
const multipartOf = (ref: StagedRef, path = "/files"): UpstreamCtx => ({
  method: "POST",
  path,
  multipart: [{ name: "Name", value: "q.pdf" }, { name: "file", staged: ref }],
});

function assertNoSecrets(text: string, ...refs: StagedRef[]): void {
  for (const ref of refs) {
    expect(text).not.toContain(ref.token);
    expect(text).not.toContain(ref.token.slice(4, 24));
    expect(text).not.toContain(ref.file_handle);
    expect(text).not.toContain(ref.file_handle.slice(3, 13));
  }
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("D5 — I1 cross-row pairs", () => {
  it("REFUTED: A's handle with B's token (and vice versa) in composed and multipart.staged → ToolError, no R2, no inspector, no fetch", async () => {
    const w = world();
    const a = await w.stage(new Uint8Array(10));
    const b = await w.stage(new Uint8Array(20));
    const mixes: StagedRef[] = [
      { file_handle: a.file_handle, token: b.token },
      { file_handle: b.file_handle, token: a.token },
    ];
    for (const mix of mixes) {
      for (const [ctx, where] of [
        [composedOf(mix), /composed segment 1: file not found or not yours \(HTTP 403\)/],
        [multipartOf(mix), /multipart part 1: file not found or not yours \(HTTP 403\)/],
      ] as const) {
        const err = await handleUpstreamRequest(w.args(ctx)).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(ToolError);
        expect((err as Error).message).toMatch(where);
        assertNoSecrets((err as Error).message, a, b);
        expect(w.audits().at(-1)).toMatchObject({ decision: "deny", reason: "staged-ref-unresolved" });
        assertNoSecrets(JSON.stringify(w.audits()), a, b);
      }
    }
    expect(w.r2.getCalls).toBe(0);
    expect(w.inspected).toHaveLength(0);
    expect(w.fetchSpy).not.toHaveBeenCalled();
  });

  it("REFUTED: a valid reference among the segments does not rescue an invalid one — all resolve independently and the first failure names its own index", async () => {
    const w = world();
    const good = await w.stage(new Uint8Array(10));
    const bad = { file_handle: mintFileHandle(), token: good.token };
    const err = await handleUpstreamRequest(
      w.args({
        method: "POST",
        path: "/upload/send",
        composed: { segments: [{ text: "h\r\n\r\n" }, { staged: good, encoding: "base64" }, { text: "\r\n" }, { staged: bad, encoding: "base64" }] },
      }),
    ).catch((e: unknown) => e);
    expect((err as Error).message).toMatch(/^composed segment 3: /);
    expect(w.r2.getCalls).toBe(0);
  });
});

describe("D5 — I2 pending / expired / corrupt produce distinct, generic status words", () => {
  it("REFUTED: the four non-OK states are told apart by status word only; none leaks the reference", async () => {
    const w = world();
    const pending = await w.pending();
    const expired = await w.stage(new Uint8Array(1));
    (await w.rowOf(expired)).expires_at = NOW - 1;
    const corrupt = await w.stage(new Uint8Array(1));
    (await w.rowOf(corrupt)).state = "corrupt";
    const unknown = { file_handle: mintFileHandle(), token: mintToken() };
    const messages: string[] = [];
    for (const [ref, expected] of [
      [pending, /upload incomplete \(HTTP 409\)/],
      [expired, /expired \(HTTP 410\)/],
      [corrupt, /stored file is corrupt \(HTTP 410\)/],
      [unknown, /file not found or not yours \(HTTP 403\)/],
    ] as const) {
      const err = await handleUpstreamRequest(w.args(composedOf(ref))).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ToolError);
      expect((err as Error).message).toMatch(expected);
      assertNoSecrets((err as Error).message, pending, expired, corrupt, unknown);
      messages.push((err as Error).message);
    }
    expect(new Set(messages).size).toBe(4);
    expect(w.r2.getCalls).toBe(0);
    expect(w.fetchSpy).not.toHaveBeenCalled();
  });
});

describe("D5 — I2' legacy rows (enc_version 1 or pre-0002)", () => {
  it("FIXED (v1 reader removed): a legacy row in composed or multipart.staged → ToolError naming the slot and 'legacy format (HTTP 410)'; deny audit; no R2, no fetch", async () => {
    const w = world();
    for (const v of [1, null]) {
      const ref = await w.stage(new Uint8Array(10));
      (await w.rowOf(ref)).enc_version = v as never;
      for (const [ctx, expected] of [
        [composedOf(ref), "composed segment 1: stored in a legacy format; re-stage the file (HTTP 410)"],
        [multipartOf(ref), "multipart part 1: stored in a legacy format; re-stage the file (HTTP 410)"],
      ] as const) {
        const err = await handleUpstreamRequest(w.args(ctx)).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(ToolError);
        expect((err as Error).message).toBe(expected);
        expect(w.audits().at(-1)).toMatchObject({ decision: "deny", reason: "staged-ref-unresolved" });
        assertNoSecrets((err as Error).message, ref);
      }
    }
    expect(w.r2.getCalls).toBe(0);
    expect(w.fetchSpy).not.toHaveBeenCalled();
  });
});

describe("D5 — I3 stageFromUpstreamJson drops composed and multipart", () => {
  it("REFUTED: `composed` and `multipart` in requestOpts never reach the upstream handler", async () => {
    const seen: Record<string, unknown>[] = [];
    const cap = createStageFromUpstreamJsonCapability({
      putFile: async () => ({ ok: true, file_handle: "fh_x", token: "stg_x", fetch_url: "u", expires_at: 0, byte_length: 1 }),
      upstreamRequest: async (ctx) => {
        seen.push(ctx as unknown as Record<string, unknown>);
        return { success: true, status: 200, result: { data: "aGk" } };
      },
    });
    const ref = { file_handle: mintFileHandle(), token: mintToken() };
    const opts = {
      method: "POST",
      path: "/upload/send",
      composed: { segments: [{ staged: ref, encoding: "identity" }] },
      multipart: [{ name: "f", staged: ref }],
      returnAs: "stage",
      headers: { "X-Evil": "1" },
      openStaged: () => {},
      transferGate: {},
      signal: new AbortController().signal,
    } as never;
    const r = await cap(opts, "data", "base64url");
    expect(r.ok).toBe(true);
    expect(seen).toHaveLength(1);
    expect(Object.keys(seen[0]!).sort()).toEqual(["bypassTruncate", "method", "path"]);
  });
});

describe("D5 — I5 unknown references cost exactly one D1 read each and no R2", () => {
  it("REFUTED: three syntactically valid unknown refs → one SELECT (stops at the first), zero R2", async () => {
    const w = world();
    const refs = [0, 1, 2].map(() => ({ file_handle: mintFileHandle(), token: mintToken() }));
    const before = w.prepares();
    // Only the first unresolvable reference is resolved before the handler stops.
    const err = await handleUpstreamRequest(
      w.args({
        method: "POST",
        path: "/upload/send",
        composed: { segments: [{ text: "h\r\n\r\n" }, ...refs.map((r) => ({ staged: r, encoding: "base64" as const }))] },
      }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect(w.prepares() - before).toBe(1);
    expect(w.r2.getCalls).toBe(0);
    // An implausible shape costs nothing at all.
    const before2 = w.prepares();
    await expect(
      handleUpstreamRequest(
        w.args({ method: "POST", path: "/upload/send", composed: { segments: [{ staged: { file_handle: "fh_short", token: "stg_short" }, encoding: "base64" }] } }),
      ),
    ).rejects.toBeInstanceOf(ToolError);
    expect(w.prepares() - before2).toBe(0);
  });
});

describe("D5 — I6 (R-3) inspectors must opt in to staged bodies", () => {
  it("FIXED (#59): composed on an inspected op without acceptsStaged → staged-not-supported before the inspector; no D1 read, no R2, no fetch", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(10));
    const before = w.prepares();
    const err = await handleUpstreamRequest(w.args(composedOf(ref, "/send"))).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/does not accept staged files/);
    expect(w.inspected).toHaveLength(0);
    expect(w.prepares() - before).toBe(0);
    expect(w.r2.getCalls).toBe(0);
    expect(w.fetchSpy).not.toHaveBeenCalled();
    expect(w.audits().at(-1)).toMatchObject({ decision: "deny", category: "malformed", reason: "staged-not-supported", operationId: "sendJson" });
  });

  it("FIXED (#59): multipart[].staged on an elicit op without acceptsStaged → staged-not-supported before any dialog", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(10));
    const err = await handleUpstreamRequest(w.args(multipartOf(ref, "/approve"))).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toMatch(/does not accept staged files/);
    expect(w.elicitInput).not.toHaveBeenCalled();
    expect(w.r2.getCalls).toBe(0);
    expect(w.audits().at(-1)).toMatchObject({ reason: "staged-not-supported", operationId: "approvePlain" });
  });

  it("FIXED (#59): a sole identity segment on the JSON-inspected op is refused by rule, never judged as an empty body", async () => {
    const w = world();
    const ref = await w.stage(new TextEncoder().encode('{"raw":"..."}'));
    await expect(
      handleUpstreamRequest(w.args({ method: "POST", path: "/send", contentType: "application/json", composed: { segments: [{ staged: ref, encoding: "identity" }] } })),
    ).rejects.toThrow(/does not accept staged files/);
    expect(w.inspected).toHaveLength(0);
  });

  it("REFUTED: a bare-allow op (Xero attachment shape) accepts composed identity and multipart.staged unchanged", async () => {
    const w = world();
    const file = new TextEncoder().encode("%PDF-1.4 ...");
    const ref = await w.stage(file);
    const r1 = (await handleUpstreamRequest(
      w.args({ method: "PUT", path: "/attach/q.pdf", contentType: "application/pdf", composed: { segments: [{ staged: ref, encoding: "identity" }] } }),
    )) as { success: boolean };
    expect(r1.success).toBe(true);
    const r2 = (await handleUpstreamRequest(w.args(multipartOf(ref)))) as { success: boolean };
    expect(r2.success).toBe(true);
    expect(w.fetchSpy).toHaveBeenCalledTimes(2);
    expect(w.r2.getCalls).toBe(2);
  });

  it("REFUTED: an inspected op WITH acceptsStaged gets the view (U+FFFC + metadata), never bytes", async () => {
    const w = world();
    const ref = await w.stage(new Uint8Array(10));
    await handleUpstreamRequest(w.args(composedOf(ref)));
    expect(w.inspected).toHaveLength(1);
    const req = w.inspected[0]!;
    expect(req.rawBody).toBe("To: a@b\r\n\r\n￼");
    expect(req.staged).toEqual([{ index: 1, byteLength: 10, contentType: "application/pdf", filename: "q.pdf", encoding: "base64-lines" }]);
    assertNoSecrets(JSON.stringify(req), ref);
  });
});
