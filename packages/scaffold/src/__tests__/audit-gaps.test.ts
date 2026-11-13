// packages/scaffold/src/__tests__/audit-gaps.test.ts
//
// B-2 (entry cap), E-4 (dispatch / outcome lines) and the wave-1 W4 notes
// (matched-request exits that left no audit line), plus the E-1 staging
// fields on the request handler's own lines (2026-11 review, wave 4).
//
// Attacker: LLM-authored sandbox code driving `codemode.request`, or an
// upstream / staged store that fails mid-request.
// Preconditions: a deployment whose surface review allows the operation; for
// the composed cases, a staged file the caller may attach.
// Payloads: a 300 000-char path or a 33-char method; `composed` with no
// staging bindings; `{ rawBody: true, body: { a: 1 } }`; a principal without
// a userId; a broker that throws; an invalid API base URL; an upstream fetch
// that rejects; a staged file whose block read fails mid-body; a response
// whose body read fails; `returnAs: "stage"` without a staging store.
// Control: every one of these ends with exactly the audit line(s) named here
// — a deny with a fixed reason before the match/mint, or an `allow` line with
// `outcome: "failed"` and a fixed reason once dispatch began; a host-assembled
// send also writes a `phase: "dispatch"` line before its first byte goes out.
// No line carries a message text, token or handle.
// Why the pre-fix code failed it: each of these paths threw (or rethrew) with
// no audit line at all, so a request that reached the upstream could vanish
// from the log, and an oversize path reached the matcher whole.

import { afterEach, describe, expect, it, vi } from "vitest";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReview } from "@local/shared";
import { failureReason, handleUpstreamRequest, isDecodableBase64, type HandleArgs, type UpstreamCtx } from "../request-handler";
import { ToolError } from "../elicit";
import { StagedFileReadError, type OpenStagedResult, type StagedRef } from "../staging/staged-file";
import { transferController } from "../compose/transfer";
import { FakeD1 } from "../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../staging/__tests__/__fixtures__/fake-r2";
import { fileRefOf } from "../staging/crypto";
import { mintFileHandle, mintToken } from "../staging/tokens";
import type { StagingConfig } from "../staging/types";

const op = (operationId: string) => ({ operationId, responses: { "200": { description: "OK" } } });
const SPEC: OpenApiSpec = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/widgets": { get: op("listWidgets") },
    "/send": { post: op("sendJson") },
    "/attach/x": { put: op("attach") },
    "/download": { get: op("download") },
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;
const SR: SurfaceReview = {
  listWidgets: { decision: "allow" },
  sendJson: { decision: "allow" },
  attach: { decision: "allow" },
  download: { decision: "allow" },
} as unknown as SurfaceReview;

const REF: StagedRef = { file_handle: mintFileHandle(), token: mintToken() };
const FILE_BYTES = new TextEncoder().encode("hello staged world");

type Upstream = (url: string, init: RequestInit) => Promise<Response>;

function harness(ctx: UpstreamCtx, upstream?: Upstream) {
  const raw: string[] = [];
  const lines = (): Array<Record<string, unknown>> => raw.map((s) => JSON.parse(s.slice(6)) as Record<string, unknown>);
  const order: string[] = [];
  vi.spyOn(console, "log").mockImplementation((s: unknown) => {
    if (typeof s === "string" && s.startsWith("AUDIT ")) {
      raw.push(s);
      const l = JSON.parse(s.slice(6)) as Record<string, unknown>;
      order.push(l.phase === "dispatch" ? "audit:dispatch" : "audit");
    }
  });
  const fetchSpy = vi.fn<typeof fetch>(async (url, init) => {
    order.push("fetch");
    if (upstream) return upstream(String(url), init ?? {});
    const body = init?.body;
    if (body instanceof ReadableStream) await new Response(body).arrayBuffer();
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchSpy);
  const mint = vi.fn(async () => "AT-x");
  const args: HandleArgs<Record<string, unknown>> = {
    ctx,
    spec: SPEC,
    surfaceReview: SR,
    apiBaseUrl: "https://api.example.com",
    deploymentName: "test",
    server: {} as never,
    props: { userId: "u1", refreshToken: "RT" },
    oauth: {
      refreshTokenAccessor: (p) => p.refreshToken as string,
      userIdAccessor: (p) => p.userId as string | undefined,
      broker: { getOrRefreshAccessToken: mint },
    },
    audit: {},
    env: {},
  };
  return { args, raw, lines, fetchSpy, mint, order };
}

/** An opener returning one in-memory staged file (fileRef "abcdef012345"). */
function openerFor(readBlocks?: (onBlock: (b: Uint8Array, i: number) => Promise<void>) => Promise<void>) {
  return async (): Promise<OpenStagedResult> => ({
    ok: true,
    file: {
      meta: { byteLength: FILE_BYTES.byteLength, contentType: "text/plain", filename: null, fileRef: "abcdef012345" },
      readBlocks: readBlocks ?? (async (onBlock) => onBlock(FILE_BYTES, 0)),
    },
  });
}

const composedCtx: UpstreamCtx = {
  method: "PUT",
  path: "/attach/x",
  composed: { segments: [{ staged: REF, encoding: "identity" }] },
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function expectNoSecrets(raw: string[]): void {
  for (const s of raw) {
    expect(s).not.toContain(REF.token);
    expect(s).not.toContain(REF.file_handle);
    expect(s).not.toContain("AT-x");
  }
}

describe("FIXED (B-2): oversize method or path is refused at entry", () => {
  it("a 300 000-char path → deny oversize-method-or-path, no match, no mint", async () => {
    const h = harness({ method: "GET", path: "/" + "A".repeat(300_000) });
    const err = await handleUpstreamRequest(h.args).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toBe("codemode.request method or path is too long");
    expect(h.lines()).toHaveLength(1);
    expect(h.lines()[0]).toMatchObject({ decision: "deny", category: "malformed", reason: "oversize-method-or-path" });
    expect(h.mint).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
  });

  it("a 33-char method → same refusal; 32 chars / 4096-char path pass the entry check", async () => {
    const h = harness({ method: "M".repeat(33), path: "/widgets" });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("codemode.request method or path is too long");
    expect(h.lines()[0]).toMatchObject({ reason: "oversize-method-or-path" });
    vi.restoreAllMocks();
    const h2 = harness({ method: "M".repeat(32), path: "/" + "A".repeat(4095) });
    await expect(handleUpstreamRequest(h2.args)).rejects.toThrow(/No operation found/);
    expect(h2.lines()[0]).toMatchObject({ reason: "no-op-match" });
  });

  it("the limit counts code points, not UTF-16 units", async () => {
    const h = harness({ method: "GET", path: "/" + "😀".repeat(4095) });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/No operation found/);
    vi.restoreAllMocks();
    const h2 = harness({ method: "GET", path: "/" + "😀".repeat(4096) });
    await expect(handleUpstreamRequest(h2.args)).rejects.toThrow("codemode.request method or path is too long");
  });
});

describe("FIXED (W4 notes): matched-request exits now leave a line", () => {
  it("composed without openStaged → deny staging-not-configured (same message)", async () => {
    const h = harness(composedCtx);
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
      "staged files are not available: server staging bindings are not configured",
    );
    expect(h.lines()).toEqual([
      expect.objectContaining({ decision: "deny", operationId: "attach", category: "malformed", reason: "staging-not-configured" }),
    ]);
    expect(h.mint).not.toHaveBeenCalled();
  });

  it("{ rawBody: true, body: { a: 1 } } → deny raw-body-not-string, no mint", async () => {
    const h = harness({ method: "POST", path: "/send", rawBody: true, body: { a: 1 } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
      "rawBody requires a string body; send binary via bodyBase64 or multipart",
    );
    expect(h.lines()).toEqual([
      expect.objectContaining({ decision: "deny", operationId: "sendJson", category: "malformed", reason: "raw-body-not-string" }),
    ]);
    expect(h.mint).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
  });

  it("REFUTED: rawBody with a string body still sends", async () => {
    const h = harness({ method: "POST", path: "/send", rawBody: true, body: "plain" });
    await expect(handleUpstreamRequest(h.args)).resolves.toMatchObject({ success: true });
  });

  it("userIdAccessor → undefined → deny no-principal, no mint", async () => {
    const h = harness({ method: "GET", path: "/widgets" });
    h.args.props = { refreshToken: "RT" };
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("Cannot mint access token: principal has no userId");
    expect(h.lines()).toEqual([expect.objectContaining({ decision: "deny", operationId: "listWidgets", reason: "no-principal" })]);
    expect(h.mint).not.toHaveBeenCalled();
  });

  it("a broker that throws → allow line with outcome failed / token-mint-failed, then the error", async () => {
    const h = harness({ method: "GET", path: "/widgets" });
    h.mint.mockRejectedValueOnce(new Error("refresh token revoked: secret-ish detail"));
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("refresh token revoked");
    expect(h.lines()).toEqual([
      expect.objectContaining({ decision: "allow", operationId: "listWidgets", outcome: "failed", reason: "token-mint-failed" }),
    ]);
    expect(h.raw[0]).not.toContain("secret-ish");
    expect(h.fetchSpy).not.toHaveBeenCalled();
  });

  it("an API base the URL builder cannot parse → deny upstream-url-build-failed (url_safety), error rethrown", async () => {
    const h = harness({ method: "GET", path: "/widgets" });
    h.args.apiBaseUrl = "not a url";
    const err = await handleUpstreamRequest(h.args).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TypeError);
    expect(h.lines()).toEqual([
      expect.objectContaining({ decision: "deny", category: "url_safety", reason: "upstream-url-build-failed" }),
    ]);
  });

  it("returnAs:\"stage\" without a staging store → the allow line (upstreamStatus 200) precedes the throw", async () => {
    const h = harness({ method: "GET", path: "/download", returnAs: "stage" });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/staging bindings/);
    expect(h.lines()).toEqual([
      expect.objectContaining({ decision: "allow", operationId: "download", upstreamStatus: 200 }),
    ]);
    expect(h.lines()[0]!.outcome).toBeUndefined();
  });
});

describe("FIXED (E-4): dispatch and outcome lines", () => {
  it("a plain JSON POST whose fetch rejects → one outcome-failed line, upstream-request-failed, no dispatch line", async () => {
    const h = harness({ method: "POST", path: "/send", body: { a: 1 } }, async () => {
      throw new TypeError("network down: 10.0.0.1");
    });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("network down");
    expect(h.lines()).toEqual([
      expect.objectContaining({ decision: "allow", operationId: "sendJson", outcome: "failed", reason: "upstream-request-failed" }),
    ]);
    expect(h.lines()[0]!.phase).toBeUndefined();
    expect(h.raw[0]).not.toContain("10.0.0.1");
  });

  it("a successful composed send → dispatch line before the fetch, then the ordinary outcome line", async () => {
    const h = harness(composedCtx);
    h.args.openStaged = openerFor();
    await expect(handleUpstreamRequest(h.args)).resolves.toMatchObject({ success: true });
    const [dispatch, outcome, ...rest] = h.lines();
    expect(rest).toEqual([]);
    expect(dispatch).toMatchObject({
      decision: "allow",
      phase: "dispatch",
      operationId: "attach",
      stagedCount: 1,
      stagedBytes: FILE_BYTES.byteLength,
      assembledBytes: FILE_BYTES.byteLength,
      stagedRefs: ["abcdef012345"],
    });
    expect(dispatch!.outcome).toBeUndefined();
    expect(dispatch!.upstreamStatus).toBeUndefined();
    expect(outcome).toMatchObject({
      decision: "allow",
      upstreamStatus: 200,
      bodyComplete: true,
      stagedRefs: ["abcdef012345"],
    });
    expect(outcome!.phase).toBeUndefined();
    expect(outcome!.outcome).toBeUndefined();
    expect(h.order.indexOf("audit:dispatch")).toBeLessThan(h.order.indexOf("fetch"));
    expectNoSecrets(h.raw);
  });

  it("a staged block read failing mid-body → dispatch line, then outcome-failed staged-read-failed", async () => {
    const h = harness(composedCtx);
    h.args.openStaged = openerFor(async (onBlock) => {
      await onBlock(FILE_BYTES.subarray(0, 4), 0);
      throw new StagedFileReadError(410, "stored file is corrupt");
    });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/^staged transfer failed: stored file is corrupt/);
    const l = h.lines();
    expect(l).toHaveLength(2);
    expect(l[0]).toMatchObject({ phase: "dispatch", stagedRefs: ["abcdef012345"] });
    expect(l[1]).toMatchObject({
      decision: "allow",
      operationId: "attach",
      outcome: "failed",
      reason: "staged-read-failed",
      stagedCount: 1,
      stagedRefs: ["abcdef012345"],
    });
    expect(h.raw[1]).not.toContain("corrupt");
    expectNoSecrets(h.raw);
  });

  it("the response body read failing → outcome-failed response-read-failed with the upstream status", async () => {
    const h = harness({ method: "GET", path: "/widgets" }, async () =>
      new Response(new ReadableStream({ start: (c) => c.error(new Error("reset by peer")) }), { status: 200 }),
    );
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("reset by peer");
    expect(h.lines()).toEqual([
      expect.objectContaining({
        decision: "allow",
        operationId: "listWidgets",
        outcome: "failed",
        reason: "response-read-failed",
        upstreamStatus: 200,
      }),
    ]);
  });

  it("a host deadline before dispatch on a composed send → dispatch line, then transfer-aborted", async () => {
    const h = harness(composedCtx);
    h.args.openStaged = openerFor();
    const run = new AbortController();
    run.abort();
    h.args.signal = run.signal;
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/^staged transfer aborted: this execution passed/);
    const l = h.lines();
    expect(l.map((x) => x.phase ?? x.outcome)).toEqual(["dispatch", "failed"]);
    expect(l[1]).toMatchObject({ reason: "transfer-aborted", operationId: "attach" });
  });
});

describe("FIXED (E-4): a refused transfer slot after the mint leaves a line", () => {
  it("transferGate.acquire rejecting on a composed send → outcome-failed transfer-gate-failed, no dispatch, no fetch", async () => {
    const h = harness(composedCtx);
    h.args.openStaged = openerFor();
    h.args.transferGate = { acquire: async () => { throw new ToolError("too many staged transfers in this execution"); } };
    h.args.runKey = {};
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("too many staged transfers");
    expect(h.lines()).toEqual([
      expect.objectContaining({
        decision: "allow",
        operationId: "attach",
        outcome: "failed",
        reason: "transfer-gate-failed",
        stagedRefs: ["abcdef012345"],
      }),
    ]);
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.raw[0]).not.toContain("too many");
  });

  it("gateLease.acquire rejecting on a bypassTruncate request → outcome-failed transfer-gate-failed", async () => {
    const h = harness({ method: "GET", path: "/download", bypassTruncate: true });
    h.args.gateLease = { acquire: async () => { throw new Error("lease refused"); } };
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("lease refused");
    expect(h.lines()).toEqual([
      expect.objectContaining({ decision: "allow", outcome: "failed", reason: "transfer-gate-failed" }),
    ]);
    expect(h.fetchSpy).not.toHaveBeenCalled();
  });
});

describe("FIXED (W4 notes, review r3): malformed bodies and host-side throws leave a line", () => {
  it("A: a top-level bodyBase64 that is not base64 → deny invalid-body-base64 (ToolError, not a DOMException), no mint", async () => {
    const h = harness({ method: "POST", path: "/send", bodyBase64: "!!!not base64!!!" });
    const err = await handleUpstreamRequest(h.args).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toBe("codemode.request `bodyBase64` must be valid base64");
    expect(h.lines()).toEqual([
      expect.objectContaining({ decision: "deny", category: "malformed", reason: "invalid-body-base64" }),
    ]);
    expect(h.mint).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
  });

  it("REFUTED: well-formed base64 (padding optional, whitespace allowed) still sends", async () => {
    for (const b of ["aGVsbG8=", "aGVsbG8", "aGVs\nbG8=", ""]) {
      const h = harness({ method: "POST", path: "/send", bodyBase64: b });
      await expect(handleUpstreamRequest(h.args)).resolves.toMatchObject({ success: true });
      vi.restoreAllMocks();
    }
  });

  it("isDecodableBase64 agrees with atob on edge cases", () => {
    const cases = ["", "a", "ab", "abc", "abcd", "ab==", "abc=", "a===", "ab=c", " a b\tc\nd ", "ab\u00a0cd", "-_", "abcde", "abcd=", "=", "YQ==\n"];
    for (const c of cases) {
      let ok = true;
      try {
        atob(c);
      } catch {
        ok = false;
      }
      expect([c, isDecodableBase64(c)]).toEqual([c, ok]);
    }
  });

  it("B: an inline multipart part with both value and bodyBase64 → deny multipart-part-malformed before the mint", async () => {
    const h = harness({ method: "POST", path: "/send", multipart: [{ name: "a", value: "x", bodyBase64: "eA==" }] });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(ToolError);
    expect(h.lines()).toEqual([
      expect.objectContaining({ decision: "deny", category: "malformed", reason: "multipart-part-malformed" }),
    ]);
    expect(h.mint).not.toHaveBeenCalled();
  });

  it("C: an inline multipart part whose bodyBase64 is not base64 → deny multipart-part-malformed before the mint", async () => {
    const h = harness({ method: "POST", path: "/send", multipart: [{ name: "a", bodyBase64: "%%%" }] });
    const err = await handleUpstreamRequest(h.args).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect(h.lines()).toEqual([expect.objectContaining({ reason: "multipart-part-malformed" })]);
    expect(h.mint).not.toHaveBeenCalled();
  });

  it("D: openStaged rejecting (D1 outage) → deny staged-ref-unresolved with staging { attach, 500 }, error rethrown", async () => {
    const h = harness(composedCtx);
    h.args.openStaged = async () => {
      throw new Error("D1_ERROR: storage unavailable");
    };
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("D1_ERROR");
    expect(h.lines()).toEqual([
      expect.objectContaining({ decision: "deny", reason: "staged-ref-unresolved", staging: { event: "attach", status: 500 } }),
    ]);
    expect(h.raw[0]).not.toContain("D1_ERROR");
    expect(h.mint).not.toHaveBeenCalled();
  });

  it("E: the provider requestHeaders hook throwing → outcome-failed request-headers-failed, no fetch", async () => {
    const h = harness({ method: "GET", path: "/widgets" });
    h.args.requestHeaders = () => {
      throw new Error("tenant lookup failed: t-123");
    };
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("tenant lookup failed");
    expect(h.lines()).toEqual([
      expect.objectContaining({ decision: "allow", outcome: "failed", reason: "request-headers-failed" }),
    ]);
    expect(h.raw[0]).not.toContain("t-123");
    expect(h.fetchSpy).not.toHaveBeenCalled();
  });
});

describe("failureReason maps the fixed transfer messages (pinned against compose/transfer.ts)", () => {
  it("each transfer controller reason", () => {
    const run = new AbortController();
    const tc = transferController(run.signal, 60_000);
    run.abort();
    expect(failureReason(tc.signal.reason)).toBe("transfer-aborted");
    tc.dispose();
    vi.useFakeTimers();
    try {
      const tc2 = transferController(undefined, 150);
      vi.advanceTimersByTime(151);
      expect((tc2.signal.reason as Error).message).toMatch(/^staged transfer timed out after 150 ms/);
      expect(failureReason(tc2.signal.reason)).toBe("transfer-timeout");
      tc2.dispose();
    } finally {
      vi.useRealTimers();
    }
  });

  it("writer and fetch failures", () => {
    expect(
      failureReason(
        new ToolError(
          "staged transfer failed: upstream closed the connection after 3 of 9 bytes were sent; the upstream request was aborted",
        ),
      ),
    ).toBe("upstream-closed");
    expect(failureReason(new ToolError("staged transfer failed: stored file is corrupt; the upstream request was aborted"))).toBe(
      "staged-read-failed",
    );
    expect(failureReason(new ToolError("upstream request failed: boom"))).toBe("upstream-request-failed");
    expect(failureReason(new ToolError("staged transfer aborted"))).toBe("transfer-aborted");
    expect(failureReason(new TypeError("fetch failed"))).toBe("upstream-request-failed");
    expect(failureReason(new Error("staged transfer timed out after 1 ms"))).toBe("upstream-request-failed");
  });
});

describe("FIXED (E-1): staging fields on the handler's own lines", () => {
  const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 1024 };
  const store = (maxBytes = 1024) => ({
    STAGING_D1: new FakeD1() as unknown as D1Database,
    STAGING_R2: new FakeR2() as unknown as R2Bucket,
    config: { ...CFG, maxBytes },
    uploadOrigin: "https://x.test",
    owner: "u1",
    now: () => 1_700_000_000,
  });

  it("returnAs:\"stage\" success → the allow line carries staging { event: store, fileRef, byteLength, status: 200 }", async () => {
    const h = harness({ method: "GET", path: "/download", returnAs: "stage" }, async () =>
      new Response("file-bytes", { status: 200, headers: { "content-type": "text/plain" } }),
    );
    h.args.stagingStore = store();
    const res = (await handleUpstreamRequest(h.args)) as { result: { file_handle: string; token: string } };
    const fileRef = await fileRefOf(res.result.file_handle);
    expect(h.lines()).toEqual([
      expect.objectContaining({
        decision: "allow",
        operationId: "download",
        upstreamStatus: 200,
        staging: { event: "store", fileRef, byteLength: 10, status: 200 },
      }),
    ]);
    expect(h.raw[0]).not.toContain(res.result.file_handle);
    expect(h.raw[0]).not.toContain(res.result.token);
  });

  it("returnAs:\"stage\" refused (over the cap) → staging { event: store, status: 413 }", async () => {
    const h = harness({ method: "GET", path: "/download", returnAs: "stage" }, async () =>
      new Response("x".repeat(64), { status: 200, headers: { "content-type": "text/plain" } }),
    );
    h.args.stagingStore = store(16);
    await expect(handleUpstreamRequest(h.args)).resolves.toMatchObject({ success: false, status: 413 });
    expect(h.lines()).toEqual([expect.objectContaining({ upstreamStatus: 200, staging: { event: "store", status: 413 } })]);
  });

  it("a store that throws → exactly one outcome-failed line, stage-store-failed, upstreamStatus 200, no error text", async () => {
    const h = harness({ method: "GET", path: "/download", returnAs: "stage" }, async () =>
      new Response("file-bytes", { status: 200, headers: { "content-type": "text/plain" } }),
    );
    h.args.stagingStore = {
      ...store(),
      now: () => {
        throw new Error("clock exploded: secret-ish");
      },
    };
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow("clock exploded");
    expect(h.lines()).toEqual([
      expect.objectContaining({
        decision: "allow",
        operationId: "download",
        outcome: "failed",
        reason: "stage-store-failed",
        upstreamStatus: 200,
      }),
    ]);
    expect(h.raw[0]).not.toContain("secret-ish");
  });

  it("an R2 put that rejects is a refused store (stageFromBlocks never throws for it) → staging { store, 500 }", async () => {
    const h = harness({ method: "GET", path: "/download", returnAs: "stage" }, async () =>
      new Response("file-bytes", { status: 200, headers: { "content-type": "text/plain" } }),
    );
    const s = store();
    const r2 = s.STAGING_R2 as unknown as FakeR2;
    r2.put = (async () => {
      throw new Error("R2 down");
    }) as unknown as FakeR2["put"];
    (r2 as unknown as { createMultipartUpload: unknown }).createMultipartUpload = async () => {
      throw new Error("R2 down");
    };
    h.args.stagingStore = s;
    await expect(handleUpstreamRequest(h.args)).resolves.toMatchObject({ success: false, status: 500 });
    expect(h.lines()).toEqual([expect.objectContaining({ upstreamStatus: 200, staging: { event: "store", status: 500 } })]);
    expect(h.raw[0]).not.toContain("R2 down");
  });

  it("the host deadline firing while the response is being stored → outcome-failed transfer-aborted with upstreamStatus and staging", async () => {
    const run = new AbortController();
    const h = harness({ method: "GET", path: "/download", returnAs: "stage" }, async () =>
      new Response(
        new ReadableStream<Uint8Array>({
          pull(c) {
            run.abort();
            c.error(new Error("stream cut"));
          },
        }),
        { status: 200, headers: { "content-type": "text/plain" } },
      ),
    );
    h.args.stagingStore = store();
    h.args.signal = run.signal;
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/^staged transfer aborted: this execution passed/);
    const l = h.lines();
    expect(l).toHaveLength(1);
    expect(l[0]).toMatchObject({
      decision: "allow",
      outcome: "failed",
      reason: "transfer-aborted",
      upstreamStatus: 200,
      staging: { event: "store", status: expect.any(Number) },
    });
  });

  it("a refused staged reference keeps staged-ref-unresolved and adds staging { event: attach, status }", async () => {
    const h = harness(composedCtx);
    h.args.openStaged = async () => ({ ok: false, status: 403, message: "file not found or not yours" });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(ToolError);
    expect(h.lines()).toEqual([
      expect.objectContaining({ decision: "deny", reason: "staged-ref-unresolved", staging: { event: "attach", status: 403 } }),
    ]);
    expectNoSecrets(h.raw);
  });
});
