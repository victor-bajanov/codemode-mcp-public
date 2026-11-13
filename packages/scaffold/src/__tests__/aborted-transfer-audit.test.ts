// packages/scaffold/src/__tests__/aborted-transfer-audit.test.ts
//
// E-4 (2026-11 review, wave 4) end to end: a host-assembled send that is
// aborted after the upstream has received the complete request body is on
// record — before its first byte goes out, and again when it fails.
//
// Attacker: (3) a prompt-injected LLM that wants an allowed-but-notable
//   action (an email with an attachment, a file upload) missing from the audit
//   log; it controls when in the run the send starts, and the run's deadline
//   is fixed (EXECUTE_HOST_TIMEOUT_MS).
// Precondition: staging bindings; an inspected operation that accepts staged
//   files (as gmail.users.messages.send.media does); a staged file the
//   caller owns.
// Payloads: `composed` = RFC 822 headers + the staged attachment, sent to an
//   upstream that reads the whole body and then never answers; the run's
//   abort signal fired after delivery (host deadline); the per-transfer
//   timeout (`transferTimeoutMs: 150`); an upstream that rejects the request
//   outright; one that resets the connection mid-body; and, as control, an
//   upstream that answers.
// Control: the handler writes an `allow` line with `phase: "dispatch"`
//   (stagedCount, stagedBytes, assembledBytes, stagedRefs) before
//   `sendAssembled` starts, and an `allow` line with `outcome: "failed"` and a
//   fixed `reason` (`transfer-aborted`, `transfer-timeout`,
//   `upstream-request-failed`, `upstream-closed`) when the dispatch throws; a successful send gets the dispatch line and
//   its ordinary final line. No line carries a handle, token, bearer or error
//   text; the staged file's `fileRef` joins its store line to the send.
// Why the pre-fix code failed it: the only allow line was written in
//   finishUpstream, after the upstream ANSWERED; an abort between "last body
//   byte sent" and "response headers received" threw past it, so the sandbox
//   was told the transfer failed, the log showed nothing, and the upstream
//   held a complete, authenticated request (0 AUDIT lines, both cases).
//
// Real code under test: handleUpstreamRequest with a composed body, the real
// staged-file opener and transfer controller, createPutFileCapability. D1/R2
// and the upstream `fetch` are faked. Hosts and ids are invented.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "../request-handler";
import { ToolError } from "../elicit";
import { createAuditSink } from "../audit";
import { FakeD1 } from "../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../staging/__tests__/__fixtures__/fake-r2";
import { createStagedFileOpener } from "../staging/staged-file";
import { createPutFileCapability, type PutFileCapabilityDeps } from "../staging/putfile-capability";
import type { StagingConfig } from "../staging/types";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReview } from "@local/shared";

const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };
const DEPLOYMENT = "test-deployment";
const OWNER = "u1";

const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example" }],
  paths: {
    "/upload/send": {
      post: { operationId: "sendMedia", responses: { "200": { description: "OK" } } },
    },
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;

const RFC822_HEAD = "To: someone@example\r\nSubject: hi\r\n\r\n";
const ATTACHMENT = "attachment bytes";

type Line = Record<string, unknown>;
type Upstream = "hang-after-body" | "answer" | "drop-before-body" | "drop-mid-body";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function setup(
  extra: Partial<HandleArgs<Record<string, unknown>>>,
  upstream: Upstream = "hang-after-body",
  attachment: string = ATTACHMENT,
) {
  const d1 = new FakeD1();
  const r2 = new FakeR2();
  const store: PutFileCapabilityDeps = {
    STAGING_D1: d1 as unknown as D1Database,
    STAGING_R2: r2 as unknown as R2Bucket,
    config: CFG,
    uploadOrigin: "https://mcp.example",
    owner: OWNER,
  };
  // The order of everything that happens: audit lines by kind, and the fetch.
  const order: string[] = [];
  const raw: string[] = [];
  const logSpy = vi.spyOn(console, "log").mockImplementation((s: unknown) => {
    if (typeof s === "string" && s.startsWith("AUDIT ")) {
      raw.push(s);
      const l = JSON.parse(s.slice(6)) as Line;
      order.push(l.phase === "dispatch" ? "audit:dispatch" : l.outcome === "failed" ? "audit:failed" : `audit:${String(l.operationId)}`);
    }
  });
  const audits = (): Line[] => raw.map((s) => JSON.parse(s.slice(6)) as Line);

  // The session's putFile, audited like init() wires it.
  const putFile = createPutFileCapability({ ...store, audit: createAuditSink({ deployment: DEPLOYMENT, principalId: OWNER }), auditPath: "__stagingHost.putFile" });
  const staged = await putFile(btoa(attachment), "application/pdf", "q.pdf");
  if (!staged.ok) throw new Error("stage failed");

  const inspected: unknown[] = [];
  // Inspected + opted in, like gmail.users.messages.send.media.
  const SR: SurfaceReview = {
    sendMedia: {
      decision: "allow",
      acceptsStaged: true,
      inspect: (req) => {
        inspected.push(req);
        return { decision: "allow" };
      },
    },
  };

  const received: { body: string; auth: string | null }[] = [];
  let bodyDelivered!: () => void;
  const delivered = new Promise<void>((r) => (bodyDelivered = r));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_u: RequestInfo | URL, init?: RequestInit) => {
      order.push("fetch");
      if (upstream === "drop-before-body") {
        // The connection goes away without the body being read.
        throw new TypeError("fetch failed: socket hang up");
      }
      if (upstream === "drop-mid-body") {
        // The connection reads the first chunk, then resets: the body's
        // consumer is gone while the writer is still mid-body.
        const reader = (init?.body as ReadableStream<Uint8Array>).getReader();
        await reader.read();
        await reader.cancel(new Error("connection reset by peer"));
        await new Promise((r) => setTimeout(r, 20));
        throw new TypeError("fetch failed: connection reset by peer");
      }
      const body = await new Response(init?.body as BodyInit).text();
      received.push({ body, auth: new Headers(init?.headers).get("authorization") });
      bodyDelivered();
      if (upstream === "answer") {
        return new Response('{"id":"sent-1"}', { status: 200, headers: { "content-type": "application/json" } });
      }
      // No response until the client aborts.
      return new Promise<Response>((_, reject) => {
        const signal = init?.signal as AbortSignal;
        const fail = () => reject(signal.reason ?? new Error("aborted"));
        if (signal.aborted) fail();
        else signal.addEventListener("abort", fail, { once: true });
      });
    }),
  );

  const ctx: UpstreamCtx = {
    method: "POST",
    path: "/upload/send",
    contentType: "message/rfc822",
    composed: {
      segments: [
        { text: RFC822_HEAD },
        { staged: { file_handle: staged.file_handle, token: staged.token }, encoding: "base64-lines" },
      ],
    },
  };
  const args: HandleArgs<Record<string, unknown>> = {
    ctx,
    spec: SPEC,
    surfaceReview: SR,
    apiBaseUrl: "https://api.example",
    deploymentName: DEPLOYMENT,
    props: { refreshToken: "RT", userId: OWNER },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    server: { server: { getClientCapabilities: () => ({}) } } as any,
    env: {},
    audit: { principalIdAccessor: () => OWNER },
    oauth: {
      refreshTokenAccessor: () => "RT",
      userIdAccessor: () => OWNER,
      broker: { getOrRefreshAccessToken: async () => "AT-secret" },
    },
    openStaged: createStagedFileOpener({ ...store }),
    stagingStore: store,
    ...extra,
  };
  // base64-lines: 76-char lines, each CRLF-terminated.
  const b64 = btoa(attachment);
  const assembledBytes = new TextEncoder().encode(RFC822_HEAD).byteLength + b64.length + 2 * Math.ceil(b64.length / 76);
  return { args, received, delivered, audits, raw, order, inspected, logSpy, staged, assembledBytes, attachment };
}

/** No line may carry the handle, the token, the bearer or an error text. */
function expectNoSecrets(t: Awaited<ReturnType<typeof setup>>): void {
  for (const s of t.raw) {
    expect(s).not.toContain(t.staged.file_handle);
    expect(s).not.toContain(t.staged.token);
    expect(s).not.toContain("AT-secret");
    expect(s).not.toMatch(/staged transfer|socket hang up|connection reset|deadline|timed out|fetch failed/);
  }
}

const DISPATCH = (t: Awaited<ReturnType<typeof setup>>) => ({
  deployment: DEPLOYMENT,
  method: "POST",
  path: "/upload/send",
  operationId: "sendMedia",
  decision: "allow",
  phase: "dispatch",
  principalId: OWNER,
  stagedCount: 1,
  stagedBytes: t.attachment.length,
  assembledBytes: t.assembledBytes,
  stagedRefs: [t.staged.file_ref],
});

describe("E-4: aborted host-assembled sends are on record", () => {
  it("FIXED (E-4): host deadline after the body was fully delivered → a dispatch line before the first byte, then outcome: failed / transfer-aborted; REFUTED: the upstream still holds the body", async () => {
    const run = new AbortController();
    const t = await setup({ signal: run.signal, runKey: {} });
    const p = handleUpstreamRequest(t.args);
    p.catch(() => {});
    await t.delivered; // upstream now holds the complete request
    // The send was on record BEFORE the body went out.
    expect(t.order).toEqual(["audit:staging.store", "audit:dispatch", "fetch"]);
    expect(t.audits()[1]).toMatchObject(DISPATCH(t));

    run.abort(new ToolError("staged transfer aborted: this execution passed its host-side deadline"));
    await expect(p).rejects.toBeInstanceOf(ToolError);

    // The upstream received a complete, authenticated message (unchanged)…
    expect(t.received).toHaveLength(1);
    expect(t.received[0]!.auth).toBe("Bearer AT-secret");
    expect(t.received[0]!.body).toContain("To: someone@example");
    expect(t.received[0]!.body).toContain(btoa(ATTACHMENT));
    // …the inspector approved it once…
    expect(t.inspected).toHaveLength(1);
    // …and the log has both halves of the story.
    expect(t.order).toEqual(["audit:staging.store", "audit:dispatch", "fetch", "audit:failed"]);
    const lines = t.audits();
    expect(lines).toHaveLength(3);
    expect(lines[2]).toMatchObject({
      deployment: DEPLOYMENT,
      method: "POST",
      path: "/upload/send",
      operationId: "sendMedia",
      decision: "allow",
      outcome: "failed",
      reason: "transfer-aborted",
      principalId: OWNER,
      stagedCount: 1,
      stagedBytes: ATTACHMENT.length,
      assembledBytes: t.assembledBytes,
      stagedRefs: [t.staged.file_ref],
    });
    expect(lines[2]).not.toHaveProperty("phase");
    expect(lines[2]).not.toHaveProperty("upstreamStatus");
    // Create and use of the file are joined by fileRef only.
    expect((lines[0] as { staging: { fileRef: string } }).staging.fileRef).toBe(t.staged.file_ref);
    expectNoSecrets(t);
  });

  it("FIXED (E-4): the per-transfer timeout has the same two lines, reason transfer-timeout", async () => {
    const t = await setup({ stagingLimits: { transferTimeoutMs: 150 } });
    await expect(handleUpstreamRequest(t.args)).rejects.toThrow(/timed out/);
    expect(t.received).toHaveLength(1);
    expect(t.order).toEqual(["audit:staging.store", "audit:dispatch", "fetch", "audit:failed"]);
    const lines = t.audits();
    expect(lines[1]).toMatchObject(DISPATCH(t));
    expect(lines[2]).toMatchObject({ operationId: "sendMedia", decision: "allow", outcome: "failed", reason: "transfer-timeout", stagedRefs: [t.staged.file_ref] });
    expectNoSecrets(t);
  });

  it("FIXED (E-4): an upstream that rejects the request before reading the body → dispatch line, then outcome: failed / upstream-request-failed", async () => {
    const t = await setup({}, "drop-before-body");
    await expect(handleUpstreamRequest(t.args)).rejects.toThrow(/^upstream request failed: /);
    expect(t.received).toHaveLength(0);
    expect(t.order).toEqual(["audit:staging.store", "audit:dispatch", "fetch", "audit:failed"]);
    const lines = t.audits();
    expect(lines).toHaveLength(3);
    expect(lines[1]).toMatchObject(DISPATCH(t));
    expect(lines[2]).toMatchObject({ operationId: "sendMedia", decision: "allow", outcome: "failed", reason: "upstream-request-failed", stagedRefs: [t.staged.file_ref] });
    expectNoSecrets(t);
  });

  it("FIXED (E-4): an upstream that resets the connection mid-body → dispatch line, then outcome: failed / upstream-closed", async () => {
    // Three 1 MiB blocks: the writer is certainly still mid-body when the
    // consumer goes away after the first chunk.
    const big = "x".repeat(2_500_000);
    const t = await setup({}, "drop-mid-body", big);
    await expect(handleUpstreamRequest(t.args)).rejects.toThrow(/^staged transfer failed: upstream closed the connection after \d+ of \d+ bytes were sent/);
    expect(t.received).toHaveLength(0);
    expect(t.order).toEqual(["audit:staging.store", "audit:dispatch", "fetch", "audit:failed"]);
    const lines = t.audits();
    expect(lines).toHaveLength(3);
    expect(lines[1]).toMatchObject(DISPATCH(t));
    expect(lines[2]).toMatchObject({ operationId: "sendMedia", decision: "allow", outcome: "failed", reason: "upstream-closed", stagedBytes: big.length, stagedRefs: [t.staged.file_ref] });
    expectNoSecrets(t);
  });

  it("REFUTED: a send the upstream answers gets the dispatch line and its ordinary final line (bodyComplete, no phase), and exactly one of each", async () => {
    const t = await setup({}, "answer");
    const r = (await handleUpstreamRequest(t.args)) as { success: boolean; status: number };
    expect(r).toMatchObject({ success: true, status: 200 });
    expect(t.received).toHaveLength(1);
    expect(t.order).toEqual(["audit:staging.store", "audit:dispatch", "fetch", "audit:sendMedia"]);
    const lines = t.audits();
    expect(lines).toHaveLength(3);
    expect(lines[1]).toMatchObject(DISPATCH(t));
    expect(lines[2]).toMatchObject({
      operationId: "sendMedia",
      decision: "allow",
      upstreamStatus: 200,
      stagedCount: 1,
      stagedBytes: ATTACHMENT.length,
      assembledBytes: t.assembledBytes,
      bodyBytesSent: t.assembledBytes,
      bodyComplete: true,
      stagedRefs: [t.staged.file_ref],
    });
    expect(lines[2]).not.toHaveProperty("phase");
    expect(lines[2]).not.toHaveProperty("outcome");
    expectNoSecrets(t);
  });
});
