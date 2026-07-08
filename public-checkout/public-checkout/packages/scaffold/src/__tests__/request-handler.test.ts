// packages/scaffold/src/__tests__/request-handler.test.ts
//
// Tests for slice-2 request-handler additions:
//   - HandleArgs.requestHeaders: when present, merged into outbound fetch headers (alongside Authorization).
//   - HandleArgs.audit.waitUntil: when provided, audit logs fire inside it (so canceled-SSE doesn't drop logs).
//   - HandleArgs.audit.principalId / context: passed through to AuditEntry.
//   - HandleArgs.oauth.broker + userIdAccessor: missing userId throws ToolError; otherwise the broker stub mints the access token used in the outbound Authorization header.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest } from "../request-handler";
import { getOrRefreshAccessToken } from "../refresh";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReview } from "@local/shared";

const SPEC: OpenApiSpec = {
  openapi: "3.0.0",
  info: { title: "Test", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/widgets": {
      get: { operationId: "listWidgets", responses: { "200": { description: "OK" } } },
    },
  },
  components: { schemas: {} },
};
const SR: SurfaceReview = {
  listWidgets: { decision: "allow", category: "standard_read" },
};

function makeFetchSpy() {
  return vi.fn<typeof fetch>(async (url: RequestInfo | URL) => {
    const u = typeof url === "string" ? url : url.toString();
    if (u.includes("/token")) {
      return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
    }
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
  });
}
function makeFakeBroker() {
  const data = new Map<string, unknown>();
  const storage = {
    get: async <T>(k: string) => data.get(k) as T | undefined,
    put: async <T>(k: string, v: T) => { data.set(k, v); },
  };
  return {
    async getOrRefreshAccessToken(args: { userId: string; refreshToken: string }) {
      return getOrRefreshAccessToken({
        storage,
        rotation: "static",
        refreshToken: args.refreshToken,
        clientId: "CID",
        clientSecret: "CSEC",
        tokenUrl: "https://api.example.com/token",
      });
    },
  };
}
function captureAudit() {
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  return {
    logSpy,
    read: () =>
      logSpy.mock.calls
        .map((c) => c[0])
        .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
        .map((s) => JSON.parse(s.slice(6)) as Record<string, unknown>),
  };
}

const baseArgs = {
  ctx: { method: "GET" as const, path: "/widgets" },
  spec: SPEC,
  surfaceReview: SR,
  apiBaseUrl: "https://api.example.com",
  deploymentName: "test",
  server: {} as never,
  oauth: {
    refreshTokenAccessor: (p: Record<string, unknown>) => p.refreshToken as string,
    userIdAccessor: (p: Record<string, unknown>) => p.userId as string | undefined,
    broker: makeFakeBroker(),
  },
  audit: {},
  env: {} as { ALLOW_PII_IN_LOGS?: string },
};

describe("request-handler slice-2 extensions", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("merges requestHeaders(props) into the outbound fetch alongside Authorization", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    captureAudit();

    const props = { refreshToken: "RT-1", userId: "test-user", tenantId: "TENANT-XYZ" };
    await handleUpstreamRequest({
      ...baseArgs,
      props,
      requestHeaders: (p) => ({ "xero-tenant-id": p.tenantId as string }),
    });

    const fetchSpy = (globalThis as unknown as { fetch: ReturnType<typeof vi.fn> }).fetch;
    const upstreamCall = fetchSpy.mock.calls.find((c) =>
      String(c[0]).includes("/widgets"),
    )!;
    const headers = (upstreamCall[1] as RequestInit).headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer AT-x");
    expect(headers["xero-tenant-id"]).toBe("TENANT-XYZ");
  });

  it("absent requestHeaders: outbound has only Authorization (regression)", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    captureAudit();

    await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
    });

    const fetchSpy = (globalThis as unknown as { fetch: ReturnType<typeof vi.fn> }).fetch;
    const upstreamCall = fetchSpy.mock.calls.find((c) =>
      String(c[0]).includes("/widgets"),
    )!;
    const headers = (upstreamCall[1] as RequestInit).headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer AT-x");
    expect(Object.keys(headers).filter((k) => k.toLowerCase() !== "authorization")).toEqual([]);
  });

  it("forwards ctx.contentType when set (overrides default application/json)", async () => {
    const fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy);
    captureAudit();

    const SR_POST: SurfaceReview = { postWidget: { decision: "allow", category: "standard_write" } };
    const SPEC_POST: OpenApiSpec = {
      openapi: "3.0.0", info: { title: "T", version: "1" }, servers: [{ url: "https://api.example.com" }],
      paths: { "/widgets": { post: { operationId: "postWidget", responses: { "200": { description: "OK" } } } } },
      components: { schemas: {} },
    };
    await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      spec: SPEC_POST,
      surfaceReview: SR_POST,
      ctx: {
        method: "POST", path: "/widgets",
        body: "<xml/>", rawBody: true, contentType: "application/xml",
      },
    });

    const upstreamCall = fetchSpy.mock.calls.find((c) => String(c[0]).includes("/widgets"))!;
    const init = upstreamCall[1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["content-type"]).toBe("application/xml");
    expect(init.body).toBe("<xml/>");
  });

  it("bodyBase64 decodes to raw bytes; high-byte values are preserved", async () => {
    const fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy);
    captureAudit();

    const SR_POST: SurfaceReview = { postWidget: { decision: "allow", category: "standard_write" } };
    const SPEC_POST: OpenApiSpec = {
      openapi: "3.0.0", info: { title: "T", version: "1" }, servers: [{ url: "https://api.example.com" }],
      paths: { "/widgets": { post: { operationId: "postWidget", responses: { "200": { description: "OK" } } } } },
      components: { schemas: {} },
    };
    // Bytes: 0x25 0x50 0x44 0x46 (PDF magic) plus high-byte 0xFF to prove no UTF-8 expansion.
    const raw = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0xff]);
    let s = "";
    for (const b of raw) s += String.fromCharCode(b);
    const bodyBase64 = btoa(s);

    await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      spec: SPEC_POST,
      surfaceReview: SR_POST,
      ctx: {
        method: "POST", path: "/widgets",
        bodyBase64, contentType: "application/pdf",
      },
    });

    const upstreamCall = fetchSpy.mock.calls.find((c) => String(c[0]).includes("/widgets"))!;
    const init = upstreamCall[1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["content-type"]).toBe("application/pdf");
    expect(init.body).toBeInstanceOf(Uint8Array);
    expect(Array.from(init.body as Uint8Array)).toEqual([0x25, 0x50, 0x44, 0x46, 0xff]);
  });

  it("multipart: assembles server-side, sets content-type with boundary, preserves binary parts", async () => {
    const fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy);
    captureAudit();

    const SR_POST: SurfaceReview = { uploadFile: { decision: "allow", category: "standard_write" } };
    const SPEC_POST: OpenApiSpec = {
      openapi: "3.0.0", info: { title: "T", version: "1" }, servers: [{ url: "https://api.example.com" }],
      paths: { "/files": { post: { operationId: "uploadFile", responses: { "200": { description: "OK" } } } } },
      components: { schemas: {} },
    };
    // Binary part: 0x25 0x50 0x44 0x46 0xff (PDF magic + high byte).
    const raw = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0xff]);
    let s = "";
    for (const b of raw) s += String.fromCharCode(b);
    const bodyBase64 = btoa(s);

    await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      spec: SPEC_POST,
      surfaceReview: SR_POST,
      ctx: {
        method: "POST", path: "/files",
        multipart: [
          { name: "Name", value: "x.pdf" },
          { name: "file", filename: "x.pdf", contentType: "application/pdf", bodyBase64 },
        ],
      },
    });

    const upstreamCall = fetchSpy.mock.calls.find((c) => String(c[0]).includes("/files"))!;
    const init = upstreamCall[1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    const ct = headers["content-type"]!;
    expect(ct).toMatch(/^multipart\/form-data; boundary=----codemode-[0-9a-f]+$/);
    const boundary = ct.replace(/^multipart\/form-data; boundary=/, "");

    expect(init.body).toBeInstanceOf(Uint8Array);
    const body = init.body as Uint8Array;
    // Find the PDF binary bytes survive intact (no UTF-8 expansion of 0xFF).
    const ffCount = body.reduce((n, b) => n + (b === 0xff ? 1 : 0), 0);
    expect(ffCount).toBe(1);

    // Decode the header regions as ASCII to spot-check structure.
    const ascii = Array.from(body, (b) => (b < 0x80 ? String.fromCharCode(b) : "·")).join("");
    expect(ascii).toContain(`--${boundary}\r\n`);
    expect(ascii).toContain('Content-Disposition: form-data; name="Name"\r\n');
    expect(ascii).toContain('Content-Type: text/plain\r\n\r\nx.pdf\r\n');
    expect(ascii).toContain('Content-Disposition: form-data; name="file"; filename="x.pdf"\r\n');
    expect(ascii).toContain('Content-Type: application/pdf\r\n\r\n');
    expect(ascii).toContain(`\r\n--${boundary}--\r\n`);
  });

  it("multipart: rejects parts that set both value and bodyBase64", async () => {
    const fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy);
    captureAudit();

    const SR_POST: SurfaceReview = { uploadFile: { decision: "allow", category: "standard_write" } };
    const SPEC_POST: OpenApiSpec = {
      openapi: "3.0.0", info: { title: "T", version: "1" }, servers: [{ url: "https://api.example.com" }],
      paths: { "/files": { post: { operationId: "uploadFile", responses: { "200": { description: "OK" } } } } },
      components: { schemas: {} },
    };
    await expect(handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      spec: SPEC_POST,
      surfaceReview: SR_POST,
      ctx: {
        method: "POST", path: "/files",
        multipart: [{ name: "x", value: "a", bodyBase64: btoa("b") }],
      },
    })).rejects.toThrow(/mutually exclusive/);
  });

  it("default JSON path still works (regression): JSON-stringified body + application/json", async () => {
    const fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy);
    captureAudit();

    const SR_POST: SurfaceReview = { postWidget: { decision: "allow", category: "standard_write" } };
    const SPEC_POST: OpenApiSpec = {
      openapi: "3.0.0", info: { title: "T", version: "1" }, servers: [{ url: "https://api.example.com" }],
      paths: { "/widgets": { post: { operationId: "postWidget", responses: { "200": { description: "OK" } } } } },
      components: { schemas: {} },
    };
    await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      spec: SPEC_POST,
      surfaceReview: SR_POST,
      ctx: { method: "POST", path: "/widgets", body: { name: "a" } },
    });

    const upstreamCall = fetchSpy.mock.calls.find((c) => String(c[0]).includes("/widgets"))!;
    const init = upstreamCall[1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["content-type"]).toBe("application/json");
    expect(init.body).toBe('{"name":"a"}');
  });

  it("waitUntil receives a promise wrapping the audit emission", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    const audit = captureAudit();
    const waitUntilSpy = vi.fn();

    await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      audit: { waitUntil: waitUntilSpy },
    });

    expect(waitUntilSpy).toHaveBeenCalled();
    // Wait for the queued promise(s) to resolve so the AUDIT log is emitted.
    await Promise.all(waitUntilSpy.mock.calls.map((c) => c[0]));
    const lines = audit.read();
    expect(lines.some((l) => l.decision === "allow" && l.operationId === "listWidgets")).toBe(true);
  });

  it("propagates principalId and context from props onto the audit entry", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    const audit = captureAudit();
    const waitUntilSpy = vi.fn();

    await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "user-123", tenantId: "tenant-abc" },
      audit: {
        principalIdAccessor: (p) => p.userId as string,
        contextAccessor: (p) => ({ tenantId: p.tenantId as string }),
        waitUntil: waitUntilSpy,
      },
    });

    await Promise.all(waitUntilSpy.mock.calls.map((c) => c[0]));
    const lines = audit.read();
    const allowLine = lines.find((l) => l.decision === "allow")!;
    expect(allowLine.principalId).toBe("user-123");
    expect(allowLine.context).toEqual({ tenantId: "tenant-abc" });
  });
});

describe("handleUpstreamRequest — elicit integration", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  const SPEC_E: OpenApiSpec = {
    openapi: "3.0.0", info: { title: "T", version: "1" }, servers: [{ url: "https://x" }],
    paths: {
      "/send": {
        post: {
          operationId: "doSend",
          requestBody: { content: { "application/json": { schema: { type: "object", properties: { to: { type: "string" } } } } } },
          responses: { "200": { description: "OK" } },
        },
      },
    },
    components: { schemas: {} },
  };
  const SR_E: SurfaceReview = {
    doSend: { decision: "elicit", category: "external_data_flow" },
  };

  function makeMcpStub(elicitInput: (p: unknown) => Promise<unknown>) {
    return {
      server: {
        getClientCapabilities: () => ({ elicitation: {} }),
        elicitInput,
      },
    };
  }

  it("accept -> upstream fetch fires; audit allow follows the elicit-accepted entry", async () => {
    const fetchSpy = vi.fn(async (url: RequestInfo | URL) => {
      const u = typeof url === "string" ? url : url.toString();
      if (u.includes("/token")) {
        return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchSpy);
    const audit = captureAudit();
    const elicitInput = vi.fn(async () => ({ action: "accept", content: { to: "x@y.com" } }));

    await handleUpstreamRequest({
      ctx: { method: "POST", path: "/send", body: { to: "x@y.com" } },
      spec: SPEC_E,
      surfaceReview: SR_E,
      apiBaseUrl: "https://x",
      deploymentName: "test",
      props: { refreshToken: "r", userId: "test-user" },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: makeMcpStub(elicitInput) as any,
      oauth: {
        refreshTokenAccessor: (p) => (p as { refreshToken: string }).refreshToken,
        userIdAccessor: (p) => (p as { userId?: string }).userId,
        broker: makeFakeBroker(),
      },
      audit: {},
      env: {},
    });

    expect(elicitInput).toHaveBeenCalledTimes(1);
    expect(fetchSpy).toHaveBeenCalled();   // upstream went through

    // Audit chain: accepted entry must precede the allow entry
    const lines = audit.read();
    const acceptedIdx = lines.findIndex((l) => l.elicitationOutcome === "accepted");
    const allowIdx = lines.findIndex((l) => l.decision === "allow");
    expect(acceptedIdx).toBeGreaterThanOrEqual(0);
    expect(allowIdx).toBeGreaterThanOrEqual(0);
    expect(acceptedIdx).toBeLessThan(allowIdx);
  });

  it("decline -> ToolError; no upstream fetch", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const elicitInput = vi.fn(async () => ({ action: "decline" }));

    await expect(
      handleUpstreamRequest({
        ctx: { method: "POST", path: "/send", body: { to: "x@y.com" } },
        spec: SPEC_E,
        surfaceReview: SR_E,
        apiBaseUrl: "https://x",
        deploymentName: "test",
        props: { refreshToken: "r", userId: "test-user" },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        server: makeMcpStub(elicitInput) as any,
        oauth: {
          refreshTokenAccessor: (p) => (p as { refreshToken: string }).refreshToken,
          userIdAccessor: (p) => (p as { userId?: string }).userId,
          broker: makeFakeBroker(),
        },
        audit: {},
        env: {},
      }),
    ).rejects.toThrow(/declined/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("freezes ctx.body before inspectors run", async () => {
    const ctx = { method: "POST" as const, path: "/send", body: { to: "x@y.com" } };
    const elicitInput = vi.fn(async () => ({ action: "accept", content: { to: "x@y.com" } }));
    vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL) => {
      const u = typeof url === "string" ? url : url.toString();
      if (u.includes("/token")) {
        return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
      }
      return new Response("{}", { status: 200 });
    }));
    captureAudit();

    await handleUpstreamRequest({
      ctx,
      spec: SPEC_E,
      surfaceReview: SR_E,
      apiBaseUrl: "https://x",
      deploymentName: "test",
      props: { refreshToken: "r", userId: "test-user" },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: makeMcpStub(elicitInput) as any,
      oauth: {
        refreshTokenAccessor: (p) => (p as { refreshToken: string }).refreshToken,
        userIdAccessor: (p) => (p as { userId?: string }).userId,
        broker: makeFakeBroker(),
      },
      audit: {},
      env: {},
    });

    expect(Object.isFrozen(ctx.body)).toBe(true);
  });

  // H1 redaction: by default `elicitFields` carrying PII (recipients/subject)
  // are collapsed to a `{__redacted__, keys, …Length/…Count/…Value}` shape.
  // Opt back in by setting `env.ALLOW_PII_IN_LOGS="true"`.
  it("audit is redacted by default (elicitFields → __redacted__ shape)", async () => {
    const fetchSpy = vi.fn(async (url: RequestInfo | URL) => {
      const u = typeof url === "string" ? url : url.toString();
      if (u.includes("/token")) {
        return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchSpy);
    const audit = captureAudit();
    const elicitInput = vi.fn(async () => ({
      action: "accept",
      content: { to: "x@y.com" },
    }));

    await handleUpstreamRequest({
      ctx: { method: "POST", path: "/send", body: { to: "x@y.com" } },
      spec: SPEC_E,
      surfaceReview: SR_E,
      apiBaseUrl: "https://x",
      deploymentName: "test",
      props: { refreshToken: "r", userId: "test-user" },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: makeMcpStub(elicitInput) as any,
      oauth: {
        refreshTokenAccessor: (p) => (p as { refreshToken: string }).refreshToken,
        userIdAccessor: (p) => (p as { userId?: string }).userId,
        broker: makeFakeBroker(),
      },
      audit: {},
      env: {},
    });

    const lines = audit.read();
    const elicitLine = lines.find(
      (l) => l.elicitationOutcome === "accepted" && l.elicitFields !== undefined,
    );
    expect(elicitLine).toBeDefined();
    const fields = elicitLine!.elicitFields as Record<string, unknown>;
    expect(fields.__redacted__).toBe(true);
    expect(Array.isArray(fields.keys)).toBe(true);
    // Raw renderer field value (`to: "x@y.com"`) must not survive.
    expect(JSON.stringify(elicitLine)).not.toContain("x@y.com");
    // Operational fields outside elicitFields survive.
    expect(elicitLine!.deployment).toBe("test");
    expect(elicitLine!.decision).toBe("elicit");
    expect(elicitLine!.category).toBe("external_data_flow");
  });

});

describe("handleUpstreamRequest — returnAs:\"stage\"", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  function makeBinaryFetchSpy(response: Response) {
    return vi.fn<typeof fetch>(async (url: RequestInfo | URL) => {
      const u = typeof url === "string" ? url : url.toString();
      if (u.includes("/token")) {
        return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
      }
      return response.clone();
    });
  }

  it("happy path: stages 2xx bytes, returns file-handle envelope, bypasses truncate", async () => {
    const raw = new Uint8Array([1, 2, 3, 4, 5]);
    const upstreamResp = new Response(raw, {
      status: 200,
      headers: {
        "content-type": "application/pdf",
        "content-disposition": 'attachment; filename="file.pdf"',
      },
    });
    vi.stubGlobal("fetch", makeBinaryFetchSpy(upstreamResp));
    captureAudit();

    const putFile = vi.fn(async () => ({
      ok: true as const,
      file_handle: "fh_x",
      token: "stg_y",
      fetch_url: "https://x.test/staging/fetch/fh_x",
      expires_at: 999,
      byte_length: 5,
    }));

    const result = (await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      ctx: { method: "GET", path: "/widgets", returnAs: "stage" },
      putFile,
    })) as {
      success: boolean;
      status: number;
      result: Record<string, unknown>;
      errors: unknown[];
    };

    expect(result.success).toBe(true);
    expect(result.status).toBe(200);
    expect(result.result.file_handle).toBe("fh_x");
    expect(result.result.token).toBe("stg_y");
    expect(result.result.fetch_url).toBe("https://x.test/staging/fetch/fh_x");
    expect(result.result.expires_at).toBe(999);
    expect(result.result.byte_length).toBe(5);
    expect(result.result.contentType).toBe("application/pdf");
    expect(result.result.filename).toBe("file.pdf");
    expect(result.errors).toEqual([]);

    expect(putFile).toHaveBeenCalledTimes(1);
    // Base64 of [1,2,3,4,5]
    let s = "";
    for (const b of raw) s += String.fromCharCode(b);
    const expectedB64 = btoa(s);
    expect(putFile).toHaveBeenCalledWith(expectedB64, "application/pdf", "file.pdf");
  });

  it("non-2xx upstream: putFile NOT called; falls through to normal error envelope", async () => {
    const upstreamResp = new Response(JSON.stringify({ error: "not found" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
    vi.stubGlobal("fetch", makeBinaryFetchSpy(upstreamResp));
    captureAudit();

    const putFile = vi.fn(async () => ({
      ok: true as const,
      file_handle: "x", token: "y", fetch_url: "z", expires_at: 0, byte_length: 0,
    }));

    const result = (await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      ctx: { method: "GET", path: "/widgets", returnAs: "stage" },
      putFile,
    })) as {
      success: boolean;
      status: number;
      result: unknown;
      errors: Array<{ code: number; message: string }>;
    };

    expect(putFile).not.toHaveBeenCalled();
    expect(result.success).toBe(false);
    expect(result.status).toBe(404);
    expect(result.errors.length).toBe(1);
    expect(result.errors[0]!.code).toBe(404);
  });

  it("stage failure: putFile returns {ok:false} → error envelope with stage_failed", async () => {
    const upstreamResp = new Response(new Uint8Array([0xff, 0xfe]), {
      status: 200,
      headers: { "content-type": "application/octet-stream" },
    });
    vi.stubGlobal("fetch", makeBinaryFetchSpy(upstreamResp));
    captureAudit();

    const putFile = vi.fn(async () => ({
      ok: false as const,
      status: 413,
      message: "too large",
    }));

    const result = (await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      ctx: { method: "GET", path: "/widgets", returnAs: "stage" },
      putFile,
    })) as {
      success: boolean;
      status: number;
      result: { error?: string; message?: string };
      errors: Array<{ code: number; message: string }>;
    };

    expect(result.success).toBe(false);
    expect(result.status).toBe(413);
    expect(result.result.error).toBe("stage_failed");
    expect(result.errors[0]!.code).toBe(413);
    expect(result.errors[0]!.message).toBe("too large");
  });

  it("missing putFile dep: returnAs:\"stage\" without args.putFile → throws ToolError", async () => {
    const upstreamResp = new Response(new Uint8Array([1, 2, 3]), {
      status: 200,
      headers: { "content-type": "application/octet-stream" },
    });
    vi.stubGlobal("fetch", makeBinaryFetchSpy(upstreamResp));
    captureAudit();

    await expect(handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      ctx: { method: "GET", path: "/widgets", returnAs: "stage" },
    })).rejects.toThrow(/putFile|staging/);
  });

  it("filename omitted when Content-Disposition absent", async () => {
    const upstreamResp = new Response(new Uint8Array([9, 8, 7]), {
      status: 200,
      headers: { "content-type": "image/png" },
    });
    vi.stubGlobal("fetch", makeBinaryFetchSpy(upstreamResp));
    captureAudit();

    const putFile = vi.fn(async () => ({
      ok: true as const,
      file_handle: "fh_n",
      token: "tk_n",
      fetch_url: "https://x.test/staging/fetch/fh_n",
      expires_at: 1,
      byte_length: 3,
    }));

    const result = (await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      ctx: { method: "GET", path: "/widgets", returnAs: "stage" },
      putFile,
    })) as { result: Record<string, unknown> };

    expect("filename" in result.result).toBe(false);
    expect(result.result.contentType).toBe("image/png");
    // putFile called with filename=null
    expect(putFile).toHaveBeenCalledWith(expect.any(String), "image/png", null);
  });
});

describe("handleUpstreamRequest — elicit PII", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  const SPEC_E: OpenApiSpec = {
    openapi: "3.0.0", info: { title: "T", version: "1" }, servers: [{ url: "https://x" }],
    paths: {
      "/send": {
        post: {
          operationId: "doSend",
          requestBody: { content: { "application/json": { schema: { type: "object", properties: { to: { type: "string" } } } } } },
          responses: { "200": { description: "OK" } },
        },
      },
    },
    components: { schemas: {} },
  };
  const SR_E: SurfaceReview = {
    doSend: { decision: "elicit", category: "external_data_flow" },
  };

  function makeMcpStub(elicitInput: (p: unknown) => Promise<unknown>) {
    return {
      server: {
        getClientCapabilities: () => ({ elicitation: {} }),
        elicitInput,
      },
    };
  }

  it("audit passes PII through when ALLOW_PII_IN_LOGS=true", async () => {
    const fetchSpy = vi.fn(async (url: RequestInfo | URL) => {
      const u = typeof url === "string" ? url : url.toString();
      if (u.includes("/token")) {
        return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchSpy);
    const audit = captureAudit();
    const elicitInput = vi.fn(async () => ({
      action: "accept",
      content: { to: "x@y.com" },
    }));

    await handleUpstreamRequest({
      ctx: { method: "POST", path: "/send", body: { to: "x@y.com" } },
      spec: SPEC_E,
      surfaceReview: SR_E,
      apiBaseUrl: "https://x",
      deploymentName: "test",
      props: { refreshToken: "r", userId: "test-user" },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: makeMcpStub(elicitInput) as any,
      oauth: {
        refreshTokenAccessor: (p) => (p as { refreshToken: string }).refreshToken,
        userIdAccessor: (p) => (p as { userId?: string }).userId,
        broker: makeFakeBroker(),
      },
      audit: {},
      env: { ALLOW_PII_IN_LOGS: "true" },
    });

    const lines = audit.read();
    const elicitLine = lines.find(
      (l) => l.elicitationOutcome === "accepted" && l.elicitFields !== undefined,
    );
    expect(elicitLine).toBeDefined();
    const fields = elicitLine!.elicitFields as Record<string, unknown>;
    // No redaction marker — raw field value survives.
    expect(fields.__redacted__).toBeUndefined();
    // The renderer for this test op produces fields populated from the body
    // (`{to: "x@y.com"}`), so the raw recipient must be observable.
    expect(JSON.stringify(fields)).toContain("x@y.com");
  });
});

describe("handleUpstreamRequest — bypassTruncate", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("bypassTruncate: true — returns large base64 field untruncated", async () => {
    const largeData = "x".repeat(200_000);
    const upstreamResp = new Response(JSON.stringify({ data: largeData }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
    const fetchSpy = vi.fn<typeof fetch>(async (url: RequestInfo | URL) => {
      const u = typeof url === "string" ? url : url.toString();
      if (u.includes("/token")) {
        return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
      }
      return upstreamResp.clone();
    });
    vi.stubGlobal("fetch", fetchSpy);
    captureAudit();

    const result = (await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      ctx: { method: "GET", path: "/widgets", bypassTruncate: true },
    })) as {
      success: boolean;
      status: number;
      result: Record<string, unknown>;
      errors: unknown[];
    };

    expect(result.success).toBe(true);
    expect(result.status).toBe(200);
    expect(typeof result.result.data).toBe("string");
    expect((result.result.data as string).length).toBe(200_000);
    expect(result.result.__truncated__).toBeUndefined();
  });

  it("bypassTruncate: false (default) — truncates large data with marker", async () => {
    const largeData = "x".repeat(200_000);
    const upstreamResp = new Response(JSON.stringify({ data: largeData }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
    const fetchSpy = vi.fn<typeof fetch>(async (url: RequestInfo | URL) => {
      const u = typeof url === "string" ? url : url.toString();
      if (u.includes("/token")) {
        return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
      }
      return upstreamResp.clone();
    });
    vi.stubGlobal("fetch", fetchSpy);
    captureAudit();

    const result = (await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1", userId: "test-user" },
      ctx: { method: "GET", path: "/widgets" },
    })) as {
      success: boolean;
      status: number;
      result: Record<string, unknown>;
      errors: unknown[];
    };

    expect(result.success).toBe(true);
    expect(result.status).toBe(200);
    expect(typeof result.result.data).toBe("string");
    expect((result.result.data as string).length).toBeLessThan(200_000);
    expect((result.result.data as string)).toContain(" ... [TRUNCATED");
    expect(result.result.__truncated__).toBe(true);
  });
});
