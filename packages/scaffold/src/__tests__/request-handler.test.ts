// packages/scaffold/src/__tests__/request-handler.test.ts
//
// Tests for slice-2 request-handler additions:
//   - HandleArgs.requestHeaders: when present, merged into outbound fetch headers (alongside Authorization).
//   - HandleArgs.audit.waitUntil: when provided, audit logs fire inside it (so canceled-SSE doesn't drop logs).
//   - HandleArgs.audit.principalId / context: passed through to AuditEntry.
//   - HandleArgs.oauth.broker + userIdAccessor: missing userId throws ToolError; otherwise the broker stub mints the access token used in the outbound Authorization header.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "../request-handler";
import { getOrRefreshAccessToken } from "../refresh";
import { ToolError } from "../elicit";
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

  it("forwards ctx.headers (e.g. Accept) to the upstream fetch", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    captureAudit();

    await handleUpstreamRequest({
      ...baseArgs,
      ctx: { method: "GET", path: "/widgets", headers: { Accept: "application/octet-stream" } },
      props: { refreshToken: "RT-1", userId: "test-user" },
    });

    const fetchSpy = (globalThis as unknown as { fetch: ReturnType<typeof vi.fn> }).fetch;
    const upstreamCall = fetchSpy.mock.calls.find((c) => String(c[0]).includes("/widgets"))!;
    const headers = (upstreamCall[1] as RequestInit).headers as Record<string, string>;
    expect(headers["Accept"]).toBe("application/octet-stream");
    expect(headers["Authorization"]).toBe("Bearer AT-x");
  });

  it("rejects disallowed ctx.headers with a ToolError before any upstream fetch", async () => {
    const fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy);
    captureAudit();

    for (const name of ["Authorization", "authorization", "X-HTTP-Method-Override", "Cookie"]) {
      await expect(
        handleUpstreamRequest({
          ...baseArgs,
          ctx: { method: "GET", path: "/widgets", headers: { [name]: "x" } },
          props: { refreshToken: "RT-1", userId: "test-user" },
        }),
      ).rejects.toThrow(`Header "${name}" cannot be set from sandbox code`);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects content-type via ctx.headers, pointing at the contentType option", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    captureAudit();

    await expect(
      handleUpstreamRequest({
        ...baseArgs,
        ctx: { method: "GET", path: "/widgets", headers: { "Content-Type": "text/plain" } },
        props: { refreshToken: "RT-1", userId: "test-user" },
      }),
    ).rejects.toThrow(/use the `contentType` option/);
  });

  it("rejects two casings of the same ctx.header — fetch would comma-combine their values", async () => {
    const fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy);
    captureAudit();

    await expect(
      handleUpstreamRequest({
        ...baseArgs,
        ctx: {
          method: "GET",
          path: "/widgets",
          headers: { Accept: "application/json", ACCEPT: "application/octet-stream" },
        },
        props: { refreshToken: "RT-1", userId: "test-user" },
      }),
    ).rejects.toThrow(/appears more than once/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects ctx.headers on inspected and elicit-gated operations — approval surfaces never see headers", async () => {
    const fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy);
    captureAudit();

    const SPEC_GATED: OpenApiSpec = {
      openapi: "3.0.0", info: { title: "T", version: "1" }, servers: [{ url: "https://api.example.com" }],
      paths: {
        "/inspected": { post: { operationId: "inspectedOp", responses: { "200": { description: "OK" } } } },
        "/elicited": { post: { operationId: "elicitedOp", responses: { "200": { description: "OK" } } } },
      },
      components: { schemas: {} },
    };
    const SR_GATED: SurfaceReview = {
      inspectedOp: {
        decision: "allow",
        category: "standard_write",
        inspect: () => ({ decision: "allow", category: "standard_write" }),
      },
      elicitedOp: { decision: "elicit", category: "external_data_flow" },
    } as unknown as SurfaceReview;

    for (const path of ["/inspected", "/elicited"]) {
      await expect(
        handleUpstreamRequest({
          ...baseArgs,
          spec: SPEC_GATED,
          surfaceReview: SR_GATED,
          ctx: { method: "POST", path, body: { a: 1 }, headers: { Accept: "application/json" } },
          props: { refreshToken: "RT-1", userId: "test-user" },
        }),
      ).rejects.toThrow(/subject to inspection\/approval/);
    }
    // Neither the upstream endpoint nor the token endpoint was reached for the gated calls.
    expect(fetchSpy.mock.calls.filter((c) => String(c[0]).includes("/inspected"))).toHaveLength(0);
    expect(fetchSpy.mock.calls.filter((c) => String(c[0]).includes("/elicited"))).toHaveLength(0);
  });

  it("provider requestHeaders wins over a case-colliding ctx.header — values never combine", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    captureAudit();

    const props = { refreshToken: "RT-1", userId: "test-user", tenantId: "TENANT-XYZ" };
    await handleUpstreamRequest({
      ...baseArgs,
      ctx: { method: "GET", path: "/widgets", headers: { "Xero-Tenant-Id": "evil" } },
      props,
      requestHeaders: (p) => ({ "xero-tenant-id": p.tenantId as string }),
    });

    const fetchSpy = (globalThis as unknown as { fetch: ReturnType<typeof vi.fn> }).fetch;
    const upstreamCall = fetchSpy.mock.calls.find((c) => String(c[0]).includes("/widgets"))!;
    const raw = (upstreamCall[1] as RequestInit).headers as Record<string, string>;
    // One key survives regardless of casing, and it carries the provider value.
    const winner = new Headers(raw).get("xero-tenant-id");
    expect(winner).toBe("TENANT-XYZ");
    expect(Object.keys(raw).filter((k) => k.toLowerCase() === "xero-tenant-id")).toHaveLength(1);
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
    // rawBody strings are now normalized to UTF-8 bytes by resolveEffective so the
    // inspected and sent payloads are identical; the wire content is unchanged.
    expect(init.body).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode(init.body as Uint8Array)).toBe("<xml/>");
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

  it("forwards relatedRequestId to elicitInput as the second arg", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL) => {
      const u = typeof url === "string" ? url : url.toString();
      if (u.includes("/token")) {
        return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }));
    captureAudit();

    let seenOptions: unknown = "UNCALLED";
    const elicitInput = vi.fn(async (_params: unknown, options?: unknown) => {
      seenOptions = options;
      return { action: "accept", content: { to: "x@y.com" } };
    });

    await handleUpstreamRequest({
      ctx: { method: "POST", path: "/send", body: { to: "x@y.com" } },
      spec: SPEC_E,
      surfaceReview: SR_E,
      apiBaseUrl: "https://x",
      deploymentName: "test",
      props: { refreshToken: "r", userId: "test-user" },
      relatedRequestId: "req-42",
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: makeMcpStub(elicitInput as (p: unknown) => Promise<unknown>) as any,
      oauth: {
        refreshTokenAccessor: (p) => (p as { refreshToken: string }).refreshToken,
        userIdAccessor: (p) => (p as { userId?: string }).userId,
        broker: makeFakeBroker(),
      },
      audit: {},
      env: {},
    });

    expect(elicitInput).toHaveBeenCalledTimes(1);
    expect(seenOptions).toEqual({ relatedRequestId: "req-42" });
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

describe("handleUpstreamRequest — inspector deny surfaces a clear message", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  const SPEC_W: OpenApiSpec = {
    openapi: "3.0.0", info: { title: "T", version: "1" }, servers: [{ url: "https://api.example.com" }],
    paths: {
      "/things": {
        put: {
          operationId: "createThings",
          requestBody: { content: { "application/json": { schema: { type: "object" } } } },
          responses: { "200": { description: "OK" } },
        },
      },
    },
    components: { schemas: {} },
  };

  const denyArgs = {
    spec: SPEC_W,
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
    props: { refreshToken: "RT-1", userId: "test-user" },
    ctx: { method: "PUT" as const, path: "/things", body: { Status: "AUTHORISED" } },
  };

  it("throws the inspector's human-readable message, not the opaque generic", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    captureAudit();
    const SR_W: SurfaceReview = {
      createThings: {
        decision: "allow",
        inspect: () => ({
          decision: "deny",
          category: "irreversible",
          reason: "thing-not-draft",
          message: "Only DRAFT or SUBMITTED things can be modified; this thing has Status \"AUTHORISED\".",
        }),
      },
    };

    await expect(handleUpstreamRequest({ ...denyArgs, surfaceReview: SR_W }))
      .rejects.toThrow(/Only DRAFT or SUBMITTED things.*AUTHORISED/);
  });

  it("records the terse reason code in the audit log even when a message is thrown", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    const audit = captureAudit();
    const SR_W: SurfaceReview = {
      createThings: {
        decision: "allow",
        inspect: () => ({
          decision: "deny",
          category: "irreversible",
          reason: "thing-not-draft",
          message: "Only DRAFT or SUBMITTED things can be modified.",
        }),
      },
    };

    await expect(handleUpstreamRequest({ ...denyArgs, surfaceReview: SR_W })).rejects.toThrow();

    const denyLine = audit.read().find((l) => l.decision === "deny" && l.operationId === "createThings");
    expect(denyLine).toBeDefined();
    expect(denyLine!.reason).toBe("thing-not-draft");
  });

  it("falls back to the generic message when the inspector supplies no message", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    captureAudit();
    const SR_W: SurfaceReview = {
      createThings: {
        decision: "allow",
        inspect: () => ({ decision: "deny", category: "irreversible", reason: "thing-not-draft" }),
      },
    };

    await expect(handleUpstreamRequest({ ...denyArgs, surfaceReview: SR_W }))
      .rejects.toThrow(/denied by surface review/);
  });
});

describe("inspection operates on the effective payload", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  const POST_SPEC: OpenApiSpec = {
    openapi: "3.0.0",
    info: { title: "T", version: "1" },
    servers: [{ url: "https://api.example.com" }],
    paths: { "/send": { post: { operationId: "send", responses: { "200": { description: "OK" } } } } },
    components: { schemas: {} },
  };
  // Inspector: deny unless body.to === "ok@allow".
  const SR_INSPECT: SurfaceReview = {
    send: {
      decision: "allow",
      inspect: (req) => {
        const to = (req.body as { to?: string } | undefined)?.to;
        return to === "ok@allow"
          ? { decision: "allow" }
          : { decision: "deny", category: "external_data_flow", reason: "off-allow" };
      },
    },
  };

  function baseInspectArgs(ctx: UpstreamCtx) {
    vi.stubGlobal("fetch", makeFetchSpy());
    captureAudit();
    return {
      ctx,
      spec: POST_SPEC,
      surfaceReview: SR_INSPECT,
      apiBaseUrl: "https://api.example.com",
      deploymentName: "test",
      props: { refreshToken: "RT-1", userId: "test-user" },
      server: {} as never,
      env: {} as { ALLOW_PII_IN_LOGS?: string },
      audit: {},
      oauth: {
        refreshTokenAccessor: (p: Record<string, unknown>) => p.refreshToken as string,
        userIdAccessor: (p: Record<string, unknown>) => p.userId as string | undefined,
        broker: makeFakeBroker(),
      },
    };
  }

  it("denies a body+bodyBase64 decoy (the PoC) as malformed", async () => {
    const evil = Buffer.from(JSON.stringify({ to: "evil@attacker" }), "utf8").toString("base64");
    await expect(
      handleUpstreamRequest(
        baseInspectArgs({ method: "POST", path: "/send", body: { to: "ok@allow" }, bodyBase64: evil, contentType: "application/json" }),
      ),
    ).rejects.toThrow(/surface review|malformed|multiple/i);
  });

  it("inspects the decoded bodyBase64 payload when it is the only channel", async () => {
    const evil = Buffer.from(JSON.stringify({ to: "evil@attacker" }), "utf8").toString("base64");
    await expect(
      handleUpstreamRequest(
        baseInspectArgs({ method: "POST", path: "/send", bodyBase64: evil, contentType: "application/json" }),
      ),
    ).rejects.toThrow(/surface review/i);
  });

  it("allows a legitimate single-channel body that the inspector approves", async () => {
    await expect(
      handleUpstreamRequest(baseInspectArgs({ method: "POST", path: "/send", body: { to: "ok@allow" } })),
    ).resolves.toBeDefined();
  });

  // Regression: a non-JSON bodyBase64 payload surfaces to the inspector as
  // `req.rawBody: Uint8Array`. deepFreeze must not throw on that typed array,
  // and the inspector must actually see the decoded bytes.
  describe("raw (non-JSON) payload reaches the inspector without crashing deepFreeze", () => {
    // Inspector reads the raw bytes and denies when they contain "evil".
    const SR_RAW: SurfaceReview = {
      send: {
        decision: "allow",
        inspect: (req) => {
          const bytes = req.rawBody as Uint8Array | undefined;
          const text = bytes ? new TextDecoder().decode(bytes) : "";
          return text.includes("evil")
            ? { decision: "deny", category: "external_data_flow", reason: "raw-evil" }
            : { decision: "allow" };
        },
      },
    };

    function rawArgs(ctx: UpstreamCtx) {
      return { ...baseInspectArgs(ctx), surfaceReview: SR_RAW };
    }

    it("denies when the decoded rawBody bytes contain the marker (no TypeError)", async () => {
      const evil = Buffer.from("From: evil@attacker\r\n\r\nhi", "utf8").toString("base64");
      await expect(
        handleUpstreamRequest(
          rawArgs({ method: "POST", path: "/send", bodyBase64: evil, contentType: "message/rfc822" }),
        ),
      ).rejects.toThrow(/surface review/i);
    });

    it("allows when the decoded rawBody bytes are clean; inspector saw the bytes", async () => {
      const clean = Buffer.from("From: ok@allow\r\n\r\nhi", "utf8").toString("base64");
      await expect(
        handleUpstreamRequest(
          rawArgs({ method: "POST", path: "/send", bodyBase64: clean, contentType: "message/rfc822" }),
        ),
      ).resolves.toBeDefined();
    });
  });
});

describe("request path hardening (F-1, F-6, F-7, F-11, F-17, F-19, F-24)", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  const HARD_SPEC: OpenApiSpec = {
    openapi: "3.0.0",
    info: { title: "T", version: "1" },
    servers: [{ url: "https://api.example.com" }],
    paths: {
      "/things/{id}": {
        get: { operationId: "getThing", responses: { "200": { description: "OK" } } },
        delete: { operationId: "deleteThing", responses: { "200": { description: "OK" } } },
      },
      // Listed first so the WIRE path "/items/labels/1" resolves here, while the
      // raw path "/items/lab%65ls/1" skips it (literal mismatch) and matches below.
      "/items/labels/{id}": {
        get: { operationId: "getLabelItem", responses: { "200": { description: "OK" } } },
      },
      "/items/{kind}/{id}": {
        get: { operationId: "getItem", responses: { "200": { description: "OK" } } },
      },
      "/send": { post: { operationId: "send", responses: { "200": { description: "OK" } } } },
      "/plain": { post: { operationId: "plain", responses: { "200": { description: "OK" } } } },
    },
    components: { schemas: {} },
  };
  const inspectSpy = vi.fn((_req: unknown) => ({ decision: "allow" as const }));
  const HARD_SR: SurfaceReview = {
    getThing: { decision: "allow", category: "standard_read" },
    deleteThing: { decision: "elicit", category: "irreversible" },
    getLabelItem: { decision: "allow", category: "standard_read" },
    getItem: { decision: "allow", category: "standard_read" },
    send: { decision: "allow", inspect: (req) => inspectSpy(req) },
    plain: { decision: "allow" },
  };

  function hardArgs(ctx: UpstreamCtx, fetchImpl?: typeof fetch) {
    const fetchSpy = fetchImpl ? vi.fn(fetchImpl) : makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy);
    const audit = captureAudit();
    const elicitInput = vi.fn(async () => ({ action: "accept", content: {} }));
    const putFile = vi.fn(async () => ({
      ok: true as const, file_handle: "fh", token: "t", fetch_url: "https://x/f", expires_at: 1, byte_length: 1,
    }));
    return {
      fetchSpy,
      audit,
      elicitInput,
      putFile,
      args: {
        ctx,
        spec: HARD_SPEC,
        surfaceReview: HARD_SR,
        apiBaseUrl: "https://api.example.com",
        deploymentName: "test",
        props: { refreshToken: "RT-1", userId: "test-user" },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        server: { getClientCapabilities: () => ({ elicitation: {} }), elicitInput } as any,
        env: {} as { ALLOW_PII_IN_LOGS?: string },
        audit: {},
        oauth: {
          refreshTokenAccessor: (p: Record<string, unknown>) => p.refreshToken as string,
          userIdAccessor: (p: Record<string, unknown>) => p.userId as string | undefined,
          broker: makeFakeBroker(),
        },
        putFile,
      },
    };
  }

  function upstreamCalls(fetchSpy: ReturnType<typeof vi.fn>) {
    return fetchSpy.mock.calls.filter((c) => !String(c[0]).includes("/token"));
  }

  function sentBody(fetchSpy: ReturnType<typeof vi.fn>): string {
    const call = upstreamCalls(fetchSpy)[0]!;
    const body = (call[1] as RequestInit).body;
    return typeof body === "string" ? body : new TextDecoder().decode(body as Uint8Array);
  }

  describe("unsafe path segments are refused before anything else (F-1, F-6)", () => {
    const UNSAFE_PATHS = [
      "/things/..",
      "/things/.",
      "/things/%2e%2E",
      "/things/a\\b",
      "/things/a?trash=true",
      "/things/a#frag",
      "/things/a%2Fb",
      "/things/a%00b",
      "/things/a\tb",
      "/things/100%",
      "/items/labels/..\\things\\abc",
    ];
    for (const path of UNSAFE_PATHS) {
      it(`${JSON.stringify(path)} → url_safety audit, no fetch, no token mint, no elicitation`, async () => {
        inspectSpy.mockClear();
        const h = hardArgs({ method: "DELETE", path });
        await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/disallowed segment/);
        expect(h.fetchSpy).not.toHaveBeenCalled(); // token mint goes through fetch too
        expect(h.elicitInput).not.toHaveBeenCalled();
        expect(h.audit.read().at(-1)).toMatchObject({
          decision: "deny",
          category: "url_safety",
          reason: "unsafe-path-segment",
        });
      });
    }
  });

  it("re-resolving the built URL to a different operation → url_safety deny, no fetch (F-1)", async () => {
    const h = hardArgs({ method: "GET", path: "/items/lab%65ls/1" });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/different operation/);
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit.read().at(-1)).toMatchObject({
      decision: "deny",
      category: "url_safety",
      reason: "operation-mismatch-after-url-build",
      operationId: "getItem",
    });
  });

  it("the fetch URL carries the template-built, percent-encoded wire path", async () => {
    const h = hardArgs({ method: "GET", path: "/things/my file+v2", query: { q: "x" } });
    await handleUpstreamRequest(h.args);
    const url = new URL(String(upstreamCalls(h.fetchSpy)[0]![0]));
    expect(url.pathname).toBe("/things/my%20file%2Bv2");
    expect(url.searchParams.get("q")).toBe("x");

    const h2 = hardArgs({ method: "GET", path: "/things/user%40example.com" });
    await handleUpstreamRequest(h2.args);
    expect(String(upstreamCalls(h2.fetchSpy)[0]![0])).toBe("https://api.example.com/things/user%40example.com");
  });

  describe("inspected raw JSON is sent canonically (F-7)", () => {
    it("duplicate keys: the inspector's view (last key wins) is what goes upstream", async () => {
      inspectSpy.mockClear();
      const raw = '{"to":"evil@attacker","to":"ok@allow"}';
      const h = hardArgs({
        method: "POST", path: "/send",
        bodyBase64: Buffer.from(raw, "utf8").toString("base64"),
        contentType: "application/json",
      });
      await handleUpstreamRequest(h.args);
      const seen = (inspectSpy.mock.calls[0]![0] as { body: unknown }).body;
      expect(seen).toEqual({ to: "ok@allow" });
      expect(sentBody(h.fetchSpy)).toBe(JSON.stringify(seen));
      expect(sentBody(h.fetchSpy)).not.toContain("evil");
      const headers = (upstreamCalls(h.fetchSpy)[0]![1] as RequestInit).headers as Record<string, string>;
      expect(headers["content-type"]).toBe("application/json");
    });

    it("BOM-prefixed bytes go out as the BOM-less canonical JSON", async () => {
      inspectSpy.mockClear();
      const raw = '﻿{"to":"ok@allow"}';
      const h = hardArgs({
        method: "POST", path: "/send",
        bodyBase64: Buffer.from(raw, "utf8").toString("base64"),
        contentType: "application/json; charset=utf-8",
      });
      await handleUpstreamRequest(h.args);
      expect(sentBody(h.fetchSpy)).toBe('{"to":"ok@allow"}');
      const headers = (upstreamCalls(h.fetchSpy)[0]![1] as RequestInit).headers as Record<string, string>;
      expect(headers["content-type"]).toBe("application/json; charset=utf-8");
    });

    it("non-inspected operations still send raw JSON bytes verbatim", async () => {
      const raw = '{"a":1,"a":2}';
      const h = hardArgs({
        method: "POST", path: "/plain",
        bodyBase64: Buffer.from(raw, "utf8").toString("base64"),
        contentType: "application/json",
      });
      await handleUpstreamRequest(h.args);
      expect(sentBody(h.fetchSpy)).toBe(raw);
    });
  });

  describe("multipart header injection is refused at entry (F-11)", () => {
    const CASES: Array<[string, Record<string, string>]> = [
      ["name CRLF", { name: 'f"\r\nX-Injected: 1' }],
      ["name LF", { name: "f\nx" }],
      ["filename CR", { name: "f", filename: "a.pdf\rX: 1" }],
      ["filename NUL", { name: "f", filename: "a\0.pdf" }],
      ["contentType CRLF", { name: "f", contentType: "text/plain\r\n\r\n--boundary" }],
    ];
    for (const [label, part] of CASES) {
      it(`${label} → malformed audit + ToolError, no fetch`, async () => {
        const h = hardArgs({ method: "POST", path: "/plain", multipart: [{ value: "v", ...part } as never] });
        await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/may not contain CR, LF or NUL/);
        expect(h.fetchSpy).not.toHaveBeenCalled();
        expect(h.audit.read().at(-1)).toMatchObject({
          decision: "deny",
          category: "malformed",
          reason: "multipart-header-injection",
        });
      });
    }
  });

  describe("malformed multipart parts are refused at entry (F-11)", () => {
    // The sandbox RPC carries arbitrary JSON: a non-string field would be
    // stringified into the part header (an array `contentType` smuggles CRLF
    // past a string-only check) or throw a raw TypeError after inspection.
    const CASES: Array<[string, unknown, RegExp]> = [
      [
        "array contentType carrying CRLF",
        { name: "file", filename: "a.txt", contentType: ["text/plain\r\nX-Injected: yes"], value: "hi" },
        /multipart part 0: `contentType` must be a string when present/,
      ],
      ["number name", { name: 42, value: "hi" }, /multipart part 0: `name` must be a non-empty string/],
      ["missing name", { value: "hi" }, /multipart part 0: `name` must be a non-empty string/],
      ["empty name", { name: "", value: "hi" }, /multipart part 0: `name` must be a non-empty string/],
      [
        "array filename",
        { name: "file", filename: ["a\r\nX: 1"], value: "hi" },
        /multipart part 0: `filename` must be a string when present/,
      ],
      ["object filename", { name: "file", filename: { a: 1 }, value: "hi" }, /`filename` must be a string when present/],
      ["number value", { name: "f", value: 7 }, /multipart part 0: `value` must be a string when present/],
      ["array bodyBase64", { name: "f", bodyBase64: ["aGk="] }, /`bodyBase64` must be a string when present/],
      ["null part", null, /multipart part 0: must be an object/],
      ["string part", "name=f", /multipart part 0: must be an object/],
      ["array part", [{ name: "f", value: "v" }], /multipart part 0: must be an object/],
    ];
    for (const [label, part, message] of CASES) {
      it(`${label} → malformed audit + ToolError, no fetch`, async () => {
        const h = hardArgs({ method: "POST", path: "/plain", multipart: [part as never] });
        const err = await handleUpstreamRequest(h.args).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(ToolError);
        expect((err as Error).message).toMatch(message);
        expect((err as Error).message).not.toContain("X-Injected");
        expect(h.fetchSpy).not.toHaveBeenCalled();
        expect(h.audit.read().at(-1)).toMatchObject({
          decision: "deny",
          category: "malformed",
          reason: "multipart-part-malformed",
        });
      });
    }

    it("names the offending part index", async () => {
      const h = hardArgs({
        method: "POST",
        path: "/plain",
        multipart: [{ name: "ok", value: "v" }, { name: "f", contentType: ["x"] as never, value: "v" }],
      });
      await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/multipart part 1: `contentType`/);
      expect(h.fetchSpy).not.toHaveBeenCalled();
    });
  });

  describe("typed arrays in body, query or multipart are refused at entry (F-19)", () => {
    const CASES: Array<[string, Partial<UpstreamCtx>]> = [
      ["body Uint8Array", { body: new Uint8Array([104, 105]) }],
      ["body ArrayBuffer", { body: new ArrayBuffer(2) }],
      ["nested body view", { body: { raw: [{ x: new DataView(new ArrayBuffer(1)) }] } }],
      ["rawBody Uint8Array", { body: new Uint8Array([1]), rawBody: true }],
      ["query value", { query: { q: new Uint8Array([1]) as never } }],
      ["multipart value", { multipart: [{ name: "f", value: new Uint8Array([1]) as never }] }],
    ];
    for (const [label, extra] of CASES) {
      it(`${label} → malformed audit + ToolError, no fetch`, async () => {
        const h = hardArgs({ method: "POST", path: "/plain", ...extra });
        await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
          "Binary values (Uint8Array/ArrayBuffer) are not accepted in body, query or multipart; send bytes with bodyBase64 or multipart[].bodyBase64",
        );
        expect(h.fetchSpy).not.toHaveBeenCalled();
        expect(h.audit.read().at(-1)).toMatchObject({
          decision: "deny",
          category: "malformed",
          reason: "binary-value-in-request",
        });
      });
    }

    it("a cyclic plain body does not hang the binary walker", async () => {
      const cyclic: Record<string, unknown> = { a: 1 };
      cyclic.self = cyclic;
      const h = hardArgs({ method: "GET", path: "/things/x", body: cyclic });
      // Passes the walker; fails later only at JSON.stringify (not our concern here).
      await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/circular/i);
      expect(h.audit.read().some((l) => l.reason === "binary-value-in-request")).toBe(false);
    });
  });

  it("non-string method or path → malformed audit + ToolError, no fetch (F-24)", async () => {
    for (const ctx of [
      { method: 42, path: "/things/x" },
      { method: "GET", path: ["/things/x"] },
      { method: undefined, path: undefined },
    ]) {
      const h = hardArgs(ctx as unknown as UpstreamCtx);
      await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
        "codemode.request needs string `method` and `path`",
      );
      expect(h.fetchSpy).not.toHaveBeenCalled();
      expect(h.audit.read().at(-1)).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "invalid-method-or-path",
      });
    }
  });

  describe("redirects are not followed (F-17)", () => {
    function upstream(res: () => Response): typeof fetch {
      return async (url: RequestInfo | URL) => {
        const u = typeof url === "string" ? url : url.toString();
        if (u.includes("/token")) {
          return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
        }
        return res();
      };
    }

    it("302 → upstream_redirect envelope, redirect: manual, Location not echoed, no staging", async () => {
      const h = hardArgs(
        { method: "GET", path: "/things/x", returnAs: "stage" },
        upstream(() => new Response("moved", {
          status: 302,
          headers: { location: "https://evil.example/steal?code=SECRET" },
        })),
      );
      const res = (await handleUpstreamRequest(h.args)) as Record<string, unknown>;
      expect(res).toEqual({
        success: false,
        status: 302,
        result: { error: "upstream_redirect" },
        errors: [{ code: 302, message: "Upstream answered with a redirect (HTTP 302); redirects are not followed" }],
      });
      expect(JSON.stringify(res)).not.toContain("evil.example");
      expect(h.putFile).not.toHaveBeenCalled();
      const calls = upstreamCalls(h.fetchSpy);
      expect(calls).toHaveLength(1);
      expect((calls[0]![1] as RequestInit).redirect).toBe("manual");
      expect(h.audit.read().at(-1)).toMatchObject({ decision: "allow", upstreamStatus: 302, operationId: "getThing" });
    });

    it("every outbound fetch carries redirect: manual", async () => {
      const h = hardArgs({ method: "GET", path: "/things/x" });
      await handleUpstreamRequest(h.args);
      expect((upstreamCalls(h.fetchSpy)[0]![1] as RequestInit).redirect).toBe("manual");
    });

    it("304 passes through as a normal non-2xx envelope", async () => {
      const h = hardArgs(
        { method: "GET", path: "/things/x" },
        upstream(() => new Response(null, { status: 304 })),
      );
      const res = (await handleUpstreamRequest(h.args)) as Record<string, unknown>;
      expect(res.success).toBe(false);
      expect(res.status).toBe(304);
      expect(res.result).not.toEqual({ error: "upstream_redirect" });
    });
  });
});

describe("approval-only operations are judged on the payload that is sent", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  const APPROVE_SPEC: OpenApiSpec = {
    openapi: "3.0.0",
    info: { title: "T", version: "1" },
    servers: [{ url: "https://api.example.com" }],
    paths: {
      "/payruns/{id}": {
        post: {
          operationId: "updatePayRun",
          requestBody: {
            content: { "application/json": { schema: { type: "object", properties: { Amount: { type: "number" } } } } },
          },
          responses: { "200": { description: "OK" } },
        },
      },
      "/calendars/{calendarId}/events": {
        get: { operationId: "listEvents", responses: { "200": { description: "OK" } } },
      },
    },
    components: { schemas: {} },
  };
  const APPROVE_SR: SurfaceReview = {
    updatePayRun: { decision: "elicit", category: "financial_legal" },
    listEvents: { decision: "allow", category: "standard_read" },
  };

  function approveArgs(ctx: UpstreamCtx) {
    const fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy);
    const audit = captureAudit();
    // Accept with a value of the right type for every requested field.
    const elicitInput = vi.fn(async (params: unknown) => {
      const props = (params as { requestedSchema: { properties: Record<string, { type: string }> } })
        .requestedSchema.properties;
      const content: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(props)) {
        content[k] = v.type === "number" ? 0 : v.type === "boolean" ? true : "";
      }
      return { action: "accept", content };
    });
    return {
      fetchSpy,
      audit,
      elicitInput,
      args: {
        ctx,
        spec: APPROVE_SPEC,
        surfaceReview: APPROVE_SR,
        apiBaseUrl: "https://api.example.com",
        deploymentName: "test",
        props: { refreshToken: "RT-1", userId: "test-user" },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        server: { server: { getClientCapabilities: () => ({ elicitation: {} }), elicitInput } } as any,
        env: {} as { ALLOW_PII_IN_LOGS?: string },
        audit: {},
        oauth: {
          refreshTokenAccessor: (p: Record<string, unknown>) => p.refreshToken as string,
          userIdAccessor: (p: Record<string, unknown>) => p.userId as string | undefined,
          broker: makeFakeBroker(),
        },
      },
    };
  }

  function upstreamInit(fetchSpy: ReturnType<typeof vi.fn>): RequestInit {
    const call = fetchSpy.mock.calls.find((c) => !String(c[0]).includes("/token"))!;
    return call[1] as RequestInit;
  }

  it("a body + bodyBase64 decoy is refused before the dialog, nothing is sent", async () => {
    const real = JSON.stringify({ PayRuns: [{ PayRunStatus: "POSTED", Amount: 999999 }, { Amount: 5 }] });
    const h = approveArgs({
      method: "POST",
      path: "/payruns/1",
      body: { PayRuns: [{ Amount: 1 }] },
      bodyBase64: Buffer.from(real, "utf8").toString("base64"),
      contentType: "application/json",
    });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/denied by surface review/);
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit.read().at(-1)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "multiple-body-channels",
      operationId: "updatePayRun",
    });
  });

  it("raw JSON is shown parsed in the dialog and sent as that same canonical document", async () => {
    const raw = '{"Amount":1,"Amount":250}';
    const h = approveArgs({
      method: "POST",
      path: "/payruns/1",
      bodyBase64: Buffer.from(raw, "utf8").toString("base64"),
      contentType: " application/json",
    });
    await handleUpstreamRequest(h.args);
    const params = h.elicitInput.mock.calls[0]![0] as { requestedSchema: { properties: Record<string, unknown> } };
    expect(Object.keys(params.requestedSchema.properties)).toContain("Amount");
    const init = upstreamInit(h.fetchSpy);
    expect(init.body).toBe('{"Amount":250}');
    expect((init.headers as Record<string, string>)["content-type"]).toBe("application/json");
  });

  it("an uninspected raw non-JSON payload is approved as opaque, never rendered as an empty request", async () => {
    const h = approveArgs({
      method: "POST",
      path: "/payruns/1",
      bodyBase64: Buffer.from("<PayRuns/>", "utf8").toString("base64"),
      contentType: "application/xml",
    });
    await handleUpstreamRequest(h.args);
    const params = h.elicitInput.mock.calls[0]![0] as { message: string; requestedSchema: { properties: Record<string, unknown> } };
    expect(params.message).toMatch(/application\/xml, 10 bytes\) cannot be shown/);
    expect(Object.keys(params.requestedSchema.properties)).toEqual(["confirm"]);
  });

  it("JSON-typed bytes that do not parse are refused before the dialog", async () => {
    const h = approveArgs({
      method: "POST",
      path: "/payruns/1",
      bodyBase64: Buffer.from('{"Amount":', "utf8").toString("base64"),
      contentType: "text/json",
    });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/denied by surface review/);
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.audit.read().at(-1)).toMatchObject({ reason: "unparseable-json-body" });
  });

  it("a non-string contentType is refused at entry with an audit line", async () => {
    const h = approveArgs({
      method: "POST",
      path: "/payruns/1",
      body: { Amount: 1 },
      contentType: ["application/json"] as unknown as string,
    });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/contentType` must be a string/);
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit.read().at(-1)).toMatchObject({ decision: "deny", reason: "invalid-content-type" });
  });

  it("an encoded # or ? inside a path value reaches the upstream re-encoded (F-1 regression)", async () => {
    const h = approveArgs({
      method: "GET",
      path: "/calendars/en.australian%23holiday%40group.v.calendar.google.com/events",
    });
    await handleUpstreamRequest(h.args);
    const url = String(h.fetchSpy.mock.calls.find((c) => !String(c[0]).includes("/token"))![0]);
    expect(url).toBe("https://api.example.com/calendars/en.australian%23holiday%40group.v.calendar.google.com/events");
    expect(new URL(url).hash).toBe("");
    expect(new URL(url).search).toBe("");
  });
});
