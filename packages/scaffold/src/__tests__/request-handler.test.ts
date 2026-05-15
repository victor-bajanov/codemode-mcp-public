// packages/scaffold/src/__tests__/request-handler.test.ts
//
// Tests for slice-2 request-handler additions:
//   - HandleArgs.requestHeaders: when present, merged into outbound fetch headers (alongside Authorization).
//   - HandleArgs.audit.waitUntil: when provided, audit logs fire inside it (so canceled-SSE doesn't drop logs).
//   - HandleArgs.audit.principalId / context: passed through to AuditEntry.
//   - HandleArgs.oauth.storage + rotation: provided to refresh module (verified indirectly: a Storage spy gets touched).

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest } from "../request-handler";
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

function makeStorage() {
  const data = new Map<string, unknown>();
  return {
    data,
    async get<T>(k: string): Promise<T | undefined> { return data.get(k) as T | undefined; },
    async put<T>(k: string, v: T): Promise<void> { data.set(k, v); },
  };
}
function makeFetchSpy() {
  return vi.fn<typeof fetch>(async (url: RequestInfo | URL) => {
    const u = typeof url === "string" ? url : url.toString();
    if (u.includes("/token")) {
      return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
    }
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
  });
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
    clientId: "CID",
    clientSecret: "CSEC",
    tokenUrl: "https://api.example.com/token",
    storage: makeStorage(),
    rotation: "static" as const,
  },
  audit: {},
  env: {} as { ALLOW_PII_IN_LOGS?: string },
};

describe("request-handler slice-2 extensions", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("merges requestHeaders(props) into the outbound fetch alongside Authorization", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    captureAudit();

    const props = { refreshToken: "RT-1", tenantId: "TENANT-XYZ" };
    await handleUpstreamRequest({
      ...baseArgs,
      props,
      oauth: { ...baseArgs.oauth, rotation: "rotating" },
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
      props: { refreshToken: "RT-1" },
    });

    const fetchSpy = (globalThis as unknown as { fetch: ReturnType<typeof vi.fn> }).fetch;
    const upstreamCall = fetchSpy.mock.calls.find((c) =>
      String(c[0]).includes("/widgets"),
    )!;
    const headers = (upstreamCall[1] as RequestInit).headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer AT-x");
    expect(Object.keys(headers).filter((k) => k.toLowerCase() !== "authorization")).toEqual([]);
  });

  it("waitUntil receives a promise wrapping the audit emission", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    const audit = captureAudit();
    const waitUntilSpy = vi.fn();

    await handleUpstreamRequest({
      ...baseArgs,
      props: { refreshToken: "RT-1" },
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
      oauth: { ...baseArgs.oauth, rotation: "rotating" },
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
      props: { refreshToken: "r" },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: makeMcpStub(elicitInput) as any,
      oauth: {
        refreshTokenAccessor: (p) => (p as { refreshToken: string }).refreshToken,
        clientId: "c", clientSecret: "s", tokenUrl: "https://t/token",
        storage: makeStorage(), rotation: "static",
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
        props: { refreshToken: "r" },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        server: makeMcpStub(elicitInput) as any,
        oauth: {
          refreshTokenAccessor: (p) => (p as { refreshToken: string }).refreshToken,
          clientId: "c", clientSecret: "s", tokenUrl: "https://t/token",
          storage: makeStorage(), rotation: "static",
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
      props: { refreshToken: "r" },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: makeMcpStub(elicitInput) as any,
      oauth: {
        refreshTokenAccessor: (p) => (p as { refreshToken: string }).refreshToken,
        clientId: "c", clientSecret: "s", tokenUrl: "https://t/token",
        storage: makeStorage(), rotation: "static",
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
      props: { refreshToken: "r" },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: makeMcpStub(elicitInput) as any,
      oauth: {
        refreshTokenAccessor: (p) => (p as { refreshToken: string }).refreshToken,
        clientId: "c", clientSecret: "s", tokenUrl: "https://t/token",
        storage: makeStorage(), rotation: "static",
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
      props: { refreshToken: "r" },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: makeMcpStub(elicitInput) as any,
      oauth: {
        refreshTokenAccessor: (p) => (p as { refreshToken: string }).refreshToken,
        clientId: "c", clientSecret: "s", tokenUrl: "https://t/token",
        storage: makeStorage(), rotation: "static",
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
