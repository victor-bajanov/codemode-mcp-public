// packages/scaffold/src/__tests__/request-handler-rate-limit.test.ts
//
// HandleArgs.readRateLimit: a provider-supplied reader that turns upstream
// rate-limit response headers into an UpstreamRateLimit. The handler puts the
// result on the response envelope (so the MCP client sees the remaining budget
// on every call) and, on a 429, folds the reason + retry delay into
// errors[0].message — the field the envelope contract tells clients to read.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest } from "../request-handler";
import { getOrRefreshAccessToken } from "../refresh";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReview } from "@local/shared";
import type { UpstreamRateLimit } from "../rate-limit";

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
const SR: SurfaceReview = { listWidgets: { decision: "allow", category: "standard_read" } };

function makeFetchSpy(upstream: Response) {
  return vi.fn<typeof fetch>(async (url: RequestInfo | URL) => {
    const u = typeof url === "string" ? url : url.toString();
    if (u.includes("/token")) {
      return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
    }
    return upstream.clone();
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
  props: { refreshToken: "RT-1", userId: "test-user" },
  oauth: {
    refreshTokenAccessor: (p: Record<string, unknown>) => p.refreshToken as string,
    userIdAccessor: (p: Record<string, unknown>) => p.userId as string | undefined,
    broker: makeFakeBroker(),
  },
  audit: {},
  env: {} as { ALLOW_PII_IN_LOGS?: string },
};

/** Stand-in for a provider reader (the real one lives in the Xero provider). */
const reader = (r: { status: number; headers: Headers }): UpstreamRateLimit | undefined => {
  const remainingHeader = r.headers.get("X-Min-Remaining");
  const remaining = remainingHeader === null ? undefined : { minute: Number(remainingHeader) };
  if (r.status !== 429) return remaining ? { remaining } : undefined;
  return {
    problem: "minute",
    limit: "per-minute limit",
    retryAfterSeconds: Number(r.headers.get("Retry-After") ?? 0),
    message: "Xero per-minute limit exceeded — retry after 43s.",
    ...(remaining ? { remaining } : {}),
  };
};

type Envelope = {
  success: boolean;
  status: number;
  result: unknown;
  errors: Array<{ code: number; message: string }>;
  rateLimit?: UpstreamRateLimit;
};

describe("handleUpstreamRequest — upstream rate limits", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("puts the reader's result on a successful envelope", async () => {
    vi.stubGlobal("fetch", makeFetchSpy(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json", "X-Min-Remaining": "57" },
    })));
    captureAudit();

    const env = (await handleUpstreamRequest({ ...baseArgs, readRateLimit: reader })) as Envelope;

    expect(env.success).toBe(true);
    expect(env.rateLimit).toEqual({ remaining: { minute: 57 } });
  });

  it("omits the rateLimit key entirely when no reader is configured (regression)", async () => {
    vi.stubGlobal("fetch", makeFetchSpy(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json", "X-Min-Remaining": "57" },
    })));
    captureAudit();

    const env = (await handleUpstreamRequest({ ...baseArgs })) as Envelope;

    expect(Object.keys(env).sort()).toEqual(["errors", "result", "status", "success"]);
  });

  it("omits the rateLimit key when the reader returns undefined", async () => {
    vi.stubGlobal("fetch", makeFetchSpy(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })));
    captureAudit();

    const env = (await handleUpstreamRequest({ ...baseArgs, readRateLimit: reader })) as Envelope;

    expect("rateLimit" in env).toBe(false);
  });

  it("429: the reason and retry delay lead errors[0].message, upstream body kept", async () => {
    vi.stubGlobal("fetch", makeFetchSpy(new Response("oops, rate limit exceeded", {
      status: 429,
      headers: { "Retry-After": "43", "X-Min-Remaining": "0" },
    })));
    captureAudit();

    const env = (await handleUpstreamRequest({ ...baseArgs, readRateLimit: reader })) as Envelope;

    expect(env.success).toBe(false);
    expect(env.status).toBe(429);
    expect(env.rateLimit).toMatchObject({ problem: "minute", retryAfterSeconds: 43 });
    expect(env.errors).toHaveLength(1);
    expect(env.errors[0]!.code).toBe(429);
    expect(env.errors[0]!.message).toContain("Xero per-minute limit exceeded — retry after 43s.");
    expect(env.errors[0]!.message).toContain("oops, rate limit exceeded");
  });

  it("429 without a reader: error message is the upstream body, unchanged (regression)", async () => {
    vi.stubGlobal("fetch", makeFetchSpy(new Response("oops", { status: 429 })));
    captureAudit();

    const env = (await handleUpstreamRequest({ ...baseArgs })) as Envelope;

    expect(env.errors[0]!.message).toBe("oops");
  });

  it("non-429 errors keep the plain upstream body as the message", async () => {
    vi.stubGlobal("fetch", makeFetchSpy(new Response("not found", {
      status: 404,
      headers: { "X-Min-Remaining": "57" },
    })));
    captureAudit();

    const env = (await handleUpstreamRequest({ ...baseArgs, readRateLimit: reader })) as Envelope;

    expect(env.errors[0]!.message).toBe("not found");
    expect(env.rateLimit).toEqual({ remaining: { minute: 57 } });
  });

  it("a throwing reader never breaks the response envelope", async () => {
    vi.stubGlobal("fetch", makeFetchSpy(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })));
    captureAudit();

    const env = (await handleUpstreamRequest({
      ...baseArgs,
      readRateLimit: () => { throw new Error("bad reader"); },
    })) as Envelope;

    expect(env.success).toBe(true);
    expect("rateLimit" in env).toBe(false);
  });

  it("stage-mode envelopes carry the rate limit too", async () => {
    vi.stubGlobal("fetch", makeFetchSpy(new Response(new Uint8Array([1, 2, 3]), {
      status: 200,
      headers: { "content-type": "application/pdf", "X-Min-Remaining": "12" },
    })));
    captureAudit();

    const env = (await handleUpstreamRequest({
      ...baseArgs,
      ctx: { method: "GET", path: "/widgets", returnAs: "stage" },
      readRateLimit: reader,
      putFile: async () => ({
        ok: true as const,
        file_handle: "fh_x",
        token: "stg_y",
        fetch_url: "https://x.test/staging/fetch/fh_x",
        expires_at: 999,
        byte_length: 3,
      }),
    })) as Envelope;

    expect(env.success).toBe(true);
    expect(env.rateLimit).toEqual({ remaining: { minute: 12 } });
  });

  it("audits the rate-limit reason on a 429", async () => {
    vi.stubGlobal("fetch", makeFetchSpy(new Response("slow down", {
      status: 429,
      headers: { "Retry-After": "43", "X-Min-Remaining": "0" },
    })));
    const audit = captureAudit();

    await handleUpstreamRequest({ ...baseArgs, readRateLimit: reader });

    const entry = audit.read().find((e) => e.upstreamStatus === 429)!;
    expect(entry.rateLimit).toMatchObject({ problem: "minute", retryAfterSeconds: 43 });
  });

  it("does not audit rate-limit counters on ordinary successful calls", async () => {
    vi.stubGlobal("fetch", makeFetchSpy(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json", "X-Min-Remaining": "57" },
    })));
    const audit = captureAudit();

    await handleUpstreamRequest({ ...baseArgs, readRateLimit: reader });

    const entry = audit.read().find((e) => e.upstreamStatus === 200)!;
    expect(entry.rateLimit).toBeUndefined();
  });
});
