// SurfaceReviewEntry.normalizeBody: provider-declared, best-effort JSON-body
// repair (e.g. Gmail rewriting a mojibake'd Subject) applied BEFORE the
// effective payload is resolved — so the inspector and the upstream fetch see
// the same normalized body. Fail-open: a normalizer that throws or returns
// undefined leaves the payload untouched.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest } from "../request-handler";
import { getOrRefreshAccessToken } from "../refresh";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { InspectRequest, SurfaceReview } from "@local/shared";

const SPEC: OpenApiSpec = {
  openapi: "3.0.0",
  info: { title: "Test", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/send": {
      post: { operationId: "sendThing", responses: { "200": { description: "OK" } } },
    },
  },
  components: { schemas: {} },
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

function argsWith(surfaceReview: SurfaceReview, body: unknown) {
  return {
    ctx: { method: "POST" as const, path: "/send", body },
    spec: SPEC,
    surfaceReview,
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
}

function upstreamBody(): unknown {
  const fetchSpy = (globalThis as unknown as { fetch: ReturnType<typeof vi.fn> }).fetch;
  const call = fetchSpy.mock.calls.find((c) => String(c[0]).includes("/send"))!;
  return JSON.parse((call[1] as RequestInit).body as string);
}

describe("SurfaceReviewEntry.normalizeBody", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("sends the normalized body upstream, and the inspector sees the same bytes", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    vi.spyOn(console, "log").mockImplementation(() => {});
    const seen: unknown[] = [];
    const sr: SurfaceReview = {
      sendThing: {
        decision: "allow",
        normalizeBody: (body) => ({ ...(body as Record<string, unknown>), subject: "repaired" }),
        inspect: (req: InspectRequest) => {
          seen.push(req.body);
          return { decision: "allow" };
        },
      },
    };
    await handleUpstreamRequest(argsWith(sr, { subject: "m0jibake", to: "a@b.com" }));
    expect(seen).toEqual([{ subject: "repaired", to: "a@b.com" }]);
    expect(upstreamBody()).toEqual({ subject: "repaired", to: "a@b.com" });
  });

  it("returning undefined leaves the payload untouched", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    vi.spyOn(console, "log").mockImplementation(() => {});
    const sr: SurfaceReview = {
      sendThing: { decision: "allow", normalizeBody: () => undefined },
    };
    await handleUpstreamRequest(argsWith(sr, { subject: "as-is" }));
    expect(upstreamBody()).toEqual({ subject: "as-is" });
  });

  it("a throwing normalizer is fail-open: original payload is sent", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    vi.spyOn(console, "log").mockImplementation(() => {});
    const sr: SurfaceReview = {
      sendThing: {
        decision: "allow",
        normalizeBody: () => {
          throw new Error("normalizer bug");
        },
      },
    };
    await handleUpstreamRequest(argsWith(sr, { subject: "survives" }));
    expect(upstreamBody()).toEqual({ subject: "survives" });
  });

  it("the normalized body handed to the inspector is frozen", async () => {
    vi.stubGlobal("fetch", makeFetchSpy());
    vi.spyOn(console, "log").mockImplementation(() => {});
    let frozen = false;
    const sr: SurfaceReview = {
      sendThing: {
        decision: "allow",
        normalizeBody: () => ({ subject: "repaired" }),
        inspect: (req: InspectRequest) => {
          frozen = Object.isFrozen(req.body);
          return { decision: "allow" };
        },
      },
    };
    await handleUpstreamRequest(argsWith(sr, { subject: "x" }));
    expect(frozen).toBe(true);
  });
});
