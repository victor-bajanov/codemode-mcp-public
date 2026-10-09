import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleUpstreamRequest, getOrRefreshAccessToken } from "@local/scaffold";
import { spec, surfaceReview } from "@local/providers-optical";

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
        rotation: "rotating",
        refreshToken: args.refreshToken,
        clientId: "CID",
        clientSecret: "CSEC",
        tokenUrl: "https://scheduler.example.com/oauth/token",
      });
    },
  };
}

const baseProps = {
  refreshToken: "RT-fake",
  userId: "operator",
  email: "operator@example.com",
};

const baseScaffoldArgs = {
  spec,
  surfaceReview,
  props: baseProps,
  apiBaseUrl: "https://scheduler.example.com",
  deploymentName: "optical-test",
  server: {} as never,
  oauth: {
    refreshTokenAccessor: (p: typeof baseProps) => p.refreshToken,
    userIdAccessor: (p: typeof baseProps) => p.userId,
    broker: makeFakeBroker(),
  },
  audit: {},
  env: {} as { ALLOW_PII_IN_LOGS?: string },
};

describe("optical adversarial: surface-review enforcement", () => {
  beforeEach(() => {
    // Default mock: any token-exchange call returns a fresh pair; any API call returns 200 {}.
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/oauth/token")) {
        return new Response(
          JSON.stringify({
            access_token: "AT-fake",
            refresh_token: "RT-fake-rotated",
            expires_in: 3600,
            token_type: "Bearer",
            scope: "read write",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("denies unrecognised paths before any fetch", async () => {
    await expect(
      handleUpstreamRequest({
        ...baseScaffoldArgs,
        ctx: { method: "GET", path: "/v1/not-a-real-endpoint" },
      }),
    ).rejects.toThrow(/No operation found/);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("allows listTasks through to the upstream Bearer-protected endpoint", async () => {
    await handleUpstreamRequest({
      ...baseScaffoldArgs,
      ctx: { method: "GET", path: "/v1/tasks" },
    });
    // The first fetch is the /oauth/token exchange (fake broker mints on first use),
    // the second is the upstream /v1/tasks call.
    const calls = (globalThis.fetch as unknown as { mock: { calls: [string | URL][] } }).mock.calls;
    const apiCall = calls.find(([u]) => String(u).includes("/v1/tasks"));
    expect(apiCall, "expected an outbound /v1/tasks call").toBeDefined();
  });

  it("sends with redirect: manual and reports an upstream 3xx instead of following it (F-17)", async () => {
    (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/oauth/token")) {
        return new Response(
          JSON.stringify({ access_token: "AT-fake", refresh_token: "RT-fake-rotated-2", expires_in: 3600, token_type: "Bearer" }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(null, { status: 302, headers: { location: "https://elsewhere.example/v1/tasks" } });
    });
    const res = (await handleUpstreamRequest({
      ...baseScaffoldArgs,
      props: { ...baseProps, refreshToken: "RT-fake-redirect" },
      ctx: { method: "GET", path: "/v1/tasks" },
    })) as { success: boolean; status: number; result: unknown };
    expect(res).toMatchObject({ success: false, status: 302, result: { error: "upstream_redirect" } });
    const calls = (globalThis.fetch as unknown as { mock: { calls: [string | URL, RequestInit?][] } }).mock.calls;
    const apiCalls = calls.filter(([u]) => String(u).includes("/v1/tasks"));
    expect(apiCalls).toHaveLength(1);
    expect(apiCalls[0]![1]?.redirect).toBe("manual");
  });

  it("refuses dot-segment paths before any fetch (F-1)", async () => {
    for (const path of ["/v1/tasks/..", "/v1/polls/%2e%2e/cancel", "/v1/tasks/.%2e"]) {
      await expect(
        handleUpstreamRequest({ ...baseScaffoldArgs, ctx: { method: "DELETE", path } }),
      ).rejects.toThrow(/disallowed segment/);
    }
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
