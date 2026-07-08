import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleUpstreamRequest, getOrRefreshAccessToken } from "@local/scaffold";
import { spec, surfaceReview } from "@local/providers-gmail";

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
        tokenUrl: "https://oauth2.googleapis.com/token",
      });
    },
  };
}

const baseProps = {
  refreshToken: "RT-fake",
  googleUserId: "u",
  userId: "u",
  email: "u@example.com",
  name: "u",
};

const baseScaffoldArgs = {
  spec,
  surfaceReview,
  props: baseProps,
  apiBaseUrl: "https://gmail.googleapis.com",
  deploymentName: "gmail-test",
  server: {} as never,
  oauth: {
    refreshTokenAccessor: (p: typeof baseProps) => p.refreshToken,
    userIdAccessor: (p: typeof baseProps) => p.userId,
    broker: makeFakeBroker(),
  },
  audit: {},
  env: {} as { ALLOW_PII_IN_LOGS?: string },
};

describe("adversarial: surface-review enforcement", () => {
  beforeEach(() => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("nope", { status: 500 }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("denies unrecognised paths before any fetch", async () => {
    await expect(
      handleUpstreamRequest({
        ...baseScaffoldArgs,
        ctx: { method: "GET", path: "/totally-unknown" },
      }),
    ).rejects.toThrow(/No operation found/);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("denies Tier 3 capability-escalation ops before any fetch", async () => {
    await expect(
      handleUpstreamRequest({
        ...baseScaffoldArgs,
        ctx: { method: "POST", path: "/gmail/v1/users/me/settings/delegates" },
      }),
    ).rejects.toThrow(/denied by surface review/);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("Tier 2 (elicit) ops route through runElicitation; fail with transport-error when server stub lacks elicitInput", async () => {
    // messages.send is now `allow + inspect` (Task 9). Use messages.import,
    // which is still `elicit`, to cover the elicit path via runElicitation.
    await expect(
      handleUpstreamRequest({
        ...baseScaffoldArgs,
        ctx: { method: "POST", path: "/gmail/v1/users/me/messages/import" },
      }),
    ).rejects.toThrow(/requires user approval/);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("routes messages.batchDelete through runElicitation; audit decision=elicit, elicitationOutcome=transport-error", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await expect(
      handleUpstreamRequest({
        ...baseScaffoldArgs,
        ctx: {
          method: "POST",
          path: "/gmail/v1/users/me/messages/batchDelete",
          body: { ids: ["m1", "m2"] },
        },
      }),
    ).rejects.toThrow(/requires user approval/);
    expect(globalThis.fetch).not.toHaveBeenCalled();

    const auditLines = logSpy.mock.calls
      .map((c) => c[0])
      .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
      .map((s) => JSON.parse(s.slice("AUDIT ".length)));
    const last = auditLines.find((l: { operationId?: string }) => l.operationId === "gmail.users.messages.batchDelete");
    expect(last).toMatchObject({
      decision: "elicit",
      elicitationOutcome: "transport-error",
      operationId: "gmail.users.messages.batchDelete",
    });
  });

  it("does not allow path-encoding attacks to escalate to denied operations", async () => {
    await expect(
      handleUpstreamRequest({
        ...baseScaffoldArgs,
        ctx: { method: "POST", path: "/gmail/v1/users/me/settings%2Fdelegates" },
      }),
    ).rejects.toThrow();   // either no-match or denied — both acceptable
  });
});

describe("adversarial: bearer token never appears in returned values", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn(async (url: RequestInfo | URL) => {
      const urlStr = typeof url === "string" ? url : url.toString();
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
          JSON.stringify({ access_token: "AT-fake-secret", expires_in: 3600 }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({ messages: [{ id: "abc" }, { id: "def" }] }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("response body does not contain the refresh token, client secret, or access token", async () => {
    // Use unique refreshToken so the module-scoped tokenCache doesn't skip mint flow.
    const uniqueProps = { ...baseProps, refreshToken: "RT-fresh-for-leak-test" };
    const result = await handleUpstreamRequest({
      ...baseScaffoldArgs,
      props: uniqueProps,
      oauth: {
        ...baseScaffoldArgs.oauth,
        refreshTokenAccessor: (p: typeof uniqueProps) => p.refreshToken,
      },
      ctx: { method: "GET", path: "/gmail/v1/users/me/messages" },
    });

    const serialised = JSON.stringify(result);
    expect(serialised).not.toContain(uniqueProps.refreshToken);
    expect(serialised).not.toContain("CSEC");
    expect(serialised).not.toContain("AT-fake-secret");
    expect(serialised).toContain("abc");  // sanity: legitimate response present
  });
});
