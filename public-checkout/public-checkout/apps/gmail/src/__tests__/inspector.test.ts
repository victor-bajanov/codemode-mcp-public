import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, getOrRefreshAccessToken } from "@local/scaffold";
import { spec } from "@local/providers-gmail";
import type { SurfaceReview } from "@local/shared";

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

function makeArgs<R extends SurfaceReview>(opts: {
  surfaceReview: R;
  refreshToken?: string;
}) {
  const props = { ...baseProps, refreshToken: opts.refreshToken ?? baseProps.refreshToken };
  return {
    spec,
    surfaceReview: opts.surfaceReview,
    props,
    apiBaseUrl: "https://gmail.googleapis.com",
    deploymentName: "gmail-test",
    server: {} as never,
    oauth: {
      refreshTokenAccessor: (p: typeof props) => p.refreshToken,
      userIdAccessor: (p: typeof props) => p.userId,
      broker: makeFakeBroker(),
    },
    audit: {},
    env: {} as { ALLOW_PII_IN_LOGS?: string },
  };
}

function makeFetchSpy() {
  return vi.fn(async (url: RequestInfo | URL) => {
    const u = typeof url === "string" ? url : url.toString();
    if (u.includes("oauth2.googleapis.com/token")) {
      return new Response(
        JSON.stringify({ access_token: "AT-x", expires_in: 3600 }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response(
      JSON.stringify({ ok: true, messages: [{ id: "abc" }] }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  });
}

function captureAuditLines(): {
  logSpy: ReturnType<typeof vi.spyOn>;
  read: () => Array<Record<string, unknown>>;
} {
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  const read = () =>
    logSpy.mock.calls
      .map((c) => c[0])
      .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
      .map((s) => JSON.parse(s.slice("AUDIT ".length)) as Record<string, unknown>);
  return { logSpy, read };
}

const TARGET_OP = "gmail.users.messages.list";
const TARGET_CTX = { method: "GET" as const, path: "/gmail/v1/users/me/messages" };

describe("request-handler inspector path", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("static allow + no inspect → fetch happens (regression)", async () => {
    const fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy);

    const surfaceReview: SurfaceReview = {
      [TARGET_OP]: { decision: "allow", category: "standard_read" },
    };

    const result = (await handleUpstreamRequest({
      ...makeArgs({ surfaceReview, refreshToken: "RT-task4-test-1" }),
      ctx: TARGET_CTX,
    })) as { success: boolean };

    expect(result.success).toBe(true);
    const upstreamCalls = fetchSpy.mock.calls.filter((c) => {
      const u = typeof c[0] === "string" ? c[0] : (c[0] as URL).toString();
      return u.includes("gmail.googleapis.com");
    });
    expect(upstreamCalls.length).toBe(1);
  });

  it("static allow + inspect returns allow → fetch happens", async () => {
    const fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy);

    const inspectSpy = vi.fn().mockReturnValue({ decision: "allow" });
    const surfaceReview: SurfaceReview = {
      [TARGET_OP]: { decision: "allow", category: "standard_read", inspect: inspectSpy },
    };

    const result = (await handleUpstreamRequest({
      ...makeArgs({ surfaceReview, refreshToken: "RT-task4-test-2" }),
      ctx: TARGET_CTX,
    })) as { success: boolean };

    expect(inspectSpy).toHaveBeenCalledTimes(1);
    expect(result.success).toBe(true);
    const upstreamCalls = fetchSpy.mock.calls.filter((c) => {
      const u = typeof c[0] === "string" ? c[0] : (c[0] as URL).toString();
      return u.includes("gmail.googleapis.com");
    });
    expect(upstreamCalls.length).toBe(1);
  });

  it("static allow + inspect returns elicit → throws + audit elicit + reason", async () => {
    const { read } = captureAuditLines();
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const inspectSpy = vi.fn().mockReturnValue({
      decision: "elicit",
      reason: "test-elicit-reason",
    });
    const surfaceReview: SurfaceReview = {
      [TARGET_OP]: { decision: "allow", category: "standard_read", inspect: inspectSpy },
    };

    await expect(
      handleUpstreamRequest({
        ...makeArgs({ surfaceReview, refreshToken: "RT-task4-test-3" }),
        ctx: TARGET_CTX,
      }),
    ).rejects.toThrow();

    expect(inspectSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy).not.toHaveBeenCalled();

    const auditForOp = read().filter((l) => l.operationId === TARGET_OP);
    expect(auditForOp.at(-1)).toMatchObject({
      decision: "elicit",
      reason: "test-elicit-reason",
      elicitationOutcome: "transport-error",
    });
  });

  it("static allow + inspect returns deny → throws + audit deny + category + reason", async () => {
    const { read } = captureAuditLines();
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const inspectSpy = vi.fn().mockReturnValue({
      decision: "deny",
      category: "capability_escalation",
      reason: "test-deny-reason",
    });
    const surfaceReview: SurfaceReview = {
      [TARGET_OP]: { decision: "allow", category: "standard_read", inspect: inspectSpy },
    };

    await expect(
      handleUpstreamRequest({
        ...makeArgs({ surfaceReview, refreshToken: "RT-task4-test-4" }),
        ctx: TARGET_CTX,
      }),
    ).rejects.toThrow();

    expect(inspectSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy).not.toHaveBeenCalled();

    const auditForOp = read().filter((l) => l.operationId === TARGET_OP);
    expect(auditForOp.at(-1)).toMatchObject({
      decision: "deny",
      category: "capability_escalation",
      reason: "test-deny-reason",
    });
  });

  it("static deny + inspect spy → spy NOT called, fetch never happens", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const inspectSpy = vi.fn().mockReturnValue({ decision: "allow" });
    const surfaceReview: SurfaceReview = {
      [TARGET_OP]: {
        decision: "deny",
        category: "capability_escalation",
        inspect: inspectSpy,
      },
    };

    await expect(
      handleUpstreamRequest({
        ...makeArgs({ surfaceReview, refreshToken: "RT-task4-test-5" }),
        ctx: TARGET_CTX,
      }),
    ).rejects.toThrow(/denied by surface review/);

    expect(inspectSpy).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("static elicit (no inspector) → routes through runElicitation, emits transport-error when server has no elicitInput", async () => {
    const { read } = captureAuditLines();
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const surfaceReview: SurfaceReview = {
      [TARGET_OP]: { decision: "elicit", category: "external_data_flow" },
    };

    await expect(
      handleUpstreamRequest({
        ...makeArgs({ surfaceReview, refreshToken: "RT-task4-test-6" }),
        ctx: TARGET_CTX,
      }),
    ).rejects.toThrow(/requires user approval/);

    expect(fetchSpy).not.toHaveBeenCalled();

    const auditForOp = read().filter((l) => l.operationId === TARGET_OP);
    expect(auditForOp.at(-1)).toMatchObject({
      decision: "elicit",
      elicitationOutcome: "transport-error",
    });
  });
});
