// D-2 (Medium) regression, end to end with the real Optical provider: query
// parameter names were never checked.
//
// Attacker: code running in the sandbox (prompt-injected model).
// Precondition: none beyond a session.
// Payloads: a method override (`$httpMethod`), a credential (`token`) and an
//   undeclared name on listTasks.
// Control: each query name must be declared inline by the matched operation
//   (Optical declares its own); Optical has no standard parameters; forbidden
//   names are refused whatever is declared.
// Why the pre-fix code failed: every key was copied onto the upstream URL.

import { afterEach, describe, expect, it, vi } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "@local/scaffold";
import { opticalProvider } from "../index";

function run(ctx: UpstreamCtx) {
  const fetchSpy = vi.fn<typeof fetch>(async () => new Response('{"tasks":[]}', { status: 200 }));
  vi.stubGlobal("fetch", fetchSpy);
  vi.spyOn(console, "log").mockImplementation(() => {});
  const promise = handleUpstreamRequest({
    ctx,
    spec: opticalProvider.spec,
    surfaceReview: opticalProvider.surfaceReview,
    apiBaseUrl: opticalProvider.apiBaseUrl,
    deploymentName: "test",
    props: { refreshToken: "r", userId: "u" },
    server: {} as never,
    oauth: {
      refreshTokenAccessor: () => "r",
      userIdAccessor: () => "u",
      broker: { getOrRefreshAccessToken: async () => "AT" },
    },
    ...(opticalProvider.standardQueryParams ? { standardQueryParams: opticalProvider.standardQueryParams } : {}),
    audit: {},
    env: {},
  });
  return { promise, fetchSpy, url: () => new URL(String(fetchSpy.mock.calls[0]![0])) };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Optical provider: query names (D-2)", () => {
  it("has no standard query parameters", () => {
    expect(opticalProvider.standardQueryParams).toBeUndefined();
  });

  it("FIXED (D-2): $httpMethod and token on listTasks are refused, nothing sent", async () => {
    for (const query of [{ $httpMethod: "DELETE" }, { token: "x" }]) {
      const r = run({ method: "GET", path: "/v1/tasks", query: query as never });
      await expect(r.promise).rejects.toThrow(/cannot be set from sandbox code/);
      expect(r.fetchSpy).not.toHaveBeenCalled();
      vi.unstubAllGlobals();
    }
  });

  it("FIXED (D-2): an undeclared name on listTasks is refused with the accepted list", async () => {
    const r = run({ method: "GET", path: "/v1/tasks", query: { notAParameterOfThisOperation: "1" } });
    await expect(r.promise).rejects.toThrow(
      'Operation listTasks does not accept query parameter "notAParameterOfThisOperation"; it accepts: from, project_id, status, to',
    );
    expect(r.fetchSpy).not.toHaveBeenCalled();
  });

  it("control: listTasks?status=open is forwarded", async () => {
    const r = run({ method: "GET", path: "/v1/tasks", query: { status: "open" } });
    await r.promise;
    expect(r.url().search).toBe("?status=open");
  });
});
