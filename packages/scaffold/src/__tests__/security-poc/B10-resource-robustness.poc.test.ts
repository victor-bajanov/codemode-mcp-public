// B10 — Resource/robustness probes with a security consequence only if they
// escape the attacker's own call. All observed failures are contained to the
// sandbox call that caused them (error string back to the sandbox), so these
// are Informational/Low.
//
//   • The host's checks over ctx.body are recursive (the F-19 entry check
//     `containsBinaryValue`, which now runs first, then deepFreeze and
//     truncateForReturn): a deeply nested ctx.body throws RangeError on the
//     host. It is caught by ToolDispatcher and turned into an error string; no
//     audit line is emitted for the attempt.
//   • bypassTruncate is sandbox-settable: the full upstream JSON is returned
//     to the sandbox. The sandbox is allowed to receive upstream bodies, and
//     codemode's own __truncateResponse still caps what reaches the LLM, so
//     this is a context-size matter rather than a disclosure.
//   • Per-run budget and host deadline (F-12, remediated 2026-10-08): a
//     sandbox run is now capped at EXECUTE_MAX_UPSTREAM_CALLS upstream
//     requests (default 1 000) and the host stops waiting after
//     EXECUTE_HOST_TIMEOUT_MS (default 75 000 ms), independently of
//     codemode's cooperative 70 s timeout (see B1 and
//     execution-limits.test.ts). Both are enforced by the guarded executor
//     in mcp-agent-factory.ts, which these probes call beneath, so the
//     assertions below are unchanged.
//
// Status: unchanged — the two observations above remain Informational and
// contained to the caller's own sandbox call.
import { describe, it, expect, vi, afterEach } from "vitest";
import { ToolDispatcher } from "@cloudflare/codemode";
import { handleUpstreamRequest } from "../../request-handler";
import { truncateForReturn } from "../../truncate";

const SPEC = { openapi: "3.0.0", info: { title: "T", version: "1" }, paths: { "/w": { post: { operationId: "p", responses: {} } } } } as never;

function args(ctx: unknown) {
  return {
    ctx: ctx as never, spec: SPEC, surfaceReview: { p: { decision: "allow" as const } }, apiBaseUrl: "https://api.example", deploymentName: "poc",
    props: { userId: "u", refreshToken: "r" }, server: {} as never,
    oauth: { refreshTokenAccessor: () => "r", userIdAccessor: () => "u", broker: { async getOrRefreshAccessToken() { return "AT"; } } },
    audit: {}, env: {},
  };
}

describe("B10 — resource robustness (Informational)", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("deeply nested ctx.body overflows the host's recursive checks (containsBinaryValue / deepFreeze): RangeError, contained, unaudited", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    vi.stubGlobal("fetch", vi.fn());
    let body: unknown = 1;
    for (let i = 0; i < 100_000; i++) body = [body];
    const d = new ToolDispatcher({ request: () => handleUpstreamRequest(args({ method: "POST", path: "/w", body })) });
    // Bypass JSON marshalling of the argument (the real path would JSON.parse it; V8's parser is iterative).
    const wire = await (d as unknown as { call: (n: string, j: string) => Promise<string> }).call("request", "");
    // argsJson "" → args = [] → handler gets undefined ctx; so call the fn directly to reach the recursive checks:
    const direct = await handleUpstreamRequest(args({ method: "POST", path: "/w", body })).then(() => "ok", (e: Error) => e.constructor.name);
    expect(direct).toBe("RangeError");
    expect(wire).toMatch(/"error":/);
    expect(logSpy.mock.calls.some((c) => String(c[0]).startsWith("AUDIT "))).toBe(false);
  });

  it("bypassTruncate is honoured when set by the sandbox", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const big = { blob: "x".repeat(200_000) };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(big), { status: 200 })));
    const r1 = await handleUpstreamRequest(args({ method: "POST", path: "/w", body: {} })) as { result: { blob: string } };
    const r2 = await handleUpstreamRequest(args({ method: "POST", path: "/w", body: {}, bypassTruncate: true })) as { result: { blob: string } };
    expect(r1.result.blob.length).toBeLessThan(70_000);     // truncateForReturn applied
    expect(r2.result.blob.length).toBe(200_000);            // sandbox opted out
  });

  it("truncateForReturn re-serialises every subtree per level (O(n·depth)) — bounded by the 64 KiB budget, not a DoS", () => {
    let v: unknown = "x".repeat(60_000);
    for (let i = 0; i < 200; i++) v = [v];
    const t0 = performance.now();
    truncateForReturn(v);
    expect(performance.now() - t0).toBeLessThan(5_000);
  });
});
