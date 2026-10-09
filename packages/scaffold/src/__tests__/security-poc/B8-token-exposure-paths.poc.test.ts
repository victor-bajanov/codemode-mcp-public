// B8 — Every value or error that crosses host → sandbox: does any carry the
// access token, refresh token or client secret?
//
// Paths traced: handleUpstreamRequest's success/error envelope, ToolError and
// non-ToolError exceptions (ToolDispatcher serialises `err.message`), the
// TokenBroker's refresh error (refresh.ts), fetch's own header-validation
// errors, and the putFile/getFile results.
//
// Status: FIXED (F-21) — refresh.ts no longer forwards the token endpoint's
//         response body: the sandbox sees only `Refresh failed <status>` plus
//         a token-shaped OAuth `error` code.
//         REFUTED for real providers (nothing secret is interpolated).
//         Previously Informational: refresh.ts forwarded the body VERBATIM
//         into the sandbox-visible error, so an operator misconfiguration
//         (OAUTH_TOKEN_URL_OVERRIDE pointing at an echoing endpoint) could make
//         that error contain the refresh token/secret; it no longer can.
//         FIXED (F-24) — a non-string `method` (or `path`) is now refused up
//         front with a ToolError ("codemode.request needs string `method` and
//         `path`") and an AUDIT line with category 'malformed' and reason
//         'invalid-method-or-path'. Previously it surfaced as a raw
//         `toUpperCase is not a function` TypeError with no audit entry.
import { describe, it, expect, vi, afterEach } from "vitest";
import { ToolDispatcher } from "@cloudflare/codemode";
import { handleUpstreamRequest } from "../../request-handler";
import { getOrRefreshAccessToken } from "../../refresh";

const SPEC = { openapi: "3.0.0", info: { title: "T", version: "1" }, paths: { "/w": { get: { operationId: "g", responses: {} } } } } as never;
const SR = { g: { decision: "allow" as const } };

function args(ctx: unknown, broker: { getOrRefreshAccessToken: (a: unknown) => Promise<string> }) {
  return {
    ctx: ctx as never, spec: SPEC, surfaceReview: SR, apiBaseUrl: "https://api.example", deploymentName: "poc",
    props: { userId: "u", refreshToken: "RT-SECRET" }, server: {} as never,
    oauth: { refreshTokenAccessor: (p: Record<string, unknown>) => p.refreshToken as string, userIdAccessor: () => "u", broker },
    audit: {}, env: {},
  };
}

/** What the sandbox would receive after ToolDispatcher serialisation. */
async function viaDispatcher(fn: () => Promise<unknown>): Promise<string> {
  const d = new ToolDispatcher({ request: fn });
  return d.call("request", "[]");
}

describe("B8 — token exposure paths", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("success envelope carries only {success,status,result,errors} — never the Authorization header (REFUTED)", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.stubGlobal("fetch", vi.fn(async () => new Response('{"x":1}', { status: 200, headers: { "content-type": "application/json" } })));
    const broker = { async getOrRefreshAccessToken() { return "AT-SECRET"; } };
    const wire = await viaDispatcher(() => handleUpstreamRequest(args({ method: "GET", path: "/w" }, broker)));
    expect(JSON.parse(wire)).toEqual({ result: { success: true, status: 200, result: { x: 1 }, errors: [] } });
    expect(wire).not.toContain("AT-SECRET");
    expect(wire).not.toContain("RT-SECRET");
  });

  it("FIXED (F-21): refresh.ts: a Google/Xero-shaped 400 reaches the sandbox as status + error code only", async () => {
    const f = vi.fn(async () => new Response('{"error":"invalid_grant","error_description":"Token has been expired or revoked."}', { status: 400 }));
    const storage = { get: async () => undefined, put: async () => {} };
    const broker = {
      getOrRefreshAccessToken: () => getOrRefreshAccessToken({ storage, rotation: "static", refreshToken: "RT-SECRET", clientId: "CID", clientSecret: "CSEC-SECRET", tokenUrl: "https://idp.example/t", fetcher: f as never }),
    };
    vi.spyOn(console, "log").mockImplementation(() => {});
    const wire = await viaDispatcher(() => handleUpstreamRequest(args({ method: "GET", path: "/w" }, broker)));
    expect(wire).toBe('{"error":"Refresh failed 400 (invalid_grant)"}');
    expect(wire).not.toContain("expired or revoked");
    expect(wire).not.toContain("RT-SECRET");
    expect(wire).not.toContain("CSEC-SECRET");
  });

  it("FIXED (F-21): refresh.ts no longer echoes the token-endpoint body, so an echoing endpoint cannot leak refresh_token + client_secret", async () => {
    // Only reachable if the operator repoints OAUTH_TOKEN_URL_OVERRIDE at a
    // non-OAuth endpoint; the defence in depth now holds.
    const f = vi.fn(async (_u: string, init: RequestInit) => new Response(String(init.body), { status: 500 }));
    const storage = { get: async () => undefined, put: async () => {} };
    let err: Error | undefined;
    try {
      await getOrRefreshAccessToken({ storage, rotation: "static", refreshToken: "RT-SECRET", clientId: "CID", clientSecret: "CSEC-SECRET", tokenUrl: "https://echo.example/t", fetcher: f as never });
    } catch (e) { err = e as Error; }
    expect(f).toHaveBeenCalledTimes(1);
    expect(err!.message).toBe("Refresh failed 500");
    expect(err!.message).not.toContain("RT-SECRET");
    expect(err!.message).not.toContain("CSEC-SECRET");
  });

  it("fetch header-validation errors from a sandbox-supplied bad header do not reflect the bearer (REFUTED)", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.stubGlobal("fetch", (u: string, init: RequestInit) => { new Request(u, init); throw new Error("unreachable"); });
    const broker = { async getOrRefreshAccessToken() { return "AT-SECRET"; } };
    const wire = await viaDispatcher(() => handleUpstreamRequest(args({ method: "GET", path: "/w", headers: { "X-Poc": "a\r\nb" } }, broker)));
    expect(wire).toMatch(/"error":/);
    expect(wire).not.toContain("AT-SECRET");
  });

  it("FIXED (F-24): non-string ctx.method is refused with a ToolError and a 'malformed' AUDIT line", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const broker = { async getOrRefreshAccessToken() { return "AT"; } };
    const wire = await viaDispatcher(() => handleUpstreamRequest(args({ method: 42, path: "/w" }, broker)));
    expect(JSON.parse(wire)).toEqual({ error: "codemode.request needs string `method` and `path`" });
    expect(wire).not.toMatch(/toUpperCase is not a function/);
    const audits = logSpy.mock.calls
      .map((c) => String(c[0]))
      .filter((l) => l.startsWith("AUDIT "))
      .map((l) => JSON.parse(l.slice("AUDIT ".length)) as Record<string, unknown>);
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ decision: "deny", category: "malformed", reason: "invalid-method-or-path" });
  });
});
