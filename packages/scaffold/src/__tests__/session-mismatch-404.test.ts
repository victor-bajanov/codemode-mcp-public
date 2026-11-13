// A session-principal mismatch (F-16) must reach the client as the MCP
// "Session not found" 404, not as an uncaught exception (a 5xx at the edge).
// A 5xx leaves the client retrying a session id it will never be allowed to
// use; a 404 makes it re-initialise with a fresh session, bound to the
// caller's own principal. Observed live on optical-dev (2026-11-13) after a
// re-sign-in returned a different `sub`: Claude.ai and Claude Code were stuck
// on 502 until reconnected by hand.
import { describe, expect, it, vi } from "vitest";

const captured: Array<Record<string, unknown>> = [];
vi.mock("@cloudflare/workers-oauth-provider", () => ({
  OAuthProvider: class {
    constructor(options: Record<string, unknown>) {
      captured.push(options);
    }
    fetch(): Response {
      return new Response(null, { status: 404 });
    }
  },
}));

import { McpAgent } from "agents/mcp";
import { withSessionMismatchAs404 } from "../mcp-agent-factory";
import { setupProvider } from "../setup-provider";
import type { ApiProvider } from "../api-provider";

const MISMATCH = "mcp-session-principal-mismatch: this MCP session belongs to a different user";

function harness(inner: (req: Request) => Promise<Response>) {
  const lines: string[] = [];
  const spy = vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => void lines.push(a.map(String).join(" ")));
  const handler = withSessionMismatchAs404(
    { fetch: (req: Request) => inner(req) },
    { principalOf: (props) => (props as { userId?: string } | undefined)?.userId ?? null },
  );
  const env = { DEPLOYMENT_NAME: "test-dep" };
  const waits: Promise<unknown>[] = [];
  const ctx = { waitUntil: (p: Promise<unknown>) => void waits.push(p), props: { userId: "u2" } };
  const call = async (req: Request) => {
    const res = await handler.fetch(req, env, ctx as unknown as ExecutionContext);
    await Promise.all(waits);
    return res;
  };
  return { call, lines, restore: () => spy.mockRestore() };
}

const req = () =>
  new Request("https://w.test/mcp", { method: "POST", headers: { "mcp-session-id": "s1" }, body: "{}" });

describe("withSessionMismatchAs404", () => {
  it("answers a principal mismatch with the MCP Session-not-found 404", async () => {
    const h = harness(async () => {
      throw new Error(MISMATCH);
    });
    const res = await h.call(req());
    h.restore();
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toMatch(/^application\/json/);
    expect(await res.json()).toEqual({ jsonrpc: "2.0", error: { code: -32001, message: "Session not found" }, id: null });
  });

  it("audits the refusal with the caller's principal, never the session id", async () => {
    const h = harness(async () => {
      throw new Error(MISMATCH);
    });
    await h.call(req());
    h.restore();
    const audit = h.lines.filter((l) => l.startsWith("AUDIT "));
    expect(audit).toHaveLength(1);
    const entry = JSON.parse(audit[0]!.slice("AUDIT ".length));
    expect(entry).toMatchObject({
      deployment: "test-dep",
      method: "POST",
      path: "/mcp",
      decision: "deny",
      reason: "session-principal-mismatch",
      principalId: "u2",
    });
    expect(audit[0]).not.toContain("s1");
  });

  it("matches the mismatch even when RPC wraps the message", async () => {
    const h = harness(async () => {
      throw new Error(`Error: ${MISMATCH}`);
    });
    const res = await h.call(req());
    h.restore();
    expect(res.status).toBe(404);
  });

  it("rethrows any other error unchanged", async () => {
    const boom = new Error("something else");
    const h = harness(async () => {
      throw boom;
    });
    await expect(h.call(req())).rejects.toBe(boom);
    h.restore();
  });

  it("setupProvider wraps the /mcp apiHandler with it", async () => {
    const serve = vi.spyOn(McpAgent, "serve").mockReturnValue({
      fetch: async () => {
        throw new Error(MISMATCH);
      },
    } as never);
    captured.length = 0;
    setupProvider({
      name: "test",
      displayName: "Test Provider",
      oauth: {
        authorizeUrl: "https://login.example.com/authorize",
        tokenUrl: "https://login.example.com/token",
        scopes: ["openid"],
        clientIdSecretName: "TEST_CLIENT_ID",
        clientSecretSecretName: "TEST_CLIENT_SECRET",
      },
      spec: {} as never,
      surfaceReview: {},
      apiBaseUrl: "https://api.example.com",
    } as ApiProvider);
    serve.mockRestore();
    const apiHandler = captured[0]!.apiHandler as {
      fetch: (r: Request, e: unknown, c: ExecutionContext) => Promise<Response>;
    };
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    const res = await apiHandler.fetch(req(), { DEPLOYMENT_NAME: "d" }, {
      waitUntil: () => {},
      props: { userId: "u2" },
    } as unknown as ExecutionContext);
    spy.mockRestore();
    expect(res.status).toBe(404);
  });

  it("passes a normal response through untouched", async () => {
    const ok = new Response("ok", { status: 200 });
    const h = harness(async () => ok);
    const res = await h.call(req());
    h.restore();
    expect(res).toBe(ok);
    expect(h.lines.filter((l) => l.startsWith("AUDIT "))).toHaveLength(0);
  });
});
