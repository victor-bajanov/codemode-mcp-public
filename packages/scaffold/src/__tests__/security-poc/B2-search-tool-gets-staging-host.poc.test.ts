// B2 — The `search` tool's sandbox used to receive `__stagingHost`, and
// through `__stagingHost.stageFromUpstreamJson` it could drive the FULL
// upstream request path (including writes), not just read the spec.
//
// mcp-agent-factory.ts wraps the executor. It used to append `__stagingHost`
// (when staging is bound) and `__docsHost` to EVERY array-form run. codemode's
// `search` tool is described to clients as spec browsing and passes an EMPTY
// providers array; openApiMcpServer deliberately withholds `__openapiHost`
// from it, and the wrapper re-introduced an upstream channel. That defeated
// any CLIENT-side policy that auto-approves `search` as read-only while
// gating `execute`.
//
// createGuardedExecutor now appends `__stagingHost` only to runs that carry
// `__openapiHost` (i.e. `execute`), and `search` is advertised with
// `readOnlyHint: true`. Server-side policy (surface review, inspectors,
// elicitation) still applies on the `execute` route — test 2.
//
// Status: FIXED (F-4) — `search` sandboxes get only `__docsHost`; staging is
// `execute`-only.
import { describe, it, expect, vi, afterEach } from "vitest";
import { DynamicWorkerExecutor } from "@cloudflare/codemode";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createProviderMcpAgent } from "../../mcp-agent-factory";
import type { ApiProvider } from "../../api-provider";
import { FakeD1 } from "../../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../../staging/__tests__/__fixtures__/fake-r2";

const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  paths: {
    "/widgets": {
      get: { operationId: "listWidgets", responses: {} },
      post: { operationId: "createWidget", responses: {} },
      delete: { operationId: "purgeWidgets", responses: {} },
    },
  },
};

const provider = {
  name: "poc",
  displayName: "POC",
  oauth: { authorizeUrl: "https://idp.example/a", tokenUrl: "https://idp.example/t", scopes: [], clientIdSecretName: "CID", clientSecretSecretName: "CSEC" },
  spec: SPEC,
  surfaceReview: {
    listWidgets: { decision: "allow", category: "standard_read" },
    createWidget: { decision: "allow", category: "standard_write" },
    purgeWidgets: { decision: "elicit", category: "bulk_destructive" },
  },
  apiBaseUrl: "https://api.example",
} as unknown as ApiProvider;

/** Node-side evaluator mirroring the sandbox contract (see the existing
 *  mcp-agent-factory test): each provider becomes a free variable. */
function stubExecutor(calls: Array<{ names: string[] }>) {
  return vi.spyOn(DynamicWorkerExecutor.prototype, "execute").mockImplementation(async function (code: string, providersOrFns: unknown) {
    const providers = Array.isArray(providersOrFns) ? (providersOrFns as Array<{ name: string; fns: Record<string, unknown> }>) : [];
    calls.push({ names: providers.map((p) => p.name) });
    const fn = new Function(...providers.map((p) => p.name), `"use strict"; return (${code})();`) as (...a: unknown[]) => Promise<unknown>;
    return { result: await fn(...providers.map((p) => p.fns)) };
  } as never);
}

async function connect() {
  const AgentClass = createProviderMcpAgent(provider);
  const agent = Object.create(AgentClass.prototype) as {
    env: Record<string, unknown>; props: Record<string, unknown>;
    ctx: { waitUntil: (p: Promise<unknown>) => void; storage: { get: (k: string) => Promise<unknown>; put: (k: string, v: unknown) => Promise<void> } };
    init: () => Promise<void>; server: { connect: (t: unknown) => Promise<void>; close: () => Promise<void> };
  };
  agent.env = {
    LOADER: {},
    DEPLOYMENT_NAME: "poc",
    STAGING_D1: new FakeD1(),
    STAGING_R2: new FakeR2(),
    STAGING_UPLOAD_ORIGIN: "https://poc.example",
    TOKEN_BROKER: { idFromName: (n: string) => n, get: () => ({ async getOrRefreshAccessToken() { return "AT-secret"; } }) },
  };
  agent.props = { userId: "u1", refreshToken: "RT" };
  // init() records the MCP session principal in DO storage (F-16).
  const storage = new Map<string, unknown>();
  agent.ctx = { waitUntil: () => {}, storage: { get: async (k) => storage.get(k), put: async (k, v) => void storage.set(k, v) } };
  await agent.init();
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await agent.server.connect(st);
  const client = new Client({ name: "poc", version: "0" });
  await client.connect(ct);
  return { client, close: async () => { await client.close(); await agent.server.close(); } };
}

async function callText(client: Client, name: string, code: string) {
  const r = (await client.callTool({ name, arguments: { code } })) as { content: Array<{ text?: string }>; isError?: boolean };
  return { text: r.content.map((c) => c.text ?? "").join(""), isError: r.isError === true };
}

describe("B2 — search tool no longer receives __stagingHost (FIXED, F-4)", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("FIXED (F-4): search sandbox gets only __docsHost, cannot reach __stagingHost, and performs no upstream WRITE", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn(async () => new Response(JSON.stringify({ data: btoa("payload"), mimeType: "text/plain" }), { status: 201, headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetchSpy);
    const calls: Array<{ names: string[] }> = [];
    stubExecutor(calls);
    const { client, close } = await connect();
    // The original payload, guarded with `typeof` so the run reports what the
    // sandbox can see instead of dying on a ReferenceError (the stub executor
    // binds provider names as function parameters).
    const guarded = await callText(client, "search", `async () => {
      const stagingType = typeof __stagingHost;
      let staged = null;
      if (stagingType !== "undefined") {
        staged = await __stagingHost.stageFromUpstreamJson(
          { method: "POST", path: "/widgets", body: { name: "created-from-search" } }, "data", "base64");
      }
      return { codemodeRequest: typeof codemode.request, stagingType, staged };
    }`);
    // The original payload verbatim: it can only fail now.
    const raw = await callText(client, "search", `async () => {
      const r = await __stagingHost.stageFromUpstreamJson(
        { method: "POST", path: "/widgets", body: { name: "created-from-search" } }, "data", "base64");
      return { codemodeRequest: typeof codemode.request, staged: r };
    }`);
    const tools = (await client.listTools()).tools;
    await close();
    expect(guarded.isError).toBe(false);
    expect(calls[0]!.names).toEqual(["__docsHost"]);                    // search: no __openapiHost, no staging
    const out = JSON.parse(guarded.text) as { codemodeRequest: string; stagingType: string; staged: unknown };
    expect(out.codemodeRequest).toBe("undefined");                       // codemode.request is withheld from search …
    expect(out.stagingType).toBe("undefined");                           // … and so is __stagingHost
    expect(out.staged).toBeNull();
    expect(raw.isError).toBe(true);
    expect(raw.text).toMatch(/__stagingHost is not defined/);
    expect(fetchSpy).not.toHaveBeenCalled();                             // no upstream write happened
    expect(tools.find((t) => t.name === "search")!.annotations?.readOnlyHint).toBe(true);
  });

  it("server-side policy still applies on the execute route, where staging remains: an elicit op fails closed when the client lacks elicitation (REFUTED for policy bypass)", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const calls: Array<{ names: string[] }> = [];
    stubExecutor(calls);
    const { client, close } = await connect();
    const { text } = await callText(client, "execute", `async () =>
      __stagingHost.stageFromUpstreamJson({ method: "DELETE", path: "/widgets" }, "data", "base64")`);
    await close();
    expect(calls[0]!.names).toEqual(["__openapiHost", "__stagingHost", "__docsHost"]);
    const out = JSON.parse(text) as { ok: boolean; status: number; message: string };
    expect(out.ok).toBe(false);
    expect(out.message).toMatch(/requires user approval; outcome: unsupported/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
