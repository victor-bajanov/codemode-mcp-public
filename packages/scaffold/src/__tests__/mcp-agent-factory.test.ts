import { describe, it, expect, vi, afterEach } from "vitest";
import { McpAgent } from "agents/mcp";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DynamicWorkerExecutor } from "@cloudflare/codemode";
import { openApiMcpServer } from "@cloudflare/codemode/mcp";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { FakeD1 } from "../staging/__tests__/__fixtures__/fake-d1";
import { registerFileHandleTool } from "../staging";
import {
  buildDocsHostFns,
  buildExecuteAddendum,
  buildSearchStrategyBlock,
  buildStagingHostFns,
  CODEMODE_SANDBOX_ANCHOR,
  createGuardedExecutor,
  createProviderMcpAgent,
  RESPONSE_CHAR_CAP,
  SESSION_PRINCIPAL_KEY,
  type HostProvider,
  type SandboxExecuteResult,
} from "../mcp-agent-factory";
import { ToolError } from "../elicit";
import { annotateSpecWithSurfaceReview } from "../annotate-spec";
import type { ApiProvider } from "../api-provider";

const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));
const xeroSpec = JSON.parse(
  readFileSync(`${repoRoot}/packages/providers/xero/src/spec.json`, "utf-8"),
) as Record<string, unknown>;
const gmailSpec = JSON.parse(
  readFileSync(`${repoRoot}/packages/providers/gmail/src/spec.json`, "utf-8"),
) as Record<string, unknown>;

// Capturing executor: never evaluates the code argument; instead records the
// namespaces (second arg) that openApiMcpServer passes for each tool invocation.
// Under codemode 0.4.2 the codemode object is fully sandbox-internal (embedded in
// the generated code string). The host only passes __openapiHost for the execute
// tool, and nothing for the search tool.
type CapturedCall = { namespaces: Array<{ name: string; fns: unknown }> };

function makeCapturingExecutor() {
  const calls: CapturedCall[] = [];
  return {
    executor: {
      // biome-ignore lint/suspicious/noExplicitAny: satisfying Executor interface while capturing call args
      execute: async (_code: string, namespacesOrFns: any) => {
        const namespaces: Array<{ name: string; fns: unknown }> = Array.isArray(namespacesOrFns)
          ? namespacesOrFns
          : [];
        calls.push({ namespaces });
        return { result: "captured" };
      },
    },
    getCalls: () => calls,
  };
}

async function callSearch(
  // biome-ignore lint/suspicious/noExplicitAny: McpServer type isn't exported usefully
  server: any,
): Promise<void> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "test", version: "1.0" });
  await client.connect(clientTransport);
  await client.callTool({ name: "search", arguments: { code: "// any" } });
  await client.close();
  await server.close();
}

async function callExecute(
  // biome-ignore lint/suspicious/noExplicitAny: McpServer type isn't exported usefully
  server: any,
): Promise<void> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "test", version: "1.0" });
  await client.connect(clientTransport);
  await client.callTool({ name: "execute", arguments: { code: "// any" } });
  await client.close();
  await server.close();
}

describe("openApiMcpServer (codemode 0.4.2 contract)", () => {
  it("codemode 0.4.2: search tool passes no external namespaces to executor (codemode is sandbox-internal)", async () => {
    const { executor, getCalls } = makeCapturingExecutor();
    const server = openApiMcpServer({
      spec: xeroSpec,
      executor,
      request: async () => ({}),
    });
    await callSearch(server);

    const calls = getCalls();
    expect(calls).toHaveLength(1);
    // Under 0.4.2, codemode.spec() is fully sandbox-internal — it is constructed
    // inside the generated code string, not passed as an external namespace.
    // The search tool therefore passes an empty namespaces array.
    expect(calls[0]!.namespaces).toHaveLength(0);
    expect(calls[0]!.namespaces.find((n) => n.name === "codemode")).toBeUndefined();
  });

  it("codemode 0.4.2: execute tool passes __openapiHost (not codemode) as the only external namespace", async () => {
    const { executor, getCalls } = makeCapturingExecutor();
    const server = openApiMcpServer({
      spec: xeroSpec,
      executor,
      request: async () => ({}),
    });
    await callExecute(server);

    const calls = getCalls();
    expect(calls).toHaveLength(1);
    // execute tool wires the user-provided request fn via __openapiHost, not codemode.
    const names = calls[0]!.namespaces.map((n) => n.name);
    expect(names).toContain("__openapiHost");
    expect(names).not.toContain("codemode");
  });

  it("constructs cleanly with the Gmail spec (regression guard)", async () => {
    const { executor, getCalls } = makeCapturingExecutor();
    const server = openApiMcpServer({
      spec: gmailSpec,
      executor,
      request: async () => ({}),
    });
    await callSearch(server);

    const calls = getCalls();
    expect(calls).toHaveLength(1);
    // Search tool ran and executor was called — basic construction sanity check.
    expect(calls[0]!.namespaces).toBeDefined();
  });
});

describe("register_file_handle tool wiring", () => {
  it("issues a working token when bindings are present", async () => {
    const d1 = new FakeD1();
    const tool = registerFileHandleTool({
      STAGING_D1: d1 as unknown as D1Database,
      config: { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 },
      uploadOrigin: "https://x.test",
      now: () => 1,
    });
    const result = await tool.handler({});
    expect(result.upload_url).toBe("https://x.test/staging/upload");
    expect(result.token.startsWith("stg_")).toBe(true);
  });
});

const dummyProvider = {
  name: "test",
  displayName: "Test",
  oauth: {} as never,
  spec: {} as never,
  surfaceReview: {} as never,
  apiBaseUrl: "https://test.example",
} as unknown as ApiProvider;

/** Durable Object storage stub: just the get/put the agent uses, over a Map. */
function makeStorage(initial: Record<string, unknown> = {}) {
  const map = new Map<string, unknown>(Object.entries(initial));
  return {
    map,
    get: async (key: string) => map.get(key),
    put: async (key: string, value: unknown) => {
      map.set(key, value);
    },
  };
}

type StubAgent = {
  env: Record<string, unknown>;
  props: Record<string, unknown> | undefined;
  ctx: { waitUntil: (p: Promise<unknown>) => void; storage: ReturnType<typeof makeStorage> };
  init: () => Promise<void>;
  setName: (name: string, props?: Record<string, unknown>) => Promise<void>;
  sessionPrincipal: string | null | undefined;
  // biome-ignore lint/suspicious/noExplicitAny: McpServer type isn't exported usefully
  server: any;
};

/** An agent instance WITHOUT running the DurableObject constructor (which
 *  needs workerd state); env/props/ctx are the minimal stubs init() reads. */
function makeStubAgent(
  provider: ApiProvider,
  opts: {
    envOverrides?: Record<string, unknown>;
    props?: Record<string, unknown>;
    storage?: ReturnType<typeof makeStorage>;
  } = {},
): StubAgent {
  const AgentClass = createProviderMcpAgent(provider);
  const agent = Object.create(AgentClass.prototype) as StubAgent;
  agent.env = { LOADER: {}, DEPLOYMENT_NAME: "test-deployment", ...(opts.envOverrides ?? {}) };
  agent.props = opts.props ?? {};
  agent.ctx = { waitUntil: () => {}, storage: opts.storage ?? makeStorage() };
  return agent;
}

// Runs the agent's real init() and connects a client to the server it built,
// so assertions see exactly what an MCP client sees. Object.create skips the
// DurableObject constructor (which needs workerd state) while leaving init() —
// the code under test — untouched; init() reads env/props/ctx lazily, so the
// minimal stubs below are enough to reach the openApiMcpServer call.
async function connectToAgentServer(
  provider: ApiProvider,
  envOverrides: Record<string, unknown> = {},
  opts: { props?: Record<string, unknown>; storage?: ReturnType<typeof makeStorage> } = {},
): Promise<{ client: Client; close: () => Promise<void>; agent: StubAgent }> {
  const agent = makeStubAgent(provider, { envOverrides, ...opts });
  await agent.init();

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await agent.server.connect(serverTransport);
  const client = new Client({ name: "test", version: "1.0" });
  await client.connect(clientTransport);
  return {
    client,
    agent,
    close: async () => {
      await client.close();
      await agent.server.close();
    },
  };
}

const namedProvider = {
  ...dummyProvider,
  name: "test-provider",
  spec: xeroSpec,
} as unknown as ApiProvider;

/** serverInfo as an MCP client sees it, read over a real transport. */
// biome-ignore lint/suspicious/noExplicitAny: McpServer type isn't exported usefully
async function serverInfoOf(server: any): Promise<{ name: string; version: string } | undefined> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "test", version: "1.0" });
  await client.connect(clientTransport);
  const info = client.getServerVersion();
  await client.close();
  await server.close();
  return info as { name: string; version: string } | undefined;
}

/**
 * Reads the `server` CLASS FIELD, i.e. the McpServer constructed before init()
 * replaces it. `Object.create` (used by connectToAgentServer) deliberately skips
 * field initializers, so it cannot observe this value at all — repointing the
 * generated class's prototype chain at a trivial base instead makes `super(...)`
 * a no-op, so the constructor runs the field initializer and nothing else. The
 * class is freshly generated per createProviderMcpAgent call, so this mutation
 * is local to the test. No `agents` internals are touched — the point is to
 * bypass them.
 */
async function fieldServerInfo(
  provider: ApiProvider,
): Promise<{ name: string; version: string } | undefined> {
  const AgentClass = createProviderMcpAgent(provider);
  class StubBase {}
  Object.setPrototypeOf(AgentClass, StubBase);
  Object.setPrototypeOf(AgentClass.prototype, StubBase.prototype);
  const Constructible = AgentClass as unknown as new (
    ctx: unknown,
    env: unknown,
    // biome-ignore lint/suspicious/noExplicitAny: McpServer type isn't exported usefully
  ) => { server: any };
  return serverInfoOf(new Constructible({}, {}).server);
}

describe("MCP serverInfo advertised to clients", () => {
  it("reports the provider name, not codemode's \"openapi\" default", async () => {
    const { client, close } = await connectToAgentServer(namedProvider);
    // What the client actually sees in the initialize result.
    expect(client.getServerVersion()).toMatchObject({ name: "test-provider" });
    // The real openApiMcpServer instance, not the throwaway McpServer field.
    const tools = (await client.listTools()).tools.map((t) => t.name);
    expect(tools).toContain("execute");
    expect(tools).toContain("search");
    await close();
  });

  it("reports 0.1.0, not codemode's 1.0.0 default", async () => {
    const { client, close } = await connectToAgentServer(namedProvider);
    expect(client.getServerVersion()?.version).toBe("0.1.0");
    await close();
  });

  it("advertises the same identity before and after init() replaces the server", async () => {
    // The McpAgent field initializer and the openApiMcpServer call are two
    // separate construction sites; if they disagree, the advertised identity
    // depends on init() timing. Reads both through a client rather than
    // trusting the literals in either call site.
    const beforeInit = await fieldServerInfo(namedProvider);
    const { client, close } = await connectToAgentServer(namedProvider);
    const afterInit = client.getServerVersion();
    await close();

    expect(beforeInit).toEqual(afterInit);
    expect(beforeInit).toMatchObject({ name: "test-provider", version: "0.1.0" });
  });
});

describe("buildExecuteAddendum", () => {
  it("always documents the response envelope, before every other block", () => {
    for (const stagingEnabled of [true, false]) {
      const out = buildExecuteAddendum(
        { ...dummyProvider, executeHint: "FLOW: do A then B." },
        stagingEnabled,
      );
      const envIdx = out.indexOf("## Response envelope");
      expect(envIdx).toBeGreaterThanOrEqual(0);
      expect(out).toContain("result: unknown");
      expect(out).toContain("return r.result;");
      expect(envIdx).toBeLessThan(out.indexOf("FLOW: do A then B."));
      expect(envIdx).toBeLessThan(out.indexOf("## codemode.request body modes"));
    }
  });

  it("places executeHint after staging/search/access blocks, before BODY_MODES_BLOCK", () => {
    // Issue #41: staging guidance used to sit behind executeHint AND the
    // spec-sized search block; the new order pulls STAGING_BLOCK forward so
    // it survives deferred-tool description truncation.
    const out = buildExecuteAddendum(
      { ...dummyProvider, executeHint: "FLOW: do A then B." },
      /* stagingEnabled */ true,
    );
    expect(out).toContain("FLOW: do A then B.");
    const hintIdx = out.indexOf("FLOW: do A then B.");
    const stagingIdx = out.indexOf("## Attachments / file uploads");
    const bodyIdx = out.indexOf("## codemode.request body modes");
    // Guard against a vacuous pass: -1 < hintIdx is trivially true, so pin
    // that the staging heading is actually present before trusting the
    // ordering assertion below it.
    expect(stagingIdx).toBeGreaterThanOrEqual(0);
    expect(stagingIdx).toBeLessThan(hintIdx);
    expect(bodyIdx).toBeGreaterThan(hintIdx);
  });

  it("places the staging block BEFORE the search-strategy block when staging is enabled (issue #41)", () => {
    // Note: buildSearchStrategyBlock is a FIXED-size block (~1KB — two
    // interpolated integers), not spec-sized, despite reading each spec to
    // compute those integers. The reorder buys roughly that much; it is not
    // "however big the spec's operation list is".
    const provider = { ...dummyProvider, spec: xeroSpec } as unknown as ApiProvider;
    const out = buildExecuteAddendum(provider, /* stagingEnabled */ true);
    const stagingIdx = out.indexOf("## Attachments / file uploads");
    const searchIdx = out.indexOf("## Searching this spec");
    expect(stagingIdx).toBeGreaterThanOrEqual(0);
    expect(searchIdx).toBeGreaterThanOrEqual(0);
    expect(stagingIdx).toBeLessThan(searchIdx);
  });

  it("pins the STAGING_BLOCK Mode A snippet's 5-arg call shape and mimeType-free example envelope (review fix)", () => {
    // Two reviewers flagged that the Mode A example envelope claimed Gmail's
    // attachments.get returns a `mimeType` field it never does, undercutting
    // the whole point of documenting the 5th contentType arg. Pin both: the
    // corrected envelope example, and that all 5 positional args are shown
    // in order in the snippet.
    const out = buildExecuteAddendum(dummyProvider, /* stagingEnabled */ true);
    expect(out).toContain("{size, attachmentId, data: <base64url>}");
    expect(out).not.toMatch(/\{data: <base64url>, mimeType, size\}/);

    const modeAStart = out.indexOf("**Mode A");
    const modeBStart = out.indexOf("**Mode B");
    expect(modeAStart).toBeGreaterThanOrEqual(0);
    expect(modeBStart).toBeGreaterThan(modeAStart);
    const modeASnippet = out.slice(modeAStart, modeBStart);
    // All 5 positional args, in call order.
    const dataIdx = modeASnippet.indexOf('"data",');
    const encodingIdx = modeASnippet.indexOf('"base64url",');
    const filenameIdx = modeASnippet.indexOf("filename ?? null,");
    const contentTypeIdx = modeASnippet.indexOf("contentType ?? null,");
    expect(dataIdx).toBeGreaterThanOrEqual(0);
    expect(encodingIdx).toBeGreaterThan(dataIdx);
    expect(filenameIdx).toBeGreaterThan(encodingIdx);
    expect(contentTypeIdx).toBeGreaterThan(filenameIdx);
    // The hardened comment: no MIME type at all, not "often absent".
    expect(modeASnippet).toMatch(/no MIME type at all|usually has no MIME type/i);
    expect(modeASnippet).not.toContain("envelope mimeType is often absent");
  });

  it("splices provider.downloadHint verbatim right after the staging block, only when staging is enabled and it is set", () => {
    // Real spec (not dummyProvider's {}), so the search-strategy block is
    // actually emitted and the "before search" assertion below isn't vacuous.
    const withHint = {
      ...dummyProvider,
      spec: xeroSpec,
      downloadHint: "DOWNLOAD-MARKER",
    } as unknown as ApiProvider;

    const enabled = buildExecuteAddendum(withHint, /* stagingEnabled */ true);
    expect(enabled).toContain("DOWNLOAD-MARKER");
    const stagingIdx = enabled.indexOf("## Attachments / file uploads");
    const downloadIdx = enabled.indexOf("DOWNLOAD-MARKER");
    const searchIdx = enabled.indexOf("## Searching this spec");
    expect(stagingIdx).toBeGreaterThanOrEqual(0);
    expect(searchIdx).toBeGreaterThanOrEqual(0);
    expect(downloadIdx).toBeGreaterThan(stagingIdx);
    expect(downloadIdx).toBeLessThan(searchIdx);

    // Staging disabled: no staging block, so no download hint either — it has
    // nowhere sensible to attach and Mode A/B don't exist without staging.
    const disabled = buildExecuteAddendum(withHint, /* stagingEnabled */ false);
    expect(disabled).not.toContain("DOWNLOAD-MARKER");

    // Staging enabled but no downloadHint set: nothing spliced.
    const noHint = buildExecuteAddendum(dummyProvider, /* stagingEnabled */ true);
    expect(noHint).not.toContain("DOWNLOAD-MARKER");
  });

  it("attachmentHint still lands at the end, after BODY_MODES_BLOCK and executeHint", () => {
    const out = buildExecuteAddendum(
      { ...dummyProvider, executeHint: "HINT-MARKER", attachmentHint: "ATTACH-MARKER" },
      /* stagingEnabled */ true,
    );
    const bodyIdx = out.indexOf("## codemode.request body modes");
    const hintIdx = out.indexOf("HINT-MARKER");
    const attachIdx = out.indexOf("ATTACH-MARKER");
    expect(hintIdx).toBeGreaterThanOrEqual(0);
    expect(hintIdx).toBeLessThan(bodyIdx);
    expect(attachIdx).toBeGreaterThan(bodyIdx);
  });

  it("states the response cap and REAL, independently-recomputed spec sizes", () => {
    const provider = { ...dummyProvider, spec: xeroSpec, executeHint: undefined } as unknown as ApiProvider;
    const addendum = buildExecuteAddendum(provider, false);

    // Independently recomputed here, in the shape codemode actually truncates:
    // JSON.stringify(content, null, 2) against MAX_TOKENS * CHARS_PER_TOKEN.
    const annotated = annotateSpecWithSurfaceReview(
      xeroSpec as never,
      (dummyProvider as unknown as ApiProvider).surfaceReview,
    ) as { paths?: Record<string, Record<string, { operationId?: string; description?: string }>> };
    const ops: Array<{ operationId: string; description?: string }> = [];
    for (const item of Object.values(annotated.paths ?? {})) {
      for (const op of Object.values(item)) {
        if (typeof op?.operationId === "string") ops.push(op as { operationId: string; description?: string });
      }
    }
    const fit = (rows: unknown[]): number => {
      let n = 0;
      for (let i = 1; i <= rows.length; i++) {
        if (JSON.stringify(rows.slice(0, i), null, 2).length <= RESPONSE_CHAR_CAP) n = i;
        else break;
      }
      return n;
    };
    const idFit = fit(ops.map((o) => o.operationId));
    const descFit = fit(ops.map((o) => ({ operationId: o.operationId, description: o.description })));

    expect(addendum).toContain(String(RESPONSE_CHAR_CAP));
    expect(addendum, "total op count must be the real one").toContain(`${ops.length} operations`);
    expect(addendum, "id-only fit must be the measured one").toContain(String(idFit));
    expect(addendum, "id+description fit must be the measured one").toContain(String(descFit));
    // The whole point: ids fit entirely, descriptions do not.
    expect(idFit).toBe(ops.length);
    expect(descFit).toBeLessThan(ops.length);
  });

  it("tells the model the truncation footer means it did NOT see everything", () => {
    const addendum = buildExecuteAddendum(
      { ...dummyProvider, spec: xeroSpec } as unknown as ApiProvider,
      false,
    );
    expect(addendum).toMatch(/TRUNCATED/);
    expect(addendum).toMatch(/narrow/i);
  });

  it("keeps the search-strategy block within its token budget", () => {
    // Unconditional cost in EVERY execute tool description, unlike the
    // per-operation annotations which are paid only on a search hit.
    const block = buildSearchStrategyBlock(
      annotateSpecWithSurfaceReview(xeroSpec as never, {} as never),
    );
    expect(block.length).toBeGreaterThan(0);
    // 962 chars for Xero, 961 for Gmail. Over the ~900 target: the two worked
    // examples are ~470 of it and are the actionable half — prose alone would
    // not tell the model HOW to scan ids. Trimmed everything else instead.
    expect(block.length, `search-strategy block is ${block.length} chars`).toBeLessThan(1000);
  });

  it("emits nothing for a spec with no operations rather than a broken claim", () => {
    expect(buildSearchStrategyBlock({ paths: {} })).toBe("");
    expect(buildSearchStrategyBlock(undefined)).toBe("");
  });

  it("explains the ACCESS convention even for a provider with NO executeHint", () => {
    // Every provider's spec is annotated, so every provider's client sees
    // `[ACCESS: …]` markers. Only Gmail had a hand-written hint explaining what
    // they mean — and, critically, what their ABSENCE means. Xero and optical
    // clients were shown the markers with no key.
    const addendum = buildExecuteAddendum(
      { ...dummyProvider, executeHint: undefined } as unknown as ApiProvider,
      false,
    );
    expect(addendum).toContain("ACCESS:");
    // The load-bearing half: no marker means plainly available.
    expect(addendum).toMatch(/with NO\s+`?ACCESS:\s*`?\s+line is plainly available/i);
  });

  it("omits executeHint section entirely when unset", () => {
    const without = buildExecuteAddendum(dummyProvider, /* stagingEnabled */ false);
    const withHint = buildExecuteAddendum(
      { ...dummyProvider, executeHint: "SHOULD-NOT-APPEAR" },
      /* stagingEnabled */ false,
    );
    expect(without).not.toContain("SHOULD-NOT-APPEAR");
    expect(withHint).toContain("SHOULD-NOT-APPEAR");
    // No leading hint marker: the addendum starts with the envelope block
    // (always present), preceded only by the standard newline separator.
    expect(without.trimStart().startsWith("## Response envelope")).toBe(true);
  });

  it("documents the envelope's rateLimit field only when the provider reads rate limits", () => {
    const without = buildExecuteAddendum(dummyProvider, /* stagingEnabled */ false);
    expect(without).not.toContain("rateLimit");

    const withReader = buildExecuteAddendum(
      { ...dummyProvider, readRateLimit: () => undefined },
      /* stagingEnabled */ false,
    );
    expect(withReader).toContain("rateLimit");
    expect(withReader).toContain("retryAfterSeconds");
    // Told where to look on a 429 and how long to wait.
    expect(withReader).toContain("429");
  });

  it("attachmentHint still appears at the bottom when staging + attachmentHint set", () => {
    const out = buildExecuteAddendum(
      { ...dummyProvider, attachmentHint: "ATTACH-MARKER" },
      /* stagingEnabled */ true,
    );
    expect(out).toContain("## Upstream-specific attachment snippet for this server");
    expect(out).toContain("ATTACH-MARKER");
    // Attachment block is the last block in the assembled addendum.
    expect(out.indexOf("ATTACH-MARKER")).toBeGreaterThan(
      out.indexOf("## codemode.request body modes"),
    );
  });
});

describe("buildStagingHostFns (__stagingHost dispatch glue, review fix)", () => {
  // A stream-A reviewer showed that deleting the args[4] forward to
  // stageFromUpstreamJson left every test in the suite green — nothing pinned
  // the positional dispatch itself. These tests reach the fns object directly
  // (extracted out of createProviderMcpAgent's init() specifically so it is
  // testable without a live WorkerLoader) and fail if that forward is dropped.
  function fakeCaps() {
    const stageFromUpstreamJsonCalls: unknown[][] = [];
    return {
      getFile: (async () => ({
        ok: true as const,
        contentType: "x",
        byteLength: 1,
        filename: null,
        bytesBase64: "",
      })) as never,
      putFile: (async () => ({
        ok: true as const,
        file_handle: "fh",
        token: "tok",
        fetch_url: "u",
        byte_length: 1,
      })) as never,
      stageFromUpstreamJson: async (...args: unknown[]) => {
        stageFromUpstreamJsonCalls.push(args);
        return { ok: true, file_handle: "fh", token: "tok", fetch_url: "u", byte_length: 1 };
      },
      stageFromUpstreamJsonCalls,
    };
  }

  it("stageFromUpstreamJson forwards all 5 positional args, including the 5th (contentTypeOverride)", async () => {
    const caps = fakeCaps();
    const { fns } = buildStagingHostFns(caps);
    await fns.stageFromUpstreamJson!(
      { method: "GET", path: "/x" },
      "data",
      "base64url",
      "f.bin",
      "image/png",
    );
    expect(caps.stageFromUpstreamJsonCalls).toEqual([
      [{ method: "GET", path: "/x" }, "data", "base64url", "f.bin", "image/png"],
    ]);
  });

  it("defaults the 5th arg to null when the caller omits it (does not drop it silently)", async () => {
    const caps = fakeCaps();
    const { fns } = buildStagingHostFns(caps);
    await fns.stageFromUpstreamJson!({ method: "GET", path: "/x" }, "data");
    expect(caps.stageFromUpstreamJsonCalls[0]).toEqual([
      { method: "GET", path: "/x" },
      "data",
      "base64url",
      null,
      null,
    ]);
  });

  it("stageFromAttachment is the SAME closure as stageFromUpstreamJson — a real alias, not a re-implementation", () => {
    const caps = fakeCaps();
    const { fns } = buildStagingHostFns(caps);
    expect(fns.stageFromAttachment).toBe(fns.stageFromUpstreamJson);
  });

  it("stageFromAttachment forwards the same 5 args as stageFromUpstreamJson would", async () => {
    const caps = fakeCaps();
    const { fns } = buildStagingHostFns(caps);
    await fns.stageFromAttachment!({ method: "GET", path: "/y" }, "field", "base64", "n.pdf", "application/pdf");
    expect(caps.stageFromUpstreamJsonCalls).toEqual([
      [{ method: "GET", path: "/y" }, "field", "base64", "n.pdf", "application/pdf"],
    ]);
  });

  it("names the capability __stagingHost", () => {
    const { name } = buildStagingHostFns(fakeCaps());
    expect(name).toBe("__stagingHost");
  });
});

// ---------------------------------------------------------------------------
// Task 4 (description-budget-docs-surface): init() docs surface.
// All tests connect a real MCP client to the server init() built, so they see
// exactly what a client sees.
// ---------------------------------------------------------------------------

async function callToolText(
  client: Client,
  name: string,
  args: Record<string, unknown> = {},
): Promise<string> {
  const res = (await client.callTool({ name, arguments: args })) as {
    content: Array<{ type: string; text?: string }>;
  };
  return res.content.map((c) => c.text ?? "").join("");
}

/** Replaces DynamicWorkerExecutor.execute with a Node-side evaluator that
 *  mirrors the real sandbox contract: each `{name, fns}` provider becomes a
 *  free variable of the generated code. Exercises the REAL codemode-generated
 *  sandbox string, our alias patch, and positional fn dispatch end to end. */
function stubExecutorWithNodeEval() {
  return vi
    .spyOn(DynamicWorkerExecutor.prototype, "execute")
    .mockImplementation(async function (code: string, providersOrFns: unknown) {
      const providers = Array.isArray(providersOrFns)
        ? (providersOrFns as Array<{
            name: string;
            fns: Record<string, (...a: unknown[]) => Promise<unknown>>;
          }>)
        : [];
      const fn = new Function(
        ...providers.map((p) => p.name),
        `"use strict"; return (${code})();`,
      ) as (...a: unknown[]) => Promise<unknown>;
      return { result: await fn(...providers.map((p) => p.fns)) };
    } as never);
}

describe("init() docs surface (Task 4)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("registers a docs tool with alwaysLoad + maxResultSizeChars _meta and a one-liner description", async () => {
    const { client, close } = await connectToAgentServer(namedProvider);
    const tools = (await client.listTools()).tools;
    const docs = tools.find((t) => t.name === "docs");
    expect(docs).toBeDefined();
    const meta = (docs as unknown as { _meta?: Record<string, unknown> })._meta;
    expect(meta?.["anthropic/alwaysLoad"]).toBe(true);
    expect(meta?.["anthropic/maxResultSizeChars"]).toBe(100_000);
    expect((docs!.description ?? "").length).toBeGreaterThan(0);
    expect((docs!.description ?? "").length).toBeLessThanOrEqual(300);
    await close();
  });

  it("docs registers even without staging bindings (unconditional), register_file_handle does not", async () => {
    const { client, close } = await connectToAgentServer(namedProvider);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toContain("docs");
    expect(names).not.toContain("register_file_handle");
    await close();
  });

  it("search and execute serve the compact descriptions, not codemode's", async () => {
    const { client, close } = await connectToAgentServer(namedProvider);
    const tools = (await client.listTools()).tools;
    const execute = tools.find((t) => t.name === "execute")!;
    const search = tools.find((t) => t.name === "search")!;
    expect((execute.description ?? "").length).toBeLessThanOrEqual(1800);
    expect((search.description ?? "").length).toBeLessThanOrEqual(1800);
    // codemode's base prose embeds the OpenAPI type dump; compact must not.
    expect(execute.description).not.toContain("interface OpenApiSpec");
    expect(search.description).not.toContain("interface OpenApiSpec");
    // The docs mandate leads.
    expect((execute.description ?? "").slice(0, 200)).toContain("docs");
    await close();
  });

  it("docs tool: no args returns the full document, {section} returns just that section", async () => {
    const { client, close } = await connectToAgentServer(namedProvider);
    const full = await callToolText(client, "docs");
    expect(full).toContain("## Response envelope");
    expect(full).toContain("## Searching this spec");
    expect(full).toContain("## codemode.request body modes");

    const envelope = await callToolText(client, "docs", { section: "envelope" });
    expect(envelope).toContain("## Response envelope");
    expect(envelope).not.toContain("## codemode.request body modes");
    expect(envelope.length).toBeLessThan(full.length);
    await close();
  });

  it("docs tool: the section enum is narrowed to this server's actual sections", async () => {
    // namedProvider has no staging bindings and no readRateLimit, so the docs
    // builder omits staging/attachments/downloads/rate-limit — the SCHEMA must
    // omit them too: a schema-valid section name must never answer "not
    // applicable" (claude.ai live-verification finding).
    const { client, close } = await connectToAgentServer(namedProvider);
    const docs = (await client.listTools()).tools.find((t) => t.name === "docs")!;
    const enumValues = (
      (docs.inputSchema as { properties?: { section?: { enum?: string[] } } }).properties
        ?.section?.enum ?? []
    ).slice();
    expect(enumValues.length).toBeGreaterThan(0);
    expect(enumValues).not.toContain("staging");
    expect(enumValues).not.toContain("rate-limit");
    // Exactly the sections the tool can actually answer — verified by calling
    // every advertised one and never seeing the not-applicable fallback.
    for (const section of enumValues) {
      const out = await callToolText(client, "docs", { section });
      expect(out).not.toContain("not applicable");
      expect(out.length).toBeGreaterThan(0);
    }
    await close();
  });

  it("docs tool: an out-of-enum section is rejected by schema validation, not answered", async () => {
    const { client, close } = await connectToAgentServer(namedProvider);
    const res = (await client.callTool({
      name: "docs",
      arguments: { section: "staging" },
    })) as { isError?: boolean; content: Array<{ text?: string }> };
    expect(res.isError).toBe(true);
    await close();
  });

  it("sandbox: __docsHost.docs with an inapplicable section still explains itself (no schema there)", async () => {
    // The sandbox path is unvalidated — the friendly fallback stays
    // load-bearing for it even though the tool path is schema-gated.
    stubExecutorWithNodeEval();
    const { client, close } = await connectToAgentServer(namedProvider);
    const out = await callToolText(client, "execute", {
      code: 'async () => await __docsHost.docs("staging")',
    });
    expect(out).toContain("not applicable");
    expect(out).toContain("Available");
    await close();
  });

  it("registers the codemode://docs resource, readable pre- and post-connect, same text as the docs tool", async () => {
    const { client, close } = await connectToAgentServer(namedProvider);
    const resources = (await client.listResources()).resources;
    const docsRes = resources.find((r) => r.uri === "codemode://docs");
    expect(docsRes).toBeDefined();
    expect(docsRes!.mimeType).toBe("text/markdown");

    const read = await client.readResource({ uri: "codemode://docs" });
    const text = (read.contents[0] as { text?: string }).text ?? "";
    const toolText = await callToolText(client, "docs");
    expect(text).toBe(toolText);
    await close();
  });

  it("sandbox: __docsHost.docs('envelope') returns the section text through a real execute round-trip", async () => {
    stubExecutorWithNodeEval();
    const { client, close } = await connectToAgentServer(namedProvider);
    const out = await callToolText(client, "execute", {
      code: 'async () => await __docsHost.docs("envelope")',
    });
    expect(out).toContain("## Response envelope");
    await close();
  });

  it("sandbox: codemode.docs is aliased onto the codemode object and matches __docsHost.docs", async () => {
    stubExecutorWithNodeEval();
    const { client, close } = await connectToAgentServer(namedProvider);
    const out = await callToolText(client, "execute", {
      code:
        "async () => { const a = await codemode.docs(\"envelope\"); " +
        "const b = await __docsHost.docs(\"envelope\"); return a === b && a.length > 0; }",
    });
    expect(out).toContain("true");
    await close();
  });

  it("sandbox: no-arg codemode.docs() returns the full document even when the RPC marshals undefined to null", async () => {
    // The real DynamicWorkerExecutor serialises capability-call args as JSON,
    // turning the alias's explicit `undefined` into `null`. Wrap each host fn
    // in a JSON round-trip so this test exercises that seam; without the
    // null-normalisation in buildDocsHostFns it answers `Section "null" is
    // not applicable…` instead of the full document.
    vi.spyOn(DynamicWorkerExecutor.prototype, "execute").mockImplementation(
      async function (code: string, providersOrFns: unknown) {
        const providers = Array.isArray(providersOrFns)
          ? (providersOrFns as Array<{
              name: string;
              fns: Record<string, (...a: unknown[]) => Promise<unknown>>;
            }>)
          : [];
        const marshalled = providers.map((p) => ({
          name: p.name,
          fns: Object.fromEntries(
            Object.entries(p.fns).map(([k, f]) => [
              k,
              (...a: unknown[]) => f(...(JSON.parse(JSON.stringify(a)) as unknown[])),
            ]),
          ),
        }));
        const fn = new Function(
          ...marshalled.map((p) => p.name),
          `"use strict"; return (${code})();`,
        ) as (...a: unknown[]) => Promise<unknown>;
        return { result: await fn(...marshalled.map((p) => p.fns)) };
      } as never,
    );
    const { client, close } = await connectToAgentServer(namedProvider);
    const out = await callToolText(client, "execute", {
      code: "async () => (await codemode.docs()).slice(0, 40)",
    });
    expect(out).toContain("## ");
    expect(out).not.toContain("not applicable");
    await close();
  });

  it("sandbox: the docs capability and alias reach the search sandbox too", async () => {
    stubExecutorWithNodeEval();
    const { client, close } = await connectToAgentServer(namedProvider);
    const out = await callToolText(client, "search", {
      code: 'async () => (await codemode.docs("envelope")).slice(0, 20)',
    });
    expect(out).toContain("## Response envelope");
    await close();
  });

  it("register_file_handle serves the compact description (no attachmentHint splice) when staging is enabled", async () => {
    const stagingEnv = {
      STAGING_D1: new FakeD1() as unknown as D1Database,
      STAGING_R2: {},
      STAGING_UPLOAD_ORIGIN: "https://x.test",
    };
    const withHint = {
      ...namedProvider,
      attachmentHint: "ATTACH-MARKER step three",
    } as unknown as ApiProvider;
    const { client, close } = await connectToAgentServer(withHint, stagingEnv);
    const tool = (await client.listTools()).tools.find(
      (t) => t.name === "register_file_handle",
    )!;
    expect(tool).toBeDefined();
    expect((tool.description ?? "").length).toBeLessThanOrEqual(1800);
    expect(tool.description).not.toContain("ATTACH-MARKER");
    // Points at the docs surface for the provider-specific snippet…
    expect(tool.description).toContain("docs");
    expect(tool.description).toContain("attachments");
    // …and the docs tool serves that snippet.
    const attach = await callToolText(client, "docs", { section: "attachments" });
    expect(attach).toContain("ATTACH-MARKER");
    await close();
  });
});

// ---------------------------------------------------------------------------
// 2026-10-07 security review — sandbox executor guard (F-4, F-12) and the
// MCP session principal binding (F-16).
// ---------------------------------------------------------------------------

type Fns = Record<string, (...a: unknown[]) => Promise<unknown>>;

/** Base executor stand-in: records each call's code + provider names and
 *  hands the providers to `run`, whose return value becomes the result. */
function makeRecordingBase(
  run: (providers: HostProvider[]) => Promise<unknown> = async () => "ok",
) {
  const calls: Array<{ code: string; names: string[]; providersOrFns: unknown }> = [];
  return {
    calls,
    base: {
      execute: async (code: string, providersOrFns: HostProvider[] | Fns): Promise<SandboxExecuteResult> => {
        const providers = Array.isArray(providersOrFns) ? providersOrFns : [];
        calls.push({ code, names: providers.map((p) => p.name), providersOrFns });
        return { result: await run(providers) };
      },
    },
  };
}

function fakeStagingProvider() {
  const hits: string[] = [];
  const fn = (name: string) => async (..._a: unknown[]) => {
    hits.push(name);
    return { ok: true, name };
  };
  const provider: HostProvider = {
    name: "__stagingHost",
    fns: {
      getFile: fn("getFile"),
      putFile: fn("putFile"),
      stageFromUpstreamJson: fn("stageFromUpstreamJson"),
      stageFromAttachment: fn("stageFromAttachment"),
    },
  };
  return { provider, hits };
}

const DOCS_PROVIDER = buildDocsHostFns(() => "docs");
const LIMITS = { hostTimeoutMs: 10_000, maxUpstreamCalls: 200 };

function openapiHost(request: (...a: unknown[]) => Promise<unknown>): HostProvider {
  return { name: "__openapiHost", fns: { request } };
}

const host = (providers: HostProvider[], name: string): Fns =>
  providers.find((p) => p.name === name)!.fns;

describe("createGuardedExecutor — which capabilities each tool gets (F-4)", () => {
  it("a search-shaped run ([] from codemode) gets ONLY __docsHost, even with staging configured", async () => {
    const { calls, base } = makeRecordingBase();
    const staging = fakeStagingProvider();
    const guarded = createGuardedExecutor(base, {
      stagingProvider: staging.provider,
      docsProvider: DOCS_PROVIDER,
      limits: LIMITS,
    });
    const out = await guarded.execute("async () => 1", []);
    expect(out).toEqual({ result: "ok" });
    expect(calls[0]!.names).toEqual(["__docsHost"]);
  });

  it("an execute-shaped run gets __openapiHost, __stagingHost and __docsHost, in that order", async () => {
    const { calls, base } = makeRecordingBase();
    const guarded = createGuardedExecutor(base, {
      stagingProvider: fakeStagingProvider().provider,
      docsProvider: DOCS_PROVIDER,
      limits: LIMITS,
    });
    await guarded.execute("async () => 1", [openapiHost(async () => "r")]);
    expect(calls[0]!.names).toEqual(["__openapiHost", "__stagingHost", "__docsHost"]);
  });

  it("without staging bindings an execute run gets __openapiHost and __docsHost only", async () => {
    const { calls, base } = makeRecordingBase();
    const guarded = createGuardedExecutor(base, {
      stagingProvider: null,
      docsProvider: DOCS_PROVIDER,
      limits: LIMITS,
    });
    await guarded.execute("async () => 1", [openapiHost(async () => "r")]);
    expect(calls[0]!.names).toEqual(["__openapiHost", "__docsHost"]);
  });

  it("alias-patches the array form's code; forwards the legacy Record form untouched", async () => {
    const { calls, base } = makeRecordingBase();
    const guarded = createGuardedExecutor(base, {
      stagingProvider: fakeStagingProvider().provider,
      docsProvider: DOCS_PROVIDER,
      limits: LIMITS,
    });
    const code = `const codemode = {\n  spec: 1${CODEMODE_SANDBOX_ANCHOR}x)`;
    await guarded.execute(code, []);
    expect(calls[0]!.code).toContain("__docsHost.docs(section)");
    const recordFns: Fns = { f: async () => 1 };
    await guarded.execute(code, recordFns);
    expect(calls[1]!.code).toBe(code);
    expect(calls[1]!.providersOrFns).toBe(recordFns);
  });
});

describe("createGuardedExecutor — per-execution upstream budget (F-12)", () => {
  it("refuses the call past maxUpstreamCalls with a ToolError, without reaching the upstream", async () => {
    let upstreamHits = 0;
    const errors: unknown[] = [];
    const { base } = makeRecordingBase(async (providers) => {
      const { request } = host(providers, "__openapiHost");
      for (let i = 0; i < 3; i++) {
        try {
          await request!({ method: "GET", path: "/x" });
        } catch (e) {
          errors.push(e);
        }
      }
      return upstreamHits;
    });
    const guarded = createGuardedExecutor(base, {
      stagingProvider: null,
      docsProvider: DOCS_PROVIDER,
      limits: { hostTimeoutMs: 10_000, maxUpstreamCalls: 2 },
    });
    const out = await guarded.execute("c", [
      openapiHost(async () => {
        upstreamHits++;
        return "r";
      }),
    ]);
    expect(out.result).toBe(2);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(ToolError);
    expect((errors[0] as Error).message).toBe(
      "upstream call budget exceeded: at most 2 upstream requests per execution",
    );
  });

  it("codemode.request and the upstream-reaching staging fns share one budget; getFile/putFile are not counted", async () => {
    const staging = fakeStagingProvider();
    const outcomes: string[] = [];
    const { base } = makeRecordingBase(async (providers) => {
      const st = host(providers, "__stagingHost");
      const attempt = async (label: string, fn: () => Promise<unknown>) => {
        try {
          await fn();
          outcomes.push(`${label}:ok`);
        } catch {
          outcomes.push(`${label}:refused`);
        }
      };
      await attempt("request", () => host(providers, "__openapiHost").request!({}));
      await attempt("getFile", () => st.getFile!("fh", "tok"));
      await attempt("putFile", () => st.putFile!("", "text/plain", null));
      await attempt("stageFromUpstreamJson", () => st.stageFromUpstreamJson!({}, "data"));
      await attempt("stageFromAttachment", () => st.stageFromAttachment!({}, "data"));
      await attempt("getFile", () => st.getFile!("fh", "tok"));
      return null;
    });
    const guarded = createGuardedExecutor(base, {
      stagingProvider: staging.provider,
      docsProvider: DOCS_PROVIDER,
      limits: { hostTimeoutMs: 10_000, maxUpstreamCalls: 2 },
    });
    await guarded.execute("c", [openapiHost(async () => "r")]);
    expect(outcomes).toEqual([
      "request:ok",
      "getFile:ok",
      "putFile:ok",
      "stageFromUpstreamJson:ok",
      "stageFromAttachment:refused",
      "getFile:ok",
    ]);
    expect(staging.hits).toEqual(["getFile", "putFile", "stageFromUpstreamJson", "getFile"]);
  });

  it("each execution starts with a fresh budget", async () => {
    const { base } = makeRecordingBase(async (providers) => {
      await host(providers, "__openapiHost").request!({});
      return "done";
    });
    const guarded = createGuardedExecutor(base, {
      stagingProvider: null,
      docsProvider: DOCS_PROVIDER,
      limits: { hostTimeoutMs: 10_000, maxUpstreamCalls: 1 },
    });
    const req = openapiHost(async () => "r");
    expect(await guarded.execute("c", [req])).toEqual({ result: "done" });
    expect(await guarded.execute("c", [req])).toEqual({ result: "done" });
  });

  it("does not mutate the caller's provider objects (the wrap is a copy)", async () => {
    const staging = fakeStagingProvider();
    const originalStage = staging.provider.fns.stageFromUpstreamJson;
    const request = async () => "r";
    const openapi = openapiHost(request);
    const { base } = makeRecordingBase();
    const guarded = createGuardedExecutor(base, {
      stagingProvider: staging.provider,
      docsProvider: DOCS_PROVIDER,
      limits: LIMITS,
    });
    await guarded.execute("c", [openapi]);
    expect(openapi.fns.request).toBe(request);
    expect(staging.provider.fns.stageFromUpstreamJson).toBe(originalStage);
  });
});

describe("createGuardedExecutor — host-side deadline (F-12)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("abandons a never-settling run after hostTimeoutMs and refuses its later upstream calls", async () => {
    let captured: HostProvider[] = [];
    let upstreamHits = 0;
    const base = {
      execute: (_code: string, providersOrFns: HostProvider[] | Fns) => {
        captured = providersOrFns as HostProvider[];
        return new Promise<SandboxExecuteResult>(() => {}); // sandbox ignores its own timeout
      },
    };
    const staging = fakeStagingProvider();
    const guarded = createGuardedExecutor(base, {
      stagingProvider: staging.provider,
      docsProvider: DOCS_PROVIDER,
      limits: { hostTimeoutMs: 20, maxUpstreamCalls: 200 },
    });
    const out = await guarded.execute("c", [
      openapiHost(async () => {
        upstreamHits++;
        return "r";
      }),
    ]);
    expect(out).toEqual({
      result: undefined,
      error: "Execution exceeded the host-side deadline of 20 ms and was abandoned",
    });
    // The abandoned sandbox is still alive; its later upstream calls are refused.
    const late = host(captured, "__openapiHost").request!({});
    await expect(late).rejects.toBeInstanceOf(ToolError);
    await expect(late).rejects.toThrow(/passed its host-side deadline; further upstream calls are refused/);
    await expect(host(captured, "__stagingHost").stageFromUpstreamJson!({}, "data")).rejects.toThrow(
      /host-side deadline/,
    );
    expect(upstreamHits).toBe(0);
    expect(staging.hits).toEqual([]);
  });

  it("clears its timer when the run completes normally", async () => {
    vi.useFakeTimers();
    const { base } = makeRecordingBase(async () => "fast");
    const guarded = createGuardedExecutor(base, {
      stagingProvider: null,
      docsProvider: DOCS_PROVIDER,
      limits: { hostTimeoutMs: 75_000, maxUpstreamCalls: 200 },
    });
    expect(await guarded.execute("c", [])).toEqual({ result: "fast" });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("never rejects: a throwing base executor resolves with its message in `error`", async () => {
    const guarded = createGuardedExecutor(
      {
        execute: async () => {
          throw new Error("loader exploded");
        },
      },
      { stagingProvider: null, docsProvider: DOCS_PROVIDER, limits: LIMITS },
    );
    expect(await guarded.execute("c", [])).toEqual({ result: undefined, error: "loader exploded" });
  });

  it("bounds the legacy Record form by the deadline too", async () => {
    const guarded = createGuardedExecutor(
      { execute: () => new Promise<SandboxExecuteResult>(() => {}) },
      { stagingProvider: null, docsProvider: DOCS_PROVIDER, limits: { hostTimeoutMs: 20, maxUpstreamCalls: 1 } },
    );
    const out = await guarded.execute("c", { f: async () => 1 });
    expect(out.error).toMatch(/host-side deadline of 20 ms/);
  });
});

describe("init() wiring of the executor guard (F-4, F-12)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  const stagingEnv = () => ({
    STAGING_D1: new FakeD1() as unknown as D1Database,
    STAGING_R2: {},
    STAGING_UPLOAD_ORIGIN: "https://x.test",
  });

  it("tools/list advertises `search` as read-only (and `execute` not)", async () => {
    const { client, close } = await connectToAgentServer(namedProvider);
    const tools = (await client.listTools()).tools;
    expect(tools.find((t) => t.name === "search")!.annotations?.readOnlyHint).toBe(true);
    expect(tools.find((t) => t.name === "execute")!.annotations?.readOnlyHint).not.toBe(true);
    await close();
  });

  it("with staging bound, the search sandbox has no __stagingHost while the execute sandbox does", async () => {
    stubExecutorWithNodeEval();
    const { client, close } = await connectToAgentServer(namedProvider, stagingEnv());
    const inSearch = await callToolText(client, "search", {
      code: "async () => typeof __stagingHost",
    });
    const inExecute = await callToolText(client, "execute", {
      code: "async () => typeof __stagingHost",
    });
    expect(inSearch).toContain("undefined");
    expect(inExecute).toContain("object");
    await close();
  });

  it("reads the limits from env: EXECUTE_MAX_UPSTREAM_CALLS=1 refuses the second codemode.request", async () => {
    stubExecutorWithNodeEval();
    vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetchSpy);
    const provider = {
      ...namedProvider,
      spec: { openapi: "3.0.0", info: { title: "T", version: "1" }, paths: { "/w": { get: { operationId: "listW", responses: {} } } } },
      surfaceReview: { listW: { decision: "allow", category: "standard_read" } },
    } as unknown as ApiProvider;
    const { client, close } = await connectToAgentServer(
      provider,
      {
        EXECUTE_MAX_UPSTREAM_CALLS: "1",
        TOKEN_BROKER: { idFromName: (n: string) => n, get: () => ({ async getOrRefreshAccessToken() { return "AT"; } }) },
      },
      { props: { userId: "u1", refreshToken: "RT" } },
    );
    const out = await callToolText(client, "execute", {
      code: `async () => {
        await codemode.request({ method: "GET", path: "/w" });
        try { await codemode.request({ method: "GET", path: "/w" }); return "second-allowed"; }
        catch (e) { return "second-refused: " + e.message; }
      }`,
    });
    expect(out).toContain("second-refused: upstream call budget exceeded: at most 1 upstream requests per execution");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    await close();
  });

  it("an invalid EXECUTE_HOST_TIMEOUT_MS fails init() loudly", async () => {
    const agent = makeStubAgent(namedProvider, { envOverrides: { EXECUTE_HOST_TIMEOUT_MS: "soon" } });
    await expect(agent.init()).rejects.toThrow(/EXECUTE_HOST_TIMEOUT_MS: must be a positive integer/);
  });
});

describe("MCP session principal binding (F-16)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  /** partyserver's real setName needs workerd state; stub the parent so the
   *  override's own decision is what is under test. */
  function spyParentSetName() {
    return vi
      .spyOn(McpAgent.prototype as unknown as { setName: (n: string, p?: unknown) => Promise<void> }, "setName")
      .mockResolvedValue(undefined);
  }

  it("init() stores the binding for the principal it was started with", async () => {
    const storage = makeStorage();
    const agent = makeStubAgent(namedProvider, { props: { userId: "u1" }, storage });
    await agent.init();
    expect(storage.map.get(SESSION_PRINCIPAL_KEY)).toEqual({ principal: "u1" });
    expect(agent.sessionPrincipal).toBe("u1");
  });

  it("init() records null for a principal-less session", async () => {
    const storage = makeStorage();
    await makeStubAgent(namedProvider, { props: {}, storage }).init();
    expect(storage.map.get(SESSION_PRINCIPAL_KEY)).toEqual({ principal: null });
  });

  it("a later init() (restart/eviction) keeps the ORIGINAL binding rather than re-recording", async () => {
    const storage = makeStorage({ [SESSION_PRINCIPAL_KEY]: { principal: "u1" } });
    const agent = makeStubAgent(namedProvider, { props: { userId: "u2" }, storage });
    await agent.init();
    expect(storage.map.get(SESSION_PRINCIPAL_KEY)).toEqual({ principal: "u1" });
    expect(agent.sessionPrincipal).toBe("u1");
  });

  it("init() uses the provider's audit principal accessor when it has one", async () => {
    const storage = makeStorage();
    const provider = {
      ...namedProvider,
      audit: { principalIdAccessor: (p: Record<string, unknown>) => p.sub as string | undefined },
    } as unknown as ApiProvider;
    await makeStubAgent(provider, { props: { userId: "ignored", sub: "sub-1" }, storage }).init();
    expect(storage.map.get(SESSION_PRINCIPAL_KEY)).toEqual({ principal: "sub-1" });
  });

  it("setName: the same principal passes through to the parent with the request's props", async () => {
    const parent = spyParentSetName();
    const agent = makeStubAgent(namedProvider, {
      storage: makeStorage({ [SESSION_PRINCIPAL_KEY]: { principal: "u1" } }),
    });
    const props = { userId: "u1", refreshToken: "RT-2" };
    await expect(agent.setName("streamable-http:s1", props)).resolves.toBeUndefined();
    expect(parent).toHaveBeenCalledWith("streamable-http:s1", props);
  });

  it("setName: a different principal is refused and never reaches the parent", async () => {
    const parent = spyParentSetName();
    const agent = makeStubAgent(namedProvider, {
      storage: makeStorage({ [SESSION_PRINCIPAL_KEY]: { principal: "u1" } }),
    });
    await expect(agent.setName("streamable-http:s1", { userId: "u2" })).rejects.toThrow(
      "mcp-session-principal-mismatch: this MCP session belongs to a different user",
    );
    await expect(agent.setName("streamable-http:s1", {})).rejects.toThrow(/principal-mismatch/);
    expect(parent).not.toHaveBeenCalled();
  });

  it("setName: no stored binding yet (new or pre-binding session) passes", async () => {
    const parent = spyParentSetName();
    const agent = makeStubAgent(namedProvider);
    await agent.setName("streamable-http:s1", { userId: "anyone" });
    expect(parent).toHaveBeenCalledTimes(1);
  });

  it("setName: props === undefined (internal bootstrap) skips the check", async () => {
    const parent = spyParentSetName();
    const agent = makeStubAgent(namedProvider, {
      storage: makeStorage({ [SESSION_PRINCIPAL_KEY]: { principal: "u1" } }),
    });
    await agent.setName("streamable-http:s1");
    expect(parent).toHaveBeenCalledWith("streamable-http:s1", undefined);
  });

  it("buildUpstreamArgs refuses once this.props resolves to a different principal than the binding", async () => {
    stubExecutorWithNodeEval();
    vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const mintSpy = vi.fn(async () => "AT");
    const { client, close, agent } = await connectToAgentServer(
      namedProvider,
      { TOKEN_BROKER: { idFromName: (n: string) => n, get: () => ({ getOrRefreshAccessToken: mintSpy }) } },
      { props: { userId: "u1", refreshToken: "RT" } },
    );
    agent.props = { userId: "u2", refreshToken: "RT-other" };
    const out = await callToolText(client, "execute", {
      code: 'async () => codemode.request({ method: "GET", path: "/Invoices" })',
    });
    expect(out).toContain("MCP session principal changed; reconnect");
    expect(mintSpy).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
    await close();
  });
});
