// D9 — What LLM code can put on a `codemode.request` ctx (issue #59, D11, plan B6).
//
// Attacker: LLM-authored (or prompt-injected) sandbox code calling
//   `codemode.request(...)` with fields the request handler treats as
//   host-internal — `bypassTruncate` (R3 found it sandbox-settable; B10
//   records the pre-fix behaviour) — or with a text segment too large to be
//   assembled.
// Precondition: the REAL pipeline — `createProviderMcpAgent(...).init()`
//   builds the openApiMcpServer `request` closure (which applies
//   `pickSandboxCtx`), `createGuardedExecutor` wraps a real
//   `DynamicWorkerExecutor`, and B1's fake WorkerLoader compiles codemode's
//   generated `executor.js` in Node so the LLM code runs through codemode's
//   own sandbox template and ToolDispatcher.
// Payloads: `{ bypassTruncate: true }` from LLM code; `composed` from LLM
//   code; a 5 MiB text segment from LLM code and a 100 MiB one host-side;
//   a non-object ctx; a ctx with inherited (prototype) fields.
// Control: only the documented request fields, as own properties, reach
//   the handler (`bypassTruncate` is dropped so the result is truncated as
//   usual); `composed` is forwarded; the text cap (4 MiB) refuses before any
//   storage access.
//
// Pre-v2 reasoning: before D11 the factory forwarded the sandbox ctx object
// verbatim, so `bypassTruncate: true` from LLM code returned the untruncated
// upstream body (B10's "honoured when set by the sandbox"). Adding
// "bypassTruncate" back to SANDBOX_CTX_FIELDS (verified by mutation) fails
// the first probe.
//
// FakeD1/FakeR2 only; `fetch` is stubbed. No network.
import { describe, it, expect, vi, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { ToolDispatcher } from "@cloudflare/codemode";
import { createProviderMcpAgent, pickSandboxCtx } from "../../mcp-agent-factory";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "../../request-handler";
import { ToolError } from "../../elicit";
import type { ApiProvider } from "../../api-provider";
import { FakeD1 } from "../../staging/__tests__/__fixtures__/fake-d1";
import { FakeR2 } from "../../staging/__tests__/__fixtures__/fake-r2";
import { COMPOSED_MAX_TEXT_BYTES } from "../../compose/validate";
import { RESPONSE_CHAR_CAP } from "../../descriptions/fragments";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";

// --- B1's real-sandbox harness: a fake WorkerLoader that compiles the ---
// --- generated executor.js in Node (see B1 for the fidelity caveats). ---
interface LoadOpts {
  mainModule: string;
  modules: Record<string, string>;
  env: unknown;
}

function compileExecutorModule(src: string) {
  class WorkerEntrypoint {
    ctx: unknown;
    env: unknown;
    constructor(ctx: unknown, env: unknown) {
      this.ctx = ctx;
      this.env = env;
    }
  }
  expect(src.startsWith('import { WorkerEntrypoint } from "cloudflare:workers";')).toBe(true);
  const body =
    '"use strict";\n' +
    src.replace('import { WorkerEntrypoint } from "cloudflare:workers";', "").replace("export default class CodeExecutor", "return class CodeExecutor");
  return new Function("WorkerEntrypoint", body)(WorkerEntrypoint) as new (ctx: unknown, env: unknown) => {
    evaluate(d: unknown, c: unknown): Promise<{ result?: unknown; error?: string; logs?: string[] }>;
  };
}

function makeFakeLoader() {
  return {
    load(opts: LoadOpts) {
      return {
        getEntrypoint() {
          return {
            async evaluate(dispatchers: Record<string, ToolDispatcher>, connectors: unknown) {
              const Cls = compileExecutorModule(opts.modules["executor.js"]!);
              const inst = new Cls({ waitUntil() {} }, opts.env);
              return inst.evaluate(dispatchers, connectors);
            },
          };
        },
      };
    },
  };
}

const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  paths: {
    "/w": { get: { operationId: "listW", responses: {} } },
    "/att/{n}": { put: { operationId: "attach", responses: {} } },
  },
} as unknown as OpenApiSpec;

const provider = {
  name: "poc-provider",
  displayName: "POC",
  oauth: {} as never,
  spec: SPEC,
  surfaceReview: {
    listW: { decision: "allow", category: "standard_read" },
    attach: { decision: "allow", category: "standard_write" },
  },
  apiBaseUrl: "https://api.example.com",
} as unknown as ApiProvider;

/** The agent's real init() over minimal env/props/ctx stubs (as the factory
 *  tests do), with B1's fake loader as `env.LOADER`. */
async function connect(envOverrides: Record<string, unknown> = {}) {
  const AgentClass = createProviderMcpAgent(provider);
  const agent = Object.create(AgentClass.prototype) as {
    env: Record<string, unknown>;
    props: Record<string, unknown>;
    ctx: unknown;
    init: () => Promise<void>;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    server: any;
  };
  const storage = new Map<string, unknown>();
  agent.env = {
    LOADER: makeFakeLoader(),
    DEPLOYMENT_NAME: "poc",
    TOKEN_BROKER: { idFromName: (n: string) => n, get: () => ({ async getOrRefreshAccessToken() { return "AT"; } }) },
    ...envOverrides,
  };
  agent.props = { userId: "u1", refreshToken: "RT" };
  agent.ctx = {
    waitUntil() {},
    storage: { get: async (k: string) => storage.get(k), put: async (k: string, v: unknown) => void storage.set(k, v) },
  };
  await agent.init();
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await agent.server.connect(st);
  const client = new Client({ name: "poc", version: "0" });
  await client.connect(ct);
  const execute = async (code: string): Promise<string> => {
    const res = (await client.callTool({ name: "execute", arguments: { code } })) as { content: Array<{ text?: string }> };
    return res.content.map((c) => c.text ?? "").join("");
  };
  return {
    execute,
    close: async () => {
      await client.close();
      await agent.server.close();
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("D9 — the factory's ctx whitelist, through the real sandbox pipeline", () => {
  it("FIXED (#59): `bypassTruncate: true` from LLM code does not reach the handler — the result is truncated as usual", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const big = "x".repeat(RESPONSE_CHAR_CAP * 4);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ big }), { status: 200, headers: { "content-type": "application/json" } })),
    );
    const { execute, close } = await connect();
    const out = await execute(`async () => {
      const r = await codemode.request({ method: "GET", path: "/w", bypassTruncate: true });
      return { len: JSON.stringify(r.result).length, success: r.success };
    }`);
    await close();
    const parsed = JSON.parse(out) as { len: number; success: boolean };
    expect(parsed.success).toBe(true);
    expect(parsed.len).toBeLessThan(big.length); // truncateForReturn applied despite the sandbox's flag
    // Control: the handler itself still honours the flag for the host-internal
    // stageFromUpstreamJson path — the whitelist is what keeps it internal.
    const direct = (await handleUpstreamRequest({
      ...hostArgs({ method: "GET", path: "/w", bypassTruncate: true }),
    })) as { result: { big: string } };
    expect(direct.result.big.length).toBe(big.length);
  });

  it("FIXED (#59): `composed` from LLM code reaches the handler and is assembled by the host (bytes never cross the sandbox)", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const sent: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_u: unknown, init?: RequestInit) => {
        const body = init?.body as ReadableStream<Uint8Array>;
        const chunks: Uint8Array[] = [];
        const reader = body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
        }
        sent.push(Buffer.concat(chunks).toString());
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      }),
    );
    const { execute, close } = await connect({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      STAGING_R2: new FakeR2() as unknown as R2Bucket,
      STAGING_UPLOAD_ORIGIN: "https://x.test",
    });
    const out = await execute(`async () => {
      const put = await __stagingHost.putFile(btoa("hello-from-r2"), "text/plain", "h.txt");
      const r = await codemode.request({ method: "PUT", path: "/att/h.txt",
        composed: { segments: [{ staged: { file_handle: put.file_handle, token: put.token }, encoding: "identity" }] } });
      return r.success;
    }`);
    await close();
    expect(out).toBe("true");
    expect(sent).toEqual(["hello-from-r2"]);
  });

  it("FIXED (#59): a 5 MiB text segment from LLM code is refused by the text cap, with no fetch", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const { execute, close } = await connect({
      STAGING_D1: new FakeD1() as unknown as D1Database,
      STAGING_R2: new FakeR2() as unknown as R2Bucket,
      STAGING_UPLOAD_ORIGIN: "https://x.test",
    });
    const out = await execute(`async () => {
      try {
        await codemode.request({ method: "PUT", path: "/att/x", composed: { segments: [{ text: "x".repeat(5 * 1024 * 1024) }] } });
        return "sent";
      } catch (e) { return "refused: " + e.message; }
    }`);
    await close();
    expect(out).toContain(`refused: \`composed\` text segments exceed ${COMPOSED_MAX_TEXT_BYTES} bytes in total`);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("FIXED (#59): host-side, a 100 MiB text segment is refused before any storage access (it could never cross RPC anyway)", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const d1 = new FakeD1();
    let prepares = 0;
    const origPrepare = d1.prepare.bind(d1);
    d1.prepare = (sql: string) => {
      prepares += 1;
      return origPrepare(sql);
    };
    const openStaged = vi.fn();
    const err = await handleUpstreamRequest({
      ...hostArgs({ method: "PUT", path: "/att/x", composed: { segments: [{ text: "x".repeat(100 * 1024 * 1024) }] } }),
      openStaged: openStaged as never,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toContain(String(COMPOSED_MAX_TEXT_BYTES));
    expect(prepares).toBe(0);
    expect(openStaged).not.toHaveBeenCalled();
  });

  it("REFUTED: only own, documented fields survive pickSandboxCtx; inherited and host-internal names are dropped", () => {
    const ctx = Object.assign(Object.create({ bypassTruncate: true, method: "GET" }), {
      path: "/w",
      composed: { segments: [{ text: "x" }] },
      relatedRequestId: 7,
      openStaged: () => {},
      transferGate: {},
      signal: new AbortController().signal,
      runKey: {},
      stagingStore: {},
      stagingLimits: { composeMaxBytes: 1 },
      env: { ALLOW_PII_IN_LOGS: "true" },
      props: { userId: "someone-else" },
    });
    expect(pickSandboxCtx(ctx)).toEqual({ path: "/w", composed: { segments: [{ text: "x" }] } });
    expect(pickSandboxCtx("GET /w")).toEqual({});
    expect(pickSandboxCtx([{ method: "GET", path: "/w" }])).toEqual({});
  });

  it("REFUTED: a non-object ctx from LLM code is refused as malformed, not treated as a request", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const { execute, close } = await connect();
    const out = await execute(`async () => {
      try { await codemode.request("GET /w"); return "sent"; } catch (e) { return "refused: " + e.message; }
    }`);
    await close();
    expect(out).toContain("refused: codemode.request needs string `method` and `path`");
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

function hostArgs(ctx: UpstreamCtx): HandleArgs<Record<string, unknown>> {
  return {
    ctx,
    spec: SPEC,
    surfaceReview: provider.surfaceReview,
    apiBaseUrl: "https://api.example.com",
    deploymentName: "poc",
    props: { refreshToken: "RT", userId: "u1" },
    server: {} as never,
    env: {},
    audit: {},
    oauth: { refreshTokenAccessor: () => "RT", userIdAccessor: () => "u1", broker: { getOrRefreshAccessToken: async () => "AT" } },
  };
}
