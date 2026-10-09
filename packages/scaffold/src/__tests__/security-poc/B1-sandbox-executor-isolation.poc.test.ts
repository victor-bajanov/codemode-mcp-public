// B1 — What the sandbox Worker actually receives, and what LLM code can reach.
//
// Runs the REAL @cloudflare/codemode 0.4.2 pipeline: openApiMcpServer builds the
// sandbox code (createOpenApiSandboxCode), our factory's wrapper would patch it,
// and DynamicWorkerExecutor assembles `executor.js`. A FAKE WorkerLoader
// captures the `load()` options and evaluates the generated module in Node
// with a shim for `cloudflare:workers`' WorkerEntrypoint. The ToolDispatcher
// instances handed to `evaluate()` are codemode's real class.
//
// Caveat on fidelity: in production `__dispatchers.*` are Workers-RPC stubs,
// so ONLY `call(name, argsJson)` is reachable and args/returns are
// structured-cloned. In Node the LLM code sees the ToolDispatcher object
// itself — anything beyond `.call` that works here would NOT work in workerd,
// so Node results over-approximate reachability; nothing below relies on that.
//
// codemode's 70 s timeout is a `Promise.race` INSIDE the sandbox, so LLM code
// can neuter it; that library behaviour is unchanged and still demonstrated
// below as context. The scaffold now wraps the executor (createGuardedExecutor)
// with a host-side deadline and a per-execution upstream budget, and refuses
// every upstream call an abandoned run makes after the deadline.
//
// Status: FIXED (F-12) — host-side deadline and upstream budget around every
// sandbox run; sandbox isolation REFUTED (holds).
import { describe, it, expect } from "vitest";
import { DynamicWorkerExecutor, ToolDispatcher } from "@cloudflare/codemode";
import { openApiMcpServer } from "@cloudflare/codemode/mcp";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildDocsHostFns, createGuardedExecutor, patchCodemodeDocsAlias } from "../../mcp-agent-factory";

interface LoadOpts {
  compatibilityDate: string;
  compatibilityFlags: string[];
  mainModule: string;
  modules: Record<string, string>;
  globalOutbound: unknown;
  env: unknown;
}

/** Compile the generated executor.js in Node. Module code is strict, so the
 *  Function body is made strict too (matters for the setTimeout test). */
function compileExecutorModule(src: string) {
  class WorkerEntrypoint { ctx: unknown; env: unknown; constructor(ctx: unknown, env: unknown) { this.ctx = ctx; this.env = env; } }
  expect(src.startsWith('import { WorkerEntrypoint } from "cloudflare:workers";')).toBe(true);
  const body =
    '"use strict";\n' +
    src
      .replace('import { WorkerEntrypoint } from "cloudflare:workers";', "")
      .replace("export default class CodeExecutor", "return class CodeExecutor");
  return new Function("WorkerEntrypoint", body)(WorkerEntrypoint) as new (ctx: unknown, env: unknown) => {
    evaluate(d: unknown, c: unknown): Promise<{ result?: unknown; error?: string; logs?: string[] }>;
  };
}

function makeFakeLoader(captured: { opts?: LoadOpts; dispatchers?: Record<string, ToolDispatcher> }) {
  return {
    load(opts: LoadOpts) {
      captured.opts = opts;
      return {
        getEntrypoint() {
          return {
            async evaluate(dispatchers: Record<string, ToolDispatcher>, connectors: unknown) {
              captured.dispatchers = dispatchers;
              const Cls = compileExecutorModule(opts.modules["executor.js"]!);
              // Mirror the runtime: env is whatever load() got (undefined here).
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
  paths: { "/widgets": { get: { operationId: "listWidgets", responses: {} } } },
};

/** Drive the REAL openApiMcpServer `execute` tool so the LLM code goes through
 *  createOpenApiSandboxCode → (our alias patch) → DynamicWorkerExecutor. */
async function runViaExecuteTool(
  llmCode: string,
  opts: {
    timeout?: number;
    extraProviders?: Array<{ name: string; fns: Record<string, (...a: unknown[]) => Promise<unknown>> }>;
    requestFn?: (ctx: unknown) => Promise<unknown>;
    /** Run through the scaffold's createGuardedExecutor instead of the bare
     *  alias-patching wrapper (F-12). */
    guard?: { hostTimeoutMs: number; maxUpstreamCalls?: number };
  } = {},
) {
  const captured: { opts?: LoadOpts; dispatchers?: Record<string, ToolDispatcher> } = {};
  const base = new DynamicWorkerExecutor({ loader: makeFakeLoader(captured) as never, timeout: opts.timeout ?? 70_000 });
  const executor = opts.guard
    ? createGuardedExecutor(base, {
        stagingProvider: null,
        docsProvider: buildDocsHostFns(() => "docs"),
        limits: { hostTimeoutMs: opts.guard.hostTimeoutMs, maxUpstreamCalls: opts.guard.maxUpstreamCalls ?? 200 },
      })
    : {
        execute: (code: string, providers: unknown) =>
          base.execute(patchCodemodeDocsAlias(code), [
            ...(providers as Array<{ name: string; fns: Record<string, (...a: unknown[]) => Promise<unknown>> }>),
            ...(opts.extraProviders ?? []),
          ]),
      };
  const requestCalls: unknown[] = [];
  const server = openApiMcpServer({
    spec: SPEC as never,
    executor: executor as never,
    request: async (ctx: unknown) => {
      requestCalls.push(ctx);
      return opts.requestFn ? opts.requestFn(ctx) : { success: true, status: 200, result: { echoed: ctx }, errors: [] };
    },
  });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: "poc", version: "0" });
  await client.connect(ct);
  const res = (await client.callTool({ name: "execute", arguments: { code: llmCode } })) as {
    content: Array<{ type: string; text?: string }>;
    isError?: boolean;
  };
  await client.close();
  await server.close();
  return { text: res.content.map((c) => c.text ?? "").join(""), isError: res.isError === true, captured, requestCalls };
}

describe("B1 — sandbox Worker configuration (REFUTED: isolation holds)", () => {
  it("the sub-Worker gets no env bindings, no outbound, nodejs_compat, and only executor.js", async () => {
    const { captured } = await runViaExecuteTool("async () => 1");
    const o = captured.opts!;
    expect(o.env).toBeUndefined();                 // no host bindings reach the sandbox
    expect(o.globalOutbound).toBeNull();           // fetch()/connect() blocked at runtime
    expect(o.compatibilityFlags).toEqual(["nodejs_compat"]);
    expect(Object.keys(o.modules)).toEqual(["executor.js"]);
    expect(o.mainModule).toBe("executor.js");
  });

  it("`this` inside LLM code is the sandbox WorkerEntrypoint: env is undefined, not the host env", async () => {
    const { text } = await runViaExecuteTool(
      "async () => ({ env: typeof this.env, ctxKeys: Object.keys(this.ctx ?? {}) })",
    );
    expect(JSON.parse(text)).toEqual({ env: "undefined", ctxKeys: ["waitUntil"] });
  });
});

describe("B1 — raw __dispatchers are lexically reachable (CONFIRMED) but grant nothing extra (REFUTED)", () => {
  it("LLM code can read __dispatchers without any template break-out — it is a free variable of the enclosing evaluate()", async () => {
    const { text } = await runViaExecuteTool(
      "async () => Object.keys(__dispatchers).join(',')",
      { extraProviders: [{ name: "__docsHost", fns: { docs: async () => "docs" } }] },
    );
    // Same names as the Proxy wrappers; nothing hidden.
    expect(text).toBe("__openapiHost,__docsHost");
  });

  it("direct __dispatchers.X.call(...) reaches exactly the declared host fn — equivalent to codemode.request()", async () => {
    const { text, requestCalls } = await runViaExecuteTool(
      `async () => {
        const raw = await __dispatchers.__openapiHost.call("request", JSON.stringify([{ method: "GET", path: "/widgets" }]));
        return JSON.parse(raw);
      }`,
    );
    expect(requestCalls).toEqual([{ method: "GET", path: "/widgets" }]);
    expect(JSON.parse(text).result.success).toBe(true);
  });

  it("prototype-chain names on ToolDispatcher's fns map yield nothing useful (Object.prototype functions called with `this` undefined)", async () => {
    const d = new ToolDispatcher({ request: async () => "declared" });
    const out = new Map<string, string>();
    for (const name of ["constructor", "__proto__", "toString", "hasOwnProperty", "__defineGetter__", "__lookupGetter__", "valueOf", "isPrototypeOf"]) {
      out.set(name, await d.call(name, JSON.stringify(["x"])));
    }
    // `constructor` is Object → Object("x") → a String wrapper → serialises as "x": a pure echo.
    expect(out.get("constructor")).toBe('{"result":"x"}');
    expect(out.get("__proto__")).toMatch(/"error":"fn is not a function"/);
    expect(out.get("toString")).toBe('{"result":"[object Undefined]"}');
    // Strict-mode built-ins throw on `this === undefined`
    expect(out.get("hasOwnProperty")).toMatch(/"error":/);
    expect(out.get("__defineGetter__")).toMatch(/"error":/);
    expect(out.get("__lookupGetter__")).toMatch(/"error":/);
    expect(out.get("valueOf")).toMatch(/"error":/);
    expect(out.get("isPrototypeOf")).toBe('{"result":false}'); // returns false for a non-object arg before reading `this`
    // No prototype name reaches host env/bindings: ToolDispatcher only closes over `fns`.
  });

  it("sanitizeToolName collisions are refused at execute() time, not resolved to the wrong fn", async () => {
    const captured = {};
    const base = new DynamicWorkerExecutor({ loader: makeFakeLoader(captured) as never });
    const r = await base.execute("async () => 1", [
      { name: "p", fns: { "get-file": async () => 1, "get.file": async () => 2 } },
    ]);
    expect(r.error).toMatch(/both sanitize to "get_file"/);
  });
});

describe("B1 — the 70 s execution timeout is sandbox-cooperative (library behaviour; FIXED host-side, F-12)", () => {
  it("context — raw codemode, unchanged: LLM code that reassigns the global setTimeout before its first await never times out", async () => {
    const realSetTimeout = globalThis.setTimeout;
    let evaluated: Promise<unknown> | undefined;
    try {
      evaluated = runViaExecuteTool(
        // Synchronous prefix runs BEFORE the template constructs its timeout
        // promise (Promise.race args evaluate left-to-right), so the
        // `setTimeout(() => reject(...), 30)` in the template is a no-op.
        `async () => {
          setTimeout = () => 0;
          await new Promise((r) => { globalThis.__b1_release = r; });
          return "finished-after-timeout-window";
        }`,
        { timeout: 30 },
      );
      const outcome = await Promise.race([
        evaluated.then(() => "settled"),
        new Promise<string>((r) => realSetTimeout(() => r("still-pending"), 300)),
      ]);
      expect(outcome).toBe("still-pending"); // 300 ms > 30 ms timeout, yet no "Execution timed out"
    } finally {
      globalThis.setTimeout = realSetTimeout;
      (globalThis as unknown as { __b1_release?: () => void }).__b1_release?.();
    }
    const { text } = (await evaluated) as { text: string };
    expect(text).toBe("finished-after-timeout-window");
  });

  it("FIXED (F-12): through createGuardedExecutor the same code is abandoned at the host-side deadline, and its later codemode.request is refused", async () => {
    const realSetTimeout = globalThis.setTimeout;
    const g = globalThis as unknown as { __b1_release?: () => void; __b1_late?: (outcome: string) => void };
    delete g.__b1_release; // left over from the test above
    const lateOutcome = new Promise<string>((r) => { g.__b1_late = r; });
    let evaluated: Promise<{ text: string; isError: boolean; requestCalls: unknown[] }> | undefined;
    const started = performance.now();
    try {
      evaluated = runViaExecuteTool(
        // Same neutering prefix as above, then — once released, long after the
        // host has given up — an upstream call through codemode.request.
        `async () => {
          setTimeout = () => 0;
          await new Promise((r) => { globalThis.__b1_release = r; });
          try {
            await codemode.request({ method: "GET", path: "/widgets" });
            globalThis.__b1_late?.("reached-upstream");
          } catch (e) {
            globalThis.__b1_late?.("refused: " + e.message);
          }
          return "finished-after-timeout-window";
        }`,
        { timeout: 30, guard: { hostTimeoutMs: 50 } },
      );
      const outcome = await Promise.race([
        evaluated.then(() => "settled"),
        new Promise<string>((r) => realSetTimeout(() => r("still-pending"), 300)),
      ]);
      expect(outcome).toBe("settled");                      // the host stopped waiting …
      expect(performance.now() - started).toBeLessThan(300);
      expect(g.__b1_release).toBeTypeOf("function");        // … while the sandbox is still pending
    } finally {
      globalThis.setTimeout = realSetTimeout;
    }
    const { text, isError, requestCalls } = await evaluated!;
    expect(isError).toBe(true);
    expect(text).toBe("Error: Execution exceeded the host-side deadline of 50 ms and was abandoned");
    // Let the abandoned sandbox continue: its upstream call must not get through.
    g.__b1_release?.();
    expect(await lateOutcome).toBe(
      "refused: this execution passed its host-side deadline; further upstream calls are refused",
    );
    expect(requestCalls).toEqual([]);
    delete g.__b1_release;
    delete g.__b1_late;
  });
});
