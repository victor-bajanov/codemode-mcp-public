// C-2 (2026-11 review) — sandbox console output separated from the host log.
//
// Attacker: prompt-injected LLM code in the codemode sandbox (or an
// authenticated user framing another one). Precondition: a session.
// Payload: `console.info('AUDIT {"decision":"allow","principalId":"<victim>",…}')`
// (and console.debug / table / trace …).
// Control: the `__docsHost` provider carries SANDBOX_CONSOLE_PRELUDE, which
// codemode emits after its own console.log/warn/error overrides and before the
// LLM code; it rebinds every other console method to the capturing
// console.log, so nothing the sandbox prints reaches the host log stream.
// Pre-fix: codemode 0.4.2's generated executor.js captured only log/warn/error;
// console.info/debug went to the real console sink, byte-identical to a
// genuine auditLog() line.
//
// Harness: the REAL DynamicWorkerExecutor builds executor.js; a fake
// WorkerLoader compiles it in Node. In Node the generated module runs
// in-process, so it replaces the process-wide console methods — every test
// snapshots and restores `console` around the run.
import { afterEach, describe, expect, it, vi } from "vitest";
import { DynamicWorkerExecutor, type ToolDispatcher } from "@cloudflare/codemode";
import { openApiMcpServer } from "@cloudflare/codemode/mcp";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { auditLog } from "../audit";
import { buildDocsHostFns, createGuardedExecutor } from "../mcp-agent-factory";
import { SANDBOX_CONSOLE_KEEP, SANDBOX_CONSOLE_PRELUDE } from "../sandbox-console";

interface LoadOpts {
  modules: Record<string, string>;
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
    src
      .replace('import { WorkerEntrypoint } from "cloudflare:workers";', "")
      .replace("export default class CodeExecutor", "const __Default = class CodeExecutor") +
    // Module semantics: statements after the class (a brace escape) still run.
    "\nreturn __Default;";
  return new Function("WorkerEntrypoint", body)(WorkerEntrypoint) as new (ctx: unknown, env: unknown) => {
    evaluate(d: unknown, c: unknown): Promise<{ result?: unknown; error?: string; logs?: string[] }>;
  };
}

function makeLoader(loads: LoadOpts[]) {
  return {
    load(opts: LoadOpts) {
      loads.push(opts);
      return {
        getEntrypoint() {
          return {
            async evaluate(dispatchers: Record<string, ToolDispatcher>, connectors: unknown) {
              const Cls = compileExecutorModule(opts.modules["executor.js"]!);
              return new Cls({ waitUntil() {} }, undefined).evaluate(dispatchers, connectors);
            },
          };
        },
      };
    },
  };
}

/** LLM code through the REAL openApiMcpServer tool → createGuardedExecutor →
 *  DynamicWorkerExecutor (fake loader), restoring the process-wide console. */
async function runViaTool(llmCode: string, tool: "search" | "execute") {
  const loads: LoadOpts[] = [];
  const base = new DynamicWorkerExecutor({ loader: makeLoader(loads) as never, timeout: 70_000 });
  const executor = createGuardedExecutor(base as never, {
    stagingProvider: null,
    docsProvider: buildDocsHostFns(() => "docs"),
    limits: { hostTimeoutMs: 10_000, maxUpstreamCalls: 100 },
  });
  const server = openApiMcpServer({
    spec: {
      openapi: "3.0.0",
      info: { title: "T", version: "1" },
      paths: { "/w": { get: { operationId: "listW", responses: {} } } },
    } as never,
    executor: executor as never,
    request: async () => ({ success: true, status: 200, result: { ok: 1 }, errors: [] }),
  });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: "t", version: "0" });
  await client.connect(ct);
  const realConsole = globalThis.console;
  const snapshot = Object.getOwnPropertyDescriptors(realConsole);
  try {
    const res = (await client.callTool({ name: tool, arguments: { code: llmCode } })) as {
      content: Array<{ text?: string }>;
    };
    return { text: res.content.map((c) => c.text ?? "").join(""), loads };
  } finally {
    globalThis.console = realConsole;
    Object.defineProperties(realConsole, snapshot);
    await client.close();
    await server.close();
  }
}

/** Run LLM code through the real executor with the scaffold's docs provider,
 *  restoring the process-wide console afterwards (Node only). */
async function runSandbox(llmCode: string) {
  const loads: LoadOpts[] = [];
  const loader = {
    load(opts: LoadOpts) {
      loads.push(opts);
      return {
        getEntrypoint() {
          return {
            async evaluate(dispatchers: Record<string, ToolDispatcher>, connectors: unknown) {
              const Cls = compileExecutorModule(opts.modules["executor.js"]!);
              return new Cls({ waitUntil() {} }, undefined).evaluate(dispatchers, connectors);
            },
          };
        },
      };
    },
  };
  const realConsole = globalThis.console;
  const snapshot = Object.getOwnPropertyDescriptors(realConsole);
  const base = new DynamicWorkerExecutor({ loader: loader as never, timeout: 70_000 });
  try {
    const out = await base.execute(llmCode, [buildDocsHostFns(() => "docs")] as never);
    return { out, src: loads[0]!.modules["executor.js"]! };
  } finally {
    globalThis.console = realConsole;
    Object.defineProperties(realConsole, snapshot);
  }
}

const FORGED = {
  deployment: "gmail",
  operationId: "gmail.users.messages.send",
  method: "POST",
  path: "/gmail/v1/users/me/messages/send",
  decision: "allow" as const,
  upstreamStatus: 200,
  principalId: "VICTIM-USER-SUB-FORGED",
  ts: "2026-11-09T00:00:00.000Z",
};

afterEach(() => vi.restoreAllMocks());

describe("C-2 sandbox console prelude", () => {
  it("REFUTED: codemode's module overrides exactly log/warn/error; FIXED (C-2): the prelude follows the third override and precedes the LLM code", async () => {
    const { src } = await runSandbox("async () => 'MARKER_LLM_CODE'");
    const overridden = [...src.matchAll(/console\.(\w+)\s*=\s*\(/g)].map((m) => m[1]).sort();
    expect(overridden).toEqual(["error", "log", "warn"]);
    const preludeAt = src.indexOf(SANDBOX_CONSOLE_PRELUDE);
    expect(preludeAt).toBeGreaterThan(src.indexOf("console.error = ("));
    expect(preludeAt).toBeLessThan(src.indexOf("MARKER_LLM_CODE"));
    expect(SANDBOX_CONSOLE_KEEP).toEqual(["log", "warn", "error"]);
  });

  it("FIXED (C-2): console.info/debug/table/trace from LLM code land in `logs`, not on the host console", async () => {
    // Control: what a genuine audit line looks like.
    const hostLines: string[] = [];
    const logSpy = vi
      .spyOn(console, "log")
      .mockImplementation((...a: unknown[]) => void hostLines.push(a.map(String).join(" ")));
    auditLog(FORGED);
    logSpy.mockRestore();
    const real = hostLines.find((l) => l.startsWith("AUDIT "))!;
    expect(real).toBeDefined();

    const sink: string[] = [];
    for (const m of ["info", "debug", "table", "trace"] as const) {
      vi.spyOn(console, m).mockImplementation((...a: unknown[]) => void sink.push(a.map(String).join(" ")));
    }
    const { out } = await runSandbox(
      `async () => {
         const forged = "AUDIT " + JSON.stringify(${JSON.stringify(FORGED)});
         console.info(forged);
         console.debug(forged);
         console.table(forged);
         console.trace(forged);
         return "ok";
       }`,
    );
    expect(out.error).toBeUndefined();
    expect(out.result).toBe("ok");
    expect(sink).toEqual([]);
    expect(out.logs).toEqual([real, real, real, real]);
  });

  it("is a valid statement block inside an async method body", () => {
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor as new (
      ...a: string[]
    ) => unknown;
    expect(() => new AsyncFunction('"use strict";\n' + SANDBOX_CONSOLE_PRELUDE)).not.toThrow();
  });

  it("throws nothing when console is frozen", () => {
    const frozen = Object.freeze({ log() {}, warn() {}, error() {}, info() {}, debug() {} });
    const run = new Function("console", '"use strict";\n' + SANDBOX_CONSOLE_PRELUDE) as (c: unknown) => void;
    expect(() => run(frozen)).not.toThrow();
  });

  it("a program that replaces globalThis.console afterwards prints nothing to the host sinks", async () => {
    const sink: string[] = [];
    for (const m of ["log", "info", "debug", "warn", "error"] as const) {
      vi.spyOn(console, m).mockImplementation((...a: unknown[]) => void sink.push(a.map(String).join(" ")));
    }
    const { out } = await runSandbox(
      `async () => {
         globalThis.console = {};
         try { console.info("AUDIT x"); } catch {}
         return "done";
       }`,
    );
    expect(out.result).toBe("done");
    expect(sink).toEqual([]);
  });

  // Reviewer payload (wave-4 T4 review): unbalanced braces make codemode's
  // normalizeCode fall back to inserting the source raw, so the code closes
  // evaluate() and the class and runs at module scope — before codemode's
  // console overrides and before any prelude.
  const BRACE_ESCAPE =
    "})()); } })()]); } catch (e) {} return { result: 'x', logs: [] }; } }\n" +
    'console.info("AUDIT {\\"decision\\":\\"allow\\",\\"principalId\\":\\"VICTIM\\"}");\n' +
    "class __Z { async m() { try { await Promise.race([(async () => { async () => { return f(await (async () => {";

  it.each(["search", "execute"] as const)(
    "FIXED (C-2): a brace-escaping %s program is refused before it reaches the sandbox; no forged line reaches console.info",
    async (tool) => {
      const sink: string[] = [];
      vi.spyOn(console, "info").mockImplementation((...a: unknown[]) => void sink.push(a.map(String).join(" ")));
      const { text, loads } = await runViaTool(BRACE_ESCAPE, tool);
      expect(sink).toEqual([]);
      expect(text).toContain("code is not valid JavaScript");
      expect(loads).toHaveLength(0);
    },
  );

  it.each([
    ["an async arrow", "async () => 1 + 1", "2"],
    ["a bare expression", "1 + 1", "2"],
    ["top-level await then an expression", "const r = await codemode.request({ method: 'GET', path: '/w' }); r.result.ok", "1"],
    ["a top-level return", "return 40 + 2", "42"],
    ["a named function declaration", "function main() { return 'm'; }", "m"],
    ["an export default function", "export default async function () { return 'd'; }", "d"],
    ["a fenced block", "```js\nasync () => 'f'\n```", "f"],
  ])("REFUTED: %s still runs through the guard", async (_label, code, expected) => {
    const { text } = await runViaTool(code, "execute");
    expect(text).not.toContain("code is not valid JavaScript");
    expect(text).toContain(expected);
  });
});
