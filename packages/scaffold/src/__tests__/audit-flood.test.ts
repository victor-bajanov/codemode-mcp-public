// packages/scaffold/src/__tests__/audit-flood.test.ts
//
// B-2 (audit-line flood) and C-2 (sandbox console forgery) end to end
// (2026-11 review, wave 4): the audit trail cannot be drowned by sandbox-sized
// lines, spammed with capped deny lines, or forged from the sandbox.
//
// Attacker: (3) prompt-injected LLM code inside a valid `execute` run (or
//   `search`), with (2) an authenticated user framing another one.
// Precondition: a session; nothing else.
// Payloads: `codemode.request({ method: "GET", path: "/" + "A".repeat(300_000) })`
//   (denied before any gate, mint or approval); the same with control
//   characters and lone surrogates (each escapes to 6 bytes of JSON); a
//   200 000-char method; 300 such requests in one run, then the activity the
//   attacker wants unrecorded; 200 refused requests launched in parallel;
//   `console.info("AUDIT …")` / `console.debug` / `table` / `trace` from the
//   sandbox; a brace-escaping program that runs at module scope of the
//   generated executor.js, before codemode's console overrides.
// Control: the sink caps every sandbox-reachable field in code points
//   (method 32, path 1024 + `pathLength`); the handler refuses an oversize
//   method/path at entry (`oversize-method-or-path`) before matching; the
//   guard's per-run denial budget (`maxDeniedCalls`) refuses further calls
//   without reaching the handler, with one `denial-budget-exceeded` summary,
//   and an in-flight semaphore keeps parallel launches inside it; the
//   `__docsHost` provider's prelude rebinds every console method codemode
//   does not capture to its capturing `console.log`; code codemode cannot
//   wrap is refused before it reaches the sandbox (`code-not-parseable`).
// Why the pre-fix code failed it: one denied request wrote a 300 KB line
//   (past the platform's 256 KB per-invocation log budget) so every later
//   line of the run was dropped; a run could write a deny line per call up to
//   the 1 000-call budget; `console.info` from the sandbox reached the real
//   console byte-identical to an `auditLog()` line; unbalanced braces made
//   codemode splice the source in raw, at module scope, before any prelude.
// Line sizes: a line is bounded per field in CODE POINTS, and JSON escaping
//   can make it ~6× the cap in bytes — the assertions below bound bytes only
//   where the payload is ASCII, and bound code points otherwise.
//
// Real code under test: handleUpstreamRequest, createGuardedExecutor with
// the real buildDocsHostFns provider, the real DynamicWorkerExecutor
// (generated executor.js compiled in Node by a fake WorkerLoader), the real
// audit sink. Only the upstream `fetch` and the broker are faked.

import { describe, it, expect, vi, afterEach } from "vitest";
import { DynamicWorkerExecutor, type ToolDispatcher } from "@cloudflare/codemode";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "../request-handler";
import { auditLog, createAuditSink, AUDIT_METHOD_MAX, AUDIT_PATH_MAX } from "../audit";
import { ToolError } from "../elicit";
import {
  buildDocsHostFns,
  createGuardedExecutor,
  type HostProvider,
  type SandboxExecutor,
} from "../mcp-agent-factory";
import { SANDBOX_CONSOLE_PRELUDE } from "../sandbox-console";

/** Cloudflare Workers: max log data recorded per invocation. */
const WORKERS_LOG_BUDGET_BYTES = 256 * 1024;
const DEPLOYMENT = "test-deployment";

const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  paths: { "/v1/messages": { get: { operationId: "listMessages", responses: {} } } },
} as never;
const SR = { listMessages: { decision: "allow" as const } };

type Line = Record<string, unknown>;

function captureAudit() {
  const raw: string[] = [];
  vi.spyOn(console, "log").mockImplementation((l: unknown) => {
    if (typeof l === "string" && l.startsWith("AUDIT ")) raw.push(l);
  });
  const lines = (): Line[] => raw.map((s) => JSON.parse(s.slice(6)) as Line);
  const bytes = (s: string) => new TextEncoder().encode(s).byteLength;
  return { raw, lines, bytes };
}

function handlerArgs(ctx: unknown, mint = vi.fn(async () => "AT")): HandleArgs<Record<string, unknown>> {
  return {
    ctx: ctx as UpstreamCtx,
    spec: SPEC,
    surfaceReview: SR,
    apiBaseUrl: "https://api.example",
    deploymentName: DEPLOYMENT,
    props: { userId: "victim-sub", refreshToken: "RT" },
    server: {} as never,
    oauth: {
      refreshTokenAccessor: (p) => p.refreshToken as string,
      userIdAccessor: () => "victim-sub",
      broker: { getOrRefreshAccessToken: mint },
    },
    audit: { principalIdAccessor: () => "victim-sub" },
    env: {},
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("FIXED (B-2): sandbox-controlled audit lines are capped and refused at entry", () => {
  it("a denied GET /AAAA…(300 000) writes a capped line, never reaches the matcher, and the real activity's line follows intact", async () => {
    const a = captureAudit();
    const upstream = vi.fn(async () => new Response('{"messages":[]}', { status: 200 }));
    vi.stubGlobal("fetch", upstream);
    const mint = vi.fn(async () => "AT");

    // Step 1 — the flood, refused at entry (not "No operation found": the
    // matcher never saw it) before any mint.
    const flood = "/" + "A".repeat(300_000);
    const err = await handleUpstreamRequest(handlerArgs({ method: "GET", path: flood }, mint)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).message).toBe("codemode.request method or path is too long");
    expect(upstream).not.toHaveBeenCalled();
    expect(mint).not.toHaveBeenCalled();

    // Step 2 — the activity the attacker wanted unrecorded.
    const res = (await handleUpstreamRequest(handlerArgs({ method: "GET", path: "/v1/messages" }, mint))) as { success: boolean };
    expect(res.success).toBe(true);

    expect(a.raw).toHaveLength(2);
    const [floodLine, realLine] = a.lines() as [Line & { path: string }, Line];
    expect(floodLine).toMatchObject({
      deployment: DEPLOYMENT,
      method: "GET",
      decision: "deny",
      category: "malformed",
      reason: "oversize-method-or-path",
      pathLength: 300_001,
      principalId: "victim-sub",
    });
    expect([...floodLine.path]).toHaveLength(AUDIT_PATH_MAX);
    expect(floodLine.path.endsWith("…")).toBe(true);
    expect(floodLine.path.startsWith("/" + "A".repeat(1022))).toBe(true);
    expect(a.raw[0]).not.toContain("A".repeat(1025));
    // ASCII payload: the whole line is well under 2 KB, so the platform's
    // per-invocation budget is nowhere near.
    expect(a.bytes(a.raw[0]!)).toBeLessThan(2048);
    expect(realLine).toMatchObject({ decision: "allow", operationId: "listMessages", upstreamStatus: 200, principalId: "victim-sub" });
    expect(a.bytes(a.raw[0]!) + a.bytes(a.raw[1]!)).toBeLessThan(WORKERS_LOG_BUDGET_BYTES);
  });

  it.each([
    ["C0 control characters", "\u0001"],
    ["lone surrogates", "\ud800"],
    ["astral code points", "\u{1F4A9}"],
  ])("a 300 000-code-point path of %s is cut to 1024 code points; the line is bounded per field, not per byte", async (_label, unit) => {
    const a = captureAudit();
    const flood = "/" + unit.repeat(300_000);
    await expect(handleUpstreamRequest(handlerArgs({ method: "GET", path: flood }))).rejects.toThrow("too long");
    expect(a.raw).toHaveLength(1);
    const line = a.lines()[0] as Line & { path: string };
    expect(line).toMatchObject({ reason: "oversize-method-or-path", pathLength: 300_001 });
    expect([...line.path]).toHaveLength(AUDIT_PATH_MAX);
    expect(line.path.endsWith("…")).toBe(true);
    // JSON.stringify writes a control character or lone surrogate as a
    // 6-byte \uXXXX escape and an astral code point raw as 4 bytes of UTF-8,
    // so the line is bounded by the cap × 6 plus the fixed fields (~6.3 KB
    // at worst) — far below the platform budget, but NOT "< 2 KB".
    expect(a.bytes(a.raw[0]!)).toBeLessThan(AUDIT_PATH_MAX * 6 + 1024);
    expect(a.bytes(a.raw[0]!)).toBeLessThan(WORKERS_LOG_BUDGET_BYTES / 32);
  });

  it("a 200 000-char method is refused at entry and logged as 32 code points; a 32-char method with contentType 42 keeps its own reason", async () => {
    const a = captureAudit();
    const mint = vi.fn(async () => "AT");
    await expect(
      handleUpstreamRequest(handlerArgs({ method: "M".repeat(200_000), path: "/x", contentType: 42 }, mint)),
    ).rejects.toThrow("codemode.request method or path is too long");
    expect(a.raw).toHaveLength(1);
    const line = a.lines()[0] as Line & { method: string };
    expect(line).toMatchObject({ reason: "oversize-method-or-path", path: "/x" });
    expect([...line.method]).toHaveLength(AUDIT_METHOD_MAX);
    expect(line.method).toBe("M".repeat(AUDIT_METHOD_MAX - 1) + "…");
    expect(a.bytes(a.raw[0]!)).toBeLessThan(2048);
    expect(line).not.toHaveProperty("pathLength");

    // At the cap, the method passes the entry check and the next malformed
    // check speaks: the attacker cannot pick which reason is recorded.
    await expect(
      handleUpstreamRequest(handlerArgs({ method: "M".repeat(AUDIT_METHOD_MAX), path: "/x", contentType: 42 }, mint)),
    ).rejects.toThrow(/contentType/);
    expect(a.lines()[1]).toMatchObject({ method: "M".repeat(AUDIT_METHOD_MAX), reason: "invalid-content-type" });
    expect(mint).not.toHaveBeenCalled();
  });

  it("a direct auditLog() with a 300 KB path is capped too: the sink, not the handler, is the control", () => {
    const a = captureAudit();
    auditLog({ deployment: DEPLOYMENT, method: "GET", path: "/" + "B".repeat(300_000), decision: "deny", reason: "no-op-match", ts: "t" });
    const line = a.lines()[0] as Line & { path: string };
    expect([...line.path]).toHaveLength(AUDIT_PATH_MAX);
    expect(line.pathLength).toBe(300_001);
    expect(a.bytes(a.raw[0]!)).toBeLessThan(2048);
  });
});

/** The guarded executor as init() builds it, driving the REAL handler through
 *  `__openapiHost.request`; `sandbox` is the "LLM code" a base executor runs. */
function guardedRun(
  sandbox: (request: (ctx: unknown) => Promise<unknown>) => Promise<unknown>,
  limits: { maxUpstreamCalls: number; maxDeniedCalls: number },
) {
  const base: SandboxExecutor = {
    async execute(_code, providers) {
      const host = (providers as HostProvider[]).find((p) => p.name === "__openapiHost")!;
      return { result: await sandbox(host.fns.request!) };
    },
  };
  const executor = createGuardedExecutor(base, {
    stagingProvider: null,
    docsProvider: buildDocsHostFns(() => "docs"),
    limits: { hostTimeoutMs: 10_000, ...limits },
    audit: createAuditSink({ deployment: DEPLOYMENT, principalId: "victim-sub" }),
  });
  const request = async (ctx: unknown) => handleUpstreamRequest(handlerArgs(ctx));
  return () => executor.execute("/* llm code */", [{ name: "__openapiHost", fns: { request } }]);
}

describe("FIXED (B-2): the per-run denial budget stops a flood of capped deny lines", () => {
  it("40 unmatched requests under maxDeniedCalls 32: the handler sees 32, calls 33–40 are refused unseen, one summary line, a new run starts fresh", async () => {
    const a = captureAudit();
    const upstream = vi.fn(async () => new Response('{"messages":[]}', { status: 200 }));
    vi.stubGlobal("fetch", upstream);
    const errors: Error[] = [];
    const run = guardedRun(async (request) => {
      for (let i = 0; i < 40; i++) {
        try {
          await request({ method: "GET", path: `/nope/${i}` });
        } catch (e) {
          errors.push(e as Error);
        }
      }
      return errors.length;
    }, { maxUpstreamCalls: 1_000, maxDeniedCalls: 32 });

    const out = await run();
    expect(out.error).toBeUndefined();
    expect(errors).toHaveLength(40);
    for (const e of errors.slice(0, 32)) expect(e.message).toMatch(/^No operation found for GET \/nope\//);
    for (const e of errors.slice(32)) {
      expect(e).toBeInstanceOf(ToolError);
      expect(e.message).toBe(
        "too many refused requests in this execution: after 32 refused calls every further request is refused",
      );
    }
    const lines = a.lines();
    expect(lines.filter((l) => l.reason === "no-op-match")).toHaveLength(32);
    const summaries = lines.filter((l) => l.reason === "denial-budget-exceeded");
    expect(summaries).toHaveLength(1);
    expect(summaries[0]).toMatchObject({
      deployment: DEPLOYMENT,
      method: "RUN",
      path: "execute",
      decision: "deny",
      category: "malformed",
      principalId: "victim-sub",
    });
    expect(lines).toHaveLength(33);
    expect(upstream).not.toHaveBeenCalled();

    // A fresh run: the budget is per run, and allowed calls do not count.
    errors.length = 0;
    const second = guardedRun(async (request) => {
      const ok: unknown[] = [];
      for (let i = 0; i < 5; i++) ok.push(await request({ method: "GET", path: "/v1/messages" }));
      try {
        await request({ method: "GET", path: "/nope" });
      } catch (e) {
        errors.push(e as Error);
      }
      return ok.length;
    }, { maxUpstreamCalls: 1_000, maxDeniedCalls: 32 });
    expect((await second()).result).toBe(5);
    expect(errors).toHaveLength(1);
    expect(errors[0]!.message).toMatch(/^No operation found/);
    expect(upstream).toHaveBeenCalledTimes(5);
    expect(a.lines().filter((l) => l.reason === "denial-budget-exceeded")).toHaveLength(1);
  });

  it("300 oversize-path requests in one run write 33 bounded lines, far under the platform budget; the next run's real activity is intact", async () => {
    const a = captureAudit();
    const upstream = vi.fn(async () => new Response('{"messages":[]}', { status: 200 }));
    vi.stubGlobal("fetch", upstream);
    const flood = "/" + "A".repeat(300_000);
    const refused: string[] = [];
    const run = guardedRun(async (request) => {
      for (let i = 0; i < 300; i++) {
        try {
          await request({ method: "GET", path: flood });
        } catch (e) {
          refused.push((e as Error).message);
        }
      }
      // The attacker's real activity in the SAME run is refused too: a run
      // that spent its denial budget is over.
      try {
        await request({ method: "GET", path: "/v1/messages" });
      } catch (e) {
        refused.push((e as Error).message);
      }
      return refused.length;
    }, { maxUpstreamCalls: 1_000, maxDeniedCalls: 32 });
    await run();
    expect(refused).toHaveLength(301);
    expect(refused.filter((m) => m === "codemode.request method or path is too long")).toHaveLength(32);
    expect(refused.filter((m) => m.startsWith("too many refused requests in this execution"))).toHaveLength(269);
    expect(upstream).not.toHaveBeenCalled();

    const total = a.raw.reduce((n, s) => n + a.bytes(s), 0);
    expect(a.raw).toHaveLength(33);
    expect(total).toBeLessThan(WORKERS_LOG_BUDGET_BYTES / 4);
    for (const l of a.lines().slice(0, 32)) expect(l).toMatchObject({ reason: "oversize-method-or-path", pathLength: 300_001 });
    expect(a.lines()[32]).toMatchObject({ reason: "denial-budget-exceeded" });

    // The next run (next tool call) records the real activity in full.
    const next = guardedRun(async (request) => request({ method: "GET", path: "/v1/messages" }), { maxUpstreamCalls: 1_000, maxDeniedCalls: 32 });
    expect(((await next()).result as { success: boolean }).success).toBe(true);
    expect(a.lines().at(-1)).toMatchObject({ decision: "allow", operationId: "listMessages", upstreamStatus: 200 });
  });

  it("200 refused requests launched in parallel: at most 2 × maxDeniedCalls reach the handler, one summary line", async () => {
    const a = captureAudit();
    const outcomes: string[] = [];
    const run = guardedRun(async (request) => {
      await Promise.all(
        Array.from({ length: 200 }, (_, i) =>
          request({ method: "GET", path: `/nope/${i}` }).then(
            () => outcomes.push("ok"),
            (e: Error) => outcomes.push(e.message.startsWith("too many refused") ? "budget" : "handler"),
          ),
        ),
      );
      return outcomes.length;
    }, { maxUpstreamCalls: 1_000, maxDeniedCalls: 32 });
    await run();
    expect(outcomes).toHaveLength(200);
    expect(outcomes.filter((o) => o === "ok")).toHaveLength(0);
    const reached = a.lines().filter((l) => l.reason === "no-op-match").length;
    expect(reached).toBe(outcomes.filter((o) => o === "handler").length);
    expect(reached).toBeGreaterThanOrEqual(32);
    expect(reached).toBeLessThanOrEqual(64);
    expect(a.lines().filter((l) => l.reason === "denial-budget-exceeded")).toHaveLength(1);
    expect(a.raw).toHaveLength(reached + 1);
  });
});

// --- C-2: the real codemode executor, generated executor.js compiled in Node ---

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

/** LLM code through the guard (as init() wires it: real __docsHost provider,
 *  real DynamicWorkerExecutor, fake loader), restoring the process-wide
 *  console the generated module overrides in Node. */
async function runGuardedSandbox(llmCode: string, tool: "execute" | "search") {
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
  const guardLines: Line[] = [];
  const base = new DynamicWorkerExecutor({ loader: loader as never, timeout: 70_000 });
  const executor = createGuardedExecutor(base as never, {
    stagingProvider: null,
    docsProvider: buildDocsHostFns(() => "docs"),
    limits: { hostTimeoutMs: 10_000, maxUpstreamCalls: 100, maxDeniedCalls: 32 },
    audit: (e) => guardLines.push(e as Line),
  });
  const providers: HostProvider[] =
    tool === "execute" ? [{ name: "__openapiHost", fns: { request: async () => ({ success: true }) } }] : [];
  const realConsole = globalThis.console;
  const snapshot = Object.getOwnPropertyDescriptors(realConsole);
  try {
    const out = await executor.execute(llmCode, providers);
    return { out, loads, guardLines };
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

// A program codemode cannot wrap: unbalanced braces close evaluate() and the
// class, so the rest would run at module scope of executor.js, before the
// console overrides and before any prelude.
const BRACE_ESCAPE =
  "})()); } })()]); } catch (e) {} return { result: 'x', logs: [] }; } }\n" +
  'console.info("AUDIT {\\"decision\\":\\"allow\\",\\"principalId\\":\\"VICTIM\\"}");\n' +
  "class __Z { async m() { try { await Promise.race([(async () => { async () => { return f(await (async () => {";

describe("FIXED (C-2): sandbox console output never reaches the host log, end to end through the guard", () => {
  it.each(["execute", "search"] as const)(
    "console.info/debug/table/trace forgeries from a %s run land in the run's `logs`, not on the host console",
    async (tool) => {
      // Control: what a genuine audit line looks like.
      const hostLines: string[] = [];
      const logSpy = vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => void hostLines.push(a.map(String).join(" ")));
      auditLog(FORGED);
      logSpy.mockRestore();
      const real = hostLines.find((l) => l.startsWith("AUDIT "))!;
      expect(real).toBeDefined();

      const sink: string[] = [];
      for (const m of ["info", "debug", "table", "trace"] as const) {
        vi.spyOn(console, m).mockImplementation((...a: unknown[]) => void sink.push(a.map(String).join(" ")));
      }
      const { out, loads, guardLines } = await runGuardedSandbox(
        `async () => {
           const forged = "AUDIT " + JSON.stringify(${JSON.stringify(FORGED)});
           console.log(forged);
           console.info(forged);
           console.debug(forged);
           console.table(forged);
           console.trace(forged);
           return "ok";
         }`,
        tool,
      );
      expect(out.error).toBeUndefined();
      expect(out.result).toBe("ok");
      expect(sink).toEqual([]);
      expect(out.logs).toEqual([real, real, real, real, real]);
      expect(guardLines).toEqual([]);
      // The generated module carries the prelude between codemode's third
      // override and the LLM code, on every run (search included).
      expect(loads).toHaveLength(1);
      const src = loads[0]!.modules["executor.js"]!;
      const preludeAt = src.indexOf(SANDBOX_CONSOLE_PRELUDE);
      expect(preludeAt).toBeGreaterThan(src.indexOf("console.error = ("));
      expect(preludeAt).toBeLessThan(src.indexOf("const forged ="));
    },
  );

  it.each(["execute", "search"] as const)(
    "a brace-escaping %s program is refused before any sandbox is loaded, audited as code-not-parseable; no forged line reaches console.info",
    async (tool) => {
      const sink: string[] = [];
      vi.spyOn(console, "info").mockImplementation((...a: unknown[]) => void sink.push(a.map(String).join(" ")));
      const { out, loads, guardLines } = await runGuardedSandbox(BRACE_ESCAPE, tool);
      expect(out).toEqual({ result: undefined, error: "code is not valid JavaScript" });
      expect(loads).toHaveLength(0);
      expect(sink).toEqual([]);
      expect(guardLines).toEqual([
        { method: "RUN", path: tool, decision: "deny", category: "malformed", reason: "code-not-parseable" },
      ]);
    },
  );

  it("REFUTED: an ordinary program still runs through the guard and can call the host", async () => {
    const { out, guardLines } = await runGuardedSandbox(
      "async () => { const r = await __openapiHost.request({ method: 'GET', path: '/x' }); return r.success ? 'called' : 'no'; }",
      "execute",
    );
    expect(out.error).toBeUndefined();
    expect(out.result).toBe("called");
    expect(guardLines).toEqual([]);
  });
});
