import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { openApiMcpServer } from "@cloudflare/codemode/mcp";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CfWorkerJsonSchemaValidator } from "@modelcontextprotocol/sdk/validation/cfworker";
import { FakeD1 } from "../staging/__tests__/__fixtures__/fake-d1";
import { registerFileHandleTool } from "../staging";

// TypeScript-only canary — see "agents@0.12.4: __DO_NOT_USE_WILL_BREAK__agentContext
// export and store shape are stable (#1490 canary)" test below.
import type { __DO_NOT_USE_WILL_BREAK__agentContext as agentContextType } from "agents";
import type { AsyncLocalStorage } from "node:async_hooks";
type _StoreShapeStillCompatible =
  typeof agentContextType extends AsyncLocalStorage<infer S>
    ? S extends {
        agent: unknown;
        connection: unknown;
        request: unknown;
        email: unknown;
      }
      ? true
      : never
    : never;
// Force the type to be used (otherwise unused-import lints may strip it):
const _agentContextStoreShapeCanary: _StoreShapeStillCompatible = true;
// biome-ignore lint/correctness/noUnusedVariables: the assignment IS the assertion
void _agentContextStoreShapeCanary;

const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));
const xeroSpec = JSON.parse(
  readFileSync(`${repoRoot}/packages/providers/xero/src/spec.json`, "utf-8"),
) as Record<string, unknown>;
const gmailSpec = JSON.parse(
  readFileSync(`${repoRoot}/packages/providers/gmail/src/spec.json`, "utf-8"),
) as Record<string, unknown>;

// Capturing executor: never evaluates the code argument; instead records the
// namespaces (second arg) that openApiMcpServer passes for each tool invocation.
// Under codemode 0.3.5 the codemode object is fully sandbox-internal (embedded in
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

describe("openApiMcpServer (codemode 0.3.5 contract)", () => {
  it("codemode 0.3.5: search tool passes no external namespaces to executor (codemode is sandbox-internal)", async () => {
    const { executor, getCalls } = makeCapturingExecutor();
    const server = openApiMcpServer({
      spec: xeroSpec,
      executor,
      request: async () => ({}),
    });
    await callSearch(server);

    const calls = getCalls();
    expect(calls).toHaveLength(1);
    // Under 0.3.5, codemode.spec() is fully sandbox-internal — it is constructed
    // inside the generated code string, not passed as an external namespace.
    // The search tool therefore passes an empty namespaces array.
    expect(calls[0]!.namespaces).toHaveLength(0);
    expect(calls[0]!.namespaces.find((n) => n.name === "codemode")).toBeUndefined();
  });

  it("codemode 0.3.5: execute tool passes __openapiHost (not codemode) as the only external namespace", async () => {
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

  // Export-and-shape canary for #1490 (ALS re-entry workaround).
  //
  // This is a TypeScript-only check, not a runtime check. It does NOT
  // verify that mcp-agent-factory.ts actually wraps its request callback
  // in agentContext.run — that's covered by the Worker-Loader integration
  // repro at scripts/repros/elicit-als-context/codemode-pattern/ (manual
  // gate in the upgrade plan).
  //
  // What it DOES catch:
  //   - If a future `agents` bump removes or renames the
  //     __DO_NOT_USE_WILL_BREAK__agentContext export, `pnpm typecheck`
  //     fails at the import below.
  //   - If the AgentContextStore shape loses the `agent` field or any of
  //     the other four fields the scaffold supplies, the conditional type
  //     resolves to `never` and `pnpm typecheck` fails at the
  //     `_StoreShapeStillCompatible` assertion.
  it("agents@0.12.4: __DO_NOT_USE_WILL_BREAK__agentContext export and store shape are stable (#1490 canary)", () => {
    // Compile-time only — the assertion lives in the type system.
    // If typecheck passed, this test passes. If typecheck fails the build
    // never reaches vitest.
    expect(true).toBe(true);
  });

  // SDK-field-writability canary for #1491 (validator swap workaround).
  //
  // This is a unit check on the SDK's field shape, not on whether
  // mcp-agent-factory.ts's init() actually performs the swap. The "does
  // init() do the swap" path is covered by the Worker-Loader integration
  // repro (codemode-pattern) which exercises elicit-accept and would fail
  // with "Code generation from strings disallowed" if the swap didn't run.
  //
  // What this catches:
  //   - If a future SDK bump renames _jsonSchemaValidator or makes it
  //     readonly/constructor-only, the assignment below either fails at
  //     typecheck (rename) or silently no-ops at runtime (the readback
  //     returns undefined and the expect fails).
  it("@modelcontextprotocol/sdk: McpServer._jsonSchemaValidator is writable (#1491 canary)", () => {
    const server = new McpServer({ name: "canary", version: "0.0.0" });
    const validator = new CfWorkerJsonSchemaValidator();
    (server.server as unknown as { _jsonSchemaValidator: unknown })._jsonSchemaValidator = validator;
    expect(
      (server.server as unknown as { _jsonSchemaValidator: unknown })._jsonSchemaValidator,
    ).toBe(validator);
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
