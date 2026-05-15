/**
 * scaffold-mini — a tiny analog of the real `openApiMcpServer({ executor, request })`
 * factory in `packages/scaffold/src/mcp-agent-factory.ts`. It exists only to give
 * the codemode-pattern repro the same wrap shape the production scaffold has:
 *
 *   server = scaffoldMini({ spec, executor, request })
 *
 * Each operation in `spec.operations` becomes a registered MCP tool whose handler
 * dispatches through `executor.execute(codeBlob, { dispatcher })`. The code blob
 * runs inside a Worker-Loader child isolate; it calls back into the host via
 * `dispatcher.call({ operationName, params })`. Mirrors the exact RPC severance
 * pattern that breaks `agentContext` ALS in production.
 *
 * The host wrap (`request: (ctx) => agentContext.run(..., () => onRequest(ctx, server))`)
 * is the fix — same as `mcp-agent-factory.ts`.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { RpcTarget } from "cloudflare:workers";
import { z } from "zod";

export interface OperationSpec {
  name: string;
  description?: string;
  destructive?: boolean;
}

export interface MiniSpec {
  operations: OperationSpec[];
}

/** Body of the child Worker that scaffoldMini loads to dispatch each call.
 *  Mirrors how `DynamicWorkerExecutor` evaluates user-supplied code that calls
 *  `dispatcher.call(...)` — the call lands on the host as a fresh entrypoint. */
const CHILD_MODULE_SOURCE = `
import { WorkerEntrypoint } from "cloudflare:workers";
export default class ScaffoldMiniChild extends WorkerEntrypoint {
  async invoke(dispatcher, operationName, params) {
    return await dispatcher.call({ operationName, params });
  }
}
`;

/** Host-side dispatcher passed to the child via Worker-Loader RPC.
 *  Equivalent to `ToolDispatcher` in the real scaffold. */
class ToolDispatcher extends RpcTarget {
  #request: (ctx: { operationName: string; params: unknown }) => Promise<unknown>;
  constructor(request: (ctx: { operationName: string; params: unknown }) => Promise<unknown>) {
    super();
    this.#request = request;
  }
  async call(ctx: { operationName: string; params: unknown }): Promise<unknown> {
    return await this.#request(ctx);
  }
}

export interface Executor {
  /** Loads a child Worker and invokes `invoke(dispatcher, operationName, params)` on it. */
  execute(operationName: string, params: unknown, dispatcher: ToolDispatcher): Promise<unknown>;
}

export interface ScaffoldMiniArgs {
  spec: MiniSpec;
  executor: Executor;
  /** Per-request hook. The production scaffold wraps this in `agentContext.run(...)`. */
  request: (ctx: { operationName: string; params: unknown }) => Promise<unknown>;
}

export function scaffoldMini({ spec, executor, request }: ScaffoldMiniArgs): McpServer {
  const server = new McpServer({ name: "elicit-als-codemode-pattern", version: "0.0.1" });

  for (const op of spec.operations) {
    server.registerTool(
      op.name,
      {
        description:
          op.description ??
          `Mini-scaffold operation ${op.name}` +
            (op.destructive ? " (destructive — gated by elicit)" : ""),
        inputSchema: { input: z.unknown().optional() },
      },
      async (args) => {
        const dispatcher = new ToolDispatcher(request);
        try {
          const result = await executor.execute(op.name, args, dispatcher);
          return {
            content: [{ type: "text", text: `OK ${JSON.stringify(result)}` }],
          };
        } catch (err) {
          const e = err as { name?: string; message?: string };
          const name = e?.name ?? "Error";
          const message = e?.message ?? String(err);
          console.log(`SCAFFOLD-ERROR ${op.name} ${name}: ${message}`);
          return {
            content: [{ type: "text", text: `ERROR ${name}: ${message}` }],
            isError: true,
          };
        }
      },
    );
  }

  return server;
}

/** Returns an Executor backed by the env.LOADER Worker-Loader binding.
 *  Mirrors `DynamicWorkerExecutor` from `@cloudflare/codemode` — minus the
 *  user-supplied code blob layer (we inline a fixed dispatcher-call). */
export function makeLoaderExecutor(loader: WorkerLoader): Executor {
  return {
    async execute(operationName, params, dispatcher) {
      const stub = loader.get(`scaffold-mini-${operationName}-${crypto.randomUUID()}`, () => ({
        compatibilityDate: "2025-03-10",
        compatibilityFlags: ["nodejs_compat"],
        mainModule: "child.js",
        modules: { "child.js": CHILD_MODULE_SOURCE },
        globalOutbound: null,
      }));
      const ep = stub.getEntrypoint() as unknown as {
        invoke: (d: ToolDispatcher, name: string, p: unknown) => Promise<unknown>;
      };
      return await ep.invoke(dispatcher, operationName, params);
    },
  };
}
