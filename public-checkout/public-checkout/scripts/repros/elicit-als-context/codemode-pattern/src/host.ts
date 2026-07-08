import { McpAgent } from "agents/mcp";
import { __DO_NOT_USE_WILL_BREAK__agentContext as agentContext } from "agents";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CfWorkerJsonSchemaValidator } from "@modelcontextprotocol/sdk/validation/cfworker";
import { scaffoldMini, makeLoaderExecutor, type MiniSpec } from "./scaffold-mini";
import { onRequest } from "./elicit-gate";

export interface Env {
  LOADER: WorkerLoader;
  MCP_OBJECT: DurableObjectNamespace;
  WRAP: string;
  VALIDATOR: string;
}

/**
 * Realistic repro — mirrors the production `openApiMcpServer({ executor, request })`
 * shape from `packages/scaffold/src/mcp-agent-factory.ts`.
 *
 * Two independent toggles, both off by default:
 *   WRAP=1                 — apply the agentContext.run wrap (ALS fix)
 *   VALIDATOR=cfworker     — swap the SDK's default AjvJsonSchemaValidator
 *                            for CfWorkerJsonSchemaValidator (AJV-codegen fix)
 *
 * Combined with verify.mjs's TRIGGER_VALIDATION flag (which controls whether
 * the mock MCP client returns content), the harness exercises:
 *   WRAP=0                                              -> ALS bug
 *   WRAP=1, TRIGGER_VALIDATION=0                        -> happy decline path
 *   WRAP=1, TRIGGER_VALIDATION=1                        -> AJV bug
 *   WRAP=1, TRIGGER_VALIDATION=1, VALIDATOR=cfworker    -> happy accept path
 *
 * INVARIANT: agentContext store contents are HOST-SIDE references only.
 * Never include child-supplied (RPC-arg-derived) values here.
 */
export class ReproMCP extends McpAgent<Env, Record<string, never>, Record<string, never>> {
  // Placeholder — replaced in init() with the scaffolded server.
  server: McpServer = new McpServer({ name: "elicit-als-codemode-pattern-placeholder", version: "0.0.1" });

  async init(): Promise<void> {
    const agent = this;
    const wrap =
      this.env.WRAP === "1"
        ? (cb: () => Promise<unknown>) =>
            agentContext.run(
              { agent, connection: undefined, request: undefined, email: undefined },
              cb,
            )
        : (cb: () => Promise<unknown>) => cb();

    const spec: MiniSpec = {
      operations: [
        { name: "delete_thing", destructive: true, description: "Delete a thing (destructive)." },
        { name: "list_things", destructive: false, description: "List things (read-only)." },
      ],
    };

    const executor = makeLoaderExecutor(this.env.LOADER);

    this.server = scaffoldMini({
      spec,
      executor,
      request: (ctx) => {
        const alsBefore = agentContext.getStore() ? "set" : "unset";
        console.log(`BEFORE-LOADER op=${ctx.operationName} ALS=${alsBefore}`);
        return wrap(() => onRequest(ctx, agent.server));
      },
    });

    // Optional AJV-vs-Workers workaround. Unconditional in production
    // (packages/scaffold/src/mcp-agent-factory.ts); conditional here so the
    // harness can demonstrate both modes.
    if (this.env.VALIDATOR === "cfworker") {
      (this.server.server as unknown as { _jsonSchemaValidator: unknown })._jsonSchemaValidator =
        new CfWorkerJsonSchemaValidator();
    }
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export default (ReproMCP as any).serve("/mcp", { binding: "MCP_OBJECT" });
