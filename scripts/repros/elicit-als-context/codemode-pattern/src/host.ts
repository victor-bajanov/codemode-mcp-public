import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { scaffoldMini, makeLoaderExecutor, type MiniSpec } from "./scaffold-mini";
import { onRequest } from "./elicit-gate";

export interface Env {
  LOADER: WorkerLoader;
  MCP_OBJECT: DurableObjectNamespace;
}

/**
 * Regression guard — mirrors the production `openApiMcpServer({ executor, request })`
 * shape from `packages/scaffold/src/mcp-agent-factory.ts`.
 *
 * Asserts the two upstream fixes hold:
 *   - agents#1734: transport retains its owning McpAgent, so server-initiated
 *     elicit works from a Worker-Loader child callback WITHOUT an agentContext.run
 *     re-entry (no "Agent was not found in send" error).
 *   - codemode 0.3.8: openApiMcpServer defaults to the MCP SDK's Workers-safe
 *     CfWorkerJsonSchemaValidator, so the accept path validates WITHOUT a manual
 *     _jsonSchemaValidator swap (no "Code generation from strings disallowed" error).
 *
 * Two scenarios (controlled by verify.mjs's TRIGGER_VALIDATION flag):
 *   node verify.mjs                  -> delete_thing, decline path (no content to validate)
 *   TRIGGER_VALIDATION=1 node verify.mjs -> delete_thing, accept path (content validated)
 *
 * Both must pass (tool-success, no ALS error, no AJV error) — any failure is a regression.
 */
export class ReproMCP extends McpAgent<Env, Record<string, never>, Record<string, never>> {
  // Placeholder — replaced in init() with the scaffolded server.
  server: McpServer = new McpServer({ name: "elicit-als-codemode-pattern-placeholder", version: "0.0.1" });

  async init(): Promise<void> {
    const spec: MiniSpec = {
      operations: [
        { name: "delete_thing", destructive: true, description: "Delete a thing (destructive)." },
        { name: "list_things", destructive: false, description: "List things (read-only)." },
      ],
    };

    const executor = makeLoaderExecutor(this.env.LOADER);

    // No agentContext.run wrap — agents#1734 means the transport retains its
    // owning McpAgent so server-initiated elicit works without ALS re-entry.
    // No _jsonSchemaValidator swap — codemode 0.3.8 defaults to the Workers-safe
    // CfWorkerJsonSchemaValidator so the accept path validates without codegen.
    this.server = scaffoldMini({
      spec,
      executor,
      request: (ctx) => {
        console.log(`BEFORE-LOADER op=${ctx.operationName}`);
        return onRequest(ctx, this.server);
      },
    });
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export default (ReproMCP as any).serve("/mcp", { binding: "MCP_OBJECT" });
