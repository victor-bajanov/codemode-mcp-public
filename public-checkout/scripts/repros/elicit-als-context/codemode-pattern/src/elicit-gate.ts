/**
 * Tiny analog of `handleUpstreamRequest` in `packages/scaffold/src/request-handler.ts`.
 * The codemode-pattern harness routes every dispatcher.call(...) through this — and for
 * destructive operations gates with `server.server.elicitInput`, which is exactly
 * the moment where ALS-context loss across Worker-Loader RPC manifests.
 */
import { __DO_NOT_USE_WILL_BREAK__agentContext as agentContext } from "agents";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export interface OnRequestCtx {
  operationName: string;
  params: unknown;
}

export async function onRequest(ctx: OnRequestCtx, server: McpServer): Promise<unknown> {
  const alsInside = agentContext.getStore() ? "set" : "unset";
  console.log(`INSIDE-CALLBACK op=${ctx.operationName} ALS=${alsInside}`);

  if (ctx.operationName === "delete_thing") {
    // Destructive — gate with elicit. This is the call that throws
    // "Agent was not found in send" when ALS is empty.
    const result = await server.server.elicitInput({
      message: "Confirm delete_thing?",
      requestedSchema: {
        type: "object",
        properties: {
          confirm: { type: "string", enum: ["yes", "no"] },
        },
        required: ["confirm"],
      },
    });
    console.log(`ELICIT-RESULT ${JSON.stringify(result)}`);
    return { deleted: true, elicit: result };
  }

  return { list: ["thing1", "thing2"] };
}
