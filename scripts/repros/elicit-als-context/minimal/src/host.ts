import { McpAgent } from "agents/mcp";
import { __DO_NOT_USE_WILL_BREAK__agentContext as agentContext } from "agents";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { RpcTarget } from "cloudflare:workers";
import { z } from "zod";

export interface Env {
  LOADER: WorkerLoader;
  MCP_OBJECT: DurableObjectNamespace;
  WRAP: string;
}

/**
 * RpcTarget passed to the child Worker. The child invokes `runCallback()` via
 * Workers RPC; that call lands on the host as a fresh entrypoint invocation
 * with NO ancestor `agentContext.run(...)` frame, which is the heart of the
 * bug being reproduced.
 */
class HostCallbackBridge extends RpcTarget {
  #cb: () => Promise<unknown>;
  constructor(cb: () => Promise<unknown>) {
    super();
    this.#cb = cb;
  }
  async runCallback(): Promise<unknown> {
    return await this.#cb();
  }
}

// Child Worker source — evaluated inside an isolated isolate via env.LOADER.
// It receives the bridge as the first arg to `run()` and immediately invokes
// `bridge.runCallback()` over Workers RPC. That RPC call is what severs the
// AsyncLocalStorage chain on the host side.
const CHILD_MODULE_SOURCE = `
import { WorkerEntrypoint } from "cloudflare:workers";
export default class Child extends WorkerEntrypoint {
  async run(bridge) {
    return await bridge.runCallback();
  }
}
`;

export class ReproMCP extends McpAgent<Env, Record<string, never>, Record<string, never>> {
  server: McpServer = new McpServer({ name: "elicit-als-repro", version: "0.0.1" });

  async init(): Promise<void> {
    const agent = this;
    const wrap = this.env.WRAP === "1";

    this.server.registerTool(
      "repro_elicit",
      {
        description:
          "Loads a child Worker and invokes a host-side callback from inside. " +
          "The callback calls server.elicitInput. With WRAP=1 the host wraps the " +
          "callback in agentContext.run(...) and the elicit succeeds; with WRAP unset " +
          "the elicit throws 'Agent was not found in send'.",
        inputSchema: { message: z.string().optional() },
      },
      async ({ message }) => {
        const promptText = message ?? "Please confirm to continue (repro)";

        const alsBefore = agentContext.getStore() ? "set" : "unset";
        console.log(`BEFORE-LOADER ALS=${alsBefore}`);

        // Body of the host-side callback. This is what the child triggers via RPC.
        const rawBody = async (): Promise<unknown> => {
          const alsInside = agentContext.getStore() ? "set" : "unset";
          console.log(`INSIDE-CALLBACK ALS=${alsInside}`);
          // server-initiated MCP request — fails when ALS is empty because
          // StreamableHTTPServerTransport.send reads `agent` from agentContext.
          const result = await agent.server.server.elicitInput({
            message: promptText,
            requestedSchema: {
              type: "object",
              properties: {
                ok: { type: "boolean", description: "User acknowledgement" },
              },
              required: ["ok"],
            },
          });
          return result;
        };

        // Optional wrap (the fix). The store contents are HOST-SIDE references
        // only — no child-supplied data — matching the trust invariant from
        // packages/scaffold/src/mcp-agent-factory.ts.
        const callback = wrap
          ? () =>
              agentContext.run(
                { agent, connection: undefined, request: undefined, email: undefined },
                () => rawBody(),
              )
          : () => rawBody();

        const bridge = new HostCallbackBridge(callback);

        // Load the child Worker once per call (a unique id keeps it cached but
        // simple to reason about for a repro).
        const stub = this.env.LOADER.get(`elicit-repro-child-${crypto.randomUUID()}`, () => ({
          compatibilityDate: "2025-03-10",
          compatibilityFlags: ["nodejs_compat"],
          mainModule: "child.js",
          modules: {
            "child.js": CHILD_MODULE_SOURCE,
          },
          globalOutbound: null,
        }));

        try {
          // The child invokes the bridge — which triggers a host-bound RPC call
          // on a fresh entrypoint with no ancestor ALS frame.
          const result = await (stub.getEntrypoint() as unknown as {
            run: (b: HostCallbackBridge) => Promise<unknown>;
          }).run(bridge);
          console.log(`ELICIT-RESULT ${JSON.stringify(result)}`);
          return {
            content: [
              { type: "text", text: `OK ${JSON.stringify(result)}` },
            ],
          };
        } catch (err) {
          const e = err as { name?: string; message?: string };
          const name = e?.name ?? "Error";
          const message = e?.message ?? String(err);
          console.log(`ELICIT-ERROR ${name}: ${message}`);
          return {
            content: [
              { type: "text", text: `ERROR ${name}: ${message}` },
            ],
            isError: true,
          };
        }
      },
    );
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export default (ReproMCP as any).serve("/mcp", { binding: "MCP_OBJECT" });
