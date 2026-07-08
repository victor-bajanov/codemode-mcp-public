import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { RpcTarget } from "cloudflare:workers";
import { z } from "zod";

export interface Env {
  LOADER: WorkerLoader;
  MCP_OBJECT: DurableObjectNamespace;
}

/**
 * RpcTarget passed to the child Worker. The child invokes `runCallback()` via
 * Workers RPC; that call lands on the host as a fresh entrypoint invocation.
 * Pre-agents#1734 the ALS frame was severed here and elicitInput would throw
 * "Agent was not found in send". agents#1734 fixes this by having the transport
 * retain its owning McpAgent directly, so no agentContext.run(...) re-entry is
 * needed.
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
// `bridge.runCallback()` over Workers RPC. The host-bound RPC arrives as a
// fresh entrypoint; agents#1734 ensures the transport still resolves the
// McpAgent without relying on an ALS frame at that entry point.
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

    this.server.registerTool(
      "repro_elicit",
      {
        description:
          "Regression guard for agents#1734. Loads a child Worker and invokes a " +
          "host-side callback from inside. The callback calls server.elicitInput. " +
          "With agents@0.17.1+ the transport retains its owning McpAgent so the " +
          "elicit succeeds WITHOUT any agentContext.run wrap.",
        inputSchema: { message: z.string().optional() },
      },
      async ({ message }) => {
        const promptText = message ?? "Please confirm to continue (regression guard)";

        console.log(`BEFORE-LOADER: entering tool body`);

        // Body of the host-side callback. This is what the child triggers via RPC.
        // agents#1734: the transport now retains its owning McpAgent, so this
        // succeeds without an explicit agentContext.run(...) re-entry wrap.
        const callback = async (): Promise<unknown> => {
          console.log(`INSIDE-CALLBACK: invoking elicitInput (no wrap)`);
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
          // on a fresh entrypoint. With agents#1734 this no longer requires an
          // ALS re-entry wrap on the host side.
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
