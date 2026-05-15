// `agents` is pinned to an exact version in package.json — minor bumps
// to this package can change McpAgent lifecycle behaviour and silently
// break the request-handler interception chain. When upgrading:
//   1. bump the pin in every manifest that declares it
//   2. run `pnpm install`
//   3. run the full test suite — focus on request-handler.test.ts and
//      mcp-agent-factory tests
//   4. manual smoke: /authorize → tool call → audit emission, confirm
//      AUDIT log lines emit after a successful tool call (and the
//      Worker-Loader integration repro at
//      scripts/repros/elicit-als-context/codemode-pattern/ still
//      passes its toggle matrix).

/* AGENTS-INTERNALS-COUPLINGS (cloudflare/agents@0.12.4 — two couplings remain)
 *
 * 1. agentContext re-entry across Worker-Loader child→host RPC
 *    Site: import + agentContext.run wrap below.
 *    Upstream: cloudflare/agents#1490 (open)
 *
 * 2. Server._jsonSchemaValidator swap (codemode forwarding gap)
 *    Site: end of init(), `this.server.server._jsonSchemaValidator = …`
 *    Upstream: cloudflare/agents#1491 (open, codemode-side)
 *
 * Cleanup gate: when #1490 and #1491 close and we update `agents` past
 * the version that includes their fixes, drop both couplings on one
 * branch with a smoke pass across Claude Code, Inspector, and Claude
 * Desktop (accept / decline / cancel / timeout).
 *
 * History: the third coupling (transport.send monkey-patch for
 * cc-elicit no-channel silent drop) was removed when its upstream fix
 * landed in agents 0.12.4 (PR #1514).
 */

import { McpAgent } from "agents/mcp";
import { __DO_NOT_USE_WILL_BREAK__agentContext as agentContext } from "agents";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CfWorkerJsonSchemaValidator } from "@modelcontextprotocol/sdk/validation/cfworker";
import { DynamicWorkerExecutor } from "@cloudflare/codemode";
import { openApiMcpServer } from "@cloudflare/codemode/mcp";
import type { ApiProvider } from "./api-provider";
import { handleUpstreamRequest } from "./request-handler";

export interface ProviderEnv extends Record<string, unknown> {
  LOADER: WorkerLoader;
  OAUTH_KV: KVNamespace;
  DEPLOYMENT_NAME: string;
  /** wrangler.jsonc `vars.ALLOW_PII_IN_LOGS` — `"true"` opts back in to
   *  raw PII in audit lines and DEBUG-ELICIT output. Default redacts. */
  ALLOW_PII_IN_LOGS?: string;
  /** wrangler.jsonc `vars.DEBUG_ELICIT` — `"true"` enables the
   *  DEBUG-ELICIT log sites (Step 3 / M2). Default disabled. */
  DEBUG_ELICIT?: string;
}

/** Returns a constructor suitable for use as a Durable Object class.
 *  The returned class extends `McpAgent` and is parameterised by `provider`. */
export function createProviderMcpAgent<
  P extends Record<string, unknown>,
  Env extends ProviderEnv = ProviderEnv,
>(provider: ApiProvider<P, Env>) {
  return class ProviderMCP extends McpAgent<Env, Record<string, never>, P> {
    server: McpServer = new McpServer({
      name: provider.name,
      version: "0.1.0",
    });

    async init(): Promise<void> {
      const executor = new DynamicWorkerExecutor({
        loader: this.env.LOADER,
        timeout: 70_000,
      });

      const agent = this;
      this.server = openApiMcpServer({
        spec: provider.spec as unknown as Record<string, unknown>,
        executor,
        // INVARIANT: agentContext store contents must be host-side references only.
        // Never include child-supplied (RPC-arg-derived) values here.
        request: (ctx) => {
          return agentContext.run(
            { agent, connection: undefined, request: undefined, email: undefined },
            () => handleUpstreamRequest({
              ctx,
              spec: provider.spec,
              surfaceReview: provider.surfaceReview,
              props: this.props as P,
              apiBaseUrl: provider.apiBaseUrl,
              deploymentName: this.env.DEPLOYMENT_NAME,
              server: this.server,
              env: this.env,
              oauth: {
                refreshTokenAccessor: (p) => p.refreshToken as string,
                clientId: this.env[provider.oauth.clientIdSecretName] as unknown as string,
                clientSecret: this.env[provider.oauth.clientSecretSecretName] as unknown as string,
                tokenUrl: provider.oauth.tokenUrl,
                storage: this.ctx.storage,
                rotation: provider.tokenRotation ?? "static",
              },
              ...(provider.requestHeaders
                ? { requestHeaders: provider.requestHeaders }
                : {}),
              ...(provider.elicitRenderers ? { elicitRenderers: provider.elicitRenderers } : {}),
              audit: {
                waitUntil: this.ctx.waitUntil.bind(this.ctx),
                ...(provider.audit?.principalIdAccessor
                  ? { principalIdAccessor: provider.audit.principalIdAccessor }
                  : {}),
                ...(provider.audit?.contextAccessor
                  ? { contextAccessor: provider.audit.contextAccessor }
                  : {}),
              },
            }),
          );
        },
      });

      // Workers runtime forbids `new Function` / `eval`, which the MCP SDK's
      // default AjvJsonSchemaValidator uses to compile elicit-response
      // validators. Swap in @cfworker/json-schema (no codegen) for the
      // server's inner Server instance. Codemode's openApiMcpServer doesn't
      // expose the constructor option, so we replace the field directly.
      // TODO: graduate this into the codemode patch (forward jsonSchemaValidator).
      (this.server.server as unknown as { _jsonSchemaValidator: unknown })._jsonSchemaValidator =
        new CfWorkerJsonSchemaValidator();
    }
  };
}
