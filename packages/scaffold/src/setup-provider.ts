import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import type { ApiProvider } from "./api-provider";
import { assertSecrets, type ScaffoldSecrets } from "./config";
import { createOAuthHandler } from "./oauth-handler";
import { createProviderMcpAgent, type ProviderEnv } from "./mcp-agent-factory";

/**
 * One-stop setup: returns the McpAgent DO class and the OAuthProvider default handler
 * for the worker entry to re-export.
 *
 * Usage in `apps/<deployment>/src/index.ts`:
 *
 *     export const { McpAgent: XeroMCP, default: OAuthHandler } = setupProvider(xeroProvider);
 *     export default OAuthHandler;
 *
 * The returned `default` handler wraps the underlying `OAuthProvider` so that
 * `assertSecrets(env)` runs at the top of every `fetch` invocation (I4 — fail
 * the first request after a misconfigured deploy with a clear message instead
 * of an opaque cookie-decrypt failure inside `/authorize`).
 */
export function setupProvider<
  P extends Record<string, unknown>,
  Env extends ProviderEnv = ProviderEnv,
>(provider: ApiProvider<P, Env>) {
  const McpAgentClass = createProviderMcpAgent(provider);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const authHandler = createOAuthHandler(provider as any);

  const oauth = new OAuthProvider({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    apiHandler: (McpAgentClass as any).serve("/mcp", { binding: "MCP_OBJECT" }),
    apiRoute: "/mcp",
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/token",
    clientRegistrationEndpoint: "/register",
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    defaultHandler: authHandler as any,
  });

  const wrapped = {
    fetch(
      request: Request,
      env: Env,
      ctx: ExecutionContext,
    ): Response | Promise<Response> {
      assertSecrets(env as ScaffoldSecrets);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (oauth as any).fetch(request, env, ctx);
    },
  };

  return {
    McpAgent: McpAgentClass,
    default: wrapped,
  };
}
