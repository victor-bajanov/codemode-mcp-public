import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import type { ApiProvider } from "./api-provider";
import { assertSecrets, readStagingConfig, type ScaffoldSecrets } from "./config";
import { createOAuthHandler } from "./oauth-handler";
import { createProviderMcpAgent, type ProviderEnv } from "./mcp-agent-factory";
import { createTokenBrokerDO } from "./token-broker";
import { handleUpload, handleFetch, runSweep } from "./staging/index.js";

/**
 * One-stop setup: returns the McpAgent DO class and the OAuthProvider default handler
 * for the worker entry to re-export.
 *
 * Usage in `apps/<deployment>/src/index.ts`:
 *
 *     export const {
 *       McpAgent: XeroMCP,
 *       TokenBrokerDO: XeroTokenBroker,
 *       default: OAuthHandler,
 *     } = setupProvider(xeroProvider);
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
  const TokenBrokerClass = createTokenBrokerDO(provider as ApiProvider<Record<string, unknown>, ProviderEnv>);
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
    async fetch(
      request: Request,
      env: Env,
      ctx: ExecutionContext,
    ): Promise<Response> {
      assertSecrets(env as ScaffoldSecrets);

      const url = new URL(request.url);
      if (url.pathname === "/staging/upload" && request.method === "POST") {
        const stagingEnv = env as unknown as {
          STAGING_D1: D1Database;
          STAGING_R2: R2Bucket;
        } & Record<string, unknown>;
        const config = readStagingConfig(env as unknown as Record<string, unknown>);
        return handleUpload(request, {
          STAGING_D1: stagingEnv.STAGING_D1,
          STAGING_R2: stagingEnv.STAGING_R2,
          config,
        });
      }
      if (url.pathname.startsWith("/staging/fetch/") && request.method === "GET") {
        const stagingEnv = env as unknown as {
          STAGING_D1: D1Database;
          STAGING_R2: R2Bucket;
        } & Record<string, unknown>;
        const config = readStagingConfig(env as unknown as Record<string, unknown>);
        return handleFetch(request, {
          STAGING_D1: stagingEnv.STAGING_D1,
          STAGING_R2: stagingEnv.STAGING_R2,
          config,
        });
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (oauth as any).fetch(request, env, ctx);
    },
    async scheduled(
      _controller: ScheduledController,
      env: Env,
      ctx: ExecutionContext,
    ): Promise<void> {
      const stagingEnv = env as unknown as {
        STAGING_D1?: D1Database;
        STAGING_R2?: R2Bucket;
      } & Record<string, unknown>;
      if (!stagingEnv.STAGING_D1 || !stagingEnv.STAGING_R2) return;
      ctx.waitUntil(
        runSweep({
          STAGING_D1: stagingEnv.STAGING_D1,
          STAGING_R2: stagingEnv.STAGING_R2,
        }).then(() => undefined),
      );
    },
  };

  return {
    McpAgent: McpAgentClass,
    TokenBrokerDO: TokenBrokerClass,
    default: wrapped,
  };
}
