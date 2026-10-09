import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import type { ApiProvider } from "./api-provider";
import {
  assertSecrets,
  readOAuthClientTtlSeconds,
  readOAuthRateLimitConfig,
  readStagingConfig,
  readStagingThrottleConfig,
  type ScaffoldSecrets,
} from "./config";
import { createOAuthHandler } from "./oauth-handler";
import { enforceOAuthHardening, enforceStagingThrottle } from "./oauth-hardening";
import { MCP_OAUTH_PROVIDER_OPTIONS } from "./oauth-provider-options";
import { runClientSweep, type ClientSweepKv } from "./oauth-client-sweep";
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
 * of an opaque failure inside `/authorize`, whose consent form tokens are
 * signed with that key — see `oauth-consent.ts`).
 *
 * The `OAuthProvider` takes its security options (MCP-client PKCE S256, the
 * 90-day refresh-token lifetime) from `MCP_OAUTH_PROVIDER_OPTIONS`. The public
 * `/staging/*` endpoints sit behind a per-client failure-budget throttle;
 * `POST /register` and `POST /token` behind rate limiting and no-store.
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
    ...MCP_OAUTH_PROVIDER_OPTIONS,
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
      const oauthKv = (env as unknown as { OAUTH_KV: KVNamespace }).OAUTH_KV;
      // Failure-budget throttle in front of the public staging endpoints
      // (F-13): once a client has spent its 403 budget it gets 429 before any
      // D1 read.
      if (url.pathname === "/staging/upload" && request.method === "POST") {
        const stagingEnv = env as unknown as {
          STAGING_D1: D1Database;
          STAGING_R2: R2Bucket;
        } & Record<string, unknown>;
        const config = readStagingConfig(env as unknown as Record<string, unknown>);
        return enforceStagingThrottle(
          request,
          oauthKv,
          readStagingThrottleConfig(env as unknown as Record<string, unknown>),
          Date.now(),
          (r) =>
            handleUpload(r, {
              STAGING_D1: stagingEnv.STAGING_D1,
              STAGING_R2: stagingEnv.STAGING_R2,
              config,
            }),
          ctx.waitUntil.bind(ctx),
        );
      }
      if (url.pathname.startsWith("/staging/fetch/") && request.method === "GET") {
        const stagingEnv = env as unknown as {
          STAGING_D1: D1Database;
          STAGING_R2: R2Bucket;
        } & Record<string, unknown>;
        const config = readStagingConfig(env as unknown as Record<string, unknown>);
        return enforceStagingThrottle(
          request,
          oauthKv,
          readStagingThrottleConfig(env as unknown as Record<string, unknown>),
          Date.now(),
          (r) =>
            handleFetch(r, {
              STAGING_D1: stagingEnv.STAGING_D1,
              STAGING_R2: stagingEnv.STAGING_R2,
              config,
            }),
          ctx.waitUntil.bind(ctx),
        );
      }
      // Rate-limit + no-store hardening for the library-owned OAuth endpoints
      // (POST /register, POST /token); all other paths pass straight through.
      const rateLimitCfg = readOAuthRateLimitConfig(env as unknown as Record<string, unknown>);
      return enforceOAuthHardening(
        request,
        oauthKv,
        rateLimitCfg,
        Date.now(),
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (req) => (oauth as any).fetch(req, env, ctx),
      );
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
      // OAuth inactive-client sweep — bounds unbounded `client:*` growth by
      // reaping ungranted, aged dynamically-registered clients. Independent of
      // staging, so it runs whenever OAUTH_KV is bound.
      const oauthKv = (env as unknown as { OAUTH_KV?: KVNamespace }).OAUTH_KV;
      if (oauthKv) {
        const clientTtlSeconds = readOAuthClientTtlSeconds(
          env as unknown as Record<string, unknown>,
        );
        ctx.waitUntil(
          runClientSweep(oauthKv as unknown as ClientSweepKv, {
            clientTtlSeconds,
            nowMs: Date.now(),
          })
            .then((r) => {
              console.log(`oauth-client-sweep ${JSON.stringify(r)}`);
            })
            .catch((err) => {
              console.error(`oauth-client-sweep failed: ${String(err)}`);
            }),
        );
      }

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
