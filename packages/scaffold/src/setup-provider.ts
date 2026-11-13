import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import type { ApiProvider } from "./api-provider";
import {
  assertSecrets,
  readOAuthHardeningConfig,
  readStagingConfig,
  readStagingThrottleConfig,
  type ScaffoldSecrets,
} from "./config";
import { createOAuthHandler } from "./oauth-handler";
import { enforceOAuthHardening, enforceStagingThrottle } from "./oauth-hardening";
import { MCP_OAUTH_PROVIDER_OPTIONS } from "./oauth-provider-options";
import { createProviderMcpAgent, withSessionMismatchAs404, type ProviderEnv } from "./mcp-agent-factory";
import { principalOf } from "./principal";
import { createTokenBrokerDO } from "./token-broker";
import { handleUpload, handleFetch, runSweep } from "./staging/index.js";
import { createAuditSink } from "./audit.js";

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
 * `POST /register`, `POST /token`, `GET`/`HEAD`/`POST /authorize` and
 * `GET`/`HEAD /callback` behind per-IP rate limiting and body caps (no-store on
 * the first two).
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
    apiHandler: withSessionMismatchAs404((McpAgentClass as any).serve("/mcp", { binding: "MCP_OBJECT" }), {
      principalOf: (props) => principalOf(provider, props as P | undefined),
    }) as any,
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
      // Both public staging routes audit every request (E-1, 2026-11 review)
      // through a sink named after the deployment; the handlers take the
      // principal from the row's owner (no MCP session here).
      const stagingAudit = () =>
        createAuditSink({
          deployment: (env as unknown as { DEPLOYMENT_NAME: string }).DEPLOYMENT_NAME,
          waitUntil: ctx.waitUntil.bind(ctx),
        });
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
              audit: stagingAudit(),
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
              audit: stagingAudit(),
            }),
          ctx.waitUntil.bind(ctx),
        );
      }
      // Rate limits, body caps, no-store and the client-record TTL for the
      // OAuth endpoints (POST /register, POST /token, /authorize, /callback);
      // all other paths pass straight through.
      const hardeningCfg = readOAuthHardeningConfig(env as unknown as Record<string, unknown>);
      return enforceOAuthHardening(
        request,
        oauthKv,
        hardeningCfg,
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
      // Staging sweep only. OAuth client records expire by KV TTL (set by
      // enforceOAuthHardening), so the cron issues no OAUTH_KV operation.
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
