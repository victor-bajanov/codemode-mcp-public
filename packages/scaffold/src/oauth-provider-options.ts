/**
 * Security-relevant options for the `@cloudflare/workers-oauth-provider`
 * `OAuthProvider` that fronts every deployment. Kept in one module so
 * `setup-provider.ts` and the security POC harness spread the SAME object and
 * the POCs exercise the real configuration.
 *
 *  - `allowPlainPKCE: false` — MCP clients must use PKCE S256 (F-2). The
 *    library's `parseAuthRequest` then throws for a missing or `plain`
 *    `code_challenge_method`, and `/authorize` additionally refuses a request
 *    with no `code_challenge` at all (see `oauth-handler.ts`). Without PKCE a
 *    public client's authorisation code is redeemable by whoever receives it.
 *
 *  - `refreshTokenTTL` — MCP grants (and therefore their refresh tokens)
 *    expire 90 days after authorisation (F-22). The library fixes the grant's
 *    `expiresAt` when the authorisation code is first exchanged and refresh
 *    exchanges do NOT extend it, so users re-authorise every 90 days. It is a
 *    module constant rather than an env var because `OAuthProvider` is
 *    constructed at module scope, before any `env` exists. Grants minted before
 *    this option was set carry no expiry until they are re-authorised.
 *
 * The endpoint paths are the scaffold's fixed routing contract: `/authorize`
 * and `/callback` are served by `createOAuthHandler`, `/token` and
 * `/register` by the library, `/mcp` by the McpAgent.
 */

/** Lifetime of an MCP grant and its refresh token: 90 days, in seconds. */
export const MCP_REFRESH_TOKEN_TTL_SECONDS = 90 * 24 * 60 * 60; // 7_776_000

export const MCP_OAUTH_PROVIDER_OPTIONS = {
  apiRoute: "/mcp",
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
  allowPlainPKCE: false,
  refreshTokenTTL: MCP_REFRESH_TOKEN_TTL_SECONDS,
} as const;
