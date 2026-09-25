# `apps/optical`

Cloudflare Worker MCP server that fronts an externally-deployed Optical
(`weekly-scheduling-assistant`) API as a codemode-mcp provider. Optical itself
lives in a separate repo; point this provider at your own deployment.

## Setup

The end-to-end bootstrap (Tofu, KV ids, secrets, deploy) is wrapped in
[`scripts/bootstrap-optical.sh`](../../scripts/bootstrap-optical.sh). Run it
once. Before doing so, complete the **prerequisites** below.

### Prerequisites

1. **Your Optical deployment is reachable and serves the vendored API.**
   Set the prod endpoints in `packages/providers/optical/src/index.ts`
   (`apiBaseUrl`, `oauth.authorizeUrl`, `oauth.tokenUrl`,
   `oauth.userInfoUrl`). The dev env repoints them through the
   `API_BASE_URL_OVERRIDE` / `OAUTH_{AUTHORIZE,TOKEN,USERINFO}_URL_OVERRIDE`
   vars in `wrangler.jsonc`. Serve Optical on a Custom Domain, not
   `workers.dev`: Cloudflare refuses same-account Worker to `workers.dev`
   fetches (error 1042), which breaks the `/callback` token exchange.

   Then check the deployment with a bearer token from Optical's own login
   flow (for example its device-code flow):

   ```bash
   OPTICAL=https://scheduler.example.com   # your deployment

   # The provider calls /v1/* paths from the vendored spec — expect 200
   curl -sS -o /dev/null -w '%{http_code}
' 
     -H "Authorization: Bearer " "/v1/tasks"

   # The OAuth flow reads the user identity here — expect 200 and JSON
   # with at least `sub` (`email` is optional)
   curl -sS -H "Authorization: Bearer " "/oauth/userinfo"
   ```

   If `/v1/tasks` returns 404, your deployment's API differs from the
   vendored spec; re-vendor from your Optical checkout (see
   [Spec re-sync](#spec-re-sync)). Optical's `/oauth/token` must also accept
   (and ignore) the `client_secret` form field the provider sends. Stock
   Optical does, and first-time consent exercises it.

2. **PKCE client registered in optical's `oauth_clients` D1 table** —
   one row per environment (prod + dev). From the **optical** repo
   (a sibling checkout, `../optical/`):

   ```bash
   # Prod
   wrangler d1 execute scheduler --remote --command "
     INSERT INTO oauth_clients (id, name, type, redirect_uris, scopes, created_at)
     VALUES ('codemode-mcp-optical', 'codemode-mcp (optical prod)', 'pkce',
             '[\"https://optical.<your-subdomain>.workers.dev/callback\"]',
             'scheduler:read scheduler:write', datetime('now'))
     ON CONFLICT(id) DO UPDATE SET redirect_uris=excluded.redirect_uris;
   "

   # Dev
   wrangler d1 execute scheduler --remote --command "
     INSERT INTO oauth_clients (id, name, type, redirect_uris, scopes, created_at)
     VALUES ('codemode-mcp-optical-dev', 'codemode-mcp (optical dev)', 'pkce',
             '[\"https://optical-dev.<your-subdomain>.workers.dev/callback\"]',
             'scheduler:read scheduler:write', datetime('now'))
     ON CONFLICT(id) DO UPDATE SET redirect_uris=excluded.redirect_uris;
   "
   ```

   The `scopes` column must list exactly the scopes the provider requests
   (`scheduler:read scheduler:write`). Optical's `/oauth/authorize` rejects
   anything outside it with `error=invalid_scope`.

   Capture the client id values; they go into the prod and dev 1Password
   items referenced by `scripts/bootstrap-optical.sh`. `client_secret` can be
   any non-empty string — optical's `pkce` flow ignores it.

3. **1Password items exist** at the op:// paths referenced by
   `scripts/bootstrap-optical.sh` (point them at your own vault), one per
   environment (prod + dev), each holding:
   - a cookie encryption key (any 32+ byte random string)
   - the PKCE client id and client secret


### Bootstrap

```bash
./scripts/bootstrap-optical.sh
```

This applies Tofu, pastes KV ids into `apps/optical/wrangler.jsonc`, pushes
secrets to both environments, and deploys.

### Connect from Claude.ai

1. Claude.ai → Settings → Connectors → Add custom MCP.
2. URL: `https://optical.<your-subdomain>.workers.dev/mcp`.
3. First `/authorize` redirect → Cloudflare Access (codemode-mcp side) →
   optical's Access (Cloudflare) → optical's IdP login → optical's
   `/oauth/authorize` issues the auth code → `/callback` on the
   codemode-mcp Worker.
4. From inside Claude.ai, ask the connector "list my tasks". You should see
   optical's actual D1 rows.

## Operational notes

- **Refresh-token rotation** — optical rotates the refresh token on every
  `/oauth/token` exchange and revokes the prior pair. The scaffold's
  TokenBroker Durable Object serialises rotations per `userId` so concurrent
  tool calls cannot race. Same behaviour as the Xero provider.
- **90-day idle expiry** — if the operator stops using the connector for
  90+ days, the refresh expires and the next tool call returns a structured
  re-auth required error. Re-running the first `/authorize` flow restores
  the grant.
- **Cloudflare Access on `/oauth/authorize`** — interactive consent goes
  through optical's Access policy. If the operator's IdP session has
  expired, the browser sees the Access login page instead of optical's
  consent flow. Not a code path codemode-mcp can recover from; sign in to
  the IdP and retry.
- **No file attachments / no staging bindings.** Unlike Gmail/Xero,
  `apps/optical/wrangler.jsonc` has no R2/D1/STAGING_* bindings. Optical's API is pure JSON. (Its
  `*/5` cron only drives the shared OAuth inactive-client sweep.)

## Spec re-sync

When optical adds or removes API operations, re-vendor the spec:

```bash
cp ../optical/schema/openapi.json \
   packages/providers/optical/src/spec.json
pnpm --filter @local/providers-optical test
```

Re-vendoring also refreshes `spec.info.description`, which flows into the
`execute` MCP tool's description via `hintFromSpecInfo(spec)` (see
`packages/providers/optical/src/index.ts`). Update the agent-facing flow
prose in optical's upstream spec, not in this repo.

The shared `providerSurfaceReviewTests` battery will flag any
surface-review entry that references an operationId the spec no longer
contains, and the local `surface-review.test.ts` will flag new operationIds
that haven't been classified yet. Categorise the new ops in
`packages/providers/optical/src/surface-review.ts`, add them to the
`EXPECTED_ALLOW_OPS` / `EXPECTED_DENY_OPS` constants in that test, and commit.
