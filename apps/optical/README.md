# `apps/optical`

Cloudflare Worker MCP server that fronts the externally-deployed
`weekly-scheduling-assistant` API (`scheduler.example.com`) as a
codemode-mcp provider. See the design at
[`docs/superpowers/specs/2026-05-23-optical-provider-design.md`](../../docs/superpowers/specs/2026-05-23-optical-provider-design.md).

## Setup

The end-to-end bootstrap (Tofu, KV ids, secrets, deploy) is wrapped in
[`scripts/bootstrap-optical.sh`](../../scripts/bootstrap-optical.sh). Run it
once. Before doing so, complete the **prerequisites** below.

### Prerequisites

1. **Optical-side changes have landed.** Verify by running the Task 0 checks
   in
   [`docs/superpowers/plans/2026-05-23-optical-provider.md`](../../docs/superpowers/plans/2026-05-23-optical-provider.md).

2. **PKCE client registered in optical's `oauth_clients` D1 table** —
   one row per environment (prod + dev). From the **optical** repo
   (a sibling checkout, `../optical/`):

   ```bash
   # Prod
   wrangler d1 execute scheduler --remote --command "
     INSERT INTO oauth_clients (id, name, type, redirect_uris, scopes, created_at)
     VALUES ('codemode-mcp-optical', 'codemode-mcp (optical prod)', 'pkce',
             '[\"https://optical.<your-subdomain>.workers.dev/callback\"]',
             'read write', datetime('now'))
     ON CONFLICT(id) DO UPDATE SET redirect_uris=excluded.redirect_uris;
   "

   # Dev
   wrangler d1 execute scheduler --remote --command "
     INSERT INTO oauth_clients (id, name, type, redirect_uris, scopes, created_at)
     VALUES ('codemode-mcp-optical-dev', 'codemode-mcp (optical dev)', 'pkce',
             '[\"https://optical-dev.<your-subdomain>.workers.dev/callback\"]',
             'read write', datetime('now'))
     ON CONFLICT(id) DO UPDATE SET redirect_uris=excluded.redirect_uris;
   "
   ```

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
  `apps/optical/wrangler.jsonc` has no R2/D1/STAGING_* bindings and no
  `triggers.crons`. Optical's API is pure JSON.

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
