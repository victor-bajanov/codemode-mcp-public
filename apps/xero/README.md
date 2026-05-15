# xero

Cloudflare Worker exposing Xero (Demo Company) to Claude.ai through the
shared Code Mode MCP scaffold. Single-operator dev deployment.

## Setup (one-time)

1. **KV namespace:**
   ```
   npx wrangler kv namespace create OAUTH_KV
   ```
   Copy the id into `wrangler.jsonc`.

2. **OAuth registration at developer.xero.com:**
   - App name: `xero`
   - Redirect URI: `https://xero.<subdomain>.workers.dev/callback`
   - Scopes: see `packages/providers/xero/src/index.ts → xeroProvider.oauth.scopes`

3. **Secrets:**
   ```
   npx wrangler secret put XERO_CLIENT_ID
   npx wrangler secret put XERO_CLIENT_SECRET
   npx wrangler secret put COOKIE_ENCRYPTION_KEY
   ```

4. **Cloudflare Access policy** (single-operator gate on `/authorize`):
   - Application path: `https://xero.<subdomain>.workers.dev/authorize`
   - Allow rule: `email is you@example.com`
   - Other paths (`/mcp`, `/token`, `/callback`, `/register`, `/.well-known/*`) bypass Access.

## Deploy

```
pnpm --filter @apps/xero typecheck
npx wrangler deploy
```

## Connect from Claude.ai

In Claude.ai → Connectors → Add custom MCP, URL:
`https://xero.<subdomain>.workers.dev/mcp`

## OAuth flow notes

- First `/authorize` shows the **Xero consent screen for ALL listed scopes** —
  the operator should see writes for accounting.transactions /
  accounting.contacts / accounting.attachments / files even though the
  surface-review only allows specific operationIds inside those scope
  buckets. Defense-in-depth: any write capability not in surface review is
  denied even if its OAuth scope is granted.

- **Single-tenant grant required.** If Xero presents a list of orgs at the
  consent screen, untick everything except **Demo Company**. Granting
  multiple tenants will cause `completeAuthHook` to error out mid-redirect
  with "Multiple tenants granted (...)" — recover by re-authorising and
  selecting one.

- **Re-auth.** Xero refresh tokens rotate on every use and have a 60-day
  idle-expiry. If the connector says "log in again", that's a refresh
  failure cycle (4xx from `/token`) — Claude.ai will run `/authorize` and a
  new grant slot is seeded. Old slots remain in DO storage; bounded growth
  ~10/year for single operator.

## Re-merging the Xero spec

When XeroAPI/Xero-OpenAPI ships an updated spec:

```
cd packages/spec-loaders/xero-merge/specs
SHA=<new-commit-sha>
curl -fsSL -o xero_accounting.yaml \
  "https://raw.githubusercontent.com/XeroAPI/Xero-OpenAPI/${SHA}/xero_accounting.yaml"
# repeat for xero_files.yaml + xero_payroll_au.yaml (note: vendored from repo root, not yaml/ subdir)
```

Update `specs/README.md → Last synced` and re-run:

```
pnpm --filter @local/spec-loaders-xero-merge build
git diff packages/providers/xero/src/operationId-list.txt
```

Diff the `operationId-list.txt` to spot newly-added or removed ops. Each new
operation is implicit-deny by default; classify intentionally in
`packages/providers/xero/src/surface-review.ts`. Spec sync = its own PR.
