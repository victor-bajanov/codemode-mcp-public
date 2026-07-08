# Cloudflare: getting started for this repo

A from-scratch guide for someone who has never deployed to Cloudflare before
and wants to ship the apps in this repo. By the end you'll have an account,
the right CLIs, a workers.dev subdomain, Zero Trust enabled, and an
identity provider wired up — enough to run the deployment steps in the root
[`README.md`](../README.md).

## What we're using and why

This repo touches five Cloudflare product surfaces. Brief tour:

| Surface | What it is | Why we use it |
|---|---|---|
| **Workers** | Serverless JavaScript/TypeScript runtime. Code runs at the edge. | The MCP server itself runs as a Worker. Entry point is each `apps/*/src/index.ts`. |
| **Durable Objects** | Stateful single-instance "objects" the Worker can address by id. Each instance is a coordination/state primitive. | One DO per MCP session — the `agents` library uses it to keep the MCP transport state, plus per-session SQLite for tool state. |
| **Workers KV** | Eventually-consistent global key-value store. | Holds the OAuth grants and refresh tokens (`OAUTH_KV` binding), keyed by client/grant id. |
| **Zero Trust → Access** | Identity-aware proxy in front of an app path. Browser hits Cloudflare first, gets challenged for SSO, only then reaches your Worker. | Gates `/authorize` so only your email through your allowed IdP can complete the OAuth dance and seed a grant. Note: `/mcp`, `/token`, `/callback`, `/register`, `/.well-known/*` are NOT gated — they need to be reachable by Claude.ai. |
| **Workers Observability** | Structured log search over Worker invocations. | Used to grep audit events and debug MCP transport behavior. Each `wrangler.jsonc` opts in with `observability.enabled = true`. |

Wrangler is the CLI that talks to all of the above. OpenTofu (in `infra/`)
provisions the KV namespace and the Access application + policy
declaratively — everything else is hand-configured once in the dashboard or
via `wrangler secret put`. (The `.tf` files are unmodified Terraform syntax;
this repo recommends OpenTofu — the open-source fork — but the standard
`terraform` CLI also works against them if you prefer.)

## Step 1 — Create a Cloudflare account

1. Sign up at <https://dash.cloudflare.com/sign-up>. Use an email you control;
   this will end up as the Access policy "allowed email" in the simplest
   single-operator setup.
2. Verify the email and log in.
3. Free plan is fine for this repo — Workers free tier gives 100k requests/day
   and Durable Objects free tier covers a single-operator MCP server
   comfortably. Workers KV is also on the free tier. Cloudflare Access has a
   free tier for up to 50 users.

## Step 2 — Reserve your workers.dev subdomain

Every Cloudflare account gets one `<your-name>.workers.dev` subdomain. All
Workers under your account live at `<worker-name>.<your-name>.workers.dev`
unless you map a custom domain.

1. Dashboard → **Workers & Pages**.
2. The first time you visit this section, Cloudflare prompts you to pick a
   subdomain. Choose carefully — you cannot change it later without account
   support.
3. Note this value. You'll set it as `TF_VAR_cloudflare_workers_subdomain`
   in `infra/.env`, and you'll reference it in OAuth redirect URIs.

## Step 3 — Find your Account ID

1. Dashboard → **Workers & Pages** (or any page).
2. In the right-hand sidebar there's an "Account ID" with a copy button.
3. Save this — you'll set it as `TF_VAR_cloudflare_account_id`.

## Step 4 — Install the CLIs

```
# Node 20+ and pnpm 9 (this repo pins pnpm@9.12.0)
node --version
corepack enable
corepack prepare pnpm@9.12.0 --activate

# OpenTofu 1.6+ (Homebrew, asdf, or download from opentofu.org)
brew install opentofu
tofu --version

# 1Password CLI (optional — only if you store creds in 1Password)
brew install --cask 1password-cli
op --version
```

`wrangler` itself is a per-app devDependency, so it's installed by
`pnpm install` and invoked as `npx wrangler` or via `pnpm --filter <app>`
scripts.

## Step 5 — Authenticate Wrangler

Wrangler reads `CLOUDFLARE_API_TOKEN` from the environment, so the scoped
token you'll mint in Step 6 (via `infra/create-api-token.sh`) covers both
`tofu apply` and `wrangler deploy` / `wrangler secret put` — one token, one
1Password item.

For the very first deploy you can do `npx wrangler login` interactively
(opens a browser, stashes a token in `~/.config/.wrangler/`); for everyday
flows the repo's deploy scripts (`pnpm run deploy:*`) and the
`scripts/bootstrap-*.sh` wrappers expect `op run --env-file=infra/.env --`
to inject `CLOUDFLARE_API_TOKEN`.

## Step 6 — Authenticate OpenTofu

Both OpenTofu and `wrangler` read the same `CLOUDFLARE_API_TOKEN` env var, so
we mint **one scoped token** that covers both: Workers Scripts + Workers KV +
Zero Trust Access (apps and policies). No Global API Key.

The repo ships [`infra/create-api-token.sh`](../infra/create-api-token.sh)
which calls Cloudflare's API to create (or update in place) a token named
`codemode-mcp-deploy` with exactly those permission groups.

1. **Mint a single-use creation token.** Dashboard → **My Profile → API
   Tokens → Create Token → Custom token**. Add the permission "**User → API
   Tokens → Edit**" and nothing else. This token only lives long enough to
   run the script; delete it afterwards.
2. **Run the script.**
   ```
   export CF_CREATE_TOKEN='<single-use creation token>'
   ./infra/create-api-token.sh
   ```
   On first run it prints `Token ID` and `Value`. Store the value in
   1Password as item `Codemode MCP Cloudflare Token`, field `credential`
   (and add an `account id` field with your Cloudflare account ID — the
   script doesn't need this, but `infra/.env` references it for
   `TF_VAR_cloudflare_account_id`). On re-runs the script updates the
   token's permissions in place and the value stays unchanged.
3. **Point `infra/.env` at the new item.** See `infra/.env.example`. If
   you don't use 1Password, set `CLOUDFLARE_API_TOKEN` and
   `TF_VAR_cloudflare_account_id` as plain env vars in your shell or in a
   non-`op://` `.env`, and drop the `op run --env-file=.env --` prefix
   from the OpenTofu / deploy commands.
4. **Delete the single-use creation token** in the dashboard.

## Step 7 — Enable Zero Trust and add an Identity Provider

Cloudflare Access needs an IdP to authenticate users against. For a
single-operator setup, Google works well:

1. Dashboard → **Zero Trust** (left sidebar). First visit prompts you to
   pick a team name (the subdomain for your Access dashboard,
   `<team>.cloudflareaccess.com`) and choose a plan — pick **Free**.
2. Zero Trust dashboard → **Settings → Authentication → Login methods →
   Add new**.
3. Pick **Google** (or your IdP of choice). Follow the in-product wizard —
   for Google you provide an OAuth client from Google Cloud Console with
   `https://<team>.cloudflareaccess.com/cdn-cgi/access/callback` as a
   redirect URI.
4. Once saved, click the IdP to edit it; the **UUID is in the URL**, e.g.
   `…/authentication/<UUID>/edit`. Save this — it goes into
   `TF_VAR_access_allowed_idp_ids` (JSON list) so the OpenTofu-provisioned
   Access policy knows which IdPs may satisfy the rule.

## Step 8 — Provision app resources via OpenTofu

Now you have everything OpenTofu needs:

```
cd infra
cp .env.example .env
# Edit .env:
#   TF_VAR_cloudflare_workers_subdomain = "your-subdomain"
#   TF_VAR_allowed_emails               = '["you@example.com"]'
#   TF_VAR_access_allowed_idp_ids       = '["<the-uuid-from-step-7>"]'
# Keep the op:// references if using 1Password; otherwise replace with literals.

op run --env-file=.env -- tofu init
op run --env-file=.env -- tofu plan      # review
op run --env-file=.env -- tofu apply
```

Outputs you care about (one set per app):

- `<app>_oauth_kv_id` — paste into the matching `apps/<app>/wrangler.jsonc`
  at `kv_namespaces[0].id`.
- `<app>_authorize_url` — visit in a browser to confirm the Access policy
  challenges you for SSO and that your email is allowed.

State is local-only (`terraform.tfstate` in `infra/`, gitignored — OpenTofu
uses the same filename for drop-in compatibility). Fine for single-operator
dev. If you add a second operator, lift the state to an R2 backend before
they run tofu.

## Step 9 — Register the upstream OAuth app (Gmail or Xero)

This is provider-specific and not Cloudflare — see the relevant section of
the root [`README.md`](../README.md) or
[`apps/xero/README.md`](../apps/xero/README.md).

The constant pattern: redirect URI is
`https://<worker-name>.<your-subdomain>.workers.dev/callback`.

## Step 10 — Set Worker secrets and deploy

Wrap wrangler commands with `op run --env-file=infra/.env --` so they pick up
`CLOUDFLARE_API_TOKEN`. (Alternative: `npx wrangler login` once, then drop
the wrapper. The wrapper form is what `scripts/bootstrap-*.sh` use.)

```
# From repo root:
op run --env-file=infra/.env -- (cd apps/gmail && npx wrangler secret put GOOGLE_CLIENT_ID)
op run --env-file=infra/.env -- (cd apps/gmail && npx wrangler secret put GOOGLE_CLIENT_SECRET)
op run --env-file=infra/.env -- (cd apps/gmail && npx wrangler secret put COOKIE_ENCRYPTION_KEY)
# (COOKIE_ENCRYPTION_KEY = any 32+ byte random string, e.g. `openssl rand -hex 32`)

pnpm --filter @apps/gmail typecheck
op run --env-file=infra/.env -- pnpm run deploy:gmail
```

Wrangler prints the deployed URL. Visit
`https://<worker>.<your-subdomain>.workers.dev/mcp` — you should hit
Cloudflare Access, then Google, then come back with a successful grant.

`wrangler secret put` writes encrypted secrets to the Worker's environment.
They are not in `wrangler.jsonc` and not in git. Rotate by re-running
`secret put` with a new value.

## Step 11 — Connect from your MCP client

Claude.ai: Settings → Connectors → Add custom MCP → URL
`https://<worker>.<your-subdomain>.workers.dev/mcp`.

The first connection runs the OAuth flow; subsequent calls use the stored
grant in KV.

## Day-2 operations

- **Logs**: `npx wrangler tail` from an app directory streams live logs.
  For search, use Workers Observability in the dashboard — each
  `wrangler.jsonc` has it enabled with full head sampling.
- **Versions and rollback**: `npx wrangler deployments list` to see recent
  deploys; `npx wrangler rollback [deployment-id]` reverts. Cloudflare
  versions every deploy.
- **Cron / scheduled work**: not used in this repo; would go in
  `wrangler.jsonc` under `triggers.crons` if added.
- **Custom domain**: not required for this repo. If you want one, dashboard
  → Workers → your worker → Settings → Triggers → Add Custom Domain. You
  must have the domain on Cloudflare DNS.

## Common gotchas

- **"Authentication error [code: 10000]" from OpenTofu.** Check that
  `CLOUDFLARE_API_TOKEN` is set in your shell (e.g. via
  `op run --env-file=infra/.env -- tofu ...`) and that it's the token
  minted by `infra/create-api-token.sh`. Hand-built tokens that omit
  "Access: Apps and Policies (Read+Write)" fail on the Access app
  resources.
- **Access app gates `/mcp` and breaks the connector.** The Access
  application's `domain` must include the `/authorize` path
  (`<worker>.<subdomain>.workers.dev/authorize`), not the bare hostname.
  The `infra/` module already does this; if you hand-built the app,
  double-check.
- **KV id mismatch after re-running OpenTofu.** If `tofu destroy` /
  `apply` recreates the KV namespace, the new id won't match what's in
  `wrangler.jsonc`. Re-paste after every recreate.
- **Workers Observability empty after deploy.** Logs take ~30s to surface,
  and `observability.enabled` must be true at deploy time (changing it
  needs a re-deploy, not just a dashboard toggle).
- **`workers.dev` route disabled.** Each Worker has a per-worker toggle at
  Worker → Settings → Domains & Routes for the workers.dev preview URL. If
  the URL returns "Error 1101" or similar, check this toggle is on.

## Reference docs

- Workers: <https://developers.cloudflare.com/workers/>
- Workers KV: <https://developers.cloudflare.com/kv/>
- Durable Objects: <https://developers.cloudflare.com/durable-objects/>
- Zero Trust / Access: <https://developers.cloudflare.com/cloudflare-one/>
- Wrangler: <https://developers.cloudflare.com/workers/wrangler/>
- OpenTofu: <https://opentofu.org/docs/>
- Cloudflare provider (works with both OpenTofu and Terraform): <https://search.opentofu.org/provider/cloudflare/cloudflare/latest>
