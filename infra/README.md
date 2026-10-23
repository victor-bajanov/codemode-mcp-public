# infra

Provisions Cloudflare resources for slice 1: the OAuth KV namespace and the Cloudflare Access policy on `/authorize`.

Auth uses a **scoped Cloudflare API token** (one token per project; the same token also drives `wrangler deploy` and `wrangler secret put`). Mint it once with [`create-api-token.sh`](./create-api-token.sh); the env var (`CLOUDFLARE_API_TOKEN`) is resolved from 1Password by `op run --env-file=.env`.

## Prerequisites

- OpenTofu 1.6+ (`brew install opentofu`)
- 1Password CLI (`op`) signed in to the relevant account
- A "Codemode MCP Cloudflare Token" item in your `Private` vault, with fields:
  - `credential` — the API token value
  - `account id` — your Cloudflare account ID
- The workers.dev subdomain reserved for your account (visible in the Cloudflare dashboard under Workers & Pages)

## Mint the API token (one-time)

```bash
# Mint a *single-use* creation token in the Cloudflare dashboard:
#   My Profile → API Tokens → Create Token → Custom token → "User > API Tokens > Edit"
# Use it once, then delete it.
export CF_CREATE_TOKEN='<single-use token>'
./infra/create-api-token.sh
```

The script either creates a `codemode-mcp-deploy` token or updates the existing one in place. Stash the printed value in 1Password (item `Codemode MCP Cloudflare Token`, fields `credential` and `account id`).

Set `CF_TRIAL_ZONE_ID` to a zone id (32 hex chars) to add a second, zone-scoped policy on that zone (Workers Routes and DNS, read and write), which a Worker served on a custom domain in that zone needs. Unset, the token has no zone permissions. The script PUTs the token's full policy set on every run, so **every re-run must pass `CF_TRIAL_ZONE_ID` again**: a run without it drops the zone grant, and the next deploy of the custom-domain Worker fails to attach its domain.

The deploy token has no user-scoped permissions; instead `infra/.env` sets `CLOUDFLARE_ACCOUNT_ID`, which makes wrangler skip its `/memberships` preflight and go straight to the account-scoped endpoints.

## Setup

```bash
cd infra
cp .env.example .env
# Edit .env: set TF_VAR_cloudflare_workers_subdomain and TF_VAR_allowed_emails
# (plus TF_VAR_extra_allowed_emails for any per-worker grants).
# Adjust the op:// paths if your vault layout differs.
op run --env-file=.env -- tofu init
op run --env-file=.env -- tofu plan
op run --env-file=.env -- tofu apply
```

After `apply`, tofu prints:
- `oauth_kv_id` — paste into `apps/gmail/wrangler.jsonc` at `kv_namespaces[0].id`.
- `authorize_url` — visit in a browser to verify the Access policy.

## What this manages

- `cloudflare_workers_kv_namespace.oauth` — the `OAUTH_KV` namespace.
- `cloudflare_zero_trust_access_application.authorize` — self-hosted Access app on `/authorize`, path-restricted (does **not** cover `/mcp`, `/token`, `/callback`). The app matches on host and path, not method, so it gates both `GET /authorize` (the consent page) and `POST /authorize` (the operator's approval, which posts back to the same path); no extra Access rule is needed for the consent flow.
- `cloudflare_zero_trust_access_policy.allow_operator` — single allow policy per Access app. Its email list is `var.allowed_emails` (the operator baseline, applied to **every** worker) plus `var.extra_allowed_emails[<worker_name>]` (that worker only). Grant a tester one deployment via the latter: anything added to `allowed_emails` reaches all six workers, so they could run an OAuth flow against any of them. Both are set in `.env`, keyed by `worker_name` — not the module label, which differs for the `-dev` deployments.
- `cloudflare_zero_trust_access_application.authorize_custom_domain` (+ its policy) — the same pair again for a Worker's custom domain, created only when the module is passed a non-empty `custom_domain`. **An Access application matches on host+path**, so a Worker serving both `<name>.workers.dev` and a custom domain needs one app per hostname; without the second app the custom-domain `/authorize` is completely ungated. Any deployment that adds a `custom_domain` route to its `wrangler.jsonc` must set `custom_domain` on its module block here in the same change.

## What this does NOT manage

- The Worker script itself — `wrangler deploy` from `apps/gmail`.
- Worker secrets (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `COOKIE_ENCRYPTION_KEY`) — `wrangler secret put`. Keeping these out of OpenTofu state avoids leaking values into `terraform.tfstate` (OpenTofu uses the same state filename for drop-in compatibility).
- The Google IdP linkage for Cloudflare Access — set up once in the dashboard at Zero Trust → Settings → Authentication → Add Login Method → Google. The Access policy here gates on email, but the user still needs an IdP to authenticate against.
- The Google Cloud OAuth client used for Gmail API access — see runbook §2.

## Upgrade scripts

Changes that need remote state migrated before the new Worker code goes live ship a script in [`scripts/upgrade/`](../scripts/upgrade/), named for the date of the change. wrangler does not apply D1 migrations on deploy, so run the script instead of a bare `pnpm deploy:*`.

### `2026-10-15-staging-v2.sh` — staged file transfer v2 (issue #59)

The v2 staging code writes an `enc_version` on every staging row, so migration `0002_enc_version.sql` must be on each deployment's remote `STAGING_D1` before that deployment's new code is live. For each deployment the script runs, in order:

1. `npx wrangler d1 migrations apply STAGING_D1 [--env=<env>] --remote` from the app directory (its `wrangler.jsonc` points `migrations_dir` at `packages/scaffold/src/staging/migrations`);
2. `pnpm deploy:<app>[:<env>]` from the repo root.

Both steps run inside `op run --env-file=infra/.env --`, so `CLOUDFLARE_API_TOKEN` is injected into the child process and never read into your shell; you do not wrap the script itself. Expect a 1Password approval prompt for each `op run`, and a confirmation prompt from `wrangler d1 migrations apply` when run from a terminal.

```bash
scripts/upgrade/2026-10-15-staging-v2.sh --dry-run                 # print every command, run nothing
scripts/upgrade/2026-10-15-staging-v2.sh --env-only=gmail-dev      # one deployment
scripts/upgrade/2026-10-15-staging-v2.sh                           # all five, stopping at the first failure
```

`--env-only` takes one of `gmail-dev`, `gmail-tester`, `gmail`, `xero-dev`, `xero`; `--dry-run` combines with it. Without `--env-only` the script works through all five in that order. Roll out dev first, then tester, then prod: run `--env-only=gmail-dev`, check it with the live staging ladder ([`scripts/harnesses/README.md`](../scripts/harnesses/README.md), drafts only, nothing is sent), then `--env-only=gmail-tester`, then `gmail`, `xero-dev` and `xero`. If the ladder shows `exceededMemory` in Workers Logs, set `STAGING_MAX_CONCURRENT_TRANSFERS` to `1` for that deployment before going further.

## State

Local-only state file (`terraform.tfstate`). Listed in `.gitignore`. For a single-operator slice-1 deployment this is fine; if a second operator ever needs to run tofu, lift state to an R2 backend or similar before that happens.
