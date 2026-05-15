# infra

Provisions Cloudflare resources for slice 1: the OAuth KV namespace and the Cloudflare Access policy on `/authorize`.

Auth uses your Cloudflare **Global API Key** via env vars resolved by 1Password CLI (`op run --env-file=.env`).

## Prerequisites

- OpenTofu 1.6+ (`brew install opentofu`)
- 1Password CLI (`op`) signed in to the relevant account
- A "Cloudflare Global API Key" item in your `Private` vault, with fields:
  - `username` — the account email
  - `credential` — the API key
  - `account id` — your Cloudflare account ID
- The workers.dev subdomain reserved for your account (visible in the Cloudflare dashboard under Workers & Pages)

## Setup

```bash
cd infra
cp .env.example .env
# Edit .env: set TF_VAR_cloudflare_workers_subdomain and TF_VAR_allowed_email.
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
- `cloudflare_zero_trust_access_application.authorize` — self-hosted Access app on `/authorize`, path-restricted (does **not** cover `/mcp`, `/token`, `/callback`).
- `cloudflare_zero_trust_access_policy.allow_operator` — single allow policy gating on `var.allowed_email`.

## What this does NOT manage

- The Worker script itself — `wrangler deploy` from `apps/gmail`.
- Worker secrets (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `COOKIE_ENCRYPTION_KEY`) — `wrangler secret put`. Keeping these out of OpenTofu state avoids leaking values into `terraform.tfstate` (OpenTofu uses the same state filename for drop-in compatibility).
- The Google IdP linkage for Cloudflare Access — set up once in the dashboard at Zero Trust → Settings → Authentication → Add Login Method → Google. The Access policy here gates on email, but the user still needs an IdP to authenticate against.
- The Google Cloud OAuth client used for Gmail API access — see runbook §2.

## State

Local-only state file (`terraform.tfstate`). Listed in `.gitignore`. For a single-operator slice-1 deployment this is fine; if a second operator ever needs to run tofu, lift state to an R2 backend or similar before that happens.
