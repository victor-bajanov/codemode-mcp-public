#!/usr/bin/env bash
# Bootstrap the optical (and optical-dev) Worker deployments end-to-end.
# Idempotent: safe to re-run after a failed run.
#
# Preconditions:
#   - infra/.env contains the same op:// references as for gmail/xero
#   - You have shell access to wrangler (apps/optical/node_modules/.bin)
#   - Optical-side companion (operationIds, /v1, /oauth/userinfo) has shipped
#     to https://scheduler.example.com.
#
# Usage:
#   ./scripts/bootstrap-optical.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

# 1. Init + plan + apply Tofu — provisions optical + optical-dev KV namespaces
#    + Access apps. Plan is written to disk and reviewed interactively before
#    apply, so accidental drift on shared modules (gmail, xero) is visible
#    before anything touches Cloudflare.
op run --env-file="$REPO/infra/.env" -- \
  tofu -chdir="$REPO/infra" init

op run --env-file="$REPO/infra/.env" -- \
  tofu -chdir="$REPO/infra" plan -out=.tfplan

echo
read -r -p "Review the plan above. Press ENTER to apply, Ctrl-C to abort: " _

op run --env-file="$REPO/infra/.env" -- \
  tofu -chdir="$REPO/infra" apply .tfplan
rm -f "$REPO/infra/.tfplan"

# 2. Paste KV ids into wrangler.jsonc.
PROD_KV=$(op run --env-file="$REPO/infra/.env" -- \
  tofu -chdir="$REPO/infra" output -raw optical_oauth_kv_id)
DEV_KV=$(op run --env-file="$REPO/infra/.env" -- \
  tofu -chdir="$REPO/infra" output -raw optical_dev_oauth_kv_id)

sed -i.bak \
  -e "s/REPLACE_WITH_TOFU_OUTPUT_optical_oauth_kv_id/$PROD_KV/" \
  -e "s/REPLACE_WITH_TOFU_OUTPUT_optical_dev_oauth_kv_id/$DEV_KV/" \
  "$REPO/apps/optical/wrangler.jsonc"
rm -f "$REPO/apps/optical/wrangler.jsonc.bak"

# 3. Push secrets. Each `wrangler secret put` reads stdin once; we read each
#    secret from 1Password and pipe it. Replace the op:// references below
#    with whatever vault paths you use.
secret_put() {
  local env_name="$1"   # "" for top-level (prod), "dev" for env.dev
  local name="$2"
  local op_ref="$3"
  op read "$op_ref" | \
    (cd "$REPO/apps/optical" && \
     op run --env-file="$REPO/infra/.env" -- \
       npx wrangler "--env=$env_name" secret put "$name")
}

# COOKIE_ENCRYPTION_KEY: any 32+ byte random string. Generate once and store.
# If you don't have an op:// item yet, run:
#   op item create --category Password --vault Private --title "optical/COOKIE_ENCRYPTION_KEY" \
#     password="$(openssl rand -hex 32)"
secret_put ""     COOKIE_ENCRYPTION_KEY  "op://YourVault/<item>/credential"
secret_put "dev"  COOKIE_ENCRYPTION_KEY  "op://YourVault/<item>/credential"

# OPTICAL_CLIENT_ID / OPTICAL_CLIENT_SECRET: registered as a `pkce` row in
# optical's oauth_clients D1 table (see apps/optical/README.md §"Register the
# PKCE client"). Client_secret can be any non-empty string for `pkce` clients
# — optical ignores it. We still set it because the scaffold requires the
# Wrangler secret to be defined.
secret_put ""     OPTICAL_CLIENT_ID      "op://YourVault/<item>/credential"
secret_put ""     OPTICAL_CLIENT_SECRET  "op://YourVault/<item>/credential"
secret_put "dev"  OPTICAL_CLIENT_ID      "op://YourVault/<item>/credential"
secret_put "dev"  OPTICAL_CLIENT_SECRET  "op://YourVault/<item>/credential"

# 4. Deploy.
op run --env-file="$REPO/infra/.env" -- pnpm run deploy:optical
op run --env-file="$REPO/infra/.env" -- pnpm run deploy:optical:dev

echo
echo "✅ optical and optical-dev deployed."
echo "Next: hit the authorize URLs to confirm Access works:"
echo "  prod: $(op run --env-file=$REPO/infra/.env -- tofu -chdir=$REPO/infra output -raw optical_authorize_url)"
echo "  dev:  $(op run --env-file=$REPO/infra/.env -- tofu -chdir=$REPO/infra output -raw optical_dev_authorize_url)"
