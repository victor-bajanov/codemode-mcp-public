#!/usr/bin/env bash
# Bootstrap the gmail-tester Worker deployment end-to-end.
# Idempotent: safe to re-run after a failed run.
#
# What it provisions:
#   - OAUTH_KV namespace + Cloudflare Access app/policy on
#     gmail-tester.<subdomain>.workers.dev/authorize (via tofu; the tester's
#     email comes from TF_VAR_extra_allowed_emails["gmail-tester"] in infra/.env)
#   - STAGING_R2 bucket + STAGING_D1 database (+ remote migrations)
#   - Worker secrets (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET from the shared
#     Google OAuth app; a FRESH per-deployment COOKIE_ENCRYPTION_KEY)
#   - First deploy
#
# Manual steps that remain in the Google Cloud console (same OAuth app as prod):
#   - add the tester as a Test user on the consent screen
#   - add https://gmail-tester.<subdomain>.workers.dev/callback as an
#     authorized redirect URI on the OAuth client
#
# Usage:
#   ./scripts/bootstrap-gmail-tester.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

# 1. Init + plan + apply Tofu — provisions the gmail-tester KV namespace +
#    Access app/policy. Plan is reviewed interactively before apply, so drift
#    on shared modules is visible before anything touches Cloudflare.
op run --env-file="$REPO/infra/.env" -- \
  tofu -chdir="$REPO/infra" init

op run --env-file="$REPO/infra/.env" -- \
  tofu -chdir="$REPO/infra" plan -out=.tfplan

echo
read -r -p "Review the plan above. Press ENTER to apply, Ctrl-C to abort: " _

op run --env-file="$REPO/infra/.env" -- \
  tofu -chdir="$REPO/infra" apply .tfplan
rm -f "$REPO/infra/.tfplan"

# 2. Paste the KV id into wrangler.jsonc (no-op once already substituted).
TESTER_KV=$(op run --env-file="$REPO/infra/.env" -- \
  tofu -chdir="$REPO/infra" output -raw gmail_tester_oauth_kv_id)

sed -i.bak \
  -e "s/REPLACE_WITH_TOFU_OUTPUT_gmail_tester_oauth_kv_id/$TESTER_KV/" \
  "$REPO/apps/gmail/wrangler.jsonc"
rm -f "$REPO/apps/gmail/wrangler.jsonc.bak"

# 3. Staging R2 bucket + D1 database. `create` fails when the resource already
#    exists — tolerated so re-runs pass.
wr() {
  (cd "$REPO/apps/gmail" && op run --env-file="$REPO/infra/.env" -- npx wrangler "$@")
}

wr r2 bucket create gmail-tester-staging || echo "R2 bucket exists — continuing"
wr d1 create gmail-tester-staging       || echo "D1 database exists — continuing"

D1_ID=$(wr d1 info gmail-tester-staging --json | python3 -c "import json,sys; print(json.load(sys.stdin)['uuid'])")
sed -i.bak \
  -e "s/REPLACE_WITH_D1_ID_gmail_tester_staging/$D1_ID/" \
  "$REPO/apps/gmail/wrangler.jsonc"
rm -f "$REPO/apps/gmail/wrangler.jsonc.bak"

wr d1 migrations apply STAGING_D1 --env=tester --remote

# 4. Push secrets.
#    COOKIE_ENCRYPTION_KEY is deliberately NOT shared with prod/dev — each
#    deployment signs its own approval cookies. Auto-create the op item with a
#    fresh random key on first run.
if ! op item get "GMail Code Mode MCP - Tester" --vault Private >/dev/null 2>&1; then
  op item create --category Password --vault Private \
    --title "GMail Code Mode MCP - Tester" \
    "cookie encryption key=$(openssl rand -hex 32)"
fi

secret_put() {
  local name="$1"
  local op_ref="$2"
  op read "$op_ref" | \
    (cd "$REPO/apps/gmail" && \
     op run --env-file="$REPO/infra/.env" -- \
       npx wrangler --env=tester secret put "$name")
}

# Same Google OAuth app as prod — the tester is added to it as a Test user.
secret_put GOOGLE_CLIENT_ID      "op://YourVault/<item>/credential"
secret_put GOOGLE_CLIENT_SECRET  "op://YourVault/<item>/credential"
secret_put COOKIE_ENCRYPTION_KEY "op://YourVault/<item>/credential"

# 5. Deploy. (If the */5 cron doesn't dispatch after this first deploy, nudge
#    it with one more `pnpm deploy:gmail:tester` — new crons sometimes need a
#    second redeploy to start firing.)
op run --env-file="$REPO/infra/.env" -- pnpm run deploy:gmail:tester

echo
echo "✅ gmail-tester deployed."
echo "Access check: $(op run --env-file=$REPO/infra/.env -- tofu -chdir=$REPO/infra output -raw gmail_tester_authorize_url)"
echo "Remaining manual steps (Google Cloud console, same OAuth app as prod):"
echo "  1. Consent screen → Test users → add the tester's email"
echo "  2. OAuth client → Authorized redirect URIs → add"
echo "     https://gmail-tester.your-subdomain.workers.dev/callback"
