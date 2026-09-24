#!/usr/bin/env bash
# Provision the Cloudflare Access application gating /authorize on the gmail
# Worker's CUSTOM DOMAIN (module.gmail's `custom_domain` in infra/main.tf).
#
# Why: an Access application matches on host+path. The pre-existing app only
# covers the workers.dev hostname's /authorize, so the custom domain — which is
# where the prod connector points — served /authorize with no Access challenge
# at all. Anyone who knew the URL could start an OAuth flow against it.
#
# Idempotent: safe to re-run. Creates nothing if the apply already succeeded.
#
# Preconditions:
#   - infra/.env contains the CLOUDFLARE_API_TOKEN op:// reference
#   - the Google IdP is already linked in Zero Trust (one-time, dashboard)
#
# Usage:
#   ./scripts/apply-custom-domain-access.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

# The custom domain is read back out of the tofu config rather than hardcoded,
# so this script carries no environment-identifying hostname (see
# scripts/release/ — shipped scripts get scrubbed, and a literal here would be
# one more thing to keep in sync with the redaction rules).
CUSTOM_DOMAIN="$(
  awk -F'"' '/^[[:space:]]*custom_domain[[:space:]]*=/ { print $2; exit }' \
    "$REPO/infra/main.tf"
)"
[ -n "$CUSTOM_DOMAIN" ] || {
  echo "could not read custom_domain from infra/main.tf" >&2
  exit 1
}

# 1. Init + plan. The plan is written to disk and reviewed interactively before
#    apply, so drift on the shared worker module (xero, optical, *-dev all use
#    it) is visible before anything touches Cloudflare. Expect exactly two
#    resources to be added and zero changed/destroyed.
op run --env-file="$REPO/infra/.env" -- \
  tofu -chdir="$REPO/infra" init

op run --env-file="$REPO/infra/.env" -- \
  tofu -chdir="$REPO/infra" plan -out=.tfplan

echo
echo "Expected: 2 to add (cloudflare_zero_trust_access_application.authorize_custom_domain"
echo "and its policy, both under module.gmail), 0 to change, 0 to destroy."
echo
read -r -p "Review the plan above. Press ENTER to apply, Ctrl-C to abort: " _

op run --env-file="$REPO/infra/.env" -- \
  tofu -chdir="$REPO/infra" apply .tfplan

rm -f "$REPO/infra/.tfplan"

# 2. Verify the gate is live. Before this change the custom domain returned the
#    Worker's own response; after it, an unauthenticated GET must 302 to the
#    cloudflareaccess.com login. No Worker redeploy is needed — Access sits in
#    front of the Worker.
echo
echo "Verifying custom-domain /authorize is now gated..."
STATUS_AND_LOCATION="$(
  curl -s -o /dev/null -w '%{http_code} %{redirect_url}' \
    "https://${CUSTOM_DOMAIN}/authorize"
)"
echo "  -> ${STATUS_AND_LOCATION}"
case "${STATUS_AND_LOCATION}" in
  302*cloudflareaccess.com*)
    echo "  OK — Access challenge is in front of the custom domain."
    ;;
  *)
    echo "  FAIL — expected a 302 to *.cloudflareaccess.com."
    echo "  Access apps can take a few seconds to propagate; re-run this curl."
    echo "  If it persists, check the app's domain matches the route in"
    echo "  apps/gmail/wrangler.jsonc exactly (host + /authorize path)."
    exit 1
    ;;
esac

# 3. Reconnecting a connector now requires passing the Access challenge as an
#    email in var.allowed_emails. Existing grants are unaffected — Access gates
#    grant ISSUANCE at /authorize, not the /mcp calls that use an existing token.
echo
echo "Done. Re-auth flows on the custom domain now require Cloudflare Access."
echo "Existing connectors keep working; only new /authorize runs are challenged."
