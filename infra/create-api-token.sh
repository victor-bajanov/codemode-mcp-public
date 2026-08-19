#!/usr/bin/env bash
set -euo pipefail

# Creates (or updates in place) a single scoped Cloudflare API token for the
# codemode-mcp project. The token is used by BOTH:
#
#   * wrangler deploy / wrangler secret put  (apps/*/wrangler.jsonc)
#   * tofu apply                              (infra/main.tf — KV namespaces +
#                                              Zero Trust Access apps/policies)
#
# Both read it from the CLOUDFLARE_API_TOKEN env var (see infra/main.tf and
# wrangler's standard auth). We no longer use the Global API Key.
#
# Auth: this script authenticates with a *single-use creation token* you mint
# by hand, NOT the global key. That creation token only needs:
#       User > API Tokens > Edit
# (it can be deleted immediately after this script succeeds.)
#
# Usage:
#   export CF_CREATE_TOKEN='<single-use token with User API Tokens: Edit>'
#   ./infra/create-api-token.sh
#
# Account id is not a secret — hardcoded below. No zone-scoped permissions:
# codemode-mcp deploys to *.workers.dev only, with no custom domains / WAF /
# DNS records owned by tofu. No user-scoped permissions either; wrangler's
# /memberships preflight is skipped by setting CLOUDFLARE_ACCOUNT_ID in
# infra/.env, which lets wrangler go straight to the account-scoped endpoint.
CF_ACCOUNT_ID="REPLACE_WITH_YOUR_CLOUDFLARE_ACCOUNT_ID"
TOKEN_NAME="codemode-mcp-deploy"

: "${CF_CREATE_TOKEN:?Set CF_CREATE_TOKEN to a single-use token with 'User > API Tokens > Edit'}"

API="https://api.cloudflare.com/client/v4"
AUTH=(-H "Authorization: Bearer ${CF_CREATE_TOKEN}")

echo "Fetching permission groups..."
RAW=$(curl -sf "${AUTH[@]}" "${API}/user/tokens/permission_groups")

# Exact permissions needed, with explicit scope.
# Format: "scope|name" where scope is "account".
WANTED=(
  # --- wrangler deploy + wrangler secret put: worker code + secret store ---
  "account|Workers Scripts Read"
  "account|Workers Scripts Write"

  # --- KV namespace creation (tofu) + KV reads/writes from the worker runtime ---
  "account|Workers KV Storage Read"
  "account|Workers KV Storage Write"

  # --- staging resources for bootstrap scripts: `wrangler d1 create` /
  #     `d1 migrations apply --remote` and `wrangler r2 bucket create` ---
  "account|D1 Read"
  "account|D1 Write"
  "account|Workers R2 Storage Read"
  "account|Workers R2 Storage Write"

  # --- tofu: Zero Trust Access apps + policies (and identity reads for allowed_idps) ---
  "account|Access: Apps and Policies Read"
  "account|Access: Apps and Policies Write"
  "account|Access: Organizations, Identity Providers, and Groups Read"
)

# Look up each permission by exact name + scope.
ACCOUNT_PG_JSON=""
MISSING=()

for entry in "${WANTED[@]}"; do
  want_scope="${entry%%|*}"
  want_name="${entry#*|}"

  if [ "$want_scope" = "account" ]; then
    scope_match="com.cloudflare.api.account"
  else
    scope_match="com.cloudflare.api.account.zone"
  fi

  id=$(echo "$RAW" | jq -r --arg name "$want_name" --arg scope "$scope_match" '
    .result[] | select(.name == $name and ((.scopes // [])[0] == $scope)) | .id
  ')

  if [ -z "$id" ]; then
    MISSING+=("${want_scope}|${want_name}")
    continue
  fi

  pg="{\"id\":\"${id}\"}"
  [ -n "$ACCOUNT_PG_JSON" ] && ACCOUNT_PG_JSON+=","
  ACCOUNT_PG_JSON+="$pg"

  printf "  %-55s [%s]\n" "$want_name" "$want_scope"
done

if [ ${#MISSING[@]} -gt 0 ]; then
  echo ""
  echo "Missing permissions:"
  for m in "${MISSING[@]}"; do
    echo "  - ${m#*|} (${m%%|*})"
  done
  echo ""
  echo "Available permission groups matching Workers/KV/Access:"
  echo "$RAW" | jq -r '
    .result[] | select(.name | test("Workers Script|Workers KV|Access"; "i"))
    | "  \(.id)  \(.name)  \((.scopes // []) | join(", "))"
  '
  echo ""
  echo "Update WANTED in this script to match the above, then rerun."
  exit 1
fi

POLICIES="[{
  \"effect\": \"allow\",
  \"resources\": {\"com.cloudflare.api.account.${CF_ACCOUNT_ID}\": \"*\"},
  \"permission_groups\": [${ACCOUNT_PG_JSON}]
}]"

echo ""
echo "Token policies:"
printf '{"name":"%s","policies":%s}' "$TOKEN_NAME" "$POLICIES" \
  | jq '.policies[] | {resources: (.resources | keys), permissions: [.permission_groups[].id[:8]]}' 2>/dev/null || true

# Idempotent: update an existing token of the same name in place, else create.
echo ""
echo "Checking for existing '${TOKEN_NAME}' token..."
EXISTING=$(curl -sf "${AUTH[@]}" "${API}/user/tokens" \
  | jq -r --arg name "$TOKEN_NAME" '.result[] | select(.name == $name) | .id')

if [ -n "$EXISTING" ]; then
  TOKEN_ID="$EXISTING"
  echo "Found existing token: ${TOKEN_ID} — updating permissions..."

  UPDATE_PAYLOAD=$(printf '{"name":"%s","policies":%s,"status":"active"}' "$TOKEN_NAME" "$POLICIES")

  RESPONSE=$(curl -sf "${AUTH[@]}" \
    -H "Content-Type: application/json" \
    -X PUT "${API}/user/tokens/${TOKEN_ID}" \
    -d "${UPDATE_PAYLOAD}")

  SUCCESS=$(echo "$RESPONSE" | jq -r '.success')
  if [ "$SUCCESS" != "true" ]; then
    echo "Failed to update token:"
    echo "$RESPONSE" | jq '.errors'
    exit 1
  fi

  echo "Token updated successfully!"
  echo ""
  echo "  Token ID: ${TOKEN_ID}"
  echo ""
  echo "The token value is unchanged. If you need a new value, roll it in the dashboard."
else
  echo "No existing token found — creating new one..."

  PAYLOAD=$(printf '{"name":"%s","policies":%s}' "$TOKEN_NAME" "$POLICIES")

  RESPONSE=$(curl -sf "${AUTH[@]}" \
    -H "Content-Type: application/json" \
    -X POST "${API}/user/tokens" \
    -d "${PAYLOAD}")

  SUCCESS=$(echo "$RESPONSE" | jq -r '.success')
  if [ "$SUCCESS" != "true" ]; then
    echo "Failed to create token:"
    echo "$RESPONSE" | jq '.errors'
    exit 1
  fi

  TOKEN=$(echo "$RESPONSE" | jq -r '.result.value')
  TOKEN_ID=$(echo "$RESPONSE" | jq -r '.result.id')

  echo "Token created successfully!"
  echo ""
  echo "  Token ID: ${TOKEN_ID}"
  echo "  Value:    ${TOKEN}"
  echo ""
  echo "Store this value securely — it won't be shown again."
fi

echo ""
echo "Next steps:"
echo "  1. Store the token value in 1Password (e.g. item 'Codemode MCP Cloudflare Token', field 'credential')."
echo "  2. Point infra/.env at it (replacing the old Global API Key lines):"
echo "       CLOUDFLARE_API_TOKEN=op://YourVault/<item>/credential"
echo "       CLOUDFLARE_ACCOUNT_ID=op://YourVault/<item>/credential"
echo "     (the explicit account id lets wrangler skip its /memberships preflight,"
echo "      which would otherwise need a user-scoped permission this token doesn't have.)"
echo "  3. Tofu (reads CLOUDFLARE_API_TOKEN automatically):"
echo "       op run --env-file=infra/.env -- tofu -chdir=infra plan"
echo "  4. Wrangler deploys (same env file — the per-app bootstrap script wraps these):"
echo "       op run --env-file=infra/.env -- pnpm run deploy:gmail:dev"
echo ""
echo "  Then delete the single-use CF_CREATE_TOKEN you used to run this script."
