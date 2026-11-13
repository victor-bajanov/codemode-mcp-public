#!/usr/bin/env bash
# Upgrade: staged-file ownership and the audit trail (security fixes wave 4).
#
# The wave-4 Worker code writes an `owner` on every staging row and counts a
# row's public downloads in `fetch_count`, so migration 0003_owner.sql
# MUST be applied to each deployment's remote STAGING_D1 BEFORE that
# deployment's new code goes live. New code on an unmigrated database refuses
# every store (register_file_handle, putFile, returnAs:"stage", ...) with 500
# "d1 insert failed". wrangler does not apply D1 migrations on deploy, hence
# this script: for every deployment it applies the pending migrations
# remotely, then deploys, in that order.
#
# What changes for users once deployed:
#   - Rows staged before the migration have no owner and are refused by every
#     reader (403 "file not found or not yours", bare `forbidden` on
#     /staging/fetch) until they expire: at most STAGING_FETCH_TTL_SECONDS
#     (default 3600, one hour). Re-stage such files.
#   - The public fetch_url works up to STAGING_FETCH_MAX_USES times (default 5)
#     within STAGING_FETCH_TTL_SECONDS; every GET counts, and past the limit a
#     GET is 410 `gone`.
# No new secret; two new optional vars (STAGING_FETCH_MAX_USES, default 5;
# EXECUTE_MAX_DENIED_CALLS, default 32).
# The optical app has no STAGING_D1 and needs no migration; it picks up the
# audit and sandbox-console changes on its next ordinary deploy.
#
# Deployments, in the default (rollout) order — dev before tester before prod:
#   gmail-dev     apps/gmail  --env=dev    pnpm deploy:gmail:dev
#   gmail-tester  apps/gmail  --env=tester pnpm deploy:gmail:tester
#   gmail         apps/gmail  (top level)  pnpm deploy:gmail
#   xero-dev      apps/xero   --env=dev    pnpm deploy:xero:dev
#   xero          apps/xero   (top level)  pnpm deploy:xero
#
# Credentials come only from `op run --env-file=infra/.env` (CLOUDFLARE_API_TOKEN
# and friends are injected into the child process); nothing is ever read out
# of 1Password into this shell. Each `op run` may stop on a 1Password approval
# prompt, and `wrangler d1 migrations apply` asks for confirmation when run
# from a terminal — both are expected. --dry-run never calls op or wrangler.
#
# Usage:
#   scripts/upgrade/2026-11-11-staging-owner.sh                          # all five, in the order above (stops at the first failure)
#   scripts/upgrade/2026-11-11-staging-owner.sh --env-only=gmail-dev     # just one
#   scripts/upgrade/2026-11-11-staging-owner.sh --dry-run [--env-only=…] # print the commands, run nothing
#
# Recommended rollout: run --env-only=gmail-dev first, then the live checks in
# packages/scaffold/SECURITY.md §7.12 and the staging ladder in
# scripts/harnesses/README.md against it (expect each fetch_url to download up
# to STAGING_FETCH_MAX_USES times, default 5, then 410), then the rest.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
MIGRATIONS_DIR="$REPO/packages/scaffold/src/staging/migrations"
MIGRATION="$MIGRATIONS_DIR/0003_owner.sql"

ALL_ENVS=(gmail-dev gmail-tester gmail xero-dev xero)
DRY_RUN=0
ONLY=""

usage() {
  sed -n '2,/^set -euo pipefail$/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
}

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --env-only=*) ONLY="${arg#--env-only=}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $arg (try --help)" >&2; exit 2 ;;
  esac
done

if [ -n "$ONLY" ]; then
  found=0
  for e in "${ALL_ENVS[@]}"; do [ "$e" = "$ONLY" ] && found=1; done
  if [ "$found" -ne 1 ]; then
    echo "--env-only: unknown deployment '$ONLY' (one of: ${ALL_ENVS[*]})" >&2
    exit 2
  fi
  TARGETS=("$ONLY")
else
  TARGETS=("${ALL_ENVS[@]}")
fi

# name → "<app dir> <wrangler env or -> <pnpm deploy script>"
spec_for() {
  case "$1" in
    gmail)        echo "gmail - deploy:gmail" ;;
    gmail-dev)    echo "gmail dev deploy:gmail:dev" ;;
    gmail-tester) echo "gmail tester deploy:gmail:tester" ;;
    xero)         echo "xero - deploy:xero" ;;
    xero-dev)     echo "xero dev deploy:xero:dev" ;;
    *) echo "internal: no spec for '$1'" >&2; return 1 ;;
  esac
}

# Pre-flight 1: the migration this upgrade exists for is in the tree and adds
# both columns. Without it `migrations apply` would succeed with nothing to do
# and the new code would then fail every store.
if [ ! -f "$MIGRATION" ]; then
  echo "pre-flight: $MIGRATION is missing. Aborting; nothing was migrated or deployed." >&2
  exit 1
fi
for col in owner fetch_count; do
  if ! grep -qiE "^[[:space:]]*ALTER[[:space:]]+TABLE[[:space:]]+staging[[:space:]]+ADD[[:space:]]+COLUMN[[:space:]]+$col[[:space:]]" "$MIGRATION"; then
    echo "pre-flight: $MIGRATION does not add the '$col' column. Aborting; nothing was migrated or deployed." >&2
    exit 1
  fi
done
echo "pre-flight: 0003_owner.sql adds owner and fetch_count."

# Pre-flight 2: every STAGING_D1 binding of each targeted app points its
# migrations_dir at the scaffold's migrations (gmail declares three bindings —
# prod, dev, tester — xero two), so `migrations apply` finds 0003.
expected_bindings() {
  case "$1" in
    gmail) echo 3 ;;
    xero)  echo 2 ;;
    *) echo "internal: no binding count for '$1'" >&2; return 1 ;;
  esac
}
checked_apps=" "
for name in "${TARGETS[@]}"; do
  read -r app _env _deploy <<<"$(spec_for "$name")"
  case "$checked_apps" in *" $app "*) continue ;; esac
  checked_apps="$checked_apps$app "
  cfg="$REPO/apps/$app/wrangler.jsonc"
  want="$(expected_bindings "$app")"
  got="$(grep -E '^[[:space:]]*\{[^}]*"binding"[[:space:]]*:[[:space:]]*"STAGING_D1"' "$cfg" \
    | grep -cE '"migrations_dir"[[:space:]]*:[[:space:]]*"\.\./\.\./packages/scaffold/src/staging/migrations"' || true)"
  if [ "$got" != "$want" ]; then
    echo "pre-flight: $cfg has $got STAGING_D1 binding(s) with migrations_dir ../../packages/scaffold/src/staging/migrations (comments excluded); expected $want." >&2
    echo "Aborting; nothing was migrated or deployed." >&2
    exit 1
  fi
done
echo "pre-flight: STAGING_D1 migrations_dir set on every binding of:${checked_apps% }."

# Pre-flight 3: the tools the real run calls (skipped on --dry-run, which
# calls none of them).
if [ "$DRY_RUN" -eq 0 ]; then
  for tool in op npx pnpm; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "pre-flight: '$tool' is not on PATH. Aborting; nothing was migrated or deployed." >&2
      exit 1
    fi
  done
  if [ ! -f "$REPO/infra/.env" ]; then
    echo "pre-flight: $REPO/infra/.env (the op run env file) is missing. Aborting; nothing was migrated or deployed." >&2
    exit 1
  fi
fi

# Print the command (shell-quoted) and run it unless --dry-run.
run() {
  printf '+'; printf ' %q' "$@"; printf '\n'
  [ "$DRY_RUN" -eq 1 ] || "$@"
}

for name in "${TARGETS[@]}"; do
  read -r app env deploy <<<"$(spec_for "$name")"
  env_flag=()
  [ "$env" = "-" ] || env_flag=("--env=$env")

  echo
  echo "=== $name: apply STAGING_D1 migrations (remote; must precede the deploy) ==="
  # Run from the app dir so wrangler picks up its wrangler.jsonc, whose
  # migrations_dir points at packages/scaffold/src/staging/migrations.
  run cd "$REPO/apps/$app"
  run op run --env-file="$REPO/infra/.env" -- \
    npx wrangler d1 migrations apply STAGING_D1 ${env_flag[@]+"${env_flag[@]}"} --remote

  echo "=== $name: deploy ==="
  run cd "$REPO"
  run op run --env-file="$REPO/infra/.env" -- pnpm "$deploy"
done

echo
if [ "$DRY_RUN" -eq 1 ]; then
  echo "dry run: nothing was executed."
else
  echo "done: ${TARGETS[*]} migrated (0003_owner) and deployed."
fi
