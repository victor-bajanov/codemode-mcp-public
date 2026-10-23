#!/usr/bin/env bash
# Upgrade: staged file transfer v2 (issue #59).
#
# The v2 Worker code writes `enc_version` on every staging row, so migration
# 0002_enc_version.sql MUST be applied to each deployment's remote STAGING_D1
# before that deployment's new code goes live. wrangler does not apply D1
# migrations on deploy, hence this script: for every deployment it applies the
# pending migrations remotely, then deploys, in that order.
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
# from a terminal — both are expected.
#
# Usage:
#   scripts/upgrade/2026-10-15-staging-v2.sh                       # all five, in the order above (stops at the first failure)
#   scripts/upgrade/2026-10-15-staging-v2.sh --env-only=gmail-dev  # just one
#   scripts/upgrade/2026-10-15-staging-v2.sh --dry-run [--env-only=…]  # print the commands, run nothing
#
# Recommended rollout (plan "Expensive phase"): run --env-only=gmail-dev first,
# then the live staging ladder against it, then the rest.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"

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

# Print the command (shell-quoted) and run it unless --dry-run.
run() {
  printf '+'; printf ' %q' "$@"; printf '\n'
  [ "$DRY_RUN" -eq 1 ] || "$@"
}

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

for name in "${TARGETS[@]}"; do
  read -r app env deploy <<<"$(spec_for "$name")"
  env_flag=()
  [ "$env" = "-" ] || env_flag=("--env=$env")

  echo
  echo "=== $name: apply STAGING_D1 migrations (remote) ==="
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
  echo "done: ${TARGETS[*]} migrated and deployed."
fi
