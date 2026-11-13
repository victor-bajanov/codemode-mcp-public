#!/usr/bin/env bash
# Upgrade: Calendar write allow-list (security fixes wave 2).
#
# The wave-2 Gmail code denies every Calendar event write (insert, update,
# patch, import, move) unless the event's calendar is on the deployment's
# CALENDAR_WRITE_ALLOWLIST var. That var is a plain wrangler var declared in
# apps/gmail/wrangler.jsonc (one entry per vars block: top level = prod,
# env.dev, env.tester), so the upgrade is a redeploy of the three Gmail
# deployments. No secret, no D1 migration, no tofu.
#
# A deployment redeployed WITHOUT the var denies every Calendar event write
# (fail closed). The pre-flight below aborts unless wrangler.jsonc declares the
# var exactly three times, once per vars block. `primary` must be listed
# explicitly; add any secondary calendar ids the user owns, comma-separated.
#
# Deployments, in rollout order — dev before tester before prod:
#   gmail-dev     apps/gmail  --env=dev     pnpm deploy:gmail:dev
#   gmail-tester  apps/gmail  --env=tester  pnpm deploy:gmail:tester
#   gmail         apps/gmail  (top level)   pnpm deploy:gmail
#
# Credentials come only from `op run --env-file=infra/.env` (CLOUDFLARE_API_TOKEN
# is injected into the child process); nothing is read out of 1Password into
# this shell. Each `op run` may stop on a 1Password approval prompt. --dry-run
# never calls op or wrangler.
#
# Usage:
#   scripts/upgrade/2026-11-10-calendar-write-allowlist.sh                          # all three, in the order above (stops at the first failure)
#   scripts/upgrade/2026-11-10-calendar-write-allowlist.sh --env-only=gmail-dev     # just one
#   scripts/upgrade/2026-11-10-calendar-write-allowlist.sh --dry-run [--env-only=…] # print the commands, run nothing
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WRANGLER_CONFIG="$REPO/apps/gmail/wrangler.jsonc"
VAR=CALENDAR_WRITE_ALLOWLIST

ALL_ENVS=(gmail-dev gmail-tester gmail)
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

# Pre-flight: the var must be declared once per vars block (prod, dev, tester),
# each as an uncommented "VAR": "<non-blank value>" line. A commented-out or
# blank declaration does not count.
count="$(grep -cE "^[[:space:]]*\"$VAR\"[[:space:]]*:[[:space:]]*\"[^\"]*[^\"[:space:]][^\"]*\"" "$WRANGLER_CONFIG" || true)"
if [ "$count" != "3" ]; then
  echo "pre-flight: $WRANGLER_CONFIG declares \"$VAR\" with a non-blank value $count time(s) (comments excluded); expected exactly 3 (top-level vars, env.dev.vars, env.tester.vars)." >&2
  echo "Without it a redeployed Gmail worker denies every Calendar event write. Aborting; nothing was deployed." >&2
  exit 1
fi
echo "pre-flight: \"$VAR\" declared in all three vars blocks of apps/gmail/wrangler.jsonc."

# Print the command (shell-quoted) and run it unless --dry-run.
run() {
  printf '+'; printf ' %q' "$@"; printf '\n'
  [ "$DRY_RUN" -eq 1 ] || "$@"
}

deploy_script_for() {
  case "$1" in
    gmail)        echo "deploy:gmail" ;;
    gmail-dev)    echo "deploy:gmail:dev" ;;
    gmail-tester) echo "deploy:gmail:tester" ;;
    *) echo "internal: no deploy script for '$1'" >&2; return 1 ;;
  esac
}

for name in "${TARGETS[@]}"; do
  deploy="$(deploy_script_for "$name")"
  echo
  echo "=== $name: deploy ==="
  run cd "$REPO"
  run op run --env-file="$REPO/infra/.env" -- pnpm "$deploy"
done

echo
if [ "$DRY_RUN" -eq 1 ]; then
  echo "dry run: nothing was executed."
else
  echo "done: ${TARGETS[*]} redeployed with $VAR."
fi
