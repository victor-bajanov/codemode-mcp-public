#!/usr/bin/env bash
# Upgrade: OAuth client-record TTL (security fixes wave 5, A-5).
#
# The wave-5 code drops the five-minute OAuth client sweep and its
# `clientreg:<id>` stamps. Instead the hardening wrapper puts a KV TTL on the
# library's own `client:<id>` record: 30 days after `/register`
# (OAUTH_CLIENT_TTL_SECONDS) and 120 days (90-day grant + 30) after every
# successful `/token`. Records written before the deploy have no TTL and would
# never expire, and the old stamps are no longer read. This script, per
# deployment and in this order:
#   1. deploys the new code (so the old sweep stops reaping and stamping
#      before step 2; running step 2 first would be undone by the old cron);
#   2. lists `client:*` in OAUTH_KV, reads every key with no expiration with
#      `kv bulk get` (100 keys per call, the API's limit) and writes them all
#      back verbatim in one `kv bulk put` whose items carry
#      `expiration_ttl: <active TTL>` (120 days): every existing client gets
#      the active lifetime; junk then drains, clients in use are renewed by
#      their next `/token`;
#   3. lists `clientreg:*` and bulk-deletes them.
# Re-running is safe: step 2 skips keys that already have an expiration and
# step 3 finds nothing left to delete.
#
# User-visible after the deploy: a connector not used for 120 days must be
# removed and re-added in the MCP client (before, any connector whose grant
# had lapsed hit this within five minutes). No new var, no wrangler.jsonc
# change, no secret.
#
# Deployments, in the default (rollout) order — dev before tester before prod:
#   gmail-dev     apps/gmail    --env=dev     pnpm deploy:gmail:dev
#   gmail-tester  apps/gmail    --env=tester  pnpm deploy:gmail:tester
#   gmail         apps/gmail    (top level)   pnpm deploy:gmail
#   xero-dev      apps/xero     --env=dev     pnpm deploy:xero:dev
#   xero          apps/xero     (top level)   pnpm deploy:xero
#   optical-dev   apps/optical  --env=dev     pnpm deploy:optical:dev
#   optical       apps/optical  (top level)   pnpm deploy:optical
# Any other deployment: --app=<dir under apps/> --wrangler-env=<env name>
# (or --wrangler-env=- for the top level); it is deployed with
# `wrangler deploy [--env=<name>]` from that app directory.
#
# Credentials come only from `op run --env-file=infra/.env`: the real run
# re-executes this script once under `op run` (CLOUDFLARE_API_TOKEN is
# injected into that child process), so there is one 1Password approval for
# the whole run and nothing is read out of 1Password into the calling shell.
# --dry-run never calls op or wrangler: it prints every command, with <file>
# placeholders standing in for the generated key lists.
#
# Flags verified against wrangler 4.87.0 (`wrangler kv key list --help`,
# `wrangler kv bulk get|put|delete --help`). In 4.87.0 `kv bulk put --ttl`
# is not applied to remote writes; the TTL therefore goes in each item's
# `expiration_ttl`, which the bulk API honours.
#
# Usage:
#   scripts/upgrade/2026-11-11-oauth-client-ttl.sh                              # all seven, in the order above (stops at the first failure)
#   scripts/upgrade/2026-11-11-oauth-client-ttl.sh --env-only=gmail-dev         # just one
#   scripts/upgrade/2026-11-11-oauth-client-ttl.sh --app=optical --wrangler-env=<name>  # a deployment not listed above
#   scripts/upgrade/2026-11-11-oauth-client-ttl.sh --dry-run [--env-only=…]     # print the commands, run nothing
#   --ttl-seconds=<n>  the TTL step 2 sets (default 10368000, 120 days); only
#                      needed when OAUTH_CLIENT_TTL_SECONDS is not 2592000
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"

# 90-day grant lifetime (MCP_REFRESH_TOKEN_TTL_SECONDS) + 30-day
# OAUTH_CLIENT_TTL_SECONDS default = the TTL a client gets on each /token.
GRANT_SECONDS=7776000
CLIENT_TTL_DEFAULT=2592000
ACTIVE_TTL=$((GRANT_SECONDS + CLIENT_TTL_DEFAULT))

ALL_ENVS=(gmail-dev gmail-tester gmail xero-dev xero optical-dev optical)
DRY_RUN=0
ONLY=""
CUSTOM_APP=""
CUSTOM_ENV=""
TTL_OVERRIDE=""

usage() {
  sed -n '2,/^set -euo pipefail$/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
}

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --env-only=*) ONLY="${arg#--env-only=}" ;;
    --app=*) CUSTOM_APP="${arg#--app=}" ;;
    --wrangler-env=*) CUSTOM_ENV="${arg#--wrangler-env=}" ;;
    --ttl-seconds=*) TTL_OVERRIDE="${arg#--ttl-seconds=}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $arg (try --help)" >&2; exit 2 ;;
  esac
done

if [ -n "$TTL_OVERRIDE" ]; then
  if ! [[ "$TTL_OVERRIDE" =~ ^[1-9][0-9]*$ ]]; then
    echo "--ttl-seconds: must be a positive integer, got '$TTL_OVERRIDE'" >&2
    exit 2
  fi
  ACTIVE_TTL="$TTL_OVERRIDE"
fi

if [ -n "$CUSTOM_APP" ] || [ -n "$CUSTOM_ENV" ]; then
  if [ -z "$CUSTOM_APP" ] || [ -z "$CUSTOM_ENV" ] || [ -n "$ONLY" ]; then
    echo "--app and --wrangler-env go together, without --env-only" >&2
    exit 2
  fi
  if ! [[ "$CUSTOM_APP" =~ ^[a-z0-9][a-z0-9-]*$ ]] || [ ! -f "$REPO/apps/$CUSTOM_APP/wrangler.jsonc" ]; then
    echo "--app: no apps/$CUSTOM_APP/wrangler.jsonc" >&2
    exit 2
  fi
  if ! [[ "$CUSTOM_ENV" =~ ^(-|[a-z0-9][a-z0-9-]*)$ ]]; then
    echo "--wrangler-env: expected an env name or '-', got '$CUSTOM_ENV'" >&2
    exit 2
  fi
  TARGETS=("custom")
elif [ -n "$ONLY" ]; then
  found=0
  for e in "${ALL_ENVS[@]}"; do [ "$e" = "$ONLY" ] && found=1; done
  if [ "$found" -ne 1 ]; then
    echo "--env-only: unknown deployment '$ONLY' (one of: ${ALL_ENVS[*]}; use --app/--wrangler-env for others)" >&2
    exit 2
  fi
  TARGETS=("$ONLY")
else
  TARGETS=("${ALL_ENVS[@]}")
fi

# name → "<app dir> <wrangler env or -> <deploy: pnpm script, or - for wrangler deploy>"
spec_for() {
  case "$1" in
    gmail)        echo "gmail - deploy:gmail" ;;
    gmail-dev)    echo "gmail dev deploy:gmail:dev" ;;
    gmail-tester) echo "gmail tester deploy:gmail:tester" ;;
    xero)         echo "xero - deploy:xero" ;;
    xero-dev)     echo "xero dev deploy:xero:dev" ;;
    optical)      echo "optical - deploy:optical" ;;
    optical-dev)  echo "optical dev deploy:optical:dev" ;;
    custom)       echo "$CUSTOM_APP $CUSTOM_ENV -" ;;
    *) echo "internal: no spec for '$1'" >&2; return 1 ;;
  esac
}

# Pre-flight 1: the default TTL assumes OAUTH_CLIENT_TTL_SECONDS is the
# 30-day default everywhere it is declared in a targeted app. A different
# value needs --ttl-seconds (= 7776000 + that value).
if [ -z "$TTL_OVERRIDE" ]; then
  checked_apps=" "
  for name in "${TARGETS[@]}"; do
    read -r app _env _deploy <<<"$(spec_for "$name")"
    case "$checked_apps" in *" $app "*) continue ;; esac
    checked_apps="$checked_apps$app "
    cfg="$REPO/apps/$app/wrangler.jsonc"
    odd="$(grep -E '^[[:space:]]*"OAUTH_CLIENT_TTL_SECONDS"[[:space:]]*:' "$cfg" \
      | grep -vcE "\"OAUTH_CLIENT_TTL_SECONDS\"[[:space:]]*:[[:space:]]*\"$CLIENT_TTL_DEFAULT\"" || true)"
    if [ "$odd" != "0" ]; then
      echo "pre-flight: $cfg sets OAUTH_CLIENT_TTL_SECONDS to something other than $CLIENT_TTL_DEFAULT; pass --ttl-seconds=<7776000 + that value>. Aborting; nothing was deployed." >&2
      exit 1
    fi
  done
  echo "pre-flight: OAUTH_CLIENT_TTL_SECONDS is the default in:${checked_apps% }; active TTL $ACTIVE_TTL s."
fi

# Pre-flight 2: the tools the real run calls (skipped on --dry-run).
UNDER_OP="${CM_OAUTH_CLIENT_TTL_UNDER_OP:-0}"
if [ "$DRY_RUN" -eq 0 ] && [ "$UNDER_OP" != "1" ]; then
  for tool in op npx pnpm node; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "pre-flight: '$tool' is not on PATH. Aborting; nothing was deployed." >&2
      exit 1
    fi
  done
  if [ ! -f "$REPO/infra/.env" ]; then
    echo "pre-flight: $REPO/infra/.env (the op run env file) is missing. Aborting; nothing was deployed." >&2
    exit 1
  fi
  # One op run for the whole upgrade: re-execute this script under it.
  echo "+ op run --env-file=$REPO/infra/.env -- $0 $*"
  exec op run --env-file="$REPO/infra/.env" -- env CM_OAUTH_CLIENT_TTL_UNDER_OP=1 "$0" "$@"
fi

# Print the command (shell-quoted) and run it unless --dry-run.
run() {
  printf '+'; printf ' %q' "$@"; printf '\n'
  [ "$DRY_RUN" -eq 1 ] || "$@"
}

# Same, with stdout to a file.
run_to() {
  local out="$1"; shift
  printf '+'; printf ' %q' "$@"; printf ' > %q\n' "$out"
  [ "$DRY_RUN" -eq 1 ] || "$@" >"$out"
}

# wrangler can print banners and warnings (some with "[...]") and a trailing
# "Success!" around its JSON on stdout: take the first "[" or "{" from which
# the text up to the last matching closer parses as JSON; fail otherwise.
json_of() {
  node -e '
    const t = require("fs").readFileSync(process.argv[1], "utf8");
    for (let i = 0; i < t.length; i++) {
      if (t[i] !== "[" && t[i] !== "{") continue;
      const end = t.lastIndexOf(t[i] === "[" ? "]" : "}");
      if (end < i) continue;
      try {
        process.stdout.write(JSON.stringify(JSON.parse(t.slice(i, end + 1))));
        process.exit(0);
      } catch {}
    }
    console.error(`no JSON in ${process.argv[1]}`);
    process.exit(1);
  ' "$1"
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ "$DRY_RUN" -eq 1 ]; then
  echo "dry run: the real run executes everything below inside one"
  echo "+ op run --env-file=$REPO/infra/.env -- $0 <same arguments>"
fi

for name in "${TARGETS[@]}"; do
  read -r app env deploy <<<"$(spec_for "$name")"
  env_flag=()
  [ "$env" = "-" ] || env_flag=("--env=$env")
  kv=(--binding=OAUTH_KV ${env_flag[@]+"${env_flag[@]}"} --remote)
  label="$name"
  [ "$name" = "custom" ] && label="apps/$app ${env_flag[*]:-(top level)}"
  work="$TMP/$name"
  mkdir -p "$work"

  echo
  echo "=== $label: 1. deploy (stops the old sweep and stamps) ==="
  if [ "$deploy" = "-" ]; then
    run cd "$REPO/apps/$app"
    run npx wrangler deploy ${env_flag[@]+"${env_flag[@]}"}
  else
    run cd "$REPO"
    run pnpm "$deploy"
  fi

  echo "=== $label: 2. give every client:* record without an expiration a ${ACTIVE_TTL}s TTL ==="
  run cd "$REPO/apps/$app"
  run_to "$work/clients.out" npx wrangler kv key list --prefix=client: "${kv[@]}"
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  names with no \"expiration\", split 100 per file into <names-N.json>:"
    run_to "<values-N.out>" npx wrangler kv bulk get "<names-N.json>" "${kv[@]}"
    echo "  every JSON value, verbatim, as {key, value, expiration_ttl: $ACTIVE_TTL} in <put.json>:"
    run npx wrangler kv bulk put "<put.json>" "${kv[@]}"
  else
    json_of "$work/clients.out" >"$work/clients.json"
    # Names without an expiration, 100 per file (the bulk-get API limit).
    node -e '
      const fs = require("fs");
      const names = JSON.parse(fs.readFileSync(process.argv[1], "utf8"))
        .filter((k) => k.expiration === undefined).map((k) => k.name);
      for (let i = 0; i * 100 < names.length; i++) {
        fs.writeFileSync(`${process.argv[2]}/names-${i}.json`, JSON.stringify(names.slice(i * 100, i * 100 + 100)));
      }
      console.log(`  ${names.length} client records have no expiration.`);
    ' "$work/clients.json" "$work"
    for names in "$work"/names-*.json; do
      [ -e "$names" ] || continue
      run_to "${names%.json}.out" npx wrangler kv bulk get "$names" "${kv[@]}"
      json_of "${names%.json}.out" >"${names%.json}.values.json"
    done
    # One bulk put of every JSON record, verbatim, with the active TTL. A value
    # that is missing or not JSON is reported and left as it is.
    node -e '
      const fs = require("fs");
      const [dir, ttl] = [process.argv[1], Number(process.argv[2])];
      const items = [];
      for (const f of fs.readdirSync(dir).filter((f) => f.endsWith(".values.json"))) {
        const values = JSON.parse(fs.readFileSync(`${dir}/${f}`, "utf8"));
        for (const [key, v] of Object.entries(values)) {
          const value = v !== null && typeof v === "object" ? v.value : v;
          try {
            if (typeof value !== "string") throw new Error("missing");
            JSON.parse(value);
          } catch {
            console.error(`  skipped ${key}: value missing or not JSON (left as it is).`);
            continue;
          }
          items.push({ key, value, expiration_ttl: ttl });
        }
      }
      fs.writeFileSync(`${dir}/put.json`, JSON.stringify(items));
      console.log(items.length);
    ' "$work" "$ACTIVE_TTL" >"$work/put-count.txt"
    if [ "$(cat "$work/put-count.txt")" = "0" ]; then
      echo "  nothing to re-put."
    else
      echo "  re-putting $(cat "$work/put-count.txt") client records."
      run npx wrangler kv bulk put "$work/put.json" "${kv[@]}"
    fi
  fi

  echo "=== $label: 3. delete the orphaned clientreg:* stamps ==="
  run_to "$work/stamps.out" npx wrangler kv key list --prefix=clientreg: "${kv[@]}"
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  the listed names, as a JSON array of strings, in <stamp-names.json>:"
    run npx wrangler kv bulk delete "<stamp-names.json>" --force "${kv[@]}"
  else
    json_of "$work/stamps.out" >"$work/stamps.json"
    node -e '
      const fs = require("fs");
      const keys = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      fs.writeFileSync(process.argv[2], JSON.stringify(keys.map((k) => k.name)));
      console.log(keys.length);
    ' "$work/stamps.json" "$work/stamp-names.json" >"$work/stamp-count.txt"
    if [ "$(cat "$work/stamp-count.txt")" = "0" ]; then
      echo "  no clientreg: stamps left."
    else
      run npx wrangler kv bulk delete "$work/stamp-names.json" --force "${kv[@]}"
    fi
  fi
done

echo
if [ "$DRY_RUN" -eq 1 ]; then
  echo "dry run: nothing was executed."
else
  echo "done: ${TARGETS[*]} deployed; legacy client records have a TTL; clientreg: stamps deleted."
fi
