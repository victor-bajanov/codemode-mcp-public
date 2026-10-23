# Operator security runbook

This is an operator runbook for the `@local/scaffold` package. It
describes where audit and debug log lines go, what the default
redaction posture looks like, how to deliberately unlock PII logging
when an incident calls for it, how to inspect the OAuth state KV, and
the OAuth, sandbox and edge controls added after the 2026-10-07
defensive security review and for staged transfers v2 (section 7).
It is intentionally not a vuln-disclosure policy.

## 1. Log sinks

`console.log` calls inside the worker land in the Workers runtime log
stream. From there:

- `wrangler tail` streams them to the operator's terminal while
  attached. Tail output is **not** persisted anywhere — it exists only
  in the session that opened it.
- Workers Logs / Logpush capture the same stream if the Cloudflare
  account has them enabled. Retention is whatever the account is
  configured for; see section 5.

Both `AUDIT` lines and any `DEBUG-ELICIT` lines share the same sink.

## 2. Default redaction (post this branch)

By default, every `AUDIT` line drops the PII-bearing values inside
`elicitFields` before it reaches `console.log`.

**Preserved** (outside `elicitFields`, always emitted as-is):

- `deployment`
- `operationId`
- `method`
- `path`
- `decision`
- `category`
- `reason`
- `principalId` — preserved as the operator-identity primitive for
  single-operator deployments
- `ts`
- `elicitationOutcome`
- `upstreamStatus`

**Replaced** (`elicitFields` is rewritten):

```
elicitFields: {
  __redacted__: true,
  keys: [<field names>],
  <field>Length:  <n>   // for string fields
  <field>Count:   <n>   // for array fields
  <field>Value:   0     // for number fields (the value itself is dropped)
}
```

The redaction runs after the entry is enriched with `principalId` and
the rest of the preserved keys, so identity and decision metadata
always survive.

## 3. Enabling PII logging

When an investigation needs the raw field values, unlock them
deliberately for the affected app:

1. Edit `apps/<name>/wrangler.jsonc` and set the existing var:

   ```jsonc
   "vars": {
     "ALLOW_PII_IN_LOGS": "true"
   }
   ```

2. Deploy:

   ```bash
   pnpm --filter @apps/<name> deploy
   ```

3. Verify by triggering one tool call and watching the live stream:

   ```bash
   npx wrangler tail
   ```

   The `AUDIT` line should now contain the raw `elicitFields` values
   instead of the `__redacted__` envelope.

Reverse the unlock by setting `ALLOW_PII_IN_LOGS` back to `"false"`
and redeploying. The flag is per-app — flipping it for `gmail` does
not change `xero`'s behaviour.

## 4. Enabling `DEBUG_ELICIT`

`DEBUG_ELICIT` emits low-level traces from the elicitation pipeline.
The unlock shape is the same as section 3:

1. Set `vars.DEBUG_ELICIT` to `"true"` in `apps/<name>/wrangler.jsonc`.
2. `pnpm --filter @apps/<name> deploy`.

PII-bearing markers stay redacted **until `ALLOW_PII_IN_LOGS` is also
set to `"true"`**. The two flags compose: `DEBUG_ELICIT` controls
whether the markers fire; `ALLOW_PII_IN_LOGS` controls whether the
PII-bearing ones carry their payload.

Marker classification:

- **PII-gated** (require both flags to see the payload): `wrap-pre`,
  `wrap-post`, `request-entry`, `elicit-pre-send`, `elicit-catch`,
  `elicit-result`.
- **Unconditional under `DEBUG_ELICIT="true"`**: `elicit-branch`,
  `elicit-caps`.

## 5. Workers Logs retention

After any incident that touched PII, check the Cloudflare account's
Workers Logs retention setting. If PII was captured before this branch
landed, two options:

- **Lower retention** for the affected period so the older lines roll
  out of the window faster.
- **Wait the window out** if retention is already short enough.

`wrangler tail` output exists only in the operator's terminal session
and is not retained anywhere on Cloudflare's side. There is nothing to
purge for tail-only investigations.

## 6. KV inspection

`OAUTH_KV` holds the OAuth library's own grant, token and client
records plus the scaffold keys below. Every scaffold key expires on its
own, is rewritten in normal use, or (`clientreg:<id>`) is removed with
its client by the scheduled sweep.

### `auth-state:<state>` — in-flight sign-in (600 s TTL)

Written when the operator approves the consent page (`POST /authorize`)
and consumed (deleted) when `/callback` exchanges the resulting
authorisation code for tokens. TTL is **600 s** (10 minutes), so
entries left behind from abandoned sign-ins drop out on their own.

The stored envelope:

```json
{
  "oauthReqInfo": { /* the original /authorize request: clientId, scopes, redirect_uri, … */ },
  "codeVerifier": "<base64url>",
  "bindingHash": "<base64url SHA-256 of the __Host-cm-auth-<state> cookie value>"
}
```

`codeVerifier` is the upstream PKCE secret bound to one in-flight
authorisation code (absent for a provider without upstream PKCE); once
`/callback` has redeemed that code the verifier has no further value.
`bindingHash` ties the flow to the browser that approved it (section
7.1). It is required: an envelope without it, including the pre-review
shape with no `bindingHash`, is treated as invalid and the sign-in must
be restarted. There is no legacy shape to migrate.

### `consent-used:<id>` — spent consent tokens (600 s TTL)

Written when a consent form token is redeemed (approve or deny), so the
same token cannot be submitted twice. The TTL outlives the token's own
300 s lifetime. The value is a constant marker; nothing sensitive is
stored.

### `clientreg:<id>` — client registration stamps (no TTL)

Written when `POST /register` succeeds, recording the new client's
registration time (`{"registeredAt": <ms>}`) so the scheduled sweep can
age it. It has no TTL: the 30-day inactive-client sweep deletes it
together with its `client:<id>` record once the client is older than
the window and no grant references it. A client that holds a grant
keeps its stamp. Nothing sensitive is stored.

### `token-slot:<userId>:<sha256>` — per-grant upstream token slots (180-day TTL)

The TokenBroker's encrypted slot for one MCP grant: the upstream
access token, its expiry and (on rotating providers such as Xero and
Optical) the current upstream refresh token, AES-GCM-sealed under a key
wrapped by that grant's original upstream refresh token. `<sha256>` is
the hex SHA-256 of that original token, so each grant of one user has
its own slot; the broker Durable Object is still one per `userId`, and
runs at most one refresh per grant at a time.

**The KV key is a copy; the broker's Durable Object storage is the
authority.** The broker keeps each grant's slot in its own
`ctx.storage` under the same key, as `{ sealed, writtenAt }`, where
`sealed` is byte-for-byte the shape KV holds (sealed under the grant's
original refresh token) and `writtenAt` is a plain epoch-ms timestamp.
A dump of either store alone exposes no live token. The broker reads
storage first and reads KV only on a storage miss, adopting what it
finds there (the sign-in seed, below, or a slot written before storage
became the authority) into storage. While storage holds the grant it
reads KV only for rollback recovery (below), because KV is eventually
consistent: a broker read
primes the location's KV cache, a later write doesn't invalidate it,
and a fresh broker instance (after an eviction) could otherwise read
the pre-rotation slot for up to KV's cache TTL and replay a spent
refresh token. So inspecting the KV key shows the last rotation that
reached KV, not necessarily the live chain.

On every refresh the broker seals the new slot once. When the refresh
token rotated (or a legacy slot was adopted) it first writes the sealed
blob to KV, refreshing its **180-day** TTL. A KV failure there doesn't
fail the call and isn't retried: it is logged as `<displayName> token
slot KV write failed` (no token material, no error object). It then
writes storage. If sealing or the storage write fails, the call fails
(`Upstream token could not be saved…`; a seal failure also logs
`<displayName> token slot seal failed`), so no token is handed out
whose rotated chain wasn't recorded. Writing KV first means a failed
storage write after an upstream rotation doesn't lose the new chain:
the next call presents storage's spent token, is rejected, and recovers
the chain from KV (below). So KV may lead storage by one rotation; that
is safe because recovery adopts KV only once the upstream accepts its
token or its access token is still valid, and reads never prefer KV
over storage. Cache hits write nothing.

**Rollback recovery.** A rollback to a KV-only broker rotates a grant's
chain in KV only, so after redeploying, storage can hold a refresh
token the upstream has spent. On a rotating provider, when the upstream
answers `400 invalid_grant` to a refresh with a token that came from
storage, the broker reads that grant's per-grant KV key once (never the
legacy key). If the blob decrypts under the grant's original refresh
token and holds a different refresh token, the broker logs
`<displayName> token slot recovered from KV` (no token material, no
error object) and retries once with the KV slot. If the upstream
accepts it, or its access token is still valid, the KV slot is adopted
into storage exactly like any other KV slot. A KV copy whose access
token is still valid is adopted without an upstream call; that trusts
KV exactly as the storage-miss path already does (planting a slot needs
KV write access plus the grant's original refresh token to seal it), so
it adds no new exposure. Otherwise the call fails:
with the original `Refresh failed 400 (invalid_grant)` when KV has no
slot, the read fails, the blob doesn't decrypt or it holds the
rejected token, or with the retry's own error. Nothing is written in
either case. The recovery happens inside the grant's single flight, so
concurrent calls share one KV read and at most two refresh requests,
and there is no further retry. Upstream acceptance, not a timestamp,
decides that KV's chain is newer: a rotating upstream has one live
refresh token per chain. Timeouts, other statuses and codes, static
providers (Gmail) and slots that already came from KV never trigger
it. Recovery can't reach another grant or revive a removed one: it
runs only for a call carrying a live MCP grant, reads only that grant's
key, and can decrypt only a blob sealed under that grant's original
token. Deleting the KV slot by hand only means there is nothing to
recover; it does not stop a storage slot whose chain is still live.
Upstream revocation (disconnecting the app at the upstream, an Optical
offboard) kills every token in the chain, so the KV token is rejected
too. A rollback to a KV-only broker and back is therefore safe for
rotating grants: the new broker mirrors every rotation to KV, which the
old one reads, and recovers whatever the old one rotated on its first
refresh after the redeploy.

Residual risks of recovery:

- **Family-revoking upstream.** If a rotating upstream revoked the
  whole token family when a spent refresh token is presented, the first
  failed refresh after a redeploy would also kill the KV chain and the
  user would have to reconnect. Optical does not do this; Xero's
  behaviour has not been verified. Without recovery the call fails in
  that case too.
- **KV cache right after the redeploy.** A recovery read inside KV's
  cache window after the old broker's last rotation can see an earlier,
  spent token. That call fails; a later call, after the window,
  recovers, because failures are not cached.
- **Repeated rollbacks.** Each redeploy recovers once per grant, on its
  first refresh.
- **KV cache after a failed storage write.** After a storage write
  fails following a rotation, the next call's recovery read can hit a
  stale KV cache (if this location read the key in the last minute or
  so) and see the rejected token. That call fails; a later call heals,
  because failures are not cached. The same holds for an adopted
  legacy slot: if the adoption rotated, the per-grant KV copy was
  written and the storage write failed, the legacy key is kept, so the
  next call can get a cached per-grant miss, fall through to the legacy
  slot's spent token and fail with `invalid_grant` (a legacy-sourced
  slot gets no recovery). That is transient too.
- **Storage and KV both fail.** If the storage write fails after a
  rotation and the KV copy failed as well, the new chain is lost and
  the user must reconnect.
- **Cost on a dead grant.** Once the upstream has revoked a rotating
  grant, every call pays one extra KV read, plus one extra rejected
  refresh request when KV holds a different token. The cost is bounded
  per call and never loops, and the call fails until the user
  reconnects either way. An in-memory memo of failed recoveries was
  considered and rejected: its state is lost on eviction, and it would
  save one request on calls that fail anyway.

Storage is pruned by the broker's Durable Object alarm: a slot not
written for 180 days (the KV TTL) is deleted, in batches of at most 128
keys (the runtime's limit per delete), and the alarm re-arms for the
oldest remaining slot. An active grant is written at least once per
access-token lifetime, so only grants unused for the TTL are removed.

**Refresh deadlines.** A hung token endpoint fails the waiting calls
(`Refresh timed out after 30000 ms`) rather than holding them. On a
static provider (Gmail) the refresh request and its body read are
aborted after 30 s (`REFRESH_TIMEOUT_MS`); sealing and the KV and
storage writes that follow a successful refresh have no deadline of
their own, so a call is bounded by the request, not by 30 s overall. On
a rotating provider (Optical, Xero) each call waits at most 30 s for
the whole flight, but the 30 s is a soft deadline: the caller stops
waiting, but the request and its body read keep running until they
answer or reach a hard cap of 5 minutes (`REFRESH_HARD_CAP_MS`), when
the request is aborted. A refresh token there is single-use, and an
abort that lands after the upstream has committed a rotation would leave
storage and KV both holding the spent token, losing the new one and
forcing a reconnect. Until the request settles it stays the grant's
single flight: a call in that late window joins it (and gets its own
30 s wait) instead of presenting the token the upstream is spending,
which would draw an `invalid_grant` and a needless recovery read, and
the prune alarm leaves its slot. A late success is persisted exactly
like a prompt one (KV copy, then storage) and served to the next call
from storage, with no further request. A late failure, or the cap,
settles the flight with nothing written, and the next call refreshes
again. Rollback recovery runs inside the same flight, and its retry
request gets its own full hard cap: aborting either request can lose a
rotation, and the retry starts only after the first request has settled,
so a flight is bounded at two caps (10 minutes) plus storage and KV
time, while its callers are bounded by their 30 s waits.

Residual risks of the soft deadline:

- **The cap still aborts.** A token endpoint that commits a rotation
  but takes more than 5 minutes to answer loses the chain, as any
  abort did before; the user must reconnect.
- **Object lifetime.** The flight lives in the broker Durable Object's
  memory, and a caller that stopped waiting is no longer an open
  request. Cloudflare documents an outbound `fetch()` as holding off
  an idle object's eviction for up to 15 minutes, which covers the
  refresh request itself (the cap is 5). The broker also passes each
  flight to `ctx.waitUntil`, which covers the KV and storage writes
  after it, but only from compatibility date 2026-10-01 or with the
  `durable_object_io_tasks_prevent_eviction` flag; the apps are on
  2025-03-10, so until that changes the call does nothing, and the
  writes after a late answer rely on the object not being evicted in
  the next few milliseconds. A deploy or runtime restart resets the
  object whatever is pending, dropping the request with it, and no
  code here can prevent that. Whether the chain survives depends on when it happens: before the
  upstream commits, nothing is lost (storage still holds the live
  token); after the KV copy is written but before storage, the next
  call recovers the chain from KV (the KV-first write order exists
  for this); between the upstream committing and the KV copy, the new
  chain exists nowhere and the user must reconnect. A caller's retry
  is an incoming request that joins the flight, which keeps the object
  busy in the common case.
- **A new instance has no flight to join.** After a reset, the next
  call starts a fresh refresh with storage's token, as it would after
  any reset.

`/callback` also writes the KV slot once, at sign-in, with the code
exchange's access token and expiry, sealed and keyed exactly as the
broker would (the key's `<userId>` is the principal the broker is
addressed by), so the grant's first API call needs no refresh. The seed
is skipped when the upstream returned no usable access token or
lifetime, and a failed seed is logged as `<displayName> token slot seed
failed` (no token material) without failing sign-in; either way the
broker falls back to one refresh with the still-unspent refresh token.

A legacy `token-slot:<userId>` slot (the single per-user slot written
before the review) is migrated on first use: the grant whose original
token decrypts it adopts it into storage, copies it to its per-grant KV
key and deletes the legacy key, whether or not the KV copy succeeded. A
failed delete is logged as `<displayName> legacy token slot delete
failed` and not retried. A leftover legacy slot is inert (only its own
grant can decrypt it, and that grant now reads storage) and can be
deleted by hand.

Slots in the broker Durable Object's own storage have no operator purge
path today: there is no `wrangler` command for a Durable Object's
storage, so the only removal is the broker's prune alarm, which deletes a
slot not written for the slot TTL. Offboarding a user does not clear
them; an admin RPC calling `ctx.storage.deleteAll()` on that user's
broker is the eventual fix. They stay sealed under the grant's original
refresh token meanwhile.

### `ratelimit:*` — throttle counters

Fixed-window counters for `/register` and `/token`, keyed by endpoint
and client identity, plus `ratelimit:staging-fail:<client>:<window>`
counters for the staging failure throttle (section 7.6). They expire
with their window. Client identities are the IPv4 address or, for IPv6,
the client's /64 (`ip6:<h0>:<h1>:<h2>:<h3>::/64`).

### Inspecting

Inspect the namespace with the deployment's Cloudflare credentials:

```bash
npx wrangler kv:key list --binding=OAUTH_KV
npx wrangler kv:key get --binding=OAUTH_KV <key>
```

Useful when a sign-in is stuck mid-redirect (look for an unconsumed
`auth-state:` entry to see how far it got) or for post-incident
forensics on what flows were in progress. None of the scaffold keys
holds a usable credential in plaintext.

## 7. OAuth, sandbox and edge controls (2026-10-07 review)

These controls close the findings of a 2026-10-07 defensive security
review.
None needs configuration; the four optional variables in 7.5 and 7.6
only tune defaults. Section 7.8 covers staged transfers v2 (issue #59),
added later, with four more optional variables.

### 7.1 `/authorize` consent page

`GET /authorize` no longer redirects straight to the upstream IdP. It
renders a consent page showing the provider, the MCP client's
registered name, the redirect URI with its host in bold (and a warning
unless it is `https://` to `claude.ai` or `claude.com`, or `http://` or
`https://` to a loopback host; a known host under any other scheme,
such as `evil://claude.ai/cb`, is warned about) and the upstream
scopes, one per line. Nothing goes upstream until
the operator clicks **Approve**, which submits `POST /authorize`, and
nothing is written to KV until the operator approves or denies (only
the spent-token marker is written on **Deny**, which returns
`error=access_denied` to the client).

- **Access gating.** The form posts back to the same path, so the
  Cloudflare Access application on `/authorize` (path-scoped and
  method-agnostic) gates both the `GET` and the `POST`. Nothing new
  sits outside Access.
- **Consent token.** The form carries an HMAC-SHA256 token signed with
  `COOKIE_ENCRYPTION_KEY`, valid for **300 s** and **single-use** (a
  `consent-used:<id>` KV marker, section 6; the consent cookie is also
  cleared once the submission is checked).
- **`__Host-cm-consent-<id>` cookie** (`SameSite=Strict`, 300 s). Its
  value must match a nonce inside the token, so a cross-site
  auto-submitted form, which carries no Strict cookie, is refused.
- **`__Host-cm-auth-<state>` cookie** (`SameSite=Lax`, so it survives
  the top-level redirect back from the IdP). Set on approval; its
  SHA-256 is stored as `bindingHash` in the `auth-state:` envelope, and
  `/callback` refuses, without consuming the state, unless the cookie
  matches. A state string alone, in a different browser, can no longer
  complete the flow.
- The page is sent with `Cache-Control: no-store`,
  `frame-ancestors 'none'` and `X-Frame-Options: DENY` against
  clickjacking. It deliberately sets no CSP `form-action`, because
  Chrome applies it to the redirect to the upstream IdP that follows
  the submission.

**Accepted residual (F-20, double submission).** The consent page runs
no script (its CSP is `default-src 'none'`), so nothing stops a double
click on **Approve**, or a re-submission after Back, from sending the
form token twice. The first submission spends it and redirects to the
IdP; the second gets "Consent expired or invalid". Browsers usually
render the second response, so the operator sees that error and must
restart the connection from the MCP client; the first flow's
`auth-state:` entry is left to expire.

**Accepted residual (F-15).** KV has no compare-and-delete, so the
*same* browser double-submitting `/callback` within KV propagation can
still pass the state check twice. The upstream's authorisation code is
single-use, so the second exchange fails.

**AUTH-VULN-01 (mitigated).** The residual named in
`oauth-client-sweep.ts`, an attacker-registered client capturing the
operator's grant through a consent-less `/authorize`, is mitigated by
the consent page, the MCP-client PKCE requirement (7.2) and the
`/register` redirect-URI rule (7.2). The `/register` rate limit and the
30-day inactive-client sweep remain as accumulation bounds.

### 7.2 MCP client requirements

- **PKCE S256 is required.** `/authorize` refuses a request without
  `code_challenge`, or with `code_challenge_method` other than `S256`
  (the provider runs with `allowPlainPKCE: false`). The MCP
  authorisation specification already requires S256, so conforming
  clients are unaffected.
- **`/register` accepts `http://` redirect URIs only for loopback**
  (`localhost`, `127.0.0.1`, `[::1]`). Every other redirect URI must be
  `https://`. There is no host allowlist, so other legitimate MCP
  clients keep working.

### 7.3 Grant lifetime, `COOKIE_ENCRYPTION_KEY` and MCP scope

- **MCP refresh tokens expire 90 days after authorisation**
  (`refreshTokenTTL`, a module constant in `oauth-provider-options.ts`).
  The library fixes the expiry when the grant is created and refreshes
  do not extend it, so users re-authorise every 90 days. Grants minted
  before this change carry no expiry and do not expire until they are
  re-authorised; to force that, revoke them (or re-authorise each
  client) after deploying.
- **`COOKIE_ENCRYPTION_KEY` now signs consent tokens.** The boot-time
  assertion (32 characters or more) is unchanged. Rotating the key
  voids only consent pages in flight (an open page must be reloaded);
  it does not affect grants, tokens or staged files.
- **MCP `scope` is unenforced by design.** The scope an MCP client
  requests is echoed into its grant but nothing consults it, so the
  consent page does not show it (listing it would suggest a limit that
  does not exist): authority comes from the per-operation surface
  review, which applies identically to every grant.

### 7.4 MCP session binding

Each MCP session Durable Object records the principal it was
initialised for (`audit.principalIdAccessor(props)`, falling back to
`props.userId`). A request routed to that session whose bearer resolves
to a different principal is refused
(`mcp-session-principal-mismatch`, surfaced as a 5xx at the edge), and
the upstream request path re-checks the principal before every call.

### 7.5 Sandbox execution limits

codemode's own 70 s timeout runs inside the sandbox and can be
disabled by the code it limits, so the host now enforces two limits on
every sandbox run:

| Variable | Default | Effect |
|---|---|---|
| `EXECUTE_HOST_TIMEOUT_MS` | `75000` | The host stops waiting for the run after this long and refuses every later upstream call that run makes. |
| `EXECUTE_MAX_UPSTREAM_CALLS` | `1000` | Upstream requests one run may make (`codemode.request` plus `__stagingHost.stageFromUpstreamJson` / `stageFromAttachment`). Sized below Cloudflare's paid-plan limit of 10,000 subrequests per invocation (each budgeted call costs at most about four), so a large run fails with the budget's clear error rather than the platform's. If you raise it, keep it under a quarter of the Worker's `limits.subrequests`. |

Both are optional Wrangler vars; a value that is not a positive integer
is a configuration error. The `search` tool's sandbox no longer
receives `__stagingHost` (it has no upstream channel at all) and the
tool is annotated `readOnlyHint: true`.

### 7.6 Staging failure throttle

`/staging/upload` and `/staging/fetch/*` sit behind a per-client
failure budget. Each request first reads the client's failure counter
(`ratelimit:staging-fail:*`, section 6) and, once the recorded failures
reach the budget, is answered 429 with `Retry-After` before the handler
(and so before any D1 read) runs. Only 403 outcomes (missing bearer,
unknown token, wrong handle) count, so legitimate traffic costs no KV
write. A KV read error fails open, because the 256-bit staging bearer
remains the access control.

**The throttle is best-effort.** The counter is a KV read followed by a
separate read-increment-write after the response, so concurrent
failures read the same count and lose increments, and KV's eventual
consistency and edge caching widen that. A burst of parallel guesses
can therefore pass well beyond the budget before it bites; it bounds
sustained, sequential guessing, not a burst. The same holds for the
`/register` and `/token` rate limits. A guaranteed bound would need
atomic counting (a Durable Object or the Workers Rate Limiting
binding). Nothing depends on the throttle for access: staging tokens
are 256-bit.

| Variable | Default | Effect |
|---|---|---|
| `STAGING_FAILURE_RATE_LIMIT` | `30` | Failed staging requests allowed per client per window. |
| `STAGING_FAILURE_RATE_LIMIT_WINDOW_SECONDS` | `300` | Window length in seconds. |

Uploads are also streamed with a byte counter and aborted at the size
cap, whether or not the client sent `Content-Length`.

### 7.7 Error text, logging and outbound redirects

- **Refresh failures** reach the sandbox (and the model) as
  `Refresh failed <status> (<error>)`, where `<error>` is the OAuth
  `error` code when it is token-shaped and is otherwise omitted. The
  token endpoint's response body is neither propagated nor logged.
- **`/callback` token-exchange failures** are logged with the status
  and the OAuth `error` code. Up to 500 characters of the upstream body
  are added only when `ALLOW_PII_IN_LOGS` is `"true"` (section 3).
- **Upstream redirects are not followed.** Outbound requests use
  `redirect: "manual"`; any 3xx response other than 304 becomes an
  `upstream_redirect` error envelope (the `Location` is not echoed) and
  is never staged.
- **Rate-limit identity.** `/register`, `/token` and the staging
  throttle bucket IPv6 clients by /64. A request without
  `CF-Connecting-IP` falls back to one shared `unknown` bucket; on
  Cloudflare the edge always sets the header, so this only affects
  local `wrangler dev` (accepted residual).

### 7.8 Staged transfers v2

Added after the review (issue #59). Staged files up to
`STAGING_MAX_BYTES` (50 MiB) now move between the encrypted staging
store and upstream APIs without crossing the host↔sandbox RPC, and no
host code path holds more than a few MiB of file-derived memory at
once. Sandbox code passes `{ file_handle, token }` references; the host
assembles the outbound body.

**At-rest format (v2).** New writes are split into 1 MiB blocks, each
sealed independently with AES-256-GCM under a key derived with HKDF
info `codemode/staging/v2`. The nonce is 8 random bytes (stored in the
row's `iv`) followed by the big-endian block index; the AAD binds the
file handle, the format version, the block index, the block count and
the total length. The R2 object is the concatenation of every
`ciphertext ‖ tag`, so a reordered, truncated, extended, duplicated or
cross-file-spliced object fails authentication at the first block out
of place. No block is emitted unless it authenticated, any failure
aborts the output (a reader sees an error, never a clean end of file),
and a row that fails once is marked `corrupt` and never read again.
Migration `0002_enc_version.sql` adds the `enc_version` column
(default 1, so rows written before it report 1). Every writer sets
`enc_version = 2`. Only v2 rows are readable: a row with `enc_version`
1 (the retired one-shot format) is refused by every reader (`getFile`,
`/staging/fetch`, `composed` and `multipart[].staged` sends) with 410,
before any R2 read and without being marked corrupt. `getFile` and
staged sends carry "stored in a legacy format; re-stage the file";
`/staging/fetch` answers a bare `gone`. An unknown version is refused
with 500.

Every write and read (`/staging/upload`, `/staging/fetch`, `putFile`,
`getFile`, `returnAs: "stage"`, `stageFromUpstreamJson`) runs block by
block into a fixed-length sink (`FixedLengthStream` in workerd) whose
wrapper counts the bytes itself: it closes only when exactly the
declared length was written and aborts otherwise. An upstream download
that ends short of, or runs past, its declared `Content-Length` is a
502 with no R2 object and no claimed row. `/staging/upload` encrypts as
the body arrives; an upload without `Content-Length` is buffered as
plaintext blocks up to the size cap. Uploads without `Content-Length`
and `returnAs: "stage"` downloads whose length is unknown (a compressed
or chunked upstream body) share one slot per isolate: a second gets 503
(`Retry-After: 1` on uploads). An upload without `Content-Length` that
is still arriving after `STAGING_TRANSFER_TIMEOUT_MS` is cut off with
408, so a stalled client holds the slot for at most that long.
Known-length uploads are unaffected.

**Composed channel.** `codemode.request` accepts
`composed: { segments: [...] }`, where each segment is either `{ text }`
or `{ staged: { file_handle, token }, encoding }` with encoding
`base64-lines` (76-character lines, CRLF after each), `base64` or
`identity`, and `multipart[i].staged` for a staged multipart part.
Shape is validated before any storage access: 1 to 32 segments, at most
4 MiB of text in total, every text well-formed UTF-16 and free of
U+FFFC, `identity` only as the sole segment, and `composed` exclusive
with `body`, `bodyBase64`, `rawBody` and `multipart` on every operation
(`multiple-body-channels`). Base64 output cannot carry CR, LF, `:` or
`--`, so staged bytes can never form a header, a blank line or a MIME
boundary. Staged multipart parts default their `filename` and
`contentType` from the row, and those defaults pass the same checks and
header sanitiser as sandbox-supplied values.

**Inspection view.** Inspectors and the approval dialog see the text
segments concatenated verbatim with each staged slot replaced by U+FFFC,
plus per-file metadata (byte length, content type, sanitised filename,
encoding) and the exact assembled length. The view is byte-for-byte the
wire body with the slots filled (a leading BOM is preserved, not
stripped). An inspected or `elicit` operation must opt in with
`acceptsStaged: true` on its surface-review entry; without it, any
staged reference is denied `staged-not-supported` before the inspector
runs. Gmail's three media operations opt in; the JSON `messages.send`
does not. Bare-allow operations (Xero attachments) need nothing.

**Sandbox ctx whitelist.** The `request` closure handed to the sandbox
forwards only `method`, `path`, `query`, `body`, `headers`,
`contentType`, `rawBody`, `bodyBase64`, `multipart`, `returnAs` and
`composed`; anything else, notably the internal `bypassTruncate`, is
dropped before the handler sees it.

**Gmail media path.** `gmail.users.messages.send.media`,
`gmail.users.drafts.create.media` and `gmail.users.drafts.update.media`
take a host-assembled `message/rfc822` body on `/upload/gmail/v1/…` with
`uploadType=media`. Send is inspected (upload type, query keys, content
type, a 35 MiB cap, no staged slot before the header block ends, then
the existing recipient rules) and its approval summary lists attachment
names with format characters stripped. Draft media operations are
plain allow with the subject normaliser, as the JSON draft operations
are.

**Order and caps.** Shape validation, operation match and surface
review, then staged-reference resolution (D1 only), then the exact
length check, then inspection, normalisation and approval, then the
OAuth token, then the transfer gate, and only then is any R2 object
opened. A denied or oversize request costs a few D1 reads.

| Variable | Default | Effect |
|---|---|---|
| `STAGING_COMPOSE_MAX_BYTES` | `75497472` (72 MiB) | Exact assembled length cap for a `composed` or staged-multipart body; over it, `composed-too-large` stating the limit and the computed size. Sized for a 50 MiB file as base64-lines plus headers. |
| `STAGING_GETFILE_MAX_BYTES` | `8388608` (8 MiB) | `getFile` refuses larger files with 413 (checked from the row before any R2 read; the message points at `composed`). |
| `STAGING_MAX_CONCURRENT_TRANSFERS` | `2` | Staged transfers running at once per isolate. |
| `STAGING_TRANSFER_TIMEOUT_MS` | `60000` | Absolute timeout for one staged transfer. |

All four are optional Wrangler vars; a value that is not a positive
integer is a configuration error.

**Transfer gate.** Every file-sized capability (composed and
staged-multipart sends, `returnAs: "stage"`, `stageFromUpstreamJson`,
`getFile`, `putFile`) takes a two-level gate. Per execution, one
transfer runs and one waits; a third concurrent one fails with "one
staged transfer at a time per execution; await each before starting the
next". Per isolate, `STAGING_MAX_CONCURRENT_TRANSFERS` run with a FIFO
queue of at most four waiters; beyond that the call fails with "too many
staged transfers are in progress on this server; retry shortly". The
isolate's 128 MB is shared with every other session Durable Object of
the deployment, so the per-execution cap stops one run filling the
queue. The gate is released in `finally`.

**Timeouts and deadline coupling.** Each send has one abort controller,
fired by the run's host deadline (`EXECUTE_HOST_TIMEOUT_MS`, 7.5), by
`STAGING_TRANSFER_TIMEOUT_MS`, or by either side failing. If the
upstream answers early (say a 413 after 4 KB) the writer is aborted; if
the writer fails (R2 read, corrupt block) the request is aborted. If
the upstream closes the connection mid-body, fetch gets up to 5 s
(`UPSTREAM_CLOSE_GRACE_MS`, still bounded by the deadline and timeout)
to deliver the upstream's answer (say Xero's 413), which is returned;
otherwise the error says the upstream closed the connection after N of
M bytes, not that a staged file could not be read. An
aborted transfer leaves the upstream with a body shorter than its
`Content-Length`, so no send completes after the run was told it
failed. `stageFromUpstreamJson`'s upstream request is a gated
transfer too: it takes its gate lease only after approval and the token
mint, so an open approval prompt never holds a slot, and it runs under
the same deadline and timeout. A download stopped by either reports the
timeout or deadline, not a storage error.

**What the logs show.** The `AUDIT` line for a host-assembled send adds
`stagedCount` (staged files attached; the same file twice counts
twice), `stagedBytes` (their plaintext bytes) and `assembledBytes` (the
exact outbound length), plus `bodyBytesSent` and `bodyComplete` (how
much of that body the upstream connection accepted before it answered),
so a truncated send the upstream still answered 2xx shows up as
`bodyComplete: false`. The approval dialog adds an `Attachments:` line
of sanitised names and sizes. A staged reference that fails to resolve
is reported by segment or part index and a status word (`not found`,
`upload incomplete`, `expired`, `corrupt`, `legacy format`). Staging
tokens, file handles and file bytes never appear in audit lines, error
messages, elicitation payloads or debug logs.

**Proof-of-concept tests.** The D-series asserts each of these controls
with the original attack payloads as regression inputs:
`packages/scaffold/src/__tests__/security-poc/D1`–`D6` and `D8`–`D10`
(compose and memory caps, upload length attacks, the transfer gate and
coupling, block-format tamper, staged-reference isolation, the
composed-body differential, token leakage, the sandbox ctx whitelist,
download length attacks) and
`packages/providers/gmail/src/__tests__/security-poc/D7` (RFC 822
smuggling through the composed channel). Run them with
`npx vitest run --config vitest.poc.config.ts` in each package.

**Rollout.** Apply migration 0002 to each deployment's remote
`STAGING_D1` before deploying the new code, with
`scripts/upgrade/2026-10-15-staging-v2.sh` (see `infra/README.md`).
