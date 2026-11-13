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

Sandbox (LLM) code does not write to this stream. The sandbox runs in
its own Worker Loader isolate, whose console output and uncaught errors
reach neither the parent Worker's `wrangler tail` nor its Workers Logs
(verified live on gmail-dev, 2026-11-12; §7.12), so a sandbox cannot
print a line that looks like an `AUDIT` line (C-2). As defence in
depth, codemode captures `console.log`, `warn` and `error` into the
run's `logs` and the scaffold's prelude routes every other `console`
method (`info`, `debug`, `table`, `trace`, ...) into the same capture.

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
- `queryKeys` — the sorted names of the request's query parameters
  (never their values), on every line emitted once the operation is
  matched. Bounded because the names are caller-chosen: at most the
  first 32 names, each cut to 64 code points with a trailing `…`
- `queryKeyCount` — the true number of query names, alongside
  `queryKeys` (so a capped list is visible as such)
- `pathLength` — the true length of `path` in code points, present only
  when the sink cut it
- `phase` — `"dispatch"` on the extra line written before a
  host-assembled body goes out (§7.12)
- `outcome` — `"failed"` on the line of an allowed request whose send or
  response handling failed; `reason` says how (§7.12)
- `staging` — `{ event, fileRef?, byteLength?, status }` on staging
  lines (§7.12); `fileRef` is a 12-hex digest of the file handle
- `stagedRefs` — the `fileRef`s of the files a host-assembled send
  attached

**Caps.** The sink caps the fields a caller can influence, in code
points: `method` 32, `path` 1024, `reason` 128, `category` 64,
`operationId` 256. A cut value is the first `max − 1` code points
followed by `…`, and a cut `path` adds `pathLength`. The caps bound each
field, not the line's byte size: JSON escaping can make a field up to
about six times its cap in bytes (a control character serialises as
`\uXXXX`).

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
own or is rewritten in normal use; the library's `client:<id>` records
carry a TTL the scaffold sets (below). No scheduled job reads this
namespace.

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

### `client:<id>` — library client records (30-day TTL on registration, 120 days after each successful `/token`)

The OAuth library's own record of a dynamically registered MCP client
(name, redirect URIs, auth method; a confidential client's secret is
stored hashed). The library writes it with no expiry; the hardening
wrapper (`enforceOAuthHardening`, A-5 of the 2026-11 review, section
7.13) re-puts it verbatim with a TTL: `OAUTH_CLIENT_TTL_SECONDS` (30
days) after a successful `POST /register`, and the grant lifetime (90
days) plus `OAUTH_CLIENT_TTL_SECONDS` (120 days in all) after every 200
from `POST /token` whose `grant_type` is `authorization_code` or
`refresh_token`, sent as an `application/x-www-form-urlencoded` body
(Content-Type essence exact). A revocation 200, a failed exchange and
`GET /authorize` do not renew it. An expired record makes the library
answer `invalid_client` / "Invalid client", and the MCP client must
register again (remove and re-add the connector). Records written
before wave 5 have no TTL until
`scripts/upgrade/2026-11-11-oauth-client-ttl.sh` gives them one; the
same script deletes the orphaned `clientreg:<id>` stamps of the removed
sweep.

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

Fixed-window counters for `/register`, `/token`, `/authorize` and
`/callback` (`ratelimit:<endpoint>:<client>:<window>`, section 7.13),
keyed by endpoint and client identity, plus `ratelimit:staging-fail:<client>:<window>`
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
renders a consent page showing the provider, a warning box, the MCP
client's self-declared name, the redirect URI with its host in bold
and the upstream scopes, one per line. Since wave 5 of the 2026-11
review (section 7.13) the box is on every page: it tells the user to
approve only a connection they started themselves, from their MCP
client, just now, and to choose **Deny** otherwise. When the redirect
URI is not a known MCP client the box adds a `Warning:` naming where
access will go. Known means exactly
`https://claude.ai/api/mcp/auth_callback` or
`https://claude.com/api/mcp/auth_callback` (`KNOWN_REDIRECT_URIS` in
`oauth-consent.ts`; no port, query, fragment or userinfo), or
`http(s)://` to `localhost`, `127.0.0.1` or `[::1]` on any port with
the path exactly `/callback` (Claude Code) or `/oauth/callback` (MCP
Inspector). Any other claude.ai path or port, any other loopback path
and a known host under another scheme (`evil://claude.ai/cb`) warn;
nothing is refused for it (the library already refuses a redirect the
client did not register). The client name is shown after the box as a
quoted claim ("An application calling itself “…”"), cut to 64
characters with control, zero-width and bidi characters removed and
quote characters mapped to `'`, so a 4 KB "security notice" registered
as a name cannot talk the user past the box. Nothing goes upstream until
the operator clicks **Approve**, which submits `POST /authorize`, and
nothing is written to KV until the operator approves or denies (only
the spent-token marker is written on **Deny**, which returns
`error=access_denied` to the client).

- **Cloudflare Access is defence in depth only.** The 2026-11 review
  assumes no Access anywhere: the Worker must not need it. Where an
  operator still runs an Access application on `/authorize`
  (path-scoped and method-agnostic, so it covers the `GET` and the
  `POST`; `infra/modules/worker`), it adds a layer in front of the
  page and nothing more. It never covered `/callback`, `/token`,
  `/register`, `/mcp` or `/staging/*`, and since wave 5 (section 7.13)
  the consent page stands alone: the warning box is always on, and a
  `/callback` from the wrong browser cancels the flow.
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
  `/callback` refuses unless the cookie matches. Since wave 5 (section
  7.13) the refusal also deletes the stash and answers "This sign-in
  could not be completed in this browser and has been cancelled. Do
  not share this page's address with anyone. …", so the refused
  address is not a credential the matching browser can redeem later;
  the upstream code is not spent. A state string alone, in a different
  browser, can neither complete the flow nor keep it alive for whoever
  holds the cookie.
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

**AUTH-VULN-01 (mitigated).** The residual once named in the (since
removed) `oauth-client-sweep.ts`, an attacker-registered client
capturing the operator's grant through a consent-less `/authorize`, is
mitigated by the consent page, the MCP-client PKCE requirement (7.2)
and the `/register` redirect-URI rule (7.2). The `/register` rate limit
and the 30-day TTL on unused client records (section 7.13; the sweep
is gone) remain as accumulation bounds.

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
- **The consent page's "known MCP client" list (7.1) is not an
  allowlist.** A client whose redirect URI is not pinned still works;
  its users see the `Warning:` sentence on the page.
- **Request bodies are capped** (section 7.13): `POST /register` at
  1 MiB, `POST /authorize` and `POST /token` at 16 KiB, answered 413
  (`invalid_request`, "Request body too large") before the library
  reads them. Every legitimate registration and token form is far
  under both.

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
to a different principal is refused (`mcp-session-principal-mismatch`),
and the upstream request path re-checks the principal before every call.
The refusal is answered with the MCP "Session not found" 404 (JSON-RPC
error -32001, the agents SDK's own answer for an unknown session) and an
`AUDIT` deny line with reason `session-principal-mismatch`, the caller's
principal and no session id. It used to surface as a 5xx at the edge,
which left clients retrying the refused session id indefinitely: seen on
optical-dev (2026-11-13) after a re-sign-in returned a different `sub`,
where Claude.ai and Claude Code stayed on 502 until reconnected by hand.
On the 404 a client re-initialises with a fresh session bound to its own
principal; the refused session and its data are untouched.

### 7.5 Sandbox execution limits

codemode's own 70 s timeout runs inside the sandbox and can be
disabled by the code it limits, so the host now enforces these limits on
every sandbox run:

| Variable | Default | Effect |
|---|---|---|
| `EXECUTE_HOST_TIMEOUT_MS` | `75000` | The host stops waiting for the run after this long and refuses every later upstream call that run makes. |
| `EXECUTE_MAX_UPSTREAM_CALLS` | `1000` | Upstream requests one run may make (`codemode.request` plus the four budgeted staging fns `__stagingHost.getFile` / `putFile` / `stageFromUpstreamJson` / `stageFromAttachment`; `getFile` and `putFile` joined in wave 4). Sized below Cloudflare's paid-plan limit of 10,000 subrequests per invocation (each budgeted call costs at most about four), so a large run fails with the budget's clear error rather than the platform's. If you raise it, keep it under a quarter of the Worker's `limits.subrequests`. |
| `EXECUTE_MAX_DENIED_CALLS` | `32` | Refused calls one run may make (wave 4, §7.12): a `codemode.request` or budgeted staging call that rejects, or a staging call answering `ok: false`. Past it every further call from the run is refused before it reaches the handler ("too many refused requests in this execution"), with one `denial-budget-exceeded` audit line, so a run cannot flood the log with capped deny lines. |

All three are optional Wrangler vars; a value that is not a positive integer
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
`/register`, `/token`, `/authorize` and `/callback` rate limits
(section 7.13). A guaranteed bound would need
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
- **Rate-limit identity.** `/register`, `/token`, `/authorize`,
  `/callback` and the staging throttle bucket IPv6 clients by /64. A request without
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
`upload incomplete`, `expired`, `corrupt`, `legacy format`). Since wave 4
(§7.12) the same line also carries `stagedRefs` (each attached file's
`fileRef`), staging itself writes `staging.*` lines, and a file is
followed across them by its `fileRef`: the first 12 hex characters of
SHA-256 of the file handle, which cannot be turned back into the handle
or used to open the file. Staging tokens, file handles and file bytes
still never appear in audit lines, error messages, elicitation payloads
or debug logs.

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

### 7.9 Approval dialogs and request policy (2026-11 wave 1)

**Approval dialogs.** The scaffold, not the provider, composes every
approval message: a headline, `Request: <METHOD> <path>`, a `Query:`
line with every defined pair, up to eight facts the provider's renderer
resolved from the request (targets come from the path, never from a
body field the caller could relabel), the `Attachments:` line for staged files,
and a fixed trailer. All of it is sanitised (control, separator and
bidi characters become spaces) and length-bounded. The requested schema
is always the single boolean `confirm`; only an answer whose sole key is
`confirm` with the value `true` approves, anything else is `declined`.
Facts are shown, never asked for. A raw or inline-multipart body on an
approval-only operation is denied before any dialog (it cannot be
shown), as is a query with more than 16 pairs. A client that does not
advertise elicitation, or exposes no capabilities accessor, is denied
with outcome `unsupported` (fail-closed); Claude.ai therefore denies
every `elicit` operation.

**Query parameter names (D-2).** After the operation is matched, and
before the URL is built (so before inspection, approval and token
mint), every query name must be declared by that operation's own
`parameters` (`in: "query"`, inline or through
`#/components/parameters/*`) or be in the provider's
`standardQueryParams` (Gmail: `fields`, `prettyPrint`, `quotaUser`,
`upload_protocol`; Xero and Optical: none). Names starting with `$`,
credential names (`access_token`, `oauth_token`, `key`, `api_key`,
`apikey`, `token`, `bearer`, `authorization`) and method-override names
(`_method`, `method`, `httpmethod`, `x-http-method-override`) are
refused case-insensitively even when declared. Values must be a string,
number or boolean. The one exception is a parameter the operation
declares as a comma-separated list (`schema.type: "array"` with
`explode: false`, style `form` or unset, such as Xero's `IDs`,
`InvoiceNumbers`, `ContactIDs`, `Statuses` and `References`): it takes
an array of strings, numbers or booleans and goes out comma-joined,
byte-for-byte as before. Any other array, and any nested array or object
element, is refused; a repeated parameter (for example Gmail's
`metadataHeaders`) carries one value per request.
Parameters declared at path-item level are not read (refused,
fail-closed). Denials are audited as `forbidden-query-param`,
`undeclared-query-param` (category `url_safety`) or
`query-value-not-primitive` (category `malformed`).

**Content type (D-3, C-4).** `contentType`, when given, must parse as a
media type (`type/subtype` plus parameters) of at most 100 characters
on every operation, else `invalid-content-type`. On an inspected or
approval operation a JSON payload (an object `body`, or raw bytes
labelled JSON) must carry a JSON label with no parameter other than
`charset=utf-8`; it is then sent, and shown to the inspector, as exactly
`application/json`. Any other label is denied before inspection as
`json-body-non-json-content-type`. Raw JSON-labelled bytes on those
operations are decoded as strict UTF-8 (a byte-order mark or an invalid
sequence is `unparseable-json-body`) and sent re-serialised. Plain
`allow` operations keep the caller's label.

**Untrusted response fields (F2-8).** A provider may name a spec
extension (`untrustedFieldExtension`; Optical: `x-optical-untrusted`)
that flags response fields holding third-party text. Every string such
a field reaches is returned as `⟦untrusted⟧…⟦/untrusted⟧`, with any
fence bracket inside the text replaced by U+FFFD, for the response's
status (its `NXX` range, or its `default` response), in the result
and in the error message of a non-2xx response. A status the operation
does not declare at all fails closed: the flags of every declared
status apply. The `docs` envelope section tells the model what the
markers mean and to strip them before reusing a value. Fencing runs
before the 64 KiB result truncation, so a flagged string cut by
truncation keeps its opening marker but loses its closing one. Staged
bodies are not fenced: `returnAs: "stage"` and the internal path that
plucks a JSON field to store it keep the upstream bytes unchanged, and
sandbox code can read them back through `__stagingHost.getFile`. A
provider that enabled both staging and an untrusted-field extension
would need fencing there; none does today (Optical has no staging
bindings).

### 7.10 Gmail sends and Calendar writes (2026-11 wave 2)

**Send paths judge `raw` and nothing else.** The recipients a send is
judged on are read from the base64url RFC 822 message in `raw`, the
same bytes Gmail delivers. Each send path has a closed key allow-list,
and any other key is denied before the recipient check
(`send-unexpected-key`), so a decoy `payload` or wrapper is refused
rather than left for Gmail to ignore:

- `messages.send`: a JSON object with top-level `raw`, `threadId`,
  `labelIds` only. A missing or empty `raw`, or a non-JSON body, is
  denied (`send-no-raw`; bytes go through `messages.send.media`).
- `drafts.send`: a JSON object `{ id, message }`, with `message`
  holding only `raw`, `threadId`, `labelIds` and `id`
  (`draft-send-body-not-object`, `draft-send-no-id` otherwise). Keys
  inside `message` are checked before `raw`, so a `payload` decoy is
  named whatever `raw` holds. `message.raw` is required and is the only
  part judged; sending a stored draft by `id` alone, or with an empty
  `raw`, stays denied (`draft-send-unvetted-recipients`), because drafts
  are written without recipient checks.
- `messages.import`: the same `raw`-only rule, applied before approval
  is sought (`import-body-not-object`, `import-no-raw`). A repeated
  `From`, `To`, `Subject` or `Date` header is denied
  (`duplicate-summary-header`): mail readers disagree on which one they
  show. The dialog's `From`, `To`, `Subject` and `Date` (first
  occurrence, RFC 2047 encoded words decoded, absent headers left out)
  come from the same parse that judges the message.

**Residual (F1-1, upstream-dependent).** `drafts.send` judges
`message.raw` and relies on two Gmail behaviours this project has not
checked live: that Gmail replaces the stored draft's content with
`message.raw` before sending, and that a concurrent `drafts.update` of
the same draft (uninspected by design) cannot slip its content in
between that replacement and the send. Gmail has no draft version or
etag to pin either. The operator should run one live check in the dev
deployment with two of their own addresses: store a draft to A, send
it with `{ id, message: { raw: <To: B> } }`, and confirm that B and
only B receives it. If the check fails, the fallback is a static deny
of `drafts.send` (sandbox code then uses `drafts.get?format=raw`,
`messages.send` and `drafts.delete`).

One RFC 822 header parser serves all three, so header-block rules
(duplicate recipient headers, ambiguous line endings, malformed header
names; §7.9 and the 2026-10 changes) apply equally.

**Calendar write allow-list (`CALENDAR_WRITE_ALLOWLIST`).** A Gmail
wrangler var: comma-separated calendar ids the agent may write events
to (`events.insert`, `update`, `patch`, `import`, `move`). Entries are
trimmed, must be printable ASCII, and are lower-cased; each must be the
literal `primary` or a plain `addr@host`-shaped id (the operator may list
the user's own address as well as `primary`, and secondary calendars as
`c_…@group.calendar.google.com`). `*@domain`, non-ASCII text and any
other shape make the parse throw, so every event
write is denied until the entry is fixed. Any throw from a sync
`inspect` (this one, or a malformed `OUTBOUND_RECIPIENT_ALLOWLIST`) is
denied by the handler as `inspector-threw` (category `malformed`, with
an audit line; a sync `inspect` that returns something other than an
inspect result, such as `{}` or a Promise, is denied the same way as
`inspector-invalid-result`); the caller gets fixed text, never the exception's
message, which quotes the offending config entry. Unset or blank means an empty
list: every Calendar event write is denied (`calendar-not-allowlisted`,
category `external_data_flow`), the same fail-closed rule as
`OUTBOUND_RECIPIENT_ALLOWLIST`. `primary` is never implied; list it. The
calendar id is taken from the matched path parameters, never from the
body, and is never trimmed: an id with edge whitespace or any character
outside printable ASCII is denied before it is lower-cased (so, for
example, a Kelvin sign cannot fold onto `k`). Reads are unaffected. The var lives in `apps/gmail/wrangler.jsonc`
(prod, `env.dev`, `env.tester`), so changing it is a redeploy;
`scripts/upgrade/2026-11-10-calendar-write-allowlist.sh` refuses to run
unless all three blocks declare it uncommented with a non-blank value.

Per write:

- `events.update` / `events.patch` read the stored event first (below),
  after the synchronous checks (calendar, `declineMessage`, request
  attendees) have passed. The read is `calendar.events.get` on the same
  `calendarId` and `eventId` as the write (re-encoded from the decoded
  path parameters, so it targets exactly the written event), with none
  of the sandbox's query. Missing path parameters deny
  (`event-path-params-missing`). An event whose `organizer.self` is not
  the boolean `true` (or a stored body that is not an object) is denied
  (`event-not-organised-by-user`): a guest's edit propagates to the
  organiser's copy whatever `sendUpdates` says. A 404 is
  `event-not-found`, any other non-2xx is `event-read-failed` (status
  only, no body), and on the user's own event a truncated guest list
  (`attendeesOmitted`) is denied (`event-attendees-omitted`).
- The one exception on a foreign event is an RSVP: `events.patch`
  whose body has exactly one key, `attendees`, equal to the stored list
  (same length, same order, every other entry structurally identical)
  except that the user's own entry may differ in `responseStatus`,
  whose value must be `accepted`, `declined`, `tentative` or
  `needsAction`. The user's own entry is the single stored entry with
  `self: true` or with the address of a `creator` marked `self: true`;
  zero or several matches deny. That entry may not carry `comment` or
  `additionalGuests` at all (even unchanged), and a truncated stored
  list denies. Such a patch is allowed without a dialog, `sendUpdates`
  included; anything else is `event-not-organised-by-user`.
  `events.update` on a foreign event stays denied. Because the
  synchronous inspector defers the attendee check of an attendees-only
  `events.patch` body to this hook, the hook applies it on the user's
  own event (`external-attendee`, `mass-invite`).
- **Residual (accepted).** The RSVP exception is a covert channel to the
  organiser of a foreign event: each patch picks one of four statuses
  (about 2 bits), and Calendar notifies the organiser of the change.
  Repeated patches can carry more. Accepted to keep RSVPs working (the
  values are a closed enum, no free text).
- On the user's own event, stored guests off the outbound allowlist
  raise an approval (`event-has-external-guests`). Stored-guest reading
  is strict: the user's own entry and Google rooms are skipped, and an
  entry without a readable address counts as off the allowlist. The
  dialog facts are `guests` (first three, `+N`) plus the facts below.
- On every non-deny, the hook returns the dialog facts for the write,
  every key set so they override whatever the sync inspector put there:
  who is affected from the STORED event (`organizer`; `guests` when it
  asks), what the event will say from the BODY (`summary`, `start`,
  `end` when the body sets them, else the stored ones; a non-string
  value shown as JSON), and `changes`, the body's top-level keys sorted
  (e.g. `description, summary`). A body `organizer` is never shown. So a
  patch that retitles an event or fills its description is approved
  under the new title, with `description` named in `changes`.
- An `outOfOfficeProperties` or `focusTimeProperties` `declineMessage`
  (either spelling, any non-empty value) is denied
  (`event-decline-message`): Calendar emails it to the organiser of
  every conflicting invitation.
- `events.move` takes no body and needs `destination`; both the source
  calendar and `destination` must be on the allow-list.
- `events.quickAdd` is denied statically: its free text is parsed by an
  undocumented grammar that turns addresses into guests.

**Host-side upstream reads (`inspectUpstream`).** A surface-review
entry may pair its synchronous `inspect` with an async `inspectUpstream`
that receives a lookup able to `GET` other paths of the same provider
with the caller's credentials. Gmail's `events.update` and
`events.patch` use it, and (since wave 3, §7.11) the Xero contact,
invoice, credit-note and repeating-invoice writes. Limits:

- It must be paired with `inspect`: the provider battery checks this,
  and at request time an unpaired hook denies
  (`upstream-inspector-without-inspect`) rather than being skipped.
- It runs only after `inspect` did not deny, and only on a JSON body or
  no body; a raw, multipart or host-assembled body is denied
  (`opaque-body-on-upstream-inspected-op`). Its decision merges with
  the most restrictive rule; its category, reason and message apply
  only when its decision is the one that stands (a hook `allow` never
  relabels a sync `elicit`). Its summary facts merge over the sync ones.
- A lookup may only read a path whose matched GET operation is a plain
  `allow` with no `inspect` and no `inspectUpstream`. Anything else (a
  gated, denied or unmatched path) throws before any fetch. The path is
  passed encoded (`encodeLookupPath` builds it from the decoded
  `pathParams`), and the hook never forwards the sandbox's query.
- At most four lookups per request; the fifth throws. Lookups are
  refused once the hook has settled, and the handler waits for any
  lookup the hook started without awaiting.
- Fail closed: if any lookup threw (refused, failed in transport, or
  aborted by the run's deadline), even one the hook caught, or the hook
  itself threw or returned something that is not an inspect result, the
  write is denied with `upstream-inspect-failed`. The caller's error
  names only the lookup's own fixed refusal text, never a path, query
  or upstream content. A non-2xx answer is not a failure: the hook gets
  the status and decides.
- The read goes through the same request handler as any call: origin
  and path guards, query policy, no redirects, the run's deadline. It
  does not count against `EXECUTE_MAX_UPSTREAM_CALLS`, and its body is
  never shown to the model (it is neither fenced nor truncated).
- It writes its own `allow` audit line (operation `calendar.events.get`,
  with `upstreamStatus`) before the write's decision line, so an
  `update`/`patch` that reads the stored event produces two audit lines
  (three when it raises an approval: the read, the elicitation outcome,
  then the write). No new audit field marks the read as a lookup.
- On those two operations the upstream token is minted for the read,
  before the write's allow/elicit/deny decision. The token stays on the
  host either way.

**Claude.ai.** Claude.ai does not support elicitation, so every
`elicit` outcome above is a deny there (`unsupported`). That covers
`event-has-external-guests`, more than 25 recipients or attendees, and
every `messages.import` and `events.import`. To let the agent edit an own event with outside
guests from Claude.ai, add those guests to
`OUTBOUND_RECIPIENT_ALLOWLIST`; there is no per-request override.

**Dialog text.** Inspectors no longer cut subjects and event titles at
200 characters; the scaffold's length bound applies, and it marks the
cut with `…`. String fact values are shown as quoted JSON strings, so a
value cannot pose as a further fact line. The Gmail renderer's
`external_data_flow` facts are the path parameters (`calendarId`,
`eventId`; `userId` dropped) followed by these summary keys in order,
within the eight-fact cap: `recipients`, `from`, `to`, `subject`,
`date`, `count`, `attendees`, `guests`, `organizer`, `changes`,
`summary`, `start`, `end`, `attachments`. Who is affected and what the
write changes come before the descriptive facts, so the cap drops only
a descriptive one. Message imports show From/To/Subject/Date; event
imports show the body's organiser, title, start and end;
`events.insert` shows no organiser; update/patch show the stored
organiser and guests, the title and times the write sets (else the
stored ones) and `changes` (see above).

### 7.11 Xero contacts, posted documents, repeating invoices and attachments (2026-11 wave 3)

All rules below are in the Xero app's surface review
(`packages/providers/xero/src/surface-review.ts`) and its inspectors
(`packages/providers/xero/src/inspectors/`). No var, secret or migration
is involved: the change lands on the next ordinary redeploy of the Xero
app. Every gated key is read case-insensitively, as Xero reads it, and a
key spelt two ways (or with a non-ASCII lookalike) is denied.

**Contacts (`createContacts` PUT, `updateOrCreateContacts` POST).**

- A create (an item with neither `ContactID` nor `ContactNumber`) is
  allowed with any fields, bank details included: a new contact has no
  money attached, and every path that pays or bills it is gated
  elsewhere. A bulk of creates is allowed too.
- An item carrying `ContactID` or `ContactNumber` is an edit. An edit
  carrying `BankAccountDetails`, `BatchPayments`, `EmailAddress`,
  `ContactStatus`, `TaxNumber` or `ContactPersons` (a second
  invoice-delivery address), or one that changes `Name` or
  `XeroNetworkKey` from the stored contact (user decision on F2-1),
  needs approval (`elicit`, category `financial_legal`, reason
  `contact-sensitive-edit`). The host reads the stored contact first
  (`GET /Contacts/{id}`) and the dialog (`contactChange` renderer) shows
  the contact id, its stored name, and `old → new` for each field the
  edit carries. An edit that echoes the stored `Name` unchanged is
  allowed after the read; any edit carrying `Name` or `XeroNetworkKey`
  therefore costs one extra GET even when nothing changes. Other edits
  (address, phones, defaults) are allowed without a read.
- Such an edit must be the only item in its request
  (`contact-one-per-request`); it may carry at most 3 `ContactPersons`
  (`contact-too-many-persons`); every fact must fit the dialog uncut
  (`contact-too-many-fields`, `contact-value-too-long`: old and new text
  together at most 200 characters). Nothing may sit beside the
  `Contacts` array, on any request (`contact-unexpected-key`). In such
  an edit, when both `ContactID` and `ContactNumber` are sent, the stored
  contact's number must match exactly (`contact-number-mismatch`).
- An edit keyed by `ContactNumber` alone is read by that number; a 404
  is treated as a create (old values shown as `(none)`, name
  `(new contact)`). A 404 on a `ContactID` is `contact-not-found`; any
  other non-2xx is `contact-read-failed`; an answer that is not exactly
  the requested contact is `contact-read-unreadable`.
- The by-id `updateContact`, contact-group membership, contact history
  and contact attachments stay out of the surface review (denied `not in
  surface review`).

**Invoices and credit notes (`createInvoices`, `updateOrCreateInvoices`,
`updateInvoice`, and the three credit-note twins).**

- `Status` is required on every item and must be the string `DRAFT` or
  `SUBMITTED` (`<prefix>-status-required`, `<prefix>-not-draft`,
  `<prefix>-bad-status`). Omitting it no longer means "keep the current
  status".
- Every item carrying an id is read from Xero before the write
  (`getInvoice` / `getCreditNote`) and is denied unless the stored
  document's status is `DRAFT` or `SUBMITTED`
  (`<prefix>-not-draft-upstream`); a 404 is `<prefix>-not-found`, any
  other non-2xx `<prefix>-read-failed`, an unreadable answer
  `<prefix>-read-unreadable`. At most four items carrying an id or a
  number per request, numbered creates count (`<prefix>-too-many-updates`). An item with no id but an
  `InvoiceNumber` / `CreditNoteNumber` is read by that number first
  (Xero may key an update on it): a 404 is a create, an existing
  document must itself be a draft (`<prefix>-number-matches-posted`).
  The number must be a string without edge spaces (`<prefix>-bad-number`);
  a number containing `/` cannot be read and is refused
  (`upstream-inspect-failed`). Trade-offs, accepted: one GET per
  numbered create, and a bill whose supplier reference equals a posted
  bill's number is refused.
- On the by-id endpoints the body takes exactly one item
  (`<prefix>-by-id-multiple-items`), a body id must equal the path id
  (`<prefix>-id-mismatch`), and the read uses the path id. No key may
  sit beside the wrapper (`<prefix>-unexpected-key`).
- An inline `Contact` carrying any of the six sensitive contact fields is
  denied (`<prefix>-inline-contact-details`): whether Xero applies
  inline contact fields to an existing contact is unverified; change
  the contact through `/Contacts`.
- Every outcome here is a deny, never a dialog. Nothing the sandbox can
  do moves a document out of DRAFT/SUBMITTED between the read and the
  write, because every status transition is denied by the same inspector.

**Repeating invoices (`createRepeatingInvoices`,
`updateOrCreateRepeatingInvoices`, `updateRepeatingInvoice`).** Each item
must carry `Status: "DRAFT"` (`repeating-status-required`,
`repeating-not-draft`); `ApprovedForSending`, `SendCopy`, `MarkAsSent`
and `IncludePDF` set are denied (`repeating-send-flag`, category
`external_data_flow`); `RepeatingInvoiceID` and `ID` must agree and match
the path id; the inline `Contact` rule above applies. An item naming a
template is read first (`getRepeatingInvoice`) and denied unless the
stored template is `DRAFT` (`repeating-not-draft-upstream`). Approving a
template for sending is done in Xero.

**Attachments (`create{Invoice,CreditNote}AttachmentByFileName`, the PUTs).**
The inspector is wired, with `acceptsStaged` (a composed staged body is
accepted; its size is the assembled length). The body must be the
file's bytes (`attachment-not-bytes` for a JSON or multipart body), the
MIME type one of the accepted set (`attachment-bad-mime`), at most
25 MiB (`attachment-too-large`). `IncludeOnline` with any value other
than `false` is denied (`attachment-include-online`, category
`external_data_flow`): it publishes the file on the customer's online
invoice. A differently cased `includeonline` is refused earlier as
`undeclared-query-param` (§7.9). The bytes-update POSTs
(`update{Invoice,CreditNote}AttachmentByFileName`) are removed from the
surface review (denied `not in surface review`): an update could
overwrite a file already published on the online invoice, and the POST
does not declare `IncludeOnline`, so it can neither be checked nor reset
there. A new version is uploaded under a new file name with the PUT.
Attaching to an
authorised invoice without `IncludeOnline` stays allowed (the file is
internal). `xero.files.uploadFile` and `createFolder` (the Files API,
not customer-facing) remain bare allows.

**Host-side reads and audit.** The stored reads are `inspectUpstream`
hooks (§7.10), so the limits there apply: plain-allow GETs only, at most
four per request, any lookup failure or hook throw denies with
`upstream-inspect-failed`. Each read costs one extra Xero API call
(counting against Xero's rate limits, not `EXECUTE_MAX_UPSTREAM_CALLS`)
and writes its own `allow` audit line (e.g. operation
`xero.accounting.getInvoice`, with `upstreamStatus`) before the write's
decision line. Contact reads are audited under
`xero.accounting.getContactByContactNumber`: the path matcher labels
`GET /Contacts/{x}` that way even when the read is keyed by `ContactID`.
A contact edit that raises an approval writes the read,
the elicitation outcome, then the write. No lookup string reaches the
model: deny messages carry at most the HTTP status, and stored values go
only into the dialog's facts.

**Claude.ai.** Claude.ai cannot elicit, so a contact edit that needs
approval (payee, delivery or status fields, or a rename) is denied there
(`unsupported`). Creates and other edits keep working.

**Left for the operator (live checks, not run).**

- Whether Xero keeps an attachment's `IncludeOnline` when its bytes are
  replaced (`POST …/Attachments/{name}`). If an update resets it to
  false, the two attachment-update POSTs could be offered again behind
  the same inspector.

- Xero `GET /Invoices/{InvoiceNumber}` and `GET /CreditNotes/{CreditNoteNumber}`
  resolve a document by number. The numbered-create read relies on it:
  if Xero answers 404 for an existing number, the read treats the item
  as a create and the control fails open for updates keyed by number.
- Xero does not upsert contacts by `Name` (an item with no id but the
  name of an existing contact must create a new contact, not edit the
  stored one). If it does, a create carrying payee details would edit
  an existing contact without approval.
- The review's §6 checks in the demo company: F2-2, `PUT
  /RepeatingInvoices` with `Status: "AUTHORISED"` and
  `ApprovedForSending: true`; F2-4, an update of an authorised unpaid
  test invoice with no `Status`. The fixes do not depend on the outcome.

**Residual (accepted).** Creates stay open, so a lookalike contact (for
example a name with a Cyrillic `е`) can be created with any bank
details; paying or billing it is gated elsewhere. Payroll
`updateEmployee` still shows only the generic dialog (payroll write
scopes are not requested, so it fails upstream with 403).

### 7.12 Staged-file ownership and the audit trail (2026-11 wave 4)

Wave 4 of the 2026-11 review fixes binds every staged file to the
principal that created it, limits the public download to
`STAGING_FETCH_MAX_USES` uses (default 5), audits
staging, closes the remaining unaudited exits of `codemode.request`,
caps and budgets audit lines, and keeps sandbox console output out of
the host log stream. Nothing here elicits, so Claude.ai (which cannot)
behaves exactly as other clients do.

**Owner rule.** Every staging row carries `owner`: the session's audit
principal (`principalOf`, the OAuth `sub`, the same value as the audit
`principalId` and the session binding of §7.4). `register_file_handle`,
`putFile`, `returnAs: "stage"` and `stageFromUpstreamJson` write it;
`getFile` and `composed` / `multipart[].staged` resolution require the
caller's principal to equal it. A row owned by someone else, or by no
one, is the same 403 "file not found or not yours" as a wrong token,
checked before state and expiry, so the answer is no ownership oracle.
An empty-string principal is treated as no owner on both sides. A
session without a truthy principal gets no `__stagingHost` and no
`register_file_handle` tool, and the capabilities themselves refuse to
store without one ("staging requires an authenticated principal").
The owner's own reuse of a `{ file_handle, token }` in later turns
(send again, `getFile`) is unchanged.

**Use-limited public download.** `GET /staging/fetch/<handle>` still
takes only the `stg_` bearer (its consumer is a human's `curl` with no
MCP token), but each open is counted against `STAGING_FETCH_MAX_USES`
(positive integer, default 5; no unlimited setting, and `0` or a
non-integer is a configuration error like every other `STAGING_*`
integer). After the row checks and before any R2 read, one atomic
`UPDATE staging SET fetch_count=fetch_count+1 WHERE … AND fetch_count<? AND expires_at>? RETURNING …`
counts the download; when it returns no row the `GET` is 410 `gone`.
A download that fails after counting (corrupt block, R2 error) still
counts. N+k concurrent `GET`s at limit N give exactly N 200s and k 410s.
The 410 does not count against the staging failure throttle (§7.6; only
403 does). The model-facing staging docs say the link allows a limited
number of downloads (default 5). In-MCP use by the owner (`getFile`,
staged sends) is not counted. The limit pairs with
`STAGING_FETCH_TTL_SECONDS`: a strict operator can set
`STAGING_FETCH_MAX_USES=1` and a short TTL.
*Residual (accepted):* a leaked `{ handle, token }` pair yields up to N
anonymous downloads (N = `STAGING_FETCH_MAX_USES`) within the fetch
TTL. A leak needs a channel out of the model's output, and every
download is audited with the owner's principal, so it is visible.

**Rows from before the migration.** Rows written before
`0003_owner.sql` have `owner` NULL and are refused by every reader:
403 from `getFile` and staged sends (`staged-ref-unresolved`), bare
`forbidden` from `/staging/fetch`. There is no shim; such rows expire
within the upload TTL (5 min) or fetch TTL (1 h) of the deploy.

**Staging audit lines.** Every staging event writes one line with
`operationId: "staging.<event>"`, a `method`/`path` naming the
capability or route (never the handle), and
`staging: { event, fileRef?, byteLength?, status }`. Refusals are
`decision: "deny"`, `reason: "staging-refused"`; `fileRef` (12 hex
characters of SHA-256 of the handle) joins the lines of one file.

| Event | `method` / `path` | Written | `principalId` |
|---|---|---|---|
| `register` | `TOOL` / `register_file_handle` | every reservation (`byteLength` = the declared `expected_byte_len`) | the session's |
| `upload` | `POST` / `/staging/upload` | every outcome after the token lookup, including a 500 logged just before a storage error is rethrown; the earlier refusals (no bearer, malformed or over-cap `Content-Length`) log nothing | the row's owner; none when no row matched |
| `store` | `HOST` / `__stagingHost.putFile` or `__stagingHost.stageFromUpstreamJson` | every call | the session's |
| `store` (`returnAs: "stage"`) | the operation's own `allow` line gains `staging` | after the upstream answered | the session's |
| `read` | `HOST` / `__stagingHost.getFile` | every call; `fileRef` only when the reference resolved to the caller's own row (absent on a cross-owner or legacy deny) | the session's |
| `attach` | the request's `staged-ref-unresolved` deny line gains `staging` | a staged reference that does not resolve (`status` 500 when the lookup itself threw) | the session's |
| `download` | `GET` / `/staging/fetch` | every request, including a missing bearer (403) or handle (404) | the row's owner when the row has one (legacy owner-less rows log none) |

Example (a 410 second download; `deployment` and `ts` omitted):

```
AUDIT {"method":"GET","path":"/staging/fetch","operationId":"staging.download","decision":"deny","reason":"staging-refused","principalId":"<sub>","staging":{"event":"download","fileRef":"3f9a0c1d2b4e","status":410}}
```

`stageFromAttachment` is an alias of `stageFromUpstreamJson`, so its
store line logs `path: "__stagingHost.stageFromUpstreamJson"`.
A successful `putFile` also returns `file_ref` to the sandbox (it is not
a secret). Host-assembled sends carry `stagedRefs` (§7.8).

**Budgets.** `getFile` and `putFile` now count against
`EXECUTE_MAX_UPSTREAM_CALLS` with `stageFromUpstreamJson` and
`stageFromAttachment` (§7.5). The denial budget
(`EXECUTE_MAX_DENIED_CALLS`, default 32) counts every budgeted call that
rejects and every staging call answering `{ ok: false }`; once a run has
reached it, every further call is refused before the handler with
"too many refused requests in this execution", and one line
`{ "method": "RUN", "path": "execute", "decision": "deny", "category":
"malformed", "reason": "denial-budget-exceeded" }` is written per run.
Because a refusal is counted only when its call settles, at most
`EXECUTE_MAX_DENIED_CALLS` budgeted calls of one run are in flight at
once; the rest wait for a slot (they do not fail for it), so at most
twice the budget in refusals ever reaches a handler. Code that codemode
could not parse (and would splice into its module verbatim, ahead of its
console overrides) is refused before the run: the tool answers
"code is not valid JavaScript" and writes one `RUN` deny line with
`reason: "code-not-parseable"` (`path` `execute` or `search`).

**Caps.** The sink caps `method`, `path`, `reason`, `category` and
`operationId` (§2), and `codemode.request` refuses a `method` over 32 or
a `path` over 4096 code points before matching
(`oversize-method-or-path`), so a 300 KB path never reaches the matcher
or the log. *Residual:* the caps bound fields, not lines, and allowed
calls are not in the denial budget; roughly 700 allowed calls with long
paths in one run could still exceed the platform's log limit if that
limit applies per invocation (unproven). The operator's lever is
`EXECUTE_MAX_UPSTREAM_CALLS`. The caps count code points, not bytes: a
capped deny line can still be about 6 KB once JSON escapes C0 controls
and lone surrogates, so 32 denials can write about 200 KB in one run,
close to a 256 KB per-invocation log budget.

**Header validation.** Sandbox-supplied `headers` are checked at entry,
before any token mint or approval, and every refusal writes a
`malformed` deny line whose `reason` is the only record (names and
values are never logged): `invalid-header-value` (not a plain object,
or a value that is not a string of at most 4096 characters free of CR,
LF, NUL and characters above U+00FF), `too-many-headers` (more than
32), `invalid-header-name` (not an RFC 7230 token, or over 256
characters), `content-type-header`, `forbidden-header`,
`duplicate-header` (two casings of one name), and, after matching,
`headers-on-gated-op` (any header on an inspected or approval
operation). The forbidden set: `authorization`, `proxy-authorization`,
`cookie`, `host`, `content-length`, `transfer-encoding`, `connection`,
`content-type`, `x-http-method-override`, `x-http-method`,
`x-method-override`, and the credential and project-attribution headers
`x-goog-api-key`, `x-goog-user-project`, `x-goog-authuser`,
`x-goog-iam-authorization-token`, `x-goog-iam-authority-selector`,
`x-api-key`, `api-key`, `x-auth-token` (exact names; `Idempotency-Key`
and the like stay allowed).

**Other refusals now audited.** `invalid-body-base64`,
`multipart-part-malformed`, `staging-not-configured`,
`raw-body-not-string`, `no-principal`, `staged-ref-unresolved` when the
staged lookup itself throws, and URL build failures other than the two
mismatches (`upstream-url-build-failed`, category `url_safety`). A
`returnAs: "stage"` without a staging store writes the operation's allow
line (with `upstreamStatus`) before it throws.

**Dispatch and outcome lines.** A host-assembled send
(`composed` / `multipart[].staged`) writes an `allow` line with
`phase: "dispatch"` (and `stagedCount`, `stagedBytes`,
`assembledBytes`, `stagedRefs`) before its first byte goes out, then its
ordinary outcome line; consumers counting one line per request must
ignore `phase: "dispatch"`. An allowed request whose processing fails
after the decision writes one `allow` line with `outcome: "failed"` and
a fixed `reason`, then rethrows: `token-mint-failed`,
`request-headers-failed` (the provider's header hook threw),
`transfer-gate-failed`, `transfer-aborted` (the run's host deadline),
`transfer-timeout`, `upstream-closed`, `staged-read-failed`,
`upstream-request-failed`, `response-read-failed` or
`stage-store-failed`. No error text is logged.

**Sandbox console (C-2).** codemode overrides only `console.log`,
`warn` and `error` in the sandbox. The scaffold's `__docsHost` provider
(given to every run, `search` included) carries a prelude that codemode
emits after those overrides and before the LLM code: every other
`console` method is replaced by a forwarder to the captured
`console.log`, so `console.info("AUDIT {…}")` lands in the run's `logs`,
not in the Worker's log stream. Code that codemode would splice in
unparsed (its `normalizeCode` falls back to the raw text when acorn
fails) is refused before it reaches the sandbox (`code-not-parseable`),
because brace-unbalanced text can close `evaluate()` and run at module
scope, before the console overrides and every prelude.

*Live result (gmail-dev, 2026-11-12, pre-wave-4 code: no prelude, no
parse guard).* Neither `wrangler tail` nor Workers Logs showed any line
from the sandbox isolate, while a refused request's genuine `AUDIT`
line appeared in both as the control. Probes: `console.info`, `debug`,
`table` and `log`; `Object.getPrototypeOf(console).info.call(…)`;
`delete console.info` then `console.info`; `reportError`; a throwing
`queueMicrotask`; and a brace escape whose `console.info`/`console.log`
and a `throw` ran at module scope (the escape itself worked: its
injected `return` became the tool result). The forged-line threat
therefore does not exist in production; the prelude and the parse guard
are defence in depth, and HMAC tagging of `AUDIT` lines is not needed.
The same run confirmed the isolate has no network either way: `fetch`,
`cloudflare:sockets` `connect()` and `node:net` `connect()` (dynamic
`import()` or static imports via the escape) all fail with the
runtime's "not permitted to access the internet" error
(`globalOutbound: null`), `node:http` is not available, and module-scope
I/O is refused by the runtime.

**Rollout.** Apply `0003_owner.sql` (adds `owner TEXT` and
`fetch_count INTEGER NOT NULL DEFAULT 0`) to each deployment's remote `STAGING_D1` before
its new code goes live: new code on an unmigrated database refuses every
store with 500 ("d1 insert failed"). `scripts/upgrade/2026-11-11-staging-owner.sh`
checks the migration and the `migrations_dir` bindings, then migrates
and deploys each deployment in turn (`--dry-run`, `--env-only=<name>`).
No new secret; two new optional vars, `STAGING_FETCH_MAX_USES` and
`EXECUTE_MAX_DENIED_CALLS`.

**Live checks (run).** The C-2 console check ran on 2026-11-12 (see
*Live result* above). The per-invocation log cap ran on gmail-dev on
2026-11-13: with `EXECUTE_MAX_DENIED_CALLS` raised to 400 for the run,
one `execute` made 300 refused requests with ~1 KB paths and then one
allowed request; all 301 lines reached Workers Logs, the allowed
request's `AUDIT` line included. `EXECUTE_MAX_UPSTREAM_CALLS` stays at
its default.

### 7.13 OAuth public legs and the release changelog (2026-11 wave 5)

Wave 5 of the 2026-11 review fixes closes A-6 (the consent page
under-warned and a refused `/callback` stayed redeemable), A-3 (the
browser legs were public, unthrottled and buffered any body), A-5 (the
client sweep amplified junk and reaped legitimate clients) and G-4 (the
release changelog published private commit subjects). The end-to-end
regression suite is `src/__tests__/oauth-flow-attacks.test.ts` (through
the real worker composition: library, handler, hardening wrapper);
unit-level probes are in `oauth-handler.test.ts`,
`oauth-consent.test.ts`, `oauth-hardening.test.ts` and
`oauth-public-legs.test.ts`.

**Rate limits (A-3).** `enforceOAuthHardening` classifies four
endpoints and gives each its own fixed-window counter
(`ratelimit:<endpoint>:<client>:<window>`, section 6), keyed by the
client identity of 7.7:

| Endpoint | Default | Variables | KV key prefix |
|---|---|---|---|
| `POST /register` | 1 per 300 s | `OAUTH_REGISTER_RATE_LIMIT`, `OAUTH_REGISTER_RATE_LIMIT_WINDOW_SECONDS` | `ratelimit:register:` |
| `POST /token` | 20 per 60 s | `OAUTH_TOKEN_RATE_LIMIT`, `OAUTH_TOKEN_RATE_LIMIT_WINDOW_SECONDS` | `ratelimit:token:` |
| `GET`/`HEAD`/`POST /authorize` | 30 per 300 s | `OAUTH_AUTHORIZE_RATE_LIMIT`, `OAUTH_AUTHORIZE_RATE_LIMIT_WINDOW_SECONDS` | `ratelimit:authorize:` |
| `GET`/`HEAD /callback` | 10 per 300 s | `OAUTH_CALLBACK_RATE_LIMIT`, `OAUTH_CALLBACK_RATE_LIMIT_WINDOW_SECONDS` | `ratelimit:callback:` |

A flow is one `GET` and one `POST` on `/authorize` and one `/callback`,
so the defaults allow fifteen connections per five minutes from one
address. `/callback` is the tighter bucket because each one costs an
upstream token request carrying the deployment's client secret. The 429
(with `Retry-After`) is answered before the handler: a refused request
costs one KV read and no write, so an abusive address writes at most
2 × 30 keys (`consent-used:` and `auth-state:`) per window instead of
without bound. The path is compared after percent-decoding, because
Hono decodes `%xx` before routing: `/%61uthorize` counts against the
`/authorize` bucket and gets the same body cap. A path holding a
malformed escape (`%ZZ`, a trailing `%`) is refused 400
(`invalid_request`, "Malformed request path") before anything else, on
every path the wrapper sees, `/mcp` included (the `/staging/*`
routes are matched on the raw path before the wrapper, so a malformed
escape there fails the handle lookup with 403 instead); before wave 5 the library
answered such paths itself (for example 401 on `/mcp%ZZ`). No
legitimate client sends one.

*Inherited caveat (A-2, open).* These buckets use the same best-effort
counter as the "The throttle is best-effort" paragraph of 7.6: a
parallel burst can pass by a small margin, and one abusive neighbour
behind a shared IPv4 address or IPv6 /64 locks the others out of that
endpoint for the rest of the window. Browser legs come from users' own
addresses rather than a hosted client's egress pool, so the lock-out
risk there is narrower than for `/token`. An atomic counter (a Durable
Object or the Workers Rate Limiting binding) and keying `/token` on
`client_id` are on the maintainers' backlog.

**Body caps (A-3).** Every hardened request body is read once, under a
streaming cap (`readBodyCapped`): a `Content-Length` over the cap is
refused without reading a byte; otherwise the stream is read chunk by
chunk and cancelled the moment the running total passes the cap, so at
most the cap plus one chunk is ever pulled. `POST /register` is capped
at 1 MiB (every registration the code accepted before still fits),
`POST /authorize` and `POST /token` at 16 KiB (a consent token is 1–2
KB, a code a few hundred bytes, a PKCE verifier 128 characters). Over
the cap is 413 (`invalid_request`, "Request body too large", no-store).
The handler receives a copy of the request rebuilt from the bytes
already read (same method, URL and headers), so nothing is tee'd or
buffered twice; the library's own 1 MiB check on `/register`, which
buffers the whole body first, is never reached with a larger one.

**Consent page (A-6(1-3)).** The warning box is on every page and
precedes the client name (7.1); the "known MCP client" rule is an exact
list plus path-pinned loopback; the client name is a capped, sanitised,
quoted claim. Clients whose users now see the `Warning:` sentence
where they did not before: any `claude.ai` or `claude.com` redirect
other than `/api/mcp/auth_callback` (including one with a port or
query), a loopback client whose path is not `/callback` or
`/oauth/callback`, and custom-scheme redirects (already warned).
Claude.ai, Claude desktop and mobile, Claude Code and MCP Inspector
keep a page with the box only. Before deploying, confirm the live
hosted client's registered redirect (`client:<id>` → `redirectUris`,
section 6) is one of the two pinned URIs; if it differs, add the exact
URI to `KNOWN_REDIRECT_URIS`. A miss costs a warning, never a refusal.

**Refused `/callback` (A-6(4)).** A `/callback` whose
`__Host-cm-auth-<state>` cookie is missing or wrong deletes the
`auth-state:` stash before answering 400 with the do-not-share text
(7.1), and never spends the upstream code (that would cost an upstream
call with the client secret per forged request; without the stash,
which holds the PKCE verifier, the code is useless here anyway). A
malformed stash is deleted the same way. So the split flow — the
attacker approves the page in their own browser, sends the IdP sign-in
link to the victim, and talks the victim into sharing the address of
the error page they land on — ends at that error page: the attacker's
replay with the matching cookie gets "State expired or invalid", no
grant exists, and no bearer resolves to the victim.

*Accepted residual.* A party who learns an in-flight `state` (122
random bits; only the IdP and the user's browser see it) can hit
`/callback` without a cookie and cancel that sign-in; the user
restarts. One restart beats one account takeover, and nothing else is
reachable with a state alone. *Second residual (same class as the
F-15 double submission of 7.1).* The stash delete is a KV write, and
KV is eventually consistent: a replay at the attacker's own location
within about 60 s of their approval may still read a cached copy of
the stash their `POST /authorize` wrote there. It needs the victim to
sign in and share the address within that minute; the refusal text
tells them not to.

**Client records (A-5).** The library's `client:<id>` record carries a
KV TTL (section 6): `OAUTH_CLIENT_TTL_SECONDS` (30 days; values under
60 are raised to 60, KV's minimum) from a successful `/register`, and
the grant lifetime (90 days, 7.3) plus `OAUTH_CLIENT_TTL_SECONDS` —
120 days — from each `/token` 200 whose `grant_type` is
`authorization_code` or `refresh_token`, only for an
`application/x-www-form-urlencoded` body (Content-Type essence exact:
the library also accepts a multipart body whose type merely includes
that string, which would let a smuggled part name another client).
A grant's last refresh is at
most 90 days after authorisation, so a client in use is never forgotten
while its grant lives and keeps 30 days to re-authorise after. A
revocation 200 does not renew (the library answers 200 for any
`token=` value, so renewing on it would let anyone who knows a public
`client_id` keep it alive for ever), nor does `GET /authorize` (it is
anonymous; a phishing client could poll it). The five-minute
`oauth-client-sweep.ts` and its `clientreg:<id>` stamps are removed:
the cron issues no `OAUTH_KV` operation (the staging sweep still uses
it). User-visible: a connector not used for 120 days must be removed
and re-added in the MCP client; before wave 5 any connector whose
grant had lapsed (after 90 days) hit the same error within five
minutes. How Claude.ai reacts to `invalid_client` after 120 days
(re-register silently, or require remove-and-re-add) is unverified;
both are acceptable.

**Upgrade.** `scripts/upgrade/2026-11-11-oauth-client-ttl.sh` deploys
each deployment first (so the old code stops stamping and sweeping),
then lists the `client:*` keys with no expiration, reads them with
`wrangler kv bulk get` (100 keys per file) and writes them back in one
`wrangler kv bulk put` with a per-item `expiration_ttl` of the active
TTL (wrangler 4.87 ignores `--ttl` on a remote bulk put), then
`bulk delete`s the orphaned `clientreg:*` stamps. One `op run` wraps
the whole run; `--dry-run` prints every command and runs none;
`--env-only=<deployment>` picks one; `--app=<apps/dir>
--wrangler-env=<name>` covers any other environment. Idempotent and
safe to re-run. Until it runs, legacy client records never expire and
the orphaned stamps stay.

**Release changelog (G-4).** `scripts/release/changelog.sh` lists a
commit only when a touched path is allowlisted, not denylisted and not
rsync-excluded from the public mirror (`.github`, `scripts/release`,
`tests/release`, at any depth; bare denylist entries match as globs,
as `sanitize.sh` applies them), so a commit touching only
`docs/security`, `docs/plans`, `docs/todo.md` or the release scripts
never prints its subject. The surviving subjects pass through
`leak_guard_text` (the leak patterns applied to text, UUIDs included):
a hit makes the script exit 1 naming the commit and the pattern, never
the subject, and the release aborts; the remedy is a token in
`lib/changelog-exclude-subjects.txt` or a reworded subject, then
re-tag. CI's copy of the patterns is self-scrubbed, so `promote.sh`
preflights the same range (previous release tag to the source SHA)
twice before committing anything: once with the intact patterns from
the source checkout, and once with the scrubbed copy from the scrubbed
tree, because the scrubbed placeholders (for example `adam`,
`your-subdomain`) can false-positive on benign subjects and would
otherwise fail only in CI, after the tag was pushed. A mixed or squash
commit that touches a public path still publishes its subject; only
the token filter and the leak guard apply to it, so squash-merge the
security branch to one neutral subject.
