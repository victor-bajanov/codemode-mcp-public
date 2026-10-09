# Operator security runbook

This is an operator runbook for the `@local/scaffold` package. It
describes where audit and debug log lines go, what the default
redaction posture looks like, how to deliberately unlock PII logging
when an incident calls for it, how to inspect the OAuth state KV, and
the OAuth, sandbox and edge controls added after the 2026-10-07
defensive security review (section 7). It is intentionally not a
vuln-disclosure policy.

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
its own slot; the broker Durable Object is still one per `userId`, which
keeps rotation serialised. Every write refreshes a **180-day** TTL, so
the slot of a grant that is never used again ages out.

A legacy `token-slot:<userId>` slot (the single per-user slot written
before the review) is migrated on first use: the grant whose original
token decrypts it adopts it, rewrites it under its per-grant key and
deletes the legacy key. A legacy slot that no remaining grant can
decrypt is inert and can be deleted by hand.

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
only tune defaults.

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
