<img src="assets/codemode-lockup.svg" alt="codemode" height="40">

# codemode-mcp

Cloudflare Worker MCP servers that expose third-party SaaS APIs (Gmail +
Google Calendar, Xero, Optical, …) to MCP clients (Claude.ai, Claude Code, etc) using Cloudflare's
**Code Mode** pattern: each provider ships a `search` / `execute` pair and
the client writes JavaScript that runs in a sandboxed sub-Worker, instead
of issuing one MCP tool call per API operation.

Cloudflare's [`agents`](https://github.com/cloudflare/agents) and
[`@cloudflare/codemode`](https://www.npmjs.com/package/@cloudflare/codemode)
libraries supply the runtime primitives — Durable-Object-backed MCP agent,
sandboxed `worker_loader`, `openApiMcpServer` over an OpenAPI spec. This
repo wraps them into a turn-key, single-operator **provider scaffold**:

- **`setupProvider(providerDefinition)`** assembles a deployable Worker
  from a provider definition. OAuth endpoints (`/authorize`, `/token`,
  `/register`, `/mcp` via `@cloudflare/workers-oauth-provider`), the MCP
  agent Durable Object, audit logging, and elicitation glue are all wired
  for you. New providers are typically ~50–100 lines.
- **Per-operation surface review** — each provider declares an explicit
  allow-list of OpenAPI operations with reviewer notes alongside the code,
  so security-relevant changes show up in code review rather than slipping
  in via a spec bump.
- **Spec loaders** for the quirks of major SaaS APIs (Google Discovery →
  OpenAPI, multi-spec merging for Xero).
- **Encrypted attachment staging** — opt-in R2 + D1 bindings give the
  sandbox a `__stagingHost.{getFile, putFile, stageFromUpstreamJson,
  stageFromAttachment}` capability (`stageFromAttachment` is an alias for
  `stageFromUpstreamJson` — same function, task-shaped name) so LLM code can
  pass multi-MB binaries (Gmail attachments,
  Xero documents) by reference instead of base64-inlining them into the
  context. `codemode.request` attaches staged files to an outbound body by
  reference (`composed`, `multipart[].staged`), assembled on the host, so
  file bytes never enter the sandbox. Bytes are HKDF/AES-GCM encrypted at
  rest in R2 in 1 MiB blocks; a cron sweep expires both rows and objects. See
  [`packages/scaffold/src/staging/`](./packages/scaffold/src/staging/).
- **Shared TokenBroker Durable Object** — refresh-token rotation runs in
  a DO addressed by `userId`, which keeps one in-flight refresh per grant:
  concurrent tool calls on a grant share a single upstream refresh, so they
  can't race on a rotated refresh token. The DO's own storage holds each
  grant's sealed slot, so a rotated refresh token survives the DO being
  evicted; KV keeps a copy, and `/callback` seeds the first slot there
  with the sign-in access token.
- **OpenTofu module** for the per-app infra — one KV namespace plus a
  Cloudflare Access policy gating the MCP endpoint to a single operator.
  One `tofu apply` per provider.
- **Reference Gmail (+ Calendar), Xero, and Optical deployments** with vetted
  surface reviews to copy from. The Gmail provider bundles the Gmail and
  Google Calendar APIs in one Worker — same Google identity, OAuth client,
  and consent screen — reached over the shared `www.googleapis.com` origin.
  The Optical provider fronts a self-hosted Optical scheduling backend; point
  it at your own Optical deployment.

The whole stack is designed for personal/operator-of-one use: OAuth tokens
live in a per-app KV namespace and the MCP endpoint is fronted by
Cloudflare Access — no multi-tenant accounting, no shared user store.

If you've never used Cloudflare before, read
[`docs/cloudflare-getting-started.md`](./docs/cloudflare-getting-started.md)
first — that covers the platform concepts, account setup, and CLI tooling
this repo assumes.

## Repository layout

```
apps/
  gmail/                  deployable Worker — Gmail
  xero/                   deployable Worker — Xero (Demo Company)
  optical/                deployable Worker — Optical scheduler (your own Optical deployment)
packages/
  scaffold/               provider-agnostic Worker scaffold (OAuth, MCP agent,
                          request-handler, audit, elicitation)
  providers/gmail/        Gmail provider definition + surface review + spec
  providers/xero/         Xero provider definition + surface review + spec
  providers/optical/      Optical provider definition + surface review + spec
  shared/                 cross-package types (surface review, elicit)
  spec-loaders/           OpenAPI spec ingestion (Google Discovery, Xero merge)
infra/                    OpenTofu — KV namespace + Cloudflare Access policy
                          (one module instance per deployed app)
scripts/                  diagnostics, repros, measurement helpers
docs/                     specs, plans, runbooks, this guide
```

Each `apps/*` is a thin entrypoint:

```ts
// apps/gmail/src/index.ts
import { setupProvider } from "@local/scaffold";
import { gmailProvider } from "@local/providers-gmail";

export const { McpAgent: GmailMCP, default: OAuthHandler } = setupProvider(gmailProvider);
export default OAuthHandler;
```

`setupProvider` returns the Durable Object class (the MCP agent) and an
`OAuthProvider` handler wired to `/authorize`, `/token`, `/register`, `/mcp`.

## Prerequisites

- **Node 20+** and **pnpm 9** (the repo pins `pnpm@9.12.0` via `packageManager`).
- **Wrangler 4** — installed per-app via `devDependencies`; invoke with
  `npx wrangler` or via the package scripts.
- **OpenTofu 1.6+** (only if you use `infra/` to provision Cloudflare
  resources). `brew install opentofu`.
- **1Password CLI** (`op`), optional — the OpenTofu setup reads secrets from
  1Password via `op run --env-file=.env`. You can substitute literal env vars
  if you don't use 1Password.
- A **Cloudflare account** with the workers.dev subdomain reserved and
  Zero Trust enabled. See the
  [getting-started guide](./docs/cloudflare-getting-started.md) if you don't
  have these yet.
- A **Google Cloud OAuth client** (for Gmail), a **Xero OAuth app** (for
  Xero), and/or a **PKCE client registered on your Optical deployment** (for
  Optical). See the per-app sections below.

## Install

```
pnpm install
```

This installs all workspaces.

## Deploy: end-to-end walkthrough

The flow is the same for every app:

1. **Provision Cloudflare resources** (KV namespace + Access policy on
   `/authorize`, which gates both the consent page and its approval).
2. **Register the OAuth app** with the upstream provider (Google / Xero /
   your Optical deployment).
3. **Configure the Worker** (paste the KV id; set Worker secrets).
4. **`wrangler deploy`**.
5. **Connect from your MCP client**.

The next sections walk through this for each app.

### Provision Cloudflare resources (OpenTofu)

The `infra/` OpenTofu stack provisions, per app:

- `cloudflare_workers_kv_namespace` — for `OAUTH_KV`.
- `cloudflare_zero_trust_access_application` on `/authorize` —
  self-hosted Access app.
- `cloudflare_zero_trust_access_policy` — allow-list by email through an
  allowed identity provider.

```
cd infra
cp .env.example .env
```

Edit `.env`:

- If you use 1Password, leave the `op://...` references and adjust paths to
  match your vault layout.
- If you don't, replace each `op://...` value with the literal credential
  and remove the `op run` prefix from the commands below.
- Set `TF_VAR_cloudflare_workers_subdomain`,
  `TF_VAR_allowed_emails` (JSON list), and
  `TF_VAR_access_allowed_idp_ids` (JSON list of Cloudflare Access IdP UUIDs
  — find them at Zero Trust → Settings → Authentication; the UUID is in the
  URL when you edit an IdP).

Apply:

```
op run --env-file=.env -- tofu init
op run --env-file=.env -- tofu plan
op run --env-file=.env -- tofu apply
```

Note the outputs — you need `*_oauth_kv_id` for the next step.

### App: `gmail`

1. **Paste the KV id** into `apps/gmail/wrangler.jsonc` at
   `kv_namespaces[0].id`. (The committed value points at the existing
   namespace; replace it with yours.)

2. **Create a Google Cloud OAuth client**:
   - Console → APIs & Services → Credentials → Create OAuth client ID
     (Web application).
   - Authorized redirect URI:
     `https://gmail.<your-subdomain>.workers.dev/callback`
   - Enable both the **Gmail API** and the **Google Calendar API** on the
     same project (the provider exposes both).
   - OAuth consent screen: add yourself as a Test user (External, Testing
     mode is fine for a single-operator deployment).
   - Scopes used by the provider live in
     `packages/providers/gmail/src/index.ts → gmailProvider.oauth.scopes`
     (full Gmail mail scope + least-privilege Calendar scopes).

3. **Set Worker secrets**:

   ```
   cd apps/gmail
   npx wrangler secret put GOOGLE_CLIENT_ID
   npx wrangler secret put GOOGLE_CLIENT_SECRET
   npx wrangler secret put COOKIE_ENCRYPTION_KEY   # 32+ char random string; signs the /authorize consent form
   ```

4. **Deploy**:

   ```
   pnpm --filter @apps/gmail typecheck
   pnpm --filter @apps/gmail deploy
   # or from repo root: pnpm deploy:gmail
   ```

5. **Connect from Claude.ai**:
   - Claude.ai → Settings → Connectors → Add custom MCP.
   - URL: `https://gmail.<your-subdomain>.workers.dev/mcp`.
   - The first `/authorize` redirect shows the Worker's consent page, then
     Google consent. Where the infra still puts a Cloudflare Access policy
     on `/authorize` (an allowed email through an allowed IdP), that sign-in
     comes first; it is defence in depth only, and the Worker does not rely
     on it. The consent page names the MCP client and the redirect URI
     access will be sent to, with its host in bold; approve only a
     connection you started yourself, and check the host (for Claude.ai it
     is `claude.ai`) before clicking **Approve**. The page expires after
     five minutes; reload it from your client if it does.

### App: `xero`

See [`apps/xero/README.md`](./apps/xero/README.md)
for the per-app specifics (Xero OAuth registration, single-tenant grant
requirement, spec re-merge procedure).

Short version:

1. Paste the Xero KV id into `apps/xero/wrangler.jsonc`.
2. Register a Xero OAuth app at developer.xero.com with redirect URI
   `https://xero.<your-subdomain>.workers.dev/callback`.
3. Secrets: `XERO_CLIENT_ID`, `XERO_CLIENT_SECRET`, `COOKIE_ENCRYPTION_KEY`
   (32+ char random string; signs the `/authorize` consent form).
4. `pnpm --filter @apps/xero deploy`.

### App: `optical`

See [`apps/optical/README.md`](./apps/optical/README.md) for the per-app
specifics (PKCE client registration on the Optical side, bootstrap script,
spec re-sync). Optical is a separate, self-hosted scheduling backend; this
provider is a reference that expects you to run your own Optical deployment.

Short version:

1. Replace the placeholder Optical origin in
   `packages/providers/optical/src/index.ts` (`apiBaseUrl` and the three
   `oauth` URLs) with your Optical deployment, or set the
   `API_BASE_URL_OVERRIDE` / `OAUTH_{AUTHORIZE,TOKEN,USERINFO}_URL_OVERRIDE`
   vars per environment in `apps/optical/wrangler.jsonc`.
2. Register a PKCE OAuth client on your Optical deployment with redirect URI
   `https://optical.<your-subdomain>.workers.dev/callback` and scopes
   `scheduler:read scheduler:write`.
3. Secrets: `OPTICAL_CLIENT_ID`, `OPTICAL_CLIENT_SECRET` (any non-empty
   string; the PKCE flow ignores it), `COOKIE_ENCRYPTION_KEY` (32+ char
   random string; signs the `/authorize` consent form).
4. `pnpm --filter @apps/optical deploy`, or run
   [`scripts/bootstrap-optical.sh`](./scripts/bootstrap-optical.sh) to do the
   Tofu apply, KV-id paste, secrets, and deploy for prod + dev in one go.

### Deploying a dev variant

Each provider Worker has a paired `-dev` deployment (`gmail-dev`, `xero-dev`,
`optical-dev`) that points at a different upstream tenant and a different Cloudflare Access
application, so you can connect Claude.ai to a dev MCP connector without
disturbing the prod connector. The same `src/index.ts` deploys to both
environments; isolation is achieved entirely via Wrangler's `env.dev` override
and a parallel OpenTofu module.

One-time setup (per provider):

1. **Provision the dev KV + Access policy.** From repo root:

   ```
   op run --env-file=.env -- tofu -chdir=infra apply
   ```

   This adds the `gmail-dev` / `xero-dev` / `optical-dev` resources alongside prod; existing
   prod state is unchanged.

2. **Paste the dev KV id.** Run:

   ```
   tofu -chdir=infra output -raw gmail_dev_oauth_kv_id
   # and
   tofu -chdir=infra output -raw xero_dev_oauth_kv_id
   # and
   tofu -chdir=infra output -raw optical_dev_oauth_kv_id
   ```

   Paste each value into the corresponding
   `apps/<provider>/wrangler.jsonc` at `env.dev.kv_namespaces[0].id`,
   replacing the `PASTE_FROM_tofu_output_*` placeholder.

3. **Register a separate OAuth app** at Google / Xero (or a separate PKCE
   client on your Optical dev deployment) with redirect URI
   `https://<provider>-dev.<your-subdomain>.workers.dev/callback`. This must
   be a different client from the prod one — Google rejects mismatched
   redirect URIs, and you want a distinct consent screen anyway.

4. **Set the dev Worker secrets** (note the `--env dev` flag on every
   `wrangler secret put` — omitting it puts the secret on the prod Worker):

   ```
   cd apps/gmail
   npx wrangler --env dev secret put GOOGLE_CLIENT_ID
   npx wrangler --env dev secret put GOOGLE_CLIENT_SECRET
   npx wrangler --env dev secret put COOKIE_ENCRYPTION_KEY   # signs the consent form
   ```

   ```
   cd apps/xero
   npx wrangler --env dev secret put XERO_CLIENT_ID
   npx wrangler --env dev secret put XERO_CLIENT_SECRET
   npx wrangler --env dev secret put COOKIE_ENCRYPTION_KEY   # signs the consent form
   ```

5. **Deploy** from the repo root:

   ```
   pnpm deploy:gmail:dev
   # or
   pnpm deploy:xero:dev
   # or
   pnpm deploy:optical:dev
   ```

6. **Connect from Claude.ai** → Settings → Connectors → Add custom MCP:
   `https://<provider>-dev.<your-subdomain>.workers.dev/mcp`. The first
   `/authorize` hit shows the same consent page as prod. Where the infra
   still runs Cloudflare Access on `/authorize`, it prompts a fresh Access
   session for the new hostname first (separate Access app, separate
   cookie) — this is expected, and defence in depth only.

The prod and dev Workers share the same Durable Object class names
(`GmailMCP`, `XeroMCP`, `OpticalMCP`), but Wrangler scopes DO namespaces
per-environment, so dev grant state is fully isolated from prod.

## Development

From the repo root:

```
pnpm typecheck     # all packages
pnpm test          # all packages
pnpm build         # all packages (no-op for most; spec loaders generate)
```

Per-app dev server:

```
pnpm --filter @apps/gmail dev
```

Note: local `wrangler dev` does not exercise Cloudflare Access. If your
infra still runs an Access policy on `/authorize`, test it by hitting the
deployed `/authorize` URL; the Worker's own controls (consent page,
browser-bound `/callback`, rate limits) run with or without it.

## Operational reference

- **Observability**: each `wrangler.jsonc` has `observability.enabled = true`
  with full head sampling. Tail logs at Cloudflare dashboard → Workers →
  your worker → Logs, or with `npx wrangler tail`. To ship logs elsewhere,
  add a [Tail Worker](https://developers.cloudflare.com/workers/observability/logs/tail-workers/)
  via `tail_consumers` in `wrangler.jsonc` (forward to a SIEM, Datadog,
  BetterStack, or your own collector), or enable
  [Workers Logpush](https://developers.cloudflare.com/workers/observability/logs/logpush/)
  for direct delivery to R2, S3, or supported HTTP endpoints (Workers Paid plan).
- **Audit**: tool invocations log structured audit entries via
  `packages/scaffold/src/audit.ts` — searchable in Workers Observability.
- **Security runbook**: see [`packages/scaffold/SECURITY.md`](./packages/scaffold/SECURITY.md) for the audit-log redaction default, the deliberate PII-logging unlock path, and KV-state inspection.
- **Surface review**: each provider exports a `surfaceReview` allow-list
  classifying every `operationId` as `allow` / `elicit` / `deny`. New ops
  added by a spec re-sync are implicit-deny until classified.
- **Refresh-token rotation**: minted inside a per-`userId` TokenBroker
  Durable Object (`packages/scaffold/src/token-broker.ts`) which runs at
  most one refresh + slot persistence per grant at a time (concurrent
  callers on that grant wait for and share its result; the DO input gate
  alone would not serialise them); the underlying rotation logic lives in
  `packages/scaffold/src/refresh.ts`. Xero rotates on every use (60-day
  idle expiry), as does Optical (90-day idle expiry); Google's are long-lived.
- **Attachment staging** (optional): provider apps that bind R2 + D1 +
  `STAGING_*` vars expose a `register_file_handle` MCP tool, a
  `POST /staging/upload` + `GET /staging/fetch/<handle>` HTTP surface, and
  the `__stagingHost` sandbox capability. Tokens are AEAD-bound to the
  handle; expired rows are swept by the cron trigger. Apps without
  staging bindings simply don't expose any of this.

## Security behaviour (2026-10-07 review)

A 2026-10-07 defensive security review
was remediated on 2026-10-08. The operator detail is in
[`packages/scaffold/SECURITY.md`](./packages/scaffold/SECURITY.md) §7;
what you are likely to notice is below.

**Connecting.** `/authorize` shows a consent page before handing off to
Google, Xero or Optical: the provider, a warning box, the client's
self-declared name, the redirect URI with its host in bold, and the
scopes. The box is on every page and says to approve only a connection
you started yourself, from your MCP client, just now, and to choose
**Deny** if you reached the page from a link someone sent you. It adds
a `Warning:` naming where access will go when the redirect is not a
known MCP client: known means exactly
`https://claude.ai/api/mcp/auth_callback` or
`https://claude.com/api/mcp/auth_callback` (Claude.ai, Claude desktop
and mobile), or `http(s)://localhost`, `127.0.0.1` or `[::1]` on any
port with the path `/callback` (Claude Code) or `/oauth/callback` (MCP
Inspector). The client's name is shown after the box as a quoted claim
("An application calling itself “…”"), cut to 64 characters, so a
long "security notice" registered as a name cannot talk you past it.
Approving submits a five-minute, single-use form token signed with
`COOKIE_ENCRYPTION_KEY`. The consent page stands alone: where an
operator still runs Cloudflare Access on `/authorize` it is defence in
depth only (the Worker never relied on it for `/callback`, `/token`,
`/register`, `/mcp` or `/staging/*`, and since the 2026-11 wave 5 fixes
not for `/authorize` either: the warning is always on, and a `/callback`
from the wrong browser cancels the flow). The form token is spent on the
first submission, so a double
click on **Approve** (or re-submitting after Back) can land on "Consent
expired or invalid"; restart the connection from the client. If you
finish signing in at the provider in a browser other than the one that
approved the page (for instance by opening a link someone sent you),
`/callback` answers "This sign-in could not be completed in this
browser and has been cancelled. Do not share this page's address with
anyone." — the sign-in is cancelled for everyone, and nobody can
complete it from that address; start again from your MCP client. MCP
grants expire 90 days after authorisation, so each client re-authorises
every 90 days (grants made before this change keep no expiry until
re-authorised).

**MCP client requirements.**

- PKCE with `code_challenge_method=S256` is required on `/authorize`;
  requests without a code challenge, or with `plain`, are refused.
- `/register` accepts `http://` redirect URIs only for loopback hosts
  (`localhost`, `127.0.0.1`, `[::1]`); everything else must be
  `https://`.
- A redirect URI outside the consent page's known list (above) still
  works; its users see the `Warning:` sentence on the page. Nothing is
  refused for it.
- Request bodies are capped: `POST /register` at 1 MiB, `POST /authorize`
  and `POST /token` at 16 KiB; larger ones get 413 "Request body too
  large". Real registrations and token forms are far smaller.

Clients that follow the MCP authorisation specification, such as Claude.ai
and Claude Code, already meet all of these.

**New optional vars** (all positive integers; omit for the default):

| Variable | Default | Purpose |
|---|---|---|
| `EXECUTE_HOST_TIMEOUT_MS` | `75000` | Host-side deadline for one sandbox run; later upstream calls from an abandoned run are refused. |
| `EXECUTE_MAX_UPSTREAM_CALLS` | `1000` | Upstream requests one sandbox run may make. Kept below Cloudflare's 10,000 subrequests per invocation (paid plans); keep it under a quarter of `limits.subrequests` if you raise either. |
| `STAGING_FAILURE_RATE_LIMIT` | `30` | Failed `/staging/*` requests per client per window before 429. |
| `STAGING_FAILURE_RATE_LIMIT_WINDOW_SECONDS` | `300` | Window for the staging failure throttle. |

**Behaviour changes.**

- Gmail filters whose actions add the `TRASH` or `SPAM` label (Gmail's
  "Delete it" and "Mark as spam") now need interactive approval, so
  they fail closed on clients without elicitation support.
- Gmail filter `action` keys outside the known set (`addLabelIds`,
  `removeLabelIds`, `forward`, `forwardingEmail` and their snake_case
  forms) are denied (`filter-unknown-action-field`), so
  `action.delete: true` is still refused.
- Calendar attendees flagged `resource: true` skip the recipient
  allowlist only when their address is at
  `resource.calendar.google.com`.
- Calendar event writes (`insert`, `update`, `patch`, `import`) must
  send the event as a JSON object in `body`; a raw or multipart
  payload is denied (`event-body-not-object`).
- Outbound mail with more than one `To`, `Cc` or `Bcc` header is
  denied (`duplicate-recipient-header`). In the header block, CRLF is
  read as LF; a lone CR, or CRLF mixed with bare LF, is denied
  (`ambiguous-line-ending`), and so is a header name that is not RFC
  5322 ftext (`malformed-header-name`). Addresses containing two `@`,
  quoted or commented address forms (including common quoted display
  names such as `"Jane Doe" <jane@example>`) and display names
  holding `@`, `:`, `;`, `,`, `[`, `]` or `\` are refused by the
  allowlist; write recipients as `addr@host` or `Name <addr@host>`.
- Xero inspectors read gated keys (`Status`, `SentToContact`,
  `IsReconciled`, `Type`, ids and wrappers) case-insensitively, deny
  two casings of one key, and treat any gated boolean other than
  absent, `null` or `false` as set.
- Upstream redirects are not followed: a 3xx response (other than 304)
  becomes an `upstream_redirect` error.
- `codemode.request` rejects typed arrays (`Uint8Array`, `ArrayBuffer`)
  in `body`, `query` and `multipart`; send bytes with `bodyBase64` or
  `multipart[].bodyBase64`. A non-string `contentType` is refused, and
  edge whitespace is trimmed from it.
- Path parameters that are `.`/`..` (or decode to dots only), or that
  contain a raw `\`, `?` or `#`, an encoded `/` or `\`, or a control
  character, are refused. An encoded `?` or `#` (`%3F`, `%23`) is
  accepted and re-encoded, so Calendar ids and file names containing
  `#` keep working.
- On operations that are inspected or need approval, a request using
  more than one of `body`, `bodyBase64` and `multipart` is denied
  (`multiple-body-channels`). Bytes sent under a JSON content-type
  (including `text/json` and `application/x-json`) must parse
  (`unparseable-json-body` otherwise) and are judged, shown and sent as
  that parsed JSON. An approval for a raw non-JSON or multipart payload
  that no inspector reads says its body cannot be shown.
- Each sandbox run may make at most `EXECUTE_MAX_UPSTREAM_CALLS`
  upstream calls (1,000 by default); split bulk work across runs.
- The `search` tool is read-only: its sandbox no longer receives
  `__stagingHost` and it carries `readOnlyHint: true`.
- Refresh failures read `Refresh failed <status> (<error>)` with no
  upstream body.

### Gmail sends and Calendar writes (2026-11 review)

A 2026-11 security review found that Gmail send paths could be judged on
a decoy part of the request and that Calendar writes could carry mailbox
content to outsiders. Operator detail is in
[`packages/scaffold/SECURITY.md`](./packages/scaffold/SECURITY.md) §7.10.

**New var** (Gmail app only):

| Variable | Default | Purpose |
|---|---|---|
| `CALENDAR_WRITE_ALLOWLIST` | unset: every Calendar event write is denied | Comma-separated calendar ids the agent may write events to. Set it to `primary` (the user's own calendar, which is never implied), optionally the user's own address as well, plus the ids of any secondary calendars the user owns (`c_…@group.calendar.google.com`). Entries are matched exactly, ignoring case. A calendar id with surrounding whitespace or any character outside printable ASCII never matches. An entry that is not `primary` or a plain ASCII `addr@host`-shaped id (`*@domain` included) makes every event write fail (denied as `inspector-threw`). Reads are unaffected. |

The committed `apps/gmail/wrangler.jsonc` sets it to `primary` for all
three deployments (prod, `dev`, `tester`). The var takes effect on the
next deploy; `scripts/upgrade/2026-11-10-calendar-write-allowlist.sh`
checks the config and redeploys `gmail-dev`, `gmail-tester` and `gmail`
in that order (`--dry-run` prints the commands, `--env-only=<name>` picks
one). A deployment redeployed without the var denies every Calendar event
write.

**Behaviour changes.**

- `messages.send` reads the message from `raw` only (base64url RFC
  822, in a JSON body). A body with `payload`, `message` or any top-level
  key other than `raw`, `threadId` and `labelIds` is denied
  (`send-unexpected-key`), as is a missing or empty `raw` or a non-JSON
  body (`send-no-raw`; upload bytes through `messages.send.media`).
  Bodies that used to send `payload.headers` now fail; send `raw`.
- `drafts.send` must carry the full message as
  `{ id, message: { raw } }`, and `message.raw` is the only part judged.
  A `payload`, or a key inside `message` other than `raw`, `threadId`,
  `labelIds` and `id`, is denied. Sending by id alone stays denied.
  This relies on Gmail replacing the stored draft with `message.raw`
  before sending; see the residual risks below.
- `messages.import` reads `raw` only too: a non-object body, a
  `payload` or other unknown key, a header block with ambiguous line
  endings or a malformed header name, or a repeated `From`, `To`,
  `Subject` or `Date` header (`duplicate-summary-header`) is denied
  before approval is asked. The approval dialog now shows the message's
  `From`, `To`, `Subject` and `Date`.
- Calendar event writes (`insert`, `update`, `patch`, `import`, `move`)
  are allowed only on calendars listed in `CALENDAR_WRITE_ALLOWLIST`
  (`calendar-not-allowlisted` otherwise). Use `primary` for the user's
  own calendar.
- `events.update` and `events.patch` first read the stored event. An
  event the user does not organise is denied
  (`event-not-organised-by-user`), because a guest's edit propagates to
  the organiser's copy. An event the user organises that already has
  guests off `OUTBOUND_RECIPIENT_ALLOWLIST` needs interactive approval
  (`event-has-external-guests`), which is a deny on Claude.ai; add those
  guests to the outbound allowlist to lift it. A stored guest entry
  without a readable address counts as outside. A missing event
  (`event-not-found`), a read that returns any other non-2xx status
  (`event-read-failed`), or an event whose guest list Google truncated
  (`event-attendees-omitted`) is denied.
- One exception keeps RSVPs working: `events.patch` on someone else's
  event is allowed, without a dialog, when the body is only `attendees`,
  identical to the stored list (same entries, same order) except that
  the user's own entry may differ in `responseStatus`, which must be
  `accepted`, `declined`, `tentative` or `needsAction`. The user's own
  entry is the single stored entry marked `self: true` or carrying the
  address of an event creator marked `self`; if there is not exactly
  one, the RSVP is denied. A `comment` or `additionalGuests` on that
  entry (even unchanged), an added, removed, reordered or edited guest,
  or any other field is denied, as is an RSVP on an event whose guest
  list Google truncated. `events.update` on someone else's event stays
  denied.
- An Out of office or Focus time event carrying a `declineMessage` is
  denied (`event-decline-message`): Calendar emails that text to the
  organiser of every conflicting invitation.
- `events.move` takes no body and needs a `destination`; both the
  event's calendar and `destination` must be on the calendar allow-list.
- `events.quickAdd` is denied; use `events.insert` with structured
  fields.
- Approval dialogs for calendar writes show the calendar and event ids
  from the path, then, as available: the attendee count and the first
  three attendees (a mass invite), the guests off the outbound allowlist
  (`event-has-external-guests`), the organiser, the fields the write
  changes (`changes`, update/patch only), title, start and end.
  On `events.import` the organiser, title and times are the ones in the
  request body. On `events.update` and `events.patch` the organiser and
  guests are the stored event's, as read before the edit (who is
  affected); the title, start and end are the ones the write sets, or
  the stored ones when it does not set them; and `changes` lists the
  body's top-level fields (e.g. `description, summary`), so a write that
  fills the description shows that it does. `events.insert` shows the
  body's title and times but no organiser (Calendar sets it).
  Text values are shown as quoted strings. Subjects and event titles
  are no longer cut at 200 characters by the inspectors; the dialog
  marks any truncation with `…`.
- When an `events.update` or `events.patch` reads the stored event, it
  writes two audit lines: the read (`calendar.events.get`, `allow`, with
  `upstreamStatus`), then the write's decision. If the read cannot be
  made or fails in transport, the write is denied with
  `upstream-inspect-failed`.
- A malformed `CALENDAR_WRITE_ALLOWLIST` or `OUTBOUND_RECIPIENT_ALLOWLIST`
  entry makes the request's inspector throw; the request is denied as
  `inspector-threw` (category `malformed`, audited) and the error the
  model sees does not quote the config entry. An inspector that returns
  something other than an inspect result (e.g. `{}` or a Promise) is
  denied as `inspector-invalid-result`.

**Residual risks.**

- `drafts.send` with `{ id, message: { raw } }` depends on Gmail
  replacing the stored draft's content with `message.raw` before it
  sends, and on a concurrent `drafts.update` of the same draft (which is
  uninspected) not winning the race against that send. Neither has been
  checked against live Gmail. The operator should check it once in the
  dev deployment, with two addresses of their own: store a draft to A,
  send it with `{ id, message: { raw: <To: B> } }`, and confirm that B
  and only B receives it. If it fails, `drafts.send` should become a
  static deny.
- The RSVP exception lets the agent signal the organiser of someone
  else's event: each `events.patch` can set one of four response
  statuses, about 2 bits per patch, and Calendar notifies the
  organiser. This was accepted to keep RSVPs working.

### Xero writes (2026-11 review)

The same review found that Xero contact edits could repoint a supplier's
bank account with no approval, that posted invoices and credit notes
could be edited by leaving out `Status`, that repeating-invoice
templates skipped every invoice rule, and that any file could be
published on a customer's online invoice. Operator detail is in
[`packages/scaffold/SECURITY.md`](./packages/scaffold/SECURITY.md) §7.11.
No new var; the change takes effect on the next deploy of the Xero app.

**Behaviour changes.**

- Contact creates (no `ContactID` or `ContactNumber`) stay allowed with
  any fields. A contact edit carrying `BankAccountDetails`,
  `BatchPayments`, `EmailAddress`, `ContactStatus`, `TaxNumber` or
  `ContactPersons`, or one that changes `Name` or `XeroNetworkKey`,
  now needs interactive approval: the stored contact is read first and
  the dialog shows the old and new value of each field. On Claude.ai,
  which cannot elicit, these edits (renames included) are denied. Other
  edits (address, phones, defaults) are allowed as before.
- Such an edit must be the only contact in its request, may carry at
  most 3 `ContactPersons`, and each value must fit the dialog (old and
  new text together at most 200 characters). Any edit carrying `Name` or
  `XeroNetworkKey` costs one extra Xero GET, even when the name is
  unchanged. Nothing may sit beside the `Contacts` array
  (`contact-unexpected-key`). By-id `updateContact`, contact groups,
  contact history and contact attachments stay unavailable.
- Invoice and credit-note writes need an explicit `Status` of `DRAFT` or
  `SUBMITTED` on every item (`invoice-status-required` /
  `creditnote-status-required`); omitting it is no longer read as "keep
  the current status". Every item with an id is read from Xero first
  and refused unless the stored document is a draft or submitted
  (`*-not-draft-upstream`). An item with an `InvoiceNumber` / `CreditNoteNumber` and no
  id is read by number first; if a posted document has that number,
  it is refused (a supplier bill whose reference equals a posted
  bill's number included). At most four items carrying an id or a
  number per request (each is read first, numbered creates included).
  On the by-id endpoints the body id must
  equal the path id and the body takes one item.
- An inline `Contact` on an invoice, credit note or repeating invoice
  may not carry bank, batch-payment, email, status, tax-number or
  contact-person details (`*-inline-contact-details`); reference the
  contact by `ContactID` and change it through `/Contacts`.
- Repeating-invoice templates can only be created and edited as
  `DRAFT`, without `ApprovedForSending`, `SendCopy`, `MarkAsSent` or
  `IncludePDF`; an existing template is read first and must itself be
  a draft. Approving a template for sending is done in Xero.
- Invoice and credit-note attachment uploads (the `PUT`s) are
  inspected again: `IncludeOnline` is denied
  (`attachment-include-online`), the body must be the file's bytes with
  an accepted MIME type, at most 25 MiB. Composed staged uploads are
  accepted. Uploads through the Files API (`xero.files.uploadFile`) are
  unchanged.
- Replacing an existing attachment's bytes (`POST
  /Invoices/{id}/Attachments/{name}` and the credit-note twin,
  `update*AttachmentByFileName`) is no longer available (`not in
  surface review`): it could overwrite a file already shown on the
  customer's online invoice, and the request cannot carry, so cannot
  check or reset, `IncludeOnline`. Upload the new version under a new
  file name with the `PUT`.
- Each stored read is one extra Xero API call with its own audit line
  (`allow`, the GET's operation) before the write's.

**Residual risks.** Not yet checked against live Xero: that `GET
/Invoices/{number}` and `GET /CreditNotes/{number}` find a document by
number (the numbered-create read relies on it), and that Xero does not
update an existing contact matched by `Name` on a create. Also
unchecked: whether Xero keeps an attachment's `IncludeOnline` when its
bytes are replaced; if it resets it, the attachment-update `POST`s could
be offered again later. The review's
live checks for repeating invoices (an AUTHORISED, approved-for-sending
template) and posted invoices (an update with no `Status`) are left to
the operator; the fixes do not depend on them. Creates stay open, so a
lookalike contact can be created with any bank details; paying or
billing it is gated elsewhere.

### Staging ownership and the audit trail (2026-11 review)

The same review found that a staged file could be read or sent by any
session holding its `{ file_handle, token }`, that its public download
could be replayed, that staging left no audit line, that sandbox code
could print lines indistinguishable from `AUDIT` lines, and that several
refusals and failed sends were not audited. Operator detail is in
[`packages/scaffold/SECURITY.md`](./packages/scaffold/SECURITY.md) §7.12.
Nothing here asks for approval, so Claude.ai (which cannot elicit)
behaves the same as other clients.

**New optional vars** (positive integers; omit for the default):

| Variable | Default | Purpose |
|---|---|---|
| `STAGING_FETCH_MAX_USES` | `5` | Public `/staging/fetch` downloads allowed per staged file within `STAGING_FETCH_TTL_SECONDS`. There is no unlimited setting; `0` or a non-integer is a configuration error. A strict deployment can set `1` with a short `STAGING_FETCH_TTL_SECONDS`. |
| `EXECUTE_MAX_DENIED_CALLS` | `32` | Refused calls one sandbox run may make (a `codemode.request` or staging call that rejects, or a staging call answering `ok: false`). Past it, every further call from that run is refused with "too many refused requests in this execution" and one `denial-budget-exceeded` audit line. |

**Upgrading.** Migration `0003_owner.sql` adds `owner` and `fetch_count`
to the staging table and must be applied to each deployment's remote
`STAGING_D1` before its new code goes live: new code on an unmigrated
database refuses every store with 500 ("d1 insert failed").
`scripts/upgrade/2026-11-11-staging-owner.sh` checks the migration and
the `migrations_dir` bindings, then migrates and deploys `gmail-dev`,
`gmail-tester`, `gmail`, `xero-dev` and `xero` in that order
(`--dry-run` prints the commands, `--env-only=<name>` picks one). The
optical app has no staging table and needs only its ordinary deploy.

**Behaviour changes.**

- Every staged file belongs to the user (the audit principal, the OAuth
  `sub`) whose session created it: `register_file_handle`, `putFile`,
  `returnAs: "stage"` and `stageFromUpstreamJson` record it. `getFile`
  and `composed` / `multipart[].staged` sends work only in that user's
  sessions; anyone else gets the same 403 "file not found or not yours"
  as a wrong token. The same user can keep reusing a reference in later
  turns until it expires.
- A session without a principal gets no `__stagingHost` and no
  `register_file_handle` tool.
- The public `fetch_url` works up to `STAGING_FETCH_MAX_USES` times
  (default 5) within `STAGING_FETCH_TTL_SECONDS`. Each `GET` is counted
  before any bytes are read, so a download that fails part-way still
  uses one; past the limit a `GET` is 410 `gone`; re-stage the file to
  download it again. The 410 does not count against the staging failure
  throttle. In-MCP use by the owner (`getFile`, staged sends) is not
  counted.
- Files staged before the migration have no owner and are refused by
  every reader (403; bare `forbidden` on `/staging/fetch`) until they
  expire, at most `STAGING_FETCH_TTL_SECONDS` (default one hour) after
  the deploy. Re-stage them.
- Staging is audited: one line per register, upload, store, read,
  attach refusal and download, with `operationId: "staging.<event>"`
  and a `staging` object (`event`, `fileRef`, `byteLength`, `status`).
  `fileRef` is a 12-hex digest of the file handle that ties together the
  lines of one file; handles and tokens still never appear. A successful
  `putFile` also returns `file_ref`. Host-assembled sends list the
  attached files' `fileRef`s in `stagedRefs`.
- `getFile` and `putFile` now count against `EXECUTE_MAX_UPSTREAM_CALLS`,
  like `stageFromUpstreamJson` and `stageFromAttachment`.
- Audit fields that sandbox code controls are capped: `method` 32 code
  points, `path` 1024 (with `pathLength` when cut), `reason` 128,
  `category` 64, `operationId` 256; a cut value ends in `…`. A request
  whose `method` is over 32 or whose `path` is over 4096 code points is
  refused (`oversize-method-or-path`) before matching.
- `codemode.request` `headers` are checked at entry, before any token
  mint or approval: at most 32, each name an RFC 7230 token of at most
  256 characters, each value a string of at most 4096 characters with
  no CR, LF, NUL or character above U+00FF. Credential and
  project-attribution headers (`X-Goog-Api-Key`, `X-Goog-User-Project`,
  `X-Goog-AuthUser`, `X-Goog-IAM-Authorization-Token`,
  `X-Goog-IAM-Authority-Selector`, `X-API-Key`, `API-Key`,
  `X-Auth-Token`) join the refused set. Every header refusal is audited
  by reason only; a name the runtime would reject is now a clean error
  instead of a raw `TypeError`.
- A host-assembled send writes an extra `allow` line with
  `phase: "dispatch"` before the body goes out; consumers counting one
  line per request should skip it. A request whose send or response
  handling fails writes an `allow` line with `outcome: "failed"` and a
  fixed `reason` (`transfer-aborted`, `transfer-timeout`,
  `upstream-request-failed`, ...). Refusals that used to leave no line
  (`staging-not-configured`, `raw-body-not-string`, `no-principal`,
  `token-mint-failed`, URL build failures) are now audited.
- Sandbox `console.info`, `console.debug`, `console.table` and every
  other console method are captured with `console.log` into the run's
  logs; nothing the sandbox prints reaches the Worker's log stream.
  Code that is not valid JavaScript is refused ("code is not valid
  JavaScript", audited as `code-not-parseable`).

**Live checks left to the operator** (SECURITY.md §7.12): on a dev
Worker, run `console.info("AUDIT {…}")` from `execute` and confirm that
Workers Logs show nothing; and, with `EXECUTE_MAX_DENIED_CALLS`
temporarily raised to 400, send about 300 refused requests with ~1 KB
paths plus one allowed one in a single run and check that the allowed
request's line is still logged (whether the platform's log cap applies
per invocation).

### OAuth public legs and the release changelog (2026-11 review)

The same review found that the consent page did not warn on a flow
someone else had started through a known client, that a `/callback`
refused for the wrong browser stayed redeemable from its address, that
`/authorize` and `/callback` were unthrottled and read any request body
whole, that the five-minute client sweep turned junk registrations into
a recurring KV read bill and dropped legitimate clients as soon as their
grant lapsed, and that the public release changelog printed the subjects
of private commits. Operator detail is in
[`packages/scaffold/SECURITY.md`](./packages/scaffold/SECURITY.md) §7.13.
Nothing here asks for approval, so Claude.ai behaves the same as other
clients.

**New optional vars** (positive integers; omit for the default):

| Variable | Default | Purpose |
|---|---|---|
| `OAUTH_AUTHORIZE_RATE_LIMIT` | `30` | `GET`/`HEAD`/`POST /authorize` requests per client IP per window before 429. A connection is one of each. |
| `OAUTH_AUTHORIZE_RATE_LIMIT_WINDOW_SECONDS` | `300` | Window for the `/authorize` limit. |
| `OAUTH_CALLBACK_RATE_LIMIT` | `10` | `GET`/`HEAD /callback` requests per client IP per window before 429 (each one costs an upstream token call). |
| `OAUTH_CALLBACK_RATE_LIMIT_WINDOW_SECONDS` | `300` | Window for the `/callback` limit. |

**Changed meaning of `OAUTH_CLIENT_TTL_SECONDS`** (default `2592000`,
30 days; the apps' `wrangler.jsonc` files are unchanged): it is now the
KV TTL on a client registration that has not been used, and the grace a
client keeps after its grant's 90-day lifetime. A successful token
exchange or refresh renews the client record to 90 + 30 = 120 days.
Values under 60 are raised to 60, KV's minimum TTL. There is no sweep
any more; the cron trigger stays for the staging sweep.

**Behaviour changes.**

- Every consent page carries the "only approve if you started this
  connection yourself" box; the `Warning:` sentence now appears for any
  `claude.ai` / `claude.com` redirect other than `/api/mcp/auth_callback`
  (including one with a port or query) and for any loopback path other
  than `/callback` or `/oauth/callback`. Claude.ai, Claude desktop and
  mobile, Claude Code and MCP Inspector are unaffected.
- A `/callback` opened in a browser other than the one that approved
  the page cancels that sign-in for everyone ("… Do not share this
  page's address with anyone."); the approving browser then sees "State
  expired or invalid" and restarts. A shared callback address no longer
  completes a sign-in for whoever holds the matching cookie.
- `/authorize` and `/callback` answer 429 with `Retry-After` past the
  limits above, per client IP (IPv6 per /64). A percent-encoded alias
  of either path (`/%61uthorize`) counts against the same limit, and a
  path with a malformed escape (`%ZZ`) is refused 400 "Malformed
  request path" on every path the worker serves except `/staging/*`
  (`/mcp` included).
- Request bodies over 1 MiB (`POST /register`) or 16 KiB
  (`POST /authorize`, `POST /token`) are refused 413 before they are
  read.
- A connector not used for 120 days must be removed and re-added in
  the MCP client (the client record has expired, so the next
  `/authorize` fails with "Invalid client"). Until this change the same
  happened to any connector within five minutes of its grant lapsing,
  that is after 90 days.
- The release changelog lists only commits that touch a path shipped
  to the public mirror, and the release aborts (rather than printing
  the subject) when a surviving subject matches a leak pattern.

**Upgrading.** Run `scripts/upgrade/2026-11-11-oauth-client-ttl.sh`
after merging (dev first; `--dry-run` prints every command,
`--env-only=<name>` picks one deployment). It deploys the new code,
then gives every existing `client:` record without an expiry the
120-day TTL (one `wrangler kv bulk put` per deployment) and deletes
the orphaned `clientreg:` stamps. Until it runs, client records from
before this change never expire.

**Checks left to the operator.**

- Before deploying, confirm the live Claude.ai client's registered
  redirect URI (KV `client:<id>` → `redirectUris`) is
  `https://claude.ai/api/mcp/auth_callback` or
  `https://claude.com/api/mcp/auth_callback`; if it differs, add the
  exact URI to `KNOWN_REDIRECT_URIS` in
  `packages/scaffold/src/oauth-consent.ts`. A miss costs a warning on
  the consent page, not a refusal.
- How Claude.ai reacts to `invalid_client` after 120 idle days
  (re-register silently, or require remove-and-re-add) is unverified;
  both are acceptable.

## Staged file transfer v2 (issue #59)

Staged files now reach upstream APIs by reference: sandbox code passes
`{ file_handle, token }` in `codemode.request`'s `composed.segments` or a
`multipart[].staged` part, and the host decrypts, encodes and streams
the bytes into the outbound body itself. File bytes no longer cross the
sandbox boundary, and files up to `STAGING_MAX_BYTES` (50 MiB) are
sent without holding more than a few MiB at once. The operator detail
(at-rest format, caps, transfer gate, log fields) is in
[`packages/scaffold/SECURITY.md`](./packages/scaffold/SECURITY.md) §7.8.

**New optional vars** (all positive integers; omit for the default):

| Variable | Default | Purpose |
|---|---|---|
| `STAGING_COMPOSE_MAX_BYTES` | `75497472` (72 MiB) | Largest host-assembled request body (`composed` or staged multipart). |
| `STAGING_GETFILE_MAX_BYTES` | `8388608` (8 MiB) | Largest file `__stagingHost.getFile` returns; also the size limit for reading files staged before this release. |
| `STAGING_MAX_CONCURRENT_TRANSFERS` | `2` | Staged transfers running at once per isolate. Lower it to `1` if Workers Logs show `exceededMemory`. |
| `STAGING_TRANSFER_TIMEOUT_MS` | `60000` | Absolute timeout for one staged transfer. |

**Behaviour changes.**

- `__stagingHost.getFile` is for reading small files in sandbox code
  (parse a CSV, read a PDF's text). Files over
  `STAGING_GETFILE_MAX_BYTES` get a 413 telling the model to send by
  reference instead.
- Gmail sends and saves mail with attachments through three media
  operations on `/upload/gmail/v1/…` (`messages.send.media`,
  `drafts.create.media`, `drafts.update.media`; `uploadType=media`,
  `message/rfc822`). Send is inspected as before, plus a 35 MiB cap,
  and its approval dialog lists the attachment names. `composed` on the
  JSON `messages.send` is refused (`staged-not-supported`).
- Xero's attachment hints send by reference and state Xero's 10 MB
  request ceiling.
- Each execution may run one staged transfer at a time with one more
  waiting (await each before starting the next); a busy server answers
  "retry shortly".

**Upgrading.** Migration `0002_enc_version.sql` must be applied to each
deployment's remote `STAGING_D1` before its new code goes live (wrangler
does not apply D1 migrations on deploy).
`scripts/upgrade/2026-10-15-staging-v2.sh` applies it and deploys, one
deployment at a time; see [`infra/README.md`](./infra/README.md).
Before upgrading from v1.1.0 or earlier, wait until every file staged
by the old version has expired: at most `STAGING_FETCH_TTL_SECONDS`
(default 3600, one hour) after the last file was uploaded or staged.
Files staged by older versions are refused with 410 ("stored in a legacy
format; re-stage the file") and must be staged again. For a
live check after upgrading a dev deployment, run the drafts-only
staging ladder in
[`scripts/harnesses/README.md`](./scripts/harnesses/README.md).

## Adding a new provider

1. Create `packages/providers/<name>/` mirroring `gmail`, `xero`, or `optical`:
   `index.ts` (the `ApiProvider` value), `surface-review.ts`, `spec.json`,
   `elicit-renderers.ts`.
2. Add a spec loader under `packages/spec-loaders/` if the spec needs
   transformation.
3. Add an app under `apps/<deployment>/` with `wrangler.jsonc`,
   `package.json`, and a four-line `src/index.ts`.
4. Add a `module "<name>"` block to `infra/main.tf` and corresponding
   outputs to `infra/outputs.tf` (OpenTofu reads the same `.tf` files).
5. Run `pnpm install` (workspace re-link), `pnpm typecheck`, deploy as
   above.

## Where to look next

- `docs/cloudflare-getting-started.md` — onboarding for Cloudflare newcomers.
- `apps/xero/README.md` — worked example of per-app setup.
- `apps/optical/README.md` — Optical setup against your own Optical deployment.
- `infra/README.md` — OpenTofu stack detail.
- `packages/scaffold/SECURITY.md` — security model + the audit/redaction defaults.
