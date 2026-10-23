# Local integration harnesses

Operator-runnable harnesses for the security-review remediations on this
branch. They drive `wrangler dev` plus a real MCP client to exercise the
parts that unit tests can't reach: the actual OAuth/PKCE round-trip, the
audit-log emission shape under both `ALLOW_PII_IN_LOGS` settings, and the
boot-time `COOKIE_ENCRYPTION_KEY` assertion. The key is no longer only
asserted: since the 2026-10-07 security review it signs the `/authorize`
consent form tokens, so a missing or short key also breaks sign-in.

The harnesses are **not** run in CI. They require operator-supplied
credentials and a browser. Use them when you want a live check before a
deploy, or when you're verifying a change to one of the affected code
paths.

## Prerequisites

1. **wrangler v3 or v4** on `PATH` (the workspace pins
   `wrangler ^4.87.0` in `apps/gmail/package.json`).
2. **A Google Cloud OAuth client** with
   `http://localhost:8787/callback` in its authorized redirect URIs.
3. **`apps/gmail/.dev.vars`** populated with three values:

   ```
   GOOGLE_CLIENT_ID=...
   GOOGLE_CLIENT_SECRET=...
   COOKIE_ENCRYPTION_KEY=...            # >=32 chars; signs the consent form; openssl rand -base64 32
   ```

4. **`pnpm install`** at the repo root has been run at least once. The
   harnesses load `tsx` from devDependencies.

## PKCE check

```
pnpm harness:mcp --check=pkce
```

What happens:

- The harness spawns `pnpm wrangler dev` inside `apps/gmail/`.
- It starts a localhost callback listener on a random high port and
  constructs an MCP client backed by
  `@modelcontextprotocol/sdk`'s `StreamableHTTPClientTransport` with a
  custom `OAuthClientProvider`.
- When the MCP transport throws `UnauthorizedError`, the harness opens
  the browser to the worker's `/authorize` URL. The worker shows its
  consent page (client name, redirect URI, scopes); click **Approve**
  within five minutes, and the worker then redirects to Google with
  `code_challenge` + `code_challenge_method=S256`. The consent and
  browser-binding cookies are `__Host-` (Secure) cookies, so use a
  browser that treats `http://localhost` as a secure context (current
  Chrome and Firefox do); otherwise the approval is refused as expired.
- The harness's own client registers a loopback `http://` redirect URI
  and sends PKCE S256, which `/register` and `/authorize` now require.
- After you complete consent, Google redirects back to
  `http://localhost:8787/callback`, which exchanges the code (with the
  PKCE `code_verifier` from the KV state envelope) for tokens.
- The browser is finally redirected to the harness's local callback
  port; the harness completes the MCP-level OAuth flow, calls
  `initialize` (implicit in `connect()`), then `listTools()`.

PASS criteria: at least one tool is returned by `listTools` — meaning
both the MCP-client↔worker PKCE *and* the worker↔Google PKCE round-trips
succeeded.

Token cache: the OAuth tokens land in
`~/.codemode-mcp/mcp-token.json` so subsequent runs skip the browser
step until the access token expires. Delete that file to force a fresh
dance.

## Audit-redacted check (default)

```
pnpm harness:mcp --check=audit-redacted
```

or equivalently:

```
pnpm harness:mcp
```

What happens:

- Spawns wrangler dev with no extra var overrides. `wrangler.jsonc`
  ships `ALLOW_PII_IN_LOGS: "false"` so the redaction default applies.
- Reuses the token cache, or runs the OAuth dance if no token is
  available.
- Calls the `execute` tool with a payload that runs
  `codemode.request({method: "POST", path: "/gmail/v1/users/me/messages/send", body: {raw}})`.
  The `raw` payload is a base64url RFC 822 message addressed to 26
  recipients on the outbound allowlist (`*@example.com`),
  which triggers the mass-send inspector (`MASS_SEND_THRESHOLD = 25`).
- The client's `ElicitRequestSchema` handler returns
  `{action: "decline"}` — so no mail is actually sent. The decline
  still triggers the audit emission with `elicitFields` populated.
- The harness scans wrangler-dev stdout for an `AUDIT {…}` line whose
  `operationId === "gmail.users.messages.send"`.

PASS asserts:

- `elicitFields.__redacted__ === true`
- `elicitFields.keys` contains `"recipients"` and `"subject"`
- Raw `recipients` / `subject` strings are absent
- `elicitFields.countValue === 0` (the inspector's `count` number is
  collapsed to 0 by `redactAuditEntry`)

## Audit-raw check

```
pnpm harness:mcp --check=audit-raw
```

Same flow as `audit-redacted`, but the harness spawns wrangler dev with
`--var ALLOW_PII_IN_LOGS:true` so the redaction is bypassed. PASS
asserts the raw `recipients` (string), `subject` (string,
`"harness-mass-send"`), and `count` (number, `26`) survive into the
audit line. No manual `wrangler.jsonc` edit is required.

## Cookie-absence check (I4)

```
pnpm harness:cookie
```

What happens:

- If `apps/gmail/.dev.vars` exists, the harness copies it to
  `/tmp/codemode-harness-<pid>/.dev.vars.backup` and rewrites the
  original with every `COOKIE_ENCRYPTION_KEY=…` line removed. If
  `.dev.vars` doesn't exist, the harness simply spawns wrangler dev
  with `COOKIE_ENCRYPTION_KEY` stripped from the inherited environment.
- Spawns wrangler dev and waits for either "Ready on" *or* a startup
  failure whose log mentions `COOKIE_ENCRYPTION_KEY` + `wrangler secret
  put` (the actionable message). Either is a PASS.
- On the happy-startup path, the harness issues `GET /` against the
  worker. Expected behaviour: the wrapped `fetch` in `setup-provider.ts`
  calls `assertSecrets(env)`, which throws, which becomes a 500
  response whose body contains both `COOKIE_ENCRYPTION_KEY` and
  `wrangler secret put`.
- On exit (including SIGINT / SIGTERM) the harness restores
  `.dev.vars` from the backup and removes the backup directory.

PASS asserts the 500 status and the two substrings.

If the harness crashes mid-run and the restore step doesn't fire, you
can recover with:

```
cp /tmp/codemode-harness-<pid>/.dev.vars.backup apps/gmail/.dev.vars
```

The backup path is printed to stderr at the start of each run.

## Generic execute check

```
pnpm harness:mcp --check=execute --code-file=/path/to/code.js --no-spawn --target=https://<server>
```

Runs the async arrow function in `--code-file` through the server's
`execute` tool and prints the raw tool result (per-call timeout 180 s by
default, `--timeout-ms=<n>` to change it). Without `--no-spawn` it
spawns `wrangler dev` in `apps/gmail/` first. `connectWithOAuth` and
`callExecute` are exported from `mcp-client.ts`, and importing the module
does not start its CLI, so other harnesses can reuse the OAuth client.

All harness HTTP, both the MCP transport (including its OAuth calls) and the
ladder's uploads and downloads, goes through `undici@7.24.8`'s `fetch`
(a pinned root devDependency), not Node's built-in one. On Node 26 the
built-in fetch never sends the `tools/call` POST while the SDK's standalone
GET SSE stream is open, so every `execute` call times out.

## Staging ladder (staged transfer v2, issue #59)

```
pnpm exec tsx scripts/harnesses/staging-ladder.ts \
  --target=https://gmail-dev.<subdomain>.workers.dev
```

Options:

- `--sizes=1,4` runs only those rungs (in both the draft and round-trip
  ladders). Use it to re-run a small rung first. The denial probes and
  the final sweep still run.
- `--draft-bytes=25000000,26214400` adds draft rungs at exact byte sizes
  (subject `codemode staging ladder <n> B`, which the sweep also matches).
  Given without `--sizes`, only these draft rungs run: no MiB drafts and
  no round trip; the probes and the sweep still run. Timeouts use the
  size rounded up to whole MiB.
- `--sweep-only` runs nothing but the exact-subject draft sweep, for
  example to clear drafts left behind by an interrupted run.
- `--execute-timeout-ms=<n>` overrides the per-call `execute` timeout.
  The default is max(180 s, 8 s per MiB); the MCP SDK's own 60 s default
  is too short for large rungs. The timer resets whenever the server
  reports progress, but never beyond twice the timeout in total.

If the sweep row shows `failed>0` or a timeout, re-run with
`--sweep-only`. One `execute` call is bounded by the server's 75 s host
deadline, so a large backlog of leftover drafts may need more than one
pass.

Raw HTTP calls to `/staging/*` time out after max(120 s, 5 s per MiB),
covering the body as well as the headers. A stalled transfer fails its
row and the run moves on.

This is the live acceptance run for staged transfer v2. It runs against
a **deployed** Gmail server, normally `gmail-dev`, after
`scripts/upgrade/2026-10-15-staging-v2.sh --env-only=gmail-dev` has
applied the D1 migration and deployed. It reuses the cached MCP bearer
for that target, or runs the OAuth dance once.

**No email is sent.** The ladder works through drafts, and every
`execute` call passes a guard (`assertLadderCodeSafe`). The guard refuses
any code with a `/send` path unless it is one of the two denial probes
the ladder minted itself. It also refuses any email address outside the
reserved `.invalid` TLD. Ladder drafts carry no recipient, and
`drafts.send` is never called.

| Stage | Sizes | Steps | Pass condition |
|---|---|---|---|
| Drafts | 1, 4, 8, 16, 24 MiB | `register_file_handle` → upload → composed `drafts.create.media` → `drafts.get` → `stageFromUpstreamJson` of the attachment → download → `drafts.delete` | draft created (24 MiB in under 15 s); `sizeEstimate` ≈ assembled length; attachment `body.size` = F; re-staged bytes' SHA-256 equals the upload's; draft deleted |
| Round trip | 1, 8, 24, 50 MiB | upload → `GET /staging/fetch/<handle>` | SHA-256 equal |
| Inspector | 1 KiB | composed `messages.send.media` to `ladder-denial-probe@codemode-ladder.invalid`; the same with `uploadType=resumable` | each **denied with its own expected denial**: the generic "…messages.send.media is denied by surface review" (audit reason `external-send`), and "needs query { uploadType: \"media\" }" (`upload-type-not-media`). Any other error fails the row |
| Sweep | — | `drafts.list` for `subject:"codemode staging ladder"`, then delete each draft whose Subject is exactly a ladder subject | always runs last, even after a failure |

The ladder prints each row (size, path, ms, status) as soon as it
completes, then the full table at the end, and exits non-zero if any row
fails. Failed rows show the real elapsed time. Staging tokens and file handles are masked
(`stg_…`, `fh_…`) in everything it prints. The denial-probe recipient cannot receive
mail, so even a wrongly allowed probe reaches no one. A wrongly allowed
probe is still a failure, and you should stop the rollout. After the
run, check Workers Logs for `exceededMemory` within the printed time
window. The audit lines show each probe's deny reason.

Unit tests for the pure parts, including the no-send guard:

```
pnpm test:harness   # typechecks scripts/harnesses, then runs staging-ladder.test.ts and xero-ladder.test.ts
```

## Xero staging ladder (staged transfer v2, issue #59)

```
pnpm exec tsx scripts/harnesses/xero-ladder.ts \
  --target=https://xero-dev.<subdomain>.workers.dev
```

Runs against a **deployed** Xero server, normally `xero-dev`, which is
connected to Xero's "Demo Company". Run
`scripts/upgrade/2026-10-15-staging-v2.sh --env-only=xero-dev` first. The
harness reuses the cached MCP bearer for the target, or runs the OAuth
dance once. Pick only "Demo Company" on Xero's tenant screen.

Options:

- `--bytes=1048576,10240000` runs only these sizes, in bytes (1 to 50 MiB).
- `--only=attachments` or `--only=files` runs one target.
- `--execute-timeout-ms=<n>` works as in the staging ladder.

| Step | What runs | Pass condition |
|---|---|---|
| Setup | find the DRAFT invoice with Reference `codemode staging ladder (one attachment)`, or create it (and contact `codemode staging ladder`) as DRAFT | invoice id returned |
| Upload | `register_file_handle` → POST N printable bytes, as `codemode-ladder-<N>.txt`, `text/plain` | 204 |
| Attachment | `POST /api.xro/2.0/Invoices/{id}/Attachments/codemode-ladder.txt` with `composed` (one `identity` segment) | accepted when N < 10,240,000; a clean 4xx otherwise |
| Attachment back | `GET` the same path with `Accept: application/octet-stream` and `returnAs: "stage"` → `GET fetch_url` | SHA-256 equal |
| Files | `POST /files.xro/1.0/Files` with `multipart: [Name, { staged }]` | accepted when N < 10,239,000; a clean 4xx at N ≥ 10,240,000; either in between |
| File back | `GET /files.xro/1.0/Files/{id}/Content`, `returnAs: "stage"` → `GET fetch_url` | SHA-256 equal |
| Cleanup | `DELETE /files.xro/1.0/Files/{id}` | deleted, or denied by surface review (expected; see below) |

The default sizes are 1 MiB, 4 MiB, 10,000,000 B, 10,239,999 B,
10,240,000 B and 10 MiB + 1. A "clean" rejection is a 4xx from Xero, or a
refusal from our host that is not a timeout. A 5xx or a timeout fails the
row, and so does an over-limit upload that Xero accepts. Every `execute`
passes `assertXeroCodeSafe`, which refuses any status beyond DRAFT,
`SentToContact`, `/Email` and payment endpoints. Output masks `stg_…` and
`fh_…`, streams rows, prints the table again at the end, and exits non-zero
on any failure.

**What the ladder cannot clean up.** The xero-dev surface review allows
neither `xero.files.deleteFile` nor `deleteFolder` nor `uploadFileToFolder`
(none is listed, so all are denied), and the draft inspector denies
VOIDED and DELETED. Xero has no API to delete an attachment at all. So:

- one DRAFT invoice is reused across runs. Every rung POSTs the same
  attachment name, which overwrites it, so the invoice never reaches
  Xero's 10-attachment cap;
- each accepted Files upload stays in the Files Inbox as
  `codemode-ladder-<N>.txt`. Delete these in the Xero UI, or let the Demo
  Company reset clear them.

### Xero limits (checked 2026-10-15)

| Limit | Documented | Source |
|---|---|---|
| Request size, all APIs | "The maximum request size limit for all APIs is 10MB." Accounting/Payroll POSTs are kept to about 3.5 MB (~50 elements) for timely responses. | [OAuth 2.0 API limits](https://developer.xero.com/documentation/guides/oauth2/limits/) |
| Accounting attachments | "10 attachments can be uploaded per document (each up to 10mb in size)". POST to an existing `…/Attachments/{Filename}` replaces it. The body is the raw file bytes. | [Accounting API Attachments](https://developer.xero.com/documentation/api/accounting/attachments) |
| Invoice attachments | "up to 10 attachments (each up to 25mb in size) per invoice" (contradicts the line above; the API enforces the 10 MB request limit) | [Accounting API Invoices](https://developer.xero.com/documentation/api/accounting/invoices) |
| Files API upload | "The maximum file size that can be uploaded through the API is 10 MB." One file per request, multipart MIME; `POST /Files` (Inbox) or `/Files/{FolderId}`. | [Files API Files](https://developer.xero.com/documentation/api/files/files) |
| Downloads | No size limit is documented. Downloads are bounded by our `STAGING_MAX_BYTES` (50 MiB), and no Xero upload can be larger than 10 MB. | — |
| Rate limits | 5 concurrent calls, 60 calls/min per tenant, 5,000/day (1,000/day for Starter-tier apps), 10,000/min app-wide | [OAuth 2.0 API limits](https://developer.xero.com/documentation/guides/oauth2/limits/) |

**Measured on the Demo Company (xero-dev, 2026-10-15).** "10MB" turns out
to mean a request body below 10,240,000 B (10,000 KiB):

- An attachment of 10,239,999 B is accepted. One of 10,240,000 B gets a
  413 in about 3 s, with
  `{"Title":"RequestEntityTooLarge","Detail":"PayloadTooLarge",…}`.
- A Files API file of 10,239,000 B is accepted. One of 10,239,999 B gets
  the same 413, because the multipart framing counts toward the limit.
- At 10 MiB and above, both endpoints answer a bare 413 with no body,
  after about 30 s (a different layer in front of Xero).
- Xero refuses unknown extensions. On the Files API, `.bin` gets a 400:
  "Extension: … is not a valid File extension". On an invoice attachment,
  the same `.bin` gets a **500** "An error occurred in Xero". The ladder
  therefore sends `.txt`.

A full run makes about 30 Xero calls, well inside 60/min.

## Token cache

```
~/.codemode-mcp/mcp-token.json              # default target, localhost:8787
~/.codemode-mcp/mcp-token.<host>.json       # any other --target
```

Stores `tokens`, `clientInformation`, and (transient) `codeVerifier`
between runs, one file per target. Delete a file to force a fresh OAuth
dance for that target. Mode is `0600`.

## Out-of-scope for these harnesses

These harnesses do **not** cover:

- Refresh-token rotation / token-endpoint failure modes.
- The `xero` provider (`apps/xero/`), apart from the Xero staging ladder above.
- `DEBUG_ELICIT` marker toggling — that's a `wrangler tail` ad-hoc
  exercise documented in `packages/scaffold/SECURITY.md`.
- The H2 `smtpMsa` host-allowlist inspector (covered by unit tests; no
  upstream call required).
- The M3 origin-invariant URL builder (unit-tested in
  `packages/scaffold/src/__tests__/build-upstream-url.test.ts`).
- The H1 `redactAuditEntry` unit tests (covered in
  `packages/scaffold/src/__tests__/redact-audit.test.ts`).

The harnesses are the integration layer on top of those unit tests —
running them once after a code change confirms the full wiring still
holds.
