# Local integration harnesses

Operator-runnable harnesses for the security-review remediations on this
branch. They drive `wrangler dev` plus a real MCP client to exercise the
parts that unit tests can't reach: the actual OAuth/PKCE round-trip, the
audit-log emission shape under both `ALLOW_PII_IN_LOGS` settings, and the
boot-time `COOKIE_ENCRYPTION_KEY` assertion.

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
   COOKIE_ENCRYPTION_KEY=...            # >=32 chars; openssl rand -base64 32
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
  the browser to the worker's `/authorize` URL (which then redirects to
  Google with `code_challenge` + `code_challenge_method=S256`).
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

## Token cache

```
~/.codemode-mcp/mcp-token.json
```

Stores `tokens`, `clientInformation`, and (transient) `codeVerifier`
between PKCE / audit runs. Delete to force a fresh OAuth dance. Mode is
`0600`.

## Out-of-scope for these harnesses

These harnesses do **not** cover:

- Refresh-token rotation / token-endpoint failure modes.
- The `xero` provider (`apps/xero/`).
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
