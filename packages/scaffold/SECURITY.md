# Operator security runbook

This is an operator runbook for the `@local/scaffold` package. It
describes where audit and debug log lines go, what the default
redaction posture looks like, how to deliberately unlock PII logging
when an incident calls for it, and how to inspect the OAuth state KV.
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

`OAUTH_KV` holds **transient sign-in state** under keys prefixed
`auth-state:<token>`. Each entry is written when a user hits
`/authorize` and is consumed (and deleted) when `/callback` exchanges
the resulting authorization code for tokens. TTL is **600 s** (10
minutes), so entries left behind from abandoned sign-ins drop out on
their own.

The stored envelope:

```json
{
  "oauthReqInfo": { /* the original /authorize request: clientId, scopes, redirect_uri, … */ },
  "codeVerifier": "<base64url>"
}
```

`codeVerifier` is the PKCE secret bound to one in-flight authorization
code; once `/callback` has redeemed that code the verifier has no
further value.

Inspect the namespace with the deployment's Cloudflare credentials:

```bash
npx wrangler kv:key list --binding=OAUTH_KV
npx wrangler kv:key get --binding=OAUTH_KV <key>
```

Useful when a sign-in is stuck mid-redirect (look for an unconsumed
`auth-state:` entry to see how far it got) or for post-incident
forensics on what flows were in progress.
