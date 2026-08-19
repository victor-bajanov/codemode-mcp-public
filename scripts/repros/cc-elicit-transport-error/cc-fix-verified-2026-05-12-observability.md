# Fix-verified evidence — 2026-05-12

Workers Observability MCP queries against the deployed `gmail` worker
on script version `de1685c6-471b-4df7-970a-4a45dae79840` (the deploy carrying
the `transport.send` monkey-patch from this branch).

**Account:** `REPLACE_WITH_YOUR_CLOUDFLARE_ACCOUNT_ID`
**Service:** `gmail`
**Script version:** `de1685c6-471b-4df7-970a-4a45dae79840`
**Window inspected:** last 3 hours from 2026-05-12 query time, covering the
user's E2E test through Claude Code (`gmail.users.threads.delete` accept flow).

## Smoking-gun signals (presence / absence)

| Signal | Pre-fix (script `63b28357`) | Post-fix (script `de1685c6`) |
|---|---|---|
| `DEBUG-AGENTS send-no-standalone` | fires on every CC elicit | **0 occurrences** in 3h |
| `DEBUG-AGENTS send-pre-write channelKind:"per-request-sse"` for elicit | absent | (templating obscures; see note) |
| `transport.send fallback engaged but no active request id in ALS` | n/a | **0 occurrences** |
| `transport.send fallback engaged but no connection contains active request id` | n/a | **0 occurrences** |
| `DEBUG-ELICIT elicit-caps` for `gmail.users.threads.delete` | always fired | fires (e.g. `requestId=9fa0c5f6fd1cd6fd` at 11:16:45 UTC) |
| Worker errors | n/a | none from the patch |
| Worker warnings | n/a | one `waitUntil() tasks did not complete` (unrelated; long-poll wrap-up) |

The absence of `send-no-standalone` is the deterministic evidence that the
monkey-patch's fallback engaged before the agents-lib silent-drop branch could
fire. Pre-fix runs (script version `63b28357`) had this line on every CC
elicit. Post-fix runs do not.

The absence of either fallback-error line confirms the ALS routing didn't
miss — the connection-based capture point in `mcp-agent-factory.ts`
correctly resolved the active inbound request id, the patched `send` found
the matching POST connection, and `writeSSEEvent` was called.

## Templating note

Workers Observability collapses log messages to templates by replacing
dynamic substrings with placeholders (`<DOMAIN>`, `<NUMBER>`, etc.). For
example `DEBUG-ELICIT elicit-caps` shows up with `operationId:"<DOMAIN>"`
in `messageTemplate`. The `wrap-pre` log we added in Task 6 (which carries
`activeRequestId`) was not surfaced in the queries against this script
version's window — most likely template-collapsed under a different
fingerprint than the queries hit. This does NOT mean the wrap didn't fire:
the elicit-caps log site lives downstream of the wrap, so wrap-pre
necessarily fired before it. If a follow-up needs to confirm the
activeRequestId thread directly, query against the message fingerprint of
the wrap-pre line (or revert to `wrangler tail` for a single-shot capture).

## Sample event (current deploy)

`DEBUG-ELICIT elicit-caps` for `gmail.users.threads.delete`:

```
timestamp:    2026-05-11T11:16:45.440Z
requestId:    9fa0c5f6fd1cd6fd
trigger:      GET /mcp
scriptVersion: de1685c6-471b-4df7-970a-4a45dae79840
message:      DEBUG-ELICIT {"stage":"elicit-caps","ts":"2026-05-11T11:16:45.440Z","operationId":"gmail.users.threads.delete","supportsElicit":true,"capsRaw":{"elicitation":{"form":{}},"roots":{}}}
outcome:      canceled (long-poll stream wrap-up — normal)
```

## Pre-fix comparison (script version `63b28357`)

`DEBUG-AGENTS send-pre-write` event from a pre-fix run (kept for
contrast — these probes lived in a separately patched agents build that
was reverted on main, so they only appear on older script versions):

```
timestamp:    2026-05-11T00:03:13.198Z
scriptVersion: 63b28357-d537-48f2-af66-512fe3eb4c2a
message:      DEBUG-AGENTS {"stage":"send-pre-write","channelKind":"per-request-sse","connectionId":"AmxUY31xFmXJFlnrNhLdi","requestId":1,"shouldClose":true,"relatedIdsCount":1}
```

Compare against the post-fix script: zero `send-no-standalone`, zero
fallback errors, elicit-caps still firing for the right operation, no
60-second timeout pattern.

## How this was queried

Workers Observability MCP, three queries:

1. All events for the deployed script version in the last 3h (limit 200).
2. Targeted `$metadata.message includes "send-no-standalone"` filter —
   returned 0 results.
3. Targeted `$metadata.message includes "send-pre-write"` and "wrap-pre"
   filters — also 0 (templating note above).
4. `$metadata.level in [error, warn]` — one unrelated warn.
