# Claude Code elicit transport-error repro

Companion to `docs/superpowers/specs/2026-05-09-cc-elicit-transport-error-design.md`.

This directory holds the evidence pack for the diagnostic protocol described in the spec. The diagnostic patch lives at `patches/agents@0.12.3.patch` (reverted at branch tip; visible in git history at commit `948b3d1`).

## Files

- `probe-sites.md` — line-number resolution notes for the seven `DEBUG-AGENTS` probes (output of plan Task 1).
- `inspector-tail.txt` — control run capture (Inspector Streamable HTTP, accept flow).
- `claude-code-tail.txt` — test run capture (Claude Code, observed timeout).
- `diff.md` — divergence-point analysis and decision-tree mapping.

## Probe set (seven probes)

| # | Stage label | Site |
|---|---|---|
| 1 | `send-entry` | `StreamableHTTPServerTransport.send` entry, line 663 (original) |
| 2 | `send-no-standalone` | The `if (standaloneConnection === void 0)` early-return path, line 671 (original) |
| 3 | `send-pre-write` (`channelKind:"standalone-sse"`) | Just before `writeSSEEvent(standaloneConnection, ...)`, line 674 (original) |
| 4 | `send-pre-write` (`channelKind:"per-request-sse"`) | Just before `writeSSEEvent(connection, ..., shouldClose)`, line 688 (original) — should NOT fire on elicit |
| 5 | `get-stream-open` | `createStreamingHttpHandler`, just after `new TransformStream()`, line 245 (original) |
| 6 | `get-stream-close` | `ws.addEventListener("close", ...)` body, line 291 (original) |
| 7 | `elicit-response-handled` | `McpAgent._handleElicitationResponse(message)` body, line 1515 (original) |

Each probe emits a single `console.log` line beginning with the literal `DEBUG-AGENTS ` (with trailing space) followed by JSON. Grep-friendly. All probes are wrapped in `try { ... } catch {}` so a serialization failure can never disrupt the request flow.

## Reproduction

Both runs target the same deployed worker and require the prior fixes from `claude/fix-elicit-als-context-5rnMa` to be present (ALS re-entry + `CfWorkerJsonSchemaValidator` swap). See spec § "Verification approach".

### Setup

1. Confirm the diagnostic patch is registered:

   ```bash
   grep -A2 patchedDependencies package.json
   # Expect: agents@0.12.3 -> patches/agents@0.12.3.patch
   ```

2. Confirm the prior-fix prerequisites are on the branch:

   ```bash
   grep -n "agentContext.run" packages/scaffold/src/mcp-agent-factory.ts
   grep -n "CfWorkerJsonSchemaValidator" packages/scaffold/src/mcp-agent-factory.ts
   ```

   Both should return at least one match. If empty, the prerequisite is missing — STOP and rebase / cherry-pick the fix branch first.

3. Deploy:

   ```bash
   pnpm --filter gmail deploy
   ```

4. Open `wrangler tail` against the deployment in a dedicated terminal:

   ```bash
   pnpm --filter gmail wrangler tail --format pretty
   ```

   Leave running for both runs. Save the entire output.

### Control run (Inspector)

1. Open MCP Inspector. Configure with **Streamable HTTP** transport (not legacy SSE) pointed at the deployed `/mcp` endpoint.
2. List tools. Pick `gmail.users.threads.delete`.
3. Provide a known-disposable thread id. Send.
4. When the elicit confirmation form appears, click **Accept**.
5. Save the wrangler tail output up to and including the audit `accepted` line into `inspector-tail.txt`.

Expected probe trail (loose order):

```
DEBUG-AGENTS {"stage":"get-stream-open",...}
DEBUG-AGENTS {"stage":"send-entry",...}
DEBUG-AGENTS {"stage":"send-pre-write","channelKind":"standalone-sse",...}
DEBUG-AGENTS {"stage":"elicit-response-handled","isResult":true,...}
```

`send-no-standalone` and `send-pre-write` with `channelKind:"per-request-sse"` should NOT appear.

### Test run (Claude Code)

1. In the same wrangler tail session, switch context.
2. Open Claude Code. Confirm the same Gmail MCP is connected.
3. Trigger the same `gmail.users.threads.delete` tool call (different thread id is fine).
4. **Do not interact** with the IDE — the user has confirmed no elicit prompt UI surfaces in Claude Code on this code path.
5. Wait for the 60-second SDK timeout to fire (the tool call returns an `MCP error -32001: Request timed out`).
6. Save the wrangler tail output covering the run into `claude-code-tail.txt`.

### Diff

Compare the two probe trails. The divergence point identifies the cause per the spec § "Diagnosis decision tree". Summary mapping:

| CC pattern | Decision-tree row |
|---|---|
| No `send-entry` | Row A |
| `send-entry` + `send-no-standalone` (any `connectionsFlagged`) | Row B |
| `send-entry` + `send-no-standalone` AND a `get-stream-close` precedes `send-entry` | Row C |
| `send-pre-write channelKind:"standalone-sse"` but no `elicit-response-handled` (ambiguous flush) | Row D |
| `send-pre-write channelKind:"standalone-sse"` AND no `get-stream-close` AND no `elicit-response-handled` | Row E |
| Anything else | Row F (stopping rule) |

Capture the divergence + cause + named row in `diff.md`. The named row's draft template lives at `docs/superpowers/drafts/2026-05-09-<row-suffix>-issue-draft.md` (created in plan Task 11).

## 2026-05-12 — Fix verified (transport.send patch engaged)

**Deployment:** `gmail.your-subdomain.workers.dev`, script version `WORKER_SCRIPT_VERSION`
**Branch:** `cc-elicit-transport-send-patch` (transport.send patch + ALS wiring)

### Result

- Claude Code elicit-gated `gmail.users.threads.delete`: prompt surfaced, accept routed through, tool call completed.
- Inspector regression run (Streamable HTTP): unaffected — standalone-SSE branch still engages (no behavior change for that path).
- No `send-no-standalone` events on the post-fix script version across a 3h window. Pre-fix runs (script `63b28357`) had this line on every CC elicit.
- No `transport.send fallback engaged but ...` errors — the ALS routing didn't miss.

### Evidence

Workers Observability MCP queries (no live `wrangler tail` was run — same data, different surface). Captured at:

- `cc-fix-verified-2026-05-12-observability.md` — full query results, signal table, sample events, pre-fix comparison.

The smoking-gun signal is the **absence of `send-no-standalone`** on the post-fix script version. Pre-fix runs have it on every elicit; post-fix runs have zero across the inspected window.
