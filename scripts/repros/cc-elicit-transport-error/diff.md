# CC elicit transport-error — Run 6 diff analysis

**Date:** 2026-05-10
**Deployment:** `gmail.your-subdomain.workers.dev`
**Probe patch:** `patches/agents@0.12.3.patch` (commit `948b3d1`)
**Branch:** `claude/brainstorm-todo-task-Ybvpm` at `44cc318` (includes prior-fix cherry-picks: ALS re-entry `1fdc2eb`, validator swap `44cc318`, scaffold-side DEBUG-ELICIT probes)

## Inspector control trail (chronological)

```
13:24:12.397  DEBUG-AGENTS  send-entry             jsonrpc:{id:0}                                    relatedRequestId:null
              ── (initialize response)

13:24:15.313  DEBUG-AGENTS  elicit-response-handled  requestId:0  isResult:true  isError:false  pendingCount:0
13:24:15.313  DEBUG-ELICIT  elicit-result            action:"accept"  validated:true
13:24:15.313  AUDIT         elicit  elicitationOutcome:"accepted"
              ── (CC's accept came back; scaffold processed; audit logged)

13:24:15.781  AUDIT         allow  upstreamStatus:403   ── (Gmail DELETE returned 403, separate scope issue)
13:24:15.781  DEBUG-AGENTS  send-entry           jsonrpc:{id:3}            relatedRequestId:null
13:24:15.781  DEBUG-AGENTS  send-pre-write       channelKind:"per-request-sse"  connectionId:by26ed…  requestId:3  shouldClose:true  relatedIdsCount:1
              ── (final tool-call response shipped back to Inspector via per-request-SSE)
```

(Note: the user's pasted Inspector capture was abridged. The outgoing elicit notification's `send-entry method:"elicitation/create"` and its expected `send-pre-write channelKind:"standalone-sse"` were not in the paste, but `elicit-response-handled requestId:0 isResult:true` proves the elicit went out and came back successfully — the standalone-SSE channel was alive.)

## Claude Code test trail (chronological)

```
13:19:28.282  DEBUG-AGENTS  send-entry  jsonrpc:{id:0}  relatedRequestId:null
              ── (initialize response)

13:19:28.288  DEBUG-AGENTS  elicit-response-handled  requestId:4  isResult:false  isError:false  pendingCount:0
              ── (some non-elicit message routed through the response handler intercept; not relevant)

13:19:28.305  DEBUG-ELICIT  wrap-pre      agentSet:false                       (request enters codemode child→host RPC frame; ALS empty as expected)
13:19:28.305  DEBUG-ELICIT  wrap-post     agentSet:true                        (Option-1 ALS fix engaged ✓)
13:19:28.305  DEBUG-ELICIT  request-entry method:DELETE
13:19:28.305  DEBUG-ELICIT  elicit-branch decision:"elicit"  category:"irreversible"
13:19:28.305  DEBUG-ELICIT  elicit-caps   supportsElicit:true                  (CC declared elicit capability)
13:19:28.305  DEBUG-ELICIT  elicit-pre-send                                    (about to call args.server.server.elicitInput)
13:19:28.305  DEBUG-AGENTS  send-entry              jsonrpc:{method:"elicitation/create",id:0}  relatedRequestId:null
                            ── (transport.send called for the elicit request)
13:19:28.305  DEBUG-AGENTS  send-no-standalone      connectionCount:1  connectionsFlagged:0
                            ── ★★★ EARLY-RETURN PATH FIRED. No DO connection has _standaloneSse=true. send() silently returns. ★★★

(60-second gap: SDK Server.request waits for a response that never comes)

13:20:28.305  DEBUG-AGENTS  send-entry             jsonrpc:{method:"notifications/cancelled"}     relatedRequestId:null
13:20:28.305  DEBUG-AGENTS  send-no-standalone     connectionCount:1  connectionsFlagged:0
                            ── (the SDK's auto-emitted cancellation notification ALSO can't be written;
                                same root cause — same early-return)

13:20:28.305  DEBUG-ELICIT  elicit-catch  errorMessage:"MCP error -32001: Request timed out"
13:20:28.305  AUDIT         elicit  elicitationOutcome:"transport-error"

13:20:28.305  DEBUG-AGENTS  send-entry              jsonrpc:{id:4}                  relatedRequestId:null
13:20:28.305  DEBUG-AGENTS  send-pre-write          channelKind:"per-request-sse"  connectionId:mm3lnV…  requestId:4  shouldClose:true  relatedIdsCount:1
                            ── (final ToolError response shipped back to CC via per-request-SSE — that channel IS alive)
```

## Divergence point

The two clients diverge at `transport.send()` for the outgoing elicit request:

| Probe | Inspector | Claude Code |
|---|---|---|
| `send-entry method:"elicitation/create"` | (paste truncated; implied by `elicit-response-handled`) | ✓ fires |
| `send-no-standalone` | does NOT fire (a `_standaloneSse=true` connection exists) | **fires (`connectionCount:1, connectionsFlagged:0`)** |
| `send-pre-write channelKind:"standalone-sse"` | (would fire next; not in paste) | does NOT fire (early-return swallowed it) |
| `elicit-response-handled requestId:<elicit-id> isResult:true` | ✓ at `requestId:0` | does NOT fire (no response ever arrives) |

`connectionCount:1` confirms a DO connection exists for the session (the per-request-SSE one carrying the original `tools/call` POST — visible in the final `send-pre-write channelKind:"per-request-sse"` for response id=4).
`connectionsFlagged:0` confirms NONE of those connections have `state._standaloneSse=true`.

Per `agents@0.12.3` `dist/mcp/index.js`, the only code path that sets `connection.state._standaloneSse = true` is `StreamableHTTPServerTransport.handleGetRequest` (line 573 in the original dist), which fires when a GET `/mcp` arrives and is bound to a live connection. Claude Code's GET `/mcp` is shown as **`Canceled` at the same instant as the POST** in wrangler tail (`GET https://gmail.your-subdomain.workers.dev/mcp - Canceled @ 11:19:28 pm` — same timestamp as the `POST /mcp` that triggered the tool call). The cancellation occurred fast enough that either (a) `handleGetRequest` never ran to set the flag, or (b) it ran but the connection was already torn down before the elicit dispatched ~tens of milliseconds later.

## Decision tree row

**Row B** — `send-entry` logs, `send-no-standalone` follows. **H1 sub-case: no DO connection had `_standaloneSse=true`; elicit had no channel; library returned silently.**

(The user's capture doesn't show `get-stream-open` / `get-stream-close` logs around the canceled GET — likely because either the GET was canceled before the worker handler ran the TransformStream construction at line 245, or the lines were dropped from the abridged paste. Either way, the `send-no-standalone connectionsFlagged:0` signal at the elicit dispatch is decisive: no standalone connection existed at write time, regardless of whether one briefly existed earlier.)

## Causal chain

1. Claude Code's MCP client opens the Streamable HTTP session by POSTing the `tools/call` request to `/mcp`. The worker establishes a DO `Connection` to handle that POST as a per-request SSE stream.
2. Claude Code (apparently) issues a GET `/mcp`, but the GET is canceled at the same instant as the POST per wrangler tail. The agent's `handleGetRequest` either never runs or doesn't successfully set `connection.state._standaloneSse = true` on a live connection.
3. The scaffold's `surface-review` decides `decision:"elicit"` for `gmail.users.threads.delete`. It calls `args.server.server.elicitInput(...)`.
4. MCP SDK `Server.elicitInput` calls `Server.request`, which calls `this._transport.send(elicitRequest)`. The transport is the agents-library `StreamableHTTPServerTransport`.
5. Inside `send()`: `getCurrentAgent()` returns the agent (ALS fix engaged). `requestId = options?.relatedRequestId` is `null`. The message is a request (not a response), so the standalone branch is taken.
6. `for (const conn of agent.getConnections()) if (conn.state?._standaloneSse) standaloneConnection = conn;` — iterates the one connection (the POST-side one), finds none flagged, leaves `standaloneConnection` undefined.
7. `if (standaloneConnection === void 0) return;` — silently returns. No write to any stream. No error.
8. SDK's `Server.request` waits for an elicit response on a Promise that's pending forever.
9. After 60 s the SDK's default request timeout fires (`Server.request` rejects with `MCP error -32001: Request timed out`).
10. SDK auto-emits `notifications/cancelled` to the client. `send()` is called again — same early-return, also silently dropped.
11. Scaffold's `runElicitation` catches `McpError`, writes audit `elicitationOutcome:"transport-error"`, throws a `ToolError`.
12. The final tool-call response (`id:4`) IS shipped back to CC via the per-request-SSE channel, which is still alive.

## Escalation target

**Primary: `cloudflare/agents`.** `StreamableHTTPServerTransport.send()` silently no-ops when no `_standaloneSse` connection exists. This is a transport-robustness gap: server-initiated server-to-client requests (elicit, sampling, listRoots) are unreliable for any client whose Streamable HTTP GET lifecycle differs from Inspector's. The library should either (a) fail fast with a clear error so the SDK timeout is unnecessary, (b) queue the message until a standalone connection appears, or (c) attempt fallback delivery via the per-request-SSE stream of the in-flight POST that triggered the tool call (which IS still alive — visible in the final `send-pre-write channelKind:"per-request-sse"` for response id:4).

**Secondary: Claude Code.** The GET `/mcp` is canceled at the same instant as the POST that triggers the tool call. This is a different lifecycle than Inspector's; depending on the MCP Streamable HTTP spec's expectations for the long-lived GET stream, this may be a non-conformant client behavior worth flagging with Anthropic. (However, the spec is permissive — the server library is the one that has to deal robustly with whatever lifecycle the client chooses.)

## Next: draft

`docs/superpowers/drafts/2026-05-09-cloudflare-agents-cc-elicit-no-channel-issue-draft.md`
