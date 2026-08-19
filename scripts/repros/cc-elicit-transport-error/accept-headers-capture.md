# CC elicit transport-error — Accept-header probe capture

**Date:** 2026-05-11
**Deployment:** `gmail.your-subdomain.workers.dev` (script version `de1685c6-471b-4df7-970a-4a45dae79840`)
**Probe patch:** `patches/agents@0.12.3.patch` (commit `2c05f8d`)
**Branch:** `claude/brainstorm-todo-task-Ybvpm`

## Purpose

Verify Claude Code's Streamable HTTP client is spec-conformant for the
`Accept` header on tool-call POSTs. The 2025-11-25 MCP spec requires the
client to list both `application/json` and `text/event-stream`. Probe
fires before `createStreamingHttpHandler`'s 406 validation, so even
non-conformant requests would be visible.

## Probes added

| # | Site | Stage label |
|---|---|---|
| 1 | `createStreamingHttpHandler` POST branch entry | `post-headers` (accept, content-type, UA, session id) |
| 2 | `createStreamingHttpHandler` GET branch entry | `get-headers` (accept, UA, session id) |
| 3 | `StreamableHTTPServerTransport.send` entry | `send-entry` (jsonrpc method/id, relatedRequestId) |

## Result: CC POST Accept header (the elicit-triggering tool call)

```
DEBUG-AGENTS {"stage":"post-headers","ts":"2026-05-11T11:16:45.415Z",
              "accept":"application/json, text/event-stream",
              "contentType":"application/json",
              "userAgent":"Claude-User",
              "mcpSessionId":"1cc26c7aed661071621cec3587a16f326672ad9961efffbcd07ea6ba7068cb25"}
```

**Conformant.** Both required content types present. Same value
observed on every POST in the capture (initialize, initialized notif,
tools/list, tools/call, subsequent retries).

The wrangler-tail request line for the paired GET (which Cloudflare's
MCP gateway opens with `upgrade: websocket` and `cf-mcp-message`
header carrying the JSON-RPC POST body) also has
`accept: "application/json, text/event-stream"` — conformant on both
channels.

## Run trail (causal chain — fresh capture, Row B reproduced cleanly)

```
11:16:45.415  POST  post-headers      accept:application/json, text/event-stream
                                      cf-ray:9fa0c5f6fd1cd6fd
11:16:45.440  ELICIT wrap-pre         agentSet:false                       (codemode child→host frame)
11:16:45.440  ELICIT wrap-post        agentSet:true                        (ALS fix engaged ✓)
11:16:45.440  ELICIT request-entry    method:DELETE  path:/gmail/v1/users/me/threads/19df5a712d9c336d
11:16:45.440  ELICIT elicit-branch    decision:"elicit"  category:"irreversible"
11:16:45.440  ELICIT elicit-caps      supportsElicit:true
                                      capsRaw:{elicitation:{form:{}},roots:{}}
11:16:45.440  ELICIT elicit-pre-send  (about to call args.server.server.elicitInput)
11:16:45.440  AGENTS send-entry       jsonrpc:{method:"elicitation/create",id:0}
                                      relatedRequestId:null
                                      ★ no send-no-standalone probe in this patch set,
                                      but per Run 6 capture this hits the early-return.
(60-second gap)
11:17:45.440  AGENTS send-entry       jsonrpc:{method:"notifications/cancelled"}
                                      (SDK auto-emit after Server.request timeout)
11:17:45.440  ELICIT elicit-catch     errorName:McpError
                                      errorMessage:"MCP error -32001: Request timed out"
                                      errorJson:{code:-32001,data:{timeout:60000},name:"McpError"}
                                      isTimeout:false  (SDK won the Promise.race vs scaffold's 60s)
11:17:45.440  AGENTS send-entry       jsonrpc:{id:4}  relatedRequestId:null
                                      (final tool-call ToolError response — shipped via per-request-SSE)
```

## Architectural notes (no need to fold into draft, just for reference)

- **No `get-headers` ever fires.** Despite the wrangler-tail showing
  `GET /mcp` requests with `entrypoint:GmailMCP`, the probe at
  `createStreamingHttpHandler` line 242 never executes. These GETs
  route directly to the DO via Cloudflare's MCP gateway (`cf-mcp-message`
  + `cf-mcp-method` headers), entering at `onConnect`/`onRequest`
  (dist line 1452 switch on `MCP_HTTP_METHOD_HEADER`) and then calling
  `this._transport.handleGetRequest()` (line 1467), which sets
  `_standaloneSse:true` (line 598).
- **The GETs are marked `outcome:"canceled"` at the same instant as
  the elicit dispatches** (all events at 11:16:45 have `canceled`
  outcomes). So `_standaloneSse:true` IS set briefly on a connection
  that gets canceled before the elicit hits `transport.send()`. By
  then, `agent.getConnections()` either no longer contains that
  connection or contains it without the flag.
- **This refines (doesn't contradict) Run 6.** Run 6 read `GET … -
  Canceled @ <same timestamp as POST>` from wrangler tail. This
  capture confirms the cancellation is real (`outcome:"canceled"`
  on the DO fetch event), and that it happens fast enough to leave
  the connection unflagged from `send()`'s vantage point. The
  silent early-return at dist line 707 is still the bug.

## Spec citation backing the conformance claim (2025-11-25 revision)

> "Every JSON-RPC request the client sends to the MCP server MUST be a
> POST to the MCP endpoint, with an Accept header listing both
> `application/json` and `text/event-stream`."

Confirmed: every CC POST in this capture meets that requirement.

> "Once the SSE stream is open, the server MAY send JSON-RPC requests
> and notifications before sending the JSON-RPC response. These
> messages SHOULD relate to the originating client request."

This is the spec hook for the fix: an elicit IS related to the
originating `tools/call`, so the server can spec-conformantly deliver
it on the per-request POST stream. The library currently doesn't —
it routes to the standalone-SSE branch when `relatedRequestId` is
undefined, even though a per-request stream is available.

> "The client MAY issue an HTTP GET to the MCP endpoint."

`MAY` — CC is not non-conformant for whatever it chooses to do with
the GET channel. The library's job is to handle any spec-permitted
client behavior.
