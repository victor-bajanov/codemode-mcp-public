# agents@0.12.3 probe insertion points

Resolved against
`node_modules/.pnpm/agents@0.12.3_@babel+core@7.29.0_@babel+runtime@7.29.2_@cloudflare+codemode@0.3.4_patch_hash=_pkgv3dxwwtokkthu4nmx6sghsq/node_modules/agents/dist/mcp/index.js`
(56,257 bytes, 1594 lines).

Notes on naming and architecture (read before applying probes):

- The dist file ships **two** server-side transports.
  - `StreamableHTTPServerTransport` (declared at line 543, `var StreamableHTTPServerTransport = class { ... }`) is the transport that the `McpAgent` instantiates inside the Durable Object (see `initTransport()` at line 1377: `const transport = new StreamableHTTPServerTransport({});`). Its `send()` (line 662) is what `McpAgent.elicitInput` calls at line 1492 (`await this._transport.send(elicitRequest)`). This is the "send" the plan cares about.
  - `WorkerTransport` (line 726) is a parallel implementation used only via the explicit `WorkerTransport`-options handler path; `McpAgent.serve("/mcp", ...)` does **not** use it. It does have its own `send` (line 1197) and its own GET handler (line 840) with `streamMapping` / `requestToStreamMapping`. Probes here are not on the active code path for `gmail-mcp`, so they are NOT chosen as the probe sites; this is documented for clarity.
- The `McpAgent.serve("/mcp", ...)` call (used by `setupProvider` in `packages/scaffold`) returns a handler from `createStreamingHttpHandler` (line 24). That handler holds the **HTTP-side** `TransformStream` for GET `/mcp`; the DO-side `StreamableHTTPServerTransport` does NOT manage the GET stream lifecycle directly. Per-session SSE bytes flow:
  `StreamableHTTPServerTransport.writeSSEEvent` -> `connection.send(JSON.stringify({ type: "cf_mcp_agent_event", event, close }))` -> WebSocket message -> `ws.addEventListener("message", ...)` in `createStreamingHttpHandler` (line 274) -> `writer.write(encoder.encode(message.event))` (line 280) -> SSE bytes to the HTTP client.
- Property names actually used in the dist:
  - On `StreamableHTTPServerTransport`: `this._started`, `this._requestResponseMap` (Map), `this._eventStore`, `this.sessionId`, `this.onmessage`, `this.onerror`, `this.onclose`, `this.messageInterceptor`. Per-request stream tracking is done **via the DO `connection` object's state** (`connection.state.requestIds` and `connection.state._standaloneSse`), not via a `_requestToStreamMapping` Map. The plan's prompt asked which of `_requestToStreamMapping` / `_streamMapping` is used here -- **neither**, this transport tracks per-request routing on the live `Connection.state`.
  - On `WorkerTransport` (not on the active path, included for reference): `this.streamMapping` and `this.requestToStreamMapping` (both Maps).
- On `McpAgent`: `this._transport`, `this._pendingElicitations` (Map of `requestId -> { resolve, reject }`).
- "GET stream open" and "GET stream close/cancel" sites are in `createStreamingHttpHandler` (the worker-side handler), not on `StreamableHTTPServerTransport`. The DO-side method that fires for an inbound GET is `StreamableHTTPServerTransport.handleGetRequest` (line 563), but it does NOT itself open or close any stream: it just flips `connection.state._standaloneSse = true` (line 573). Bytes flow through the worker-side `TransformStream` opened at line 245 and torn down at lines 287-292 (`error`/`close` event listeners both call `writer.close()`).

## Site 1: StreamableHTTPServerTransport.send entry

- File: `dist/mcp/index.js`
- Line: 663 (insert as the first line inside the `async send(message, options) { ... }` body, immediately after the `{` on line 662)
- Method signature: `async send(message, options) {`
- Available vars at entry:
  - `this.sessionId` (string, set in constructor from `agent.getSessionId()`)
  - `this._eventStore` (optional)
  - `this._requestResponseMap` (Map of requestId -> response message)
  - `this.messageInterceptor`, `this.onmessage`, `this.onerror`, `this.onclose`
  - `message` (the JSON-RPC message; for elicit calls this is `{ jsonrpc: "2.0", id: "elicit_<...>", method: "elicitation/create", params: {...} }`)
  - `options` (may be `undefined`); `options?.relatedRequestId` is the only field read
  - `getCurrentAgent()` is callable but is invoked one line down inside the method
- 5-line context (lines 658-668):
  ```js
  			if (!agent) throw new Error("Agent was not found in close");
  			for (const conn of agent.getConnections()) conn.close(1e3, "Session closed");
  			this.onclose?.();
  		}
  		async send(message, options) {
  			const { agent } = getCurrentAgent();
  			if (!agent) throw new Error("Agent was not found in send");
  			let requestId = options?.relatedRequestId;
  			if (isJSONRPCResultResponse(message) || isJSONRPCErrorResponse(message)) requestId = message.id;
  			if (requestId === void 0) {
  				if (isJSONRPCResultResponse(message) || isJSONRPCErrorResponse(message)) throw new Error("Cannot send a response on a standalone SSE stream unless resuming a previous client request");
  ```

## Site 2: send pre-write

There are **two** write paths in `StreamableHTTPServerTransport.send`. Both end in a call to `this.writeSSEEvent(...)` (which itself calls `connection.send(...)` on a DO `Connection`, not a `controller.enqueue` / `writer.write`). The plan's note that "may exist twice if there are two write paths" applies. Both pre-write points should be probed.

### Site 2a: standalone-SSE write path

- File: `dist/mcp/index.js`
- Line: 674 (probe immediately before this `this.writeSSEEvent(standaloneConnection, message, eventId);` call; insert on a new line at 674, pushing the write to 675)
- Available vars at this point:
  - `agent` (from destructured `getCurrentAgent()` on line 663)
  - `requestId` (`undefined` in this branch)
  - `standaloneConnection` (the `Connection` DO peer with `state._standaloneSse === true`)
  - `eventId` (optional, from `this._eventStore.storeEvent(...)`)
  - `message` (the JSON-RPC payload to be written)
  - `this.sessionId`, `this._eventStore`
- 5-line context (lines 670-679):
  ```js
  			for (const conn of agent.getConnections()) if (conn.state?._standaloneSse) standaloneConnection = conn;
  			if (standaloneConnection === void 0) return;
  			let eventId;
  			if (this._eventStore) eventId = await this._eventStore.storeEvent(standaloneConnection.id, message);
  			this.writeSSEEvent(standaloneConnection, message, eventId);
  			return;
  		}
  		const connection = Array.from(agent.getConnections()).find((conn) => conn.state?.requestIds?.includes(requestId));
  		if (!connection) throw new Error(`No connection established for request ID: ${String(requestId)}`);
  		let eventId;
  ```

### Site 2b: per-request-SSE write path (the elicit-relevant path)

- File: `dist/mcp/index.js`
- Line: 688 (probe immediately before this `this.writeSSEEvent(connection, message, eventId, shouldClose);` call; insert on a new line at 688, pushing the write to 689)
- Available vars at this point:
  - `agent`, `requestId`
  - `connection` (the `Connection` whose `state.requestIds` includes `requestId`)
  - `connection.state.requestIds` (array of in-flight request ids on this connection)
  - `eventId`
  - `shouldClose` (boolean; true iff every requestId in `connection.state.requestIds` has a response in `this._requestResponseMap`)
  - `this._requestResponseMap`
  - `message`
- 5-line context (lines 684-693):
  ```js
  			const relatedIds = connection.state?.requestIds ?? [];
  			shouldClose = relatedIds.every((id) => this._requestResponseMap.has(id));
  			if (shouldClose) for (const id of relatedIds) this._requestResponseMap.delete(id);
  		}
  		this.writeSSEEvent(connection, message, eventId, shouldClose);
  	}
  };
  //#endregion
  //#region src/mcp/client-transports.ts
  /**
  ```

## Site 3: send exit

- File: `dist/mcp/index.js`
- Line: 689 (insert immediately after the per-request `writeSSEEvent` call on line 688, on a new line at 689, before the closing `}` of `send` on line 689)
- Note: `send` has multiple exit points -- two early `return`s (line 671 for "no standalone connection" and line 675 for after the standalone write) and the implicit fall-through return at end of body (line 689). The plan calls for one "exit" probe; the most useful is the per-request-path exit immediately after `writeSSEEvent` on line 688, because that is the elicit code path. To cover all exits, additional probes can be inserted at line 671 (early return: no standalone) and line 675 (early return: standalone written), but per the plan the primary exit probe goes here.
- Available vars at exit (per-request path):
  - All the per-request-path vars above (`requestId`, `connection`, `eventId`, `shouldClose`)
  - `this._requestResponseMap` reflects the post-write state
- 5-line context (lines 685-694):
  ```js
  			shouldClose = relatedIds.every((id) => this._requestResponseMap.has(id));
  			if (shouldClose) for (const id of relatedIds) this._requestResponseMap.delete(id);
  		}
  		this.writeSSEEvent(connection, message, eventId, shouldClose);
  	}
  };
  //#endregion
  //#region src/mcp/client-transports.ts
  /**
  * Deprecated transport wrappers
  ```

## Site 4: GET /mcp stream open

- File: `dist/mcp/index.js`
- Line: 245 (probe immediately after the `TransformStream` is constructed, before `getWriter()`. Insert on a new line at 246, pushing the existing `getWriter()` to 247.)
- Location: inside `createStreamingHttpHandler`'s `request.method === "GET"` branch, after session validation and after `agent.getInitializeRequest()` succeeded, the moment the per-request SSE pipe is created.
- Available vars at this point:
  - `request` (the inbound `Request`)
  - `sessionId` (already validated, non-null string from `mcp-session-id` header)
  - `agent` (the `DurableObject` stub fetched via `getAgentByName(namespace, "streamable-http:" + sessionId, ...)`)
  - `readable`, `writable` (from the freshly-constructed `TransformStream`)
  - `options.corsOptions`, `options.jurisdiction`, `namespace`, `basePath` (closure vars)
- 5-line context (lines 241-250):
  ```js
  					message: "Bad Request: Mcp-Session-Id header is required"
  				},
  				id: null,
  				jsonrpc: "2.0"
  			}), { status: 400 });
  			const { readable, writable } = new TransformStream();
  			const writer = writable.getWriter();
  			const encoder = new TextEncoder();
  			const agent = await getAgentByName(namespace, `streamable-http:${sessionId}`, {
  				props: ctx.props,
  				jurisdiction: options.jurisdiction
  			});
  ```

## Site 5: GET /mcp stream close/cancel

- File: `dist/mcp/index.js`
- Line: 290 (the `ws.addEventListener("close", ...)` block; insert the probe inside the close handler at line 291, immediately before `writer.close().catch(() => {});`).
- Sibling site (also worth probing): line 287, the `error` handler at line 287-289, which also tears the writer down. Both paths converge on `writer.close().catch(() => {});`. To keep one canonical probe site per the plan, choose the `close` handler (line 290-292), because the WebSocket-from-the-DO closing is the dominant "stream end" signal for normal shutdown; the `error` listener fires only on transport faults.
- Limitation: there is no explicit `stream.cancel()` call anywhere on the GET path. The HTTP-side stream is torn down purely via `writer.close()` reactions to WebSocket lifecycle events (`message` with `close: true` is only handled in the POST branch at line 185-188; the GET branch on line 274-286 does NOT honour `message.close`, it only tears down on `error`/`close` of the inbound DO WebSocket). Document this in the patch: a "stream-cancel-by-client" event (e.g., HTTP client disconnect) is observable only as the upstream WebSocket closing.
- Available vars at this point:
  - `writer` (the TransformStream writer from Site 4)
  - `ws` (the WebSocket to the DO)
  - `request`, `sessionId`, `agent` (closure)
- 5-line context (lines 286-295):
  ```js
  				});
  				ws.addEventListener("error", () => {
  					writer.close().catch(() => {});
  				});
  				ws.addEventListener("close", () => {
  					writer.close().catch(() => {});
  				});
  				return new Response(readable, {
  					headers: {
  						"Cache-Control": "no-cache",
  ```

## Site 6: _handleElicitationResponse entry

- File: `dist/mcp/index.js`
- Line: 1515 (insert as the first line inside the `_handleElicitationResponse(message) { ... }` body, immediately after the `{` on line 1514)
- Method signature: `_handleElicitationResponse(message) {`
- This method is called from four places in the dist (per `grep -n "_handleElicitationResponse(" dist/mcp/index.js`):
  - line 1379 -- inside `initTransport()`'s `messageInterceptor` callback for `streamable-http` (the path that matters for the cc-elicit repro)
  - line 1446 -- inside `onSSEMcpMessage` (legacy SSE path)
  - line 1514 -- the method definition itself
  - line 1547 -- inside `handleMcpMessage` (RPC path)
- The plan asks for the **method-entry** probe, so the insertion point is the body of the definition (line 1515), giving one probe that fires for all four call sites.
- Available vars at entry:
  - `this._pendingElicitations` (Map of `"elicit_<rand>"` -> `{ resolve, reject }`; populated by `McpAgent.elicitInput` at line 1473)
  - `this._transport`, `this.props`, `this.ctx` (DO context), other `McpAgent` state
  - `message` (the inbound JSON-RPC message; expected to be a result/error response with `id` starting with `"elicit_"`)
- 5-line context (lines 1510-1520):
  ```js
  			return responsePromise;
  		});
  	}
  	/** Handle elicitation responses via in-memory resolver */
  	_handleElicitationResponse(message) {
  		if (isJSONRPCResultResponse(message) && message.result) {
  			const requestId = message.id?.toString();
  			if (!requestId || !requestId.startsWith("elicit_")) return false;
  			const pending = this._pendingElicitations.get(requestId);
  			if (!pending) return false;
  			pending.resolve(message.result);
  		}
  ```
