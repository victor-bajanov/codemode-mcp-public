# Minimal repro — `agentContext` ALS gap across Worker-Loader callbacks

A standalone Cloudflare Worker that reproduces an upstream
`cloudflare/agents` bug:

> A DO-based `McpAgent` whose tools are dispatched through a
> Worker-Loader child isolate cannot perform server-initiated MCP
> requests (`server.elicitInput`, `createMessage`, `listRoots`) from
> within a host-side callback that the child invokes via Workers RPC.
>
> `StreamableHTTPServerTransport.send` reads the current agent from a
> host-side `AsyncLocalStorage`
> (`__DO_NOT_USE_WILL_BREAK__agentContext`). That store is empty inside
> the callback because child→host RPC arrives as a fresh entrypoint
> invocation with no ancestor in the original `agentContext.run(...)`
> call tree. The transport throws `"Agent was not found in send"`.

The fix (also reproduced here) is to wrap the host-side callback body
in `agentContext.run({ agent: this, ... }, ...)` so the ALS frame is
re-established at the RPC boundary.

## What's in this directory

| File | Purpose |
|------|---------|
| `wrangler.jsonc` | Single Worker entry, `LOADER` worker_loaders binding, `MCP_OBJECT` DO binding for `ReproMCP`, `WRAP` var. |
| `src/host.ts` | The host Worker. `ReproMCP` extends `McpAgent` and registers one tool, `repro_elicit`. |
| `src/child.ts` | Documentation-only TypeScript form of the child Worker. The runtime injects the equivalent JS as `CHILD_MODULE_SOURCE` in `host.ts`. |
| `verify.mjs` | Node driver: spawns `wrangler dev`, drives an MCP client, captures the result and wrangler logs. |
| `package.json` | Local-only — **NOT** part of the gmail-mcp pnpm workspace. Install with `--ignore-workspace`. |
| `expected-output-before.txt` | Captured failing output (`WRAP=`) — must contain `"Agent was not found in send"`. |
| `expected-output-after.txt` | Captured successful output (`WRAP=1`) — elicit round-tripped. |

## What the tool does

`repro_elicit`:

1. Logs `BEFORE-LOADER ALS=set/unset` from the tool body (this is
   inside the original `agentContext.run` frame; should always be `set`).
2. Loads a child Worker via `env.LOADER.get(...)` whose source is
   `CHILD_MODULE_SOURCE`. The child has one method: `run(bridge)` that
   calls `bridge.runCallback()` over Workers RPC.
3. Constructs an `RpcTarget` (`HostCallbackBridge`) whose
   `runCallback()` body:
   - logs `INSIDE-CALLBACK ALS=set/unset`,
   - calls `await this.server.server.elicitInput({...})`.
4. If `env.WRAP === "1"`, wraps that body in
   `agentContext.run({ agent: this, ... }, ...)`.
5. Logs `ELICIT-RESULT ...` on success or
   `ELICIT-ERROR <name>: <message>` on failure.

## Why a Worker-Loader child triggers the bug

The child Worker invokes `bridge.runCallback()` via Workers RPC. The
host receives the RPC as a fresh entrypoint invocation; the Node
`AsyncLocalStorage` instance behind `agentContext` has no frame at the
entrypoint root. Without an explicit `agentContext.run(...)` re-entry
the host-side callback runs with `agentContext.getStore() === undefined`.

This is exactly the same pattern `@cloudflare/codemode`'s
`DynamicWorkerExecutor` uses — it passes `ToolDispatcher` (an
`RpcTarget`) to the child via `evaluate(dispatchers)` and the child
invokes `dispatcher.call(...)` back. Hence the production manifestation
in `packages/scaffold/src/mcp-agent-factory.ts`.

## Running it

> The harness is **outside** the gmail-mcp pnpm workspace
> (`pnpm-workspace.yaml` only globs `packages/*`,
> `packages/providers/*`, `packages/spec-loaders/*`, `apps/*`). Install
> with `--ignore-workspace` to keep its `node_modules` independent.

### 1. Install

```sh
cd scripts/repros/elicit-als-context/minimal
pnpm install --ignore-workspace
# (or `npm install` — anything that produces a local `node_modules` works.)
```

### 2. Reproduce the failure (`WRAP=`)

```sh
WRAP= node verify.mjs
```

Expected: tail of wrangler stderr/stdout contains
`Agent was not found in send`. The tool returns `ERROR ... Agent was not found in send`. See
`expected-output-before.txt`.

### 3. Observe the fix (`WRAP=1`)

```sh
WRAP=1 node verify.mjs
```

Expected: the MCP client receives the elicit prompt, replies `{ ok: true }`,
and the tool returns `OK { ... }`. No `Agent was not found in send`
appears. See `expected-output-after.txt`.

### Manual driving (alternative)

If `verify.mjs` can't drive the harness in your environment (e.g.
`wrangler dev` is slow to start), drive it manually:

```sh
WRAP= pnpm dev    # or WRAP=1 pnpm dev
```

then point [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
at `http://localhost:<port>/mcp` and call `repro_elicit`. Inspector
must declare elicitation capability and provide a stub elicit handler.

## What to look for in logs

| Log line | Meaning |
|----------|---------|
| `BEFORE-LOADER ALS=set` | Tool body is inside `agentContext`. Always expected. |
| `INSIDE-CALLBACK ALS=unset` | Bug present — the host-side callback ran on a fresh RPC entry. |
| `INSIDE-CALLBACK ALS=set` | Wrap is active or the upstream package has fixed this. |
| `ELICIT-ERROR Error: Agent was not found in send` | The bug at full strength. |
| `ELICIT-RESULT {"action":"accept", ...}` | Round-trip succeeded. |

## Known issues

- `wrangler dev` startup is slow inside fresh sandboxes. `verify.mjs`
  waits up to 60 s for `Ready on`. If startup exceeds that, increase
  `READY_TIMEOUT_MS` in `verify.mjs` or fall back to manual driving.
- The repro intentionally pins `compatibility_date` and
  `nodejs_compat` to match `apps/gmail/wrangler.jsonc`. Older
  runtimes lack `WorkerLoader` entirely — Worker Loader requires a
  recent runtime build.
- The harness does not exercise OAuth, OpenAPI, or `@cloudflare/codemode`.
  We use raw `env.LOADER` + an `RpcTarget` so the cause-and-effect is
  visible in <100 lines of host code. The same bug manifests through
  `DynamicWorkerExecutor` in production because it relies on the same
  RPC mechanism.
- The verify-mode MCP client returns `{ action: "decline" }` rather
  than `{ action: "accept", content: {...} }`. This is intentional:
  the MCP SDK validates `accept`-shaped responses with an ajv-compiled
  schema, and ajv calls `new Function(...)`, which the Workers runtime
  blocks (`Code generation from strings disallowed for this context`).
  That is **unrelated** to the ALS bug under test — the round-trip
  `server.elicitInput` -> client -> server -> tool-return that proves
  the fix still happens for declines. If you drive the harness from
  MCP Inspector or any browser/Node client where ajv is unconstrained,
  you can return `accept` with content and observe the same successful
  round-trip.
