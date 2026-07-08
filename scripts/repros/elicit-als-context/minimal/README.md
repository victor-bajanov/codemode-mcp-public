# Minimal regression guard — elicit from a Worker-Loader child callback (agents#1734)

A standalone Cloudflare Worker that **asserts the fix** introduced in
`agents#1734`:

> A DO-based `McpAgent` whose tools are dispatched through a
> Worker-Loader child isolate can perform server-initiated MCP
> requests (`server.elicitInput`) from within a host-side callback
> that the child invokes via Workers RPC — WITHOUT any manual
> `agentContext.run(...)` re-entry wrap.
>
> Prior to agents#1734, `StreamableHTTPServerTransport.send` resolved
> the current agent through `AsyncLocalStorage`
> (`__DO_NOT_USE_WILL_BREAK__agentContext`). That store was empty
> inside child→host RPC callbacks because they arrive as fresh
> entrypoint invocations. The fix retains the McpAgent directly on
> the transport, so the store is no longer needed on the RPC
> re-entry path.

If this guard fails — `verify.mjs` exits non-zero, or
`"Agent was not found in send"` reappears in the output — the fix
has regressed and should be investigated before deploying.

## What's in this directory

| File | Purpose |
|------|---------|
| `wrangler.jsonc` | Single Worker entry, `LOADER` worker_loaders binding, `MCP_OBJECT` DO binding for `ReproMCP`. |
| `src/host.ts` | The host Worker. `ReproMCP` extends `McpAgent` and registers one tool, `repro_elicit`. |
| `verify.mjs` | Node driver: spawns `wrangler dev`, drives an MCP client, asserts the fixed behavior. |
| `package.json` | Local-only — **NOT** part of the pnpm workspace. Install with `--ignore-workspace`. |
| `expected-output-fixed.txt` | Reference output from a passing run against agents@0.17.1. |

## What the tool does

`repro_elicit`:

1. Logs `BEFORE-LOADER: entering tool body` from the tool body.
2. Loads a child Worker via `env.LOADER.get(...)` whose source is
   `CHILD_MODULE_SOURCE`. The child has one method: `run(bridge)` that
   calls `bridge.runCallback()` over Workers RPC.
3. Constructs an `RpcTarget` (`HostCallbackBridge`) whose
   `runCallback()` body:
   - logs `INSIDE-CALLBACK: invoking elicitInput (no wrap)`,
   - calls `await this.server.server.elicitInput({...})` directly,
     **without** any `agentContext.run(...)` wrapper.
4. Logs `ELICIT-RESULT ...` on success or
   `ELICIT-ERROR <name>: <message>` on failure.

## Why a Worker-Loader child is the right test vector

The child Worker invokes `bridge.runCallback()` via Workers RPC. The
host receives the RPC as a fresh entrypoint invocation, which is the
exact scenario that severed the `AsyncLocalStorage` chain before the fix.

This is the same pattern `@cloudflare/codemode`'s
`DynamicWorkerExecutor` uses in production — it passes a
`ToolDispatcher` (an `RpcTarget`) to the child via `evaluate(dispatchers)`
and the child invokes `dispatcher.call(...)` back. The production
manifestation was in `packages/scaffold/src/mcp-agent-factory.ts`.

## Running it

> The harness is **outside** the pnpm workspace
> (`pnpm-workspace.yaml` only globs `packages/*`,
> `packages/providers/*`, `packages/spec-loaders/*`, `apps/*`). Install
> with `--ignore-workspace` to keep its `node_modules` independent.

### 1. Install

```sh
cd scripts/repros/elicit-als-context/minimal
pnpm install --ignore-workspace
```

### 2. Run the regression guard

```sh
node verify.mjs
```

Expected: exit 0. The MCP client receives the elicit prompt, replies
`{ action: "decline" }`, and the tool returns `OK { ... }`. No
`Agent was not found in send` appears anywhere. See
`expected-output-fixed.txt`.

### Manual driving (alternative)

If `verify.mjs` can't drive the harness (e.g. `wrangler dev` is slow
to start), drive it manually:

```sh
pnpm dev
```

then point [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
at `http://localhost:<port>/mcp` and call `repro_elicit`. Inspector
must declare elicitation capability and provide a stub elicit handler.

## What to look for in logs

| Log line | Meaning |
|----------|---------|
| `BEFORE-LOADER: entering tool body` | Tool body entered. Always expected. |
| `INSIDE-CALLBACK: invoking elicitInput (no wrap)` | Callback running on the RPC re-entry; confirms no wrap is applied. |
| `ELICIT-RESULT {"action":"decline"}` | Round-trip succeeded. **Expected.** |
| `Agent was not found in send` | **REGRESSION** — agents#1734 fix has regressed. |
| `ELICIT-ERROR Error: Agent was not found in send` | **REGRESSION** — same regression, visible in tool return. |

## Known issues / notes

- `wrangler dev` startup can be slow inside fresh sandboxes. `verify.mjs`
  waits up to 60 s for `Ready on`. If startup exceeds that, increase
  `READY_TIMEOUT_MS` in `verify.mjs` or fall back to manual driving.
- The repro intentionally pins `compatibility_date` and
  `nodejs_compat` to match the production Worker config. Older
  runtimes lack `WorkerLoader` entirely — Worker Loader requires a
  recent runtime build.
- The harness does not exercise OAuth, OpenAPI, or `@cloudflare/codemode`.
  We use raw `env.LOADER` + an `RpcTarget` so the cause-and-effect is
  visible in <100 lines of host code.
- The verify-mode MCP client returns `{ action: "decline" }` rather
  than `{ action: "accept", content: {...} }`. This is intentional:
  the MCP SDK validates `accept`-shaped responses with an ajv-compiled
  schema, and ajv calls `new Function(...)`, which the Workers runtime
  blocks (`Code generation from strings disallowed for this context`).
  That is **unrelated** to the agents#1734 fix under test — the
  round-trip `server.elicitInput` -> client -> server -> tool-return
  still exercises the full elicit path. If you drive the harness from
  MCP Inspector or any browser/Node client where ajv is unconstrained,
  you can return `accept` with content and observe the same successful
  round-trip.
