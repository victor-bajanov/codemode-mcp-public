# codemode-pattern repro — `agentContext` ALS gap **and** AJV-validator-default gap, scaffold-shaped

Sibling of `../minimal/`. Reproduces **two independent bugs** that both
need fixing for elicit-with-accept to work end-to-end on a DO-based MCP
agent that uses `@cloudflare/codemode`-style scaffolding under the
Workers runtime:

1. **ALS gap.** A DO-based `McpAgent` whose tools are dispatched
   through a Worker-Loader child isolate cannot perform server-initiated
   MCP requests (`server.elicitInput`, `createMessage`, `listRoots`)
   from a host-side callback the child invokes via Workers RPC.
   `StreamableHTTPServerTransport.send` reads the current agent from a
   host-side `AsyncLocalStorage` (`__DO_NOT_USE_WILL_BREAK__agentContext`).
   That store is empty inside the callback because child→host RPC
   arrives as a fresh entrypoint invocation with no ancestor in the
   original `agentContext.run(...)` call tree. The transport throws
   `"Agent was not found in send"`.

2. **AJV-validator-default gap.** Once the ALS gap is worked around and
   the elicit succeeds in reaching the client, the user's **accept**
   payload is then validated server-side. The MCP SDK's default
   `AjvJsonSchemaValidator` compiles validators by calling
   `new Function(...)`, which the Workers runtime forbids
   (`Code generation from strings disallowed for this context`). The
   accept path therefore throws even after the ALS fix — until the SDK's
   alternate `CfWorkerJsonSchemaValidator` (no codegen) is wired in.

Both bugs are independently toggleable in this harness.

## How this differs from `../minimal/`

The minimal harness inlines a single `repro_elicit` tool whose handler
hand-creates an `RpcTarget` and calls back via the loader. That's enough
to demonstrate the ALS bug, but it doesn't show that the production
shape — `openApiMcpServer({ executor, request })` — has the same hole,
nor does it exercise the AJV codepath.

The codemode-pattern harness layers a tiny `scaffoldMini` factory on top of
the same Worker-Loader plumbing. It mirrors the production
`packages/scaffold/src/mcp-agent-factory.ts` shape closely enough that
the wrap fix and validator swap are byte-equivalent to the production
patches.

## Mapping to production code

| Realistic harness file | Mirrors production file |
|------------------------|--------------------------|
| `src/host.ts` (the `wrap` + `scaffoldMini({ executor, request })` block + the `_jsonSchemaValidator` swap) | `packages/scaffold/src/mcp-agent-factory.ts` (`openApiMcpServer({ executor, request: (ctx) => agentContext.run(..., () => handleUpstreamRequest(...)) })` + the unconditional CfWorker swap) |
| `src/elicit-gate.ts` (`onRequest(ctx, server)`) | `packages/scaffold/src/request-handler.ts` (`handleUpstreamRequest(args)`) |
| `src/scaffold-mini.ts` (`scaffoldMini`, `makeLoaderExecutor`, `ToolDispatcher`) | `openApiMcpServer` + `DynamicWorkerExecutor` from `@cloudflare/codemode` (its `ToolDispatcher` RpcTarget pattern) |

## What's in this directory

| File | Purpose |
|------|---------|
| `wrangler.jsonc` | Single Worker entry, `LOADER` worker_loaders binding, `MCP_OBJECT` DO binding for `ReproMCP`, `WRAP` and `VALIDATOR` vars. |
| `src/host.ts` | The host Worker. `ReproMCP` extends `McpAgent`; in `init()` it builds the scaffold-mini server with `executor`, `request`, the optional `agentContext.run(...)` wrap, and the optional `_jsonSchemaValidator` swap. |
| `src/scaffold-mini.ts` | Tiny analog of `openApiMcpServer({ spec, executor, request })`. |
| `src/elicit-gate.ts` | Tiny analog of `handleUpstreamRequest`. For `delete_thing` it gates on `server.server.elicitInput(...)`; for `list_things` it returns immediately. |
| `verify.mjs` | Node driver: spawns `wrangler dev`, drives an MCP client that calls `delete_thing`, captures result and wrangler logs. Three env toggles control which scenario runs. |
| `package.json` | Local-only — **NOT** part of the gmail-mcp pnpm workspace. Install with `--ignore-workspace`. |
| `expected-output-als-bug.txt` | Captured failing output: `WRAP=` → ALS error. |
| `expected-output-als-fix-decline.txt` | Captured passing output: `WRAP=1` → decline path round-trips. |
| `expected-output-ajv-bug.txt` | Captured failing output: `WRAP=1 TRIGGER_VALIDATION=1` → AJV codegen blocked. |
| `expected-output-ajv-fix.txt` | Captured passing output: `WRAP=1 TRIGGER_VALIDATION=1 VALIDATOR=cfworker` → full happy path. |

## Toggle matrix

Three independent flags, off by default:

| Flag | Where read | What it does |
|------|------------|--------------|
| `WRAP=1` | host (via `--var`) | Apply the `agentContext.run(...)` wrap (ALS fix). |
| `TRIGGER_VALIDATION=1` | verify driver | Mock client returns `{action:"accept", content:{confirm:"yes"}}` instead of `{action:"decline"}` — i.e., gives the SDK something to validate, which fires the validator path. The SDK currently requires `action === 'accept' && content` to enter validation; either alone wouldn't suffice. |
| `VALIDATOR=cfworker` | host (via `--var`) | Replace the SDK's default `AjvJsonSchemaValidator` with `CfWorkerJsonSchemaValidator` (AJV-codegen fix). |

Resulting scenarios:

| `WRAP` | `TRIGGER_VALIDATION` | `VALIDATOR` | Expected outcome |
|---|---|---|---|
| `0` | (any) | (any) | `Agent was not found in send` (ALS bug) |
| `1` | `0` | (any) | `tool-success` — decline path |
| `1` | `1` | unset / `ajv` | `Code generation from strings disallowed` (AJV bug) |
| `1` | `1` | `cfworker` | `tool-success` — full accept happy path |

## Running it

> The harness is **outside** the gmail-mcp pnpm workspace. Install with
> `--ignore-workspace` to keep its `node_modules` independent.

### Install

```sh
cd scripts/repros/elicit-als-context/codemode-pattern
pnpm install --ignore-workspace
```

### Reproduce + observe each scenario

```sh
# Scenario 1: ALS bug
node verify.mjs

# Scenario 2: ALS fix, decline path (validation skipped)
WRAP=1 node verify.mjs

# Scenario 3: AJV bug (validator fires under default AJV)
WRAP=1 TRIGGER_VALIDATION=1 node verify.mjs

# Scenario 4: full happy path (CfWorker validator)
WRAP=1 TRIGGER_VALIDATION=1 VALIDATOR=cfworker node verify.mjs
```

Each invocation exits 0 if the observed behavior matches the expectation
for the given toggle combination. Compare the resulting wrangler-log
tails against `expected-output-*.txt` for the matching scenario.

### Manual driving (alternative)

If `verify.mjs` can't drive the harness in your environment (e.g.
`wrangler dev` is slow to start), drive it manually:

```sh
WRAP=1 VALIDATOR=cfworker pnpm dev
```

then point [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
at `http://localhost:<port>/mcp` and call `delete_thing`. Inspector
must declare elicitation capability and provide a stub elicit handler.

## What to look for in logs

| Log line | Meaning |
|----------|---------|
| `BEFORE-LOADER op=delete_thing ALS=set` | `request` hook entered while ALS still set. With WRAP=1 always; with WRAP unset depends on call timing. |
| `INSIDE-CALLBACK op=delete_thing ALS=unset` | ALS bug present — host-side callback ran on a fresh RPC entry without re-entry. |
| `INSIDE-CALLBACK op=delete_thing ALS=set` | Wrap is active. |
| `Agent was not found in send` | The ALS bug at full strength (when `WRAP` is unset). |
| `Code generation from strings disallowed for this context` | The AJV bug at full strength (when `TRIGGER_VALIDATION=1` and `VALIDATOR` is not `cfworker`). |
| `ELICIT-RESULT {"action":"decline"}` | Decline path round-tripped (Scenario 2). |
| `ELICIT-RESULT {"action":"accept","content":...}` | Accept path round-tripped (Scenario 4 — only succeeds with the validator swap). |

## Why a Worker-Loader child triggers the ALS bug

The dispatcher is an `RpcTarget`. The child Worker invokes
`dispatcher.call(...)` via Workers RPC. The host receives the RPC as a
fresh entrypoint invocation; the Node `AsyncLocalStorage` instance behind
`agentContext` has no frame at the entrypoint root. Without an explicit
`agentContext.run(...)` re-entry the host-side callback runs with
`agentContext.getStore() === undefined`.

This is exactly the same pattern `@cloudflare/codemode`'s
`DynamicWorkerExecutor` uses — it passes `ToolDispatcher` (an
`RpcTarget`) to the child via `evaluate(dispatchers)` and the child
invokes `dispatcher.call(...)` back. Hence the production manifestation
in `packages/scaffold/src/mcp-agent-factory.ts`.

## Why AJV breaks under Workers

`AjvJsonSchemaValidator` (the SDK default) compiles each schema into a
JavaScript function at validation time using `new Function(...)`. The
Cloudflare Workers runtime blocks `new Function` and `eval` for security
reasons. The MCP SDK ships an alternative `CfWorkerJsonSchemaValidator`
(`@modelcontextprotocol/sdk/validation/cfworker`) backed by
`@cfworker/json-schema`, which interprets schemas at runtime without
codegen. The SDK accepts a `jsonSchemaValidator` option on the `Server`
constructor — but `@cloudflare/codemode`'s `openApiMcpServer` doesn't
forward it, so we currently swap `_jsonSchemaValidator` directly on the
inner Server instance after construction.

## Known issues / sandbox/CI environment notes

- `wrangler dev` startup is slow inside fresh sandboxes. `verify.mjs`
  waits up to 60 s for `Ready on`. If startup exceeds that, increase
  `READY_TIMEOUT_MS` in `verify.mjs` or fall back to manual driving.
- The repro pins `compatibility_date` and `nodejs_compat`. Older
  runtimes lack `WorkerLoader` entirely — Worker Loader requires a
  recent runtime build.
- In sandboxed environments without network access to npm or without a
  recent Workers runtime build, `pnpm install` and `wrangler dev` can
  fail or hang. The committed `expected-output-*.txt` files capture
  what *would* be observed and serve as the documentation of the bugs'
  signatures.
