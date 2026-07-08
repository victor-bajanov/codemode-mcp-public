# codemode-pattern regression guard — agents#1734 + codemode 0.3.8

Sibling of `../minimal/`. Asserts that two upstream fixes hold for the
`openApiMcpServer({ executor, request })` scaffold shape used by production
DO-based MCP agents:

1. **agents#1734 (ALS fix):** `delete_thing` round-trips via a Worker-Loader
   child callback — `elicitInput` succeeds from the host-side `request` hook
   **without** an `agentContext.run` re-entry. The transport now retains its
   owning `McpAgent`, so `"Agent was not found in send"` must NOT appear.

2. **codemode 0.3.8 (validator-default fix):** `openApiMcpServer` now defaults
   to the MCP SDK's `CfWorkerJsonSchemaValidator` (no `new Function` codegen).
   The accept path validates **without** a manual `_jsonSchemaValidator` swap, so
   `"Code generation from strings disallowed"` must NOT appear.

Both fixes are exercised together. If either error marker appears, the run is a
regression.

## How this differs from `../minimal/`

The minimal harness inlines a single `repro_elicit` tool and demonstrates the
ALS bug alone. This harness layers a `scaffoldMini` factory that mirrors the
production `openApiMcpServer({ executor, request })` shape — same RPC severance
pattern, same tool-dispatch flow, same accept-path validator — so a regression
in either fix is caught in the realistic production shape.

## Mapping to production code

| Realistic harness file | Mirrors production file |
|------------------------|--------------------------|
| `src/host.ts` (no wrap, no validator swap in `init()`) | `packages/scaffold/src/mcp-agent-factory.ts` (both couplings removed in this upgrade) |
| `src/elicit-gate.ts` (`onRequest(ctx, server)`) | `packages/scaffold/src/request-handler.ts` (`handleUpstreamRequest(args)`) |
| `src/scaffold-mini.ts` (`scaffoldMini`, `makeLoaderExecutor`, `ToolDispatcher` + CfWorker default) | `openApiMcpServer` + `DynamicWorkerExecutor` from `@cloudflare/codemode` (Workers-safe validator now the default) |

## What's in this directory

| File | Purpose |
|------|---------|
| `wrangler.jsonc` | Single Worker entry, `LOADER` worker_loaders binding, `MCP_OBJECT` DO binding for `ReproMCP`. |
| `src/host.ts` | The host Worker. `ReproMCP.init()` builds the scaffold-mini server with no `agentContext.run` wrap and no manual validator swap — both are now the correct defaults. |
| `src/scaffold-mini.ts` | Tiny analog of `openApiMcpServer({ spec, executor, request })`. Applies `CfWorkerJsonSchemaValidator` by default (mirroring codemode 0.3.8). |
| `src/elicit-gate.ts` | Tiny analog of `handleUpstreamRequest`. For `delete_thing` gates on `server.server.elicitInput(...)`; for `list_things` returns immediately. Logs `INSIDE-CALLBACK ALS=unset` — expected since no wrap is applied. |
| `verify.mjs` | Node driver: spawns `wrangler dev`, drives an MCP client that calls `delete_thing`, asserts fixed behavior. One env toggle controls whether validation is exercised. |
| `package.json` | Local-only — **NOT** part of the pnpm workspace. Install with `--ignore-workspace`. |
| `expected-output-decline-fixed.txt` | Captured passing output: decline path — `tool-success`, no ALS error (agents#1734 guard). |
| `expected-output-accept-fixed.txt` | Captured passing output: accept path — `tool-success`, no ALS error, no AJV error (agents#1734 + codemode 0.3.8 guard). |

## Running it

> The harness is **outside** the pnpm workspace. Install with
> `--ignore-workspace` to keep its `node_modules` independent.

### Install

```sh
cd scripts/repros/elicit-als-context/codemode-pattern
pnpm install --ignore-workspace
```

### Run the two regression scenarios

```sh
# Scenario 1: decline path (elicit round-trips, no validation exercised)
node verify.mjs

# Scenario 2: accept path (elicit round-trips and SDK validates the response)
TRIGGER_VALIDATION=1 node verify.mjs
```

Both must exit 0. Compare output against `expected-output-decline-fixed.txt` and
`expected-output-accept-fixed.txt` respectively. The `PASS:` line is the key
indicator; port numbers and timing values will differ.

### Manual driving (alternative)

If `verify.mjs` can't drive the harness (e.g. `wrangler dev` is slow to start),
drive it manually:

```sh
pnpm dev
```

then point [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
at `http://localhost:<port>/mcp` and call `delete_thing`. Inspector must declare
elicitation capability and provide a stub elicit handler.

## What to look for in logs

| Log line | Meaning |
|----------|---------|
| `BEFORE-LOADER op=delete_thing` | `request` hook entered; the child dispatch is about to start. |
| `INSIDE-CALLBACK op=delete_thing ALS=unset` | Host-side callback ran on a fresh RPC entry without ALS re-entry — **expected** with agents#1734. Elicit succeeds regardless because the transport now retains its owning McpAgent. |
| `ELICIT-RESULT {"action":"decline"}` | Decline path round-tripped — Scenario 1 success marker. |
| `ELICIT-RESULT {"action":"accept","content":...}` | Accept path round-tripped — Scenario 2 success marker. |
| **`Agent was not found in send`** | **REGRESSION** — agents#1734 fix has regressed. Must NOT appear. |
| **`Code generation from strings disallowed for this context`** | **REGRESSION** — codemode 0.3.8 validator default has regressed. Must NOT appear. |

## Why a Worker-Loader child triggers the ALS gap (historical context)

The dispatcher is an `RpcTarget`. The child Worker invokes
`dispatcher.call(...)` via Workers RPC. The host receives the RPC as a
fresh entrypoint invocation; the `AsyncLocalStorage` instance behind
`agentContext` has no frame at the entrypoint root. Without an explicit
`agentContext.run(...)` re-entry the host-side callback ran with
`agentContext.getStore() === undefined` — causing the transport to throw
`"Agent was not found in send"`.

**agents#1734** fixed this by making the transport retain a direct reference to
its owning `McpAgent` rather than reading it from ALS at send time. The
`agentContext.run` wrap is therefore no longer needed and has been removed from
both this harness and from `packages/scaffold/src/mcp-agent-factory.ts`.

## Why AJV broke under Workers (historical context)

`AjvJsonSchemaValidator` (the prior SDK default) compiled each schema into a
JavaScript function at validation time using `new Function(...)`. The Cloudflare
Workers runtime blocks `new Function` for security reasons. The MCP SDK ships an
alternative `CfWorkerJsonSchemaValidator`
(`@modelcontextprotocol/sdk/validation/cfworker`) backed by `@cfworker/json-schema`,
which interprets schemas at runtime without codegen.

**codemode 0.3.8** made `openApiMcpServer` default to this Workers-safe validator.
The `_jsonSchemaValidator` field swap is therefore no longer needed and has been
removed from `packages/scaffold/src/mcp-agent-factory.ts`. This harness's
`scaffoldMini` mirrors that default (it applies `CfWorkerJsonSchemaValidator`
unconditionally on construction).

## Known issues / sandbox/CI environment notes

- `wrangler dev` startup is slow inside fresh sandboxes. `verify.mjs` waits up
  to 60 s for `Ready on`. If startup exceeds that, increase `READY_TIMEOUT_MS`
  in `verify.mjs` or fall back to manual driving.
- The repro pins `compatibility_date` and `nodejs_compat`. Older runtimes lack
  `WorkerLoader` entirely — Worker Loader requires a recent runtime build.
- In sandboxed environments without network access to npm or without a recent
  Workers runtime build, `pnpm install` and `wrangler dev` can fail or hang. The
  committed `expected-output-*.txt` files capture what *should* be observed and
  serve as the documentation of the regression guards' expected signatures.
