// `agents` and `@cloudflare/codemode` are pinned to exact versions in
// package.json — bumps can change McpAgent lifecycle behaviour and the
// codemode executor/openApiMcpServer contracts that the request-handler
// interception chain relies on. When upgrading:
//   1. bump the pin in every manifest that declares it
//   2. run `pnpm install`
//   3. inspect node_modules/@cloudflare/codemode/dist/*.d.ts to confirm
//      openApiMcpServer({spec,executor,description,request}), the request
//      callback's (options, context) shape, and the executor injection
//      contract still hold
//   4. run the full test suite — focus on request-handler.test.ts and the
//      mcp-agent-factory tests
//   5. manual smoke: /authorize → tool call → audit emission, plus the
//      elicit accept/decline/cancel/timeout matrix on Claude Code and MCP
//      Inspector (the only clients that support elicitation), and confirm
//      the regression repro at scripts/repros/elicit-als-context/ still
//      asserts the fixed behavior.

/* AGENTS-INTERNALS-COUPLINGS — none remain as of agents@0.17.1 / codemode@0.4.2.
 *
 * History (all three couplings now resolved upstream):
 *  1. transport.send monkey-patch (cc-elicit no-channel silent drop) —
 *     removed when its fix landed in agents 0.12.4 (PR #1514).
 *  2. agentContext.run re-entry across Worker-Loader child→host RPC —
 *     removed here; fixed upstream by agents#1734 (transport retains its
 *     owning McpAgent, so server-initiated elicit works without ALS re-entry).
 *  3. Server._jsonSchemaValidator swap (codemode forwarding gap) — removed
 *     here; codemode 0.3.8 defaults openApiMcpServer to the MCP SDK's
 *     Workers-safe validator (agents#1555 / codemode#1491).
 *
 * The MCP request id is now threaded into elicitInput as relatedRequestId via
 * codemode's (options, context) request callback (codemode#1793, agents#1510).
 */

import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { DynamicWorkerExecutor } from "@cloudflare/codemode";
import { openApiMcpServer } from "@cloudflare/codemode/mcp";
import { z } from "zod";
import type { ApiProvider } from "./api-provider";
import { annotateSpecWithSurfaceReview } from "./annotate-spec";
import { buildProviderDocs, type DocSection } from "./descriptions/docs";
import {
  buildCompactExecuteDescription,
  COMPACT_SEARCH_DESCRIPTION,
  DOCS_TOOL_DESCRIPTION,
} from "./descriptions/compact";
// Moved to descriptions/compact.ts (review: keeps the battery's import free of
// this module's cloudflare:workers chain); re-exported for compatibility.
export { DOCS_TOOL_DESCRIPTION } from "./descriptions/compact";
import {
  ACCESS_CONVENTION_BLOCK,
  BODY_MODES_BLOCK,
  ENVELOPE_BLOCK,
  RATE_LIMIT_BLOCK,
  STAGING_BLOCK,
  buildSearchStrategyBlock,
} from "./descriptions/fragments";

// Re-exported from ./descriptions/fragments (moved there in Task 1 of the
// description-budget plan) so existing import sites and tests keep working.
export { RESPONSE_CHAR_CAP, buildSearchStrategyBlock } from "./descriptions/fragments";
import { resolveEndpoints } from "./config";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "./request-handler";
import { ToolError } from "./elicit";
import type { TokenBrokerStub } from "./token-broker";
import { createGetFileCapability } from "./staging/getfile-capability";
import { createPutFileCapability } from "./staging/putfile-capability";
import {
  createStageFromUpstreamJsonCapability,
  type StageRequestOpts,
  type UpstreamRequestResult,
} from "./staging/stage-from-upstream-json";

export interface ProviderEnv extends Record<string, unknown> {
  LOADER: WorkerLoader;
  OAUTH_KV: KVNamespace;
  TOKEN_BROKER: DurableObjectNamespace;
  DEPLOYMENT_NAME: string;
  /** wrangler.jsonc `vars.ALLOW_PII_IN_LOGS` — `"true"` opts back in to
   *  raw PII in audit lines and DEBUG-ELICIT output. Default redacts. */
  ALLOW_PII_IN_LOGS?: string;
  /** wrangler.jsonc `vars.DEBUG_ELICIT` — `"true"` enables the
   *  DEBUG-ELICIT log sites (Step 3 / M2). Default disabled. */
  DEBUG_ELICIT?: string;
  // Staging (optional — apps without these bindings simply won't expose the tool):
  STAGING_R2?: R2Bucket;
  STAGING_D1?: D1Database;
  STAGING_UPLOAD_TTL_SECONDS?: string;
  STAGING_FETCH_TTL_SECONDS?: string;
  STAGING_MAX_BYTES?: string;
  STAGING_UPLOAD_ORIGIN?: string;     // e.g., "https://xero.example.com"; required when staging is enabled
}

/**
 * LEGACY — no longer feeds any client-visible description: init() passes no
 * `description` to openApiMcpServer and replaces the search/execute text with
 * the compact builders; the full content now ships via buildProviderDocs
 * (descriptions/docs.ts). Kept for reference and pre-existing tests only;
 * candidate for deletion once its remaining test consumers are repointed.
 *
 * Historically built the `description` argument this factory passed to
 * `openApiMcpServer`. Pure: depends only on `provider.executeHint`,
 * `provider.attachmentHint`, `provider.downloadHint`, and the boolean
 * `stagingEnabled`.
 *
 * Assembled order (issue #41). Rationale, stated honestly: buildSearchStrategyBlock
 * is a FIXED-size block (~1KB — two interpolated integers, not the operation
 * list itself) despite the "measured from this spec" framing below, so moving
 * STAGING_BLOCK ahead of it only buys about that much. The real fix for #41 was
 * splitting Gmail's download guidance out of the provider-owned attachmentHint
 * (previously spliced dead last) into `downloadHint`, spliced right after
 * STAGING_BLOCK: on the Gmail provider this moves that guidance from ~11.9KB
 * deep in the assembled description to ~5.3KB deep — the actual distance a
 * truncating client saves. Exact offsets vary per provider/spec; these are
 * measured Gmail numbers, not a general bound.
 *   1. ENVELOPE_BLOCK             [always]
 *   2. RATE_LIMIT_BLOCK           [only if provider.readRateLimit is set]
 *   3. STAGING_BLOCK              [only if stagingEnabled]
 *   4. downloadHint, verbatim     [only if stagingEnabled + downloadHint set — sits next to Mode A/B]
 *   5. search-strategy block      [always — sizes measured from this spec]
 *   6. ACCESS_CONVENTION_BLOCK    [always — every spec is annotated]
 *   7. executeHint                [provider-owned]
 *   8. BODY_MODES_BLOCK           [always]
 *   9. attachmentHint, wrapped    [only if stagingEnabled + attachmentHint set — upload snippet]
 */
export function buildExecuteAddendum(
  provider: Pick<
    ApiProvider,
    "executeHint" | "attachmentHint" | "downloadHint" | "readRateLimit" | "spec" | "surfaceReview"
  >,
  stagingEnabled: boolean,
  annotatedSpec?: unknown,
): string {
  // Prefer the already-annotated spec from init(); fall back to annotating
  // here so the stated sizes always describe what the client will actually see.
  const measured =
    annotatedSpec ??
    (provider.spec
      ? annotateSpecWithSurfaceReview(
          provider.spec as unknown as Record<string, unknown>,
          provider.surfaceReview ?? {},
        )
      : undefined);
  return (
    "\n" + ENVELOPE_BLOCK +
    (provider.readRateLimit ? RATE_LIMIT_BLOCK : "") +
    (stagingEnabled ? STAGING_BLOCK : "") +
    (stagingEnabled && provider.downloadHint ? "\n" + provider.downloadHint + "\n" : "") +
    (measured ? buildSearchStrategyBlock(measured) : "") +
    ACCESS_CONVENTION_BLOCK +
    (provider.executeHint ? "\n" + provider.executeHint + "\n" : "") +
    BODY_MODES_BLOCK +
    (stagingEnabled && provider.attachmentHint
      ? "## Upstream-specific attachment snippet for this server\n\n" + provider.attachmentHint + "\n"
      : "")
  );
}

/**
 * Builds the `{ name: "__stagingHost", fns }` capability object handed to
 * codemode's executor. Pure positional-arg dispatch glue, extracted out of
 * `createProviderMcpAgent`'s `init()` so it is unit-testable without a live
 * `WorkerLoader` — `init()` constructs the three capability closures (which DO
 * need real D1/R2 bindings) and passes them in here.
 *
 * codemode 0.4.x dispatches every tool call positionally, so:
 *   __stagingHost.getFile(handle, token)
 *   __stagingHost.putFile(bytesBase64, contentType, filename)
 *   __stagingHost.stageFromUpstreamJson(opts, dataField, encoding?, filename?, contentType?)
 *   __stagingHost.stageFromAttachment(...)  — same signature, alias (issue #41: agents
 *     grep for task-shaped names and miss the mechanism-shaped original)
 * arrive as positional args without any per-provider flag.
 */
export function buildStagingHostFns(caps: {
  getFile: ReturnType<typeof createGetFileCapability>;
  putFile: ReturnType<typeof createPutFileCapability>;
  stageFromUpstreamJson: (
    requestOpts: StageRequestOpts,
    dataField: string,
    dataEncoding?: "base64url" | "base64",
    filenameOverride?: string | null,
    contentTypeOverride?: string | null,
  ) => Promise<unknown>;
}): { name: "__stagingHost"; fns: Record<string, (...args: unknown[]) => Promise<unknown>> } {
  const stageFromUpstreamJsonFn = (...args: unknown[]) =>
    caps.stageFromUpstreamJson(
      args[0] as StageRequestOpts,
      args[1] as string,
      (args[2] as "base64url" | "base64" | undefined) ?? "base64url",
      (args[3] as string | null | undefined) ?? null,
      (args[4] as string | null | undefined) ?? null,
    );
  return {
    name: "__stagingHost",
    fns: {
      getFile: (...args: unknown[]) => caps.getFile(args[0] as string, args[1] as string),
      putFile: (...args: unknown[]) =>
        caps.putFile(
          args[0] as string,
          args[1] as string,
          (args[2] as string | null | undefined) ?? null,
        ),
      stageFromUpstreamJson: stageFromUpstreamJsonFn,
      stageFromAttachment: stageFromUpstreamJsonFn,
    },
  };
}

/**
 * The unique seam in codemode 0.4.2's generated sandbox code, right at the
 * close of its `const codemode = { spec, request? }` object literal. Every
 * fixed template line before it, and the LLM's own code after it (embedded
 * inside the `__truncateResponse(await (…)())` call), so the FIRST occurrence
 * is always the generated one. Pinned against the installed bundle by
 * __tests__/codemode-cap-drift.test.ts.
 */
export const CODEMODE_SANDBOX_ANCHOR = "\n};\nreturn __truncateResponse(";

/**
 * Best-effort `codemode.docs()` alias (spec D6). The sandbox's `codemode` is
 * a `const` local of the generated arrow body, shadowing anything the
 * executor could provide — so the only way to put `docs` ON that object is a
 * string patch at the anchor above, turning
 *   `const codemode = { spec, request };`
 * into
 *   `const codemode = { spec, request, docs: … };`
 * On no match (codemode upgrade moved the seam) the code is forwarded
 * unpatched and `__docsHost.docs()` — the canonical, patch-free path —
 * still works.
 */
export function patchCodemodeDocsAlias(code: string): string {
  const idx = code.indexOf(CODEMODE_SANDBOX_ANCHOR);
  if (idx === -1) return code;
  return (
    code.slice(0, idx) +
    ",\n  docs: async (section) => await __docsHost.docs(section)" +
    code.slice(idx)
  );
}

/**
 * Builds the `{ name: "__docsHost", fns }` capability handed to codemode's
 * executor — positional-dispatch glue in the same shape as
 * buildStagingHostFns, and the guaranteed sandbox path to the docs text
 * (`codemode.docs` above is the best-effort sugar over it).
 */
export function buildDocsHostFns(
  docs: (section?: DocSection) => string,
): { name: "__docsHost"; fns: Record<string, (...args: unknown[]) => Promise<unknown>> } {
  return {
    name: "__docsHost",
    fns: {
      // args[0] == null also catches the JSON-marshalled `undefined` from a
      // no-arg `codemode.docs()` — the sandbox RPC serialises it to `null`.
      docs: async (...args: unknown[]) =>
        docs(args[0] == null ? undefined : (args[0] as DocSection)),
    },
  };
}

/** Version reported in MCP `serverInfo`. Single source of truth: the field
 *  initializer below and the openApiMcpServer instance that replaces it in
 *  init() must agree, or the advertised version depends on init() timing.
 *  That agreement is enforced — see "advertises the same identity before and
 *  after init()" in __tests__/mcp-agent-factory.test.ts, which reads both
 *  through an MCP client rather than trusting either call site.
 *  Kept at the repo's own 0.1.0 rather than codemode's 1.0.0 default — these
 *  servers make no 1.0 stability promise. */
const SERVER_VERSION = "0.1.0";

/** Returns a constructor suitable for use as a Durable Object class.
 *  The returned class extends `McpAgent` and is parameterised by `provider`. */
export function createProviderMcpAgent<
  P extends Record<string, unknown>,
  Env extends ProviderEnv = ProviderEnv,
>(provider: ApiProvider<P, Env>) {
  return class ProviderMCP extends McpAgent<Env, Record<string, never>, P> {
    server: McpServer = new McpServer({
      name: provider.name,
      version: SERVER_VERSION,
    });

    async init(): Promise<void> {
      const baseExecutor = new DynamicWorkerExecutor({
        loader: this.env.LOADER,
        timeout: 70_000,
      });

      // CODEMODE 0.4.2 capability-injection contract (re-verify by inspecting
      // node_modules/@cloudflare/codemode/dist/*.{d.ts,js} on each bump):
      //
      //   • `DynamicWorkerExecutor` exposes ONLY `execute(code, providersOrFns)`.
      //     There is no `registerCapability`, no constructor-level capabilities
      //     option, and no per-instance namespace registry.
      //   • Host capabilities are passed as `ResolvedProvider[]` at the
      //     execute() call-site. Each becomes a sandbox global named after
      //     `provider.name`.
      //   • `openApiMcpServer` controls its own call-sites: the `execute` MCP
      //     tool internally invokes
      //       executor.execute(code, [{ name: "__openapiHost", fns: { request } }])
      //     with a fixed providers array. There is no public hook to extend
      //     that array.
      //
      // To add a SECOND capability (`__stagingHost`) we wrap the executor: the
      // wrapped `execute()` forwards to the underlying executor but appends
      // `__stagingHost` to the providers array (only when staging bindings are
      // configured). This is the minimum surface change and avoids forking
      // openApiMcpServer.
      //
      // On preludes: codemode 0.4.2 DOES have a sandbox prelude (the fixed
      // template createOpenApiSandboxCode emits before the LLM's code), but
      // nothing we inject through it can reach the `const codemode = {...}`
      // local that shadows any executor-level provider of the same name — so
      // extending `codemode.*` itself requires the string patch applied by
      // patchCodemodeDocsAlias at CODEMODE_SANDBOX_ANCHOR (see both above).
      // Capabilities that live under their own names (__stagingHost,
      // __docsHost) need no patch at all; LLM code invokes them directly and
      // base64-decodes `bytesBase64` itself.
      // Gate requires STAGING_UPLOAD_ORIGIN as well: putFile populates its
      // `fetch_url` return field from it. In every deployment that has D1+R2
      // STAGING_UPLOAD_ORIGIN is already present (it gates register-tool too),
      // so the tightened gate is observationally a no-op for current envs.
      // The late-bound `buildUpstreamArgs` is referenced through
      // `buildUpstreamArgsRef` by the staging IIFE — see that indirection
      // further down for why it can't simply be assigned inline.
      // putFileCapability is hoisted out of the staging IIFE so it can be
      // threaded into HandleArgs.putFile (enables returnAs:"stage" in the
      // request handler) AND consumed by the stageFromUpstreamJson sandbox
      // capability constructed below. Same instance — single source of truth.
      let putFileCapability:
        | ReturnType<typeof createPutFileCapability>
        | undefined;
      // Late binding: stageFromUpstreamJson's upstreamRequest closure needs
      // `buildUpstreamArgs`, which itself closes over `putFileCapability`
      // (set inside the IIFE). To avoid TDZ, the closure dereferences this
      // ref at call time. The ref is assigned synchronously below — long
      // before sandbox code can invoke __stagingHost.stageFromUpstreamJson.
      const buildUpstreamArgsRef: { current: (ctx: UpstreamCtx) => HandleArgs<P> } = {
        current: () => {
          throw new Error("buildUpstreamArgs not yet initialised");
        },
      };
      const stagingProvider: {
        name: string;
        fns: Record<string, (...args: unknown[]) => Promise<unknown>>;
      } | null =
        this.env.STAGING_D1 && this.env.STAGING_R2 && this.env.STAGING_UPLOAD_ORIGIN
          ? await (async () => {
              const { readStagingConfig } = await import("./config.js");
              const config = readStagingConfig(this.env as unknown as Record<string, unknown>);
              const getFile = createGetFileCapability({
                STAGING_D1: this.env.STAGING_D1 as D1Database,
                STAGING_R2: this.env.STAGING_R2 as R2Bucket,
                config,
              });
              putFileCapability = createPutFileCapability({
                STAGING_D1: this.env.STAGING_D1 as D1Database,
                STAGING_R2: this.env.STAGING_R2 as R2Bucket,
                config,
                uploadOrigin: this.env.STAGING_UPLOAD_ORIGIN as string,
              });
              const putFile = putFileCapability;
              const stageFromUpstreamJson = createStageFromUpstreamJsonCapability({
                putFile,
                upstreamRequest: (ctx) =>
                  handleUpstreamRequest(
                    buildUpstreamArgsRef.current(ctx as unknown as UpstreamCtx),
                  ) as Promise<UpstreamRequestResult>,
              });
              return buildStagingHostFns({ getFile, putFile, stageFromUpstreamJson });
            })()
          : null;

      const stagingEnabled = stagingProvider !== null;
      // Annotate ONCE per Durable Object: the same object is handed to
      // openApiMcpServer and measured for the docs builder's search-strategy
      // section, so the sizes the docs state are the sizes of the spec the
      // client receives.
      const annotatedSpec = annotateSpecWithSurfaceReview(
        provider.spec as unknown as Record<string, unknown>,
        provider.surfaceReview,
      );
      // One source of truth for the full documentation (spec D1): the `docs`
      // tool, the codemode://docs resource, and the __docsHost sandbox
      // capability below all read this object.
      const providerDocs = buildProviderDocs(provider, stagingEnabled, annotatedSpec);
      const docsFn = (section?: DocSection): string => {
        if (section === undefined) return providerDocs.full;
        return (
          providerDocs.sections[section] ??
          `Section "${section}" is not applicable to this server. Available sections: ` +
            `${Object.keys(providerDocs.sections).join(", ")}.`
        );
      };
      const docsProvider = buildDocsHostFns(docsFn);

      // Wrap unconditionally: __docsHost is appended to EVERY sandbox run
      // (search included — codemode passes the array form for both tools),
      // __stagingHost only when staging bindings exist, and the code string is
      // alias-patched (best-effort, spec D6) before forwarding.
      const executor = {
        execute: (
          code: string,
          providersOrFns:
            | Array<{ name: string; fns: Record<string, (...args: unknown[]) => Promise<unknown>> }>
            | Record<string, (...args: unknown[]) => Promise<unknown>>,
        ) => {
          // openApiMcpServer always passes an array form; the Record form
          // is the legacy convenience API. Append only when array form.
          if (Array.isArray(providersOrFns)) {
            return baseExecutor.execute(patchCodemodeDocsAlias(code), [
              ...providersOrFns,
              ...(stagingProvider ? [stagingProvider] : []),
              docsProvider,
            ]);
          }
          return baseExecutor.execute(code, providersOrFns);
        },
      };
      // Single source of truth for the per-request HandleArgs object. Both
      // call sites (codemode `request` closure for execute(), and the
      // stageFromUpstreamJson sandbox capability) build their args via this
      // helper — keeps oauth/audit/env/putFile wiring consistent.
      //
      // Resolve userId once for both the request-handler accessor and the
      // broker DO address. When userId is missing we hand a throwing stub to
      // the handler rather than addressing the broker namespace at all. The
      // handler's own userIdAccessor-undefined check (request-handler.ts) is
      // the primary guard; this stub is the defence-in-depth that ensures a
      // future relaxation of that check can't accidentally route every
      // anonymous caller to a single shared `""` broker instance.
      const buildUpstreamArgs = (ctx: UpstreamCtx): HandleArgs<P> => {
        const resolvedUserId: string | undefined =
          (provider.audit?.principalIdAccessor?.(this.props as P)) ??
          (typeof (this.props as Record<string, unknown>).userId === "string"
            ? ((this.props as Record<string, unknown>).userId as string)
            : undefined);
        const broker: TokenBrokerStub = resolvedUserId
          ? (this.env.TOKEN_BROKER.get(
              this.env.TOKEN_BROKER.idFromName(resolvedUserId),
            ) as unknown as TokenBrokerStub)
          : {
              getOrRefreshAccessToken: () => {
                throw new ToolError(
                  "Cannot mint access token: principal has no userId",
                );
              },
            };
        return {
          ctx,
          spec: provider.spec,
          surfaceReview: provider.surfaceReview,
          props: this.props as P,
          apiBaseUrl: resolveEndpoints(provider, this.env as unknown as Record<string, unknown>).apiBaseUrl,
          deploymentName: this.env.DEPLOYMENT_NAME,
          server: this.server,
          env: this.env,
          oauth: {
            refreshTokenAccessor: (p) => p.refreshToken as string,
            userIdAccessor: () => resolvedUserId,
            broker,
          },
          ...(provider.requestHeaders
            ? { requestHeaders: provider.requestHeaders }
            : {}),
          ...(provider.readRateLimit ? { readRateLimit: provider.readRateLimit } : {}),
          ...(provider.elicitRenderers ? { elicitRenderers: provider.elicitRenderers } : {}),
          ...(putFileCapability ? { putFile: putFileCapability } : {}),
          audit: {
            waitUntil: this.ctx.waitUntil.bind(this.ctx),
            ...(provider.audit?.principalIdAccessor
              ? { principalIdAccessor: provider.audit.principalIdAccessor }
              : {}),
            ...(provider.audit?.contextAccessor
              ? { contextAccessor: provider.audit.contextAccessor }
              : {}),
          },
        };
      };
      buildUpstreamArgsRef.current = buildUpstreamArgs;

      this.server = openApiMcpServer({
        // Annotated, not raw: each operation's description states its own
        // availability and any request-time condition, so `search` surfaces
        // the gating where it is relevant instead of the executeHint carrying
        // it in every context window. The annotator is pure — `provider.spec`
        // is an imported JSON module shared process-wide, and mutating it
        // would corrupt every other consumer.
        spec: annotatedSpec,
        executor,
        // This instance replaces the McpServer field above, so its identity is
        // the one clients see in `serverInfo`. Without an explicit name the
        // library defaults to "openapi", which says nothing about which API is
        // behind it. `provider.name` is per-provider, not per-deployment —
        // gmail/gmail-dev/gmail-tester all report "gmail"; DEPLOYMENT_NAME is
        // what distinguishes those (it is what audit lines carry).
        name: provider.name,
        version: SERVER_VERSION,
        // No `description`: it only feeds codemode's oversized executeDescription,
        // which is replaced wholesale with the compact text right below.
        // codemode forwards the originating MCP request context as the second
        // arg (codemode#1793). `context.requestId` lets elicit route its
        // server-initiated message back through that request's POST stream.
        request: (ctx, context?: { requestId?: string | number }) =>
          handleUpstreamRequest({
            ...buildUpstreamArgs(ctx),
            ...(context?.requestId !== undefined ? { relatedRequestId: context.requestId } : {}),
          }),
      });

      // Replace codemode's oversized search/execute descriptions with the
      // compact, budgeted ones (spec D2/D3). `_registeredTools` is a private
      // SDK field and `update()` is safe pre-connect (`sendToolListChanged` is
      // `isConnected()`-guarded) — both facts pinned by
      // __tests__/codemode-cap-drift.test.ts.
      const registeredTools = (this.server as unknown as {
        _registeredTools?: Record<string, { update(u: { description?: string }): void }>;
      })._registeredTools;
      if (!registeredTools?.execute || !registeredTools?.search) {
        throw new Error(
          "codemode tool registry shape changed — see codemode-cap-drift.test.ts",
        );
      }
      registeredTools.execute.update({
        description: buildCompactExecuteDescription(
          provider,
          stagingEnabled,
          Object.keys(providerDocs.sections),
        ),
      });
      registeredTools.search.update({ description: COMPACT_SEARCH_DESCRIPTION });

      // The docs tool — UNCONDITIONAL (not staging-gated): it is the recovery
      // channel for everything the compact descriptions evict. `_meta` opts it
      // out of client-side ToolSearch deferral and raises its result-size cap.
      //
      // The `section` enum is narrowed to THIS provider's actual sections, not
      // the full DOC_SECTIONS vocabulary — a schema that admits "rate-limit"
      // on a server whose docs omit it promises a section the config doesn't
      // implement (claude.ai live-verification finding). Both the enum and the
      // sections are computed once per DO init, so they cannot drift apart.
      // The unvalidated sandbox path (__docsHost.docs / codemode.docs) keeps
      // the docsFn fallback text above as its out-of-vocabulary answer.
      const availableSections = Object.keys(providerDocs.sections) as [
        DocSection,
        ...DocSection[],
      ];
      this.server.registerTool(
        "docs",
        {
          description: DOCS_TOOL_DESCRIPTION,
          inputSchema: { section: z.enum(availableSections).optional() },
          _meta: {
            "anthropic/alwaysLoad": true,
            "anthropic/maxResultSizeChars": 100_000,
          },
        },
        async ({ section }: { section?: DocSection | undefined }) => ({
          content: [{ type: "text" as const, text: docsFn(section) }],
        }),
      );

      // Same text as a resource, for clients that @-mention resources instead
      // of spending a tool call. Must register pre-connect: registerResource
      // lazily registers the `resources` capability, which throws after a
      // transport is attached.
      this.server.registerResource(
        "docs",
        "codemode://docs",
        {
          title: `${provider.displayName} — full codemode documentation`,
          mimeType: "text/markdown",
        },
        async (uri) => ({
          contents: [
            { uri: uri.href, mimeType: "text/markdown", text: providerDocs.full },
          ],
        }),
      );

      // Staging attachments — register the tool only when bindings are present.
      if (this.env.STAGING_D1 && this.env.STAGING_R2 && this.env.STAGING_UPLOAD_ORIGIN) {
        const { registerFileHandleTool } = await import("./staging/index.js");
        const { readStagingConfig } = await import("./config.js");
        const tool = registerFileHandleTool({
          STAGING_D1: this.env.STAGING_D1,
          config: readStagingConfig(this.env as unknown as Record<string, unknown>),
          uploadOrigin: this.env.STAGING_UPLOAD_ORIGIN,
          // Compact body (spec D3): the provider-specific Step-3 snippet moves
          // to the docs tool's "attachments" section; attachmentHint still
          // feeds the docs builder above.
          descriptionMode: "compact",
          ...(provider.attachmentHint ? { attachmentHint: provider.attachmentHint } : {}),
        });
        this.server.registerTool(
          tool.name,
          {
            description: tool.description,
            inputSchema: tool.inputShape,
          },
          async (input: unknown) => {
            const out = await tool.handler((input ?? {}) as never);
            return {
              content: [{ type: "text", text: JSON.stringify(out) }],
            };
          },
        );
      }
    }
  };
}
