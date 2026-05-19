// `agents` is pinned to an exact version in package.json — minor bumps
// to this package can change McpAgent lifecycle behaviour and silently
// break the request-handler interception chain. When upgrading:
//   1. bump the pin in every manifest that declares it
//   2. run `pnpm install`
//   3. run the full test suite — focus on request-handler.test.ts and
//      mcp-agent-factory tests
//   4. manual smoke: /authorize → tool call → audit emission, confirm
//      AUDIT log lines emit after a successful tool call (and the
//      Worker-Loader integration repro at
//      scripts/repros/elicit-als-context/codemode-pattern/ still
//      passes its toggle matrix).

/* AGENTS-INTERNALS-COUPLINGS (cloudflare/agents@0.12.4 — two couplings remain)
 *
 * 1. agentContext re-entry across Worker-Loader child→host RPC
 *    Site: import + agentContext.run wrap below.
 *    Upstream: cloudflare/agents#1490 (open)
 *
 * 2. Server._jsonSchemaValidator swap (codemode forwarding gap)
 *    Site: end of init(), `this.server.server._jsonSchemaValidator = …`
 *    Upstream: cloudflare/agents#1491 (open, codemode-side)
 *
 * Cleanup gate: when #1490 and #1491 close and we update `agents` past
 * the version that includes their fixes, drop both couplings on one
 * branch with a smoke pass across Claude Code, Inspector, and Claude
 * Desktop (accept / decline / cancel / timeout).
 *
 * History: the third coupling (transport.send monkey-patch for
 * cc-elicit no-channel silent drop) was removed when its upstream fix
 * landed in agents 0.12.4 (PR #1514).
 */

import { McpAgent } from "agents/mcp";
import { __DO_NOT_USE_WILL_BREAK__agentContext as agentContext } from "agents";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CfWorkerJsonSchemaValidator } from "@modelcontextprotocol/sdk/validation/cfworker";
import { DynamicWorkerExecutor } from "@cloudflare/codemode";
import { openApiMcpServer } from "@cloudflare/codemode/mcp";
import type { ApiProvider } from "./api-provider";
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

/** Returns a constructor suitable for use as a Durable Object class.
 *  The returned class extends `McpAgent` and is parameterised by `provider`. */
export function createProviderMcpAgent<
  P extends Record<string, unknown>,
  Env extends ProviderEnv = ProviderEnv,
>(provider: ApiProvider<P, Env>) {
  return class ProviderMCP extends McpAgent<Env, Record<string, never>, P> {
    server: McpServer = new McpServer({
      name: provider.name,
      version: "0.1.0",
    });

    async init(): Promise<void> {
      const baseExecutor = new DynamicWorkerExecutor({
        loader: this.env.LOADER,
        timeout: 70_000,
      });

      // CODEMODE 0.3.5 capability-injection contract (verified by inspecting
      // node_modules/@cloudflare/codemode/dist/{executor-C-DgAHLS,mcp}.{d.ts,js}):
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
      // Limitation: codemode 0.3.5 has no sandbox prelude that runs before LLM
      // code in the OpenAPI execute path (the `modules` option on
      // DynamicWorkerExecutorOptions exists but is not exposed here, and the
      // sandbox code string is generated by openApiMcpServer itself). So LLM
      // code must invoke `__stagingHost.getFile(handle, token)` directly and
      // base64-decode `bytesBase64` itself. A prelude/modules-prepend API
      // would let us wrap that in a Response-like object; until codemode
      // ships one, callers see the raw wire form.
      // Gate requires STAGING_UPLOAD_ORIGIN as well: putFile populates its
      // `fetch_url` return field from it. In every deployment that has D1+R2
      // STAGING_UPLOAD_ORIGIN is already present (it gates register-tool too),
      // so the tightened gate is observationally a no-op for current envs.
      // Captured early so closures below (and the staging IIFE) can reference
      // `agent` and the late-bound `buildUpstreamArgs` — see the
      // `buildUpstreamArgsRef` indirection further down for why this can't
      // simply be assigned inline.
      const agent = this;
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
        positionalArgs: true;
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
                  agentContext.run(
                    { agent, connection: undefined, request: undefined, email: undefined },
                    () =>
                      handleUpstreamRequest(
                        buildUpstreamArgsRef.current(ctx as unknown as UpstreamCtx),
                      ),
                  ) as Promise<UpstreamRequestResult>,
              });
              // positionalArgs:true so calls like
              //   __stagingHost.getFile(handle, token)
              //   __stagingHost.putFile(bytesBase64, contentType, filename)
              //   __stagingHost.stageFromUpstreamJson(opts, dataField, encoding?, filename?)
              // are dispatched as positional args. With the default (false),
              // codemode would marshal only the first.
              return {
                name: "__stagingHost",
                positionalArgs: true as const,
                fns: {
                  getFile: (...args: unknown[]) =>
                    getFile(args[0] as string, args[1] as string),
                  putFile: (...args: unknown[]) =>
                    putFile(
                      args[0] as string,
                      args[1] as string,
                      (args[2] as string | null | undefined) ?? null,
                    ),
                  stageFromUpstreamJson: (...args: unknown[]) =>
                    stageFromUpstreamJson(
                      args[0] as StageRequestOpts,
                      args[1] as string,
                      (args[2] as "base64url" | "base64" | undefined) ?? "base64url",
                      (args[3] as string | null | undefined) ?? null,
                    ),
                },
              };
            })()
          : null;

      const executor = stagingProvider
        ? {
            execute: (
              code: string,
              providersOrFns:
                | Array<{ name: string; fns: Record<string, (...args: unknown[]) => Promise<unknown>>; positionalArgs?: boolean }>
                | Record<string, (...args: unknown[]) => Promise<unknown>>,
            ) => {
              // openApiMcpServer always passes an array form; the Record form
              // is the legacy convenience API. Append only when array form.
              if (Array.isArray(providersOrFns)) {
                return baseExecutor.execute(code, [...providersOrFns, stagingProvider]);
              }
              return baseExecutor.execute(code, providersOrFns);
            },
          }
        : baseExecutor;

      const stagingEnabled = stagingProvider !== null;
      // Appended to codemode's executeDescription. Closes a real gap in codemode
      // 0.3.5: its declared RequestOptions interface (body?:unknown, rawBody?:boolean)
      // reads as "use rawBody for binary" — but the sandbox→host RPC marshals args
      // via JSON.stringify, which destroys Uint8Array/ArrayBuffer before reaching
      // the host. Result: rawBody+Uint8Array silently uploads "[object Object]"
      // (15 bytes). This addendum documents the bodyBase64 / multipart escape
      // hatches (handled server-side in request-handler.ts).
      const executeAddendum =
        (stagingEnabled
          ? "\n## Attachments / file uploads — ALWAYS use `register_file_handle` first\n\n" +
            "When the user wants to attach, upload, send, or otherwise transmit ANY file/binary on this server, " +
            "the workflow is fixed and non-negotiable:\n\n" +
            "  1. Call the `register_file_handle` tool (NOT codemode.request) → get { upload_url, token, file_handle }.\n" +
            "  2. POST the file bytes to upload_url out-of-band, with `Authorization: Bearer <token>` (your runtime/host does this — bytes never enter execute()).\n" +
            "  3. Inside execute(), read the bytes via the sandbox capability:\n" +
            "       const f = await __stagingHost.getFile(file_handle, token);\n" +
            "       // f = { ok: true, contentType, byteLength, filename, bytesBase64 } | { ok: false, status, message }\n" +
            "       // __stagingHost is a sandbox-scope local (NOT on codemode.*, NOT on globalThis).\n" +
            "  4. Forward `f.bytesBase64` to the upstream API per the provider-specific snippet below.\n\n" +
            "Do NOT try to read files from disk, embed bytes literally in code, fetch URLs into Uint8Array, or pass Uint8Array/ArrayBuffer through codemode.request — none of those paths reach the host as binary (the sandbox→host RPC marshals via JSON.stringify, destroying typed arrays).\n\n" +
            "## Returning large binary payloads from execute() — three modes\n\n" +
            "When upstream responses contain multi-MB binary, DO NOT return the bytes inline (`r.result.data`); they will be truncated to ~64KB by the response budget AND flood your context on the next turn. Use one of the three modes below.\n\n" +
            "**Mode A — JSON envelope with base64 field (e.g. Gmail attachments.get returns `{data: <base64url>, mimeType, size}`):**\n\n" +
            "  const f = await __stagingHost.stageFromUpstreamJson(\n" +
            "    { method: \"GET\", path: \"/<endpoint>\" },\n" +
            "    \"data\",            // field name in the JSON envelope\n" +
            "    \"base64url\",       // \"base64url\" (default, Gmail) or \"base64\"\n" +
            "    filename ?? null,  // staged filename; null lets the host omit it\n" +
            "  );\n" +
            "  if (!f.ok) throw new Error(`stage: ${f.status} ${f.message}`);\n" +
            "  return { file_handle: f.file_handle, token: f.token, fetch_url: f.fetch_url, byte_length: f.byte_length };\n\n" +
            "Host extracts the field server-side (no 64KB cap, no base64url→base64 conversion needed). Uses upstream `result.mimeType` as Content-Type if present, else `application/octet-stream`.\n\n" +
            "**Mode B — Raw upstream body (e.g. Xero `/api.xro/2.0/Invoices/{id}/Attachments/{name}` with `Accept: application/octet-stream`):**\n\n" +
            "  const r = await codemode.request({\n" +
            "    method: \"GET\",\n" +
            "    path: \"/<endpoint>\",\n" +
            "    headers: { Accept: \"application/octet-stream\" },\n" +
            "    returnAs: \"stage\",   // bytes go upstream→R2 server-side; r.result is the file-handle envelope\n" +
            "  });\n" +
            "  if (!r.success) throw new Error(`stage: ${r.status}`);\n" +
            "  return { file_handle: r.result.file_handle, token: r.result.token, fetch_url: r.result.fetch_url, byte_length: r.result.byte_length };\n\n" +
            "On 2xx upstream the bytes are staged automatically; Content-Type and filename are taken from the upstream response headers (Content-Disposition). On non-2xx, the normal error envelope is returned (no staging).\n\n" +
            "**Mode C — Bytes you computed in execute() (fallback when neither A nor B applies):**\n\n" +
            "  const f = await __stagingHost.putFile(bytesAsBase64, contentType, filename ?? null);\n" +
            "  if (!f.ok) throw new Error(`stage: ${f.status} ${f.message}`);\n" +
            "  return { file_handle: f.file_handle, token: f.token, fetch_url: f.fetch_url, byte_length: f.byte_length };\n\n" +
            "Use this only when the bytes originate inside execute() (e.g. you computed them, decompressed something, merged multiple sources). For upstream payloads, prefer Mode A or B — they avoid pulling the bytes through your context entirely.\n\n" +
            "The client (or user) downloads any staged file with:\n" +
            "  curl -H \"Authorization: Bearer <token>\" <fetch_url> -o file.bin\n\n" +
            "Notes:\n" +
            "- The token is short-lived (default 60 min, matches getFile). After expiry the row is swept and the URL returns 410.\n" +
            "- A later turn in this same conversation can re-pull the bytes via `__stagingHost.getFile(file_handle, token)` if needed.\n\n"
          : "") +
        "## codemode.request body modes (binary / non-JSON)\n\n" +
        "codemode.request marshals `options` to the host via JSON.stringify, which destroys typed arrays. " +
        "`rawBody: true` only suppresses JSON serialisation of `body` — it does NOT enable Uint8Array/ArrayBuffer passthrough. " +
        "The host-side modes (handled by this server, forwarded verbatim upstream):\n\n" +
        "  • Default (JSON):       `body: {...}` → serialised; Content-Type defaults to application/json.\n" +
        "  • Text body:            `body: \"…\", rawBody: true, contentType: \"…\"` (e.g. application/xml). Do NOT use rawBody with binary.\n" +
        "  • Binary octet-stream:  `bodyBase64: \"<base64>\", contentType: \"…\"` — host decodes base64 before fetching.\n" +
        "  • multipart/form-data:  `multipart: [{ name, filename?, contentType?, value? | bodyBase64? }, …]` — host generates the boundary and Content-Type; do NOT set `contentType` yourself.\n" +
        "  • contentType is forwarded as-is for body / bodyBase64 / rawBody; only `multipart` overrides it.\n\n" +
        (stagingEnabled && provider.attachmentHint
          ? "## Upstream-specific attachment snippet for this server\n\n" + provider.attachmentHint + "\n"
          : "");
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
          apiBaseUrl: provider.apiBaseUrl,
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
        spec: provider.spec as unknown as Record<string, unknown>,
        executor,
        description: executeAddendum,
        // INVARIANT: agentContext store contents must be host-side references only.
        // Never include child-supplied (RPC-arg-derived) values here.
        request: (ctx) => {
          return agentContext.run(
            { agent, connection: undefined, request: undefined, email: undefined },
            () => handleUpstreamRequest(buildUpstreamArgs(ctx)),
          );
        },
      });

      // Workers runtime forbids `new Function` / `eval`, which the MCP SDK's
      // default AjvJsonSchemaValidator uses to compile elicit-response
      // validators. Swap in @cfworker/json-schema (no codegen) for the
      // server's inner Server instance. Codemode's openApiMcpServer doesn't
      // expose the constructor option, so we replace the field directly.
      // TODO: graduate this into the codemode patch (forward jsonSchemaValidator).
      (this.server.server as unknown as { _jsonSchemaValidator: unknown })._jsonSchemaValidator =
        new CfWorkerJsonSchemaValidator();

      // Staging attachments — register the tool only when bindings are present.
      if (this.env.STAGING_D1 && this.env.STAGING_R2 && this.env.STAGING_UPLOAD_ORIGIN) {
        const { registerFileHandleTool } = await import("./staging/index.js");
        const { readStagingConfig } = await import("./config.js");
        const tool = registerFileHandleTool({
          STAGING_D1: this.env.STAGING_D1,
          config: readStagingConfig(this.env as unknown as Record<string, unknown>),
          uploadOrigin: this.env.STAGING_UPLOAD_ORIGIN,
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
