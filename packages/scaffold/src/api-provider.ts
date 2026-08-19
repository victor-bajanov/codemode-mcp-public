import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { ElicitRenderer, SurfaceReview } from "@local/shared";
import type { ReadRateLimit } from "./rate-limit.js";

export type TokenRotation = "static" | "rotating";

/** Subset of upstream OAuth `/token` JSON we consume in `completeAuthHook`. */
export interface UpstreamTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type?: string;
  scope?: string;
  id_token?: string;
}

export interface CompleteAuthHookArgs<Env = unknown> {
  tokens: UpstreamTokenResponse;
  /** Result of fetching `oauth.userInfoUrl`, if configured. `null` otherwise. */
  userInfo: unknown;
  env: Env;
}

export interface ApiProvider<
  Props extends Record<string, unknown> = Record<string, unknown>,
  Env = unknown,
> {
  /** Stable identifier; used as the McpServer name. */
  name: string;
  /** Human-readable label, e.g. "Gmail (personal)". */
  displayName: string;
  /** Outbound OAuth configuration (provider as an OAuth server). */
  oauth: {
    authorizeUrl: string;
    tokenUrl: string;
    scopes: string[];
    /** Name of the wrangler secret holding the OAuth client id. */
    clientIdSecretName: string;
    /** Name of the wrangler secret holding the OAuth client secret. */
    clientSecretSecretName: string;
    /** Optional userinfo endpoint, used to derive a displayable label after consent. */
    userInfoUrl?: string;
    /** Additional URL query parameters merged into the /authorize redirect.
     *  Useful for provider-specific consent flags (e.g. Google's access_type=offline).
     *
     *  Base OAuth2 params (client_id, redirect_uri, response_type, scope, state) are
     *  set by the scaffold and protected — collisions here are silently skipped, not
     *  overridden. Don't use this hook to alter what those base params carry. */
    extraAuthorizeParams?: Record<string, string>;
    /** PKCE method for the authorization-code flow. Default: "s256" when absent. */
    pkce?: "s256" | "none";
  };
  /** Bundled OpenAPI 3 spec for the API. */
  spec: OpenApiSpec;
  /** Hand-curated decision per operationId. */
  surfaceReview: SurfaceReview;
  /** Base URL for upstream API calls. ctx.path from openApiMcpServer is appended verbatim. */
  apiBaseUrl: string;

  /** Token-rotation behaviour at refresh time.
   *  "static": initial refresh token is pinned and reused.
   *  "rotating": refresh token is replaced on every refresh.
   *  Default: "static". */
  tokenRotation?: TokenRotation;

  /** Per-request additional headers, computed from props.
   *  Merged into the outbound fetch alongside Authorization. */
  requestHeaders?: (props: Props) => Record<string, string>;

  /** Read the upstream API's rate-limit headers off every response.
   *
   *  Header names are provider-specific, so the parsing lives here; the
   *  scaffold puts the result on the `codemode.request` envelope as
   *  `rateLimit` and, on a 429, prefixes `errors[0].message` with the
   *  returned `message` so the client is told which limit it hit and how long
   *  to wait. Omit when the API reports nothing useful — the envelope then
   *  keeps its original shape (no `rateLimit` key). */
  readRateLimit?: ReadRateLimit;

  /** Run once after upstream OAuth exchange, before `OAuthProvider.completeAuthorization`.
   *  Return value is merged into props (e.g. tenantId from `/connections`). */
  completeAuthHook?: (args: CompleteAuthHookArgs<Env>) => Promise<Partial<Props>>;

  /** Optional renderers that produce the elicit form from a body when
   *  surface-review's decision resolves to `elicit`. Keyed by
   *  `SurfaceReviewCategory`. The scaffold falls back to a generic walker
   *  when no renderer resolves. */
  elicitRenderers?: Partial<Record<string, ElicitRenderer>>;

  /** Provider-specific Step-3 guidance for the staging/attachment workflow — the
   *  UPLOAD direction (bytes TO the upstream API). For the opposite direction
   *  (bytes FROM the upstream API), see `downloadHint` below; the two are never
   *  merged, because `attachmentHint` is spliced into the upload-only
   *  `register_file_handle` tool and a mixed hint there misdirects an agent
   *  trying to download.
   *
   *  Served verbatim as the `docs` tool's "attachments" section when this
   *  server has staging bindings configured (STAGING_D1 + STAGING_R2 +
   *  STAGING_UPLOAD_ORIGIN); when unset, the section falls back to the
   *  generic GENERIC_STEP_THREE text. Since description-budget-docs-surface
   *  it is NOT spliced into any tool description — the compact
   *  `register_file_handle` body points the model at that docs section.
   *  (register-tool.ts's descriptionMode:"full" legacy path still splices it,
   *  but the factory serves the compact path.)
   *
   *  Should show, in concrete code, exactly how to forward `f.bytesBase64` from
   *  `__stagingHost.getFile(file_handle, token)` to THIS provider's upstream API.
   *  Strongly recommended when staging is enabled — without it, the LLM tends to
   *  miss that the workflow applies to non-Xero providers.
   *
   *  Format: a leading "Step 3 — …" heading or short imperative, followed by a
   *  fenced code-style snippet that uses `await codemode.request({...})` to call
   *  an upstream operationId allowed by `surfaceReview`. */
  attachmentHint?: string;

  /** Provider-specific guidance for staging bytes FROM the upstream API — the
   *  DOWNLOAD/export direction, the opposite of `attachmentHint`. Served
   *  verbatim as the `docs` tool's "downloads" section when this server has
   *  staging bindings configured (since description-budget-docs-surface it is
   *  NOT spliced into any tool description) — and never associated with
   *  `register_file_handle`, which is upload-only.
   *
   *  Should show, in concrete code, how to call `__stagingHost.stageFromUpstreamJson`
   *  (Mode A — JSON envelope with a base64 field) or `codemode.request(...,
   *  { returnAs: "stage" })` (Mode B — raw upstream body) for THIS provider's
   *  download/export endpoints.
   *
   *  Leave unset if the provider has no download-specific guidance beyond the
   *  generic Mode A/B/C documentation already in the staging block — there is
   *  no auto-fallback. */
  downloadHint?: string;

  /** Provider-owned full prose, served as the `docs` tool's "provider"
   *  section (description-budget-docs-surface: since that change, NO
   *  provider hint is spliced into a client-visible tool description — the
   *  compact `execute` description carries only `compactHint`, and
   *  everything longer lives behind the `docs` tool / codemode://docs
   *  resource). Use this for workflow guidance too long for the 200-char
   *  compactHint slot (multi-op flow ordering, plan-hash semantics,
   *  surface-review state machine).
   *
   *  IMPORTANT: a load-bearing fact that must reach a client that never
   *  calls `docs` belongs (in distilled form) in `compactHint` below —
   *  executeHint alone reaches no tool description.
   *
   *  Distinct from `attachmentHint` (upload Step-3 content → docs
   *  "attachments" section) and `downloadHint` (download/export guidance →
   *  docs "downloads" section). Leave unset if the provider has no general
   *  guidance — there is no auto-fallback, and the docs "provider" section
   *  is then omitted. */
  executeHint?: string | undefined;

  /** Provider's one-liner carried inside the COMPACT `execute` description —
   *  the text every client sees once the 1,800-char compact budget is in
   *  effect (description-budget-docs-surface, spec D3). E.g. Gmail's "this
   *  connection also serves Google Calendar".
   *
   *  Keep this to ≤200 chars: it is one fixed-size slot in a description
   *  that must fit Claude Code's 2,048-char truncation cap. That budget is
   *  enforced by the shared provider-description test battery
   *  (`@local/scaffold/testing`, `providerDescriptionBudgetTests`), NOT by
   *  the type system — nothing here rejects a longer string at compile
   *  time.
   *
   *  Full prose belongs in `executeHint` above, which feeds the `docs` tool
   *  (unbounded) rather than the compact description. Leave unset if the
   *  provider has nothing worth saying in 200 chars — there is no
   *  auto-fallback. */
  compactHint?: string | undefined;

  /** Optional accessors that pull audit-log identifiers out of the request props.
   *  - principalId: the authenticated subject (OAuth sub).
   *  - context: provider-specific identifier blob (e.g. { tenantId } for Xero). */
  audit?: {
    principalIdAccessor?: (props: Props) => string | undefined;
    contextAccessor?: (props: Props) => Record<string, string> | undefined;
  };
}

/** Convenience: return `spec.info.description` as the executeHint value (or
 *  undefined if absent / whitespace-only). Use when the provider's upstream
 *  OpenAPI spec is the canonical home for the agent-facing prose —
 *  re-vendoring the spec then updates the hint without touching provider
 *  code.
 *
 *  Other patterns (inline string literal, computed from multiple sources)
 *  remain valid; this helper just documents the "spec is source of truth"
 *  pattern as a first-class option. */
export function hintFromSpecInfo(
  spec: { info?: { description?: string } },
): string | undefined {
  return spec.info?.description?.trim() || undefined;
}
