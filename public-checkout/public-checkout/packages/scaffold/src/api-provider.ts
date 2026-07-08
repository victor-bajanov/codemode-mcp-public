import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { ElicitRenderer, SurfaceReview } from "@local/shared";

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

  /** Run once after upstream OAuth exchange, before `OAuthProvider.completeAuthorization`.
   *  Return value is merged into props (e.g. tenantId from `/connections`). */
  completeAuthHook?: (args: CompleteAuthHookArgs<Env>) => Promise<Partial<Props>>;

  /** Optional renderers that produce the elicit form from a body when
   *  surface-review's decision resolves to `elicit`. Keyed by
   *  `SurfaceReviewCategory`. The scaffold falls back to a generic walker
   *  when no renderer resolves. */
  elicitRenderers?: Partial<Record<string, ElicitRenderer>>;

  /** Provider-specific Step-3 guidance for the staging/attachment workflow.
   *
   *  Spliced verbatim into TWO LLM-facing description sites when this server has
   *  staging bindings configured (STAGING_D1 + STAGING_R2 + STAGING_UPLOAD_ORIGIN):
   *
   *    1. the `register_file_handle` tool description (after Steps 1 + 2, which
   *       are provider-agnostic and explain minting + reading the bytes), and
   *    2. the `execute` tool's description (codemode's executeAddendum).
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

  /** Optional accessors that pull audit-log identifiers out of the request props.
   *  - principalId: the authenticated subject (OAuth sub).
   *  - context: provider-specific identifier blob (e.g. { tenantId } for Xero). */
  audit?: {
    principalIdAccessor?: (props: Props) => string | undefined;
    contextAccessor?: (props: Props) => Record<string, string> | undefined;
  };
}
