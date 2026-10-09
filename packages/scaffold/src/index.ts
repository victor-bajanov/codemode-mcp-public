export type { ApiProvider } from "./api-provider.js";
export { hintFromSpecInfo } from "./api-provider.js";
export { resolveOperation, findShadowConflicts, type ShadowConflict } from "./path-matcher.js";
export { truncateForReturn, stringifyForMcpResult } from "./truncate.js";
export { auditLog, type AuditEntry } from "./audit.js";
export {
  handleUpstreamRequest,
  type UpstreamCtx,
  type HandleArgs,
} from "./request-handler.js";
export { mostRestrictive } from "./restrict";
export {
  annotateSpecWithSurfaceReview,
  SURFACE_REVIEW_MARKER,
  SURFACE_REVIEW_SUMMARY_MARKER,
  type AnnotatableSpec,
} from "./annotate-spec.js";
export type { UpstreamRateLimit, ReadRateLimit } from "./rate-limit.js";
export {
  getOrRefreshAccessToken,
  hashRefreshToken,
  type GrantSlot,
  type RefreshTokenStorage,
  type RefreshArgs,
} from "./refresh.js";
export { type TokenRotation, type UpstreamTokenResponse, type CompleteAuthHookArgs } from "./api-provider.js";
export { createOAuthHandler } from "./oauth-handler.js";
// buildExecuteAddendum is LEGACY: since description-budget-docs-surface no
// client-visible description is built from it (init() serves the compact
// descriptions + docs tool instead). Kept exported for reference and for
// pre-existing provider tests; candidate for removal — see the plan's
// follow-ups.
export {
  createProviderMcpAgent,
  buildExecuteAddendum,
  type ProviderEnv,
} from "./mcp-agent-factory.js";
export { DOC_SECTIONS, buildProviderDocs, type DocSection } from "./descriptions/docs.js";
export {
  buildCompactExecuteDescription,
  COMPACT_SEARCH_DESCRIPTION,
  buildCompactRegisterFileHandleDescription,
} from "./descriptions/compact.js";
export { setupProvider } from "./setup-provider.js";
export {
  createTokenBrokerDO,
  type TokenBrokerStub,
  type TokenBrokerArgs,
} from "./token-broker.js";
export { runElicitation, type RunElicitationArgs, ToolError } from "./elicit.js";
export { allowPiiInLogs, debugElicit, debugLog, assertSecrets, type ScaffoldSecrets } from "./config.js";
export * as staging from "./staging/index.js";
export { readStagingConfig, resolveEndpoints, type ResolvedEndpoints } from "./config.js";
export {
  readOAuthRateLimitConfig,
  type OAuthRateLimitConfig,
} from "./config.js";
export {
  enforceOAuthHardening,
  checkRateLimit,
  withNoStore,
  type RateLimitStore,
  type RateLimitConfig,
} from "./oauth-hardening.js";
