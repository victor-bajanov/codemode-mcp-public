import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { Decision, ElicitRenderer, InspectResult, SurfaceReview } from "@local/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { resolveOperation } from "./path-matcher";
import { truncateForReturn } from "./truncate";
import { auditLog, redactAuditEntry, type AuditEntry } from "./audit";
import { mostRestrictive } from "./restrict";
import { getOrRefreshAccessToken, type RefreshTokenStorage } from "./refresh";
import type { TokenRotation } from "./api-provider";
import { runElicitation, ToolError } from "./elicit";
import { deepFreeze } from "./freeze";
import { allowPiiInLogs, debugLog } from "./config";
import { buildUpstreamUrl } from "./build-upstream-url";

export interface UpstreamCtx {
  method: string;
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
}

export interface HandleArgs<P extends Record<string, unknown>> {
  // Stable core
  ctx: UpstreamCtx;
  spec: OpenApiSpec;
  surfaceReview: SurfaceReview;
  apiBaseUrl: string;
  deploymentName: string;
  props: P;
  server: McpServer;

  // OAuth — everything needed to mint a fresh access token
  oauth: {
    refreshTokenAccessor: (props: P) => string;
    clientId: string;
    clientSecret: string;
    tokenUrl: string;
    storage: RefreshTokenStorage;
    rotation: TokenRotation;
  };

  // Per-request provider hook — merged into outbound fetch headers
  requestHeaders?: (props: P) => Record<string, string>;

  // Audit — fire-and-forget side effects
  audit: {
    waitUntil?: (p: Promise<unknown>) => void;
    principalIdAccessor?: (props: P) => string | undefined;
    contextAccessor?: (props: P) => Record<string, string> | undefined;
  };

  /** Per-category elicit renderers from provider config. Optional;
   *  scaffold falls back to genericWalker when no renderer resolves. */
  elicitRenderers?: Partial<Record<string, ElicitRenderer>>;

  /** Narrow env shape; populated by `mcp-agent-factory` from `this.env`.
   *  Kept structural (not `ProviderEnv`) so tests can build minimal envs. */
  env: { ALLOW_PII_IN_LOGS?: string; DEBUG_ELICIT?: string };
}

function emitAudit<P extends Record<string, unknown>>(
  args: HandleArgs<P>,
  entry: AuditEntry,
): void {
  const principalId = args.audit.principalIdAccessor?.(args.props);
  const context = args.audit.contextAccessor?.(args.props);
  const enriched: AuditEntry = {
    ...entry,
    ...(principalId !== undefined ? { principalId } : {}),
    ...(context !== undefined ? { context } : {}),
  };

  // H1: redact PII-bearing audit fields by default; preserve operational
  // metadata (deployment/operationId/decision/category/reason/principalId/ts).
  // Opt back in by setting `ALLOW_PII_IN_LOGS="true"` in wrangler.jsonc vars.
  const finalEntry = allowPiiInLogs(args.env) ? enriched : redactAuditEntry(enriched);

  if (args.audit.waitUntil) {
    args.audit.waitUntil(Promise.resolve().then(() => auditLog(finalEntry)));
  } else {
    auditLog(finalEntry);
  }
}

export async function handleUpstreamRequest<P extends Record<string, unknown>>(
  args: HandleArgs<P>,
): Promise<unknown> {
  const { spec, surfaceReview } = args;
  const ctx = {
    ...args.ctx,
    ...(args.ctx.body !== undefined ? { body: deepFreeze(args.ctx.body) } : {}),
  };
  debugLog(
    args.env,
    "request-entry",
    {
      method: ctx.method,
      path: ctx.path,
      hasBody: ctx.body !== undefined,
    },
    { containsPii: true },
  );
  const op = resolveOperation(spec, ctx.method, ctx.path);

  if (!op) {
    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      decision: "deny",
      reason: "no-op-match",
      ts: new Date().toISOString(),
    });
    throw new ToolError(`No operation found for ${ctx.method} ${ctx.path}`);
  }

  const review = surfaceReview[op.operationId];
  if (!review) {
    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      operationId: op.operationId,
      decision: "deny",
      reason: "not-in-surface-review",
      ts: new Date().toISOString(),
    });
    throw new ToolError(`Operation ${op.operationId} not in surface review`);
  }

  if (review.decision === "deny") {
    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      operationId: op.operationId,
      decision: "deny",
      ...(review.category ? { category: review.category } : {}),
      ts: new Date().toISOString(),
    });
    throw new ToolError(`Operation ${op.operationId} is denied by surface review`);
  }

  let decision: Decision = review.decision;
  let category: string | undefined = review.category;
  let reason: string | undefined;

  let inspectResult: InspectResult | undefined;
  if (review.inspect) {
    inspectResult = review.inspect({
      ...(ctx.body !== undefined ? { body: ctx.body } : {}),
      ...(ctx.query !== undefined ? { query: ctx.query } : {}),
    });
    decision = mostRestrictive(decision, inspectResult.decision);
    if (inspectResult.category) category = inspectResult.category;
    if (inspectResult.reason) reason = inspectResult.reason;
  }

  if (decision === "deny") {
    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      operationId: op.operationId,
      decision: "deny",
      ...(category ? { category } : {}),
      ...(reason ? { reason } : {}),
      ts: new Date().toISOString(),
    });
    throw new ToolError(`Operation ${op.operationId} is denied by surface review`);
  }

  if (decision === "elicit") {
    debugLog(
      args.env,
      "elicit-branch",
      {
        operationId: op.operationId,
        decision,
        ...(category ? { category } : {}),
        ...(reason ? { reason } : {}),
        hasInspector: review.inspect != null,
      },
      { containsPii: false },
    );
    await runElicitation({
      spec: args.spec,
      operationId: op.operationId,
      method: ctx.method,
      path: ctx.path,
      body: ctx.body,
      env: args.env,
      ...(ctx.query !== undefined ? { query: ctx.query } : {}),
      ...(category ? { category } : {}),
      ...(reason ? { reason } : {}),
      ...(inspectResult?.summary ? { inspectorSummary: inspectResult.summary } : {}),
      entry: review,
      ...(args.elicitRenderers ? { elicitRenderers: args.elicitRenderers } : {}),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: args.server as any,
      emitAudit: (e) =>
        emitAudit(args, {
          deployment: args.deploymentName,
          method: e.method,
          path: e.path,
          ...(e.operationId ? { operationId: e.operationId } : {}),
          decision: e.decision,
          elicitationOutcome: e.elicitationOutcome,
          ...(e.category ? { category: e.category } : {}),
          ...(e.reason ? { reason: e.reason } : {}),
          ...(e.elicitFields ? { elicitFields: e.elicitFields } : {}),
          ts: new Date().toISOString(),
        }),
    });
    // accepted; fall through to upstream fetch
  }

  const accessToken = await getOrRefreshAccessToken({
    storage: args.oauth.storage,
    rotation: args.oauth.rotation,
    refreshToken: args.oauth.refreshTokenAccessor(args.props),
    clientId: args.oauth.clientId,
    clientSecret: args.oauth.clientSecret,
    tokenUrl: args.oauth.tokenUrl,
  });

  let urlString: string;
  try {
    urlString = buildUpstreamUrl(args.apiBaseUrl, ctx.path, ctx.query);
  } catch (err) {
    // M3: defence-in-depth on URL origin. Tag origin-mismatch deny audits
    // with category "url_safety" so they're greppable in production logs.
    if (err instanceof ToolError && err.message.startsWith("upstream-url-origin-mismatch")) {
      emitAudit(args, {
        deployment: args.deploymentName,
        method: ctx.method,
        path: ctx.path,
        operationId: op.operationId,
        decision: "deny",
        category: "url_safety",
        reason: err.message,
        ts: new Date().toISOString(),
      });
    }
    throw err;
  }

  const headers: Record<string, string> = { Authorization: `Bearer ${accessToken}` };
  if (ctx.body) headers["content-type"] = "application/json";
  if (args.requestHeaders) Object.assign(headers, args.requestHeaders(args.props));

  const fetchOptions: RequestInit = { method: ctx.method, headers };
  if (ctx.body) fetchOptions.body = JSON.stringify(ctx.body);

  const upstreamRes = await fetch(urlString, fetchOptions);

  const responseText = await upstreamRes.text();
  let parsed: unknown = responseText;
  try { parsed = JSON.parse(responseText); } catch { /* leave as text */ }

  emitAudit(args, {
    deployment: args.deploymentName,
    method: ctx.method,
    path: ctx.path,
    operationId: op.operationId,
    decision: "allow",
    upstreamStatus: upstreamRes.status,
    ts: new Date().toISOString(),
  });

  return {
    success: upstreamRes.ok,
    status: upstreamRes.status,
    result: truncateForReturn(parsed),
    errors: upstreamRes.ok ? [] : [{ code: upstreamRes.status, message: responseText.slice(0, 500) }],
  };
}
