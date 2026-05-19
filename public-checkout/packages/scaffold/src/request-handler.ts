import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { Decision, ElicitRenderer, InspectResult, SurfaceReview } from "@local/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { resolveOperation } from "./path-matcher";
import { truncateForReturn } from "./truncate";
import { auditLog, redactAuditEntry, type AuditEntry } from "./audit";
import { mostRestrictive } from "./restrict";
import { runElicitation, ToolError } from "./elicit";
import { deepFreeze } from "./freeze";
import { allowPiiInLogs, debugLog } from "./config";
import { buildUpstreamUrl } from "./build-upstream-url";
import type { PutFileResult } from "./staging/putfile-capability";

export interface MultipartPart {
  /** Form-data field name (required). */
  name: string;
  /** Filename for the part. Required for binary parts; omit for text fields. */
  filename?: string;
  /** Content-Type of the part. Defaults: text part → `text/plain`; binary part → `application/octet-stream`. */
  contentType?: string;
  /** Text value of the part. Mutually exclusive with `bodyBase64`. */
  value?: string;
  /** Base64-encoded bytes for the part. Decoded server-side. Mutually exclusive with `value`. */
  bodyBase64?: string;
}

export interface UpstreamCtx {
  method: string;
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  /** Override the outbound `Content-Type` header. When unset and `body` is
   *  present, defaults to `application/json`. */
  contentType?: string;
  /** Send `body` to the upstream verbatim (no `JSON.stringify`). Use for
   *  text/XML/form payloads. Binary uploads should use `bodyBase64` instead
   *  because the sandbox→host RPC encodes args via `JSON.stringify`, which
   *  mangles high-byte values in strings. */
  rawBody?: boolean;
  /** Base64-encoded raw bytes for binary upstream bodies. Decoded server-side
   *  and used as the outbound body. Takes precedence over `body` when set. */
  bodyBase64?: string;
  /** Build a `multipart/form-data` request server-side. When set, overrides
   *  `body`/`bodyBase64`/`rawBody`. The handler picks a boundary, assembles
   *  the body from `parts`, and sets the `Content-Type` header. Use this for
   *  endpoints like Xero's `/files.xro/1.0/Files` that require multipart. */
  multipart?: MultipartPart[];
  /** When set to "stage", read the upstream response as bytes, stage them
   *  into R2 via the supplied `putFile` capability, and return a file-handle
   *  envelope instead of the parsed body. Bypasses truncateForReturn. Requires
   *  HandleArgs.putFile to be supplied (else throws). Upstream non-2xx
   *  responses are NOT staged and fall through to the normal error envelope. */
  returnAs?: "stage";
  /** Internal escape hatch for `__stagingHost.stageFromUpstreamJson`. When
   *  true, the parsed JSON result is returned WITHOUT `truncateForReturn` —
   *  so a downstream caller can pluck a large base64 field intact and stage
   *  it server-side. NOT documented in `executeAddendum` — internal use only.
   *  Ignored when `returnAs === "stage"`. */
  bypassTruncate?: boolean;
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

function filenameFromContentDisposition(header: string | null): string | null {
  if (!header) return null;
  // Prefer RFC 5987 filename* (UTF-8); fall back to plain filename=.
  const star = /filename\*\s*=\s*(?:[^']*'[^']*')?([^;\r\n]+)/i.exec(header);
  if (star && star[1]) {
    try { return decodeURIComponent(star[1].replace(/^"|"$/g, "")); } catch { /* fall through */ }
  }
  const plain = /filename\s*=\s*("([^"]+)"|([^;\r\n]+))/i.exec(header);
  if (plain) return (plain[2] ?? plain[3] ?? "").trim() || null;
  return null;
}

function buildMultipartBody(parts: MultipartPart[]): { body: Uint8Array; boundary: string } {
  // RFC 2046 §5.1.1: boundary is `1*70(bchars)`. Use 24 random bytes hex (48 chars).
  const rb = new Uint8Array(24);
  crypto.getRandomValues(rb);
  const boundary = "----codemode-" + Array.from(rb, (b) => b.toString(16).padStart(2, "0")).join("");
  const enc = new TextEncoder();
  const chunks: Uint8Array[] = [];
  for (const p of parts) {
    if (!p.name) throw new ToolError("multipart part: name is required");
    if (p.value !== undefined && p.bodyBase64 !== undefined) {
      throw new ToolError(`multipart part "${p.name}": value and bodyBase64 are mutually exclusive`);
    }
    const filenameAttr = p.filename ? `; filename="${p.filename.replace(/"/g, "")}"` : "";
    const defaultCt = p.bodyBase64 !== undefined ? "application/octet-stream" : "text/plain";
    const headerStr =
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="${p.name.replace(/"/g, "")}"${filenameAttr}\r\n` +
      `Content-Type: ${p.contentType ?? defaultCt}\r\n\r\n`;
    chunks.push(enc.encode(headerStr));
    if (p.bodyBase64 !== undefined) {
      chunks.push(base64ToBytes(p.bodyBase64));
    } else if (typeof p.value === "string") {
      chunks.push(enc.encode(p.value));
    }
    chunks.push(enc.encode("\r\n"));
  }
  chunks.push(enc.encode(`--${boundary}--\r\n`));
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const body = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { body.set(c, off); off += c.byteLength; }
  return { body, boundary };
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

  // OAuth — broker stub mints fresh access tokens; rotation lives in the broker.
  oauth: {
    refreshTokenAccessor: (props: P) => string;
    userIdAccessor: (props: P) => string | undefined;
    broker: import("./token-broker").TokenBrokerStub;
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

  /** Optional staging dep. When present, enables `ctx.returnAs === "stage"`.
   *  Constructed by mcp-agent-factory from createPutFileCapability. */
  putFile?: (bytesBase64: string, contentType: string, filename: string | null) =>
    Promise<PutFileResult>;
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

  const userId = args.oauth.userIdAccessor(args.props);
  if (!userId) {
    throw new ToolError("Cannot mint access token: principal has no userId");
  }
  const accessToken = await args.oauth.broker.getOrRefreshAccessToken({
    userId,
    refreshToken: args.oauth.refreshTokenAccessor(args.props),
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

  // Body marshalling. Four modes, mutually exclusive (priority top-down):
  //   multipart  → server-side multipart/form-data assembly (content-type set with boundary)
  //   bodyBase64 → decode to bytes, send raw (default content-type octet-stream)
  //   rawBody    → pass body through verbatim (string/ArrayBuffer/Uint8Array)
  //   default    → JSON.stringify body, content-type application/json
  // ctx.contentType, when set, always wins over the mode-default content-type
  // — except for `multipart`, where the boundary parameter must match the body.
  let bodyToSend: BodyInit | undefined;
  let defaultCt: string | undefined;
  let lockedCt: string | undefined;
  if (Array.isArray(ctx.multipart)) {
    const { body, boundary } = buildMultipartBody(ctx.multipart);
    bodyToSend = body;
    lockedCt = `multipart/form-data; boundary=${boundary}`;
  } else if (typeof ctx.bodyBase64 === "string") {
    bodyToSend = base64ToBytes(ctx.bodyBase64);
    defaultCt = "application/octet-stream";
  } else if (ctx.rawBody && ctx.body !== undefined && ctx.body !== null) {
    bodyToSend = ctx.body as BodyInit;
    defaultCt = "application/octet-stream";
  } else if (ctx.body !== undefined && ctx.body !== null) {
    bodyToSend = JSON.stringify(ctx.body);
    defaultCt = "application/json";
  }

  if (lockedCt) {
    headers["content-type"] = lockedCt;
  } else if (bodyToSend !== undefined) {
    headers["content-type"] = ctx.contentType ?? defaultCt ?? "application/json";
  } else if (ctx.contentType) {
    // No body but caller set a content-type — honour it (rare, but cheap).
    headers["content-type"] = ctx.contentType;
  }

  if (args.requestHeaders) Object.assign(headers, args.requestHeaders(args.props));

  const fetchOptions: RequestInit = { method: ctx.method, headers };
  if (bodyToSend !== undefined) fetchOptions.body = bodyToSend;

  const upstreamRes = await fetch(urlString, fetchOptions);

  // Stage-mode: only on 2xx + putFile dep present. Bytes go straight to R2,
  // bypassing truncateForReturn. On non-2xx, fall through to the normal error
  // envelope (so the LLM can debug — error bodies are usually small JSON).
  if (ctx.returnAs === "stage" && upstreamRes.ok) {
    if (!args.putFile) {
      throw new ToolError("returnAs:\"stage\" requires putFile dep — server staging bindings not configured");
    }
    const buf = await upstreamRes.arrayBuffer();
    const bytes = new Uint8Array(buf);
    const upstreamContentType = upstreamRes.headers.get("content-type") ?? "application/octet-stream";
    const filename = filenameFromContentDisposition(upstreamRes.headers.get("content-disposition"));
    const b64 = bytesToBase64(bytes);
    const staged = await args.putFile(b64, upstreamContentType, filename);

    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      operationId: op.operationId,
      decision: "allow",
      upstreamStatus: upstreamRes.status,
      ts: new Date().toISOString(),
    });

    if (!staged.ok) {
      return {
        success: false,
        status: staged.status,
        result: { error: "stage_failed", message: staged.message },
        errors: [{ code: staged.status, message: staged.message }],
      };
    }
    return {
      success: true,
      status: upstreamRes.status,
      result: {
        file_handle: staged.file_handle,
        token: staged.token,
        fetch_url: staged.fetch_url,
        expires_at: staged.expires_at,
        byte_length: staged.byte_length,
        contentType: upstreamContentType,
        ...(filename ? { filename } : {}),
      },
      errors: [],
    };
  }

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
    result: ctx.bypassTruncate ? parsed : truncateForReturn(parsed),
    errors: upstreamRes.ok ? [] : [{ code: upstreamRes.status, message: responseText.slice(0, 500) }],
  };
}
