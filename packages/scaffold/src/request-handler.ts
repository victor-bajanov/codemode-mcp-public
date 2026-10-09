import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { Decision, ElicitRenderer, InspectRequest, InspectResult, SurfaceReview } from "@local/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { hasUnsafePathSegment, matchOperation } from "./path-matcher";
import { truncateForReturn } from "./truncate";
import { auditLog, redactAuditEntry, type AuditEntry } from "./audit";
import { mostRestrictive } from "./restrict";
import { runElicitation, ToolError } from "./elicit";
import { deepFreeze } from "./freeze";
import { allowPiiInLogs, debugLog } from "./config";
import { buildUpstreamUrl } from "./build-upstream-url";
import type { PutFileResult } from "./staging/putfile-capability";
import type { ReadRateLimit, UpstreamRateLimit } from "./rate-limit";

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
  /** Extra outbound request headers (e.g. `Accept: application/octet-stream`
   *  for endpoints that content-negotiate binary). Merged BENEATH the
   *  scaffold-controlled set: they can never override `Authorization`, the
   *  computed `Content-Type` (use `contentType` for that), or headers set by
   *  the provider's `requestHeaders` hook. Names in DISALLOWED_CTX_HEADERS
   *  (auth material, cookies, method-override variants, content-type, …)
   *  throw a ToolError — loudly, never silently dropped. */
  headers?: Record<string, string>;
  /** Override the outbound `Content-Type` header. When unset and `body` is
   *  present, defaults to `application/json`. */
  contentType?: string;
  /** Send `body` to the upstream verbatim (no `JSON.stringify`). Use for
   *  text/XML/form payloads. For binary uploads prefer `bodyBase64` (or
   *  `multipart`) — they are the explicit, lossless binary paths handled
   *  server-side. */
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

/** JSON inspection parse cap — mirrors DEFAULT_MAX_BYTES in config.ts (50 MiB).
 *  Effective JSON payloads larger than this are denied on inspected ops rather
 *  than parsed, so the inspector never blocks on decoding an oversized body.
 *  This is a hard ceiling on inspected JSON sends; there is no larger-payload
 *  bypass channel wired today (see Task 5). */
export const INSPECT_JSON_MAX_BYTES = 50 * 1024 * 1024;

// Media-type essence (before any `;` parameters) whose subtype is `json`,
// `x-json` or a `+json` suffix, under any top-level type: `application/json`,
// `application/vnd.api+json`, `text/json`, `application/x-json`. Upstreams are
// lenient about which of these they parse as JSON, so all of them are judged
// as JSON (F-7).
const JSON_CONTENT_TYPE_RE = /^[\w.+-]+\/(?:[\w.+-]+\+)?(?:x-)?json$/i;

/** Leading and trailing HTTP whitespace (space, tab, CR, LF), which fetch's
 *  `Headers` strips from a header value before it goes on the wire. */
const HTTP_WHITESPACE_EDGES = /^[\t\n\r ]+|[\t\n\r ]+$/g;

/** The content-type as it will appear on the wire: HTTP whitespace trimmed,
 *  as `Headers` does, so the inspector judges the value that is sent (F-7). */
export function normaliseContentType(contentType: string | undefined): string | undefined {
  return contentType === undefined ? undefined : contentType.replace(HTTP_WHITESPACE_EDGES, "");
}

/** True when the content-type denotes JSON: a media type whose subtype is
 *  `json`, `x-json` or ends in `+json` (parameters and edge whitespace ignored). */
export function isJsonContentType(contentType: string | undefined): boolean {
  if (contentType === undefined) return false;
  const essence = (normaliseContentType(contentType) ?? "").split(";")[0]!.replace(HTTP_WHITESPACE_EDGES, "");
  return JSON_CONTENT_TYPE_RE.test(essence);
}

/** The single effective outbound payload, resolved from the legacy channel
 *  precedence (multipart > bodyBase64 > rawBody+body > body JSON). */
export type EffectiveBody =
  | { kind: "none" }
  | { kind: "json"; body: unknown; contentType: string }
  | { kind: "raw"; bytes: Uint8Array; contentType: string }
  | { kind: "multipart"; parts: MultipartPart[] };

/** Count of distinct body channels supplied. A legitimate request uses one. */
export function bodyChannelCount(ctx: UpstreamCtx): number {
  let n = 0;
  if (ctx.body !== undefined && ctx.body !== null) n++;
  if (typeof ctx.bodyBase64 === "string") n++;
  if (Array.isArray(ctx.multipart)) n++;
  return n;
}

/** Resolve the effective outbound payload (wire form). */
export function resolveEffective(ctx: UpstreamCtx): EffectiveBody {
  const contentType = normaliseContentType(ctx.contentType);
  if (Array.isArray(ctx.multipart)) {
    return { kind: "multipart", parts: ctx.multipart };
  }
  if (typeof ctx.bodyBase64 === "string") {
    return {
      kind: "raw",
      bytes: base64ToBytes(ctx.bodyBase64),
      contentType: contentType ?? "application/octet-stream",
    };
  }
  if (ctx.rawBody && ctx.body !== undefined && ctx.body !== null) {
    // Typed arrays (which codemode's RPC codec can revive from tagged values)
    // are rejected at handler entry (`containsBinaryValue`), so `ctx.body` is
    // never a view here. Guard the string invariant rather than silently
    // marshalling an EMPTY body — the old code sent `ctx.body as BodyInit`
    // verbatim, so a non-string here must fail loudly, not vanish.
    if (typeof ctx.body !== "string") {
      throw new ToolError("rawBody requires a string body; send binary via bodyBase64 or multipart");
    }
    return {
      kind: "raw",
      bytes: new TextEncoder().encode(ctx.body),
      contentType: contentType ?? "application/octet-stream",
    };
  }
  if (ctx.body !== undefined && ctx.body !== null) {
    return { kind: "json", body: ctx.body, contentType: contentType ?? "application/json" };
  }
  return { kind: "none" };
}

/** Marshal the effective payload to the outbound fetch body + content-type.
 *  Reused for the upstream request so inspected == sent: on inspected
 *  operations the handler passes `DerivedInspect.sendAs` when set, so raw JSON
 *  bytes go out as the canonical re-serialisation of what the inspector
 *  judged, not as the original bytes. */
export function marshalBody(
  ctx: UpstreamCtx,
  eff: EffectiveBody,
): { bodyToSend: BodyInit | undefined; contentType: string | undefined } {
  switch (eff.kind) {
    case "multipart": {
      const { body, boundary } = buildMultipartBody(eff.parts);
      return { bodyToSend: body, contentType: `multipart/form-data; boundary=${boundary}` };
    }
    case "raw":
      return { bodyToSend: eff.bytes, contentType: eff.contentType };
    case "json":
      return { bodyToSend: JSON.stringify(eff.body), contentType: eff.contentType };
    case "none":
      // No body; honour an explicit caller content-type if present (rare).
      return { bodyToSend: undefined, contentType: normaliseContentType(ctx.contentType) };
  }
}

export interface DerivedInspect {
  req: InspectRequest;
  /** True when the effective payload is JSON over the parse cap (→ deny). */
  oversize?: boolean;
  /** True when raw bytes carry a JSON content-type but do not parse (→ deny
   *  on gated operations: neither an inspector nor an approver can judge
   *  them as the JSON the upstream may still read leniently). */
  unparseableJson?: boolean;
  /** Payload to send instead of the effective one. Set when raw JSON-typed
   *  bytes parsed: the inspector judges `JSON.parse(bytes)` (last duplicate
   *  key wins, BOM stripped), so the bytes sent must be
   *  `JSON.stringify(parsed)`, never the original bytes (F-7). */
  sendAs?: EffectiveBody;
}

/** Build the canonical InspectRequest from the effective payload. */
export function deriveInspectRequest(
  ctx: UpstreamCtx,
  eff: EffectiveBody,
  maxBytes: number,
): DerivedInspect {
  const base: InspectRequest = ctx.query !== undefined ? { query: ctx.query } : {};
  switch (eff.kind) {
    case "none":
      return { req: base };
    case "json":
      return { req: { ...base, body: eff.body, contentType: eff.contentType } };
    case "multipart":
      return { req: { ...base, multipart: eff.parts, contentType: "multipart/form-data" } };
    case "raw": {
      if (isJsonContentType(eff.contentType)) {
        if (eff.bytes.byteLength > maxBytes) {
          return { req: base, oversize: true };
        }
        try {
          const parsed: unknown = JSON.parse(new TextDecoder().decode(eff.bytes));
          return {
            req: { ...base, body: parsed, contentType: eff.contentType },
            sendAs: { kind: "json", body: parsed, contentType: eff.contentType },
          };
        } catch {
          /* not valid JSON despite the content-type → flagged; also exposed as raw bytes */
          return { req: { ...base, rawBody: eff.bytes, contentType: eff.contentType }, unparseableJson: true };
        }
      }
      return { req: { ...base, rawBody: eff.bytes, contentType: eff.contentType } };
    }
  }
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

// CR, LF or NUL in a part's name/filename/content-type would let the caller
// inject extra part headers (or a whole extra part) into the assembled body
// while the inspector sees one structured part (F-11).
const MULTIPART_HEADER_INJECTION = /[\r\n\0]/;
const MULTIPART_OPTIONAL_STRING_FIELDS = ["filename", "contentType", "value", "bodyBase64"] as const;
const MULTIPART_HEADER_FIELDS = ["name", "filename", "contentType"] as const;

/** Why a multipart part list is refused, as an audit reason plus a message
 *  naming the part and field (never echoing the value), or `null` when every
 *  part is well formed. Each part must be a plain object whose `name` is a
 *  non-empty string and whose `filename`, `contentType`, `value` and
 *  `bodyBase64` are strings when present: the sandbox RPC carries arbitrary
 *  JSON, and a non-string `contentType` (for example an array) is
 *  stringified straight into the part header by `buildMultipartBody`. String
 *  header fields must not contain CR, LF or NUL. */
function multipartPartsProblem(
  parts: readonly unknown[],
): { reason: "multipart-part-malformed" | "multipart-header-injection"; message: string } | null {
  for (let i = 0; i < parts.length; i++) {
    const p: unknown = parts[i];
    if (p === null || typeof p !== "object" || Array.isArray(p)) {
      return { reason: "multipart-part-malformed", message: `multipart part ${i}: must be an object` };
    }
    const part = p as Record<string, unknown>;
    if (typeof part.name !== "string" || part.name === "") {
      return {
        reason: "multipart-part-malformed",
        message: `multipart part ${i}: \`name\` must be a non-empty string`,
      };
    }
    for (const field of MULTIPART_OPTIONAL_STRING_FIELDS) {
      const v = part[field];
      if (v !== undefined && typeof v !== "string") {
        return {
          reason: "multipart-part-malformed",
          message: `multipart part ${i}: \`${field}\` must be a string when present`,
        };
      }
    }
    for (const field of MULTIPART_HEADER_FIELDS) {
      const v = part[field];
      if (typeof v === "string" && MULTIPART_HEADER_INJECTION.test(v)) {
        return {
          reason: "multipart-header-injection",
          message: `multipart part ${i}: \`${field}\` may not contain CR, LF or NUL characters`,
        };
      }
    }
  }
  return null;
}

/** True when `value` is, or contains (through arrays and object properties),
 *  an ArrayBuffer or ArrayBuffer view. codemode's RPC codec revives
 *  `{"__codemode_binary_v1__": …}` tags into real typed arrays, which the
 *  inspector would see as bytes while `JSON.stringify` sends `{"0":104,…}` or
 *  `{}` (F-19). Cycle-safe; recursive like `deepFreeze`. */
function containsBinaryValue(value: unknown, seen: WeakSet<object> = new WeakSet()): boolean {
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return true;
  if (value === null || typeof value !== "object") return false;
  if (Object.prototype.toString.call(value) === "[object ArrayBuffer]") return true;
  if (seen.has(value)) return false;
  seen.add(value);
  for (const v of Object.values(value)) {
    if (containsBinaryValue(v, seen)) return true;
  }
  return false;
}

/** Audit-safe rendering of a ctx field that should have been a string. */
function describeNonString(v: unknown): string {
  if (v !== null && (typeof v === "object" || typeof v === "function")) {
    return Array.isArray(v) ? "[array]" : "[object]";
  }
  return String(v);
}

function buildMultipartBody(parts: MultipartPart[]): { body: Uint8Array; boundary: string } {
  // Defence in depth: handler entry already refused these (with an audit line).
  const problem = multipartPartsProblem(parts);
  if (problem) throw new ToolError(problem.message);
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

  /** MCP request id of the tool call that triggered this upstream request.
   *  Threaded from codemode's `(options, context)` request callback and passed
   *  to `elicitInput` as `relatedRequestId`, so server-initiated elicit
   *  messages route back through the originating POST response stream
   *  (codemode#1793 / agents#1510). Optional: undefined in non-MCP callers
   *  (e.g. the stageFromUpstreamJson capability) falls back to the prior
   *  best-effort routing. */
  relatedRequestId?: string | number;

  // OAuth — broker stub mints fresh access tokens; rotation lives in the broker.
  oauth: {
    refreshTokenAccessor: (props: P) => string;
    userIdAccessor: (props: P) => string | undefined;
    broker: import("./token-broker").TokenBrokerStub;
  };

  // Per-request provider hook — merged into outbound fetch headers
  requestHeaders?: (props: P) => Record<string, string>;

  /** Provider hook — parses the upstream's rate-limit response headers.
   *  When set, its result rides on the response envelope as `rateLimit` and,
   *  on a 429, leads `errors[0].message`. See `rate-limit.ts`. */
  readRateLimit?: ReadRateLimit;

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

// Header names sandbox code may NOT supply via ctx.headers. Auth material
// never enters the sandbox; content-type has dedicated fields (`contentType`,
// `multipart` — which owns its boundary header); and the method-override
// family would let an allowed operation impersonate a different, unreviewed
// verb upstream (Google APIs honour X-HTTP-Method-Override). Rejection is a
// loud ToolError: the silently-dropped-header behaviour this feature replaces
// produced wrong upstream bytes with no error anywhere.
const DISALLOWED_CTX_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "content-type",
  "x-http-method-override",
  "x-http-method",
  "x-method-override",
]);

function assertAllowedCtxHeaders(headers: Record<string, string> | undefined): void {
  if (!headers) return;
  const seen = new Set<string>();
  for (const name of Object.keys(headers)) {
    const lower = name.toLowerCase();
    if (DISALLOWED_CTX_HEADERS.has(lower)) {
      throw new ToolError(
        lower === "content-type"
          ? 'headers may not set content-type — use the `contentType` option (or `multipart`, which generates its own)'
          : `Header "${name}" cannot be set from sandbox code`,
      );
    }
    // Two casings of one name would BOTH survive the plain-object spread and
    // fetch's Headers would comma-combine their values ("application/json,
    // application/octet-stream") — corrupted content negotiation with no error.
    if (seen.has(lower)) {
      throw new ToolError(
        `Header "${name}" appears more than once (names differing only by case are the same header)`,
      );
    }
    seen.add(lower);
  }
}

export async function handleUpstreamRequest<P extends Record<string, unknown>>(
  args: HandleArgs<P>,
): Promise<unknown> {
  const { spec, surfaceReview } = args;
  // Entry validation (malformed requests): before anything reads the ctx, so a
  // doomed request never reaches surface review, elicitation or token minting.
  if (typeof args.ctx.method !== "string" || typeof args.ctx.path !== "string") {
    // F-24: `method: 42` used to surface as a raw TypeError with no audit line.
    emitAudit(args, {
      deployment: args.deploymentName,
      method: describeNonString(args.ctx.method),
      path: describeNonString(args.ctx.path),
      decision: "deny",
      category: "malformed",
      reason: "invalid-method-or-path",
      ts: new Date().toISOString(),
    });
    throw new ToolError("codemode.request needs string `method` and `path`");
  }
  if (args.ctx.contentType !== undefined && typeof args.ctx.contentType !== "string") {
    // A non-string content-type would be stringified into the header while
    // the JSON check below read something else (F-7).
    emitAudit(args, {
      deployment: args.deploymentName,
      method: args.ctx.method,
      path: args.ctx.path,
      decision: "deny",
      category: "malformed",
      reason: "invalid-content-type",
      ts: new Date().toISOString(),
    });
    throw new ToolError("codemode.request `contentType` must be a string when present");
  }
  if (
    containsBinaryValue(args.ctx.body) ||
    containsBinaryValue(args.ctx.query) ||
    containsBinaryValue(args.ctx.multipart)
  ) {
    emitAudit(args, {
      deployment: args.deploymentName,
      method: args.ctx.method,
      path: args.ctx.path,
      decision: "deny",
      category: "malformed",
      reason: "binary-value-in-request",
      ts: new Date().toISOString(),
    });
    throw new ToolError(
      "Binary values (Uint8Array/ArrayBuffer) are not accepted in body, query or multipart; send bytes with bodyBase64 or multipart[].bodyBase64",
    );
  }
  if (Array.isArray(args.ctx.multipart)) {
    const problem = multipartPartsProblem(args.ctx.multipart);
    if (problem) {
      emitAudit(args, {
        deployment: args.deploymentName,
        method: args.ctx.method,
        path: args.ctx.path,
        decision: "deny",
        category: "malformed",
        reason: problem.reason,
        ts: new Date().toISOString(),
      });
      throw new ToolError(problem.message);
    }
  }
  // Validate before any token mint / elicitation round: a doomed request must
  // not cost the user an approval dialog first.
  assertAllowedCtxHeaders(args.ctx.headers);
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
  // F-1 / F-6: refuse any segment the WHATWG URL parser could rewrite (dot
  // segments, `\`, control characters) or that smuggles query/fragment syntax
  // (a raw `?` or `#`) or an extra segment (encoded `/` or `\`), so the
  // operation matched below is the operation the upstream receives. An encoded
  // `?`/`#` inside a value is fine: the wire path re-encodes it.
  if (hasUnsafePathSegment(ctx.path)) {
    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      decision: "deny",
      category: "url_safety",
      reason: "unsafe-path-segment",
      ts: new Date().toISOString(),
    });
    throw new ToolError(
      'Path contains a disallowed segment ("."/"..", a raw "\\", "?" or "#", a control character, or an encoded "/" or "\\"); pass query parameters via `query`, and percent-encode "?" or "#" inside a path value',
    );
  }
  const match = matchOperation(spec, ctx.method, ctx.path);

  if (!match) {
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
  const op = match.op;

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

  // Build the outbound URL from the template-derived wire path BEFORE
  // inspection, elicitation and token minting, so nothing is judged, approved
  // or authorised for a request that cannot be sent as reviewed.
  let urlString: string;
  try {
    urlString = buildUpstreamUrl(args.apiBaseUrl, match.wirePath, ctx.query);
  } catch (err) {
    // M3 / F-1: defence-in-depth on URL origin and path. Tag mismatch deny
    // audits with category "url_safety" so they're greppable in production logs.
    if (
      err instanceof ToolError &&
      (err.message.startsWith("upstream-url-origin-mismatch") ||
        err.message.startsWith("upstream-url-path-mismatch"))
    ) {
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
  // Re-resolve the operation from what the upstream will actually receive and
  // require the very same operation object (F-1): a raw segment such as
  // `lab%65ls` matches a param slot but goes out as the literal `labels`.
  const wire = matchOperation(spec, ctx.method, new URL(urlString).pathname);
  if (!wire || wire.op !== op) {
    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      operationId: op.operationId,
      decision: "deny",
      category: "url_safety",
      reason: "operation-mismatch-after-url-build",
      ts: new Date().toISOString(),
    });
    throw new ToolError(
      `Path for ${op.operationId} would reach a different operation once sent; refusing the request`,
    );
  }

  // Sandbox-supplied headers are refused outright on gated operations. The
  // inspector receives query/body only, the elicit dialog renders
  // method/path/body/query only, and the audit line records none of the
  // headers — so a semantics-bearing header (If-Match, Prefer, …) would ride
  // through approval unseen and the approved request would differ from the
  // bytes actually sent. Plain "allow" operations grant the caller the
  // operation wholesale, so extra headers add no authority there.
  if (
    ctx.headers &&
    Object.keys(ctx.headers).length > 0 &&
    (review.inspect !== undefined || review.decision === "elicit")
  ) {
    throw new ToolError(
      `Operation ${op.operationId} is subject to inspection/approval — ` +
        "sandbox-supplied `headers` are not allowed on it; remove `headers` from this codemode.request call",
    );
  }

  let decision: Decision = review.decision;
  let category: string | undefined = review.category;
  let reason: string | undefined;
  // Human-readable explanation from the inspector, surfaced to the caller on deny.
  // `reason` stays the terse audit code; `denyMessage` is the caller-facing prose.
  let denyMessage: string | undefined;

  // Provider-declared payload normalization (SurfaceReviewEntry.normalizeBody):
  // best-effort repair of the parsed JSON body (e.g. Gmail rewriting a
  // mojibake'd Subject into a proper RFC 2047 encoded-word), applied BEFORE the
  // effective payload is resolved so inspection, the elicit dialog, and the
  // upstream send all see the same normalized payload. Fail-open by contract:
  // a normalizer that throws or returns undefined leaves the payload untouched
  // — repair must never block a request it cannot confidently improve.
  let nctx = ctx;
  if (review.normalizeBody && ctx.body !== undefined && ctx.body !== null) {
    try {
      const replaced = review.normalizeBody(ctx.body);
      if (replaced !== undefined) {
        nctx = { ...ctx, body: deepFreeze(replaced) };
      }
    } catch {
      /* keep the original payload */
    }
  }

  // Resolve the single effective outbound payload ONCE, before inspection, and
  // reuse it for marshalling below — so the bytes inspected and the bytes sent
  // are one and the same. Can throw ToolError (rawBody + non-string body); that
  // propagation is correct, mirroring the other deny paths.
  const eff = resolveEffective(nctx);
  // What is actually marshalled: `eff`, except on gated raw JSON, where it is
  // the canonical re-serialisation of what was inspected and approved (F-7).
  // Plain "allow" operations keep sending the original bytes.
  let sendEff: EffectiveBody = eff;

  // Gated operations (inspected, or needing approval) must be judged on the
  // payload that is sent. Plain "allow" operations grant the caller the
  // operation wholesale, so they keep the legacy channel precedence.
  const gated = review.inspect !== undefined || review.decision === "elicit";
  let inspectResult: InspectResult | undefined;
  // What the approval dialog renders: the parsed JSON payload that is sent,
  // or nothing when the payload cannot be shown (see `opaquePayload`).
  let renderBody: unknown = nctx.body;
  // Set when an approval would otherwise be asked over a payload nobody
  // interpreted (raw non-JSON bytes or multipart, no inspector).
  let opaquePayload: string | undefined;
  if (gated) {
    const denyMalformed = (why: string): never => {
      emitAudit(args, {
        deployment: args.deploymentName,
        method: ctx.method,
        path: ctx.path,
        operationId: op.operationId,
        decision: "deny",
        category: "malformed",
        reason: why,
        ts: new Date().toISOString(),
      });
      throw new ToolError(`Operation ${op.operationId} is denied by surface review`);
    };
    // One-channel guard: a legitimate caller uses exactly one body channel.
    // Supplying two is the decoy primitive (inspect or show one, send
    // another) → deny, on approval-only operations as well as inspected ones.
    if (bodyChannelCount(nctx) > 1) denyMalformed("multiple-body-channels");
    const derived = deriveInspectRequest(nctx, eff, INSPECT_JSON_MAX_BYTES);
    if (derived.oversize) denyMalformed("oversize-json-body");
    if (derived.unparseableJson) denyMalformed("unparseable-json-body");
    sendEff = derived.sendAs ?? eff;
    if (sendEff.kind === "json") {
      renderBody = sendEff.body;
    } else if (sendEff.kind === "none") {
      renderBody = undefined;
    } else {
      renderBody = undefined;
      if (!review.inspect) {
        opaquePayload =
          sendEff.kind === "raw"
            ? `${sendEff.contentType.slice(0, 100)}, ${sendEff.bytes.byteLength} bytes`
            : `multipart, ${sendEff.parts.length} part${sendEff.parts.length === 1 ? "" : "s"}`;
      }
    }
    if (review.inspect) {
      // Freeze the derived request so inspectors cannot mutate what will be sent,
      // matching the deepFreeze protection previously applied to ctx.body.
      // env rides along un-frozen (it is the live worker env, bindings included)
      // so inspectors can resolve per-deployment policy vars.
      inspectResult = review.inspect(deepFreeze(derived.req), args.env);
      decision = mostRestrictive(decision, inspectResult.decision);
      if (inspectResult.category) category = inspectResult.category;
      if (inspectResult.reason) reason = inspectResult.reason;
      if (inspectResult.message) denyMessage = inspectResult.message;
    }
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
    // Prefer the inspector's specific explanation (e.g. "only DRAFT or SUBMITTED
    // credit notes can be modified; this one is AUTHORISED") over the opaque generic.
    throw new ToolError(denyMessage ?? `Operation ${op.operationId} is denied by surface review`);
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
      body: renderBody,
      ...(opaquePayload !== undefined ? { opaquePayload } : {}),
      env: args.env,
      ...(args.relatedRequestId !== undefined ? { relatedRequestId: args.relatedRequestId } : {}),
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

  // ctx.headers first (validated at entry), so the scaffold-controlled set
  // below always wins on collision — sandbox code can extend, never override.
  // Collisions are matched case-insensitively: a plain-object spread would
  // keep `Xero-Tenant-Id` and `xero-tenant-id` as distinct keys, and fetch's
  // Headers would then COMBINE both values — an override-by-casing bypass.
  const headers: Record<string, string> = { ...ctx.headers };
  const setHeader = (name: string, value: string): void => {
    for (const k of Object.keys(headers)) {
      if (k.toLowerCase() === name.toLowerCase()) delete headers[k];
    }
    headers[name] = value;
  };
  setHeader("Authorization", `Bearer ${accessToken}`);

  // Marshal the SAME effective payload resolved before inspection (or its
  // canonical form, see `sendEff`), so the bytes inspected and the bytes sent
  // are one and the same.
  const { bodyToSend, contentType: outboundContentType } = marshalBody(nctx, sendEff);
  if (outboundContentType) {
    setHeader("content-type", outboundContentType);
  }

  if (args.requestHeaders) {
    for (const [name, value] of Object.entries(args.requestHeaders(args.props))) {
      setHeader(name, value);
    }
  }

  // F-17: never follow redirects. The origin and path guards vouch only for
  // the URL built above; a followed 3xx would replay the request to wherever
  // the upstream (or anything in front of it) points, unreviewed.
  const fetchOptions: RequestInit = { method: ctx.method, headers, redirect: "manual" };
  if (bodyToSend !== undefined) fetchOptions.body = bodyToSend;

  const upstreamRes = await fetch(urlString, fetchOptions);

  // Rate-limit headers are read off EVERY response (2xx included) so the caller
  // sees its remaining budget before it runs out, not only once throttled. A
  // provider reader is best-effort telemetry: if it throws, the upstream result
  // still gets returned intact.
  let rateLimit: UpstreamRateLimit | undefined;
  if (args.readRateLimit) {
    try {
      rateLimit = args.readRateLimit(upstreamRes);
    } catch (err) {
      debugLog(args.env, "rate-limit-reader-threw", { message: String(err) }, { containsPii: false });
    }
  }
  const rateLimitField = rateLimit ? { rateLimit } : {};
  // Audit only the throttled responses: `problem`/`retryAfterSeconds` are the
  // operationally interesting signal, whereas per-call remaining counters would
  // bloat every audit line.
  const rateLimitAudit = rateLimit && upstreamRes.status === 429 ? { rateLimit } : {};

  // A 3xx (other than 304 Not Modified) is reported, never followed or staged.
  // `Location` is not echoed: it is upstream-controlled and may carry tokens.
  if (upstreamRes.status >= 300 && upstreamRes.status < 400 && upstreamRes.status !== 304) {
    try { await upstreamRes.body?.cancel(); } catch { /* best effort */ }
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
      success: false,
      status: upstreamRes.status,
      result: { error: "upstream_redirect" },
      errors: [{
        code: upstreamRes.status,
        message: `Upstream answered with a redirect (HTTP ${upstreamRes.status}); redirects are not followed`,
      }],
      ...rateLimitField,
    };
  }

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
        ...rateLimitField,
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
      ...rateLimitField,
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
    ...rateLimitAudit,
    ts: new Date().toISOString(),
  });

  // On a 429 the upstream body is usually a bare "oops, rate limit exceeded"
  // with no indication of WHICH limit or how long to wait — that lives in the
  // headers. The envelope contract points clients at `errors[0].message`, so
  // the reason leads there (body kept after it, for debugging).
  const errorMessage = responseText.slice(0, 500);
  const rateLimitedMessage =
    upstreamRes.status === 429 && rateLimit?.message
      ? (errorMessage ? `${rateLimit.message} Upstream said: ${errorMessage}` : rateLimit.message)
      : errorMessage;

  return {
    success: upstreamRes.ok,
    status: upstreamRes.status,
    result: ctx.bypassTruncate ? parsed : truncateForReturn(parsed),
    errors: upstreamRes.ok ? [] : [{ code: upstreamRes.status, message: rateLimitedMessage }],
    ...rateLimitField,
  };
}
