import type { OpenApiOperation, OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type {
  Decision,
  ElicitRenderer,
  InspectMultipartPart,
  InspectRequest,
  InspectResult,
  SurfaceReview,
  SurfaceReviewEntry,
} from "@local/shared";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { hasUnsafePathSegment, matchOperation } from "./path-matcher";
import { truncateForReturn } from "./truncate";
import { auditLog, redactAuditEntry, type AuditEntry } from "./audit";
import { mostRestrictive } from "./restrict";
import { MAX_DIALOG_QUERY_PAIRS, runElicitation, ToolError } from "./elicit";
import { deepFreeze } from "./freeze";
import { allowPiiInLogs, debugLog } from "./config";
import { buildUpstreamUrl } from "./build-upstream-url";
import type { PutFileResult } from "./staging/putfile-capability";
import type { ReadRateLimit, UpstreamRateLimit } from "./rate-limit";
import {
  assembledLength,
  base64ToBytes,
  buildInspectionView,
  compileStagedMultipart,
  multipartPartHead,
  newMultipartBoundary,
  sanitiseStagedFilename,
  stagedPartDefaults,
} from "./compose/assemble";
import {
  COMPOSED_MAX_TEXT_BYTES,
  STAGED_SENTINEL,
  isWellFormedText,
  parseStagedRef,
  validateComposed,
  type Segment,
  type StagedEncoding,
} from "./compose/validate";
import {
  platformSuppliesContentLength,
  sendAssembled,
  transferController,
  transferFailure,
  type TransferController,
} from "./compose/transfer";
import type { TransferGateLike } from "./staging/gate-dep";
import {
  blockSourceFromBytes,
  blockSourceFromStream,
  stageFromBlocks,
  type OpenStagedFile,
  type OpenStagedResult,
  type StagedFileMeta,
  type StagedRef,
} from "./staging/staged-file";
import type { PutFileCapabilityDeps } from "./staging/putfile-capability";
import { DEFAULT_COMPOSE_MAX_BYTES, DEFAULT_TRANSFER_TIMEOUT_MS } from "./staging/types";
import { auditQueryKeys, checkQuery } from "./query-policy";
import { createUpstreamLookup, UpstreamLookupError } from "./upstream-lookup";
import { canonicalJsonContentType, JSON_ESSENCE_RE, parseMediaType } from "./content-type-policy";
import { collectUntrustedPointers, fenceUntrusted, untrustedPointersForStatus } from "./untrusted-fence";

const DECISIONS: ReadonlySet<unknown> = new Set<Decision>(["allow", "elicit", "deny"]);

/** A hook result the handler can act on: an object with a known decision
 *  and, when present, an object `summary`. Anything else is a deny. */
function isInspectResult(r: unknown): r is InspectResult {
  if (r === null || typeof r !== "object") return false;
  const { decision, summary } = r as { decision?: unknown; summary?: unknown };
  if (!DECISIONS.has(decision)) return false;
  return summary === undefined || (summary !== null && typeof summary === "object" && !Array.isArray(summary));
}

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
  /** A staged file the host attaches as this part's bytes (never crossing
   *  the sandbox). Mutually exclusive with `value`/`bodyBase64`;
   *  `filename`/`contentType` default from the staged row. */
  staged?: StagedRef;
}

export type ComposedSegmentInput =
  | { text: string }
  | { staged: StagedRef; encoding: StagedEncoding };
export interface ComposedBody {
  segments: ComposedSegmentInput[];
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
  /** Host-assembled body: text segments plus staged-file references, each
   *  with an encoding. The host resolves the references, shows inspectors a
   *  view with one U+FFFC per staged slot, and writes the bytes itself — they
   *  never cross the sandbox. Mutually exclusive with `body`, `bodyBase64`,
   *  `rawBody` and `multipart` on every operation. */
  composed?: ComposedBody;
  /** Internal escape hatch for `__stagingHost.stageFromUpstreamJson`. When
   *  true, the parsed JSON result is returned WITHOUT `truncateForReturn` —
   *  so a downstream caller can pluck a large base64 field intact and stage
   *  it server-side. NOT documented in `executeAddendum` — internal use only.
   *  Ignored when `returnAs === "stage"`. */
  bypassTruncate?: boolean;
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
// as JSON (F-7). The rule (`JSON_ESSENCE_RE`) is shared with the D-3
// content-type policy so both judge "is this JSON" identically.

/** Leading and trailing HTTP whitespace (space, tab, CR, LF), which fetch's
 *  `Headers` strips from a header value before it goes on the wire. */
const HTTP_WHITESPACE_EDGES = /^[\t\n\r ]+|[\t\n\r ]+$/g;

/** Strict UTF-8 for raw JSON bodies (see `deriveInspectRequest`). A
 *  non-streaming `decode` keeps no state, so one instance is reused. */
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

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
  return JSON_ESSENCE_RE.test(essence);
}

/** The single effective outbound payload, resolved from the legacy channel
 *  precedence (multipart > bodyBase64 > rawBody+body > body JSON). */
export type EffectiveBody =
  | { kind: "none" }
  | { kind: "json"; body: unknown; contentType: string }
  | { kind: "raw"; bytes: Uint8Array; contentType: string }
  | { kind: "multipart"; parts: MultipartPart[] }
  | {
      /** Host-assembled: a `composed` body, or a multipart list with staged
       *  parts compiled behind a host-random boundary (`multipartParts`). */
      kind: "composed";
      segments: Segment[];
      files: OpenStagedFile[];
      metas: StagedFileMeta[];
      contentType: string;
      length: number;
      multipartParts?: MultipartPart[];
    };

/** Count of distinct body channels supplied. A legitimate request uses one. */
export function bodyChannelCount(ctx: UpstreamCtx): number {
  let n = 0;
  if (ctx.body !== undefined && ctx.body !== null) n++;
  if (typeof ctx.bodyBase64 === "string") n++;
  if (Array.isArray(ctx.multipart)) n++;
  if (ctx.composed !== undefined) n++;
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
    case "composed":
      // The body is written by `sendAssembled` into a fixed-length sink.
      return { bodyToSend: undefined, contentType: eff.contentType };
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
   *  bytes parsed: the inspector judges `JSON.parse(bytes)` (strict UTF-8, no
   *  BOM; last duplicate key wins), so the bytes sent must be
   *  `JSON.stringify(parsed)`, never the original bytes (F-7). */
  sendAs?: EffectiveBody;
}

/** An inline (non-staged) part as the inspector sees it. */
function inlinePart(p: MultipartPart): InspectMultipartPart {
  const { staged: _staged, ...rest } = p;
  return rest;
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
      return { req: { ...base, multipart: eff.parts.map(inlinePart), contentType: "multipart/form-data" } };
    case "composed": {
      if (eff.multipartParts) {
        let k = 0;
        const multipart = eff.multipartParts.map((p): InspectMultipartPart => {
          if (p.staged === undefined) return inlinePart(p);
          const meta = eff.metas[k++]!;
          const d = stagedPartDefaults(p, meta);
          return {
            name: p.name,
            ...(d.filename !== null ? { filename: d.filename } : {}),
            contentType: d.contentType,
            staged: { byteLength: meta.byteLength, contentType: d.contentType, filename: d.filename },
          };
        });
        return {
          req: { ...base, multipart, contentType: "multipart/form-data", assembledByteLength: eff.length },
        };
      }
      const view = buildInspectionView(eff.segments, eff.metas);
      return {
        req: {
          ...base,
          rawBody: view.rawBody,
          contentType: eff.contentType,
          staged: view.staged,
          assembledByteLength: view.assembledByteLength,
        },
      };
    }
    case "raw": {
      if (isJsonContentType(eff.contentType)) {
        if (eff.bytes.byteLength > maxBytes) {
          return { req: base, oversize: true };
        }
        try {
          // Strict UTF-8 (RFC 8259 §8.1): a BOM is kept (so JSON.parse
          // refuses it) and an invalid sequence throws, instead of being
          // stripped or replaced with U+FFFD, so the parsed value is exactly
          // what a UTF-8 reader upstream would see (D-3).
          const text = STRICT_UTF8.decode(eff.bytes);
          const parsed: unknown = JSON.parse(text);
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

/** True when `atob` (WHATWG forgiving-base64) would decode `s`: ASCII
 *  whitespace ignored, `=` padding optional, alphabet A–Z a–z 0–9 + /. */
export function isDecodableBase64(s: string): boolean {
  let t = s.replace(/[\t\n\f\r ]/g, "");
  if (t.length % 4 === 0) t = t.replace(/={1,2}$/, "");
  return t.length % 4 !== 1 && /^[A-Za-z0-9+/]*$/.test(t);
}

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
    if (part.staged !== undefined) {
      if (parseStagedRef(part.staged) === null) {
        return {
          reason: "multipart-part-malformed",
          message: `multipart part ${i}: \`staged\` must be { file_handle, token } from register_file_handle or a staging call`,
        };
      }
      if (part.value !== undefined || part.bodyBase64 !== undefined) {
        return {
          reason: "multipart-part-malformed",
          message: `multipart part ${i}: \`staged\` cannot be combined with \`value\` or \`bodyBase64\``,
        };
      }
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
    if (part.staged === undefined && part.value !== undefined && part.bodyBase64 !== undefined) {
      return {
        reason: "multipart-part-malformed",
        message: `multipart part ${i}: \`value\` and \`bodyBase64\` are mutually exclusive`,
      };
    }
    if (typeof part.bodyBase64 === "string" && !isDecodableBase64(part.bodyBase64)) {
      return {
        reason: "multipart-part-malformed",
        message: `multipart part ${i}: \`bodyBase64\` must be valid base64`,
      };
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

export function buildMultipartBody(
  parts: MultipartPart[],
  boundary: string = newMultipartBoundary(),
): { body: Uint8Array; boundary: string } {
  // Defence in depth: handler entry already refused these (with an audit line).
  const problem = multipartPartsProblem(parts);
  if (problem) throw new ToolError(problem.message);
  const enc = new TextEncoder();
  const chunks: Uint8Array[] = [];
  for (const p of parts) {
    if (!p.name) throw new ToolError("multipart part: name is required");
    if (p.staged !== undefined) throw new ToolError("multipart part: staged parts are assembled by the host");
    if (p.value !== undefined && p.bodyBase64 !== undefined) {
      throw new ToolError(`multipart part "${p.name}": value and bodyBase64 are mutually exclusive`);
    }
    const defaultCt = p.bodyBase64 !== undefined ? "application/octet-stream" : "text/plain";
    chunks.push(enc.encode(multipartPartHead(boundary, p.name, p.filename, p.contentType ?? defaultCt)));
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

  /** `ApiProvider.standardQueryParams`: query names accepted on every
   *  operation besides the ones it declares (D-2). */
  standardQueryParams?: readonly string[];

  /** `ApiProvider.untrustedFieldExtension`: response-schema extension key
   *  whose flagged strings are fenced before they are returned (F2-8). */
  untrustedFieldExtension?: string;

  /** Narrow env shape; populated by `mcp-agent-factory` from `this.env`.
   *  Kept structural (not `ProviderEnv`) so tests can build minimal envs. */
  env: { ALLOW_PII_IN_LOGS?: string; DEBUG_ELICIT?: string };

  /** Optional staging store (UNGATED putFile deps: the handler holds the
   *  transfer gate itself). When present, enables `ctx.returnAs === "stage"`:
   *  the upstream body is read block by block, encrypted and streamed to R2. */
  stagingStore?: PutFileCapabilityDeps;

  /** Resolves a `{ file_handle, token }` reference against D1 (no R2 read
   *  until the blocks are pulled). When absent, `composed` and
   *  `multipart[].staged` are refused. */
  openStaged?: (ref: StagedRef) => Promise<OpenStagedResult>;

  /** Gate lease of `__stagingHost.stageFromUpstreamJson` (the internal
   *  `bypassTruncate` path): acquired after the request is approved and the
   *  token minted, released by the capability after it has parsed and
   *  stored the result. The handler never releases it. */
  gateLease?: { acquire(): Promise<void> };

  /** Transfer gate (D8) held across every file-sized send or download. */
  transferGate?: TransferGateLike;

  /** Aborted when the execute run's host-side deadline fires; aborts any
   *  staged transfer in flight (D3a). */
  signal?: AbortSignal;

  /** One object per execute run: the gate's per-run key. Absent → each call
   *  is its own run. */
  runKey?: object;

  /** `STAGING_COMPOSE_MAX_BYTES` / `STAGING_TRANSFER_TIMEOUT_MS`; defaults
   *  apply when absent. */
  stagingLimits?: { composeMaxBytes?: number; transferTimeoutMs?: number };
}

/** Status words for a staged reference that does not resolve; the opener's
 *  own messages are token- and handle-free by contract. */
function stagedRefFailure(where: string, r: { status: number; message: string }): string {
  return `${where}: ${r.message} (HTTP ${r.status})`;
}

/** "name (N bytes)" per staged file, for the approval dialog. Filenames are
 *  row-derived: control and Unicode format characters (bidi overrides) are
 *  stripped so they cannot reorder the dialog text. */
function attachmentsLine(metas: readonly StagedFileMeta[]): string {
  return metas
    .map((m) => `${sanitiseStagedFilename(m.filename, { stripFormat: true }) ?? "unnamed file"} (${m.byteLength} bytes)`)
    .join("; ");
}

/** Strict `Content-Length` of an identity-encoded response, else null (a
 *  decoded `Content-Encoding` body has a different length). */
function declaredResponseLength(headers: Headers): number | null {
  const enc = headers.get("content-encoding");
  if (enc !== null && enc.trim().toLowerCase() !== "identity" && enc.trim() !== "") return null;
  const v = headers.get("content-length");
  if (v === null || !/^\d+$/.test(v.trim())) return null;
  const n = Number(v.trim());
  return Number.isSafeInteger(n) ? n : null;
}

/** Apply `normalizeComposedText` to the text before the first staged
 *  segment. Fail-open: a throw, `undefined`, or a result that breaks the text
 *  rules leaves the segments unchanged. */
function normaliseComposed(entry: SurfaceReviewEntry, segments: Segment[]): Segment[] {
  const fn = entry.normalizeComposedText;
  if (!fn) return segments;
  const firstStaged = segments.findIndex((s) => s.kind === "staged");
  const leadEnd = firstStaged < 0 ? segments.length : firstStaged;
  if (leadEnd === 0) return segments;
  // ignoreBOM: a leading U+FEFF is part of the bytes sent and must survive.
  const decoder = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });
  let text = "";
  for (let i = 0; i < leadEnd; i++) {
    const seg = segments[i]!;
    if (seg.kind === "text") {
      text += decoder.decode(seg.bytes);
    }
  }
  let replaced: string | undefined;
  try {
    replaced = fn(text);
  } catch {
    return segments;
  }
  if (typeof replaced !== "string" || replaced.includes(STAGED_SENTINEL) || !isWellFormedText(replaced)) {
    return segments;
  }
  const bytes = new TextEncoder().encode(replaced);
  let otherText = 0;
  for (let i = leadEnd; i < segments.length; i++) {
    const seg = segments[i]!;
    if (seg.kind === "text") otherText += seg.bytes.byteLength;
  }
  if (bytes.byteLength + otherText > COMPOSED_MAX_TEXT_BYTES) return segments;
  return [{ kind: "text", bytes }, ...segments.slice(leadEnd)];
}

const NEVER_ABORTED = new AbortController().signal;

/** Best-effort, not awaited: cancelling a teed or stalled body can wait on
 *  the other branch or the network, and nothing here depends on it. */
function cancelQuietly(res: Response): void {
  try {
    res.body?.cancel().catch(() => {});
  } catch {
    /* locked or already consumed */
  }
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
// verb upstream (Google APIs honour X-HTTP-Method-Override). The credential /
// project-attribution set (wave-1 W4 note: the header twin of the refused
// `key` query parameter) would add authority even on a plain-allow operation.
// Exact names only: `Idempotency-Key` and the like stay allowed. Rejection is
// a loud, audited ToolError: the silently-dropped-header behaviour this
// feature replaces produced wrong upstream bytes with no error anywhere.
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
  "x-goog-api-key",
  "x-goog-user-project",
  "x-goog-authuser",
  "x-goog-iam-authorization-token",
  "x-goog-iam-authority-selector",
  "x-api-key",
  "api-key",
  "x-auth-token",
]);

/** At most this many sandbox-supplied headers per request (D-6). */
const MAX_CTX_HEADERS = 32;
/** At most this many characters per header name (D-6). */
const MAX_CTX_HEADER_NAME = 256;
/** At most this many characters per header value (D-6). */
const MAX_CTX_HEADER_VALUE = 4096;
/** RFC 7230 `token`: the only names `fetch`'s Headers accepts. */
const HEADER_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
/** CR, LF, NUL, or anything outside a ByteString (Headers throws on those). */
const BAD_HEADER_VALUE_RE = /[\r\n\0\u0100-\uffff]/;

/** Why sandbox-supplied `headers` are refused (an audit reason and the
 *  caller-facing message), or undefined when they may be sent. Pure; the
 *  message never echoes an invalid name or any value. */
export function headerProblem(headers: unknown): { reason: string; message: string } | undefined {
  if (headers === undefined || headers === null) return undefined;
  if (typeof headers !== "object" || Array.isArray(headers)) {
    return {
      reason: "invalid-header-value",
      message: "codemode.request `headers` must be an object of header names to string values",
    };
  }
  const entries = Object.entries(headers as Record<string, unknown>);
  if (entries.length > MAX_CTX_HEADERS) {
    return {
      reason: "too-many-headers",
      message: `codemode.request \`headers\` may carry at most ${MAX_CTX_HEADERS} headers`,
    };
  }
  const seen = new Set<string>();
  for (const [name, value] of entries) {
    if (name.length > MAX_CTX_HEADER_NAME || !HEADER_NAME_RE.test(name)) {
      return {
        reason: "invalid-header-name",
        message:
          "codemode.request `headers` has a name that is not a valid HTTP header name (letters, digits and !#$%&'*+.^_`|~- only)",
      };
    }
    const lower = name.toLowerCase();
    if (lower === "content-type") {
      return {
        reason: "content-type-header",
        message:
          'headers may not set content-type — use the `contentType` option (or `multipart`, which generates its own)',
      };
    }
    if (DISALLOWED_CTX_HEADERS.has(lower)) {
      return { reason: "forbidden-header", message: `Header "${name}" cannot be set from sandbox code` };
    }
    // Two casings of one name would BOTH survive the plain-object spread and
    // fetch's Headers would comma-combine their values ("application/json,
    // application/octet-stream") — corrupted content negotiation with no error.
    if (seen.has(lower)) {
      return {
        reason: "duplicate-header",
        message: `Header "${name}" appears more than once (names differing only by case are the same header)`,
      };
    }
    seen.add(lower);
    if (typeof value !== "string" || value.length > MAX_CTX_HEADER_VALUE || BAD_HEADER_VALUE_RE.test(value)) {
      return {
        reason: "invalid-header-value",
        message: `Header "${name}" needs a string value of at most ${MAX_CTX_HEADER_VALUE} characters with no CR, LF, NUL or characters above U+00FF`,
      };
    }
  }
  return undefined;
}

/** Longest `method` / `path` (code points) the handler will match (B-2). */
const MAX_REQUEST_METHOD = 32;
const MAX_REQUEST_PATH = 4096;

/** True when `s` has more than `max` code points (no copy for short strings). */
function exceedsCodePoints(s: string, max: number): boolean {
  if (s.length <= max) return false;
  let n = 0;
  for (const _ of s) {
    if (++n > max) return true;
  }
  return false;
}

/** The fixed audit `reason` of a failed dispatch or transfer (E-4). Only the
 *  fixed prefixes of `compose/transfer.ts`'s ToolErrors are read; no message
 *  text reaches the log. */
export function failureReason(err: unknown): string {
  if (!(err instanceof ToolError)) return "upstream-request-failed";
  const m = err.message;
  if (m.startsWith("staged transfer aborted")) return "transfer-aborted";
  if (m.startsWith("staged transfer timed out")) return "transfer-timeout";
  if (m.startsWith("staged transfer failed: upstream closed the connection")) return "upstream-closed";
  if (m.startsWith("staged transfer failed:")) return "staged-read-failed";
  return "upstream-request-failed";
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
  const { method: entryMethod, path: entryPath } = args.ctx;
  /** Audit an entry-validation deny (category `malformed`; no operation is
   *  resolved yet) and throw `message`. */
  function denyAtEntry(reason: string, message: string): never {
    emitAudit(args, {
      deployment: args.deploymentName,
      method: entryMethod,
      path: entryPath,
      decision: "deny",
      category: "malformed",
      reason,
      ts: new Date().toISOString(),
    });
    throw new ToolError(message);
  }
  if (
    exceedsCodePoints(args.ctx.method, MAX_REQUEST_METHOD) ||
    exceedsCodePoints(args.ctx.path, MAX_REQUEST_PATH)
  ) {
    // B-2: a 300 KB path never reaches the matcher; the sink caps the line.
    denyAtEntry("oversize-method-or-path", "codemode.request method or path is too long");
  }
  if (args.ctx.contentType !== undefined && typeof args.ctx.contentType !== "string") {
    // A non-string content-type would be stringified into the header while
    // the JSON check below read something else (F-7).
    denyAtEntry("invalid-content-type", "codemode.request `contentType` must be a string when present");
  }
  if (args.ctx.contentType !== undefined && parseMediaType(args.ctx.contentType) === undefined) {
    // C-4 / D-3: only a syntactically valid media type can be carried, so no
    // prose, newline or control character can reach a header or a dialog.
    denyAtEntry(
      "invalid-content-type",
      "codemode.request `contentType` must be a media type such as application/json (parameters allowed; at most 100 characters)",
    );
  }
  if (typeof args.ctx.bodyBase64 === "string" && !isDecodableBase64(args.ctx.bodyBase64)) {
    // `atob` would throw a raw DOMException later, unaudited (W4 note).
    denyAtEntry("invalid-body-base64", "codemode.request `bodyBase64` must be valid base64");
  }
  if (
    containsBinaryValue(args.ctx.body) ||
    containsBinaryValue(args.ctx.query) ||
    containsBinaryValue(args.ctx.multipart) ||
    containsBinaryValue(args.ctx.composed)
  ) {
    denyAtEntry(
      "binary-value-in-request",
      "Binary values (Uint8Array/ArrayBuffer) are not accepted in body, query or multipart; send bytes with bodyBase64 or multipart[].bodyBase64",
    );
  }
  if (Array.isArray(args.ctx.multipart)) {
    const problem = multipartPartsProblem(args.ctx.multipart);
    if (problem) denyAtEntry(problem.reason, problem.message);
  }
  // `composed` is validated (shape, text rules, exclusivity with every other
  // body channel) on every operation, before any storage access.
  let composedSegments: Segment[] | undefined;
  if (args.ctx.composed !== undefined) {
    const v = validateComposed(args.ctx);
    if (!v.ok) denyAtEntry(v.reason, v.message);
    composedSegments = v.segments;
  }
  // Validate before any token mint / elicitation round: a doomed request must
  // not cost the user an approval dialog first. Audited by reason only: header
  // names and values are sandbox-controlled and never logged (D-6).
  const hp = headerProblem(args.ctx.headers);
  if (hp) denyAtEntry(hp.reason, hp.message);
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
  // D-2: the query names are judged against the matched operation; the
  // sorted names (never values) ride on every audit line from here on.
  const queryCheck = checkQuery(op, spec, ctx.query, args.standardQueryParams);
  // Bounded (32 names × 64 code points, plus the true count): the key set is
  // sandbox-controlled. The policy and the dialog check use the full set.
  const queryAudit: Pick<AuditEntry, "queryKeys" | "queryKeyCount"> = auditQueryKeys(queryCheck.keys);

  /** Audit a deny (category `malformed` unless given) and throw `message`
   *  (default: the generic surface-review denial). */
  const denyMalformed = (
    why: string,
    message = `Operation ${op.operationId} is denied by surface review`,
    auditCategory: string | undefined = "malformed",
  ): never => {
    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      operationId: op.operationId,
      decision: "deny",
      ...(auditCategory ? { category: auditCategory } : {}),
      reason: why,
      ...queryAudit,
      ts: new Date().toISOString(),
    });
    throw new ToolError(message);
  };

  const review = surfaceReview[op.operationId];
  if (!review) {
    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      operationId: op.operationId,
      decision: "deny",
      reason: "not-in-surface-review",
      ...queryAudit,
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
      ...queryAudit,
      ts: new Date().toISOString(),
    });
    throw new ToolError(`Operation ${op.operationId} is denied by surface review`);
  }

  // D-2: refuse a query name the operation does not declare (or a forbidden
  // one, or a non-primitive value) before the URL is built, so it never
  // reaches inspection, approval, token mint or the wire.
  if (!queryCheck.ok) {
    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      operationId: op.operationId,
      decision: "deny",
      category: queryCheck.category,
      reason: queryCheck.reason,
      ...queryAudit,
      ts: new Date().toISOString(),
    });
    throw new ToolError(queryCheck.message);
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
    // Any other failure (e.g. an unparsable base URL) is audited too, by a
    // fixed reason — its message is not logged (W4 note).
    const mismatch =
      err instanceof ToolError &&
      (err.message.startsWith("upstream-url-origin-mismatch") ||
        err.message.startsWith("upstream-url-path-mismatch"));
    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      operationId: op.operationId,
      decision: "deny",
      category: "url_safety",
      reason: mismatch ? (err as ToolError).message : "upstream-url-build-failed",
      ...queryAudit,
      ts: new Date().toISOString(),
    });
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
      ...queryAudit,
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
    denyMalformed(
      "headers-on-gated-op",
      `Operation ${op.operationId} is subject to inspection/approval — ` +
        "sandbox-supplied `headers` are not allowed on it; remove `headers` from this codemode.request call",
    );
  }

  // Host-assembled bodies (D7, D10a): refuse staged references on gated
  // operations whose entry has not opted in, BEFORE any inspector runs (an
  // inspector written for JSON or inline parts may fail open on a view it
  // cannot read); then resolve each reference against D1 only, apply the
  // normaliser, and enforce the exact assembled length. No R2 object is
  // opened until the request is approved and the token minted.
  const stagedParts = Array.isArray(ctx.multipart) && ctx.multipart.some((p) => p.staged !== undefined);
  let stagedEff: Extract<EffectiveBody, { kind: "composed" }> | undefined;
  if (composedSegments !== undefined || stagedParts) {
    const auditDeny = (reason: string, cat?: string, staging?: AuditEntry["staging"]): void =>
      emitAudit(args, {
        deployment: args.deploymentName,
        method: ctx.method,
        path: ctx.path,
        operationId: op.operationId,
        decision: "deny",
        ...(cat ? { category: cat } : {}),
        reason,
        ...queryAudit,
        ...(staging ? { staging } : {}),
        ts: new Date().toISOString(),
      });
    // Staged multipart parts are a new channel with no legacy precedence: a
    // second body channel alongside them is refused before any D1 read.
    // (`composed` exclusivity was already enforced at entry.)
    if (bodyChannelCount(ctx) > 1) {
      auditDeny("multiple-body-channels", "malformed");
      throw new ToolError("`multipart` with staged parts cannot be combined with `body` or `bodyBase64`");
    }
    if ((review.inspect !== undefined || review.decision === "elicit") && review.acceptsStaged !== true) {
      auditDeny("staged-not-supported", "malformed");
      throw new ToolError(
        `Operation ${op.operationId} does not accept staged files (\`composed\` or \`multipart[].staged\`)`,
      );
    }
    if (!args.openStaged) {
      return denyMalformed(
        "staging-not-configured",
        "staged files are not available: server staging bindings are not configured",
      );
    }
    const refs: Array<{ ref: StagedRef; where: string }> = [];
    if (composedSegments !== undefined) {
      for (const seg of composedSegments) {
        if (seg.kind === "staged") refs.push({ ref: seg.ref, where: `composed segment ${seg.index}` });
      }
    } else {
      ctx.multipart!.forEach((p, i) => {
        if (p.staged !== undefined) refs.push({ ref: p.staged, where: `multipart part ${i}` });
      });
    }
    const files: OpenStagedFile[] = [];
    for (const { ref, where } of refs) {
      let r: OpenStagedResult;
      try {
        r = await args.openStaged(ref);
      } catch (err) {
        // A storage outage ends the request too: on record, then rethrown.
        auditDeny("staged-ref-unresolved", undefined, { event: "attach", status: 500 });
        throw err;
      }
      if (!r.ok) {
        auditDeny("staged-ref-unresolved", undefined, { event: "attach", status: r.status });
        throw new ToolError(stagedRefFailure(where, r));
      }
      files.push(r.file);
    }
    const metas = files.map((f) => f.meta);
    let segments: Segment[];
    let contentType: string;
    if (composedSegments !== undefined) {
      segments = normaliseComposed(review, composedSegments);
      contentType = normaliseContentType(ctx.contentType) ?? "application/octet-stream";
    } else {
      const boundary = newMultipartBoundary();
      segments = compileStagedMultipart(ctx.multipart!, boundary, metas);
      contentType = `multipart/form-data; boundary=${boundary}`;
    }
    const length = assembledLength(segments, metas);
    const maxBytes = args.stagingLimits?.composeMaxBytes ?? DEFAULT_COMPOSE_MAX_BYTES;
    if (length > maxBytes) {
      auditDeny("composed-too-large");
      throw new ToolError(
        `composed-too-large: the assembled body would be ${length} bytes; the limit is ${maxBytes} bytes`,
      );
    }
    stagedEff = {
      kind: "composed",
      segments,
      files,
      metas,
      contentType,
      length,
      ...(composedSegments === undefined ? { multipartParts: ctx.multipart! } : {}),
    };
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
  if (
    stagedEff === undefined &&
    !Array.isArray(nctx.multipart) &&
    typeof nctx.bodyBase64 !== "string" &&
    nctx.rawBody &&
    nctx.body !== undefined &&
    nctx.body !== null &&
    typeof nctx.body !== "string"
  ) {
    // The one throw of `resolveEffective`, audited here (W4 note); the
    // function keeps it for direct callers.
    denyMalformed("raw-body-not-string", "rawBody requires a string body; send binary via bodyBase64 or multipart");
  }
  const eff: EffectiveBody = stagedEff ?? resolveEffective(nctx);
  // What is actually marshalled: `eff`, except on gated raw JSON, where it is
  // the canonical re-serialisation of what was inspected and approved (F-7).
  // Plain "allow" operations keep sending the original bytes.
  let sendEff: EffectiveBody = eff;

  // Gated operations (inspected, or needing approval) must be judged on the
  // payload that is sent. Plain "allow" operations grant the caller the
  // operation wholesale, so they keep the legacy channel precedence.
  const gated =
    review.inspect !== undefined || review.decision === "elicit" || review.inspectUpstream !== undefined;
  let inspectResult: InspectResult | undefined;
  // What the approval dialog renders: the parsed JSON payload that is sent,
  // or nothing when the payload cannot be shown (see `opaquePayload`).
  let renderBody: unknown = nctx.body;
  // Set when an approval would otherwise be asked over a payload nobody
  // interpreted (raw non-JSON bytes or multipart, no inspector).
  let opaquePayload: string | undefined;
  if (gated) {
    // One-channel guard: a legitimate caller uses exactly one body channel.
    // Supplying two is the decoy primitive (inspect or show one, send
    // another) → deny, on approval-only operations as well as inspected ones.
    if (bodyChannelCount(nctx) > 1) denyMalformed("multiple-body-channels");
    const derived = deriveInspectRequest(nctx, eff, INSPECT_JSON_MAX_BYTES);
    if (derived.oversize) denyMalformed("oversize-json-body");
    if (derived.unparseableJson) denyMalformed("unparseable-json-body");
    sendEff = derived.sendAs ?? eff;
    // F1-2b: inspectors see the decoded target (a copy, frozen with the rest).
    let inspectReq: InspectRequest = { ...derived.req, pathParams: { ...match.params } };
    if (sendEff.kind === "json") {
      // D-3: a JSON payload on a gated operation goes out as exactly
      // `application/json` (`charset=utf-8` accepted and dropped); any other
      // label could make the upstream re-read the judged bytes as something
      // else. Checked before the inspector, which then sees the final label.
      const canonical =
        canonicalJsonContentType(sendEff.contentType) ??
        denyMalformed(
          "json-body-non-json-content-type",
          `Operation ${op.operationId} sends its \`body\` as JSON; on this operation the content type must be application/json (omit \`contentType\`)`,
        );
      sendEff = { ...sendEff, contentType: canonical };
      inspectReq = { ...inspectReq, contentType: canonical };
      renderBody = sendEff.body;
    } else if (sendEff.kind === "none") {
      renderBody = undefined;
    } else {
      renderBody = undefined;
      if (!review.inspect) {
        // Approval-only operation (D-1): raw bytes or inline multipart parts
        // cannot be shown, so the user could only approve blind — deny before
        // any dialog. A host-assembled (`composed`) body stays approvable only
        // when it attaches staged files, which the dialog's Attachments line
        // lists; a composed body of inline segments alone is as blind as raw.
        if (
          sendEff.kind === "raw" ||
          sendEff.kind === "multipart" ||
          (sendEff.kind === "composed" && sendEff.metas.length === 0)
        ) {
          denyMalformed(
            "opaque-body-on-approval-op",
            `Operation ${op.operationId} requires approval but its body cannot be shown; send it as JSON (object \`body\`) or omit it`,
          );
        }
        opaquePayload = describeOpaque(nctx, sendEff);
      }
    }
    if (review.inspect) {
      // Freeze the derived request so inspectors cannot mutate what will be sent,
      // matching the deepFreeze protection previously applied to ctx.body.
      // env rides along un-frozen (it is the live worker env, bindings included)
      // so inspectors can resolve per-deployment policy vars.
      // Frozen in place: a paired `inspectUpstream` below gets the same object.
      // A throwing inspector (e.g. a malformed operator allow-list var, whose
      // message quotes the config text) is a fail-closed deny with an audit
      // line; its text is never forwarded to the caller.
      try {
        inspectResult = review.inspect(deepFreeze(inspectReq), args.env);
      } catch {
        return denyMalformed(
          "inspector-threw",
          `Operation ${op.operationId} is denied: its request check failed`,
        );
      }
      // A non-InspectResult (e.g. `{}`, or a Promise from an async inspect)
      // must never merge as allow.
      if (!isInspectResult(inspectResult)) {
        return denyMalformed(
          "inspector-invalid-result",
          `Operation ${op.operationId} is denied: its request check failed`,
        );
      }
      decision = mostRestrictive(decision, inspectResult.decision);
      if (inspectResult.category) category = inspectResult.category;
      if (inspectResult.reason) reason = inspectResult.reason;
      if (inspectResult.message) denyMessage = inspectResult.message;
    }
    // A hook must be paired with `inspect` (the provider battery checks it);
    // an unpaired one is a misconfiguration and is refused, never skipped.
    if (review.inspectUpstream !== undefined && review.inspect === undefined) {
      denyMalformed("upstream-inspector-without-inspect");
    }
    if (review.inspectUpstream !== undefined && decision !== "deny") {
      // F1-2b: the async hook may read plain-allow GETs (minting the token
      // before the decision). It never runs on a body it cannot read: an
      // opaque or host-assembled payload is denied instead (fail closed).
      if (sendEff.kind !== "json" && sendEff.kind !== "none") {
        denyMalformed(
          "opaque-body-on-upstream-inspected-op",
          `Operation ${op.operationId} checks upstream state before sending and takes a JSON \`body\` only`,
        );
      }
      const session = createUpstreamLookup(args, handleUpstreamRequest);
      let r: InspectResult | undefined;
      let failure: unknown;
      try {
        // Already deep-frozen for `inspect` (a hook without one was denied above).
        r = await review.inspectUpstream(inspectReq, session.lookup, args.env);
      } catch (err) {
        failure = err;
      } finally {
        session.close();
      }
      // A lookup the hook fired without awaiting still counts: wait for it.
      await session.settled();
      if (failure !== undefined || session.failed() || !isInspectResult(r)) {
        // Only the session's own fixed refusals are named: any other text
        // (nested request, hook) may carry lookup paths or upstream content.
        const detail = failure instanceof UpstreamLookupError ? `: ${failure.message}` : "";
        return denyMalformed(
          "upstream-inspect-failed",
          `Operation ${op.operationId} is denied: its check of the stored upstream state failed${detail}`,
          category ?? "malformed",
        );
      }
      const merged = mostRestrictive(decision, r.decision);
      // The hook's labels apply when its decision is the one that stands; a
      // hook `allow` never relabels a sync `elicit`.
      if (merged === r.decision) {
        if (r.category) category = r.category;
        if (r.reason) reason = r.reason;
        if (r.message) denyMessage = r.message;
      }
      decision = merged;
      const summary = { ...inspectResult?.summary, ...r.summary };
      inspectResult = {
        ...inspectResult,
        ...r,
        decision,
        ...(Object.keys(summary).length > 0 ? { summary } : {}),
      };
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
      ...queryAudit,
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
    // The dialog shows every query pair (none may hide behind a count), so a
    // query too long to show is refused before any dialog.
    // `queryCheck.keys` are exactly the defined query names (see `checkQuery`).
    const queryPairCount = queryCheck.keys.length;
    if (queryPairCount > MAX_DIALOG_QUERY_PAIRS) {
      denyMalformed(
        "too-many-query-params-for-dialog",
        `Operation ${op.operationId} requires approval but its query has ${queryPairCount} parameters; at most ${MAX_DIALOG_QUERY_PAIRS} can be shown in the approval dialog`,
      );
    }
    await runElicitation({
      spec: args.spec,
      operationId: op.operationId,
      method: ctx.method,
      path: ctx.path,
      pathParams: match.params,
      body: renderBody,
      ...(opaquePayload !== undefined ? { opaquePayload } : {}),
      env: args.env,
      ...(args.relatedRequestId !== undefined ? { relatedRequestId: args.relatedRequestId } : {}),
      ...(ctx.query !== undefined ? { query: ctx.query } : {}),
      ...(category ? { category } : {}),
      ...(reason ? { reason } : {}),
      ...(inspectResult?.summary ? { inspectorSummary: inspectResult.summary } : {}),
      ...(stagedEff ? { attachments: attachmentsLine(stagedEff.metas) } : {}),
      entry: review,
      ...(queryAudit.queryKeys ? { queryKeys: queryAudit.queryKeys } : {}),
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
          ...(e.queryKeys ? { queryKeys: e.queryKeys } : {}),
          ...(e.queryKeys && queryAudit.queryKeyCount !== undefined ? { queryKeyCount: queryAudit.queryKeyCount } : {}),
          ...(e.elicitFields ? { elicitFields: e.elicitFields } : {}),
          ts: new Date().toISOString(),
        }),
    });
    // accepted; fall through to upstream fetch
  }

  const userId = args.oauth.userIdAccessor(args.props);
  if (!userId) {
    return denyMalformed("no-principal", "Cannot mint access token: principal has no userId", undefined);
  }
  /** The request was allowed but did not complete: a line with a fixed
   *  `reason` (never the error text), written once per request (E-4). */
  let outcomeWritten = false;
  const auditFailed = (why: string, extra: Partial<AuditEntry> = {}): void => {
    if (outcomeWritten) return;
    outcomeWritten = true;
    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      operationId: op.operationId,
      decision: "allow",
      outcome: "failed",
      reason: why,
      ...queryAudit,
      ...extra,
      ts: new Date().toISOString(),
    });
  };
  let accessToken: string;
  try {
    accessToken = await args.oauth.broker.getOrRefreshAccessToken({
      userId,
      refreshToken: args.oauth.refreshTokenAccessor(args.props),
    });
  } catch (err) {
    auditFailed("token-mint-failed");
    throw err;
  }

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
    let provided: Record<string, string>;
    try {
      provided = args.requestHeaders(args.props);
    } catch (err) {
      auditFailed("request-headers-failed");
      throw err;
    }
    for (const [name, value] of Object.entries(provided)) {
      setHeader(name, value);
    }
  }

  // F-17: never follow redirects. The origin and path guards vouch only for
  // the URL built above; a followed 3xx would replay the request to wherever
  // the upstream (or anything in front of it) points, unreviewed.
  const fetchOptions: RequestInit = { method: ctx.method, headers, redirect: "manual" };
  if (bodyToSend !== undefined) fetchOptions.body = bodyToSend;

  // File-sized work (a host-assembled send, or a staged download) holds a
  // transfer-gate slot (D8) from here until the response has been handled.
  // The gate comes after the token mint, so a refused or failed approval
  // never queues.
  // The stageFromUpstreamJson inner request (`bypassTruncate`) is file-sized
  // too — its response may be a 50 MiB base64 field — but the capability owns
  // that slot through `gateLease`, held until it has stored the file.
  const viaLease = ctx.bypassTruncate === true && args.gateLease !== undefined;
  const fileSized = sendEff.kind === "composed" || ctx.returnAs === "stage" || ctx.bypassTruncate === true;
  // The counters of a host-assembled send known before dispatch; they ride on
  // the dispatch line, a failure line and the final line alike.
  const composedAudit: Pick<AuditEntry, "stagedCount" | "stagedBytes" | "assembledBytes" | "stagedRefs"> =
    sendEff.kind === "composed"
      ? {
          stagedCount: sendEff.metas.length,
          stagedBytes: sendEff.metas.reduce((n, m) => n + m.byteLength, 0),
          assembledBytes: sendEff.length,
          stagedRefs: sendEff.metas.map((m) => m.fileRef),
        }
      : {};
  let release: (() => void) | undefined;
  try {
    if (viaLease) await args.gateLease!.acquire();
    release =
      fileSized && !viaLease && args.transferGate
        ? await args.transferGate.acquire(args.runKey ?? {}, args.signal ?? NEVER_ABORTED)
        : undefined;
  } catch (err) {
    // A refused or aborted slot ends an allowed, minted request (E-4).
    auditFailed("transfer-gate-failed", composedAudit);
    throw err;
  }
  const timeoutMs = args.stagingLimits?.transferTimeoutMs ?? DEFAULT_TRANSFER_TIMEOUT_MS;
  // One controller per file-sized transfer (D3a), alive until the response
  // has been handled: it bounds the send, the response read and a staged
  // download alike, and is disposed with the gate release below.
  const transfer: TransferController | undefined = fileSized
    ? transferController(args.signal, timeoutMs)
    : undefined;
  const outcome: Outcome = {
    written: () => outcomeWritten,
    markWritten: () => {
      outcomeWritten = true;
    },
    failed: auditFailed,
  };
  try {
    let upstreamRes: Response;
    let stagedAudit: StagedAudit = {};
    if (sendEff.kind === "composed") {
      if (!platformSuppliesContentLength()) setHeader("Content-Length", String(sendEff.length));
      // E-4: the body can reach the upstream and the client vanish before
      // any answer, so the send is on record before its first byte goes out.
      emitAudit(args, {
        deployment: args.deploymentName,
        method: ctx.method,
        path: ctx.path,
        operationId: op.operationId,
        decision: "allow",
        phase: "dispatch",
        ...queryAudit,
        ...composedAudit,
        ts: new Date().toISOString(),
      });
      const sent = await sendAssembled(
        urlString,
        fetchOptions,
        { segments: sendEff.segments, files: sendEff.files, length: sendEff.length },
        transfer!,
      );
      upstreamRes = sent.response;
      // An upstream may answer (even 2xx) after reading only part of the
      // body; the audit line records how much it accepted.
      stagedAudit = {
        stagedCount: composedAudit.stagedCount!,
        stagedBytes: composedAudit.stagedBytes!,
        assembledBytes: composedAudit.assembledBytes!,
        bodyBytesSent: sent.bodyBytesSent,
        bodyComplete: sent.bodyComplete,
        stagedRefs: composedAudit.stagedRefs!,
      };
    } else if (transfer) {
      if (transfer.signal.aborted) throw transferFailure(transfer, undefined);
      fetchOptions.signal = transfer.signal;
      upstreamRes = await fetch(urlString, fetchOptions);
    } else {
      upstreamRes = await fetch(urlString, fetchOptions);
    }
    return await finishUpstream(args, ctx, op, upstreamRes, { ...queryAudit, ...stagedAudit }, transfer, outcome);
  } catch (err) {
    const failure = transfer ? transferFailure(transfer, err) : err;
    // Every allowed request that ends here without its final line gets one
    // (E-4): a rejected fetch, a failed or aborted transfer.
    auditFailed(failureReason(failure), composedAudit);
    throw failure;
  } finally {
    transfer?.dispose();
    release?.();
  }
}

/** Opaque-payload description for the approval dialog when no inspector
 *  interpreted the body (never the bytes, never a token or handle). */
function describeOpaque(ctx: UpstreamCtx, eff: EffectiveBody): string | undefined {
  const plural = (n: number, w: string): string => `${n} ${w}${n === 1 ? "" : "s"}`;
  switch (eff.kind) {
    case "raw":
      return `${eff.contentType.slice(0, 100)}, ${eff.bytes.byteLength} bytes`;
    case "multipart":
      return `multipart, ${plural(eff.parts.length, "part")}`;
    case "composed": {
      const files = plural(eff.metas.length, "staged file");
      return eff.multipartParts
        ? `multipart, ${plural(eff.multipartParts.length, "part")}, ${files}, ${eff.length} bytes`
        : `composed, ${plural(ctx.composed?.segments.length ?? eff.segments.length, "segment")}, ${files}, ${eff.length} bytes`;
    }
    default:
      return undefined;
  }
}

/** The audit counters of a host-assembled send (empty for any other request). */
type StagedAudit = Pick<
  AuditEntry,
  "stagedCount" | "stagedBytes" | "assembledBytes" | "bodyBytesSent" | "bodyComplete" | "stagedRefs"
>;

/** The request's single closing line (E-4): `finishUpstream` marks it
 *  written with its ordinary allow line, or writes an `outcome: "failed"`
 *  line itself; the dispatch `catch` writes one only when neither happened. */
interface Outcome {
  written(): boolean;
  markWritten(): void;
  failed(reason: string, extra?: Partial<AuditEntry>): void;
}

/** Extra fields for the final audit line: the query names plus the counters
 *  of a host-assembled send. */
type FinalAudit = Pick<AuditEntry, "queryKeys" | "queryKeyCount"> & StagedAudit;

/** Everything after the upstream answered: rate-limit telemetry, redirect
 *  refusal, staged download, and the response envelope. */
async function finishUpstream<P extends Record<string, unknown>>(
  args: HandleArgs<P>,
  ctx: UpstreamCtx,
  op: OpenApiOperation,
  upstreamRes: Response,
  finalAudit: FinalAudit,
  transfer: TransferController | undefined,
  outcome: Outcome,
): Promise<unknown> {
  const operationId = op.operationId;
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
    cancelQuietly(upstreamRes);
    outcome.markWritten();
    emitAudit(args, {
      deployment: args.deploymentName,
      method: ctx.method,
      path: ctx.path,
      operationId,
      decision: "allow",
      upstreamStatus: upstreamRes.status,
      ...finalAudit,
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

  // Stage-mode: only on 2xx + a staging store. The body is read block by
  // block, encrypted and streamed to R2 (no arrayBuffer(), no base64),
  // bypassing truncateForReturn. On non-2xx, fall through to the normal error
  // envelope (so the LLM can debug — error bodies are usually small JSON).
  if (ctx.returnAs === "stage" && upstreamRes.ok) {
    const store = args.stagingStore;
    const stageLine = (staging?: AuditEntry["staging"]): void => {
      outcome.markWritten();
      emitAudit(args, {
        deployment: args.deploymentName,
        method: ctx.method,
        path: ctx.path,
        operationId,
        decision: "allow",
        upstreamStatus: upstreamRes.status,
        ...(finalAudit.queryKeys ? { queryKeys: finalAudit.queryKeys } : {}),
        ...(finalAudit.queryKeyCount !== undefined ? { queryKeyCount: finalAudit.queryKeyCount } : {}),
        ...(staging ? { staging } : {}),
        ts: new Date().toISOString(),
      });
    };
    if (!store) {
      cancelQuietly(upstreamRes);
      // The upstream already answered: its line comes first (W4 note).
      stageLine();
      throw new ToolError("returnAs:\"stage\" requires server staging bindings, which are not configured");
    }
    const upstreamContentType = upstreamRes.headers.get("content-type") ?? "application/octet-stream";
    const filename = filenameFromContentDisposition(upstreamRes.headers.get("content-disposition"));
    const declared = declaredResponseLength(upstreamRes.headers);
    let staged: PutFileResult;
    if (declared !== null && declared > store.config.maxBytes) {
      cancelQuietly(upstreamRes);
      staged = { ok: false, status: 413, message: "payload too large" };
    } else {
      const src = upstreamRes.body
        ? blockSourceFromStream(upstreamRes.body, declared, store.config.maxBytes)
        : blockSourceFromBytes(new Uint8Array(0));
      try {
        staged = await stageFromBlocks(store, src, upstreamContentType, filename);
      } catch (err) {
        cancelQuietly(upstreamRes);
        const failure = transfer ? transferFailure(transfer, err) : err;
        outcome.failed(transfer?.signal.aborted ? failureReason(failure) : "stage-store-failed", {
          upstreamStatus: upstreamRes.status,
        });
        throw failure;
      }
      // The shared unknown-length slot's own message ("…or send
      // Content-Length") is for uploaders; a download caller can only retry.
      if (!staged.ok && staged.status === 503) {
        staged = { ok: false, status: 503, message: "staging busy with another unknown-length transfer; retry shortly" };
      }
      // A refused or failed store may never have touched the body (e.g. the
      // shared unknown-length slot is busy → 503): cancel it either way.
      if (!staged.ok) cancelQuietly(upstreamRes);
      if (!staged.ok && transfer?.signal.aborted) {
        const failure = transferFailure(transfer, undefined);
        outcome.failed(failureReason(failure), {
          upstreamStatus: upstreamRes.status,
          staging: { event: "store", status: staged.status },
        });
        throw failure;
      }
    }

    // E-1: the store on record by its fileRef (never the handle or token).
    stageLine(
      staged.ok
        ? { event: "store", fileRef: staged.file_ref, byteLength: staged.byte_length, status: 200 }
        : { event: "store", status: staged.status },
    );

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

  // The response text is needed only to parse it and, on an error, for the
  // first 500 characters of the message. Neither outlives this block, so on
  // the `bypassTruncate` path (stageFromUpstreamJson: a large base64 field)
  // only the parsed value stays reachable once the text is parsed.
  let parsed: unknown;
  let errorMessage = "";
  {
    let responseText: string | undefined;
    try {
      responseText = await upstreamRes.text();
    } catch (err) {
      const failure = transfer ? transferFailure(transfer, err) : err;
      outcome.failed(transfer?.signal.aborted ? failureReason(failure) : "response-read-failed", {
        upstreamStatus: upstreamRes.status,
        ...finalAudit,
      });
      throw err;
    }
    if (!upstreamRes.ok) errorMessage = responseText.slice(0, 500);
    parsed = responseText;
    try { parsed = JSON.parse(responseText); } catch { /* leave as text */ }
    responseText = undefined;
  }

  // F2-8: fence the strings the provider's spec flags as third-party text,
  // for this status (or `default`), before truncation — on everything that
  // returns to the model, including an error envelope (a non-2xx answer to a
  // `returnAs: "stage"` request lands here too). The internal
  // `bypassTruncate` path plucks a field to stage it and never returns it.
  if (args.untrustedFieldExtension && ctx.bypassTruncate !== true) {
    const pointers = untrustedPointersForStatus(
      collectUntrustedPointers(op, args.untrustedFieldExtension, args.spec),
      upstreamRes.status,
    );
    if (pointers.length > 0) {
      const fenced = fenceUntrusted(parsed, pointers);
      if (fenced !== parsed) {
        parsed = fenced;
        // The error message is a second copy of the body: rebuild it from
        // the fenced value so it carries no unfenced flagged text.
        if (!upstreamRes.ok) {
          errorMessage = (typeof fenced === "string" ? fenced : JSON.stringify(fenced)).slice(0, 500);
        }
      }
    }
  }

  outcome.markWritten();
  emitAudit(args, {
    deployment: args.deploymentName,
    method: ctx.method,
    path: ctx.path,
    operationId,
    decision: "allow",
    upstreamStatus: upstreamRes.status,
    ...rateLimitAudit,
    ...finalAudit,
    ts: new Date().toISOString(),
  });

  // On a 429 the upstream body is usually a bare "oops, rate limit exceeded"
  // with no indication of WHICH limit or how long to wait — that lives in the
  // headers. The envelope contract points clients at `errors[0].message`, so
  // the reason leads there (body kept after it, for debugging).
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
