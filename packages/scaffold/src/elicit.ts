// Verified during Task 1 against @modelcontextprotocol/sdk@1.29.0:
//   - Server.elicitInput(params, options?): Promise<ElicitResult>
//     (server/index.d.ts:158)
//   - Server.getClientCapabilities(): ClientCapabilities | undefined
//     (server/index.d.ts:121) — method, not property
//   - McpServer.server: Server (server/mcp.d.ts:18)
// Capability check call site: args.server.server.getClientCapabilities()?.elicitation
// Elicit call site:           args.server.server.elicitInput({...})

import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type {
  ElicitRenderer,
  ElicitRendererOutput,
  FormFields,
  Primitive,
  SurfaceReviewEntry,
} from "@local/shared";
import { debugLog } from "./config";

const MAX_FIELDS = 5;
const MAX_VALUE_LEN = 256;
const BASE64_PATTERN = /^[A-Za-z0-9+/=_-]{200,}$/;

function isPrimitive(v: unknown): v is Primitive {
  return typeof v === "string" || typeof v === "number" || typeof v === "boolean";
}

function isWalkable(v: Primitive): boolean {
  if (typeof v !== "string") return true;
  if (v.length > MAX_VALUE_LEN) return false;
  if (BASE64_PATTERN.test(v)) return false;
  return true;
}

interface SchemaProperties {
  type?: string;
  properties?: Record<string, { type?: string }>;
}

function getRequestSchemaProps(spec: OpenApiSpec, operationId: string): SchemaProperties | undefined {
  const paths = (spec as unknown as { paths?: Record<string, Record<string, {
    operationId?: string;
    requestBody?: { content?: Record<string, { schema?: SchemaProperties }> };
  }>> }).paths ?? {};
  for (const methods of Object.values(paths)) {
    for (const op of Object.values(methods)) {
      if (op.operationId === operationId) {
        return op.requestBody?.content?.["application/json"]?.schema;
      }
    }
  }
  return undefined;
}

export interface GenericWalkerArgs {
  spec: OpenApiSpec;
  operationId: string;
  body: unknown;
  inspectorSummary?: Record<string, Primitive>;
}

/** Fallback renderer: inspector summary primitives first, then top-level
 *  body primitives the request schema declares, at most `MAX_FIELDS`. It may
 *  return no facts: the scaffold still shows the request line, and `confirm`
 *  is never a fact (it is the only input). */
export function genericWalker(args: GenericWalkerArgs): ElicitRendererOutput {
  const facts: FormFields = {};

  if (args.inspectorSummary) {
    for (const [k, v] of Object.entries(args.inspectorSummary)) {
      if (Object.keys(facts).length >= MAX_FIELDS) break;
      if (isPrimitive(v) && isWalkable(v)) facts[k] = v;
    }
  }

  const schemaProps = getRequestSchemaProps(args.spec, args.operationId);
  if (
    schemaProps &&
    args.body !== null &&
    typeof args.body === "object" &&
    schemaProps.properties
  ) {
    for (const key of Object.keys(schemaProps.properties)) {
      if (Object.keys(facts).length >= MAX_FIELDS) break;
      if (Object.hasOwn(facts, key)) continue;
      const v = (args.body as Record<string, unknown>)[key];
      if (isPrimitive(v) && isWalkable(v)) facts[key] = v;
    }
  }

  return { headline: `Confirm operation: ${args.operationId}`, facts };
}

export interface RequestedSchema {
  readonly type: "object";
  readonly properties: { readonly confirm: { readonly type: "boolean" } };
  readonly required: readonly ["confirm"];
  readonly additionalProperties: false;
}

/** The only form the approval dialog ever requests: one boolean. Facts are
 *  shown in the message, never asked as inputs (D-1: the user used to type
 *  the "count"). Same bytes as the pre-D-1 single-confirm dialogs, so the
 *  elicitation transport shape is unchanged. */
export const CONFIRM_SCHEMA: RequestedSchema = Object.freeze({
  type: "object",
  properties: Object.freeze({ confirm: Object.freeze({ type: "boolean" }) }),
  required: Object.freeze(["confirm"]) as readonly ["confirm"],
  additionalProperties: false,
} as const);

/** A fresh mutable copy of `CONFIRM_SCHEMA` for the transport (the SDK gets
 *  a plain object, as before; the frozen constant is never handed out). */
function confirmSchemaForTransport(): unknown {
  return JSON.parse(JSON.stringify(CONFIRM_SCHEMA));
}

/** True only for a non-array object whose own keys are exactly `["confirm"]`
 *  and whose `confirm` is the boolean `true`. Anything else is a decline. */
export function validateAcceptedContent(content: unknown): boolean {
  if (content === null || typeof content !== "object" || Array.isArray(content)) return false;
  const keys = Reflect.ownKeys(content);
  if (keys.length !== 1 || keys[0] !== "confirm") return false;
  return (content as { confirm?: unknown }).confirm === true;
}

// Every control (Cc: C0, C1), format character (Cf: bidi embeddings,
// overrides, isolates and marks, zero-width characters, BOM, soft hyphen,
// tag characters, interlinear annotation controls) and line/paragraph
// separator (Zl, Zp): each could forge a line, hide text or reorder it.
const DIALOG_UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;
// Runs of whitespace (incl. every Zs space and the invisible letter-class
// fillers: Hangul fillers U+115F/U+1160/U+3164/U+FFA0, Braille blank U+2800,
// Mongolian vowel separator U+180E) collapse to one space, so padding cannot
// push a fact onto what looks like a line of its own or out of its cap.
const WHITESPACE_RUN = /[\s\p{Zs}\u115F\u1160\u180E\u2800\u3164\uFFA0]+/gu;

/** Dialog-unsafe code points become spaces and whitespace runs collapse to
 *  one space (exported for providers that pre-check a fact fits uncut). */
export function cleanDialogText(text: string): string {
  return text.replace(DIALOG_UNSAFE, " ").replace(WHITESPACE_RUN, " ");
}

/** Replace every dialog-unsafe code point with a space, collapse whitespace
 *  runs to one space, then cut at `maxCodePoints` code points, appending `…`
 *  when cut. */
export function sanitiseDialogText(text: string, maxCodePoints: number): string {
  const cleaned = cleanDialogText(text);
  const cps = Array.from(cleaned);
  return cps.length > maxCodePoints ? cps.slice(0, maxCodePoints).join("") + "…" : cleaned;
}

/** As `sanitiseDialogText`, but a cut keeps the head and the tail around a
 *  middle `…`, so the trailing segment of a path (the target id) stays visible. */
function sanitiseDialogTextMiddle(text: string, maxCodePoints: number): string {
  const cleaned = cleanDialogText(text);
  const cps = Array.from(cleaned);
  if (cps.length <= maxCodePoints) return cleaned;
  const tail = Math.floor(maxCodePoints / 2);
  const head = maxCodePoints - tail;
  return cps.slice(0, head).join("") + "…" + cps.slice(cps.length - tail).join("");
}

export const MAX_DIALOG_FACTS = 8;
/** Most query pairs an approval dialog shows; a request with more is denied
 *  before the dialog (every pair is shown, so none can hide behind a count). */
export const MAX_DIALOG_QUERY_PAIRS = 16;
const HEADLINE_MAX = 200;
const PATH_MAX = 300;
const QUERY_KEY_MAX = 40;
const QUERY_VALUE_MAX = 200;
const FACT_LABEL_MAX = 40;
export const FACT_VALUE_MAX = 200;
const ATTACHMENTS_MAX = 600;
const OPAQUE_DESCRIPTION_MAX = 200;
const DIALOG_TRAILER = "Approve only if this is exactly the request you intended.";

/** The facts the dialog shows and the audit records: the first 8, in
 *  renderer order, labels and string values already sanitised and truncated
 *  (so audit `elicitFields` is bounded). Numbers and booleans keep their type. */
function shownFacts(facts: FormFields): FormFields {
  // Object.fromEntries defines own properties, so a "__proto__" label stays a fact.
  return Object.fromEntries(
    Object.entries(facts)
      .slice(0, MAX_DIALOG_FACTS)
      .map(([label, value]): [string, Primitive] => [
        sanitiseDialogText(label, FACT_LABEL_MAX),
        typeof value === "number" || typeof value === "boolean"
          ? value
          : sanitiseDialogText(String(value), FACT_VALUE_MAX),
      ]),
  );
}

/** The query pairs that reach the wire (`undefined` values are dropped, as
 *  `buildUpstreamUrl` drops them). */
export function definedQueryPairs(query: unknown): Array<[string, unknown]> {
  if (query === undefined || query === null) return [];
  return Object.entries(query as object).filter(([, v]) => v !== undefined);
}

/** A fact value as shown: strings (already sanitised) as JSON string
 *  literals so a value cannot masquerade as further facts or lines; numbers
 *  plain; booleans yes/no. */
function factText(v: Primitive): string {
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "number") return String(v);
  return JSON.stringify(v);
}

/** A query value as shown: what `buildUpstreamUrl` sends (`String(v)`),
 *  sanitised; numbers and booleans plain, anything else as a JSON string
 *  literal so it cannot masquerade as further pairs. */
function queryValueText(v: unknown): string {
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(sanitiseDialogText(String(v), QUERY_VALUE_MAX));
}

export interface DialogMessageParts {
  headline: string;
  /** Set for a body that cannot be shown (host-assembled, uninspected): a
   *  short scaffold-built description. Adds the fixed warning line, which is
   *  never truncated (only the description inside it is capped). */
  opaqueBody?: string;
  method: string;
  path: string;
  /** Rendered as on the wire: `undefined` values are dropped, every other
   *  value is `String(v)` (what `buildUpstreamUrl` sends). Every pair is
   *  shown; callers refuse more than `MAX_DIALOG_QUERY_PAIRS` beforehand. */
  query?: unknown;
  facts: FormFields;
  /** Host-assembled attachments line ("name (N bytes); …"); sanitised again
   *  here, since staged filenames may carry separators. */
  attachments?: string;
}

/** The approval dialog text: headline, opaque-body warning, `Request: METHOD
 *  path`, `Query:`, one line per fact (at most 8), `Attachments:`, then a
 *  fixed trailer. Empty lines are omitted; every caller-influenced part is
 *  sanitised and bounded; scaffold-fixed text is never truncated. */
export function composeDialogMessage(parts: DialogMessageParts): string {
  const lines: string[] = [];
  const headline = sanitiseDialogText(parts.headline, HEADLINE_MAX);
  if (headline.trim() !== "") lines.push(headline);
  if (parts.opaqueBody !== undefined) {
    lines.push(
      `Its request body (${sanitiseDialogText(parts.opaqueBody, OPAQUE_DESCRIPTION_MAX)}) ` +
        "cannot be shown here; approve only if you expected this upload.",
    );
  }
  lines.push(`Request: ${parts.method} ${sanitiseDialogTextMiddle(parts.path, PATH_MAX)}`);
  if (parts.query !== undefined && parts.query !== null) {
    // Every pair is shown (none hidden behind a count); the handler refuses
    // an approval whose query exceeds MAX_DIALOG_QUERY_PAIRS before any dialog.
    const pairs = definedQueryPairs(parts.query).map(([k, v]) =>
      `${sanitiseDialogText(k, QUERY_KEY_MAX)}=${queryValueText(v)}`);
    if (pairs.length > 0) lines.push(`Query: ${pairs.join("; ")}`);
  }
  // shownFacts has already sanitised and truncated labels and values.
  for (const [label, value] of Object.entries(shownFacts(parts.facts))) {
    lines.push(`${label}: ${factText(value)}`);
  }
  if (parts.attachments !== undefined && parts.attachments !== "") {
    lines.push(`Attachments: ${sanitiseDialogText(parts.attachments, ATTACHMENTS_MAX)}`);
  }
  lines.push(DIALOG_TRAILER);
  return lines.join("\n");
}

export function resolveRenderer(
  entry: SurfaceReviewEntry,
  category: string | undefined,
  renderers: Partial<Record<string, ElicitRenderer>> | undefined,
): ElicitRenderer | undefined {
  if (entry.elicit) return entry.elicit;
  if (!category || !renderers) return undefined;
  return renderers[category];
}

export class TimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TimeoutError";
  }
}

export function raceTimeout<T>(inner: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new TimeoutError(`elicit timed out after ${ms}ms`)), ms);
    inner.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); },
    );
  });
}

interface ServerLike {
  server?: {
    getClientCapabilities?: () => ({ elicitation?: unknown } & Record<string, unknown>) | undefined;
  };
}

export function clientSupportsElicitation(server: ServerLike): boolean {
  const srv = server.server;
  // Fail-closed: a server object that cannot report the client's
  // capabilities is treated as a client that cannot be asked (denied).
  if (typeof srv?.getClientCapabilities !== "function") return false;
  const caps = srv.getClientCapabilities();
  // The capability is an object (possibly empty); `false`, `true`, numbers or
  // strings are not a declaration of support.
  const e = caps?.elicitation;
  return typeof e === "object" && e !== null && !Array.isArray(e);
}

export class ToolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ToolError";
  }
}

export interface RunElicitationArgs {
  spec: OpenApiSpec;
  operationId: string;
  method: string;
  /** The request path as matched (shown on the dialog's `Request:` line). */
  path: string;
  /** Decoded path-template parameters (`OperationMatch.params`), handed to
   *  renderers so targets come from the path, never from the body. */
  pathParams: Record<string, string>;
  body: unknown;
  /** Set when the payload being approved is a host-assembled (`composed`)
   *  body no inspector interpreted: a short scaffold-built description. The
   *  dialog then says the body cannot be shown and lists the attachments.
   *  (Raw and inline multipart bodies on approval-only operations are denied
   *  by the handler before any dialog.) */
  opaquePayload?: string;
  query?: Record<string, Primitive | undefined>;
  category?: string;
  reason?: string;
  inspectorSummary?: Record<string, Primitive>;
  /** Staged files the host will attach (host-assembled bodies): a
   *  pre-sanitised "name (N bytes); …" line appended to the dialog message,
   *  whatever renderer runs. Never contains a token, a handle or file bytes. */
  attachments?: string;
  entry: SurfaceReviewEntry;
  /** Sorted query parameter names (never values) for every audit line (D-2). */
  queryKeys?: string[];
  /** Forwarded from HandleArgs; passed to elicitInput as relatedRequestId so
   *  the server-initiated elicit routes through the originating POST stream. */
  relatedRequestId?: string | number;
  elicitRenderers?: Partial<Record<string, ElicitRenderer>>;
  server: ServerLike & {
    server?: {
      elicitInput?: (params: unknown, options?: { relatedRequestId?: string | number }) => Promise<unknown>;
    };
  };
  emitAudit: (entry: {
    method: string;
    path: string;
    operationId?: string;
    decision: "elicit";
    elicitationOutcome:
      | "accepted" | "declined" | "cancelled"
      | "timeout" | "transport-error" | "unsupported";
    category?: string;
    reason?: string;
    /** Sorted query parameter names (never values), from `queryKeys`. */
    queryKeys?: string[];
    elicitFields?: FormFields;
  }) => void;
  /** Override for tests; production uses 60_000. */
  elicitTimeoutMs?: number;
  /** Narrow env shape for DEBUG_ELICIT gating; threaded from `mcp-agent-factory`
   *  via `request-handler`. Same structural shape as `HandleArgs.env`. */
  env: { DEBUG_ELICIT?: string; ALLOW_PII_IN_LOGS?: string };
}

const DEFAULT_ELICIT_TIMEOUT_MS = 60_000;

export async function runElicitation(args: RunElicitationArgs): Promise<void> {
  const baseAudit = {
    method: args.method,
    path: args.path,
    operationId: args.operationId,
    decision: "elicit" as const,
    ...(args.category ? { category: args.category } : {}),
    ...(args.reason ? { reason: args.reason } : {}),
    ...(args.queryKeys && args.queryKeys.length > 0 ? { queryKeys: args.queryKeys } : {}),
  };

  const supportsElicit = clientSupportsElicitation(args.server);
  const capsRaw = args.server.server?.getClientCapabilities?.();
  debugLog(
    args.env,
    "elicit-caps",
    {
      operationId: args.operationId,
      supportsElicit,
      capsRaw,
    },
    { containsPii: false },
  );
  if (!supportsElicit) {
    args.emitAudit({ ...baseAudit, elicitationOutcome: "unsupported" });
    throw new ToolError(
      `Operation ${args.operationId} requires user approval; outcome: unsupported`,
    );
  }

  const renderer =
    resolveRenderer(args.entry, args.category, args.elicitRenderers) ??
    ((input: Parameters<ElicitRenderer>[0]) => genericWalker({
      spec: args.spec,
      operationId: input.operationId,
      body: input.body,
      ...(input.inspectorSummary ? { inspectorSummary: input.inspectorSummary } : {}),
    }));

  const rendered: ElicitRendererOutput =
    args.opaquePayload !== undefined
      ? { headline: `Confirm operation: ${args.operationId}`, facts: {} }
      : renderer({
          operationId: args.operationId,
          method: args.method,
          path: args.path,
          pathParams: args.pathParams,
          body: args.body,
          ...(args.query !== undefined ? { query: args.query } : {}),
          ...(args.inspectorSummary ? { inspectorSummary: args.inspectorSummary } : {}),
        });
  // The audit records exactly the facts the dialog shows.
  const fields = shownFacts(rendered.facts);
  const message = composeDialogMessage({
    headline: rendered.headline,
    ...(args.opaquePayload !== undefined ? { opaqueBody: args.opaquePayload } : {}),
    method: args.method,
    path: args.path,
    ...(args.query !== undefined ? { query: args.query } : {}),
    facts: rendered.facts,
    ...(args.attachments !== undefined ? { attachments: args.attachments } : {}),
  });
  const requestedSchema = confirmSchemaForTransport();

  const elicitSrv = args.server.server;
  if (typeof elicitSrv?.elicitInput !== "function") {
    args.emitAudit({ ...baseAudit, elicitationOutcome: "transport-error", elicitFields: fields });
    throw new ToolError(`Operation ${args.operationId} requires user approval; outcome: transport-error`);
  }

  {
    const outerObj = args.server as { constructor?: { name?: string } };
    const innerObj = args.server.server as unknown as
      | { constructor?: { name?: string }; _transport?: unknown; transport?: unknown }
      | undefined;
    const hasTransport = (innerObj?._transport != null) || (innerObj?.transport != null);
    debugLog(
      args.env,
      "elicit-pre-send",
      {
        operationId: args.operationId,
        outerCtor: outerObj.constructor?.name,
        innerCtor: innerObj?.constructor?.name,
        typeofElicitInput: typeof elicitSrv.elicitInput,
        hasTransport,
        fieldNames: Object.keys(fields),
        messagePreview: message.slice(0, 80),
      },
      { containsPii: true },
    );
  }

  let result: unknown;
  try {
    result = await raceTimeout(
      elicitSrv.elicitInput(
        { message, requestedSchema },
        args.relatedRequestId !== undefined ? { relatedRequestId: args.relatedRequestId } : undefined,
      ),
      args.elicitTimeoutMs ?? DEFAULT_ELICIT_TIMEOUT_MS,
    );
  } catch (e) {
    {
      const err = e as { name?: unknown; message?: unknown; stack?: unknown } | null;
      let errorJson: string;
      try { errorJson = JSON.stringify(e); } catch { errorJson = String(e); }
      debugLog(
        args.env,
        "elicit-catch",
        {
          operationId: args.operationId,
          isTimeout: e instanceof TimeoutError,
          errorName: err?.name,
          errorMessage: err?.message,
          errorStack: err?.stack,
          errorJson,
        },
        { containsPii: true },
      );
    }
    const outcome = e instanceof TimeoutError ? "timeout" : "transport-error";
    args.emitAudit({ ...baseAudit, elicitationOutcome: outcome, elicitFields: fields });
    throw new ToolError(`Operation ${args.operationId} requires user approval; outcome: ${outcome}`);
  }

  const r = result as { action?: unknown; content?: unknown } | null;
  const action = r && typeof r === "object" ? r.action : undefined;
  {
    const validated = action === "accept" ? validateAcceptedContent(r?.content) : null;
    debugLog(
      args.env,
      "elicit-result",
      {
        operationId: args.operationId,
        action,
        validated,
      },
      { containsPii: true },
    );
  }

  if (action === "accept") {
    if (!validateAcceptedContent(r?.content)) {
      args.emitAudit({ ...baseAudit, elicitationOutcome: "declined", elicitFields: fields });
      throw new ToolError(`Operation ${args.operationId} requires user approval; outcome: declined`);
    }
    args.emitAudit({ ...baseAudit, elicitationOutcome: "accepted", elicitFields: fields });
    return;
  }

  if (action === "cancel") {
    args.emitAudit({ ...baseAudit, elicitationOutcome: "cancelled", elicitFields: fields });
    throw new ToolError(`Operation ${args.operationId} requires user approval; outcome: cancelled`);
  }

  args.emitAudit({ ...baseAudit, elicitationOutcome: "declined", elicitFields: fields });
  throw new ToolError(`Operation ${args.operationId} requires user approval; outcome: declined`);
}
