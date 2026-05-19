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
  query?: unknown;
  inspectorSummary?: Record<string, Primitive>;
}

export function genericWalker(args: GenericWalkerArgs): ElicitRendererOutput {
  const fields: FormFields = {};

  if (args.inspectorSummary) {
    for (const [k, v] of Object.entries(args.inspectorSummary)) {
      if (Object.keys(fields).length >= MAX_FIELDS) break;
      if (isPrimitive(v) && isWalkable(v)) fields[k] = v;
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
      if (Object.keys(fields).length >= MAX_FIELDS) break;
      if (key in fields) continue;
      const v = (args.body as Record<string, unknown>)[key];
      if (isPrimitive(v) && isWalkable(v)) fields[key] = v;
    }
  }

  if (Object.keys(fields).length === 0) fields.confirm = true;

  return {
    message: `Confirm operation: ${args.operationId}`,
    fields,
  };
}

export interface RequestedSchema {
  type: "object";
  properties: Record<string, { type: "string" | "number" | "boolean" }>;
  required: string[];
  additionalProperties: false;
}

export function buildRequestedSchema(fields: FormFields): RequestedSchema {
  const properties: RequestedSchema["properties"] = {};
  const required: string[] = [];
  for (const key of Object.keys(fields)) {
    const v = fields[key];
    const t = typeof v as "string" | "number" | "boolean";
    properties[key] = { type: t };
    required.push(key);
  }
  return { type: "object", properties, required, additionalProperties: false };
}

export function validateAcceptedContent(
  content: unknown,
  expected: FormFields,
): boolean {
  if (content === null || typeof content !== "object") return false;
  const c = content as Record<string, unknown>;
  const expectedKeys = Object.keys(expected);
  if (Object.keys(c).length !== expectedKeys.length) return false;
  for (const k of expectedKeys) {
    if (!(k in c)) return false;
    if (typeof c[k] !== typeof expected[k]) return false;
  }
  return true;
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
  if (typeof srv?.getClientCapabilities !== "function") return true;     // fail-open; let elicitInput reject
  const caps = srv.getClientCapabilities();
  return caps?.elicitation != null;
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
  path: string;
  body: unknown;
  query?: unknown;
  category?: string;
  reason?: string;
  inspectorSummary?: Record<string, Primitive>;
  entry: SurfaceReviewEntry;
  elicitRenderers?: Partial<Record<string, ElicitRenderer>>;
  server: ServerLike & {
    server?: {
      elicitInput?: (params: unknown) => Promise<unknown>;
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
      ...(input.query !== undefined ? { query: input.query } : {}),
      ...(input.inspectorSummary ? { inspectorSummary: input.inspectorSummary } : {}),
    }));

  const rendered = renderer({
    operationId: args.operationId,
    body: args.body,
    ...(args.query !== undefined ? { query: args.query } : {}),
    ...(args.inspectorSummary ? { inspectorSummary: args.inspectorSummary } : {}),
  });
  const requestedSchema = buildRequestedSchema(rendered.fields);
  const fields = rendered.fields;

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
        messagePreview: rendered.message.slice(0, 80),
      },
      { containsPii: true },
    );
  }

  let result: unknown;
  try {
    result = await raceTimeout(
      elicitSrv.elicitInput({ message: rendered.message, requestedSchema }),
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
    const validated = action === "accept" ? validateAcceptedContent(r?.content, fields) : null;
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
    if (!validateAcceptedContent(r?.content, fields)) {
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
