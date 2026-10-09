import type { PutFileResult } from "./putfile-capability";

// Re-declare the bits of UpstreamCtx the capability uses (avoid a cyclical
// import on request-handler.ts which already imports from this directory).
export interface StageRequestOpts {
  method: string;
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  contentType?: string;
  rawBody?: boolean;
  bodyBase64?: string;
}

export interface UpstreamRequestResult {
  success: boolean;
  status: number;
  result: unknown;
  errors?: Array<{ code: number; message: string }>;
}

export interface StageFromUpstreamJsonDeps {
  putFile: (bytesBase64: string, contentType: string, filename: string | null) => Promise<PutFileResult>;
  /** Closure constructed by mcp-agent-factory. Receives the full request ctx
   *  (including the internal `bypassTruncate: true`) and returns the parsed
   *  upstream envelope WITHOUT truncation. */
  upstreamRequest: (ctx: StageRequestOpts & { bypassTruncate: true }) => Promise<UpstreamRequestResult>;
}

export type StageFromUpstreamJsonCapability = (
  requestOpts: StageRequestOpts,
  dataField: string,
  dataEncoding?: "base64url" | "base64",
  filenameOverride?: string | null,
  contentTypeOverride?: string | null,
) => Promise<PutFileResult>;

/** The declared StageRequestOpts fields — the only ones forwarded to the
 *  upstream handler (F-24). Anything else on the sandbox-supplied object
 *  (`headers`, `returnAs`, `multipart`, `relatedRequestId`, …) is dropped. */
const DECLARED_REQUEST_FIELDS = [
  "method",
  "path",
  "query",
  "body",
  "contentType",
  "rawBody",
  "bodyBase64",
] as const satisfies ReadonlyArray<keyof StageRequestOpts>;

function pickDeclaredRequestOpts(
  requestOpts: Record<string, unknown>,
): StageRequestOpts & { bypassTruncate: true } {
  const picked: Record<string, unknown> = {};
  for (const field of DECLARED_REQUEST_FIELDS) {
    // Own properties only, and only when defined (exactOptionalPropertyTypes).
    if (Object.hasOwn(requestOpts, field) && requestOpts[field] !== undefined) {
      picked[field] = requestOpts[field];
    }
  }
  return { ...(picked as unknown as StageRequestOpts), bypassTruncate: true };
}

function base64urlToBase64(s: string): string {
  const standard = s.replace(/-/g, "+").replace(/_/g, "/");
  const padNeeded = (4 - (standard.length % 4)) % 4;
  return standard + "=".repeat(padNeeded);
}

export function createStageFromUpstreamJsonCapability(
  deps: StageFromUpstreamJsonDeps,
): StageFromUpstreamJsonCapability {
  return async function stageFromUpstreamJson(
    requestOpts,
    dataField,
    dataEncoding = "base64url",
    filenameOverride = null,
    contentTypeOverride = null,
  ) {
    if (!dataField || typeof dataField !== "string") {
      return { ok: false, status: 400, message: "dataField must be a non-empty string" };
    }
    if (dataEncoding !== "base64url" && dataEncoding !== "base64") {
      return { ok: false, status: 400, message: 'dataEncoding must be "base64url" or "base64"' };
    }

    if (
      requestOpts === null ||
      typeof requestOpts !== "object" ||
      Array.isArray(requestOpts)
    ) {
      return { ok: false, status: 400, message: "requestOpts must be an object" };
    }

    let r: UpstreamRequestResult;
    try {
      r = await deps.upstreamRequest(
        pickDeclaredRequestOpts(requestOpts as unknown as Record<string, unknown>),
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, status: 502, message: `upstream request failed: ${msg}` };
    }

    if (!r.success) {
      return { ok: false, status: r.status || 502, message: "upstream non-2xx" };
    }

    if (!r.result || typeof r.result !== "object") {
      return { ok: false, status: 502, message: "upstream result is not an object" };
    }

    const result = r.result as Record<string, unknown>;
    const raw = result[dataField];
    if (typeof raw !== "string" || raw.length === 0) {
      return { ok: false, status: 502, message: `field "${dataField}" missing or not a non-empty string` };
    }

    const b64 = dataEncoding === "base64url" ? base64urlToBase64(raw) : raw;
    const overrideTrimmed = typeof contentTypeOverride === "string" ? contentTypeOverride.trim() : "";
    const envelopeTrimmed = typeof result.mimeType === "string" ? result.mimeType.trim() : "";
    const mime =
      overrideTrimmed.length > 0
        ? overrideTrimmed
        : envelopeTrimmed.length > 0
          ? envelopeTrimmed
          : "application/octet-stream";

    return deps.putFile(b64, mime, filenameOverride ?? null);
  };
}
