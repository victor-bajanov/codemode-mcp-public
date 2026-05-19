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
) => Promise<PutFileResult>;

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
  ) {
    if (!dataField || typeof dataField !== "string") {
      return { ok: false, status: 400, message: "dataField must be a non-empty string" };
    }
    if (dataEncoding !== "base64url" && dataEncoding !== "base64") {
      return { ok: false, status: 400, message: 'dataEncoding must be "base64url" or "base64"' };
    }

    let r: UpstreamRequestResult;
    try {
      r = await deps.upstreamRequest({ ...requestOpts, bypassTruncate: true });
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
    const mime = typeof result.mimeType === "string" && result.mimeType.length > 0
      ? result.mimeType
      : "application/octet-stream";

    return deps.putFile(b64, mime, filenameOverride ?? null);
  };
}
