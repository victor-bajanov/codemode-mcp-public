import type { ElicitRenderer, Primitive } from "./elicit.js";

export type Decision = "allow" | "elicit" | "deny";

export type SurfaceReviewCategory =
  | "persistent_state"
  | "external_data_flow"
  | "capability_escalation"
  | "credential_change"
  | "financial_legal"
  | "bulk_destructive"
  | "irreversible"
  | "standard_read"
  | "standard_write"
  | "malformed"
  | "url_safety";

/**
 * One part of a multipart/form-data upload as seen by an inspector. Structural
 * subset of the scaffold's outbound `MultipartPart` (name/filename/contentType
 * + one of value|bodyBase64), carried so inspectors can read an uploaded
 * message part without re-parsing the assembled wire body.
 */
export interface InspectMultipartPart {
  name: string;
  filename?: string;
  contentType?: string;
  value?: string;
  bodyBase64?: string;
}

/**
 * The canonical view of the *effective* outbound payload — the bytes that will
 * actually be sent upstream, not any unsent channel. At most one of
 * `{body, rawBody, multipart}` is populated (none for query-only requests):
 *   - `body`      → effective payload is JSON within the parse cap (parsed object)
 *   - `rawBody`   → effective payload is non-JSON bytes (e.g. message/rfc822 media upload)
 *   - `multipart` → effective payload is a multipart/form-data upload
 * `contentType` is the effective outbound content-type. `query` is always the
 * outbound query. An inspector that cannot interpret the populated channel must
 * fail closed (deny).
 */
export interface InspectRequest {
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined>;
  contentType?: string;
  rawBody?: ArrayBuffer | string | Uint8Array;
  multipart?: InspectMultipartPart[];
}

export interface InspectResult {
  decision: Decision;
  category?: SurfaceReviewCategory;
  /** Short, greppable machine code for audit logs (e.g. "creditnote-not-draft"). */
  reason?: string;
  /**
   * Human-readable explanation surfaced to the caller when a deny is thrown.
   * Explains *why* the operation was blocked (e.g. "only DRAFT or SUBMITTED
   * credit notes can be modified") instead of the opaque "denied by surface
   * review". Keep `reason` as the terse log code; this is the caller-facing prose.
   */
  message?: string;
  /** Inspector-extracted, primitives-only summary surfaced into elicitation forms. */
  summary?: Record<string, Primitive>;
}

export interface SurfaceReviewEntry {
  decision: Decision;
  category?: SurfaceReviewCategory;
  reasoning?: string;
  inspect?: (req: InspectRequest) => InspectResult;
  /** Per-op override; runs ahead of `provider.elicitRenderers[category]`. */
  elicit?: ElicitRenderer;
}

export type SurfaceReview = Readonly<Record<string, SurfaceReviewEntry>>;
