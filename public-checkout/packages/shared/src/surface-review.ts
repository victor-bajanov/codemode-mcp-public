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

export interface InspectRequest {
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined>;
  /** Outbound `content-type` if non-JSON. Set by request-handler when relevant. */
  contentType?: string;
  /** Raw outbound body for binary/multipart (e.g. file uploads). Mutually exclusive with `body`. */
  rawBody?: ArrayBuffer | string;
}

export interface InspectResult {
  decision: Decision;
  category?: SurfaceReviewCategory;
  reason?: string;
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
