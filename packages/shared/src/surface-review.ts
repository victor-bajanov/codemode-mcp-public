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
  /** Present when the part's bytes come from a staged file the host attaches
   *  at send time. The bytes themselves are never shown to an inspector; only
   *  this metadata (filename sanitised, contentType from the part or the row). */
  staged?: { byteLength: number; contentType: string; filename: string | null };
}

/**
 * Metadata for one staged-file slot of a host-assembled (`composed`) body. In
 * the inspection view's `rawBody` each staged slot is a single U+FFFC (OBJECT
 * REPLACEMENT CHARACTER); `index` is the segment index in `composed.segments`.
 */
export interface InspectStaged {
  index: number;
  byteLength: number;
  contentType: string;
  filename: string | null;
  encoding: "base64-lines" | "base64" | "identity";
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
  /** Staged-file slots of a `composed` body, in segment order. Present only
   *  when the effective payload is host-assembled. */
  staged?: ReadonlyArray<InspectStaged>;
  /** Exact byte length of the assembled outbound body (composed or staged
   *  multipart), staged slots expanded in their encoding. */
  assembledByteLength?: number;
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

/** Deployment vars visible to an inspector (the worker's wrangler `vars`,
 *  passed through by the request handler). Lets an inspector resolve
 *  per-deployment policy — e.g. an outbound recipient allowlist — instead of
 *  baking it in at compile time. */
export type InspectEnv = Readonly<Record<string, unknown>>;

export interface SurfaceReviewEntry {
  decision: Decision;
  category?: SurfaceReviewCategory;
  /** Reviewer-facing justification for the decision — why a human reviewer
   *  chose it (e.g. "Same concern as gmail delegates.list"). Internal prose:
   *  it is NEVER shown to a client. Client-visible text goes in `clientNote`;
   *  the two are deliberately separate fields so review rationale cannot leak
   *  into the model's context. */
  reasoning?: string;
  /** Client-visible prose, aimed at the model, describing any request-time
   *  condition that determines whether this call actually succeeds — what will
   *  get it refused, and what shape of request passes. Typically that is the
   *  condition this entry's `inspect` hook applies, but it also covers
   *  conditions outside the inspector, e.g. an operation the surface review
   *  allows but the granted OAuth scopes cannot reach (it will 403 whatever the
   *  inspector decides), so the model does not plan around an endpoint that
   *  cannot work.
   *
   *  Appended to the operation's spec `description` by
   *  `annotateSpecWithSurfaceReview`, so `search` surfaces it at the moment it
   *  is relevant. Distinct from `reasoning` (reviewer-facing, never surfaced):
   *  keep the two apart. Terse — it is paid for on every search hit. The
   *  structural facts (denied / needs approval / inspected at all) are
   *  generated from `decision` + the presence of `inspect`, so do not repeat
   *  them here. */
  clientNote?: string;
  /** Body-level inspector. `env` is optional (test batteries and probes omit
   *  it); an inspector whose policy depends on env must fail closed — treat a
   *  missing var the same as an empty policy, never fall back to a permissive
   *  default. */
  inspect?: (req: InspectRequest, env?: InspectEnv) => InspectResult;
  /** Best-effort JSON-body normalizer, applied by the request handler BEFORE
   *  the effective payload is resolved — so inspection, the elicit dialog, and
   *  the upstream send all see the same normalized payload (the inspected ==
   *  approved == sent invariant holds over the normalized bytes). Return the
   *  replacement body, or `undefined` to leave the payload unchanged.
   *
   *  Scope: presentation-layer repair only (e.g. Gmail rewriting a mojibake'd
   *  Subject header into a proper RFC 2047 encoded-word). It must never change
   *  the semantics an inspector rules on — recipients, ids, amounts. Fail-open
   *  by contract: a throw is treated as "no change"; repair never blocks a
   *  request it cannot confidently improve. Only the parsed JSON channel is
   *  normalized — rawBody/bodyBase64/multipart payloads pass through untouched. */
  normalizeBody?: (body: unknown) => unknown;
  /** Opt in to host-assembled bodies (`composed` or `multipart[].staged`).
   *  On an inspected or `elicit` operation without it, any staged reference
   *  is denied `staged-not-supported` before the inspector runs: an inspector
   *  written for JSON or inline parts must not be asked to judge a body whose
   *  bytes it cannot see. Bare-allow operations are unaffected. */
  acceptsStaged?: true;
  /** Best-effort normaliser for a `composed` body, applied to the text that
   *  precedes the first staged segment (all text segments before it, joined).
   *  Same contract as `normalizeBody`: presentation repair only, fail-open,
   *  `undefined` = no change. A no-op when the body is a sole identity
   *  segment. */
  normalizeComposedText?: (text: string) => string | undefined;
  /** Per-op override; runs ahead of `provider.elicitRenderers[category]`. */
  elicit?: ElicitRenderer;
}

export type SurfaceReview = Readonly<Record<string, SurfaceReviewEntry>>;
