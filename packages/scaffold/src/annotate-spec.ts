// Per-operation surface-review annotation.
//
// A client discovers this server's API through the codemode `search` tool,
// which runs sandbox code over the whole spec. Gating facts therefore belong on
// the operation they apply to — surfaced at the moment the model is looking at
// that endpoint — rather than in the global `executeHint`, which is paid for in
// every context window whether or not it is relevant.
//
// The states, and why each needs its own wording (see request-handler.ts):
//
//   1. `deny`               A static deny short-circuits BEFORE the inspector
//                           runs. Unconditionally unavailable.
//   2. `allow`, no inspect  Unconditionally available. Annotated with NOTHING —
//                           see NO_ANNOTATION note below.
//   3. `allow` + `inspect`  Available by default, but the request payload is
//                           examined at call time and may be refused. This must
//                           NOT read like state 1: the operation is usable, it
//                           is the specific request that may not be.
//   4. `elicit`, no inspect Needs interactive approval. Clients without MCP
//                           elicitation support (Claude.ai included) cannot
//                           show one, and elicit.ts throws
//                           "requires user approval; outcome: unsupported".
//   5. `elicit` + `inspect` The inspector runs first and can refuse before
//                           approval is ever reached
//                           (`decision = mostRestrictive(static, inspected)` —
//                           the static decision is a floor, never a ceiling).
//
// Plus: an operation present in the spec with NO surface-review entry is
// implicitly denied ("not in surface review"). Those are annotated too —
// otherwise a client plans around endpoints that silently fail.
//
// NO_ANNOTATION: state 2 is deliberately left untouched. It is the large
// majority of operations, the annotation would carry no information (an
// operation behaves exactly as its spec says), and the text is paid for on
// every search hit across a spec with hundreds of operations. Because every
// other state — including unlisted — IS annotated, the absence of a marker is
// itself unambiguous: plainly available.
//
// REJECTED, with numbers — "make a whole-surface {operationId, description}
// sweep of Xero fit under codemode's 24,000-char cap". It cannot be done, and
// was not overlooked:
//
//   raw sweep (unannotated)      20,433 chars  → 3,567 headroom for 283 ops,
//                                                i.e. 12.6 chars per operation
//   annotated sweep              38,278 chars  → 164 of 283 ops fit
//   structural text alone,
//   every clientNote deleted      9,239 chars  → still 5,672 OVER the headroom
//
// So no amount of note-shortening reaches 283; only annotating nothing does,
// which is the feature. The "fit all 283" baseline was an artefact — 264 of
// those descriptions were `undefined`, so the projection was already at 85% of
// cap before anything was added.
//
// Shrinking the deny/unlisted text to a bare "ACCESS: denied." would reach
// ~230 and was rejected too: it drops the explicit "always fail" phrasing the
// surface owner asked for, and — the stronger reason — every fact removed for
// length is a fact the client-note-semantics tests can no longer verify against
// the real inspector. Note length is a CORRECTNESS surface here, not just a
// cost one. The cheap-breadth path is the `[ACCESS: …]` summary markers: scan
// `{method, path, summary}`, then pull descriptions for the few candidates.

import type { SurfaceReview, SurfaceReviewEntry } from "@local/shared";

/** Delimiter that introduces the generated block. Greppable, and the anchor
 *  that makes re-annotation idempotent: an existing block is cut at this
 *  marker before the fresh one is appended. Verified absent from every bundled
 *  provider spec, so stripping can never eat upstream prose. */
export const SURFACE_REVIEW_MARKER = "ACCESS: ";

/** Separator between the upstream description and the generated block. */
const MARKER_SEP = "\n\n";

/**
 * Anchor for the SHORT pointer appended to `summary`.
 *
 * Why a second field at all: which field carries an operation's prose is not
 * consistent across the bundled specs. Every one of Gmail's 79 operations has a
 * `description` and NO `summary`; 260 of Xero's 283 have a `summary` and no
 * `description`; 19 Xero operations have both; 4 Xero
 * operations have neither. Client search code picks one field — codemode's own
 * worked example in the search tool description returns `op.summary` — so an
 * annotation written only to `description` is invisible to a `summary` reader
 * for the bulk of the Xero surface. That is worse than no annotation: it is
 * cost with no benefit, and it makes the surface look covered when it is not.
 *
 * `summary` is a one-liner by convention, so it gets a bare one- or two-word
 * label rather than a copy of the full text — and deliberately NOT a "see the
 * description" cross-reference, which would tell the model to look at a field
 * it already holds in the same operation object. Every char here is multiplied
 * by the number of operations a search returns and counts against codemode's
 * 24,000-char response cap (MAX_TOKENS 6e3 × CHARS_PER_TOKEN 4, mcp.js), so
 * marker length converts directly into lost discovery breadth. Measured on the
 * real Xero spec: dropping a "— see description" suffix from the 119 markers
 * saved 2,121 chars and moved the `{method, path, summary}` fit from 137 back
 * to 142 operations (unannotated baseline is 152).
 */
export const SURFACE_REVIEW_SUMMARY_MARKER = "[ACCESS: ";

/** Separator between the upstream summary and the pointer. */
const SUMMARY_SEP = " ";

/** What a client without elicitation support actually experiences. Kept
 *  verbatim from the ToolError thrown in elicit.ts so the text a model reads
 *  matches the text it will get back. */
const UNSUPPORTED_CLAUSE =
  "clients without MCP elicitation support (Claude.ai included) cannot give it, " +
  'and the call then fails with "requires user approval; outcome: unsupported" ' +
  "without changing anything.";

const ELICIT_TAIL = `requires interactive user approval; ${UNSUPPORTED_CLAUSE}`;

/**
 * Appended when a `clientNote` says the INSPECTOR may require approval.
 *
 * A static `elicit` is not the only route to an approval prompt: an `allow` +
 * `inspect` entry escalates at call time via
 * `mostRestrictive(static, inspected)`, so a note like "more than 25 attendees
 * needs interactive approval" describes a real elicit that the structural text
 * for `allow` never mentions. Without this the model promises the user a
 * confirmation it cannot show — the precise failure this annotation exists to
 * prevent. Triggered off the note's own wording rather than a hand-maintained
 * per-entry flag, because hand-maintained prose is what regressed before.
 */
const ESCALATED_APPROVAL_CAVEAT = ` Where approval is required, ${UNSUPPORTED_CLAUSE}`;

/** True when prose claims approval may be needed. */
const MENTIONS_APPROVAL = /\bapprovals?\b/i;

const INSPECTED_CLAUSE =
  "each request is inspected at call time and may be refused";

/**
 * Every label this module can emit inside a summary marker.
 *
 * A closed set, because it is what tells one of OUR summary markers apart from
 * upstream prose that happens to end in a bracketed `[ACCESS: …]` token —
 * position cannot, since ours is always the final token. `Annotation.summary`
 * is typed to this union so the set cannot drift from what `annotationFor`
 * actually emits: adding a label without listing it here is a type error, not a
 * silent hole in the collision guard.
 */
const SUMMARY_LABELS = [
  "unavailable",
  "denied",
  "conditional + approval",
  "approval required",
  "note",
  "conditional",
] as const;

type SummaryLabel = (typeof SUMMARY_LABELS)[number];

const IS_OUR_SUMMARY_LABEL: ReadonlySet<string> = new Set(SUMMARY_LABELS);

/** The full annotation body and the short summary pointer for one operation.
 *  Both null means leave the operation alone (state 2 — see NO_ANNOTATION). */
interface Annotation {
  /** Appended to `description` (which is created if absent). */
  description: string | null;
  /** Appended to `summary` — ONLY when a summary already exists. Never a copy
   *  of `description`; just enough to tell the reader which way it goes and
   *  where the detail is. */
  summary: SummaryLabel | null;
}

const NO_ANNOTATION: Annotation = { description: null, summary: null };

function annotationFor(entry: SurfaceReviewEntry | undefined): Annotation {
  if (!entry) {
    return {
      description: "not on this server's reviewed surface, so calls always fail.",
      summary: "unavailable",
    };
  }

  if (entry.decision === "deny") {
    // A static deny short-circuits ahead of any inspector, so even an entry
    // that carries one is unconditional here.
    return {
      description: "denied by this server's surface review, so calls always fail.",
      summary: "denied",
    };
  }

  const inspected = entry.inspect !== undefined;
  const note = entry.clientNote ? ` ${entry.clientNote}` : "";

  if (entry.decision === "elicit") {
    return inspected
      ? {
          description: `${INSPECTED_CLAUSE} before any approval is sought; otherwise it ${ELICIT_TAIL}${note}`,
          summary: "conditional + approval",
        }
      : {
          description: `${ELICIT_TAIL}${note}`,
          summary: "approval required",
        };
  }

  // decision === "allow"
  if (!inspected) {
    // No inspector means no policy condition to state — but a `clientNote` here
    // is a non-inspector condition on whether the call succeeds (e.g. an
    // operation the review allows that the granted OAuth scopes cannot reach).
    // Surfacing it is the entire reason it was written, so it is emitted alone,
    // without the inspection or approval language that would be false here.
    if (!entry.clientNote) return NO_ANNOTATION;
    return { description: entry.clientNote, summary: "note" };
  }
  // If the note says the inspector can demand approval, the operation can end
  // in elicit despite its static `allow` — so it needs the same
  // unsupported-client caveat a statically-elicit entry gets.
  const escalates = entry.clientNote !== undefined && MENTIONS_APPROVAL.test(entry.clientNote);
  return {
    description:
      `allowed, but ${INSPECTED_CLAUSE}.${note}` +
      (escalates ? ESCALATED_APPROVAL_CAVEAT : ""),
    summary: escalates ? "conditional + approval" : "conditional",
  };
}

/**
 * True when the marker in `text` is one WE wrote, rather than upstream prose
 * that happens to contain it.
 *
 * Positional, not wording-based: a generated block always starts the text (when
 * the operation had no description) or directly follows the MARKER_SEP blank
 * line. Upstream prose containing the marker has it mid-sentence — "Grants
 * ACCESS: read-only rights" — which annotating would truncate to "Grants".
 * Checking position rather than the block's opening words matters because one
 * state emits a bare `clientNote` whose wording is arbitrary.
 */
function isOurAnnotation(text: string): boolean {
  return anchoredMarkerIndex(text, SURFACE_REVIEW_MARKER, "description") >= 0;
}

/** Index of OUR marker in `text`, or -1. Anchored: the description marker only
 *  counts at the start or directly after the blank-line separator, and the
 *  summary marker only when it runs to the end of the string AND carries one of
 *  our own labels. Bare-substring matching truncated upstream prose — "Grants
 *  ACCESS: read-only…" became "Grants", and "Legacy [ACCESS: LEGACY] endpoint"
 *  lost " endpoint". */
function anchoredMarkerIndex(text: string, marker: string, kind: "description" | "summary"): number {
  if (kind === "description") {
    if (text.startsWith(marker)) return 0;
    const i = text.indexOf(`${MARKER_SEP}${marker}`);
    return i < 0 ? -1 : i;
  }
  // Summary: ours is always the final token, ` [ACCESS: <label>]` at the end.
  // Position alone is not enough — an upstream summary can end in a bracketed
  // token of its own ("Legacy endpoint [ACCESS: LEGACY]"), and stripping that
  // as if it were ours would silently eat real spec text. The label must be one
  // we emit; anything else is a collision for the caller to reject.
  const m = /\s\[ACCESS: ([^\][]*)\]$/.exec(text);
  if (!m) return -1;
  // Specs are re-annotated on every boot, so a spec written by an EARLIER
  // release still carries that release's label form — the retired one appended
  // " — see description" (dropped for length; see SURFACE_REVIEW_SUMMARY_MARKER).
  // Matching on the label stem lets those converge on the current form; failing
  // to would report a past annotation of ours as an upstream collision and
  // throw at boot. A tail is only ever OURS to begin with, so this widens the
  // recognizer, not the collision.
  const label = (m[1] as string).split(" — ")[0] as string;
  return IS_OUR_SUMMARY_LABEL.has(label) ? m.index : -1;
}

interface OperationLike {
  operationId?: unknown;
  description?: unknown;
  summary?: unknown;
}

type PathItemLike = Record<string, unknown>;

export interface AnnotatableSpec {
  paths?: Record<string, PathItemLike>;
}

/**
 * Return a copy of `spec` whose operations carry a terse statement of their
 * availability under `surfaceReview`: the full text on `description` (created
 * when absent), and a short pointer on `summary` when the operation has one, so
 * the fact is reachable whichever field the client's search code reads.
 *
 * PURE: the input is never mutated. Provider specs are imported JSON modules
 * shared process-wide and asserted by other tests, so mutating one would
 * corrupt every other consumer. Objects that need no change are reused by
 * reference; only the containers along a changed path are rebuilt.
 *
 * Idempotent on BOTH fields: an existing block (identified by
 * SURFACE_REVIEW_MARKER / SURFACE_REVIEW_SUMMARY_MARKER) is stripped before the
 * fresh one is appended, so re-annotating neither double-appends nor preserves
 * a stale claim.
 *
 * A `summary` is never invented where none existed — only ever appended to.
 *
 * Keyed on `operationId`, which is what `surfaceReview` is keyed on too
 * (enforced by each provider's surface-review-keys-match-spec test).
 */
export function annotateSpecWithSurfaceReview<S extends AnnotatableSpec>(
  spec: S,
  surfaceReview: SurfaceReview,
): S {
  const paths = spec.paths;
  if (!paths) return spec;

  const nextPaths: Record<string, PathItemLike> = {};
  let specChanged = false;

  for (const [path, pathItem] of Object.entries(paths)) {
    if (typeof pathItem !== "object" || pathItem === null) {
      nextPaths[path] = pathItem;
      continue;
    }

    const nextItem: PathItemLike = {};
    let itemChanged = false;

    // A $ref'd path item hides its operations behind a reference this function
    // does not resolve, so every operation under it would go un-annotated and
    // read as state 2 ("plainly available") regardless of its real decision.
    // That is the annotation layer failing OPEN in the code whose entire job is
    // making denies visible, so refuse rather than under-annotate. No bundled
    // spec uses this form; if one starts, resolve refs before annotating.
    if (typeof pathItem["$ref"] === "string") {
      throw new Error(
        `annotateSpecWithSurfaceReview: path "${path}" is a $ref path item; ` +
          "its operations cannot be annotated and would read as unconditionally " +
          "available. Resolve $ref path items before annotating.",
      );
    }

    for (const [method, op] of Object.entries(pathItem)) {
      // Path items also carry non-operation members ("parameters", …).
      const candidate = op as OperationLike | null;
      if (
        typeof candidate !== "object" ||
        candidate === null ||
        typeof candidate.operationId !== "string"
      ) {
        nextItem[method] = op;
        continue;
      }

      const annotation = annotationFor(surfaceReview[candidate.operationId]);

      const originalDesc =
        typeof candidate.description === "string" ? candidate.description : "";
      // An upstream description containing the marker would be TRUNCATED at it
      // on the first pass (a plain-allow op described as "Grants ACCESS:
      // read-only…" would become "Grants") — silent loss of real spec content.
      // Idempotent re-annotation is indistinguishable from a collision by text
      // alone, so only flag it when there is no annotation of ours to explain
      // it: a marker with no generated body following one of our labels.
      if (originalDesc.includes(SURFACE_REVIEW_MARKER) && !isOurAnnotation(originalDesc)) {
        throw new Error(
          `annotateSpecWithSurfaceReview: operation "${candidate.operationId}" has an ` +
            `upstream description containing the reserved marker "${SURFACE_REVIEW_MARKER}"; ` +
            "annotating would truncate it. Rename the marker or fix the spec.",
        );
      }
      const descMarker = anchoredMarkerIndex(originalDesc, SURFACE_REVIEW_MARKER, "description");
      const baseDesc =
        descMarker < 0 ? originalDesc : originalDesc.slice(0, descMarker).trimEnd();
      const description =
        annotation.description === null
          ? baseDesc
          : baseDesc
            ? `${baseDesc}${MARKER_SEP}${SURFACE_REVIEW_MARKER}${annotation.description}`
            : `${SURFACE_REVIEW_MARKER}${annotation.description}`;

      // `summary` is only ever appended to, never created: an operation with no
      // summary (every Gmail op) must not sprout one.
      const hasSummary = typeof candidate.summary === "string";
      const originalSummary = hasSummary ? (candidate.summary as string) : "";
      const sumMarker = anchoredMarkerIndex(originalSummary, SURFACE_REVIEW_SUMMARY_MARKER, "summary");
      // Same reserved-marker collision as the description above, and the same
      // reason to fail loudly: an upstream summary ending in its own bracketed
      // "[ACCESS: LEGACY]" token would be cut off by `baseSummary`. Ours is
      // recognised by its label, so a marker here with a label we never emit is
      // upstream text, whatever its position.
      if (originalSummary.includes(SURFACE_REVIEW_SUMMARY_MARKER) && sumMarker < 0) {
        throw new Error(
          `annotateSpecWithSurfaceReview: operation "${candidate.operationId}" has an ` +
            `upstream summary containing the reserved marker "${SURFACE_REVIEW_SUMMARY_MARKER}"; ` +
            "annotating would truncate it. Rename the marker or fix the spec.",
        );
      }
      const baseSummary =
        sumMarker < 0 ? originalSummary : originalSummary.slice(0, sumMarker).trimEnd();
      const summary = !hasSummary
        ? originalSummary
        : annotation.summary === null
          ? baseSummary // no marker warranted; strips a stale one if present
          : `${baseSummary}${SUMMARY_SEP}${SURFACE_REVIEW_SUMMARY_MARKER}${annotation.summary}]`;

      const descChanged = description !== originalDesc;
      const summaryChanged = hasSummary && summary !== originalSummary;
      // An operation that had no description and needs no annotation keeps
      // having none, rather than gaining an empty string.
      if (!descChanged && !summaryChanged) {
        nextItem[method] = op;
        continue;
      }
      itemChanged = true;
      nextItem[method] = {
        ...candidate,
        ...(descChanged ? { description } : {}),
        ...(summaryChanged ? { summary } : {}),
      };
    }

    if (itemChanged) {
      specChanged = true;
      nextPaths[path] = nextItem;
    } else {
      nextPaths[path] = pathItem;
    }
  }

  if (!specChanged) return spec;
  return { ...spec, paths: nextPaths };
}
