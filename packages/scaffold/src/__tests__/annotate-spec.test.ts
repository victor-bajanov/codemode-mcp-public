// annotateSpecWithSurfaceReview: per-operation availability annotation.
//
// The gating detail a client needs lives on the operation it applies to, where
// `search` surfaces it at the moment it is relevant, rather than in a global
// executeHint paid for in every context window.
//
// The five states this must keep distinct (see request-handler.ts):
//   1. deny              → short-circuits BEFORE the inspector; always fails.
//   2. allow, no inspect → unconditionally available (annotated with nothing).
//   3. allow + inspect   → available, but the payload is inspected at request
//                          time and may be refused. NOT the same as (1).
//   4. elicit            → needs interactive approval; on a client without
//                          elicitation support (Claude.ai) it fails outright.
//   5. elicit + inspect  → inspector can refuse before approval is reached.
// Plus: an operation in the spec with NO surface-review entry is implicitly
// denied ("not in surface review") and must say so.

import { describe, it, expect } from "vitest";
import type { SurfaceReview } from "@local/shared";
import {
  annotateSpecWithSurfaceReview,
  SURFACE_REVIEW_MARKER,
  SURFACE_REVIEW_SUMMARY_MARKER,
  type AnnotatableSpec,
} from "../annotate-spec";

const GOOGLE_TEXT = "Sends the specified message to the recipients.";
const XERO_SUMMARY = "Retrieves the full chart of accounts";

/**
 * Minimal spec covering all five states + an unlisted operation, in all three
 * field shapes the real specs actually use:
 *   - description only          → every Gmail op (79/79, zero summaries)
 *   - summary only              → 260 of Xero's 283 ops
 *   - both                      → 19 Xero ops, and all 33 optical ops
 *   - neither                   → 4 Xero ops
 * The ACCESS text has to be reachable whichever field the client's search code
 * reads, so every state below is exercised in the summary-bearing shape too.
 */
function makeSpec() {
  return {
    openapi: "3.0.0",
    info: { title: "t", version: "1" },
    paths: {
      // description-only (Gmail shape)
      "/denied": { post: { operationId: "op.denied", description: GOOGLE_TEXT } },
      "/plain": { get: { operationId: "op.plain", description: GOOGLE_TEXT } },
      "/inspected": { post: { operationId: "op.inspected", description: GOOGLE_TEXT } },
      "/elicited": { post: { operationId: "op.elicited", description: GOOGLE_TEXT } },
      "/elicitedInspected": {
        post: { operationId: "op.elicitedInspected", description: GOOGLE_TEXT },
      },
      "/unlisted": { post: { operationId: "op.unlisted", description: GOOGLE_TEXT } },
      "/noteOnly": { post: { operationId: "op.noteOnly", description: GOOGLE_TEXT } },
      "/sumNoteOnly": { post: { operationId: "sum.noteOnly", summary: XERO_SUMMARY } },
      // summary-only (the Xero majority)
      "/sumDenied": { post: { operationId: "sum.denied", summary: XERO_SUMMARY } },
      "/sumPlain": { get: { operationId: "sum.plain", summary: XERO_SUMMARY } },
      "/sumInspected": { post: { operationId: "sum.inspected", summary: XERO_SUMMARY } },
      "/sumElicited": { post: { operationId: "sum.elicited", summary: XERO_SUMMARY } },
      "/sumElicitedInspected": {
        post: { operationId: "sum.elicitedInspected", summary: XERO_SUMMARY },
      },
      "/sumUnlisted": { post: { operationId: "sum.unlisted", summary: XERO_SUMMARY } },
      // both (optical / the 19 Xero ops)
      "/both": { post: { operationId: "op.both", summary: XERO_SUMMARY, description: GOOGLE_TEXT } },
      // neither (the 4 Xero ops)
      "/neither": { post: { operationId: "op.neither" } },
      "/nodesc": { post: { operationId: "op.nodesc", summary: "no description here" } },
    },
  };
}

const inspect = () => ({ decision: "allow" as const });

const review: SurfaceReview = {
  "op.denied": { decision: "deny", category: "capability_escalation", reasoning: "reviewer-only prose" },
  "op.plain": { decision: "allow", category: "standard_read" },
  "op.inspected": { decision: "allow", inspect, clientNote: "NOTE-INSPECTED" },
  "op.elicited": { decision: "elicit", category: "irreversible" },
  "op.elicitedInspected": { decision: "elicit", inspect, clientNote: "NOTE-BOTH" },
  "op.nodesc": { decision: "allow", inspect },
  "sum.denied": { decision: "deny", category: "capability_escalation", reasoning: "reviewer-only prose" },
  "sum.plain": { decision: "allow", category: "standard_read" },
  "sum.inspected": { decision: "allow", inspect, clientNote: "NOTE-INSPECTED" },
  "sum.elicited": { decision: "elicit", category: "irreversible" },
  "sum.elicitedInspected": { decision: "elicit", inspect, clientNote: "NOTE-BOTH" },
  "op.both": { decision: "allow", inspect, clientNote: "NOTE-BOTH-FIELDS" },
  "op.neither": { decision: "deny", category: "irreversible", reasoning: "reviewer-only prose" },
  // A plain allow that still has something the client must know (e.g. an
  // operation the surface review allows but the granted OAuth scopes cannot
  // reach). No inspector, so no policy condition — but the note must still be
  // surfaced, or writing one is pointless.
  "op.noteOnly": { decision: "allow", category: "standard_read", clientNote: "NOTE-ONLY" },
  "sum.noteOnly": { decision: "allow", category: "standard_read", clientNote: "NOTE-ONLY" },
};

// biome-ignore lint/suspicious/noExplicitAny: walking a plain JSON spec in tests
const opOf = (spec: any, path: string, method: string): any => spec.paths[path][method];
// biome-ignore lint/suspicious/noExplicitAny: walking a plain JSON spec in tests
const descOf = (spec: any, path: string, method: string): string =>
  opOf(spec, path, method).description ?? "";
// biome-ignore lint/suspicious/noExplicitAny: walking a plain JSON spec in tests
const summaryOf = (spec: any, path: string, method: string): string =>
  opOf(spec, path, method).summary ?? "";
/** The appended marker only, without the original upstream summary. */
// biome-ignore lint/suspicious/noExplicitAny: walking a plain JSON spec in tests
const summaryMarkerOf = (spec: any, path: string, method: string): string => {
  const u = summaryOf(spec, path, method);
  const i = u.indexOf(SURFACE_REVIEW_SUMMARY_MARKER);
  return i < 0 ? "" : u.slice(i);
};
/** The appended text only, without the original upstream description. */
// biome-ignore lint/suspicious/noExplicitAny: walking a plain JSON spec in tests
const annotationOf = (spec: any, path: string, method: string): string => {
  const d = descOf(spec, path, method);
  const i = d.indexOf(SURFACE_REVIEW_MARKER);
  return i < 0 ? "" : d.slice(i);
};

describe("annotateSpecWithSurfaceReview — purity", () => {
  it("does not mutate the input spec", () => {
    const spec = makeSpec();
    const before = JSON.parse(JSON.stringify(spec));
    annotateSpecWithSurfaceReview(spec, review);
    expect(spec).toEqual(before);
  });

  it("returns a new spec object and a new paths object", () => {
    const spec = makeSpec();
    const out = annotateSpecWithSurfaceReview(spec, review);
    expect(out).not.toBe(spec);
    expect(out.paths).not.toBe(spec.paths);
  });

  it("structurally shares operations it does not change", () => {
    const spec = makeSpec();
    const out = annotateSpecWithSurfaceReview(spec, review);
    // op.plain is allow-with-no-inspector → no annotation → same object reused.
    expect(opOf(out, "/plain", "get")).toBe(opOf(spec, "/plain", "get"));
    expect(out.paths["/plain"]).toBe(spec.paths["/plain"]);
    // ...while an annotated one is a fresh object.
    expect(opOf(out, "/denied", "post")).not.toBe(opOf(spec, "/denied", "post"));
  });

  it("preserves fields other than description/summary on an annotated operation", () => {
    const spec = makeSpec();
    const out = annotateSpecWithSurfaceReview(spec, review);
    expect(opOf(out, "/denied", "post").operationId).toBe("op.denied");
    // The upstream summary text is kept; the marker is appended to it.
    expect(summaryOf(out, "/nodesc", "post").startsWith("no description here")).toBe(true);
  });

  it("does not mutate summaries on the input spec either", () => {
    const spec = makeSpec();
    annotateSpecWithSurfaceReview(spec, review);
    expect(summaryOf(spec, "/sumDenied", "post")).toBe(XERO_SUMMARY);
    expect(summaryOf(spec, "/both", "post")).toBe(XERO_SUMMARY);
  });
});

describe("annotateSpecWithSurfaceReview — the five states", () => {
  const out = annotateSpecWithSurfaceReview(makeSpec(), review);

  it("keeps the upstream description and appends behind a greppable marker", () => {
    const d = descOf(out, "/denied", "post");
    expect(d.startsWith(GOOGLE_TEXT)).toBe(true);
    expect(d).toContain(SURFACE_REVIEW_MARKER);
  });

  it("1. deny → says it always fails", () => {
    expect(annotationOf(out, "/denied", "post")).toMatch(/denied/i);
    expect(annotationOf(out, "/denied", "post")).toMatch(/always fail/i);
  });

  it("1. deny → never leaks the reviewer-facing `reasoning` into client text", () => {
    expect(descOf(out, "/denied", "post")).not.toContain("reviewer-only prose");
  });

  it("2. allow with no inspector → no annotation at all", () => {
    expect(descOf(out, "/plain", "get")).toBe(GOOGLE_TEXT);
    expect(descOf(out, "/plain", "get")).not.toContain(SURFACE_REVIEW_MARKER);
  });

  it("3. allow + inspect → reads as available-but-conditional, NOT as a deny", () => {
    const a = annotationOf(out, "/inspected", "post");
    expect(a).toMatch(/allowed/i);
    // The user's constraint: a conditional refusal must never read like an
    // unconditional deny.
    expect(a).not.toMatch(/always fail/i);
    expect(a).toMatch(/inspected|checked/i);
    expect(a).toMatch(/may be refused/i);
    expect(a).toContain("NOTE-INSPECTED");
  });

  it("4. elicit with no inspector → approval, and says it fails where unsupported", () => {
    const a = annotationOf(out, "/elicited", "post");
    expect(a).toMatch(/approval/i);
    expect(a).toContain("Claude.ai");
    // The literal error the caller gets (elicit.ts).
    expect(a).toContain("requires user approval; outcome: unsupported");
    // No inspector on this entry → must not claim the request is inspected.
    expect(a).not.toMatch(/inspected/i);
  });

  it("5. elicit + inspect → inspector can refuse before approval is reached", () => {
    const a = annotationOf(out, "/elicitedInspected", "post");
    expect(a).toMatch(/inspected/i);
    expect(a).toMatch(/approval/i);
    expect(a).toContain("Claude.ai");
    expect(a).toContain("NOTE-BOTH");
  });

  it("unlisted operation → says it is not on the reviewed surface and fails", () => {
    const a = annotationOf(out, "/unlisted", "post");
    expect(a).toMatch(/not (on|in)/i);
    expect(a).toMatch(/always fail/i);
  });

  it("creates a description when the operation had none", () => {
    const d = descOf(out, "/nodesc", "post");
    expect(d.startsWith(SURFACE_REVIEW_MARKER.trimStart())).toBe(true);
  });

  it("a plain allow WITH a clientNote is still annotated (the note is the point)", () => {
    const a = annotationOf(out, "/noteOnly", "post");
    expect(a).toContain("NOTE-ONLY");
    // No inspector on this entry → must not claim the request is inspected,
    // and must not read as denied.
    expect(a).not.toMatch(/inspected/i);
    expect(a).not.toMatch(/always fail/i);
    expect(a).not.toMatch(/approval/i);
  });

  it("appends clientNote only when the entry has one", () => {
    const bare = annotateSpecWithSurfaceReview(makeSpec(), {
      "op.inspected": { decision: "allow", inspect },
    });
    expect(annotationOf(bare, "/inspected", "post")).toMatch(/may be refused/i);
    expect(annotationOf(bare, "/inspected", "post")).not.toContain("NOTE-INSPECTED");
  });
});

describe("annotateSpecWithSurfaceReview — the summary marker", () => {
  // 260 of Xero's 283 operations carry a `summary` and NO `description`. Search
  // code that reads `op.summary` (which codemode's own worked example does)
  // would never see a description-only annotation, so the ACCESS fact has to be
  // reachable from `summary` too — as a short pointer, not a second copy.
  const out = annotateSpecWithSurfaceReview(makeSpec(), review);

  it("keeps the upstream summary and appends behind a greppable marker", () => {
    const u = summaryOf(out, "/sumDenied", "post");
    expect(u.startsWith(XERO_SUMMARY)).toBe(true);
    expect(u).toContain(SURFACE_REVIEW_SUMMARY_MARKER);
  });

  it("still creates a full description for a summary-only operation", () => {
    // The pointer is useless without the text it points at.
    expect(descOf(out, "/sumInspected", "post")).toContain(SURFACE_REVIEW_MARKER);
    expect(annotationOf(out, "/sumInspected", "post")).toContain("NOTE-INSPECTED");
  });

  it("annotates an operation that has NEITHER field (4 such ops in Xero)", () => {
    expect(descOf(out, "/neither", "post")).toContain(SURFACE_REVIEW_MARKER);
    expect(annotationOf(out, "/neither", "post")).toMatch(/always fail/i);
    // No summary existed, so none is invented.
    expect(opOf(out, "/neither", "post").summary).toBeUndefined();
  });

  it("never invents a summary on a description-only operation (every Gmail op)", () => {
    for (const path of ["/denied", "/inspected", "/elicited", "/elicitedInspected", "/unlisted"]) {
      expect(opOf(out, path, "post").summary, path).toBeUndefined();
    }
  });

  it("1. deny → summary says denied", () => {
    expect(summaryMarkerOf(out, "/sumDenied", "post")).toMatch(/denied/i);
  });

  it("2. allow with no inspector → no summary marker at all", () => {
    expect(summaryOf(out, "/sumPlain", "get")).toBe(XERO_SUMMARY);
    expect(summaryOf(out, "/sumPlain", "get")).not.toContain(SURFACE_REVIEW_SUMMARY_MARKER);
  });

  it("3. allow + inspect → summary says conditional, NOT denied", () => {
    const m = summaryMarkerOf(out, "/sumInspected", "post");
    expect(m).toMatch(/conditional/i);
    expect(m).not.toMatch(/denied|unavailable/i);
  });

  it("4. elicit → summary says approval required", () => {
    expect(summaryMarkerOf(out, "/sumElicited", "post")).toMatch(/approval/i);
  });

  it("5. elicit + inspect → summary says both conditional and approval", () => {
    const m = summaryMarkerOf(out, "/sumElicitedInspected", "post");
    expect(m).toMatch(/conditional/i);
    expect(m).toMatch(/approval/i);
  });

  it("a plain allow with a clientNote gets a neutral summary label", () => {
    const m = summaryMarkerOf(out, "/sumNoteOnly", "post");
    expect(m).toMatch(/note/i);
    // Nothing is conditional, denied or approval-gated here — the label must
    // not imply any of those.
    expect(m).not.toMatch(/conditional|denied|approval|unavailable/i);
  });

  it("unlisted → summary says unavailable", () => {
    expect(summaryMarkerOf(out, "/sumUnlisted", "post")).toMatch(/unavailable/i);
  });

  it("every summary marker is a bare label — no prose, no cross-reference", () => {
    for (const [path, method] of [
      ["/sumDenied", "post"],
      ["/sumInspected", "post"],
      ["/sumElicited", "post"],
      ["/sumElicitedInspected", "post"],
      ["/sumUnlisted", "post"],
      ["/sumNoteOnly", "post"],
    ] as const) {
      const m = summaryMarkerOf(out, path, method);
      // Budget re-derived from the marker set itself: the longest is the
      // two-condition elicit+inspect label `[ACCESS: conditional + approval]`
      // at 32 chars, so 35 leaves room for a wording tweak without letting
      // prose back in. Every char here is multiplied by the number of ops a
      // search returns and counts against codemode's 24,000-char response cap
      // (MAX_TOKENS 6e3 × CHARS_PER_TOKEN 4), so this directly costs discovery
      // breadth on the `{method, path, summary}` projection.
      expect(m.length, `${path} marker length`).toBeLessThanOrEqual(35);
      // "see description" told the model to look at a field it already has in
      // the same object — ~2,100 wasted chars across Xero's 119 markers.
      expect(m, path).not.toMatch(/see description/i);
    }
  });

  it("never duplicates the full ACCESS text into the summary", () => {
    for (const [path, method] of [
      ["/sumInspected", "post"],
      ["/sumElicitedInspected", "post"],
    ] as const) {
      expect(summaryOf(out, path, method), path).not.toContain("NOTE-INSPECTED");
      expect(summaryOf(out, path, method), path).not.toContain("NOTE-BOTH");
      expect(summaryOf(out, path, method).length, path).toBeLessThan(
        descOf(out, path, method).length,
      );
    }
  });

  it("annotates BOTH fields when the operation has both (optical, 19 Xero ops)", () => {
    expect(descOf(out, "/both", "post").startsWith(GOOGLE_TEXT)).toBe(true);
    expect(annotationOf(out, "/both", "post")).toContain("NOTE-BOTH-FIELDS");
    expect(summaryOf(out, "/both", "post").startsWith(XERO_SUMMARY)).toBe(true);
    expect(summaryMarkerOf(out, "/both", "post")).toMatch(/conditional/i);
  });
});

// MUST-FIX B (regression): ELICIT_TAIL fired only for STATICALLY-elicit entries.
// An `allow` + `inspect` entry can escalate to elicit at call time
// (decision = mostRestrictive(static, inspected)), and its note says things like
// "more than 25 attendees needs interactive approval" — with nothing saying that
// approval CANNOT be given on Claude.ai and the call simply fails. HEAD's
// executeHint carried that caveat; the refactor dropped it. This is the exact
// failure the feature exists to prevent: the model promises the user a
// confirmation prompt that never appears.
describe("annotateSpecWithSurfaceReview — approval always carries the caveat", () => {
  const UNSUPPORTED = /clients without MCP elicitation support/i;

  it("an inspector-escalated approval gets the unsupported-client caveat", () => {
    const out = annotateSpecWithSurfaceReview(makeSpec(), {
      "op.inspected": {
        decision: "allow",
        inspect,
        clientNote: "More than 25 attendees needs interactive approval instead.",
      },
    });
    const a = annotationOf(out, "/inspected", "post");
    expect(a).toMatch(/approval/i);
    expect(a, "escalated approval must not promise a prompt it cannot show").toMatch(UNSUPPORTED);
    expect(a).toContain("requires user approval; outcome: unsupported");
  });

  it("an inspected entry whose note never mentions approval stays terse", () => {
    const out = annotateSpecWithSurfaceReview(makeSpec(), {
      "op.inspected": { decision: "allow", inspect, clientNote: "Recipients must be allowlisted." },
    });
    const a = annotationOf(out, "/inspected", "post");
    expect(a).not.toMatch(UNSUPPORTED);
  });

  it("ANY rendered description mentioning approval also carries the caveat", () => {
    // The general invariant, over every state at once.
    const out = annotateSpecWithSurfaceReview(makeSpec(), {
      ...review,
      "op.inspected": { decision: "allow", inspect, clientNote: "past 25 this needs approval" },
    });
    for (const [path, method] of [
      ["/denied", "post"], ["/plain", "get"], ["/inspected", "post"],
      ["/elicited", "post"], ["/elicitedInspected", "post"], ["/unlisted", "post"],
    ] as const) {
      const d = descOf(out, path, method);
      if (/approval/i.test(d)) {
        expect(d, `${path} mentions approval without the caveat`).toMatch(UNSUPPORTED);
      }
    }
  });
});

describe("annotateSpecWithSurfaceReview — idempotence", () => {
  it("annotating twice does not double-append", () => {
    const once = annotateSpecWithSurfaceReview(makeSpec(), review);
    const twice = annotateSpecWithSurfaceReview(once, review);
    for (const [path, method] of [
      ["/denied", "post"],
      ["/inspected", "post"],
      ["/elicited", "post"],
      ["/elicitedInspected", "post"],
      ["/unlisted", "post"],
      ["/nodesc", "post"],
      ["/sumDenied", "post"],
      ["/sumInspected", "post"],
      ["/sumElicitedInspected", "post"],
      ["/sumUnlisted", "post"],
      ["/both", "post"],
      ["/neither", "post"],
    ] as const) {
      expect(descOf(twice, path, method)).toBe(descOf(once, path, method));
      const occurrences = descOf(twice, path, method).split(SURFACE_REVIEW_MARKER).length - 1;
      expect(occurrences, `${path} ${method}`).toBe(1);
    }
  });

  it("annotating twice does not double-append to the SUMMARY either", () => {
    const once = annotateSpecWithSurfaceReview(makeSpec(), review);
    const twice = annotateSpecWithSurfaceReview(once, review);
    for (const [path, method] of [
      ["/sumDenied", "post"],
      ["/sumInspected", "post"],
      ["/sumElicited", "post"],
      ["/sumElicitedInspected", "post"],
      ["/sumUnlisted", "post"],
      ["/both", "post"],
      ["/nodesc", "post"],
    ] as const) {
      expect(summaryOf(twice, path, method), path).toBe(summaryOf(once, path, method));
      const occurrences =
        summaryOf(twice, path, method).split(SURFACE_REVIEW_SUMMARY_MARKER).length - 1;
      expect(occurrences, `${path} ${method} summary`).toBe(1);
    }
  });

  it("re-annotating with a changed review replaces the old annotation", () => {
    const once = annotateSpecWithSurfaceReview(makeSpec(), review);
    const flipped = annotateSpecWithSurfaceReview(once, {
      ...review,
      "op.denied": { decision: "allow", category: "standard_read" },
    });
    // Now allow-with-no-inspector → annotation gone, upstream text intact.
    expect(descOf(flipped, "/denied", "post")).toBe(GOOGLE_TEXT);
  });

  it("replaces an OLD long-form marker rather than stacking a new one", () => {
    // Specs are re-annotated at runtime on every boot, so a spec carrying the
    // previous `[ACCESS: denied — see description]` form must converge on the
    // short form, not accumulate both.
    const stale = {
      paths: {
        "/x": {
          post: {
            operationId: "op.denied",
            summary: `${XERO_SUMMARY} [ACCESS: denied — see description]`,
            description: `${GOOGLE_TEXT}\n\nACCESS: denied by this server's surface review, so calls always fail.`,
          },
        },
      },
    };
    const out2 = annotateSpecWithSurfaceReview(stale, review);
    const u = summaryOf(out2, "/x", "post");
    expect(u.split(SURFACE_REVIEW_SUMMARY_MARKER).length - 1).toBe(1);
    expect(u).not.toMatch(/see description/i);
    expect(u).toBe(`${XERO_SUMMARY} [ACCESS: denied]`);
    // ...and the description likewise converges rather than doubling.
    expect(descOf(out2, "/x", "post").split(SURFACE_REVIEW_MARKER).length - 1).toBe(1);
    expect(descOf(out2, "/x", "post").startsWith(GOOGLE_TEXT)).toBe(true);
  });

  it("flipping a decision REPLACES the summary marker rather than stacking one", () => {
    const once = annotateSpecWithSurfaceReview(makeSpec(), review);
    // deny → allow+inspect: the marker must change, not accumulate.
    const flipped = annotateSpecWithSurfaceReview(once, {
      ...review,
      "sum.denied": { decision: "allow", inspect },
    });
    const m = summaryMarkerOf(flipped, "/sumDenied", "post");
    expect(m).toMatch(/conditional/i);
    expect(m).not.toMatch(/denied/i);
    expect(summaryOf(flipped, "/sumDenied", "post").split(SURFACE_REVIEW_SUMMARY_MARKER).length - 1).toBe(1);
    // ...and flipping to a plain allow removes it entirely, restoring the original.
    const cleared = annotateSpecWithSurfaceReview(once, {
      ...review,
      "sum.denied": { decision: "allow", category: "standard_read" },
    });
    expect(summaryOf(cleared, "/sumDenied", "post")).toBe(XERO_SUMMARY);
  });
});

describe("annotateSpecWithSurfaceReview — spec shapes", () => {
  it("ignores path-item members that are not operations", () => {
    const spec = {
      paths: {
        "/x": {
          parameters: [{ name: "id", in: "path" }],
          get: { operationId: "op.plain", description: GOOGLE_TEXT },
        },
      },
    };
    const out = annotateSpecWithSurfaceReview(spec, review);
    expect(out.paths["/x"]!.parameters).toEqual(spec.paths["/x"]!.parameters);
  });

  it("THROWS on a $ref'd path item rather than silently skipping it", () => {
    // A skipped operation gets no annotation, which reads as state 2 ("plainly
    // available") whatever its real decision — the annotation layer failing
    // OPEN, in the code whose job is making denies visible. No bundled spec
    // uses $ref path items today; if one ever does, fail loudly.
    const withRef = { paths: { "/x": { $ref: "#/components/pathItems/Shared" } } };
    expect(() => annotateSpecWithSurfaceReview(withRef, review)).toThrow(/\$ref/i);
  });

  it("THROWS when an upstream description already contains the marker", () => {
    // Otherwise stripAnnotation() cuts real upstream prose on the FIRST pass:
    // "Grants ACCESS: read-only…" would annotate down to "Grants". Verified
    // absent from every bundled spec by the grep test in this file.
    const collides = {
      paths: {
        "/x": { get: { operationId: "op.plain", description: "Grants ACCESS: read-only rights." } },
      },
    };
    expect(() => annotateSpecWithSurfaceReview(collides, review)).toThrow(/marker/i);
  });

  it("THROWS when an upstream summary already contains the marker", () => {
    // The summary marker is anchored to end-of-string, so an upstream summary
    // that genuinely ends in its own bracketed token — "Legacy endpoint
    // [ACCESS: LEGACY]" — sits exactly where ours would and would be stripped
    // as if it were a stale annotation. Ours is told apart by its LABEL, so an
    // unknown label is upstream prose and must fail loudly rather than vanish.
    const collides = {
      paths: {
        "/x": {
          get: {
            operationId: "op.plain",
            summary: "Legacy endpoint [ACCESS: LEGACY]",
          },
        },
      },
    };
    expect(() => annotateSpecWithSurfaceReview(collides, review)).toThrow(/marker/i);

    // Mid-string is caught too, matching the description guard: the marker is
    // reserved outright, not merely reserved in the position we happen to use.
    const midString = {
      paths: {
        "/x": {
          get: { operationId: "op.plain", summary: "Legacy [ACCESS: LEGACY] endpoint" },
        },
      },
    };
    expect(() => annotateSpecWithSurfaceReview(midString, review)).toThrow(/marker/i);
  });

  it("tolerates a spec with no paths", () => {
    // Not an object literal at the call site: TypeScript's excess-property check
    // would reject the extra `info` key, which the generic happily accepts.
    const noPaths: AnnotatableSpec & { info: { title: string } } = { info: { title: "t" } };
    expect(() => annotateSpecWithSurfaceReview(noPaths, review)).not.toThrow();
    expect(annotateSpecWithSurfaceReview(noPaths, review)).toBe(noPaths);
  });
});
