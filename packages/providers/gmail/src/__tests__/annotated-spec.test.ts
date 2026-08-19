// Destination for the per-operation contracts that used to be pinned against
// the global executeHint (see execute-hint-calendar.test.ts). Those claims are
// no longer prose in a hint — they are generated onto each operation's own
// description, so they are asserted here, against the spec a client actually
// reads through `search`.
//
// Moved here from execute-hint-calendar.test.ts:
//   - every allowed / gated / denied Calendar operation is accounted for
//   - each operation is filed under a claim whose decision actually matches
//   - unlisted operations are described as denied
//   - an explicitly-denied watch channel is not swept into the unlisted bucket
//   - elicit operations say they FAIL on clients without elicitation (Claude.ai)
//     rather than promising a prompt
//   - events.import is attendee-inspected before any approval is reached

import { describe, it, expect } from "vitest";
import { annotateSpecWithSurfaceReview, SURFACE_REVIEW_MARKER } from "@local/scaffold";
import { gmailProvider } from "../index";
import { surfaceReview } from "../surface-review";

const annotated = annotateSpecWithSurfaceReview(
  gmailProvider.spec as unknown as { paths?: Record<string, Record<string, unknown>> },
  surfaceReview,
);

/** operationId → description, over the annotated spec. */
const descriptions = new Map<string, string>();
for (const item of Object.values(annotated.paths ?? {})) {
  for (const op of Object.values(item)) {
    const o = op as { operationId?: unknown; description?: unknown };
    if (typeof o?.operationId === "string") {
      descriptions.set(o.operationId, typeof o.description === "string" ? o.description : "");
    }
  }
}

const describeOp = (id: string): string => {
  const d = descriptions.get(id);
  if (d === undefined) throw new Error(`no operation ${id} in spec`);
  return d;
};
/** The generated block only, without the upstream text. */
const annotationOf = (id: string): string => {
  const d = describeOp(id);
  const i = d.indexOf(SURFACE_REVIEW_MARKER);
  return i < 0 ? "" : d.slice(i);
};

const idsWithDecision = (decision: string): string[] =>
  Object.keys(surfaceReview).filter((id) => surfaceReview[id]?.decision === decision);

// Phrases that promise the user a dialog. Elicitation only renders on clients
// that advertise the capability; on everything else (Claude.ai included)
// elicit.ts throws ToolError("...requires user approval; outcome: unsupported")
// without showing anything, so text that promises a prompt is a lie on the
// primary client.
const PROMPT_PROMISES =
  /(the user is asked|asks the user|prompts? the user|you will be prompted|user is prompted|confirmation dialog)/i;

describe("gmail annotated spec — every operation accounts for itself", () => {
  it("covers the whole surface review, Gmail and Calendar alike", () => {
    const missing = Object.keys(surfaceReview).filter((id) => !descriptions.has(id));
    expect(missing).toEqual([]);
    expect(idsWithDecision("allow").length).toBeGreaterThan(0);
    expect(idsWithDecision("elicit").length).toBeGreaterThan(0);
    expect(idsWithDecision("deny").length).toBeGreaterThan(0);
  });

  it("every deny says it always fails", () => {
    for (const id of idsWithDecision("deny")) {
      expect(annotationOf(id), id).toMatch(/denied by this server's surface review/i);
      expect(annotationOf(id), id).toMatch(/always fail/i);
    }
  });

  it("every elicit says it fails where elicitation is unsupported, and never promises a prompt", () => {
    for (const id of idsWithDecision("elicit")) {
      const a = annotationOf(id);
      expect(a, id).toMatch(/approval/i);
      expect(a, id).toContain("Claude.ai");
      expect(a, id).toContain("requires user approval; outcome: unsupported");
      expect(a, id).not.toMatch(PROMPT_PROMISES);
    }
  });

  it("every inspected allow reads as conditional, never as an outright deny", () => {
    const inspectedAllows = Object.keys(surfaceReview).filter(
      (id) => surfaceReview[id]?.decision === "allow" && surfaceReview[id]?.inspect,
    );
    expect(inspectedAllows.length).toBeGreaterThan(0);
    for (const id of inspectedAllows) {
      const a = annotationOf(id);
      expect(a, id).toMatch(/allowed, but/i);
      expect(a, id).not.toMatch(/always fail/i);
    }
  });

  it("plain allows carry no annotation at all (the cost-free default)", () => {
    const plain = Object.keys(surfaceReview).filter(
      (id) => surfaceReview[id]?.decision === "allow" && !surfaceReview[id]?.inspect,
    );
    expect(plain.length).toBeGreaterThan(0);
    for (const id of plain) {
      expect(describeOp(id), id).not.toContain(SURFACE_REVIEW_MARKER);
    }
  });

  it("operations absent from the surface review are described as unavailable", () => {
    const unlisted = [...descriptions.keys()].filter((id) => !surfaceReview[id]);
    expect(unlisted.length).toBeGreaterThan(0);
    for (const id of unlisted) {
      expect(annotationOf(id), id).toMatch(/not on this server's reviewed surface/i);
      expect(annotationOf(id), id).toMatch(/always fail/i);
    }
  });

  it("does not sweep an explicitly-denied watch channel into the unlisted bucket", () => {
    // calendar.acl.watch is a named deny entry, so it must carry the deny text
    // and NOT the "not on the reviewed surface" text.
    expect(surfaceReview["calendar.acl.watch"]?.decision).toBe("deny");
    expect(annotationOf("calendar.acl.watch")).toMatch(/denied by this server's surface review/i);
    expect(annotationOf("calendar.acl.watch")).not.toMatch(/not on this server's reviewed surface/i);
  });

  it("events.import says the attendee check runs BEFORE any approval", () => {
    expect(surfaceReview["calendar.events.import"]?.inspect).toBeDefined();
    const a = annotationOf("calendar.events.import");
    expect(a).toMatch(/inspected at call time/i);
    expect(a).toMatch(/before any approval is sought/i);
    expect(a).toMatch(/allowlist/i);
  });

  it("preserves Google's original description text ahead of the annotation", () => {
    const d = describeOp("gmail.users.messages.send");
    expect(d.startsWith("Sends the specified message")).toBe(true);
    expect(d).toContain(SURFACE_REVIEW_MARKER);
  });
});
