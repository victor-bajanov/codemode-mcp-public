// STRUCTURAL invariants for `clientNote`: which entries must have one, that it
// reaches the annotated spec, and that reviewer-facing `reasoning` never does.
//
// This file deliberately does NOT verify what a note SAYS. String matching was
// shown to accept notes stating the exact opposite of their inspector (e.g.
// `toContain("25")` is satisfied by "250"), so every claim about behaviour is
// verified in client-note-semantics.test.ts by running the real inspector
// against the request the note describes. Do not add vocabulary assertions here.

import { describe, it, expect } from "vitest";
import { annotateSpecWithSurfaceReview, SURFACE_REVIEW_MARKER } from "@local/scaffold";
import { gmailProvider } from "../index";
import { surfaceReview } from "../surface-review";

const inspected = Object.entries(surfaceReview).filter(([, e]) => e.inspect !== undefined);

/** Required scopes per operationId, from the bundled spec. */
const requiredScopes = new Map<string, string[]>();
for (const item of Object.values(
  (gmailProvider.spec as unknown as { paths?: Record<string, Record<string, unknown>> }).paths ?? {},
)) {
  for (const op of Object.values(item)) {
    const o = op as { operationId?: unknown; "x-google-scopes"?: unknown };
    if (typeof o?.operationId === "string") {
      requiredScopes.set(o.operationId, (o["x-google-scopes"] as string[]) ?? []);
    }
  }
}

/** allow/elicit entries whose required scopes are ALL ungranted → 403 upstream
 *  whatever the surface review says. Computed, not hand-listed, so a scope
 *  change surfaces as a failure here rather than rotting silently. */
const granted = new Set(gmailProvider.oauth.scopes);
const scopeUnreachable = Object.entries(surfaceReview)
  .filter(([, e]) => e.decision !== "deny")
  .filter(([id]) => {
    const need = requiredScopes.get(id) ?? [];
    return need.length > 0 && !need.some((s) => granted.has(s));
  })
  .map(([id]) => id);

describe("gmail surface review — clientNote on every inspected entry", () => {
  it("has an inspected surface to describe at all", () => {
    expect(inspected.length).toBeGreaterThan(0);
  });

  it("every entry with an inspector carries a clientNote", () => {
    const missing = inspected.filter(([, e]) => !e.clientNote?.trim()).map(([id]) => id);
    expect(missing).toEqual([]);
  });

  it("an un-inspected entry may carry a note ONLY for a non-inspector condition", () => {
    // `clientNote` covers any request-time condition deciding whether the call
    // succeeds, not just inspectors — a scope-unreachable operation is the
    // canonical case and MUST be permitted here, since that is the state the
    // field was widened for. Anything else appearing is unexplained.
    const stray = Object.entries(surfaceReview)
      .filter(([, e]) => e.inspect === undefined && e.clientNote !== undefined)
      .map(([id]) => id)
      .filter((id) => !scopeUnreachable.includes(id));
    expect(stray).toEqual([]);
  });
});

// An operation the surface review allows but the granted OAuth scopes cannot
// reach will 403 no matter what the inspector decides. Such an operation should
// not be `allow` at all — the one that existed (sendAs.create) is now denied
// outright, which is why this audit finds nothing. The audit KEEPS RUNNING as
// the guard: if a future scope change or spec regeneration strands another
// allow/elicit operation, it fails here instead of shipping a dead endpoint.
describe("gmail surface review — operations unreachable with the granted scopes", () => {
  it("every gmail operation declares its scopes, so this audit is sound", () => {
    const missing = [...requiredScopes].filter(([, v]) => v.length === 0).map(([id]) => id);
    expect(missing).toEqual([]);
  });

  it("finds no scope gap — the only one is now denied outright", () => {
    expect(scopeUnreachable).toEqual([]);
  });

  it("sendAs.create is denied, matching its already-denied siblings", () => {
    const entry = surfaceReview["gmail.users.settings.sendAs.create"];
    expect(entry?.decision).toBe("deny");
    expect(entry?.category).toBe("capability_escalation");
    // A static deny short-circuits before `inspect` is read, so leaving an
    // inspector or a client note on the entry would describe a code path that
    // can never run.
    expect(entry?.inspect, "denied entry must not carry an inspector").toBeUndefined();
    expect(entry?.clientNote, "the deny annotation already says calls always fail").toBeUndefined();
    for (const sibling of [
      "gmail.users.settings.sendAs.update",
      "gmail.users.settings.sendAs.patch",
      "gmail.users.settings.sendAs.delete",
    ]) {
      expect(surfaceReview[sibling]?.decision, sibling).toBe("deny");
    }
  });

  it("keeps the re-enablement path documented in `reasoning`", () => {
    // The inspector and its tests are retained precisely so restoring this
    // capability stays cheap; a future operator needs to know how.
    const reasoning = surfaceReview["gmail.users.settings.sendAs.create"]?.reasoning ?? "";
    expect(reasoning).toContain("gmail.settings.sharing");
    expect(reasoning).toMatch(/oauth\.scopes/);
    expect(reasoning, "must say the inspector has to be re-wired too").toMatch(/inspectSendAsCreate/);
  });

  it("each unreachable operation says so in its clientNote, naming the scope", () => {
    for (const id of scopeUnreachable) {
      const note = surfaceReview[id]?.clientNote ?? "";
      expect(note, id).toMatch(/scope/i);
      const need = requiredScopes.get(id) ?? [];
      expect(need.some((s) => note.includes(s)), `${id} names no required scope`).toBe(true);
    }
  });
});

describe("gmail clientNote reaches the annotated spec", () => {
  const annotated = annotateSpecWithSurfaceReview(
    gmailProvider.spec as unknown as { paths?: Record<string, Record<string, unknown>> },
    surfaceReview,
  );

  const descriptionOf = (operationId: string): string => {
    for (const item of Object.values(annotated.paths ?? {})) {
      for (const op of Object.values(item)) {
        const o = op as { operationId?: unknown; description?: unknown };
        if (o?.operationId === operationId) return (o.description as string) ?? "";
      }
    }
    throw new Error(`no operation ${operationId}`);
  };

  it("carries each inspected entry's note onto its operation description", () => {
    for (const [id, entry] of inspected) {
      const d = descriptionOf(id);
      expect(d, id).toContain(SURFACE_REVIEW_MARKER);
      expect(d, id).toContain(entry.clientNote);
    }
  });

  it("EVERY entry with a clientNote has it reach the spec, inspector or not", () => {
    // A note that never reaches a description is pure cost: it looks like the
    // surface is documented while the client sees nothing.
    const unreached = Object.entries(surfaceReview)
      .filter(([, e]) => e.clientNote)
      .filter(([id, e]) => !descriptionOf(id).includes(e.clientNote as string))
      .map(([id]) => id);
    expect(unreached).toEqual([]);
  });

  it("never surfaces the reviewer-facing `reasoning` of any entry", () => {
    const whole = JSON.stringify(annotated);
    for (const [id, entry] of Object.entries(surfaceReview)) {
      if (!entry.reasoning) continue;
      expect(whole.includes(entry.reasoning), `${id} reasoning leaked`).toBe(false);
    }
  });
});
