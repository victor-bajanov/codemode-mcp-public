// Semantic verification of `clientNote` prose against the REAL inspectors.
//
// The previous version of these checks matched vocabulary (`toContain("25")`,
// `toMatch(/approval/i)`) and was shown to pass on notes rewritten to state the
// exact OPPOSITE of their inspector — including "unset means no restriction,
// every send allowed" when an unset allowlist actually denies every send. A
// note that lies is worse than no note: the model plans around it.
//
// So every claim here is checked by CONSTRUCTING the request the note
// describes, running the actual `inspect` function from the surface review, and
// asserting the note's claim matches the decision that comes back. Where the
// note names a value set ("Status must be DRAFT or SUBMITTED"), the set is
// PARSED out of the note and compared against what the inspector really
// accepts, so adding a value to the prose fails unless the inspector agrees.

import { describe, it, expect } from "vitest";
import type { InspectRequest, InspectResult, SurfaceReviewEntry } from "@local/shared";
import { surfaceReview } from "../surface-review";
import { MASS_INVITE_THRESHOLD } from "../inspectors/calendar-attendees";
import { MASS_SEND_THRESHOLD } from "../inspectors/outbound";
import { inspectSendAsCreate } from "../inspectors/sendas";

const ALLOWED = "ok@allowed.test";
const OFF_LIST = "stranger@elsewhere.test";
const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@allowed.test" };

/** Run the real inspector wired to this operation in the surface review. */
function run(opId: string, req: InspectRequest, env?: Record<string, unknown>): InspectResult {
  const entry: SurfaceReviewEntry | undefined = surfaceReview[opId];
  if (!entry?.inspect) throw new Error(`${opId} has no inspector`);
  return entry.inspect(req, env);
}
const noteOf = (opId: string): string => surfaceReview[opId]?.clientNote ?? "";

/** A Gmail message body addressed to `to`. */
const messageTo = (...to: string[]): InspectRequest => ({
  body: { payload: { headers: [{ name: "To", value: to.join(", ") }] } },
});
/** A Calendar event body with `n` distinct allowlisted attendees. */
const eventWithAttendees = (n: number): InspectRequest => ({
  body: { attendees: Array.from({ length: n }, (_, i) => ({ email: `a${i}@allowed.test` })) },
});

describe("calendar attendee note states what inspectEventAttendees does", () => {
  /** Every op wired to inspectEventAttendees. */
  const OPS = [
    "calendar.events.insert",
    "calendar.events.update",
    "calendar.events.patch",
    "calendar.events.import",
  ];
  /** The statically-`allow` ones. events.import is statically `elicit`, so
   *  clauses implying "under the threshold it just works" are FALSE for it and
   *  it carries a variant note (see the events.import describe block). */
  const WRITE_OPS = OPS.filter((o) => o !== "calendar.events.import");

  it("off-allowlist attendee is a HARD DENY, and the note says deny — not approval", () => {
    for (const op of OPS) {
      const result = run(op, { body: { attendees: [{ email: OFF_LIST }] } }, ENV);
      // The behaviour.
      expect(result.decision, `${op} inspector`).toBe("deny");
      // The note must claim exactly that. This is the deny/elicit conflation the
      // whole feature exists to prevent, one layer down.
      expect(noteOf(op), `${op} note`).toMatch(/denies the whole write outright/i);
      expect(noteOf(op), `${op} note`).toMatch(/hard deny, not an approval prompt/i);
    }
  });

  it("an unset allowlist DENIES every attendee, and the note says so (fail-closed)", () => {
    for (const op of OPS) {
      // No env at all, and an env whose var is missing: both → empty list.
      for (const env of [undefined, {}] as const) {
        expect(run(op, { body: { attendees: [{ email: ALLOWED }] } }, env).decision, op).toBe("deny");
      }
      expect(noteOf(op), `${op} note`).toMatch(/unset means an empty list/i);
      expect(noteOf(op), `${op} note`).toMatch(/any attendee at all is denied/i);
      // Must NOT claim the permissive opposite.
      expect(noteOf(op), `${op} note`).not.toMatch(/no restriction|every (send|attendee|write) allowed/i);
    }
  });

  it("the threshold in the note is the inspector's threshold, digit for digit", () => {
    for (const op of WRITE_OPS) {
      // Literal template, so "More than 250 attendees" cannot satisfy a check
      // for 25 by substring — the previous failure mode.
      expect(noteOf(op), `${op} note`).toContain(`More than ${MASS_INVITE_THRESHOLD} attendees`);
      const parsed = /More than (\d+) attendees/.exec(noteOf(op));
      expect(parsed?.[1], `${op} threshold`).toBe(String(MASS_INVITE_THRESHOLD));
    }
  });

  it("the threshold behaves as the note describes: at it allow, past it elicit", () => {
    for (const op of OPS) {
      expect(run(op, eventWithAttendees(MASS_INVITE_THRESHOLD), ENV).decision, `${op} at`).toBe("allow");
      expect(run(op, eventWithAttendees(MASS_INVITE_THRESHOLD + 1), ENV).decision, `${op} past`).toBe("elicit");
    }
  });

  it("resource attendees are exempt, as the note claims", () => {
    for (const op of OPS) {
      const result = run(op, { body: { attendees: [{ email: OFF_LIST, resource: true }] } }, ENV);
      expect(result.decision, `${op} resource attendee`).toBe("allow");
      expect(noteOf(op), `${op} note`).toMatch(/resource.*exempt/is);
    }
  });

  it("a body with no attendees is unaffected, as the note claims", () => {
    for (const op of OPS) {
      // Inspector-level truth holds for all four...
      expect(run(op, { body: { summary: "no attendees here" } }, ENV).decision, op).toBe("allow");
    }
    // ...but only the statically-allow ops may SAY so: for events.import the
    // static elicit still stops the call, so "unaffected" would be a lie.
    for (const op of WRITE_OPS) {
      expect(noteOf(op), `${op} note`).toMatch(/no `?attendees`? array is unaffected/i);
    }
  });
});

describe("outbound mail notes state what inspectOutboundMessage does", () => {
  const OP = "gmail.users.messages.send";

  it("one off-allowlist recipient denies the send, and the note says denies", () => {
    expect(run(OP, messageTo(ALLOWED, OFF_LIST), ENV).decision).toBe("deny");
    expect(noteOf(OP)).toMatch(/one off-allowlist address denies the send/i);
  });

  it("an unset allowlist denies EVERY send, and the note says so (fail-closed)", () => {
    for (const env of [undefined, {}] as const) {
      expect(run(OP, messageTo(ALLOWED), env).decision).toBe("deny");
    }
    expect(noteOf(OP)).toMatch(/unset means an empty\s+list, so every send is denied/i);
    expect(noteOf(OP)).not.toMatch(/no restriction|every send (is )?allowed/i);
  });

  it("no readable recipients is a deny, as the note claims", () => {
    expect(run(OP, { body: { payload: { headers: [] } } }, ENV).decision).toBe("deny");
    expect(noteOf(OP)).toMatch(/no readable recipients is denied/i);
  });

  it("the mass-send threshold matches the inspector, digit for digit", () => {
    expect(noteOf(OP)).toContain(`More than ${MASS_SEND_THRESHOLD} recipients`);
    const many = Array.from({ length: MASS_SEND_THRESHOLD + 1 }, (_, i) => `r${i}@allowed.test`);
    expect(run(OP, messageTo(...many), ENV).decision).toBe("elicit");
    const atLimit = Array.from({ length: MASS_SEND_THRESHOLD }, (_, i) => `r${i}@allowed.test`);
    expect(run(OP, messageTo(...atLimit), ENV).decision).toBe("allow");
  });
});

describe("drafts.send note states what inspectDraftSend does", () => {
  const OP = "gmail.users.drafts.send";

  it("a bare send-by-id is denied, and the note says always denied", () => {
    expect(run(OP, { body: { id: "draft-1" } }, ENV).decision).toBe("deny");
    expect(noteOf(OP)).toMatch(/sending by id alone is always denied/i);
  });

  it("the update-and-send shape the note prescribes actually passes", () => {
    const result = run(
      OP,
      { body: { id: "draft-1", message: { payload: { headers: [{ name: "To", value: ALLOWED }] } } } },
      ENV,
    );
    expect(result.decision).toBe("allow");
    expect(noteOf(OP)).toMatch(/\{ ?id, message/);
  });

  it("update-and-send is still allowlist-gated, as the note claims", () => {
    const result = run(
      OP,
      { body: { id: "d", message: { payload: { headers: [{ name: "To", value: OFF_LIST }] } } } },
      ENV,
    );
    expect(result.decision).toBe("deny");
    expect(noteOf(OP)).toMatch(/unset means every send is denied/i);
  });
});

describe("filters.create note states what inspectFilterCreate does", () => {
  const OP = "gmail.users.settings.filters.create";

  it("each action branch behaves as the note claims", () => {
    expect(run(OP, { body: { action: { delete: true } } }).decision).toBe("deny");
    expect(run(OP, { body: { action: { forward: "x@y.test" } } }).decision).toBe("deny");
    expect(run(OP, { body: { action: { forwardingEmail: "x@y.test" } } }).decision).toBe("deny");
    expect(run(OP, { body: { action: { removeLabelIds: ["INBOX"] } } }).decision).toBe("elicit");
    expect(run(OP, { body: { action: { addLabelIds: ["Label_1"] } } }).decision).toBe("allow");
    expect(run(OP, { body: {} }).decision).toBe("deny");

    const note = noteOf(OP);
    expect(note).toMatch(/`?delete: true`? is denied/i);
    expect(note).toMatch(/forward.*denied/i);
    expect(note).toMatch(/INBOX.*needs interactive approval/is);
    expect(note).toMatch(/no `?action`? object is denied/i);
    // The one branch that passes must not be described as blocked.
    expect(note).toMatch(/label-only actions pass/i);
  });
});

// sendAs.create is now a static deny, so there is no note to verify and no
// wired inspector to run. What still needs pinning is that the retained
// inspector's behaviour is unchanged — it is kept as a reference implementation
// and for cheap re-enablement, and is exercised directly by
// surface-review-sendas.test.ts / surface-review-sendas-smtpmsa.test.ts.
describe("sendAs.create is denied, so the inspector is unwired but intact", () => {
  const OP = "gmail.users.settings.sendAs.create";

  it("the entry has no inspector to describe", () => {
    expect(surfaceReview[OP]?.decision).toBe("deny");
    expect(surfaceReview[OP]?.inspect).toBeUndefined();
    expect(() => run(OP, { body: {} }, ENV)).toThrow(/no inspector/);
  });

  it("the retained inspector still enforces what it always did", () => {
    // Imported directly, not through the surface review — this is the contract
    // an operator relies on when re-wiring the entry.
    expect(inspectSendAsCreate({ body: { sendAsEmail: OFF_LIST } }, ENV).decision).toBe("deny");
    expect(inspectSendAsCreate({ body: { sendAsEmail: ALLOWED } }, ENV).decision).toBe("allow");
    expect(inspectSendAsCreate({ body: {} }, ENV).decision).toBe("deny");
    // Empty-by-default host allowlist → any smtpMsa denies.
    expect(
      inspectSendAsCreate({ body: { sendAsEmail: ALLOWED, smtpMsa: { host: "smtp.any.test" } } }, ENV).decision,
    ).toBe("deny");
  });
});

// MUST-FIX C: events.import is STATICALLY elicit, so it always needs approval.
// The shared attendee note's "needs interactive approval instead" and "a body
// with no attendees is unaffected" both imply the small/no-attendee case just
// works there. It does not.
describe("events.import does not contradict its own generated prefix", () => {
  const IMPORT = "calendar.events.import";

  it("is statically elicit, so nothing about it 'just works'", () => {
    expect(surfaceReview[IMPORT]?.decision).toBe("elicit");
  });

  it("its note does not claim approval is only needed past the threshold", () => {
    expect(noteOf(IMPORT)).not.toMatch(/needs interactive approval instead/i);
  });

  it("its note does not claim an attendee-less body is unaffected", () => {
    expect(noteOf(IMPORT)).not.toMatch(/unaffected/i);
  });

  it("the non-elicit siblings keep those clauses, which are true for them", () => {
    for (const op of ["calendar.events.insert", "calendar.events.update", "calendar.events.patch"]) {
      expect(surfaceReview[op]?.decision, op).toBe("allow");
      expect(noteOf(op), op).toMatch(/needs interactive approval instead/i);
      expect(noteOf(op), op).toMatch(/unaffected/i);
    }
  });
});
