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
// Where an entry also has an `inspectUpstream` hook (events.update/patch), the
// claim is checked against the sync inspector AND the hook, combined the way
// the request handler combines them (most restrictive wins).

import { describe, it, expect } from "vitest";
import type { Decision, InspectRequest, InspectResult, SurfaceReviewEntry, UpstreamLookup } from "@local/shared";
import { surfaceReview } from "../surface-review";
import { MASS_INVITE_THRESHOLD } from "../inspectors/calendar-attendees";
import { MASS_SEND_THRESHOLD, MESSAGE_INPUT_KEYS } from "../inspectors/outbound";
import { inspectSendAsCreate } from "../inspectors/sendas";

const ALLOWED = "ok@allowed.test";
const OFF_LIST = "stranger@elsewhere.test";
const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@allowed.test" };
const CAL_ENV = { ...ENV, CALENDAR_WRITE_ALLOWLIST: "primary" };

/** Run the real inspector wired to this operation in the surface review. */
function run(opId: string, req: InspectRequest, env?: Record<string, unknown>): InspectResult {
  const entry: SurfaceReviewEntry | undefined = surfaceReview[opId];
  if (!entry?.inspect) throw new Error(`${opId} has no inspector`);
  return entry.inspect(req, env);
}
const noteOf = (opId: string): string => surfaceReview[opId]?.clientNote ?? "";

const RANK: Record<Decision, number> = { allow: 0, elicit: 1, deny: 2 };

/** The user's own event, no guests: what the hook reads unless told otherwise. */
const OWN_EVENT = { organizer: { email: "me@allowed.test", self: true }, summary: "Mine", attendees: [] };

/** The sync inspector, then (when it did not deny) the entry's upstream hook
 *  against a fake lookup answering `stored`: the request handler's pipeline. */
async function runFull(
  opId: string,
  req: InspectRequest,
  env: Record<string, unknown> | undefined,
  stored: unknown = OWN_EVENT,
): Promise<InspectResult> {
  const entry = surfaceReview[opId];
  const sync = run(opId, req, env);
  if (sync.decision === "deny" || entry?.inspectUpstream === undefined) return sync;
  const lookup: UpstreamLookup = { get: async () => ({ status: 200, body: stored }) };
  const up = await entry.inspectUpstream(req, lookup, env);
  return RANK[up.decision] >= RANK[sync.decision] ? up : sync;
}

const b64url = (s: string): string => Buffer.from(s, "utf8").toString("base64url");
/** A Gmail message body addressed to `to`, carried in `raw` (the only field read). */
const rawTo = (...to: string[]): string =>
  b64url((to.length > 0 ? `To: ${to.join(", ")}\r\n` : "") + "Subject: s\r\n\r\nhi\r\n");
const messageTo = (...to: string[]): InspectRequest => ({ body: { raw: rawTo(...to) } });

/** A Calendar write to the user's own calendar (path parameters as the
 *  request handler passes them). */
const ev = (body: unknown, calendarId = "primary"): InspectRequest => ({
  body,
  pathParams: { calendarId, eventId: "evt1" },
});
/** A Calendar event body with `n` distinct allowlisted attendees. */
const eventWithAttendees = (n: number): InspectRequest =>
  ev({ attendees: Array.from({ length: n }, (_, i) => ({ email: `a${i}@allowed.test` })) });

/** "a, b and c" / "a, b, c or d" → ["a", "b", "c"]; backticks stripped. */
const parseList = (s: string): string[] =>
  s
    .split(/,\s*|\s+(?:and|or)\s+/)
    .map((x) => x.replace(/`/g, "").trim())
    .filter((x) => x.length > 0);

describe("calendar attendee note states what inspectEventAttendees does", () => {
  /** Every op wired to the attendee check. */
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

  it("off-allowlist attendee is a HARD DENY, and the note says deny — not approval", async () => {
    for (const op of OPS) {
      const result = await runFull(op, ev({ attendees: [{ email: OFF_LIST }] }), CAL_ENV);
      // The behaviour.
      expect(result.decision, `${op} inspector`).toBe("deny");
      // The note must claim exactly that. This is the deny/elicit conflation the
      // whole feature exists to prevent, one layer down.
      expect(noteOf(op), `${op} note`).toMatch(/denies the whole write outright/i);
      expect(noteOf(op), `${op} note`).toMatch(/hard deny, not an approval prompt/i);
    }
  });

  it("an unset allowlist DENIES every attendee, and the note says so (fail-closed)", async () => {
    for (const op of OPS) {
      // The calendar var alone: OUTBOUND_RECIPIENT_ALLOWLIST missing → empty list.
      const r = await runFull(op, ev({ attendees: [{ email: ALLOWED }] }), { CALENDAR_WRITE_ALLOWLIST: "primary" });
      expect(r.decision, op).toBe("deny");
      expect(r.reason, op).toBe("external-attendee");
      expect(noteOf(op), `${op} note`).toMatch(/unset means an empty list/i);
      expect(noteOf(op), `${op} note`).toMatch(/any attendee at all is denied/i);
      // Must NOT claim the permissive opposite.
      expect(noteOf(op), `${op} note`).not.toMatch(/no restriction|every (send|attendee|write) allowed/i);
    }
  });

  it("FIXED (F1-2a): the calendar must be allow-listed, unset denies every write, and the note says so", async () => {
    for (const op of OPS) {
      const off = await runFull(op, ev({ summary: "x" }, "c_attacker@group.calendar.google.com"), CAL_ENV);
      expect(off.reason, `${op} unlisted calendar`).toBe("calendar-not-allowlisted");
      for (const env of [undefined, ENV]) {
        expect((await runFull(op, ev({ summary: "x" }), env)).reason, `${op} unset`).toBe("calendar-not-allowlisted");
      }
      // `primary` must be listed, as the note says.
      expect((await runFull(op, ev({ summary: "x" }), CAL_ENV)).decision, `${op} primary`).toBe("allow");
      expect(noteOf(op), `${op} note`).toMatch(/calendar allow-list \(CALENDAR_WRITE_ALLOWLIST; use `primary`/);
      expect(noteOf(op), `${op} note`).toMatch(/unset means every event write is denied/i);
    }
  });

  it("FIXED (F1-2c): a declineMessage is denied, as the note claims", async () => {
    for (const op of OPS) {
      for (const props of [
        { outOfOfficeProperties: { declineMessage: "x" } },
        { focusTimeProperties: { declineMessage: "x" } },
      ]) {
        expect((await runFull(op, ev(props), CAL_ENV)).reason, op).toBe("event-decline-message");
      }
      expect(noteOf(op), `${op} note`).toMatch(/An outOfOffice\/focusTime `declineMessage` is denied/);
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

  it("the threshold behaves as the note describes: at it allow, past it elicit", async () => {
    for (const op of OPS) {
      expect((await runFull(op, eventWithAttendees(MASS_INVITE_THRESHOLD), CAL_ENV)).decision, `${op} at`).toBe("allow");
      expect((await runFull(op, eventWithAttendees(MASS_INVITE_THRESHOLD + 1), CAL_ENV)).decision, `${op} past`).toBe(
        "elicit",
      );
    }
  });

  it("only Google room/equipment calendars are exempt, as the note claims", async () => {
    const ROOM = "room-101@resource.calendar.google.com";
    for (const op of OPS) {
      // A real Workspace room: flagged AND at the resource-calendar domain.
      const room = await runFull(op, ev({ attendees: [{ email: ROOM, resource: true }] }), CAL_ENV);
      expect(room.decision, `${op} room`).toBe("allow");
      // The flag alone exempts nothing (F-9)...
      const flagged = await runFull(op, ev({ attendees: [{ email: OFF_LIST, resource: true }] }), CAL_ENV);
      expect(flagged.decision, `${op} flagged external`).toBe("deny");
      // ...and nor does the domain without the flag.
      const unflagged = await runFull(op, ev({ attendees: [{ email: ROOM }] }), CAL_ENV);
      expect(unflagged.decision, `${op} unflagged room address`).toBe("deny");
      expect(noteOf(op), `${op} note`).toMatch(/only google rooms\/equipment.*resource: true.*resource\.calendar\.google\.com.*exempt/is);
    }
  });

  it("a body with no attendees is unaffected, as the note claims", async () => {
    for (const op of OPS) {
      // Inspector-level truth holds for all four...
      expect((await runFull(op, ev({ summary: "no attendees here" }), CAL_ENV)).decision, op).toBe("allow");
    }
    // ...but only the statically-allow ops may SAY so: for events.import the
    // static elicit still stops the call, so "unaffected" would be a lie.
    for (const op of WRITE_OPS) {
      expect(noteOf(op), `${op} note`).toMatch(/no `?attendees`? array is not subject to the attendee check/i);
    }
  });
});

describe("update/patch notes state what the stored-event hook does (F1-2b)", () => {
  const FOREIGN = {
    organizer: { email: "boss@elsewhere.test", self: false },
    attendees: [
      { email: "boss@elsewhere.test", organizer: true, responseStatus: "accepted" },
      { email: "me@allowed.test", self: true, responseStatus: "needsAction" },
    ],
  };
  const OWN_WITH_GUEST = { ...OWN_EVENT, attendees: [{ email: OFF_LIST }] };

  it("an event the user does not organise is denied, and one with outside guests needs approval", async () => {
    for (const op of ["calendar.events.update", "calendar.events.patch"]) {
      expect((await runFull(op, ev({ description: "x" }), CAL_ENV, FOREIGN)).reason, op).toBe(
        "event-not-organised-by-user",
      );
      const guests = await runFull(op, ev({ description: "x" }), CAL_ENV, OWN_WITH_GUEST);
      expect(guests, op).toMatchObject({ decision: "elicit", reason: "event-has-external-guests" });
      expect(noteOf(op), op).toMatch(/stored event is read first/i);
      expect(noteOf(op), op).toMatch(/an event the user does not organise is denied/i);
      expect(noteOf(op), op).toMatch(/guests off the outbound allowlist needs interactive approval/i);
    }
    // insert creates the event: nothing stored to read, and the note must not say otherwise.
    expect(noteOf("calendar.events.insert")).not.toMatch(/stored event/i);
  });

  it("patch: the RSVP the note describes passes on someone else's event, with exactly the statuses it lists", async () => {
    const note = noteOf("calendar.events.patch");
    const m = /own entry's `responseStatus` \(([^)]+)\)/.exec(note);
    expect(m, "patch note names the RSVP statuses").not.toBeNull();
    const listed = parseList(m![1]!);
    expect(listed.sort()).toEqual(["accepted", "declined", "needsAction", "tentative"]);
    const rsvp = (status: unknown) => ({
      attendees: FOREIGN.attendees.map((a) => ("self" in a ? { ...a, responseStatus: status } : a)),
    });
    for (const status of listed) {
      expect((await runFull("calendar.events.patch", ev(rsvp(status)), CAL_ENV, FOREIGN)).decision, status).toBe("allow");
    }
    expect((await runFull("calendar.events.patch", ev(rsvp("maybe")), CAL_ENV, FOREIGN)).decision).toBe("deny");
    // "a body of only `attendees`": anything else beside it is denied.
    expect(note).toMatch(/a body of only `attendees`/);
    const extra = { ...rsvp("accepted"), description: "x" };
    expect((await runFull("calendar.events.patch", ev(extra), CAL_ENV, FOREIGN)).decision).toBe("deny");
    // update has no such exception, and its note does not offer one.
    expect((await runFull("calendar.events.update", ev(rsvp("accepted")), CAL_ENV, FOREIGN)).decision).toBe("deny");
    expect(noteOf("calendar.events.update")).not.toMatch(/RSVP/);
  });
});

describe("events.move and events.quickAdd notes (F1-2d, F1-2e)", () => {
  const OP = "calendar.events.move";
  const move = (calendarId: string, destination: string | undefined, body?: unknown): InspectRequest => ({
    pathParams: { calendarId, eventId: "evt1" },
    query: destination === undefined ? {} : { destination },
    ...(body !== undefined ? { body } : {}),
  });

  it("both calendars must be allow-listed and the request takes no body, as the note claims", () => {
    expect(run(OP, move("primary", "primary"), CAL_ENV).decision).toBe("allow");
    expect(run(OP, move("primary", "c_attacker@group.calendar.google.com"), CAL_ENV).reason).toBe("calendar-not-allowlisted");
    expect(run(OP, move("c_attacker@group.calendar.google.com", "primary"), CAL_ENV).reason).toBe("calendar-not-allowlisted");
    expect(run(OP, move("primary", "primary"), ENV).reason).toBe("calendar-not-allowlisted");
    expect(run(OP, move("primary", undefined), CAL_ENV).decision).toBe("deny");
    expect(run(OP, move("primary", "primary", {}), CAL_ENV).decision).toBe("deny");
    const note = noteOf(OP);
    expect(note).toMatch(/Both the event's calendar and the `destination` query parameter must be on/);
    expect(note).toMatch(/CALENDAR_WRITE_ALLOWLIST/);
    expect(note).toMatch(/takes no body/);
  });

  it("quickAdd is denied, so it has no note to describe", () => {
    expect(surfaceReview["calendar.events.quickAdd"]?.decision).toBe("deny");
    expect(noteOf("calendar.events.quickAdd")).toBe("");
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

  it("a `raw` with no readable recipients is a deny, as the note claims", () => {
    expect(run(OP, messageTo(), ENV)).toMatchObject({ decision: "deny", reason: "send-no-recipients" });
    expect(noteOf(OP)).toMatch(/no readable recipients/i);
  });

  it("FIXED (F1-3): only raw, threadId and labelIds are read; the note's key list is the inspector's", () => {
    const note = noteOf(OP);
    const m = /any key other than ([^.]+?) is denied/.exec(note);
    expect(m, "note names the accepted keys").not.toBeNull();
    expect(new Set(parseList(m![1]!))).toEqual(new Set(MESSAGE_INPUT_KEYS));
    // Every listed key is accepted beside raw...
    expect(run(OP, { body: { raw: rawTo(ALLOWED), threadId: "t1", labelIds: ["INBOX"] } }, ENV).decision).toBe("allow");
    // ...and the decoys the note names are denied.
    expect(note).toMatch(/a body carrying `payload`, `message`/);
    const decoys = [
      { raw: rawTo(OFF_LIST), message: { raw: rawTo(ALLOWED) } },
      { payload: { headers: [{ name: "To", value: ALLOWED }] } },
      { raw: rawTo(ALLOWED), id: "x" },
    ];
    for (const body of decoys) {
      expect(run(OP, { body }, ENV).reason, JSON.stringify(body)).toBe("send-unexpected-key");
    }
  });

  it("a missing or empty `raw`, or a body that is not JSON, is denied, as the note claims", () => {
    for (const body of [{}, { raw: "" }, { raw: null }]) {
      expect(run(OP, { body }, ENV).reason, JSON.stringify(body)).toBe("send-no-raw");
    }
    expect(run(OP, { rawBody: "To: ok@allowed.test\r\n\r\nhi", contentType: "message/rfc822" }, ENV).decision).toBe("deny");
    const note = noteOf(OP);
    expect(note).toMatch(/`raw` is missing, empty/);
    expect(note).toMatch(/gmail\.users\.messages\.send\.media/);
    // The op no longer reads payload.headers or an uploaded body: the note must not offer them.
    expect(note).not.toMatch(/payload\.headers/);
    expect(note).not.toMatch(/multipart/i);
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
    expect(run(OP, { body: { id: "draft-1" } }, ENV)).toMatchObject({
      decision: "deny",
      reason: "draft-send-unvetted-recipients",
    });
    expect(noteOf(OP)).toMatch(/sending by id alone is always denied/i);
  });

  it("the update-and-send shape the note prescribes actually passes", () => {
    const result = run(OP, { body: { id: "draft-1", message: { raw: rawTo(ALLOWED) } } }, ENV);
    expect(result.decision).toBe("allow");
    expect(noteOf(OP)).toMatch(/`\{ id, message: \{ raw \} \}`/);
  });

  it("update-and-send is still allowlist-gated, as the note claims", () => {
    const result = run(OP, { body: { id: "d", message: { raw: rawTo(OFF_LIST) } } }, ENV);
    expect(result.decision).toBe("deny");
    expect(noteOf(OP)).toMatch(/unset means every send is denied/i);
  });

  it("FIXED (F1-1): `message.raw` is the only field read; the note's key list is the inspector's", () => {
    const note = noteOf(OP);
    const m = /any key inside `message` other than ([^,]+(?:, [^,]+)*?), is denied/.exec(note);
    expect(m, "note names the keys accepted inside message").not.toBeNull();
    const listed = parseList(m![1]!);
    expect(new Set(listed)).toEqual(new Set([...MESSAGE_INPUT_KEYS, "id"]));
    // Every listed key is accepted beside raw...
    const all = Object.fromEntries(listed.map((k) => [k, k === "labelIds" ? ["INBOX"] : `v-${k}`]));
    expect(run(OP, { body: { id: "d", message: { ...all, raw: rawTo(ALLOWED) } } }, ENV).decision).toBe("allow");
    // ...a `payload` (the decoy Gmail never reads) is denied wherever it rides...
    expect(note).toMatch(/a `payload`/);
    for (const body of [
      { id: "d", message: { payload: { headers: [{ name: "To", value: ALLOWED }] } } },
      { id: "d", message: { raw: rawTo(ALLOWED), payload: {} } },
      { id: "d", payload: {} },
    ]) {
      expect(run(OP, { body }, ENV).reason, JSON.stringify(body)).toBe("send-unexpected-key");
    }
    // ...and so is an empty raw.
    expect(note).toMatch(/as is an empty `raw`/);
    expect(run(OP, { body: { id: "d", message: { raw: "" } } }, ENV).decision).toBe("deny");
  });
});

describe("filters.create note states what inspectFilterCreate does", () => {
  const OP = "gmail.users.settings.filters.create";

  it("each action branch behaves as the note claims", () => {
    expect(run(OP, { body: { action: { forward: "x@y.test" } } }).decision).toBe("deny");
    expect(run(OP, { body: { action: { forwardingEmail: "x@y.test" } } }).decision).toBe("deny");
    expect(run(OP, { body: { action: { addLabelIds: ["TRASH"] } } }).decision).toBe("elicit");
    expect(run(OP, { body: { action: { addLabelIds: ["SPAM"] } } }).decision).toBe("elicit");
    expect(run(OP, { body: { action: { removeLabelIds: ["INBOX"] } } }).decision).toBe("elicit");
    expect(run(OP, { body: { action: { addLabelIds: ["Label_1"] } } }).decision).toBe("allow");
    expect(run(OP, { body: {} }).decision).toBe("deny");
    expect(run(OP, { body: { action: { add_label_ids: ["TRASH"] } } }).decision).toBe("elicit");
    expect(run(OP, { body: { action: { remove_label_ids: ["INBOX"] } } }).decision).toBe("elicit");
    expect(run(OP, { body: { action: { delete: true } } }).decision).toBe("deny");

    const note = noteOf(OP);
    // `delete` is not a FilterAction field (F-8); it is refused only by the
    // generic unknown-key rule, so the note must not single it out.
    expect(note).not.toMatch(/delete: true/i);
    expect(note).toMatch(/forward.*denied/i);
    expect(note).toMatch(/TRASH.*SPAM.*needs interactive approval/is);
    expect(note).toMatch(/INBOX.*needs interactive approval/is);
    expect(note).toMatch(/action` key other than.*denied/is);
    expect(note).toMatch(/no `?action`? object.*denied/is);
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
    expect(noteOf(IMPORT)).not.toMatch(/unaffected|not subject to the attendee check/i);
  });

  it("the non-elicit siblings keep those clauses, which are true for them", () => {
    for (const op of ["calendar.events.insert", "calendar.events.update", "calendar.events.patch"]) {
      expect(surfaceReview[op]?.decision, op).toBe("allow");
      expect(noteOf(op), op).toMatch(/needs interactive approval instead/i);
      expect(noteOf(op), op).toMatch(/not subject to the attendee check/i);
    }
  });
});

describe("messages.import note states what inspectMessageImport does", () => {
  const OP = "gmail.users.messages.import";

  it("is statically elicit and reads `raw` only; the note's key list is the inspector's", () => {
    expect(surfaceReview[OP]?.decision).toBe("elicit");
    const note = noteOf(OP);
    const m = /any key other than ([^.]+?) is denied/.exec(note);
    expect(m, "note names the accepted keys").not.toBeNull();
    expect(new Set(parseList(m![1]!))).toEqual(new Set(MESSAGE_INPUT_KEYS));
    expect(run(OP, { body: { raw: rawTo(ALLOWED), threadId: "t", labelIds: ["INBOX"] } }).decision).toBe("allow");
    expect(note).toMatch(/a body with `payload`/);
    expect(run(OP, { body: { raw: rawTo(ALLOWED), payload: {} } }).reason).toBe("send-unexpected-key");
  });

  it("a header block with ambiguous line endings is denied, as the note claims", () => {
    expect(run(OP, { body: { raw: b64url("To: a@b.test\rSubject: s\r\n\r\nhi") } }).decision).toBe("deny");
    expect(noteOf(OP)).toMatch(/ambiguous line endings/);
    // Off-allowlist recipients are NOT judged on import (nothing is sent), so
    // the note must not claim an allowlist check.
    expect(run(OP, { body: { raw: rawTo(OFF_LIST) } }).decision).toBe("allow");
    expect(noteOf(OP)).not.toMatch(/allowlist/i);
  });
});
