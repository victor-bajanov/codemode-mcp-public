// F1-2b regression: events.update / events.patch read the stored event first.
//
// Attacker: a prompt-injected LLM in the user's own session, or the organiser
//   of an invitation in the user's calendar (an outsider).
// Precondition: an event in an allow-listed calendar that the user does not
//   organise (an invitation), or one the user organises that has outside
//   guests.
// Payload: PATCH /calendar/v3/calendars/primary/events/{eventId}?sendUpdates=all
//   with `{ description: <mailbox content> }`. A guest's edit propagates to the
//   organiser's copy whatever `sendUpdates` says, and an edit to the user's own
//   event notifies its guests.
// Control: `inspectStoredEvent` (update) and `inspectStoredEventPatch` (patch)
//   GET the stored event through the host's lookup: an event the user does not
//   organise is denied (patch keeps one narrow exception, an RSVP that changes
//   only the user's own `responseStatus`), and one that already has guests off
//   the outbound allowlist needs interactive approval (a deny on clients
//   without elicitation). The dialog facts are the stored event's.
// Pre-fix: the inspector saw only the request body; a body without
//   `attendees` was allowed unconditionally, whoever organised the event.
import { describe, it, expect, vi } from "vitest";
import type { InspectRequest, UpstreamLookup, UpstreamLookupResult } from "@local/shared";
import { inspectStoredEvent, inspectStoredEventPatch } from "../calendar-stored-event";
import { MASS_INVITE_THRESHOLD } from "../calendar-attendees";

const ENV = {
  OUTBOUND_RECIPIENT_ALLOWLIST: "*@corp.example",
  CALENDAR_WRITE_ALLOWLIST: "primary",
};
const SECRET = "Q3 numbers: revenue 4.2M (from the CFO's mail)";

function fakeLookup(result: UpstreamLookupResult | (() => Promise<UpstreamLookupResult>)) {
  const get = vi.fn<UpstreamLookup["get"]>(async () =>
    typeof result === "function" ? result() : result,
  );
  return { lookup: { get } as UpstreamLookup, get };
}
const ok = (body: unknown): UpstreamLookupResult => ({ status: 200, body });
const req = (body: unknown, pathParams: Record<string, string> = { calendarId: "primary", eventId: "evt1" }): InspectRequest => ({
  body,
  query: { sendUpdates: "all" },
  pathParams,
});

const FOREIGN = {
  id: "evt1",
  summary: "Invitation",
  organizer: { email: "attacker@evil.example", self: false },
  start: { dateTime: "2026-12-01T09:00:00Z" },
  end: { dateTime: "2026-12-01T10:00:00Z" },
  attendees: [
    { email: "attacker@evil.example", organizer: true, responseStatus: "accepted" },
    { email: "me@corp.example", self: true, responseStatus: "needsAction" },
    { email: "other@evil.example", responseStatus: "tentative", displayName: "Other" },
  ],
};
const OWN = {
  id: "evt1",
  summary: "Team sync",
  organizer: { email: "me@corp.example", self: true },
  start: { dateTime: "2026-12-01T09:00:00Z" },
  end: { dateTime: "2026-12-01T10:00:00Z" },
  attendees: [] as unknown[],
};

/** Stored facts the dialog shows when the body does not set them (the hook
 *  returns facts on every non-deny: organizer from the stored event, summary
 *  / start / end from the body when present, else stored, and `changes`). */
const OWN_FACTS = { organizer: "me@corp.example", summary: "Team sync", start: "2026-12-01T09:00:00Z", end: "2026-12-01T10:00:00Z" };
const FOREIGN_FACTS = { organizer: "attacker@evil.example", summary: "Invitation", start: "2026-12-01T09:00:00Z", end: "2026-12-01T10:00:00Z" };

describe.each([
  ["inspectStoredEvent (update)", inspectStoredEvent],
  ["inspectStoredEventPatch (patch)", inspectStoredEventPatch],
])("%s", (_label, inspect) => {
  it("reads the stored event at its own path, ids percent-encoded", async () => {
    const { lookup, get } = fakeLookup(ok(OWN));
    await inspect(req({ description: "x" }, { calendarId: "c_team@group.calendar.google.com", eventId: "a/b c" }), lookup, ENV);
    expect(get).toHaveBeenCalledTimes(1);
    expect(get.mock.calls[0]![0]).toBe(
      "/calendar/v3/calendars/c_team%40group.calendar.google.com/events/a%2Fb%20c",
    );
  });

  it("FIXED (F1-2b): an event organised by someone else is denied", async () => {
    const { lookup } = fakeLookup(ok(FOREIGN));
    const r = await inspect(req({ description: SECRET }), lookup, ENV);
    expect(r).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "event-not-organised-by-user",
    });
    expect(r.message).toMatch(/organised by someone else/);
  });

  it.each([
    ["a non-object body", "nope"],
    ["an array body", [OWN]],
    ["no organizer", { ...OWN, organizer: undefined }],
    ["a string organizer", { ...OWN, organizer: "me@corp.example" }],
    ["organizer.self absent", { ...OWN, organizer: { email: "me@corp.example" } }],
    ["organizer.self a string", { ...OWN, organizer: { email: "me@corp.example", self: "true" } }],
  ])("treats %s as not organised by the user (fail closed)", async (_l, stored) => {
    const { lookup } = fakeLookup(ok(stored));
    expect((await inspect(req({ description: "x" }), lookup, ENV)).reason).toBe("event-not-organised-by-user");
  });

  it("denies event-not-found on a 404 and event-read-failed on any other non-2xx, without echoing the body", async () => {
    const nf = await inspect(req({}), fakeLookup({ status: 404, body: { error: "SECRET-404" } }).lookup, ENV);
    expect(nf).toMatchObject({ decision: "deny", category: "malformed", reason: "event-not-found" });
    for (const status of [403, 500, 302]) {
      const r = await inspect(req({}), fakeLookup({ status, body: { error: "SECRET-BODY" } }).lookup, ENV);
      expect(r, String(status)).toMatchObject({ decision: "deny", category: "malformed", reason: "event-read-failed" });
      expect(r.message).toContain(String(status));
      expect(r.message).not.toContain("SECRET-BODY");
    }
  });

  it.each([
    ["no pathParams", undefined],
    ["no eventId", { calendarId: "primary" }],
    ["no calendarId", { eventId: "evt1" }],
    ["an empty eventId", { calendarId: "primary", eventId: "" }],
  ])("denies event-path-params-missing with %s, before any read", async (_l, pathParams) => {
    const { lookup, get } = fakeLookup(ok(OWN));
    const r = await inspect({ body: {}, ...(pathParams ? { pathParams } : {}) }, lookup, ENV);
    expect(r).toMatchObject({ decision: "deny", category: "malformed", reason: "event-path-params-missing" });
    expect(get).not.toHaveBeenCalled();
  });

  it("allows an edit to the user's own event with no guests", async () => {
    expect(await inspect(req({ description: "x" }), fakeLookup(ok(OWN)).lookup, ENV)).toEqual({ decision: "allow", summary: { ...OWN_FACTS, changes: "description" } });
  });

  it("allows an own event whose guests are all on the outbound allowlist, rooms and self skipped", async () => {
    const stored = {
      ...OWN,
      attendees: [
        { email: "me@corp.example", self: true, organizer: true },
        { email: "colleague@corp.example" },
        { email: "room-1@resource.calendar.google.com", resource: true },
      ],
    };
    expect(await inspect(req({ description: "x" }), fakeLookup(ok(stored)).lookup, ENV)).toEqual({ decision: "allow", summary: { ...OWN_FACTS, changes: "description" } });
  });

  it("denies event-attendees-omitted when the stored guest list is incomplete", async () => {
    const r = await inspect(req({ description: "x" }), fakeLookup(ok({ ...OWN, attendeesOmitted: true })).lookup, ENV);
    expect(r).toMatchObject({ decision: "deny", category: "malformed", reason: "event-attendees-omitted" });
  });

  it("FIXED (F1-2b'): an own event with an outside guest elicits: who is affected from the stored event, what changes from the body", async () => {
    const stored = {
      ...OWN,
      attendees: [
        { email: "outsider@evil.example" },
        { email: "me@corp.example", self: true },
        { email: "colleague@corp.example" },
      ],
    };
    const r = await inspect(req({ description: SECRET, summary: "decoy title" }), fakeLookup(ok(stored)).lookup, ENV);
    expect(r).toEqual({
      decision: "elicit",
      category: "external_data_flow",
      reason: "event-has-external-guests",
      summary: {
        organizer: "me@corp.example",
        guests: "outsider@evil.example",
        summary: "decoy title",
        changes: "description, summary",
        start: "2026-12-01T09:00:00Z",
        end: "2026-12-01T10:00:00Z",
      },
    });
  });

  it("names the first three outside guests and counts the rest; facts default to empty strings", async () => {
    const stored = {
      organizer: { self: true },
      start: { date: "2026-12-01" },
      attendees: ["a", "b", "c", "d", "e"].map((x) => ({ email: `${x}@evil.example` })),
    };
    const r = await inspect(req({ description: "x" }), fakeLookup(ok(stored)).lookup, ENV);
    expect(r.summary).toEqual({
      organizer: "",
      guests: "a@evil.example, b@evil.example, c@evil.example (+2)",
      summary: "",
      start: "2026-12-01",
      end: "",
      changes: "description",
    });
  });

  it("shows the body's summary, start and end when it sets them (non-strings as JSON), never the stored ones", async () => {
    const stored = { ...OWN, attendees: [{ email: "outsider@evil.example" }] };
    const r = await inspect(
      req({ summary: 42, start: { date: "2027-01-01" }, end: { timeZone: "UTC" }, organizer: { email: "decoy@corp.example" } }),
      fakeLookup(ok(stored)).lookup,
      ENV,
    );
    expect(r.summary).toEqual({
      organizer: "me@corp.example",
      guests: "outsider@evil.example",
      summary: "42",
      start: "2027-01-01",
      end: '{"timeZone":"UTC"}',
      changes: "end, organizer, start, summary",
    });
  });

  it("an empty body changes nothing and says so", async () => {
    const r = await inspect(req({}), fakeLookup(ok(OWN)).lookup, ENV);
    expect(r).toEqual({ decision: "allow", summary: { ...OWN_FACTS, changes: "" } });
  });

  it.each([
    ["a non-object entry", "outsider@evil.example"],
    ["an entry without email", { displayName: "No address" }],
    ["an empty email", { email: "" }],
    ["a non-string email", { email: ["x@corp.example"] }],
    ["a resource flag at a non-room address", { email: "outsider@evil.example", resource: true }],
  ])("counts %s among the stored guests as outside (strict)", async (_l, entry) => {
    const stored = { ...OWN, attendees: [entry] };
    const r = await inspect(req({ description: "x" }), fakeLookup(ok(stored)).lookup, ENV);
    expect(r).toMatchObject({ decision: "elicit", reason: "event-has-external-guests" });
  });

  it("with no outbound allowlist every stored guest is outside", async () => {
    const stored = { ...OWN, attendees: [{ email: "colleague@corp.example" }] };
    const r = await inspect(req({ description: "x" }), fakeLookup(ok(stored)).lookup, { CALENDAR_WRITE_ALLOWLIST: "primary" });
    expect(r.reason).toBe("event-has-external-guests");
  });

  it("propagates a lookup throw (the handler denies the write)", async () => {
    const { lookup } = fakeLookup(async () => {
      throw new Error("lookup refused");
    });
    await expect(inspect(req({ description: "x" }), lookup, ENV)).rejects.toThrow(/lookup refused/);
  });
});

// §9 amendment: a narrow RSVP on an invitation stays allowed on events.patch.
describe("inspectStoredEventPatch: RSVP on an event organised by someone else", () => {
  const rsvp = (status: string) =>
    FOREIGN.attendees.map((a) => ("self" in a && a.self ? { ...a, responseStatus: status } : { ...a }));

  it.each(["accepted", "declined", "tentative", "needsAction"])("allows changing only the user's own responseStatus to %s", async (status) => {
    const r = await inspectStoredEventPatch(req({ attendees: rsvp(status) }), fakeLookup(ok(FOREIGN)).lookup, ENV);
    expect(r).toEqual({ decision: "allow", summary: { ...FOREIGN_FACTS, changes: "attendees" } });
  });

  it("allows the RSVP when the user's entry is found by the creator's address instead of self: true", async () => {
    const stored = {
      ...FOREIGN,
      creator: { email: "me@corp.example", self: true },
      attendees: FOREIGN.attendees.map((a) => {
        const { self: _self, ...rest } = a as { self?: boolean };
        return rest;
      }),
    };
    const body = stored.attendees.map((a) =>
      (a as { email: string }).email === "me@corp.example" ? { ...a, responseStatus: "declined" } : a,
    );
    expect(await inspectStoredEventPatch(req({ attendees: body }), fakeLookup(ok(stored)).lookup, ENV)).toEqual({
      decision: "allow",
      summary: { ...FOREIGN_FACTS, changes: "attendees" },
    });
  });

  it("events.update gets no RSVP exception", async () => {
    const r = await inspectStoredEvent(req({ attendees: rsvp("accepted") }), fakeLookup(ok(FOREIGN)).lookup, ENV);
    expect(r.reason).toBe("event-not-organised-by-user");
  });

  const deniedRsvp: Array<[string, unknown]> = [
    ["RSVP plus a comment", { attendees: rsvp("accepted").map((a) => ("self" in a ? { ...a, comment: SECRET } : a)) }],
    ["RSVP plus additionalGuests", { attendees: rsvp("accepted").map((a) => ("self" in a ? { ...a, additionalGuests: 2 } : a)) }],
    ["RSVP plus a changed guest", { attendees: rsvp("accepted").map((a, i) => (i === 2 ? { ...a, displayName: SECRET } : a)) }],
    ["RSVP plus an added guest", { attendees: [...rsvp("accepted"), { email: "new@evil.example" }] }],
    ["RSVP with a guest removed", { attendees: rsvp("accepted").slice(0, 2) }],
    ["RSVP with the guests reordered", { attendees: [...rsvp("accepted")].reverse() }],
    ["changing another attendee's responseStatus", { attendees: FOREIGN.attendees.map((a, i) => (i === 2 ? { ...a, responseStatus: "declined" } : a)) }],
    ["an out-of-enum responseStatus", { attendees: rsvp("maybe") }],
    ["a non-string responseStatus", { attendees: FOREIGN.attendees.map((a) => ("self" in a ? { ...a, responseStatus: 1 } : a)) }],
    ["RSVP plus another top-level key", { attendees: rsvp("accepted"), description: SECRET }],
    ["the user's entry with a changed email", { attendees: rsvp("accepted").map((a) => ("self" in a ? { ...a, email: "x@evil.example" } : a)) }],
    ["the user's entry with responseStatus removed", { attendees: FOREIGN.attendees.map((a) => { if (!("self" in a)) return a; const { responseStatus: _r, ...rest } = a; return rest; }) }],
    ["attendees not an array", { attendees: { 0: rsvp("accepted")[0] } }],
    ["an empty body", {}],
  ];
  it.each(deniedRsvp)("denies %s (event-not-organised-by-user)", async (_l, body) => {
    const r = await inspectStoredEventPatch(req(body), fakeLookup(ok(FOREIGN)).lookup, ENV);
    expect(r).toMatchObject({ decision: "deny", reason: "event-not-organised-by-user" });
  });

  it("denies when the stored event marks no attendee, or two, as the user", async () => {
    const none = { ...FOREIGN, attendees: FOREIGN.attendees.map(({ self: _s, ...rest }: { self?: boolean }) => rest) };
    const body0 = none.attendees.map((a, i) => (i === 1 ? { ...a, responseStatus: "accepted" } : a));
    expect((await inspectStoredEventPatch(req({ attendees: body0 }), fakeLookup(ok(none)).lookup, ENV)).reason).toBe(
      "event-not-organised-by-user",
    );
    // Entries 1 and 2 both claim to be the user; only entry 1 changes. Picking
    // the first match would accept this, so it exercises the uniqueness rule.
    const two = { ...FOREIGN, attendees: FOREIGN.attendees.map((a, i) => (i === 0 ? a : { ...a, self: true })) };
    const body2 = two.attendees.map((a, i) => (i === 1 ? { ...a, responseStatus: "accepted" } : a));
    expect((await inspectStoredEventPatch(req({ attendees: body2 }), fakeLookup(ok(two)).lookup, ENV)).reason).toBe(
      "event-not-organised-by-user",
    );
  });

  it.each([
    ["a comment", { comment: "old" }],
    ["additionalGuests", { additionalGuests: 1 }],
  ])("denies an RSVP whose stored own entry already has %s, even echoed unchanged", async (_l, extra) => {
    const stored = {
      ...FOREIGN,
      attendees: FOREIGN.attendees.map((a) => ("self" in a ? { ...a, ...extra } : a)),
    };
    const body = stored.attendees.map((a) => ("self" in a ? { ...a, responseStatus: "accepted" } : a));
    const r = await inspectStoredEventPatch(req({ attendees: body }), fakeLookup(ok(stored)).lookup, ENV);
    expect(r.reason).toBe("event-not-organised-by-user");
  });

  it("denies an RSVP when the stored guest list is incomplete (attendeesOmitted)", async () => {
    const stored = { ...FOREIGN, attendeesOmitted: true };
    const r = await inspectStoredEventPatch(req({ attendees: rsvp("accepted") }), fakeLookup(ok(stored)).lookup, ENV);
    expect(r.decision).toBe("deny");
  });
});

// The patch sync inspector defers the attendee check of an attendees-only body
// (the RSVP shape) to this hook; on the user's own event the hook applies it.
describe("inspectStoredEventPatch: attendees-only body on the user's own event", () => {
  it("denies an off-allowlist attendee (external-attendee)", async () => {
    const r = await inspectStoredEventPatch(req({ attendees: [{ email: "outsider@evil.example" }] }), fakeLookup(ok(OWN)).lookup, ENV);
    expect(r).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "external-attendee" });
  });

  it("allows allowlisted attendees", async () => {
    const r = await inspectStoredEventPatch(req({ attendees: [{ email: "colleague@corp.example" }] }), fakeLookup(ok(OWN)).lookup, ENV);
    expect(r).toEqual({ decision: "allow", summary: { ...OWN_FACTS, changes: "attendees" } });
  });

  it("elicits a mass invite past the threshold, with the stored event's facts", async () => {
    const attendees = Array.from({ length: MASS_INVITE_THRESHOLD + 1 }, (_, i) => ({ email: `u${i}@corp.example` }));
    const r = await inspectStoredEventPatch(req({ attendees }), fakeLookup(ok(OWN)).lookup, ENV);
    expect(r).toMatchObject({ decision: "elicit", reason: "mass-invite" });
    expect(r.summary).toMatchObject({ count: MASS_INVITE_THRESHOLD + 1, summary: "Team sync", organizer: "me@corp.example", changes: "attendees" });
  });

  it("an outside stored guest wins over the mass invite, and the dialog keeps both", async () => {
    const attendees = Array.from({ length: MASS_INVITE_THRESHOLD + 1 }, (_, i) => ({ email: `u${i}@corp.example` }));
    const stored = { ...OWN, attendees: [{ email: "outsider@evil.example" }] };
    const r = await inspectStoredEventPatch(req({ attendees }), fakeLookup(ok(stored)).lookup, ENV);
    expect(r).toMatchObject({ decision: "elicit", reason: "event-has-external-guests" });
    expect(r.summary).toMatchObject({ guests: "outsider@evil.example", count: MASS_INVITE_THRESHOLD + 1 });
  });
});

// pathParams are decoded; the lookup takes an encoded path and decodes it
// again. The read must target exactly the resource the write does.
describe("the stored-event read targets the written resource", () => {
  const HOLIDAY = "en.usa#holiday@group.v.calendar.google.com";
  const EVENT_ID = "ev%25x?z#w"; // an encoded "/" is refused by the path guard, outer write included

  it("percent-encodes every segment (a '#' calendar id, a '%25' event id) and forwards no query", async () => {
    const { lookup, get } = fakeLookup(ok(OWN));
    await inspectStoredEventPatch(
      { body: { description: "x" }, query: { maxAttendees: 1, sendUpdates: "all" }, pathParams: { calendarId: HOLIDAY, eventId: EVENT_ID } },
      lookup,
      ENV,
    );
    expect(get).toHaveBeenCalledTimes(1);
    const [path, query] = get.mock.calls[0]!;
    expect(query).toBeUndefined();
    const segs = path.split("/");
    expect(segs.slice(0, 4)).toEqual(["", "calendar", "v3", "calendars"]);
    expect(segs).toHaveLength(7);
    expect(decodeURIComponent(segs[4]!)).toBe(HOLIDAY);
    expect(segs[5]).toBe("events");
    expect(decodeURIComponent(segs[6]!)).toBe(EVENT_ID);
  });

  it("end to end: the GET and the PATCH hit the same upstream URL", async () => {
    const urls: Array<{ method: string; url: string }> = [];
    const fetchSpy = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input);
      urls.push({ method: init?.method ?? "GET", url });
      const body = (init?.method ?? "GET") === "GET" ? OWN : { id: "upstream-ok" };
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetchSpy);
    vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const { handleUpstreamRequest } = await import("@local/scaffold");
      const { gmailProvider } = await import("../../index");
      await handleUpstreamRequest({
        ctx: {
          method: "PATCH",
          path: `/calendar/v3/calendars/${encodeURIComponent(HOLIDAY)}/events/${encodeURIComponent(EVENT_ID)}`,
          query: { maxAttendees: 1, sendUpdates: "none" },
          body: { description: "x" },
        },
        spec: gmailProvider.spec,
        surfaceReview: gmailProvider.surfaceReview,
        apiBaseUrl: gmailProvider.apiBaseUrl,
        deploymentName: "test",
        props: { refreshToken: "r", userId: "u" },
        server: {} as never,
        oauth: {
          refreshTokenAccessor: () => "r",
          userIdAccessor: () => "u",
          broker: { getOrRefreshAccessToken: async () => "AT" },
        },
        audit: {},
        env: { ...ENV, CALENDAR_WRITE_ALLOWLIST: `primary,${HOLIDAY}` } as { ALLOW_PII_IN_LOGS?: string },
      });
    } finally {
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
    expect(urls.map((u) => u.method)).toEqual(["GET", "PATCH"]);
    const get = new URL(urls[0]!.url);
    const patch = new URL(urls[1]!.url);
    expect(get.pathname).toBe(patch.pathname);
    expect(get.search).toBe("");
    expect(decodeURIComponent(patch.pathname.split("/")[4]!)).toBe(HOLIDAY);
    expect(decodeURIComponent(patch.pathname.split("/")[6]!)).toBe(EVENT_ID);
  });
});
