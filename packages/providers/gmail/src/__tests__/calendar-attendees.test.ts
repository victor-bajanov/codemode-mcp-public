// Tests for the Calendar event-write inspector: calendar allow-list (F1-2a),
// auto-decline message (F1-2c), attendee allowlist, and the event facts it
// hands the approval dialog.

import { describe, it, expect } from "vitest";
import type { InspectRequest } from "@local/shared";
import {
  inspectEventAttendees,
  inspectEventImport,
  inspectEventPatch,
  MASS_INVITE_THRESHOLD,
} from "../inspectors/calendar-attendees";

// Mirrors the prod (gmail/gmail-dev) wrangler vars.
const ENV = {
  OUTBOUND_RECIPIENT_ALLOWLIST: "*@example.com,adam@gmail.com",
  CALENDAR_WRITE_ALLOWLIST: "primary",
};
/** The matched path parameters of a write to the user's own calendar. */
const ON_PRIMARY = { pathParams: { calendarId: "primary" } } as const;

describe("inspectEventAttendees", () => {
  it("allows an event with no attendees field (e.g. partial patch) without consulting the outbound allowlist", () => {
    // Attendee-less writes never consult OUTBOUND_RECIPIENT_ALLOWLIST, so a
    // deployment without that var can still manage its own events.
    expect(
      inspectEventAttendees({ ...ON_PRIMARY, body: { summary: "Focus time" } }, { CALENDAR_WRITE_ALLOWLIST: "primary" }),
    ).toMatchObject({ decision: "allow" });
  });

  it("FIXED (F1-2a): denies even an attendee-free write without env (calendar-not-allowlisted, fail closed)", () => {
    expect(inspectEventAttendees({ ...ON_PRIMARY, body: { summary: "Focus time" } })).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "calendar-not-allowlisted",
    });
  });

  it("allows an empty attendees array", () => {
    expect(inspectEventAttendees({ ...ON_PRIMARY, body: { attendees: [] } }, ENV)).toMatchObject({
      decision: "allow",
    });
  });

  it("allows attendees that are all on the allowlist", () => {
    const result = inspectEventAttendees(
      {
        ...ON_PRIMARY,
        body: {
          attendees: [
            { email: "you@example.com" },
            { email: "adam@gmail.com" },
          ],
        },
      },
      ENV,
    );
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("matches the allowlist case-insensitively", () => {
    expect(
      inspectEventAttendees(
        { ...ON_PRIMARY, body: { attendees: [{ email: "you@example.com" }] } },
        ENV,
      ),
    ).toMatchObject({ decision: "allow" });
  });

  it("denies when any attendee is off the allowlist", () => {
    const result = inspectEventAttendees(
      {
        ...ON_PRIMARY,
        body: {
          attendees: [
            { email: "you@example.com" },
            { email: "stranger@evil.example" },
          ],
        },
      },
      ENV,
    );
    expect(result).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "external-attendee",
    });
  });

  it("denies every attendee when no env is passed (fail closed; the calendar check fires first)", () => {
    expect(
      inspectEventAttendees({ ...ON_PRIMARY, body: { attendees: [{ email: "you@example.com" }] } }),
    ).toMatchObject({ decision: "deny", reason: "calendar-not-allowlisted" });
  });

  it("denies every attendee when only the calendar var is set (outbound allowlist unset means empty)", () => {
    expect(
      inspectEventAttendees(
        { ...ON_PRIMARY, body: { attendees: [{ email: "pal@allowed.example" }] } },
        { CALENDAR_WRITE_ALLOWLIST: "primary" },
      ),
    ).toMatchObject({ decision: "deny", reason: "external-attendee" });
  });

  it("resolves the allowlist per deployment (a tester deployment invites its own contacts)", () => {
    const testerEnv = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@tester.example", CALENDAR_WRITE_ALLOWLIST: "primary" };
    expect(
      inspectEventAttendees({ ...ON_PRIMARY, body: { attendees: [{ email: "pal@tester.example" }] } }, testerEnv),
    ).toMatchObject({ decision: "allow" });
    expect(
      inspectEventAttendees(
        { ...ON_PRIMARY, body: { attendees: [{ email: "you@example.com" }] } },
        testerEnv,
      ),
    ).toMatchObject({ decision: "deny", reason: "external-attendee" });
  });

  it("off-allowlist wins over mass-invite", () => {
    const attendees = Array.from({ length: MASS_INVITE_THRESHOLD + 5 }, (_, i) => ({
      email: i === 0 ? "stranger@evil.example" : `user${i}@example.com`,
    }));
    expect(inspectEventAttendees({ ...ON_PRIMARY, body: { attendees } }, ENV)).toMatchObject({
      decision: "deny",
      reason: "external-attendee",
    });
  });

  it("elicits a mass-invite when all attendees are on-allowlist but exceed the threshold", () => {
    // Distinct addresses on the wildcard-allowlisted domain so dedup keeps them all.
    const attendees = Array.from({ length: MASS_INVITE_THRESHOLD + 1 }, (_, i) => ({
      email: `user${i}@example.com`,
    }));
    const result = inspectEventAttendees({ ...ON_PRIMARY, body: { summary: "All hands", attendees } }, ENV);
    expect(result).toMatchObject({
      decision: "elicit",
      category: "external_data_flow",
      reason: "mass-invite",
    });
    expect(result.summary).toMatchObject({ count: MASS_INVITE_THRESHOLD + 1 });
  });

  it("does not elicit at exactly the threshold (strictly greater-than)", () => {
    const attendees = Array.from({ length: MASS_INVITE_THRESHOLD }, (_, i) => ({
      email: `user${i}@example.com`,
    }));
    expect(inspectEventAttendees({ ...ON_PRIMARY, body: { attendees } }, ENV)).toMatchObject({ decision: "allow" });
  });

  it("skips resource attendees (meeting rooms) when checking the allowlist", () => {
    const result = inspectEventAttendees(
      {
        ...ON_PRIMARY,
        body: {
          attendees: [
            { email: "you@example.com" },
            { email: "room-101@resource.calendar.google.com", resource: true },
          ],
        },
      },
      ENV,
    );
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies an external address flagged resource: true (F-9)", () => {
    const result = inspectEventAttendees(
      {
        ...ON_PRIMARY,
        body: {
          attendees: [
            { email: "you@example.com" },
            { email: "outsider@evil.example", resource: true },
          ],
        },
      },
      ENV,
    );
    expect(result).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "external-attendee",
    });
  });

  it("applies the allowlist to a resource-calendar address without the resource flag", () => {
    const result = inspectEventAttendees(
      { ...ON_PRIMARY, body: { attendees: [{ email: "room-101@resource.calendar.google.com" }] } },
      ENV,
    );
    expect(result).toMatchObject({ decision: "deny", reason: "external-attendee" });
  });

  it("does not exempt look-alike or subdomain resource addresses", () => {
    for (const email of [
      "room@evil.resource.calendar.google.com",
      "room@resource.calendar.google.com.evil.example",
      "outsider@evil.example@resource.calendar.google.com",
      "room@xresource.calendar.google.com",
    ]) {
      const result = inspectEventAttendees({ ...ON_PRIMARY, body: { attendees: [{ email, resource: true }] } }, ENV);
      expect(result.decision, email).toBe("deny");
    }
  });

  it("matches the resource-calendar domain case-insensitively and does not count rooms", () => {
    const attendees = [
      ...Array.from({ length: MASS_INVITE_THRESHOLD }, (_, i) => ({
        email: `user${i}@example.com`,
      })),
      { email: " Room-101@Resource.Calendar.Google.com ", resource: true },
    ];
    expect(inspectEventAttendees({ ...ON_PRIMARY, body: { attendees } }, ENV)).toMatchObject({ decision: "allow" });
  });

  it("allows a request with no payload at all (nothing to gate)", () => {
    expect(inspectEventAttendees({ ...ON_PRIMARY, body: undefined }, ENV)).toMatchObject({ decision: "allow" });
    expect(inspectEventAttendees({ ...ON_PRIMARY, query: { sendUpdates: "all" } }, ENV)).toMatchObject({ decision: "allow" });
  });

  // F-7: a payload whose attendees cannot be read here may still be parsed by
  // Calendar, so anything other than a JSON object (or no payload) denies.
  it.each([
    ["raw bytes", { rawBody: new TextEncoder().encode('{"attendees":[{"email":"x@evil.example"}]}'), contentType: "text/json" }],
    ["raw string", { rawBody: '{"attendees":[{"email":"x@evil.example"}]}', contentType: "application/x-json" }],
    ["multipart", { multipart: [{ name: "event", value: "{}" }], contentType: "multipart/form-data" }],
    ["string body", { body: '{"attendees":[{"email":"x@evil.example"}]}' }],
    ["array body", { body: [{ attendees: [{ email: "x@evil.example" }] }] }],
    ["number body", { body: 42 }],
  ])("denies a non-object payload (%s)", (_label, req) => {
    expect(inspectEventAttendees({ ...ON_PRIMARY, ...req }, ENV)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "event-body-not-object",
    });
  });
});

// F1-2a: event writes only on the deployment's allow-listed calendars.
describe("inspectEventAttendees: calendar allow-list (F1-2a)", () => {
  const SECRET_EVENT = { summary: "x", description: "SECRET mailbox content" };
  const ATTACKER_CAL = "c_attacker@group.calendar.google.com";

  it("FIXED (F1-2a): an event on a calendar off the allow-list is denied, naming the calendar", () => {
    const r = inspectEventAttendees({ pathParams: { calendarId: ATTACKER_CAL }, body: SECRET_EVENT }, ENV);
    expect(r).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "calendar-not-allowlisted" });
    expect(r.message).toContain(ATTACKER_CAL);
    expect(r.message).toContain("CALENDAR_WRITE_ALLOWLIST");
  });

  it("allows an allow-listed secondary calendar, compared case-insensitively", () => {
    const env = { ...ENV, CALENDAR_WRITE_ALLOWLIST: "primary,c_team@group.calendar.google.com" };
    expect(
      inspectEventAttendees({ pathParams: { calendarId: "C_Team@group.calendar.google.com" }, body: SECRET_EVENT }, env).decision,
    ).toBe("allow");
  });

  it("denies when the request carries no calendarId (unit probe without pathParams: fail closed)", () => {
    expect(inspectEventAttendees({ body: SECRET_EVENT }, ENV).reason).toBe("calendar-not-allowlisted");
    expect(inspectEventAttendees({ pathParams: {}, body: SECRET_EVENT }, ENV).reason).toBe("calendar-not-allowlisted");
  });

  it("denies a write with no payload at all on an unlisted calendar", () => {
    expect(inspectEventAttendees({ pathParams: { calendarId: ATTACKER_CAL } }, ENV).reason).toBe("calendar-not-allowlisted");
  });

  it("a non-object payload is still refused as such (checked first)", () => {
    expect(inspectEventAttendees({ pathParams: { calendarId: ATTACKER_CAL }, body: "x" }, ENV).reason).toBe(
      "event-body-not-object",
    );
  });

  it("throws on a malformed CALENDAR_WRITE_ALLOWLIST (the request errors before anything is sent)", () => {
    expect(() =>
      inspectEventAttendees({ ...ON_PRIMARY, body: SECRET_EVENT }, { CALENDAR_WRITE_ALLOWLIST: "not a calendar" }),
    ).toThrow(/CALENDAR_WRITE_ALLOWLIST/);
  });
});

// F1-2c: Calendar emails an outOfOffice/focusTime declineMessage to the
// organiser of every conflicting invitation.
describe("inspectEventAttendees: auto-decline message (F1-2c)", () => {
  const ooo = (props: Record<string, unknown>) => ({ ...ON_PRIMARY, body: { eventType: "outOfOffice", ...props } });

  it.each([
    ["outOfOfficeProperties.declineMessage", { outOfOfficeProperties: { autoDeclineMode: "declineAllConflictingInvitations", declineMessage: "SECRET" } }],
    ["out_of_office_properties.decline_message", { out_of_office_properties: { decline_message: "SECRET" } }],
    ["out_of_office_properties.declineMessage", { out_of_office_properties: { declineMessage: "SECRET" } }],
    ["outOfOfficeProperties.decline_message", { outOfOfficeProperties: { decline_message: "SECRET" } }],
    ["focusTimeProperties.declineMessage", { focusTimeProperties: { declineMessage: "SECRET" } }],
    ["focus_time_properties.decline_message", { focus_time_properties: { decline_message: "SECRET" } }],
    ["a non-string declineMessage", { outOfOfficeProperties: { declineMessage: { text: "SECRET" } } }],
    ["a numeric declineMessage", { focusTimeProperties: { declineMessage: 0 } }],
  ])("FIXED (F1-2c): denies %s", (_l, props) => {
    const r = inspectEventAttendees(ooo(props), ENV);
    expect(r).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "event-decline-message" });
    expect(r.message).toMatch(/omit declineMessage/);
  });

  it.each([
    ["no declineMessage", { outOfOfficeProperties: { autoDeclineMode: "declineAllConflictingInvitations" } }],
    ["a null declineMessage", { outOfOfficeProperties: { declineMessage: null } }],
    ["an empty declineMessage", { focusTimeProperties: { declineMessage: "" } }],
    ["a non-object properties value", { outOfOfficeProperties: "declineMessage" }],
  ])("allows an outOfOffice/focusTime event with %s", (_l, props) => {
    expect(inspectEventAttendees(ooo(props), ENV).decision).toBe("allow");
  });
});

describe("inspectEventAttendees: facts for the approval dialog", () => {
  const IMPORTED = {
    ...ON_PRIMARY,
    body: {
      iCalUID: "x@evil.example",
      summary: "Board meeting",
      organizer: { email: "ceo@corp.example" },
      start: { dateTime: "2026-12-01T09:00:00Z" },
      end: { date: "2026-12-02" },
    },
  };

  it("events.import: returns organizer, summary, start and end from the event (carry-over: import dialog)", () => {
    const r = inspectEventImport(IMPORTED, ENV);
    expect(r).toEqual({
      decision: "allow",
      summary: {
        organizer: "ceo@corp.example",
        summary: "Board meeting",
        start: "2026-12-01T09:00:00Z",
        end: "2026-12-02",
      },
    });
  });

  it("insert/update/patch: no `organizer` fact (Calendar sets the organiser itself; update/patch show the stored one)", () => {
    for (const inspect of [inspectEventAttendees, inspectEventPatch]) {
      expect(inspect(IMPORTED, ENV)).toEqual({
        decision: "allow",
        summary: { summary: "Board meeting", start: "2026-12-01T09:00:00Z", end: "2026-12-02" },
      });
    }
  });

  it("events.import otherwise judges exactly as inspectEventAttendees", () => {
    const cases: InspectRequest[] = [
      { pathParams: { calendarId: "c_attacker@group.calendar.google.com" }, body: { summary: "x" } },
      { ...ON_PRIMARY, body: { attendees: [{ email: "stranger@evil.example" }] } },
      { ...ON_PRIMARY, body: { outOfOfficeProperties: { declineMessage: "x" } } },
      { ...ON_PRIMARY, body: "x" },
    ];
    for (const req of cases) {
      expect(inspectEventImport(req, ENV), JSON.stringify(req)).toEqual(inspectEventAttendees(req, ENV));
    }
  });

  it("omits facts that are absent or not strings, and returns a bare allow when there are none", () => {
    expect(
      inspectEventImport({ ...ON_PRIMARY, body: { organizer: { email: 7 }, summary: 3, start: {}, end: "x" } }, ENV),
    ).toEqual({ decision: "allow" });
    expect(inspectEventAttendees({ ...ON_PRIMARY, body: { summary: "Only" } }, ENV)).toEqual({
      decision: "allow",
      summary: { summary: "Only" },
    });
  });

  it("carry-over: the mass-invite summary is not cut at 200 (the scaffold's visible ellipsis applies)", () => {
    const attendees = Array.from({ length: MASS_INVITE_THRESHOLD + 1 }, (_, i) => ({ email: `user${i}@allowed.example` }));
    const long = "S".repeat(300);
    const env = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@allowed.example", CALENDAR_WRITE_ALLOWLIST: "primary" };
    const r = inspectEventAttendees({ ...ON_PRIMARY, body: { summary: long, attendees } }, env);
    expect(r.decision).toBe("elicit");
    expect(r.summary?.["summary"]).toBe(long);
    expect((r.summary?.["summary"] as string).length).toBe(300);
  });
});

// events.patch: an attendees-only body is the RSVP shape, which only the
// stored event can judge, so the sync inspector defers its attendee check to
// inspectStoredEventPatch (the paired inspectUpstream hook, which always runs
// after a non-deny). Every other check still applies here.
describe("inspectEventPatch", () => {
  const RSVP_BODY = {
    attendees: [
      { email: "attacker@evil.example", organizer: true, responseStatus: "accepted" },
      { email: "me@corp.example", self: true, responseStatus: "accepted" },
    ],
  };

  it("defers the attendee check of an attendees-only body", () => {
    expect(inspectEventPatch({ ...ON_PRIMARY, body: RSVP_BODY }, ENV)).toEqual({ decision: "allow" });
  });

  it("still applies the calendar allow-list to an attendees-only body", () => {
    const r = inspectEventPatch({ pathParams: { calendarId: "c_attacker@group.calendar.google.com" }, body: RSVP_BODY }, ENV);
    expect(r.reason).toBe("calendar-not-allowlisted");
  });

  it("checks attendees as inspectEventAttendees does when the body has any other key", () => {
    const r = inspectEventPatch({ ...ON_PRIMARY, body: { ...RSVP_BODY, description: "x" } }, ENV);
    expect(r).toMatchObject({ decision: "deny", reason: "external-attendee" });
  });

  it("matches inspectEventAttendees on every non-RSVP-shaped request", () => {
    const cases: InspectRequest[] = [
      { ...ON_PRIMARY, body: { summary: "x" } },
      { ...ON_PRIMARY, body: "x" },
      { ...ON_PRIMARY },
      { body: { summary: "x" } },
      { ...ON_PRIMARY, body: { focusTimeProperties: { declineMessage: "SECRET" } } },
      { ...ON_PRIMARY, body: { attendees: "not an array" } },
    ];
    for (const req of cases) {
      expect(inspectEventPatch(req, ENV), JSON.stringify(req)).toEqual(inspectEventAttendees(req, ENV));
    }
  });
});
