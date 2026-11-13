// F1-2d regression: events.move cannot hand an event to someone else's calendar.
//
// Attacker: a prompt-injected LLM in the user's own session.
// Precondition: an event on the user's calendar (its description may carry
//   mailbox content the model pasted in earlier).
// Payload: POST /calendar/v3/calendars/primary/events/{eventId}/move
//   ?destination=c_attacker@group.calendar.google.com&sendUpdates=all — the
//   destination calendar becomes the organiser, and its owner gets the event.
// Control: `inspectEventMove` requires both the source `calendarId` and the
//   `destination` query parameter to be on the deployment's calendar
//   allow-list (CALENDAR_WRITE_ALLOWLIST), and refuses any body.
// Pre-fix: events.move was a plain `allow` on the stated belief that it "moves
//   between the user's own calendars"; nothing checked the destination.
import { describe, it, expect } from "vitest";
import type { InspectRequest } from "@local/shared";
import { inspectEventMove } from "../calendar-move";

const ENV = { CALENDAR_WRITE_ALLOWLIST: "primary,c_team@group.calendar.google.com" };
const ATTACKER = "c_attacker@group.calendar.google.com";

const move = (calendarId: string | undefined, destination: unknown, extra: Partial<InspectRequest> = {}): InspectRequest => ({
  ...(calendarId !== undefined ? { pathParams: { calendarId, eventId: "someEventId" } } : {}),
  query: { ...(destination !== undefined ? { destination: destination as string } : {}), sendUpdates: "all" },
  ...extra,
});

describe("inspectEventMove", () => {
  it("FIXED (F1-2d): a destination off the calendar allow-list is denied", () => {
    expect(inspectEventMove(move("primary", ATTACKER), ENV)).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "calendar-not-allowlisted",
    });
    expect(inspectEventMove(move("primary", ATTACKER), ENV).message).toContain(ATTACKER);
  });

  it("FIXED (F1-2d): a source calendar off the allow-list is denied", () => {
    const r = inspectEventMove(move(ATTACKER, "primary"), ENV);
    expect(r).toMatchObject({ decision: "deny", reason: "calendar-not-allowlisted" });
    expect(r.message).toContain(ATTACKER);
  });

  it("allows a move between two allow-listed calendars (ids compared case-insensitively)", () => {
    expect(inspectEventMove(move("primary", "C_Team@group.calendar.google.com"), ENV)).toEqual({ decision: "allow" });
    expect(inspectEventMove(move("c_team@group.calendar.google.com", "PRIMARY"), ENV)).toEqual({ decision: "allow" });
  });

  it("denies without CALENDAR_WRITE_ALLOWLIST (fail closed: primary is not implicit)", () => {
    for (const env of [undefined, {}, { CALENDAR_WRITE_ALLOWLIST: "" }]) {
      expect(inspectEventMove(move("primary", "primary"), env).reason).toBe("calendar-not-allowlisted");
    }
  });

  it("denies without pathParams (a unit probe cannot name the source calendar)", () => {
    expect(inspectEventMove(move(undefined, "primary"), ENV)).toMatchObject({
      decision: "deny",
      reason: "calendar-not-allowlisted",
    });
  });

  it.each([
    ["absent", undefined],
    ["empty", ""],
    ["a number", 42],
    ["a boolean", true],
  ])("denies a missing destination (%s) as move-no-destination", (_label, destination) => {
    expect(inspectEventMove(move("primary", destination), ENV)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "move-no-destination",
    });
  });

  it.each([
    ["a JSON body", { body: {} }],
    ["a null body", { body: null }],
    ["raw bytes", { rawBody: "x" }],
    ["multipart", { multipart: [{ name: "a", value: "b" }] }],
  ])("refuses %s (the request takes no body)", (_label, extra) => {
    expect(inspectEventMove(move("primary", "primary", extra as Partial<InspectRequest>), ENV)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "move-body-not-allowed",
    });
  });
});
