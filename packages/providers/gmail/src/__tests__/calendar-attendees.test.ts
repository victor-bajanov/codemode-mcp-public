// Tests for the Calendar event-write attendee allowlist inspector.

import { describe, it, expect } from "vitest";
import { inspectEventAttendees, MASS_INVITE_THRESHOLD } from "../inspectors/calendar-attendees";

describe("inspectEventAttendees", () => {
  it("allows an event with no attendees field (e.g. partial patch)", () => {
    expect(inspectEventAttendees({ body: { summary: "Focus time" } })).toMatchObject({
      decision: "allow",
    });
  });

  it("allows an empty attendees array", () => {
    expect(inspectEventAttendees({ body: { attendees: [] } })).toMatchObject({
      decision: "allow",
    });
  });

  it("allows attendees that are all on the allowlist", () => {
    const result = inspectEventAttendees({
      body: {
        attendees: [
          { email: "you@example.com" },
          { email: "adam@gmail.com" },
        ],
      },
    });
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("matches the allowlist case-insensitively", () => {
    expect(
      inspectEventAttendees({ body: { attendees: [{ email: "you@example.com" }] } }),
    ).toMatchObject({ decision: "allow" });
  });

  it("denies when any attendee is off the allowlist", () => {
    const result = inspectEventAttendees({
      body: {
        attendees: [
          { email: "you@example.com" },
          { email: "stranger@evil.example" },
        ],
      },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "external-attendee",
    });
  });

  it("off-allowlist wins over mass-invite", () => {
    const attendees = Array.from({ length: MASS_INVITE_THRESHOLD + 5 }, (_, i) => ({
      email: i === 0 ? "stranger@evil.example" : `user${i}@example.com`,
    }));
    expect(inspectEventAttendees({ body: { attendees } })).toMatchObject({
      decision: "deny",
      reason: "external-attendee",
    });
  });

  it("elicits a mass-invite when all attendees are on-allowlist but exceed the threshold", () => {
    // Distinct addresses on the wildcard-allowlisted domain so dedup keeps them all.
    const attendees = Array.from({ length: MASS_INVITE_THRESHOLD + 1 }, (_, i) => ({
      email: `user${i}@example.com`,
    }));
    const result = inspectEventAttendees({ body: { summary: "All hands", attendees } });
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
    expect(inspectEventAttendees({ body: { attendees } })).toMatchObject({ decision: "allow" });
  });

  it("skips resource attendees (meeting rooms) when checking the allowlist", () => {
    const result = inspectEventAttendees({
      body: {
        attendees: [
          { email: "you@example.com" },
          { email: "room-101@resource.calendar.google.com", resource: true },
        ],
      },
    });
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("allows a non-object body (nothing to gate)", () => {
    expect(inspectEventAttendees({ body: undefined })).toMatchObject({ decision: "allow" });
  });
});
