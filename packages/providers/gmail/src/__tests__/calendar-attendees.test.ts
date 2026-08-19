// Tests for the Calendar event-write attendee allowlist inspector.

import { describe, it, expect } from "vitest";
import { inspectEventAttendees, MASS_INVITE_THRESHOLD } from "../inspectors/calendar-attendees";

// Mirrors the prod (gmail/gmail-dev) wrangler var.
const ENV = {
  OUTBOUND_RECIPIENT_ALLOWLIST: "*@example.com,adam@gmail.com",
};

describe("inspectEventAttendees", () => {
  it("allows an event with no attendees field (e.g. partial patch) — even without env", () => {
    // Attendee-less writes never consult the allowlist, so a deployment with
    // no OUTBOUND_RECIPIENT_ALLOWLIST var can still manage its own events.
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
    const result = inspectEventAttendees(
      {
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
        { body: { attendees: [{ email: "you@example.com" }] } },
        ENV,
      ),
    ).toMatchObject({ decision: "allow" });
  });

  it("denies when any attendee is off the allowlist", () => {
    const result = inspectEventAttendees(
      {
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

  it("denies every attendee when no env is passed (fail closed)", () => {
    expect(
      inspectEventAttendees({ body: { attendees: [{ email: "you@example.com" }] } }),
    ).toMatchObject({ decision: "deny", reason: "external-attendee" });
  });

  it("resolves the allowlist per deployment (a tester deployment invites its own contacts)", () => {
    const testerEnv = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@tester.example" };
    expect(
      inspectEventAttendees({ body: { attendees: [{ email: "pal@tester.example" }] } }, testerEnv),
    ).toMatchObject({ decision: "allow" });
    expect(
      inspectEventAttendees(
        { body: { attendees: [{ email: "you@example.com" }] } },
        testerEnv,
      ),
    ).toMatchObject({ decision: "deny", reason: "external-attendee" });
  });

  it("off-allowlist wins over mass-invite", () => {
    const attendees = Array.from({ length: MASS_INVITE_THRESHOLD + 5 }, (_, i) => ({
      email: i === 0 ? "stranger@evil.example" : `user${i}@example.com`,
    }));
    expect(inspectEventAttendees({ body: { attendees } }, ENV)).toMatchObject({
      decision: "deny",
      reason: "external-attendee",
    });
  });

  it("elicits a mass-invite when all attendees are on-allowlist but exceed the threshold", () => {
    // Distinct addresses on the wildcard-allowlisted domain so dedup keeps them all.
    const attendees = Array.from({ length: MASS_INVITE_THRESHOLD + 1 }, (_, i) => ({
      email: `user${i}@example.com`,
    }));
    const result = inspectEventAttendees({ body: { summary: "All hands", attendees } }, ENV);
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
    expect(inspectEventAttendees({ body: { attendees } }, ENV)).toMatchObject({ decision: "allow" });
  });

  it("skips resource attendees (meeting rooms) when checking the allowlist", () => {
    const result = inspectEventAttendees(
      {
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

  it("allows a non-object body (nothing to gate)", () => {
    expect(inspectEventAttendees({ body: undefined }, ENV)).toMatchObject({ decision: "allow" });
  });
});
