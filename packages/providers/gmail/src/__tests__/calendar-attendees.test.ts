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

  it("denies an external address flagged resource: true (F-9)", () => {
    const result = inspectEventAttendees(
      {
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
      { body: { attendees: [{ email: "room-101@resource.calendar.google.com" }] } },
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
      const result = inspectEventAttendees({ body: { attendees: [{ email, resource: true }] } }, ENV);
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
    expect(inspectEventAttendees({ body: { attendees } }, ENV)).toMatchObject({ decision: "allow" });
  });

  it("allows a request with no payload at all (nothing to gate)", () => {
    expect(inspectEventAttendees({ body: undefined }, ENV)).toMatchObject({ decision: "allow" });
    expect(inspectEventAttendees({ query: { sendUpdates: "all" } }, ENV)).toMatchObject({ decision: "allow" });
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
    expect(inspectEventAttendees(req, ENV)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "event-body-not-object",
    });
  });
});
