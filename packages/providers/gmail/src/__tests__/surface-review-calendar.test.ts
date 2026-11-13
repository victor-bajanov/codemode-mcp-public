// Decision invariants for the Google Calendar entries on the Gmail provider's
// surface review. The shared providerSurfaceReviewTests battery
// (surface-review-keys-match-spec.test.ts) already asserts every key maps to a
// real merged-spec operationId and that deny entries carry reasoning; this file
// pins the specific Calendar tiering choices.

import { describe, it, expect } from "vitest";
import { surfaceReview } from "../surface-review";
import { inspectEventAttendees, inspectEventImport, inspectEventPatch } from "../inspectors/calendar-attendees";
import { inspectStoredEvent, inspectStoredEventPatch } from "../inspectors/calendar-stored-event";
import { inspectEventMove } from "../inspectors/calendar-move";

describe("calendar surface-review tiering", () => {
  it("exposes the read surface as allow/standard_read", () => {
    const reads = [
      "calendar.calendarList.list",
      "calendar.calendarList.get",
      "calendar.calendars.get",
      "calendar.events.list",
      "calendar.events.get",
      "calendar.events.instances",
      "calendar.freebusy.query",
      "calendar.colors.get",
      "calendar.settings.get",
      "calendar.settings.list",
    ];
    for (const id of reads) {
      expect(surfaceReview[id], id).toMatchObject({ decision: "allow", category: "standard_read" });
    }
  });

  it("gates attendee-bearing event writes with the attendee inspector", () => {
    for (const id of ["calendar.events.insert", "calendar.events.update"]) {
      const entry = surfaceReview[id];
      expect(entry?.decision, id).toBe("allow");
      expect(entry?.inspect, id).toBe(inspectEventAttendees);
    }
    // patch defers an attendees-only (RSVP-shaped) body to its upstream hook.
    expect(surfaceReview["calendar.events.patch"]?.decision).toBe("allow");
    expect(surfaceReview["calendar.events.patch"]?.inspect).toBe(inspectEventPatch);
  });

  it("FIXED (F1-2b): update and patch read the stored event before deciding; insert does not", () => {
    expect(surfaceReview["calendar.events.update"]?.inspectUpstream).toBe(inspectStoredEvent);
    expect(surfaceReview["calendar.events.patch"]?.inspectUpstream).toBe(inspectStoredEventPatch);
    expect(surfaceReview["calendar.events.insert"]?.inspectUpstream).toBeUndefined();
    expect(surfaceReview["calendar.events.import"]?.inspectUpstream).toBeUndefined();
  });

  it("FIXED (F1-2d): events.move is inspected (source and destination calendars allow-listed)", () => {
    const entry = surfaceReview["calendar.events.move"];
    expect(entry?.decision).toBe("allow");
    expect(entry?.inspect).toBe(inspectEventMove);
    expect(entry?.clientNote).toMatch(/CALENDAR_WRITE_ALLOWLIST/);
  });

  it("FIXED (F1-2e): events.quickAdd is denied outright, with reasoning and no note", () => {
    const entry = surfaceReview["calendar.events.quickAdd"];
    expect(entry).toMatchObject({ decision: "deny", category: "external_data_flow" });
    expect(entry?.reasoning).toMatch(/events\.insert/);
    expect(entry?.inspect).toBeUndefined();
    expect(entry?.clientNote).toBeUndefined();
  });

  // The hook reads through calendar.events.get, which must stay a plain allow
  // (the lookup refuses anything else and the write is then denied).
  it("the stored-event read is a plain-allow GET", () => {
    const get = surfaceReview["calendar.events.get"];
    expect(get).toEqual({ decision: "allow", category: "standard_read" });
  });

  it("elicits on import (external data) and delete (irreversible)", () => {
    expect(surfaceReview["calendar.events.import"]).toMatchObject({
      decision: "elicit",
      category: "external_data_flow",
    });
    // import also carries the attendee inspector so off-allowlist invitees escalate to deny
    expect(surfaceReview["calendar.events.import"]?.inspect).toBe(inspectEventImport);
    expect(surfaceReview["calendar.events.delete"]).toMatchObject({
      decision: "elicit",
      category: "irreversible",
    });
  });

  it("denies calendar sharing (acl.*) as capability escalation", () => {
    for (const id of [
      "calendar.acl.list",
      "calendar.acl.get",
      "calendar.acl.insert",
      "calendar.acl.update",
      "calendar.acl.patch",
      "calendar.acl.delete",
      "calendar.acl.watch",
    ]) {
      expect(surfaceReview[id], id).toMatchObject({
        decision: "deny",
        category: "capability_escalation",
      });
    }
  });

  it("denies destructive calendar lifecycle ops", () => {
    expect(surfaceReview["calendar.calendars.delete"]).toMatchObject({
      decision: "deny",
      category: "irreversible",
    });
    expect(surfaceReview["calendar.calendars.clear"]).toMatchObject({
      decision: "deny",
      category: "bulk_destructive",
    });
  });

  it("leaves out-of-scope ops implicitly denied (not listed)", () => {
    for (const id of [
      "calendar.calendars.insert",
      "calendar.calendars.update",
      "calendar.calendarList.insert",
      "calendar.calendarList.delete",
      "calendar.events.watch",
      "calendar.channels.stop",
    ]) {
      expect(surfaceReview[id], id).toBeUndefined();
    }
  });
});
