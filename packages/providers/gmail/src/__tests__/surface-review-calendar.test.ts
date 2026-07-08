// Decision invariants for the Google Calendar entries on the Gmail provider's
// surface review. The shared providerSurfaceReviewTests battery
// (surface-review-keys-match-spec.test.ts) already asserts every key maps to a
// real merged-spec operationId and that deny entries carry reasoning; this file
// pins the specific Calendar tiering choices.

import { describe, it, expect } from "vitest";
import { surfaceReview } from "../surface-review";
import { inspectEventAttendees } from "../inspectors/calendar-attendees";

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
    for (const id of ["calendar.events.insert", "calendar.events.update", "calendar.events.patch"]) {
      const entry = surfaceReview[id];
      expect(entry?.decision, id).toBe("allow");
      expect(entry?.inspect, id).toBe(inspectEventAttendees);
    }
  });

  it("allows attendee-free event writes without an inspector", () => {
    for (const id of ["calendar.events.move", "calendar.events.quickAdd"]) {
      const entry = surfaceReview[id];
      expect(entry?.decision, id).toBe("allow");
      expect(entry?.category, id).toBe("standard_write");
      expect(entry?.inspect, id).toBeUndefined();
    }
  });

  it("elicits on import (external data) and delete (irreversible)", () => {
    expect(surfaceReview["calendar.events.import"]).toMatchObject({
      decision: "elicit",
      category: "external_data_flow",
    });
    // import also carries the attendee inspector so off-allowlist invitees escalate to deny
    expect(surfaceReview["calendar.events.import"]?.inspect).toBe(inspectEventAttendees);
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
