import type { InspectEnv, InspectRequest, InspectResult } from "@local/shared";
import { calendarDecision } from "./calendar-allowlist.js";

/**
 * Inspector for calendar.events.move (F1-2d). A move makes the destination
 * calendar the event's organiser, so it is only safe between calendars the
 * user owns: both the source `calendarId` path parameter and the
 * `destination` query parameter must be on CALENDAR_WRITE_ALLOWLIST.
 *
 *   1. any payload (the operation takes none) → deny/malformed/move-body-not-allowed;
 *   2. `destination` not a non-empty string → deny/malformed/move-no-destination;
 *   3. source or destination off the calendar allow-list (unset → empty; a
 *      missing source, as in a unit probe, denies) →
 *      deny/external_data_flow/calendar-not-allowlisted, naming the id;
 *   4. otherwise allow.
 */
export function inspectEventMove(req: InspectRequest, env?: InspectEnv): InspectResult {
  if (req.body !== undefined || req.rawBody !== undefined || req.multipart !== undefined) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "move-body-not-allowed",
      message: "calendar.events.move takes no body; pass the target calendar as the `destination` query parameter.",
    };
  }
  const destination = req.query?.["destination"];
  if (typeof destination !== "string" || destination.length === 0) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "move-no-destination",
      message: "calendar.events.move needs the target calendar id in the `destination` query parameter.",
    };
  }
  return (
    calendarDecision(req.pathParams?.["calendarId"], env) ??
    calendarDecision(destination, env) ?? { decision: "allow" }
  );
}
