import type { InspectEnv, InspectRequest, InspectResult } from "@local/shared";
import { isAllowedRecipient, isPlainAddrSpec, outboundAllowlistFromEnv } from "./allowlist.js";

/** Strictly-greater-than threshold for mass-invite elicitation. 26+ attendees elicits.
 *  Mirrors the outbound mail MASS_SEND_THRESHOLD. */
export const MASS_INVITE_THRESHOLD = 25;

/** Domain of Google Workspace room and equipment calendars. */
const GOOGLE_RESOURCE_CALENDAR_DOMAIN = "@resource.calendar.google.com";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * True for a Google Workspace room/equipment calendar: flagged
 * `resource: true` AND addressed at exactly `resource.calendar.google.com`.
 * The caller sets `resource` when it adds an attendee, so the flag alone
 * proves nothing — trusting it let any external address skip the allowlist
 * (F-9). Subdomains and look-alikes do not match.
 */
function isGoogleResourceCalendar(attendee: Record<string, unknown>, email: string): boolean {
  return (
    attendee["resource"] === true &&
    email.endsWith(GOOGLE_RESOURCE_CALENDAR_DOMAIN) &&
    isPlainAddrSpec(email)
  );
}

/**
 * Extract attendee email addresses from a Calendar Event resource body.
 * Returns deduplicated, lowercase-normalised addresses. Google Workspace
 * room/equipment calendars (`resource: true` and an address at
 * `resource.calendar.google.com`) are skipped — they are not outbound human
 * recipients. Every other attendee, flagged `resource` or not, is collected.
 * Returns an empty array when there is no `attendees` array (e.g. partial
 * patch that does not touch attendees).
 */
function extractAttendees(body: Record<string, unknown>): string[] {
  const attendees = body["attendees"];
  if (!Array.isArray(attendees)) return [];
  const collected: string[] = [];
  for (const a of attendees) {
    if (!isObject(a)) continue;
    const email = a["email"];
    if (typeof email !== "string") continue;
    const norm = email.trim().toLowerCase();
    if (norm.length === 0) continue;
    if (isGoogleResourceCalendar(a, norm)) continue;
    collected.push(norm);
  }
  return Array.from(new Set(collected));
}

/**
 * Inspector for Calendar event writes that can email invitations to attendees:
 * events.insert, events.update, events.patch, events.import. Gates attendee
 * addresses through the same per-deployment allowlist as outbound Gmail
 * (OUTBOUND_RECIPIENT_ALLOWLIST var; missing env/var → empty list, so any
 * attendee denies), so the agent cannot invite — and thereby email / leak
 * event details to — arbitrary external addresses.
 *
 * Decision flow (parallel to inspectOutboundMessage):
 *   0. A payload that is not a JSON object (raw bytes, multipart, or a parsed
 *      body that is a string, number or array) → deny / malformed /
 *      event-body-not-object. The attendees in such a payload cannot be read
 *      here, yet the upstream may still parse it (F-7). Only a request with
 *      no payload at all passes this step.
 *   1. No `attendees` → allow (no invitees introduced; partial updates that
 *      don't touch attendees are unaffected).
 *   2. No usable attendee emails once Google room/equipment calendars
 *      (`resource: true` at `resource.calendar.google.com`) are set aside →
 *      allow. A `resource: true` attendee at any other address is checked
 *      like everyone else.
 *   3. Any attendee off the allowlist → deny / external_data_flow /
 *      external-attendee. (Off-allowlist wins, regardless of `sendUpdates`: an
 *      off-list attendee on the event record is the exfiltration concern.)
 *   4. Attendee count > MASS_INVITE_THRESHOLD → elicit / external_data_flow /
 *      mass-invite, with a primitives-only summary.
 *   5. Otherwise → allow.
 */
export function inspectEventAttendees(req: InspectRequest, env?: InspectEnv): InspectResult {
  const body = req.body;
  if (!isObject(body) || Array.isArray(body)) {
    const noPayload = body === undefined && req.rawBody === undefined && req.multipart === undefined;
    if (noPayload) return { decision: "allow" };
    return {
      decision: "deny",
      category: "malformed",
      reason: "event-body-not-object",
      message:
        "Calendar event writes must send the event as a JSON object in `body` " +
        "(no bodyBase64, rawBody or multipart), so its attendees can be checked.",
    };
  }

  const attendees = extractAttendees(body);
  if (attendees.length === 0) return { decision: "allow" };

  const allowlist = outboundAllowlistFromEnv(env);
  for (const a of attendees) {
    if (!isAllowedRecipient(a, allowlist)) {
      return {
        decision: "deny",
        category: "external_data_flow",
        reason: "external-attendee",
      };
    }
  }

  if (attendees.length > MASS_INVITE_THRESHOLD) {
    const summary = typeof body["summary"] === "string" ? body["summary"] : "";
    return {
      decision: "elicit",
      category: "external_data_flow",
      reason: "mass-invite",
      summary: {
        attendees:
          attendees.slice(0, 3).join(", ") +
          (attendees.length > 3 ? ` (+${attendees.length - 3})` : ""),
        summary: summary.slice(0, 200),
        count: attendees.length,
      },
    };
  }

  return { decision: "allow" };
}
