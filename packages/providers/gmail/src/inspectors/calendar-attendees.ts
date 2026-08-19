import type { InspectEnv, InspectRequest, InspectResult } from "@local/shared";
import { isAllowedRecipient, outboundAllowlistFromEnv } from "./allowlist.js";

/** Strictly-greater-than threshold for mass-invite elicitation. 26+ attendees elicits.
 *  Mirrors the outbound mail MASS_SEND_THRESHOLD. */
export const MASS_INVITE_THRESHOLD = 25;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Extract attendee email addresses from a Calendar Event resource body.
 * Returns deduplicated, lowercase-normalized addresses. Resource attendees
 * (`attendee.resource === true`, e.g. meeting rooms) are skipped — they are not
 * outbound human recipients. Returns an empty array when there is no
 * `attendees` array (e.g. partial patch that does not touch attendees).
 */
function extractAttendees(body: Record<string, unknown>): string[] {
  const attendees = body["attendees"];
  if (!Array.isArray(attendees)) return [];
  const collected: string[] = [];
  for (const a of attendees) {
    if (!isObject(a)) continue;
    if (a["resource"] === true) continue;
    const email = a["email"];
    if (typeof email === "string" && email.trim().length > 0) {
      collected.push(email.trim().toLowerCase());
    }
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
 *   1. Body not an object, or no `attendees` → allow (no invitees introduced;
 *      partial updates that don't touch attendees are unaffected).
 *   2. No usable attendee emails → allow.
 *   3. Any attendee off the allowlist → deny / external_data_flow /
 *      external-attendee. (Off-allowlist wins, regardless of `sendUpdates`: an
 *      off-list attendee on the event record is the exfiltration concern.)
 *   4. Attendee count > MASS_INVITE_THRESHOLD → elicit / external_data_flow /
 *      mass-invite, with a primitives-only summary.
 *   5. Otherwise → allow.
 */
export function inspectEventAttendees(req: InspectRequest, env?: InspectEnv): InspectResult {
  const body = req.body;
  if (!isObject(body)) return { decision: "allow" };

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
