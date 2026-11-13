import type { InspectEnv, InspectRequest, InspectResult } from "@local/shared";
import { isAllowedRecipient, isPlainAddrSpec, outboundAllowlistFromEnv } from "./allowlist.js";
import { calendarDecision } from "./calendar-allowlist.js";
import { firstThree, isJsonObject } from "./outbound.js";

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
 * (F-9). Subdomains and look-alikes do not match. `email` must already be
 * trimmed and lower-cased.
 */
export function isGoogleResourceCalendar(attendee: Record<string, unknown>, email: string): boolean {
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

// ---------------------------------------------------------------------------
// Auto-decline message (F1-2c)
// ---------------------------------------------------------------------------

/** Both spellings Google accepts (JSON name and proto name). */
const DECLINE_PROPERTY_KEYS = [
  "outOfOfficeProperties",
  "out_of_office_properties",
  "focusTimeProperties",
  "focus_time_properties",
] as const;
const DECLINE_MESSAGE_KEYS = ["declineMessage", "decline_message"] as const;

/** Calendar emails an outOfOffice / focusTime `declineMessage` to the
 *  organiser of every conflicting invitation: a channel to outsiders the
 *  agent has no legitimate need to author. Absent, `null` and `""` pass; any
 *  other value (a non-string included) denies. */
function declineMessageDecision(body: Record<string, unknown>): InspectResult | null {
  for (const propsKey of DECLINE_PROPERTY_KEYS) {
    const props = body[propsKey];
    if (!isObject(props)) continue;
    for (const key of DECLINE_MESSAGE_KEYS) {
      if (!Object.hasOwn(props, key)) continue;
      const value = (props as Record<string, unknown>)[key];
      if (value === null || value === "") continue;
      return {
        decision: "deny",
        category: "external_data_flow",
        reason: "event-decline-message",
        message:
          "The event's auto-decline message would be emailed by Calendar to the organiser of every " +
          "conflicting invitation; omit declineMessage.",
      };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Event facts for the approval dialog
// ---------------------------------------------------------------------------

/** `dateTime` when a string, else `date` when a string, else undefined. */
export function eventTime(value: unknown): string | undefined {
  if (!isObject(value)) return undefined;
  const dateTime = value["dateTime"];
  if (typeof dateTime === "string") return dateTime;
  const date = value["date"];
  return typeof date === "string" ? date : undefined;
}

/** summary / start / end as written in the request body, and `organizer`
 *  only when `withOrganizer` (events.import, where Calendar keeps the
 *  imported organiser; on insert Calendar sets it itself, and update/patch
 *  show the stored one). Keys omitted when absent or not strings. */
function eventFacts(body: Record<string, unknown>, withOrganizer: boolean): Record<string, string> {
  const facts: Record<string, string> = {};
  const organizer = body["organizer"];
  if (withOrganizer && isObject(organizer) && typeof organizer["email"] === "string") {
    facts["organizer"] = organizer["email"];
  }
  if (typeof body["summary"] === "string") facts["summary"] = body["summary"];
  const start = eventTime(body["start"]);
  if (start !== undefined) facts["start"] = start;
  const end = eventTime(body["end"]);
  if (end !== undefined) facts["end"] = end;
  return facts;
}

// ---------------------------------------------------------------------------
// Attendee allowlist
// ---------------------------------------------------------------------------

/**
 * The attendee check of a request body: null when it has nothing to object
 * to; deny/external_data_flow/external-attendee when any attendee (rooms
 * aside) is off OUTBOUND_RECIPIENT_ALLOWLIST (missing env/var → empty list,
 * so any attendee denies; off-allowlist wins over mass-invite, whatever
 * `sendUpdates` says); elicit/external_data_flow/mass-invite past
 * MASS_INVITE_THRESHOLD, with a primitives-only summary.
 */
export function attendeeDecision(body: Record<string, unknown>, env?: InspectEnv): InspectResult | null {
  const attendees = extractAttendees(body);
  if (attendees.length === 0) return null;

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
        attendees: firstThree(attendees),
        summary,
        count: attendees.length,
      },
    };
  }
  return null;
}

/** A patch body whose only key is an `attendees` array: the RSVP shape, which
 *  only the stored event can judge (see inspectStoredEventPatch). */
export function isAttendeesOnlyBody(body: unknown): body is { attendees: unknown[] } {
  if (!isJsonObject(body)) return false;
  const keys = Object.keys(body);
  return keys.length === 1 && keys[0] === "attendees" && Array.isArray(body["attendees"]);
}

interface WriteOptions {
  /** events.patch: defer the attendee check of an attendees-only body. */
  deferAttendeesOnly: boolean;
  /** events.import: show the body's organiser in the dialog. */
  withOrganizer: boolean;
}

function inspectEventWrite(req: InspectRequest, env: InspectEnv | undefined, opts: WriteOptions): InspectResult {
  const body = req.body;
  const noPayload = body === undefined && req.rawBody === undefined && req.multipart === undefined;
  if (!noPayload && !isJsonObject(body)) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "event-body-not-object",
      message:
        "Calendar event writes must send the event as a JSON object in `body` " +
        "(no bodyBase64, rawBody or multipart), so its attendees can be checked.",
    };
  }

  const calendarDeny = calendarDecision(req.pathParams?.["calendarId"], env);
  if (calendarDeny) return calendarDeny;
  if (!isJsonObject(body)) return { decision: "allow" };

  const declineDeny = declineMessageDecision(body);
  if (declineDeny) return declineDeny;

  const facts = eventFacts(body, opts.withOrganizer);
  const attendees = opts.deferAttendeesOnly && isAttendeesOnlyBody(body) ? null : attendeeDecision(body, env);
  if (attendees?.decision === "deny") return attendees;
  if (attendees?.decision === "elicit") {
    return { ...attendees, summary: { ...facts, ...attendees.summary } };
  }
  return Object.keys(facts).length > 0 ? { decision: "allow", summary: facts } : { decision: "allow" };
}

/**
 * Inspector for Calendar event writes that can email invitations to attendees:
 * events.insert and events.update (events.patch uses `inspectEventPatch`,
 * events.import `inspectEventImport`). Gates the target calendar through the deployment's
 * calendar allow-list (CALENDAR_WRITE_ALLOWLIST) and attendee addresses
 * through the same per-deployment allowlist as outbound Gmail
 * (OUTBOUND_RECIPIENT_ALLOWLIST var), so the agent cannot write mailbox
 * content into — or invite — anyone else's calendar.
 *
 * Decision flow:
 *   0. A payload that is not a JSON object (raw bytes, multipart, or a parsed
 *      body that is a string, number or array) → deny / malformed /
 *      event-body-not-object. The attendees in such a payload cannot be read
 *      here, yet the upstream may still parse it (F-7).
 *   1. The `calendarId` path parameter missing (a unit probe) or not on the
 *      calendar allow-list (unset var → empty list) → deny /
 *      external_data_flow / calendar-not-allowlisted (F1-2a). A request with
 *      no payload at all is then allowed.
 *   2. An outOfOffice / focusTime `declineMessage` (either spelling) that is
 *      not null or "" → deny / external_data_flow / event-decline-message
 *      (F1-2c).
 *   3. Any attendee off the outbound allowlist → deny / external_data_flow /
 *      external-attendee; more than MASS_INVITE_THRESHOLD → elicit /
 *      external_data_flow / mass-invite. Google room/equipment calendars are
 *      exempt.
 *   4. Otherwise allow, with the event's summary / start / end (and, on
 *      import, organizer) as `summary` (read only by an approval dialog:
 *      events.import's static elicit, or a mass invite).
 */
export function inspectEventAttendees(req: InspectRequest, env?: InspectEnv): InspectResult {
  return inspectEventWrite(req, env, { deferAttendeesOnly: false, withOrganizer: false });
}

/**
 * events.patch: `inspectEventAttendees`, except that the attendee check of an
 * attendees-only body (the RSVP shape) is deferred to the paired
 * `inspectUpstream` hook, `inspectStoredEventPatch`, which always runs after
 * a non-deny and applies the same check on the user's own event. Only safe
 * on an entry that carries that hook.
 */
export function inspectEventPatch(req: InspectRequest, env?: InspectEnv): InspectResult {
  return inspectEventWrite(req, env, { deferAttendeesOnly: true, withOrganizer: false });
}

/**
 * events.import: `inspectEventAttendees`, plus the body's `organizer` among
 * the dialog facts. An imported event keeps the organiser it is given, so
 * the approval dialog must show it.
 */
export function inspectEventImport(req: InspectRequest, env?: InspectEnv): InspectResult {
  return inspectEventWrite(req, env, { deferAttendeesOnly: false, withOrganizer: true });
}
