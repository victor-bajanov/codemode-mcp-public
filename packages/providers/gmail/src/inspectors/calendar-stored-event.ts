import type { InspectEnv, InspectRequest, InspectResult, UpstreamLookup } from "@local/shared";
import { encodeLookupPath } from "@local/shared";
import { isAllowedRecipient, outboundAllowlistFromEnv } from "./allowlist.js";
import { attendeeDecision, eventTime, isAttendeesOnlyBody, isGoogleResourceCalendar } from "./calendar-attendees.js";
import { firstThree, isJsonObject } from "./outbound.js";

// F1-2b: `inspectUpstream` hooks for calendar.events.update / .patch. The
// sync inspector sees only the request; whether the user organises the event,
// and who its guests already are, is upstream state. These hooks read the
// stored event through the host's lookup (a plain-allow GET of
// calendar.events.get, same request handler, never the sandbox) and decide.

const NOT_ORGANISED: InspectResult = {
  decision: "deny",
  category: "external_data_flow",
  reason: "event-not-organised-by-user",
  message:
    "This event is organised by someone else; edits to it propagate to the organiser. Only events the " +
    "user organises can be updated here.",
};

/** The values events.patch may set on the user's own attendee entry (§9 RSVP). */
const RSVP_STATUSES: ReadonlySet<string> = new Set(["accepted", "declined", "tentative", "needsAction"]);

/** Attendee keys that carry free text or numbers to the organiser; never
 *  accepted on the RSVP path, even unchanged. */
const RSVP_FORBIDDEN_KEYS = ["comment", "additionalGuests"] as const;

/** calendar.events.get, a plain-allow read (surface-review.ts). */
const STORED_EVENT_PATH = "/calendar/v3/calendars/{calendarId}/events/{eventId}";

type Stored = Record<string, unknown>;

/** Read the stored event, or the deny that stands instead. */
type Read = { stored: Stored } | { deny: InspectResult };

async function readStoredEvent(req: InspectRequest, lookup: UpstreamLookup): Promise<Read> {
  const calendarId = req.pathParams?.["calendarId"];
  const eventId = req.pathParams?.["eventId"];
  if (typeof calendarId !== "string" || calendarId.length === 0 || typeof eventId !== "string" || eventId.length === 0) {
    return {
      deny: {
        decision: "deny",
        category: "malformed",
        reason: "event-path-params-missing",
        message: "Cannot tell which stored event this write targets (calendarId and eventId are required).",
      },
    };
  }
  // pathParams are decoded; the lookup takes an encoded path, so every
  // segment is percent-encoded and the read targets exactly the event the
  // write does. The sandbox's query (e.g. `maxAttendees`) is never forwarded.
  const r = await lookup.get(encodeLookupPath(STORED_EVENT_PATH, { calendarId, eventId }));
  if (r.status === 404) {
    const notFound: InspectResult = {
      decision: "deny",
      category: "malformed",
      reason: "event-not-found",
      message: "The event to update was not found in that calendar.",
    };
    return { deny: notFound };
  }
  if (r.status < 200 || r.status > 299) {
    const failed: InspectResult = {
      decision: "deny",
      category: "malformed",
      reason: "event-read-failed",
      message: `Reading the stored event before the update failed (upstream status ${r.status}).`,
    };
    return { deny: failed };
  }
  const stored = r.body;
  if (!isJsonObject(stored)) return { deny: NOT_ORGANISED };
  return { stored };
}

function organisedByUser(stored: Stored): boolean {
  const organizer = stored["organizer"];
  return isJsonObject(organizer) && organizer["self"] === true;
}

/** JSON structural equality: same own keys, same values, arrays in order. */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((x, i) => deepEqual(x, b[i]));
  }
  if (!isJsonObject(a) || !isJsonObject(b)) return false;
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => Object.hasOwn(b, k) && deepEqual(a[k], b[k]));
}

/** Index of the user's own entry in the stored attendee list: the one entry
 *  marked `self: true`, or whose email equals the user's address as the
 *  stored event shows it (`creator.self`). -1 unless exactly one matches. */
function selfIndex(stored: Stored, attendees: readonly unknown[]): number {
  const creator = stored["creator"];
  const selfAddress =
    isJsonObject(creator) && creator["self"] === true && typeof creator["email"] === "string"
      ? creator["email"].trim().toLowerCase()
      : undefined;
  const matches: number[] = [];
  attendees.forEach((a, i) => {
    if (!isJsonObject(a)) return;
    const email = typeof a["email"] === "string" ? a["email"].trim().toLowerCase() : undefined;
    if (a["self"] === true || (selfAddress !== undefined && email === selfAddress)) matches.push(i);
  });
  return matches.length === 1 ? matches[0]! : -1;
}

/**
 * §9: on an event someone else organises, events.patch may still RSVP. The
 * body must be exactly `{ attendees }`, equal to the stored list (same
 * entries, same order, each identical) except the user's own entry, which
 * may differ only in `responseStatus`, set to one of RSVP_STATUSES. No
 * `comment` / `additionalGuests` on that entry, not even unchanged: those
 * carry text and numbers to the organiser; the status is a closed enum.
 */
function isNarrowRsvp(body: unknown, stored: Stored): boolean {
  if (stored["attendeesOmitted"] === true) return false;
  if (!isAttendeesOnlyBody(body)) return false;
  const want = body.attendees;
  const have = stored["attendees"];
  if (!Array.isArray(have) || have.length !== want.length) return false;
  const me = selfIndex(stored, have);
  if (me < 0) return false;
  for (let i = 0; i < have.length; i++) {
    if (i === me) continue;
    if (!deepEqual(want[i], have[i])) return false;
  }
  const mine = want[me];
  const was = have[me];
  if (!isJsonObject(mine) || !isJsonObject(was)) return false;
  for (const k of RSVP_FORBIDDEN_KEYS) if (Object.hasOwn(mine, k)) return false;
  const status = mine["responseStatus"];
  if (typeof status !== "string" || !RSVP_STATUSES.has(status)) return false;
  const { responseStatus: _a, ...mineRest } = mine;
  const { responseStatus: _b, ...wasRest } = was;
  return deepEqual(mineRest, wasRest);
}

/** Stored guests off the outbound allowlist. Strict, unlike the request
 *  inspector (F1-2f leniency is for request bodies only): an entry that is
 *  not an object or has no non-empty string email counts as outside. The
 *  user's own entry and Google rooms are skipped. */
function outsideGuests(stored: Stored, env?: InspectEnv): string[] {
  const attendees = stored["attendees"];
  if (!Array.isArray(attendees)) return [];
  const allowlist = outboundAllowlistFromEnv(env);
  const outside: string[] = [];
  for (const a of attendees) {
    if (!isJsonObject(a)) {
      outside.push("(unreadable guest)");
      continue;
    }
    if (a["self"] === true) continue;
    const email = a["email"];
    if (typeof email !== "string" || email.trim().length === 0) {
      outside.push("(unreadable guest)");
      continue;
    }
    const norm = email.trim().toLowerCase();
    if (isGoogleResourceCalendar(a, norm)) continue;
    if (!isAllowedRecipient(norm, allowlist)) outside.push(norm);
  }
  return Array.from(new Set(outside));
}

/** A value the body sets, as dialog text: a string as is, anything else as JSON. */
function shown(value: unknown): string {
  return typeof value === "string" ? value : (JSON.stringify(value) ?? String(value));
}

/**
 * The dialog facts for an update/patch, returned on every non-deny with every
 * key set (so whatever the sync inspector put under these keys is overridden
 * in the request handler's merge):
 *   - `organizer` from the STORED event (who owns it and is notified; a body
 *     `organizer` is never shown);
 *   - `summary`, `start`, `end` from the BODY when it sets them (what the
 *     event will say after the write), else the stored ones;
 *   - `changes`: the body's top-level keys, sorted (what the write touches,
 *     e.g. "description, summary"; "" for an empty body).
 * Outside `guests` are added by the caller when there are any.
 */
function dialogFacts(stored: Stored, body: unknown): Record<string, string> {
  const b = isJsonObject(body) ? body : {};
  const pick = (key: "summary" | "start" | "end"): string => {
    if (Object.hasOwn(b, key)) {
      const v = b[key];
      return key === "summary" ? shown(v) : (eventTime(v) ?? shown(v));
    }
    const s = stored[key];
    if (key === "summary") return typeof s === "string" ? s : "";
    return eventTime(s) ?? "";
  };
  const organizer = stored["organizer"];
  return {
    organizer: isJsonObject(organizer) && typeof organizer["email"] === "string" ? organizer["email"] : "",
    summary: pick("summary"),
    start: pick("start"),
    end: pick("end"),
    changes: Object.keys(b).sort().join(", "),
  };
}

async function inspectStored(
  req: InspectRequest,
  lookup: UpstreamLookup,
  env: InspectEnv | undefined,
  isPatch: boolean,
): Promise<InspectResult> {
  const read = await readStoredEvent(req, lookup);
  if ("deny" in read) return read.deny;
  const stored = read.stored;
  const facts = dialogFacts(stored, req.body);

  if (!organisedByUser(stored)) {
    return isPatch && isNarrowRsvp(req.body, stored) ? { decision: "allow", summary: facts } : NOT_ORGANISED;
  }
  if (stored["attendeesOmitted"] === true) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "event-attendees-omitted",
      message: "The stored event's guest list is incomplete (attendeesOmitted), so its guests cannot be checked.",
    };
  }

  // events.patch defers the attendee check of an attendees-only body to here
  // (inspectEventPatch); on the user's own event it applies as usual.
  const fromBody = isPatch && isAttendeesOnlyBody(req.body) ? attendeeDecision(req.body, env) : null;
  if (fromBody?.decision === "deny") return fromBody;

  const outside = outsideGuests(stored, env);
  if (outside.length > 0) {
    return {
      decision: "elicit",
      category: "external_data_flow",
      reason: "event-has-external-guests",
      summary: {
        ...(fromBody?.summary ?? {}),
        ...facts,
        guests: firstThree(outside),
      },
    };
  }
  if (fromBody?.decision === "elicit") {
    return { ...fromBody, summary: { ...fromBody.summary, ...facts } };
  }
  return { decision: "allow", summary: facts };
}

/** inspectUpstream for events.update: reads the stored event and refuses to
 *  edit one the user does not organise; asks before editing one with outside
 *  guests. */
export async function inspectStoredEvent(
  req: InspectRequest,
  lookup: UpstreamLookup,
  env?: InspectEnv,
): Promise<InspectResult> {
  return inspectStored(req, lookup, env, false);
}

/** inspectUpstream for events.patch: as `inspectStoredEvent`, plus the
 *  narrow RSVP on someone else's event (§9), and the attendee check of an
 *  attendees-only body that `inspectEventPatch` deferred. */
export async function inspectStoredEventPatch(
  req: InspectRequest,
  lookup: UpstreamLookup,
  env?: InspectEnv,
): Promise<InspectResult> {
  return inspectStored(req, lookup, env, true);
}
