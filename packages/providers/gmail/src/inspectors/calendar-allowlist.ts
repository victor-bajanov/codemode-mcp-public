/**
 * Calendar write allow-list: the calendars this deployment lets the agent
 * write events to (insert / update / patch / import / move).
 *
 * The list is per-deployment, declared in the `CALENDAR_WRITE_ALLOWLIST`
 * wrangler var (comma-separated calendar ids). Calendar ids are either the
 * literal `primary` (the user's own calendar) or email-shaped (the user's own
 * address, `c_…@group.calendar.google.com` for a secondary calendar).
 *
 * Fail-closed semantics, the same as `OUTBOUND_RECIPIENT_ALLOWLIST`:
 *   - var unset / blank / non-string → empty list → every Calendar event write
 *     is denied (reads are unaffected). `primary` is NOT implicit: it must be
 *     listed.
 *   - any malformed entry → throw → the request errors before anything is sent.
 *
 * Matching is exact on the lower-cased id (never trimmed; printable ASCII only): no domain wildcards, no
 * plus-address widening, no prefix or substring match.
 */

import type { InspectEnv, InspectResult } from "@local/shared";
import { isPlainAddrSpec } from "./allowlist";

export const CALENDAR_WRITE_ALLOWLIST_VAR = "CALENDAR_WRITE_ALLOWLIST";

const PRIMARY = "primary";

/** Printable ASCII, no space. Checked before lower-casing so that a character
 *  such as U+212A KELVIN SIGN cannot fold onto an ASCII entry. */
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;

function assertCalendarEntry(entry: string): void {
  if (!PRINTABLE_ASCII.test(entry)) {
    throw new Error(
      `Invalid ${CALENDAR_WRITE_ALLOWLIST_VAR} entry (only printable ASCII is accepted): ${JSON.stringify(entry)}`,
    );
  }
  if (entry.toLowerCase() === PRIMARY) return;
  // `*@domain` passes the addr-spec shape but would only ever match the
  // literal id "*@domain"; refuse it so an operator expecting a wildcard
  // learns at the first write rather than seeing silent denies.
  if (entry.includes("*") || !isPlainAddrSpec(entry)) {
    throw new Error(
      `Invalid ${CALENDAR_WRITE_ALLOWLIST_VAR} entry (expected "primary" or an email-shaped calendar id): ${JSON.stringify(entry)}`,
    );
  }
}

// Memo for the last successfully parsed var value (fixed for the lifetime of
// an isolate); keyed by the raw string so tests with several envs re-parse.
let cachedRaw: string | undefined;
let cachedList: readonly string[] = [];

/**
 * Resolve this deployment's calendar write allow-list from its wrangler vars.
 * Unset / blank / non-string → []. Entries are trimmed, must be printable ASCII, and are lower-cased; each
 * must be exactly "primary" or pass `isPlainAddrSpec`, else this throws.
 */
export function calendarWriteAllowlistFromEnv(
  env?: Readonly<Record<string, unknown>>,
): readonly string[] {
  const raw = env?.[CALENDAR_WRITE_ALLOWLIST_VAR];
  if (typeof raw !== "string" || raw.trim().length === 0) return [];
  if (raw === cachedRaw) return cachedList;
  const trimmed = raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const entry of trimmed) {
    assertCalendarEntry(entry);
  }
  // Every entry is printable ASCII now, so lower-casing is ASCII-only.
  const entries = trimmed.map((s) => s.toLowerCase());
  cachedRaw = raw;
  cachedList = Object.freeze(entries);
  return cachedList;
}

/** True iff `calendarId`, lower-cased, equals an entry. The id is the one the
 *  request is sent to, so it is never trimmed: an id with edge whitespace, or
 *  any character outside printable ASCII, is denied before lower-casing. An
 *  empty list matches nothing; a non-string id is never allowed. */
export function isAllowedCalendar(calendarId: string, allowlist: readonly string[]): boolean {
  if (typeof calendarId !== "string") return false;
  if (!PRINTABLE_ASCII.test(calendarId)) return false;
  return allowlist.includes(calendarId.toLowerCase());
}

/** The deny for a write whose calendar is not on CALENDAR_WRITE_ALLOWLIST. */
function calendarNotAllowlisted(calendarId: string | undefined): InspectResult {
  const named =
    calendarId === undefined || calendarId.length === 0
      ? "This request names no calendar."
      : `Calendar ${JSON.stringify(calendarId.slice(0, 200))} is not on it.`;
  return {
    decision: "deny",
    category: "external_data_flow",
    reason: "calendar-not-allowlisted",
    message:
      "Calendar event writes are allowed only on this deployment's allow-listed calendars " +
      "(CALENDAR_WRITE_ALLOWLIST; use `primary` for the user's own calendar). " +
      named,
  };
}

/** null when `calendarId` is a non-empty string on the deployment's calendar
 *  allow-list; otherwise the calendar-not-allowlisted deny. Shared with
 *  events.move (both its source and its destination). A missing id (a
 *  unit probe without pathParams) denies: fail closed. Throws on a malformed
 *  CALENDAR_WRITE_ALLOWLIST, so the request errors before anything is sent. */
export function calendarDecision(calendarId: unknown, env?: InspectEnv): InspectResult | null {
  const allowlist = calendarWriteAllowlistFromEnv(env);
  if (typeof calendarId === "string" && calendarId.length > 0 && isAllowedCalendar(calendarId, allowlist)) {
    return null;
  }
  return calendarNotAllowlisted(typeof calendarId === "string" ? calendarId : undefined);
}
