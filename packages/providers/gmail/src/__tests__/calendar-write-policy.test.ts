// F1-2 (a–e) regression, end to end: the real request handler with the real
// Gmail + Calendar provider; only fetch (routed by URL), the token broker and
// the MCP client's elicitation answer are faked.
//
// Attacker: a prompt-injected LLM in the user's own session. It has read the
//   mailbox (SECRET below) and wants it in front of someone outside the
//   deployment's allowlists without naming a single attendee, which the
//   attendee inspector has always refused.
// Precondition: OUTBOUND_RECIPIENT_ALLOWLIST is empty (no outside address is
//   allowed); the user owns `primary` and `c_team@group.calendar.google.com`.
// Payloads (one per sub-finding):
//   a. events.insert into a calendar the attacker owns or shares
//      (`c_attacker@group.calendar.google.com`) with SECRET in the
//      description — no attendees, so nothing was checked;
//   b. events.patch of an event the attacker organises and invited the user
//      to (`?sendUpdates=all`): a guest's edit propagates to the organiser's
//      copy; b' the same on the user's own event that already has an outside
//      guest (that guest is notified of the new text);
//   c. an outOfOffice event whose `declineMessage` is SECRET: Calendar emails
//      it to the organiser of every conflicting invitation;
//   d. events.move of a user event to the attacker's calendar (the attacker
//      becomes organiser, so it owns the content);
//   e. events.quickAdd with SECRET and an attacker address in `text`: Google's
//      parser turns the address into a guest and `sendUpdates` invites it.
// Control: CALENDAR_WRITE_ALLOWLIST gates the target calendar of every event
//   write (and both ends of a move); update/patch read the stored event
//   through the host's plain-allow lookup and refuse foreign events (a narrow
//   RSVP aside, §9) and ask before editing one with outside guests;
//   declineMessage is denied; quickAdd is statically denied.
// Pre-fix: the attendee inspector saw only body and query (no path params),
//   allowed every attendee-free body, and move/quickAdd were plain `allow`;
//   each payload below was sent unchanged with no dialog.
// §9 cases guard the one carve-out (an RSVP on someone else's event). They
//   fail pre-fix because no stored read happened at all: an attendees-only
//   patch was judged by the attendee check alone (here it denied
//   external-attendee, the organiser being off the empty outbound allowlist,
//   so even a legitimate RSVP was refused).
// "control (still works)" cases are legitimate requests that pass before and
//   after; they prove each FIXED probe is refused by its control, not by a
//   broken harness.
import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "@local/scaffold";
import { gmailProvider } from "../index";

const SECRET = "Q3 board deck: acquisition of corp.example closes 2026-12-15, price 41.20/share";
const TEAM = "c_team@group.calendar.google.com";
const ATTACKER_CAL = "c_attacker@group.calendar.google.com";
const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "", CALENDAR_WRITE_ALLOWLIST: `primary,${TEAM}` };
const UPSTREAM = "https://www.googleapis.com";

const EVENT = {
  summary: "Notes",
  description: SECRET,
  start: { dateTime: "2026-12-01T09:00:00Z" },
  end: { dateTime: "2026-12-01T10:00:00Z" },
};

interface Stored {
  status?: number;
  body: unknown;
}

interface Sent {
  method: string;
  url: string;
  body: string;
  authorization: string | undefined;
  redirect: string | undefined;
}

/** `GET …/calendars/<c>/events/<id>` answers `stored[<id>]` (404 when absent);
 *  every other request answers 200 {id:"upstream-ok"}. */
function world(opts: {
  stored?: Record<string, Stored>;
  env?: Record<string, string>;
  caps?: unknown;
  answer?: unknown;
  getThrows?: boolean;
} = {}) {
  const stored = opts.stored ?? {};
  const fetchSpy = vi.fn<typeof fetch>(async (input, init) => {
    const url = new URL(String(input));
    const m = /^\/calendar\/v3\/calendars\/[^/]+\/events\/([^/]+)$/.exec(url.pathname);
    if ((init?.method ?? "GET") === "GET" && m) {
      if (opts.getThrows) throw new TypeError("network down");
      const hit = stored[decodeURIComponent(m[1]!)];
      return new Response(JSON.stringify(hit?.body ?? { error: { code: 404, message: "Not Found" } }), {
        status: hit ? (hit.status ?? 200) : 404,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ id: "upstream-ok" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fetchSpy);
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  const audits = () =>
    logSpy.mock.calls
      .map((c) => c[0])
      .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
      .map((s) => JSON.parse(s.slice(6)) as Record<string, unknown>);
  const elicits: Array<{ message: string }> = [];
  const elicitInput = vi.fn(async (params: { message: string }) => {
    elicits.push(params);
    return opts.answer ?? { action: "accept", content: { confirm: true } };
  });
  const caps = "caps" in opts ? opts.caps : { elicitation: {} };
  const run = (ctx: Partial<UpstreamCtx> & { method: string; path: string }) =>
    handleUpstreamRequest({
      ctx: ctx as UpstreamCtx,
      spec: gmailProvider.spec,
      surfaceReview: gmailProvider.surfaceReview,
      apiBaseUrl: gmailProvider.apiBaseUrl,
      deploymentName: "test",
      props: { refreshToken: "r", userId: "u" },
      server: { server: { getClientCapabilities: () => caps, elicitInput } } as never,
      oauth: {
        refreshTokenAccessor: () => "r",
        userIdAccessor: () => "u",
        broker: { getOrRefreshAccessToken: async () => "AT" },
      },
      audit: {},
      env: (opts.env ?? ENV) as { ALLOW_PII_IN_LOGS?: string },
      ...(gmailProvider.elicitRenderers ? { elicitRenderers: gmailProvider.elicitRenderers } : {}),
    } as HandleArgs<Record<string, unknown>>);
  const sent = (): Sent[] =>
    fetchSpy.mock.calls.map(([url, init]) => ({
      method: String(init?.method ?? "GET"),
      url: String(url),
      body: typeof init?.body === "string" ? init.body : "",
      authorization: (init?.headers as Record<string, string> | undefined)?.["Authorization"],
      redirect: init?.redirect,
    }));
  const wireText = () => sent().map((s) => s.url + "\n" + s.body).join("\n");
  return { run, audits, sent, wireText, elicits, elicitInput, fetchSpy };
}

async function settle(p: Promise<unknown>): Promise<{ ok: true } | { ok: false; message: string }> {
  try {
    await p;
    return { ok: true };
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : String(e) };
  }
}

/** The last audit line (the outer request's decision). */
const last = (a: Array<Record<string, unknown>>) => a[a.length - 1]!;

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const ME = "me@corp.example";
const ATTACKER = "attacker@evil.example";

/** An event the attacker organises with the user invited. */
const FOREIGN: Stored = {
  body: {
    id: "attackerOrganisedEventId",
    summary: "Catch-up",
    organizer: { email: ATTACKER, self: false },
    creator: { email: ATTACKER },
    attendees: [
      { email: ATTACKER, organizer: true, responseStatus: "accepted" },
      { email: ME, self: true, responseStatus: "needsAction" },
    ],
    start: { dateTime: "2026-12-02T09:00:00Z" },
    end: { dateTime: "2026-12-02T09:30:00Z" },
  },
};

/** The user's own event with no guests. */
const OWN: Stored = {
  body: {
    id: "ownEventId",
    summary: "Focus",
    organizer: { email: ME, self: true },
    attendees: [],
    start: { dateTime: "2026-12-03T09:00:00Z" },
    end: { dateTime: "2026-12-03T10:00:00Z" },
  },
};

/** The user's own event with one outside guest. */
const OWN_WITH_OUTSIDER: Stored = {
  body: {
    id: "ownMeetingId",
    summary: "Vendor sync",
    organizer: { email: ME, self: true },
    attendees: [{ email: "outsider@evil.example" }, { self: true, email: ME }],
    start: { dateTime: "2026-12-04T09:00:00Z" },
    end: { dateTime: "2026-12-04T10:00:00Z" },
  },
};

describe("control (unchanged): an off-allowlist attendee is refused", () => {
  it("REFUTED: insert on primary with an outside attendee is denied external-attendee, nothing sent", async () => {
    const w = world();
    const r = await settle(w.run({
      method: "POST",
      path: "/calendar/v3/calendars/primary/events",
      body: { ...EVENT, attendees: [{ email: ATTACKER }] },
    }));
    expect(r.ok).toBe(false);
    expect(w.fetchSpy).not.toHaveBeenCalled();
    expect(last(w.audits())).toMatchObject({ decision: "deny", reason: "external-attendee" });
  });
});

describe("F1-2a: event writes only on allow-listed calendars", () => {
  it("FIXED (F1-2a): insert into an unlisted calendar is denied calendar-not-allowlisted; SECRET never on the wire", async () => {
    const w = world();
    const r = await settle(w.run({
      method: "POST",
      path: `/calendar/v3/calendars/${encodeURIComponent(ATTACKER_CAL)}/events`,
      query: { sendUpdates: "all" },
      body: EVENT,
    }));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.message).toContain("CALENDAR_WRITE_ALLOWLIST");
      expect(r.message).toContain(ATTACKER_CAL);
      expect(r.message).not.toContain(SECRET);
    }
    expect(w.fetchSpy).not.toHaveBeenCalled();
    expect(last(w.audits())).toMatchObject({
      operationId: "calendar.events.insert",
      decision: "deny",
      category: "external_data_flow",
      reason: "calendar-not-allowlisted",
    });
  });

  it("control (still works): the same body on primary and on a listed secondary calendar is sent verbatim", async () => {
    const w = world();
    await w.run({ method: "POST", path: "/calendar/v3/calendars/primary/events", body: EVENT });
    await w.run({ method: "POST", path: `/calendar/v3/calendars/${encodeURIComponent(TEAM)}/events`, body: EVENT });
    expect(w.sent().map((s) => [s.method, s.url])).toEqual([
      ["POST", `${UPSTREAM}/calendar/v3/calendars/primary/events`],
      ["POST", `${UPSTREAM}/calendar/v3/calendars/${encodeURIComponent(TEAM)}/events`],
    ]);
    for (const s of w.sent()) {
      expect(JSON.parse(s.body)).toEqual(EVENT);
      expect(s.authorization).toBe("Bearer AT");
    }
  });

  it("FIXED (F1-2a): with CALENDAR_WRITE_ALLOWLIST unset even primary is denied (fail closed)", async () => {
    for (const env of [{ OUTBOUND_RECIPIENT_ALLOWLIST: "" }, { OUTBOUND_RECIPIENT_ALLOWLIST: "", CALENDAR_WRITE_ALLOWLIST: " " }]) {
      const w = world({ env });
      const r = await settle(w.run({ method: "POST", path: "/calendar/v3/calendars/primary/events", body: EVENT }));
      expect(r.ok).toBe(false);
      expect(w.fetchSpy).not.toHaveBeenCalled();
      expect(last(w.audits())).toMatchObject({ decision: "deny", reason: "calendar-not-allowlisted" });
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it("FIXED (F1-2a): the target id is the decoded path segment, matched exactly — edge whitespace and look-alikes are denied, case is ignored", async () => {
    const denied = [
      "primary%20",            // "primary " — never trimmed
      "%20primary",
      "primary%0A",
      "prim%C4%B1ary",         // dotless i
      encodeURIComponent("c_team@group.calendar.google.com.evil.example"),
      encodeURIComponent("C_TEAM@GROUP.CALENDAR.GOOGLE.COM​"),
    ];
    for (const seg of denied) {
      const w = world();
      const r = await settle(w.run({ method: "POST", path: `/calendar/v3/calendars/${seg}/events`, body: EVENT }));
      expect(r.ok, seg).toBe(false);
      expect(w.fetchSpy, seg).not.toHaveBeenCalled();
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
    const w = world();
    await w.run({ method: "POST", path: "/calendar/v3/calendars/PRIMARY/events", body: EVENT });
    await w.run({ method: "POST", path: `/calendar/v3/calendars/${encodeURIComponent(TEAM.toUpperCase())}/events`, body: EVENT });
    expect(w.fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("FIXED (F1-2a): update / patch / import on an unlisted calendar are denied before the stored-event read (no fetch at all)", async () => {
    const enc = encodeURIComponent(ATTACKER_CAL);
    const reqs: Array<{ method: string; path: string; body: unknown }> = [
      { method: "PUT", path: `/calendar/v3/calendars/${enc}/events/e1`, body: EVENT },
      { method: "PATCH", path: `/calendar/v3/calendars/${enc}/events/e1`, body: { description: SECRET } },
      { method: "POST", path: `/calendar/v3/calendars/${enc}/events/import`, body: { ...EVENT, iCalUID: "x@evil.example" } },
    ];
    for (const q of reqs) {
      const w = world({ stored: { e1: OWN } });
      const r = await settle(w.run(q));
      expect(r.ok, q.method).toBe(false);
      expect(w.fetchSpy, q.method).not.toHaveBeenCalled();
      expect(w.elicits, q.method).toHaveLength(0);
      expect(w.audits(), q.method).toHaveLength(1);
      expect(last(w.audits()), q.method).toMatchObject({ decision: "deny", reason: "calendar-not-allowlisted" });
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });
});

describe("F1-2b: update/patch read the stored event first", () => {
  it("FIXED (F1-2b): patching an event someone else organises is denied after one read; no PATCH, audit read-then-deny", async () => {
    const w = world({ stored: { attackerOrganisedEventId: FOREIGN } });
    const r = await settle(w.run({
      method: "PATCH",
      path: "/calendar/v3/calendars/primary/events/attackerOrganisedEventId",
      query: { sendUpdates: "all" },
      body: { description: SECRET },
    }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.message).toContain("organised by someone else");
    const s = w.sent();
    expect(s).toHaveLength(1);
    expect(s[0]).toMatchObject({
      method: "GET",
      url: `${UPSTREAM}/calendar/v3/calendars/primary/events/attackerOrganisedEventId`,
      authorization: "Bearer AT",
      redirect: "manual",
      body: "",
    });
    expect(w.wireText()).not.toContain("Q3 board deck");
    const a = w.audits();
    expect(a).toHaveLength(2);
    expect(a[0]).toMatchObject({
      operationId: "calendar.events.get",
      method: "GET",
      decision: "allow",
      upstreamStatus: 200,
    });
    expect(a[1]).toMatchObject({
      operationId: "calendar.events.patch",
      method: "PATCH",
      decision: "deny",
      category: "external_data_flow",
      reason: "event-not-organised-by-user",
    });
  });

  it("FIXED (F1-2b): events.update of a foreign event is denied too", async () => {
    const w = world({ stored: { attackerOrganisedEventId: FOREIGN } });
    const r = await settle(w.run({
      method: "PUT",
      path: "/calendar/v3/calendars/primary/events/attackerOrganisedEventId",
      body: { ...EVENT },
    }));
    expect(r.ok).toBe(false);
    expect(w.sent().map((s) => s.method)).toEqual(["GET"]);
    expect(last(w.audits())).toMatchObject({ operationId: "calendar.events.update", reason: "event-not-organised-by-user" });
  });

  it("FIXED (F1-2b): organiser `self` must be the boolean true (a string \"true\", or no organizer, is foreign)", async () => {
    for (const organizer of [{ email: ME, self: "true" }, { email: ME }, undefined]) {
      const body = { ...(OWN.body as Record<string, unknown>), organizer };
      const w = world({ stored: { ownEventId: { body } } });
      const r = await settle(w.run({
        method: "PATCH",
        path: "/calendar/v3/calendars/primary/events/ownEventId",
        body: { description: SECRET },
      }));
      expect(r.ok).toBe(false);
      expect(w.sent().map((s) => s.method)).toEqual(["GET"]);
      expect(last(w.audits())).toMatchObject({ reason: "event-not-organised-by-user" });
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it("FIXED (F1-2b): the user's own guest-free event: GET then PATCH, in that order, PATCH body verbatim", async () => {
    const w = world({ stored: { ownEventId: OWN } });
    await w.run({
      method: "PATCH",
      path: "/calendar/v3/calendars/primary/events/ownEventId",
      query: { sendUpdates: "all" },
      body: { description: "agenda: item 1" },
    });
    const s = w.sent();
    expect(s.map((x) => x.method)).toEqual(["GET", "PATCH"]);
    expect(s[1]!.url).toBe(`${UPSTREAM}/calendar/v3/calendars/primary/events/ownEventId?sendUpdates=all`);
    expect(s[1]!.body).toBe('{"description":"agenda: item 1"}');
    expect(w.elicits).toHaveLength(0);
    const a = w.audits();
    expect(a.map((x) => [x.operationId, x.decision])).toEqual([
      ["calendar.events.get", "allow"],
      ["calendar.events.patch", "allow"],
    ]);
  });

  it("FIXED (F1-2b): the read targets exactly the event the write does (encoded ids) and never carries the sandbox's query", async () => {
    const id = "evt?x=1#frag%2F";
    const w = world({ stored: { [id]: OWN } });
    await w.run({
      method: "PATCH",
      path: `/calendar/v3/calendars/${encodeURIComponent(TEAM)}/events/${encodeURIComponent(id)}`,
      query: { maxAttendees: 1, sendUpdates: "none" },
      body: { description: "x" },
    });
    const s = w.sent();
    expect(s.map((x) => x.method)).toEqual(["GET", "PATCH"]);
    const get = new URL(s[0]!.url);
    const patch = new URL(s[1]!.url);
    expect(get.pathname).toBe(patch.pathname);
    expect(get.pathname).toBe(`/calendar/v3/calendars/${encodeURIComponent(TEAM)}/events/${encodeURIComponent(id)}`);
    expect(get.search).toBe("");
  });

  it("FIXED (F1-2b'): own event with an outside guest asks first; the dialog names the target and the stored guests; confirm sends", async () => {
    const w = world({ stored: { ownMeetingId: OWN_WITH_OUTSIDER } });
    await w.run({
      method: "PATCH",
      path: "/calendar/v3/calendars/primary/events/ownMeetingId",
      query: { sendUpdates: "all" },
      body: { description: SECRET },
    });
    expect(w.elicits).toHaveLength(1);
    const m = w.elicits[0]!.message;
    expect(m).toContain("Request: PATCH /calendar/v3/calendars/primary/events/ownMeetingId");
    expect(m).toContain('Query: sendUpdates="all"');
    expect(m).toContain('calendarId: "primary"');
    expect(m).toContain('eventId: "ownMeetingId"');
    expect(m).toContain('guests: "outsider@evil.example"');
    expect(m).toContain(`organizer: "${ME}"`);
    expect(m).toContain('summary: "Vendor sync"');
    expect(m).toContain('start: "2026-12-04T09:00:00Z"');
    expect(m).toContain('end: "2026-12-04T10:00:00Z"');
    // The user's own entry is not a guest.
    expect(m).not.toMatch(/guests: "[^"]*me@corp\.example/);
    expect(w.sent().map((x) => x.method)).toEqual(["GET", "PATCH"]);
    expect(w.audits().map((x) => [x.operationId, x.decision, x.elicitationOutcome ?? null, x.reason ?? null])).toEqual([
      ["calendar.events.get", "allow", null, null],
      ["calendar.events.patch", "elicit", "accepted", "event-has-external-guests"],
      ["calendar.events.patch", "allow", null, null],
    ]);
    expect(m).toContain('changes: "description"');
  });

  // The dialog must show what the write does, not only what is stored: a
  // patch that retitles the event to SECRET and fills its description was
  // approved under the OLD title when only stored facts were shown.
  it("FIXED (F1-2b'): the dialog shows the patched title and which fields change; who is affected stays the stored event's", async () => {
    const w = world({ stored: { ownMeetingId: OWN_WITH_OUTSIDER } });
    await w.run({
      method: "PATCH",
      path: "/calendar/v3/calendars/primary/events/ownMeetingId",
      query: { sendUpdates: "all" },
      body: { summary: SECRET, description: SECRET, organizer: { email: "decoy@corp.example" } },
    });
    expect(w.elicits).toHaveLength(1);
    const m = w.elicits[0]!.message;
    expect(m).toContain(`summary: ${JSON.stringify(SECRET)}`);
    expect(m).not.toContain('summary: "Vendor sync"');
    expect(m).toContain('changes: "description, organizer, summary"');
    expect(m).toContain(`organizer: "${ME}"`);
    expect(m).not.toContain("decoy@corp.example");
    expect(m).toContain('guests: "outsider@evil.example"');
    // Body has no start/end: the stored ones are shown.
    expect(m).toContain('start: "2026-12-04T09:00:00Z"');
  });

  it("FIXED (F1-2b'): a 26-guest update of the user's own event shows the new title, not the stored one", async () => {
    const attendees = Array.from({ length: 26 }, (_, i) => ({ email: `staff${i}@corp.example` }));
    const w = world({
      stored: { ownEventId: OWN },
      env: { OUTBOUND_RECIPIENT_ALLOWLIST: "*@corp.example", CALENDAR_WRITE_ALLOWLIST: "primary" },
    });
    await w.run({
      method: "PUT",
      path: "/calendar/v3/calendars/primary/events/ownEventId",
      body: { ...EVENT, summary: "All hands: new title", attendees },
    });
    expect(w.elicits).toHaveLength(1);
    const m = w.elicits[0]!.message;
    expect(m).toContain("count: 26");
    expect(m).toContain('summary: "All hands: new title"');
    expect(m).not.toContain('summary: "Focus"');
    expect(m).toContain('changes: "attendees, description, end, start, summary"');
    expect(w.audits().at(-2)).toMatchObject({ operationId: "calendar.events.update", decision: "elicit", reason: "mass-invite" });
  });

  it("FIXED (F1-2b'): a client without elicitation (Claude.ai) gets `unsupported`; only the read went out", async () => {
    const w = world({ stored: { ownMeetingId: OWN_WITH_OUTSIDER }, caps: {} });
    const r = await settle(w.run({
      method: "PATCH",
      path: "/calendar/v3/calendars/primary/events/ownMeetingId",
      body: { description: SECRET },
    }));
    expect(r).toEqual({
      ok: false,
      message: "Operation calendar.events.patch requires user approval; outcome: unsupported",
    });
    expect(w.elicitInput).not.toHaveBeenCalled();
    expect(w.sent().map((x) => x.method)).toEqual(["GET"]);
  });

  it("FIXED (F1-2b'): declining the dialog sends nothing but the read", async () => {
    const w = world({ stored: { ownMeetingId: OWN_WITH_OUTSIDER }, answer: { action: "accept", content: { confirm: false } } });
    const r = await settle(w.run({
      method: "PUT",
      path: "/calendar/v3/calendars/primary/events/ownMeetingId",
      body: { ...EVENT },
    }));
    expect(r.ok).toBe(false);
    expect(w.sent().map((x) => x.method)).toEqual(["GET"]);
  });

  it("FIXED (F1-2b): stored-guest reading is strict — an unreadable guest entry counts as outside", async () => {
    const body = { ...(OWN.body as Record<string, unknown>), attendees: [{ displayName: "no email" }, "junk"] };
    const w = world({ stored: { ownEventId: { body } }, caps: {} });
    const r = await settle(w.run({
      method: "PATCH",
      path: "/calendar/v3/calendars/primary/events/ownEventId",
      body: { description: SECRET },
    }));
    expect(r.ok).toBe(false);
    expect(w.sent().map((x) => x.method)).toEqual(["GET"]);
  });

  it("FIXED (F1-2b): an attendees-only patch on the user's own event still gets the attendee check (deferred to the hook)", async () => {
    const w = world({ stored: { ownEventId: OWN } });
    const r = await settle(w.run({
      method: "PATCH",
      path: "/calendar/v3/calendars/primary/events/ownEventId",
      query: { sendUpdates: "all" },
      body: { attendees: [{ email: ATTACKER }] },
    }));
    expect(r.ok).toBe(false);
    expect(w.sent().map((x) => x.method)).toEqual(["GET"]);
    expect(last(w.audits())).toMatchObject({ decision: "deny", reason: "external-attendee" });
  });

  it("FIXED (F1-2b): a sync deny (declineMessage, outside attendee) never reaches the read", async () => {
    const w = world({ stored: { ownEventId: OWN } });
    await settle(w.run({
      method: "PATCH",
      path: "/calendar/v3/calendars/primary/events/ownEventId",
      body: { outOfOfficeProperties: { declineMessage: SECRET } },
    }));
    await settle(w.run({
      method: "PUT",
      path: "/calendar/v3/calendars/primary/events/ownEventId",
      body: { ...EVENT, attendees: [{ email: ATTACKER }] },
    }));
    expect(w.fetchSpy).not.toHaveBeenCalled();
  });

  it("FIXED (F1-2b): 404, 403, 500, attendeesOmitted and a failing read all deny with no write", async () => {
    const cases: Array<[Stored | undefined, string]> = [
      [undefined, "event-not-found"],
      [{ status: 403, body: { error: { code: 403, message: "Forbidden " + SECRET } } }, "event-read-failed"],
      [{ status: 500, body: { error: { code: 500 } } }, "event-read-failed"],
      [{ body: { ...(OWN.body as Record<string, unknown>), attendeesOmitted: true } }, "event-attendees-omitted"],
    ];
    for (const [stored, reason] of cases) {
      const w = world({ stored: stored ? { e1: stored } : {} });
      const r = await settle(w.run({ method: "PATCH", path: "/calendar/v3/calendars/primary/events/e1", body: { description: "x" } }));
      expect(r.ok, reason).toBe(false);
      if (!r.ok) expect(r.message, reason).not.toContain("Q3 board deck");
      expect(w.sent().map((x) => x.method), reason).toEqual(["GET"]);
      expect(last(w.audits()), reason).toMatchObject({ decision: "deny", reason });
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
    const w = world({ stored: { e1: OWN }, getThrows: true });
    const r = await settle(w.run({ method: "PATCH", path: "/calendar/v3/calendars/primary/events/e1", body: { description: "x" } }));
    expect(r.ok).toBe(false);
    expect(w.sent().map((x) => x.method)).toEqual(["GET"]);
    expect(last(w.audits())).toMatchObject({ operationId: "calendar.events.patch", decision: "deny", reason: "upstream-inspect-failed" });
  });
});

describe("§9: the narrow RSVP on someone else's event", () => {
  const rsvp = (status: string, extra: Record<string, unknown> = {}) => ({
    attendees: [
      { email: ATTACKER, organizer: true, responseStatus: "accepted" },
      { email: ME, self: true, responseStatus: status, ...extra },
    ],
  });
  const path = "/calendar/v3/calendars/primary/events/attackerOrganisedEventId";

  it("FIXED (§9): changing only the user's own responseStatus is sent (GET then PATCH, no dialog), sendUpdates allowed", async () => {
    for (const status of ["accepted", "declined", "tentative", "needsAction"]) {
      const w = world({ stored: { attackerOrganisedEventId: FOREIGN } });
      await w.run({ method: "PATCH", path, query: { sendUpdates: "all" }, body: rsvp(status) });
      expect(w.sent().map((x) => x.method), status).toEqual(["GET", "PATCH"]);
      expect(JSON.parse(w.sent()[1]!.body), status).toEqual(rsvp(status));
      expect(w.elicits).toHaveLength(0);
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it("FIXED (§9): the user's entry found by the creator's address when `self` is absent", async () => {
    const stored = {
      body: {
        ...(FOREIGN.body as Record<string, unknown>),
        creator: { email: "ME@corp.example", self: true },
        attendees: [{ email: ATTACKER, organizer: true }, { email: ME, responseStatus: "needsAction" }],
      },
    };
    const w = world({ stored: { attackerOrganisedEventId: stored } });
    await w.run({
      method: "PATCH",
      path,
      body: { attendees: [{ email: ATTACKER, organizer: true }, { email: ME, responseStatus: "declined" }] },
    });
    expect(w.sent().map((x) => x.method)).toEqual(["GET", "PATCH"]);
  });

  const denied: Array<[string, unknown]> = [
    ["RSVP plus a comment", rsvp("declined", { comment: SECRET })],
    ["RSVP plus additionalGuests", rsvp("accepted", { additionalGuests: 7 })],
    ["a status outside the enum (free text)", rsvp(SECRET)],
    ["a changed guest", { attendees: [{ email: "other@evil.example", organizer: true, responseStatus: "accepted" }, { email: ME, self: true, responseStatus: "accepted" }] }],
    ["an added guest", { attendees: [...rsvp("accepted").attendees, { email: "friend@evil.example" }] }],
    ["a removed guest", { attendees: [{ email: ME, self: true, responseStatus: "accepted" }] }],
    ["another attendee's responseStatus", { attendees: [{ email: ATTACKER, organizer: true, responseStatus: "declined" }, { email: ME, self: true, responseStatus: "needsAction" }] }],
    ["the user's displayName changed", rsvp("accepted", { displayName: SECRET })],
    ["reordered attendees", { attendees: [...rsvp("accepted").attendees].reverse() }],
  ];
  for (const [label, body] of denied) {
    it(`FIXED (§9): ${label} is denied event-not-organised-by-user; no PATCH`, async () => {
      const w = world({ stored: { attackerOrganisedEventId: FOREIGN } });
      const r = await settle(w.run({ method: "PATCH", path, query: { sendUpdates: "all" }, body }));
      expect(r.ok).toBe(false);
      expect(w.sent().map((x) => x.method)).toEqual(["GET"]);
      expect(last(w.audits())).toMatchObject({ decision: "deny", reason: "event-not-organised-by-user" });
    });
  }

  // Not attendees-only, or not a patch: the sync attendee check runs on the
  // body as usual, and the organiser in the list is off the (empty) outbound
  // allowlist, so these never reach the stored-event read.
  it("REFUTED: RSVP plus a second key, or the RSVP shape on events.update (PUT), is denied before the read (unchanged attendee check)", async () => {
    for (const [method, body] of [
      ["PATCH", { ...rsvp("accepted"), description: SECRET }],
      ["PUT", rsvp("accepted")],
    ] as const) {
      const w = world({ stored: { attackerOrganisedEventId: FOREIGN } });
      const r = await settle(w.run({ method, path, body }));
      expect(r.ok, method).toBe(false);
      expect(w.fetchSpy, method).not.toHaveBeenCalled();
      expect(last(w.audits()), method).toMatchObject({ decision: "deny", reason: "external-attendee" });
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it("FIXED (§9): with the organiser allow-listed, the RSVP shape on events.update (PUT) still reaches the read and is denied", async () => {
    const w = world({
      stored: { attackerOrganisedEventId: FOREIGN },
      env: { ...ENV, OUTBOUND_RECIPIENT_ALLOWLIST: `${ATTACKER},${ME}` },
    });
    const r = await settle(w.run({ method: "PUT", path, body: rsvp("accepted") }));
    expect(r.ok).toBe(false);
    expect(w.sent().map((x) => x.method)).toEqual(["GET"]);
    expect(last(w.audits())).toMatchObject({ operationId: "calendar.events.update", reason: "event-not-organised-by-user" });
  });

  it("FIXED (§9): no RSVP when the stored list is truncated (attendeesOmitted) or the user's entry is ambiguous", async () => {
    const truncated = { body: { ...(FOREIGN.body as Record<string, unknown>), attendeesOmitted: true } };
    const twoSelves = {
      body: {
        ...(FOREIGN.body as Record<string, unknown>),
        attendees: [{ email: ATTACKER, self: true }, { email: ME, self: true, responseStatus: "needsAction" }],
      },
    };
    for (const stored of [truncated, twoSelves] as Array<{ body: Record<string, unknown> }>) {
      const w = world({ stored: { attackerOrganisedEventId: stored } });
      const body = { attendees: (stored.body["attendees"] as Array<Record<string, unknown>>).map((a, i) => (i === 1 ? { ...a, responseStatus: "accepted" } : a)) };
      const r = await settle(w.run({ method: "PATCH", path, body }));
      expect(r.ok).toBe(false);
      expect(w.sent().map((x) => x.method)).toEqual(["GET"]);
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });
});

describe("F1-2c: auto-decline messages", () => {
  const ooo = (props: Record<string, unknown>) => ({
    eventType: "outOfOffice",
    start: { dateTime: "2026-12-10T00:00:00Z" },
    end: { dateTime: "2026-12-11T00:00:00Z" },
    ...props,
  });

  it("FIXED (F1-2c): a declineMessage in either spelling, on either property, of any non-empty type is denied; nothing sent", async () => {
    const bodies = [
      ooo({ outOfOfficeProperties: { autoDeclineMode: "declineAllConflictingInvitations", declineMessage: SECRET } }),
      ooo({ out_of_office_properties: { decline_message: SECRET } }),
      ooo({ outOfOfficeProperties: { decline_message: SECRET } }),
      { eventType: "focusTime", start: EVENT.start, end: EVENT.end, focusTimeProperties: { declineMessage: SECRET } },
      { eventType: "focusTime", start: EVENT.start, end: EVENT.end, focus_time_properties: { declineMessage: SECRET } },
      ooo({ outOfOfficeProperties: { declineMessage: { text: SECRET } } }),
      ooo({ outOfOfficeProperties: { declineMessage: 42 } }),
    ];
    for (const body of bodies) {
      const w = world();
      const r = await settle(w.run({ method: "POST", path: "/calendar/v3/calendars/primary/events", body }));
      expect(r.ok, JSON.stringify(body)).toBe(false);
      expect(w.fetchSpy).not.toHaveBeenCalled();
      expect(last(w.audits())).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "event-decline-message" });
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it("control (still works): an outOfOffice event without a declineMessage (or with null / \"\") is sent", async () => {
    const w = world();
    for (const declineMessage of [undefined, null, ""]) {
      const props: Record<string, unknown> = { autoDeclineMode: "declineAllConflictingInvitations" };
      if (declineMessage !== undefined) props["declineMessage"] = declineMessage;
      await w.run({ method: "POST", path: "/calendar/v3/calendars/primary/events", body: ooo({ outOfOfficeProperties: props }) });
    }
    expect(w.sent().map((x) => x.method)).toEqual(["POST", "POST", "POST"]);
  });
});

describe("F1-2d: events.move only between allow-listed calendars", () => {
  const movePath = "/calendar/v3/calendars/primary/events/someEventId/move";

  it("FIXED (F1-2d): a destination off the allow-list is denied calendar-not-allowlisted; nothing sent", async () => {
    const w = world();
    const r = await settle(w.run({ method: "POST", path: movePath, query: { destination: ATTACKER_CAL, sendUpdates: "all" } }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.message).toContain(ATTACKER_CAL);
    expect(w.fetchSpy).not.toHaveBeenCalled();
    expect(last(w.audits())).toMatchObject({ operationId: "calendar.events.move", decision: "deny", reason: "calendar-not-allowlisted" });
  });

  it("control (still works): a listed destination is sent with both query pairs", async () => {
    const w = world();
    await w.run({ method: "POST", path: movePath, query: { destination: TEAM, sendUpdates: "all" } });
    const s = w.sent();
    expect(s).toHaveLength(1);
    const u = new URL(s[0]!.url);
    expect(u.pathname).toBe(movePath);
    expect(u.searchParams.get("destination")).toBe(TEAM);
    expect(u.searchParams.get("sendUpdates")).toBe("all");
    expect(s[0]!.body).toBe("");
  });

  it("FIXED (F1-2d): an unlisted source, a missing or empty destination, or any body is denied; nothing sent", async () => {
    const cases: Array<[Partial<UpstreamCtx> & { method: string; path: string }, string]> = [
      [{ method: "POST", path: `/calendar/v3/calendars/${encodeURIComponent(ATTACKER_CAL)}/events/e/move`, query: { destination: "primary" } }, "calendar-not-allowlisted"],
      [{ method: "POST", path: movePath }, "move-no-destination"],
      [{ method: "POST", path: movePath, query: { destination: "" } }, "move-no-destination"],
      [{ method: "POST", path: movePath, query: { destination: TEAM }, body: { summary: SECRET } }, "move-body-not-allowed"],
      [{ method: "POST", path: movePath, query: { destination: "primary " } }, "calendar-not-allowlisted"],
    ];
    for (const [ctx, reason] of cases) {
      const w = world();
      const r = await settle(w.run(ctx));
      expect(r.ok, reason).toBe(false);
      expect(w.fetchSpy, reason).not.toHaveBeenCalled();
      expect(last(w.audits()), reason).toMatchObject({ decision: "deny", reason });
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });
});

describe("F1-2e: events.quickAdd", () => {
  it("FIXED (F1-2e): quickAdd is statically denied — no dialog, nothing sent, even on primary", async () => {
    const w = world();
    const r = await settle(w.run({
      method: "POST",
      path: "/calendar/v3/calendars/primary/events/quickAdd",
      query: { text: `${SECRET} with ${ATTACKER} tomorrow 10am`, sendUpdates: "all" },
    }));
    expect(r.ok).toBe(false);
    expect(w.fetchSpy).not.toHaveBeenCalled();
    expect(w.elicitInput).not.toHaveBeenCalled();
    expect(w.audits()).toHaveLength(1);
    expect(last(w.audits())).toMatchObject({ operationId: "calendar.events.quickAdd", decision: "deny", category: "external_data_flow" });
  });
});
