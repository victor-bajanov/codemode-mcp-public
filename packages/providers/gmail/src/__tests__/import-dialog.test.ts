// Carry-over regression (wave 2, §2.4 / §3.5): the approval dialogs for
// gmail.users.messages.import and calendar.events.import show what is being
// imported, and decoys are refused before any dialog. End to end: the real
// request handler with the real Gmail + Calendar provider; only fetch, the
// token broker and the MCP client's elicitation answer are faked.
//
// Attacker: a prompt-injected LLM in the user's own session.
// Precondition: an MCP client that supports elicitation (both imports are
//   statically `elicit`; on a client without it they are denied).
// Payloads: a forged "CEO wire transfer" message planted in the inbox; the same
//   with a `payload` decoy that a reader of the JSON would trust over `raw`;
//   a raw whose header block repeats From or hides a line break in an encoded
//   word; a calendar event imported with a forged organiser, into the user's
//   calendar or a calendar the attacker shares.
// Control: inspectMessageImport reads `raw` only (keys ⊆ raw, threadId,
//   labelIds), refuses header blocks a reader could see differently, and hands
//   the dialog From / To / Subject / Date from the same parse;
//   inspectEventImport gates the calendar (CALENDAR_WRITE_ALLOWLIST) and the
//   attendees, and hands the dialog organizer / summary / start / end.
// Pre-fix: messages.import had no inspector — the dialog showed only the
//   request line and query, never who the message claims to be from, and any
//   JSON body (a `payload` decoy included) was approvable; events.import had
//   the attendee check only — no calendar check, and its dialog showed the
//   calendar id alone.
import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "@local/scaffold";
import { gmailProvider } from "../index";

const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@corp.example", CALENDAR_WRITE_ALLOWLIST: "primary" };
const MSG_IMPORT = "/gmail/v1/users/me/messages/import";
const EVT_IMPORT = "/calendar/v3/calendars/primary/events/import";

const b64url = (s: string): string => Buffer.from(s, "utf8").toString("base64url");
const FORGED =
  "From: ceo@corp.example\r\nTo: victim@corp.example\r\nSubject: Wire transfer today\r\n" +
  "Date: Tue, 1 Dec 2026 09:00:00 +0000\r\n\r\npay this\r\n";

function world(opts: { answer?: unknown; caps?: unknown; env?: Record<string, string> } = {}) {
  const fetchSpy = vi.fn<typeof fetch>(async () =>
    new Response(JSON.stringify({ id: "upstream-ok" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
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
  const sent = () =>
    fetchSpy.mock.calls.map(([url, init]) => ({
      method: String(init?.method ?? "GET"),
      url: String(url),
      body: typeof init?.body === "string" ? init.body : "",
    }));
  return { run, elicits, elicitInput, fetchSpy, audits, sent };
}

async function settle(p: Promise<unknown>): Promise<{ ok: true } | { ok: false; message: string }> {
  try {
    await p;
    return { ok: true };
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : String(e) };
  }
}

const lines = (m: string) => m.split("\n");
const last = (a: Array<Record<string, unknown>>) => a[a.length - 1]!;

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("messages.import: the dialog shows the imported message's From/To/Subject/Date", () => {
  it("FIXED (carry-over): the forged message's sender, recipient, subject and date are facts, in that order; confirm imports raw verbatim", async () => {
    const w = world();
    await w.run({ method: "POST", path: MSG_IMPORT, query: { neverMarkSpam: true }, body: { raw: b64url(FORGED) } });
    expect(w.elicits).toHaveLength(1);
    const l = lines(w.elicits[0]!.message);
    expect(l[0]).toBe("Confirm Gmail import (gmail.users.messages.import)");
    expect(l[1]).toBe(`Request: POST ${MSG_IMPORT}`);
    expect(l[2]).toBe("Query: neverMarkSpam=true");
    expect(l.slice(3, 7)).toEqual([
      'from: "ceo@corp.example"',
      'to: "victim@corp.example"',
      'subject: "Wire transfer today"',
      'date: "Tue, 1 Dec 2026 09:00:00 +0000"',
    ]);
    const s = w.sent();
    expect(s).toHaveLength(1);
    expect(JSON.parse(s[0]!.body)).toEqual({ raw: b64url(FORGED) });
  });

  it("FIXED (carry-over): an RFC 2047 subject is shown decoded; absent headers are simply left out", async () => {
    const w = world();
    const raw = b64url(`From: cfo@corp.example\r\nSubject: =?UTF-8?B?${Buffer.from("Überweisung heute").toString("base64")}?=\r\n\r\nx\r\n`);
    await w.run({ method: "POST", path: MSG_IMPORT, body: { raw } });
    const m = w.elicits[0]!.message;
    expect(m).toContain('subject: "Überweisung heute"');
    expect(m).toContain('from: "cfo@corp.example"');
    expect(m).not.toMatch(/^to: /m);
    expect(m).not.toMatch(/^date: /m);
  });

  it("FIXED (carry-over): a line break smuggled in an encoded word cannot forge a second fact line", async () => {
    const w = world();
    const evil = 'hello"\nfrom: "it-support@corp.example';
    const raw = b64url(
      `From: attacker@evil.example\r\nSubject: =?UTF-8?B?${Buffer.from(evil).toString("base64")}?=\r\n\r\nx\r\n`,
    );
    await w.run({ method: "POST", path: MSG_IMPORT, body: { raw } });
    const l = lines(w.elicits[0]!.message);
    expect(l.filter((x) => x.startsWith("from: "))).toEqual(['from: "attacker@evil.example"']);
    expect(l.filter((x) => x.startsWith("subject: "))).toHaveLength(1);
  });

  it("FIXED (carry-over): a 300-character subject reaches the dialog whole and is cut there with …", async () => {
    const w = world();
    const subject = "S".repeat(300);
    await w.run({ method: "POST", path: MSG_IMPORT, body: { raw: b64url(`From: a@corp.example\r\nSubject: ${subject}\r\n\r\nx\r\n`) } });
    const line = lines(w.elicits[0]!.message).find((x) => x.startsWith("subject: "))!;
    expect(line).toBe(`subject: "${"S".repeat(200)}…"`);
  });

  const refused: Array<[string, unknown, string]> = [
    ["a payload decoy alone", { payload: { headers: [{ name: "From", value: "newsletter@corp.example" }] } }, "send-unexpected-key"],
    ["raw beside a payload decoy", { raw: b64url(FORGED), payload: { headers: [{ name: "From", value: "newsletter@corp.example" }] } }, "send-unexpected-key"],
    ["raw beside a message wrapper", { raw: b64url(FORGED), message: { raw: b64url("From: newsletter@corp.example\r\n\r\nx") } }, "send-unexpected-key"],
    ["an empty body", {}, "import-no-raw"],
    ["an empty raw", { raw: "" }, "import-no-raw"],
    ["a lone CR in the header block", { raw: b64url("From: newsletter@corp.example\rFrom: ceo@corp.example\r\n\r\nx") }, "ambiguous-line-ending"],
    ["a repeated From", { raw: b64url("From: newsletter@corp.example\r\nFrom: ceo@corp.example\r\nSubject: hi\r\n\r\nx") }, "duplicate-summary-header"],
    ["a repeated Subject", { raw: b64url("From: a@corp.example\r\nSubject: lunch\r\nSubject: Wire transfer today\r\n\r\nx") }, "duplicate-summary-header"],
    ["a non-object body", "From: ceo@corp.example", "import-body-not-object"],
  ];
  for (const [label, body, reason] of refused) {
    it(`FIXED (carry-over): ${label} is denied ${reason} before any dialog; nothing sent`, async () => {
      const w = world();
      const r = await settle(w.run({ method: "POST", path: MSG_IMPORT, body }));
      expect(r.ok).toBe(false);
      expect(w.elicitInput).not.toHaveBeenCalled();
      expect(w.fetchSpy).not.toHaveBeenCalled();
      expect(w.audits()).toHaveLength(1);
      expect(last(w.audits())).toMatchObject({
        operationId: "gmail.users.messages.import",
        decision: "deny",
        reason,
      });
    });
  }

  it("REFUTED: a client without elicitation cannot import at all (unsupported), nothing sent", async () => {
    const w = world({ caps: {} });
    const r = await settle(w.run({ method: "POST", path: MSG_IMPORT, body: { raw: b64url(FORGED) } }));
    expect(r).toEqual({
      ok: false,
      message: "Operation gmail.users.messages.import requires user approval; outcome: unsupported",
    });
    expect(w.fetchSpy).not.toHaveBeenCalled();
  });
});

describe("events.import: the dialog shows the imported event, and only allow-listed calendars are reachable", () => {
  const event = {
    iCalUID: "board-2026-12@corp.example",
    summary: "Board meeting",
    organizer: { email: "ceo@corp.example" },
    start: { dateTime: "2026-12-01T09:00:00Z" },
    end: { dateTime: "2026-12-01T10:00:00Z" },
  };

  it("FIXED (carry-over): calendarId, organizer, summary, start and end are facts; confirm imports the body verbatim", async () => {
    const w = world();
    await w.run({ method: "POST", path: EVT_IMPORT, body: event });
    expect(w.elicits).toHaveLength(1);
    const l = lines(w.elicits[0]!.message);
    expect(l[0]).toBe("Confirm Gmail import (calendar.events.import)");
    expect(l[1]).toBe(`Request: POST ${EVT_IMPORT}`);
    expect(l.slice(2, 7)).toEqual([
      'calendarId: "primary"',
      'organizer: "ceo@corp.example"',
      'summary: "Board meeting"',
      'start: "2026-12-01T09:00:00Z"',
      'end: "2026-12-01T10:00:00Z"',
    ]);
    expect(JSON.parse(w.sent()[0]!.body)).toEqual(event);
  });

  it("FIXED (carry-over): an all-day import shows its dates", async () => {
    const w = world();
    await w.run({ method: "POST", path: EVT_IMPORT, body: { ...event, start: { date: "2026-12-24" }, end: { date: "2026-12-25" } } });
    const m = w.elicits[0]!.message;
    expect(m).toContain('start: "2026-12-24"');
    expect(m).toContain('end: "2026-12-25"');
  });

  it("FIXED (carry-over): a 26-guest import keeps every decisive fact within the eight-fact cap", async () => {
    const w = world();
    const attendees = Array.from({ length: 26 }, (_, i) => ({ email: `staff${i}@corp.example` }));
    await w.run({ method: "POST", path: EVT_IMPORT, body: { ...event, attendees } });
    const l = lines(w.elicits[0]!.message);
    expect(l.slice(2, 9)).toEqual([
      'calendarId: "primary"',
      "count: 26",
      'attendees: "staff0@corp.example, staff1@corp.example, staff2@corp.example (+23)"',
      'organizer: "ceo@corp.example"',
      'summary: "Board meeting"',
      'start: "2026-12-01T09:00:00Z"',
      'end: "2026-12-01T10:00:00Z"',
    ]);
  });

  it("FIXED (F1-2a): an import into a calendar off CALENDAR_WRITE_ALLOWLIST is denied before any dialog; nothing sent", async () => {
    const w = world();
    const r = await settle(w.run({
      method: "POST",
      path: `/calendar/v3/calendars/${encodeURIComponent("c_attacker@group.calendar.google.com")}/events/import`,
      body: event,
    }));
    expect(r.ok).toBe(false);
    expect(w.elicitInput).not.toHaveBeenCalled();
    expect(w.fetchSpy).not.toHaveBeenCalled();
    expect(last(w.audits())).toMatchObject({ operationId: "calendar.events.import", decision: "deny", reason: "calendar-not-allowlisted" });
  });

  it("FIXED (F1-2a): with CALENDAR_WRITE_ALLOWLIST unset an import into primary is denied before any dialog", async () => {
    const w = world({ env: { OUTBOUND_RECIPIENT_ALLOWLIST: "*@corp.example" } });
    const r = await settle(w.run({ method: "POST", path: EVT_IMPORT, body: event }));
    expect(r.ok).toBe(false);
    expect(w.elicitInput).not.toHaveBeenCalled();
    expect(w.fetchSpy).not.toHaveBeenCalled();
  });

  it("REFUTED: an import with an off-allowlist attendee is denied before any dialog (unchanged)", async () => {
    const w = world();
    const r = await settle(w.run({ method: "POST", path: EVT_IMPORT, body: { ...event, attendees: [{ email: "outsider@evil.example" }] } }));
    expect(r.ok).toBe(false);
    expect(w.elicitInput).not.toHaveBeenCalled();
    expect(last(w.audits())).toMatchObject({ decision: "deny", reason: "external-attendee" });
  });

  it("FIXED (F1-2c): an import carrying a declineMessage is denied before any dialog", async () => {
    const w = world();
    const r = await settle(w.run({
      method: "POST",
      path: EVT_IMPORT,
      body: { ...event, eventType: "outOfOffice", outOfOfficeProperties: { declineMessage: "secret text" } },
    }));
    expect(r.ok).toBe(false);
    expect(w.elicitInput).not.toHaveBeenCalled();
    expect(last(w.audits())).toMatchObject({ decision: "deny", reason: "event-decline-message" });
  });
});
