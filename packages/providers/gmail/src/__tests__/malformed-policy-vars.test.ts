// A malformed per-deployment policy var (CALENDAR_WRITE_ALLOWLIST,
// OUTBOUND_RECIPIENT_ALLOWLIST) makes the allow-list parser throw with the
// offending entry quoted. End to end through the real request handler: the
// request is denied before anything is sent, the deny is audited, and the
// operator's config text never reaches the caller (the model).
//
// Pre-fix: a throw from a sync `inspect` escaped `handleUpstreamRequest` with
//   no deny audit line and its message (quoting the config) as the error.
//   A throw inside the `inspectUpstream` hook was already a fixed-text
//   `upstream-inspect-failed` deny (covered here as a control).
import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "@local/scaffold";
import { gmailProvider } from "../index";

const SENTINEL = "CFG-SENTINEL-entry";
const ME = "me@corp.example";

function world(env: Record<string, string>, stored?: unknown) {
  const fetchSpy = vi.fn<typeof fetch>(async (input, init) => {
    const url = new URL(String(input));
    if ((init?.method ?? "GET") === "GET" && /\/calendar\/v3\/calendars\/[^/]+\/events\/[^/]+$/.test(url.pathname)) {
      return new Response(JSON.stringify(stored ?? {}), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ id: "upstream-ok" }), { status: 200, headers: { "content-type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchSpy);
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  const audits = () =>
    logSpy.mock.calls
      .map((c) => c[0])
      .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
      .map((s) => JSON.parse(s.slice(6)) as Record<string, unknown>);
  const run = async (ctx: Partial<UpstreamCtx> & { method: string; path: string }): Promise<Error> => {
    try {
      await handleUpstreamRequest({
        ctx: ctx as UpstreamCtx,
        spec: gmailProvider.spec,
        surfaceReview: gmailProvider.surfaceReview,
        apiBaseUrl: gmailProvider.apiBaseUrl,
        deploymentName: "test",
        props: { refreshToken: "r", userId: "u" },
        server: { server: { getClientCapabilities: () => ({ elicitation: {} }), elicitInput: vi.fn() } } as never,
        oauth: {
          refreshTokenAccessor: () => "r",
          userIdAccessor: () => "u",
          broker: { getOrRefreshAccessToken: async () => "AT" },
        },
        audit: {},
        env: env as { ALLOW_PII_IN_LOGS?: string },
      } as HandleArgs<Record<string, unknown>>);
    } catch (e) {
      return e as Error;
    }
    throw new Error("expected the request to be denied");
  };
  const writes = () => fetchSpy.mock.calls.filter(([, init]) => (init?.method ?? "GET") !== "GET");
  return { run, audits, fetchSpy, writes };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const EVENT = { summary: "Notes", start: { dateTime: "2026-12-01T09:00:00Z" }, end: { dateTime: "2026-12-01T10:00:00Z" } };

describe("malformed policy vars: deny, audit, no config text to the caller", () => {
  it("FIXED: malformed CALENDAR_WRITE_ALLOWLIST on events.insert → inspector-threw, nothing sent", async () => {
    const w = world({ OUTBOUND_RECIPIENT_ALLOWLIST: "", CALENDAR_WRITE_ALLOWLIST: `primary,${SENTINEL}` });
    const err = await w.run({ method: "POST", path: "/calendar/v3/calendars/primary/events", body: EVENT });
    expect(err.message).toMatch(/denied/);
    expect(err.message).not.toContain(SENTINEL);
    expect(err.message).not.toContain("CALENDAR_WRITE_ALLOWLIST");
    expect(w.fetchSpy).not.toHaveBeenCalled();
    const a = w.audits();
    expect(a[a.length - 1]).toMatchObject({ decision: "deny", category: "malformed", reason: "inspector-threw" });
    expect(JSON.stringify(a)).not.toContain(SENTINEL);
  });

  it("FIXED: malformed OUTBOUND_RECIPIENT_ALLOWLIST on messages.send → inspector-threw, nothing sent", async () => {
    const w = world({ OUTBOUND_RECIPIENT_ALLOWLIST: `*@corp.example,${SENTINEL}`, CALENDAR_WRITE_ALLOWLIST: "primary" });
    const raw = Buffer.from(`To: friend@corp.example\r\nSubject: hi\r\n\r\nbody\r\n`, "utf8").toString("base64url");
    const err = await w.run({ method: "POST", path: "/gmail/v1/users/me/messages/send", body: { raw } });
    expect(err.message).toMatch(/denied/);
    expect(err.message).not.toContain(SENTINEL);
    expect(w.fetchSpy).not.toHaveBeenCalled();
    const a = w.audits();
    expect(a[a.length - 1]).toMatchObject({ decision: "deny", category: "malformed", reason: "inspector-threw" });
  });

  it("FIXED: malformed OUTBOUND_RECIPIENT_ALLOWLIST on an events.insert with attendees → inspector-threw", async () => {
    const w = world({ OUTBOUND_RECIPIENT_ALLOWLIST: SENTINEL, CALENDAR_WRITE_ALLOWLIST: "primary" });
    const err = await w.run({
      method: "POST",
      path: "/calendar/v3/calendars/primary/events",
      body: { ...EVENT, attendees: [{ email: "friend@corp.example" }] },
    });
    expect(err.message).not.toContain(SENTINEL);
    expect(w.fetchSpy).not.toHaveBeenCalled();
    const a = w.audits();
    expect(a[a.length - 1]).toMatchObject({ decision: "deny", category: "malformed", reason: "inspector-threw" });
  });

  it("control: malformed OUTBOUND_RECIPIENT_ALLOWLIST hit inside the stored-event hook (events.patch) → upstream-inspect-failed, no write", async () => {
    const stored = {
      id: "ownMeetingId",
      summary: "Vendor sync",
      organizer: { email: ME, self: true },
      attendees: [{ email: "outsider@evil.example" }, { self: true, email: ME }],
    };
    const w = world({ OUTBOUND_RECIPIENT_ALLOWLIST: SENTINEL, CALENDAR_WRITE_ALLOWLIST: "primary" }, stored);
    const err = await w.run({ method: "PATCH", path: "/calendar/v3/calendars/primary/events/ownMeetingId", body: { summary: "x" } });
    expect(err.message).toMatch(/denied/);
    expect(err.message).not.toContain(SENTINEL);
    expect(w.writes()).toEqual([]);
    const a = w.audits();
    expect(a[a.length - 1]).toMatchObject({ decision: "deny", category: "malformed", reason: "upstream-inspect-failed" });
  });
});
