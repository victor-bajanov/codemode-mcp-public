// F-7 regression, end to end: the real request handler with the real Gmail
// provider. A Calendar event write sent through a raw channel (bodyBase64 or
// rawBody) whose content-type is a JSON variant the handler did not recognise
// (edge whitespace, `text/json`, `application/x-json`) used to reach
// `inspectEventAttendees` as `rawBody`, which it allowed, while the wire
// carried the JSON event, off-allowlist attendee included.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "@local/scaffold";
import { gmailProvider } from "../index";

const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@allowed.example" };
const EVENT = {
  summary: "x",
  start: { dateTime: "2026-10-09T10:00:00Z" },
  end: { dateTime: "2026-10-09T11:00:00Z" },
  attendees: [{ email: "outsider@evil.example" }],
};
const EVENT_JSON = JSON.stringify(EVENT);
const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");

function run(ctx: UpstreamCtx) {
  const fetchSpy = vi.fn<typeof fetch>(async () => new Response("{}", { status: 200 }));
  vi.stubGlobal("fetch", fetchSpy);
  vi.spyOn(console, "log").mockImplementation(() => {});
  const promise = handleUpstreamRequest({
    ctx,
    spec: gmailProvider.spec,
    surfaceReview: gmailProvider.surfaceReview,
    apiBaseUrl: gmailProvider.apiBaseUrl,
    deploymentName: "test",
    props: { refreshToken: "r", userId: "u" },
    server: {} as never,
    oauth: {
      refreshTokenAccessor: () => "r",
      userIdAccessor: () => "u",
      broker: { getOrRefreshAccessToken: async () => "AT" },
    },
    audit: {},
    env: ENV as { ALLOW_PII_IN_LOGS?: string },
  });
  return { promise, fetchSpy };
}

const PATH = "/calendar/v3/calendars/primary/events";

describe("calendar.events.insert: raw channels cannot bypass the attendee allowlist (F-7)", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("control: the plain JSON body is denied", async () => {
    const { promise, fetchSpy } = run({ method: "POST", path: PATH, body: EVENT, query: { sendUpdates: "all" } });
    await expect(promise).rejects.toThrow(/denied by surface review/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  for (const contentType of [
    "application/json",
    " application/json",
    "\tapplication/json",
    "application/json ",
    "text/json",
    "application/x-json",
    "Application/JSON; charset=utf-8",
  ]) {
    it(`bodyBase64 with content-type ${JSON.stringify(contentType)} is denied, nothing is sent`, async () => {
      const { promise, fetchSpy } = run({
        method: "POST",
        path: PATH,
        query: { sendUpdates: "all" },
        contentType,
        bodyBase64: b64(EVENT_JSON),
      });
      await expect(promise).rejects.toThrow(/denied by surface review/);
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  }

  it("rawBody with a JSON-variant content-type is denied", async () => {
    const { promise, fetchSpy } = run({
      method: "POST",
      path: PATH,
      contentType: "text/json",
      rawBody: true,
      body: EVENT_JSON,
    });
    await expect(promise).rejects.toThrow(/denied by surface review/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("raw bytes under a non-JSON content-type are denied by the inspector (fail closed)", async () => {
    const { promise, fetchSpy } = run({
      method: "POST",
      path: PATH,
      contentType: "text/plain",
      bodyBase64: b64(EVENT_JSON),
    });
    await expect(promise).rejects.toThrow(/JSON object in `body`/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("a JSON content-type over bytes that do not parse is denied", async () => {
    const { promise, fetchSpy } = run({
      method: "POST",
      path: PATH,
      contentType: "text/json",
      bodyBase64: b64(EVENT_JSON + "}"),
    });
    await expect(promise).rejects.toThrow(/denied by surface review/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("an allowlisted attendee sent as whitespace-padded JSON goes out canonically with the trimmed content-type", async () => {
    const ok = { ...EVENT, attendees: [{ email: "staff@allowed.example" }] };
    const { promise, fetchSpy } = run({
      method: "POST",
      path: PATH,
      contentType: " application/json ",
      bodyBase64: b64(JSON.stringify(ok)),
    });
    await promise;
    const init = fetchSpy.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>)["content-type"]).toBe("application/json");
    expect(init.body).toBe(JSON.stringify(ok));
  });
});
