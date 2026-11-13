// D-3 (Medium) and F1-7 regression, end to end with the real Gmail + Calendar
// provider: inspected JSON bodies were sent under any Content-Type.
//
// Attacker: code running in the sandbox (prompt-injected model).
// Precondition: an inspected JSON operation (messages.send, events.insert,
//   filters.create) and an allowlist the visible payload satisfies.
// Payloads: (F1-7) an events.insert whose `description` carries `+ACI-`
//   sequences — UTF-7 for `"` — that a UTF-7 reader decodes into an extra
//   `attendees` member, sent as `application/json; charset=utf-7`; (D-3) the
//   same object bodies under form, XML, text, multipart and UTF-16 labels.
// Control: on a gated operation a JSON body must be labelled JSON with no
//   parameter but `charset=utf-8`, and goes out as exactly `application/json`;
//   anything else is denied before the inspector runs.
// Why the pre-fix code failed: the inspector parsed the JSON object it was
//   given and allowed it, while the wire carried the sandbox's label, so the
//   upstream could decode the same bytes as a different document.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "@local/scaffold";
import { gmailProvider } from "../index";

const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "ok@allowed.example", CALENDAR_WRITE_ALLOWLIST: "primary" };

function run(ctx: UpstreamCtx) {
  const fetchSpy = vi.fn<typeof fetch>(async () => new Response('{"id":"x"}', { status: 200 }));
  vi.stubGlobal("fetch", fetchSpy);
  const audits: Array<Record<string, unknown>> = [];
  vi.spyOn(console, "log").mockImplementation((line: unknown) => {
    if (typeof line === "string" && line.startsWith("AUDIT ")) audits.push(JSON.parse(line.slice(6)) as Record<string, unknown>);
  });
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
    ...(gmailProvider.standardQueryParams ? { standardQueryParams: gmailProvider.standardQueryParams } : {}),
    audit: {},
    env: ENV as { ALLOW_PII_IN_LOGS?: string },
  });
  return {
    promise,
    fetchSpy,
    audits,
    wireContentType: () => ((fetchSpy.mock.calls[0]![1] as RequestInit).headers as Record<string, string>)["content-type"],
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const DENIED = /sends its `body` as JSON; on this operation the content type must be application\/json/;

describe("Gmail provider: gated JSON bodies are sent as application/json (D-3, F1-7)", () => {
  it("FIXED (F1-7): events.insert under 'application/json; charset=utf-7' with a UTF-7-only attendees member is denied; nothing sent", async () => {
    const q = "+ACI-"; // UTF-7 for a double quote
    const description = `x${q},${q}attendees${q}:[{${q}email${q}:${q}attacker@evil.example${q}}],${q}y${q}:${q}z`;
    const r = run({
      method: "POST",
      path: "/calendar/v3/calendars/primary/events",
      contentType: "application/json; charset=utf-7",
      query: { sendUpdates: "all" },
      body: {
        summary: "sync",
        description,
        start: { dateTime: "2026-12-01T09:00:00Z" },
        end: { dateTime: "2026-12-01T09:30:00Z" },
      },
    });
    await expect(r.promise).rejects.toThrow(DENIED);
    expect(r.fetchSpy).not.toHaveBeenCalled();
    expect(r.audits.at(-1)).toMatchObject({
      operationId: "calendar.events.insert",
      decision: "deny",
      category: "malformed",
      reason: "json-body-non-json-content-type",
      queryKeys: ["sendUpdates"],
    });
  });

  const CASES: Array<[string, UpstreamCtx]> = [
    [
      "messages.send",
      {
        method: "POST",
        path: "/gmail/v1/users/me/messages/send",
        body: { raw: Buffer.from("To: ok@allowed.example\r\nSubject: s\r\n\r\nb").toString("base64url") },
      },
    ],
    [
      "events.insert",
      { method: "POST", path: "/calendar/v3/calendars/primary/events", body: { summary: "x", attendees: [{ email: "ok@allowed.example" }] } },
    ],
    [
      "filters.create",
      { method: "POST", path: "/gmail/v1/users/me/settings/filters", body: { criteria: { from: "a@b.example" }, action: { addLabelIds: ["Label_1"] } } },
    ],
  ];
  const LABELS = [
    "application/x-www-form-urlencoded",
    "text/xml",
    "text/plain",
    "multipart/form-data; boundary=x",
    "application/json; charset=utf-16",
    "application/json; charset=utf-7",
  ];
  for (const [name, ctx] of CASES) {
    for (const contentType of LABELS) {
      it(`FIXED (D-3): ${name} under ${JSON.stringify(contentType)} is denied before inspection`, async () => {
        const r = run({ ...ctx, contentType });
        await expect(r.promise).rejects.toThrow(DENIED);
        expect(r.fetchSpy).not.toHaveBeenCalled();
      });
    }
  }

  it("control: messages.send with 'application/json; charset=utf-8' goes out as exactly application/json", async () => {
    const r = run({ ...CASES[0]![1], contentType: "application/json; charset=utf-8" });
    await r.promise;
    expect(r.wireContentType()).toBe("application/json");
  });
});
