// F1-1 / F1-3 regression: a send is judged on the message Gmail actually
// builds, which is `raw` and nothing else.
//
// Attacker: a prompt-injected LLM in the user's own session (sandbox code that
//   can call drafts.create, drafts.update and the send endpoints).
// Precondition: OUTBOUND_RECIPIENT_ALLOWLIST lists only the user's own domain
//   (`*@allowed.example`); drafts are created and updated without recipient
//   checks by design.
// Payloads:
//   F1-1 — store a draft addressed to an outsider, then call drafts.send with
//     `{ id, message: { payload: { headers: [To: friend@allowed.example] } } }`
//     (or `raw: ""`/`null`/`0` beside the payload). `payload` is Gmail's
//     output-only parsed view: it is ignored on input, so the stored draft goes
//     out to the outsider.
//   F1-3 — messages.send with `{ raw: <To: outsider>, message: { raw: <To:
//     friend@allowed.example> } }`. Gmail reads the top-level `raw`; the
//     `message` member is an unknown field it ignores.
// Control: messages.send accepts only `raw`, `threadId` and `labelIds`, needs a
//   non-empty `raw` and judges it; drafts.send accepts only `{ id, message }`,
//   needs a non-empty `message.raw` and judges it. Any other key (so `payload`
//   or a `message` wrapper) is refused as `send-unexpected-key` before anything
//   leaves the host.
// Pre-fix: the inspector picked the shape from the body — a `message` key made
//   it judge `body.message` and never look at `body.raw` (F1-3), and whenever
//   `raw` was not a non-empty string it read recipients from
//   `payload.headers` (F1-1), so both decoys were judged and allowed.
import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "@local/scaffold";
import type { InspectRequest } from "@local/shared";
import { gmailProvider } from "../index";
import { inspectDraftSend, inspectOutboundMessage, MASS_SEND_THRESHOLD } from "../inspectors/outbound";

const ENV = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@allowed.example" };
const FRIEND = "friend@allowed.example";
const OUTSIDER = "outsider@evil.example";
const SEND_PATH = "/gmail/v1/users/me/messages/send";
const DRAFT_SEND_PATH = "/gmail/v1/users/me/drafts/send";

const b64url = (s: string): string => Buffer.from(s, "utf8").toString("base64url");
const rawTo = (to: string, subject = "hi"): string => b64url(`To: ${to}\r\nSubject: ${subject}\r\n\r\nbody\r\n`);
const toHeaders = (to: string) => ({ headers: [{ name: "To", value: to }] });

function world(opts: { answer?: unknown } = {}) {
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
  const run = (ctx: Partial<UpstreamCtx> & { method: string; path: string }) =>
    handleUpstreamRequest({
      ctx: ctx as UpstreamCtx,
      spec: gmailProvider.spec,
      surfaceReview: gmailProvider.surfaceReview,
      apiBaseUrl: gmailProvider.apiBaseUrl,
      deploymentName: "test",
      props: { refreshToken: "r", userId: "u" },
      server: { server: { getClientCapabilities: () => ({ elicitation: {} }), elicitInput } } as never,
      oauth: {
        refreshTokenAccessor: () => "r",
        userIdAccessor: () => "u",
        broker: { getOrRefreshAccessToken: async () => "AT" },
      },
      audit: {},
      env: ENV as { ALLOW_PII_IN_LOGS?: string },
      ...(gmailProvider.elicitRenderers ? { elicitRenderers: gmailProvider.elicitRenderers } : {}),
    } as HandleArgs<Record<string, unknown>>);
  const sent = () =>
    fetchSpy.mock.calls.map(([url, init]) => ({
      url: String(url),
      body: typeof init?.body === "string" ? init.body : "",
      auth: new Headers(init?.headers).get("authorization"),
    }));
  return { run, elicits, fetchSpy, audits, sent };
}

async function settle(p: Promise<unknown>): Promise<{ ok: true } | { ok: false; message: string }> {
  try {
    await p;
    return { ok: true };
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : String(e) };
  }
}

/** Run one POST and assert it was denied with `reason` before anything was fetched. */
async function expectDeniedBeforeFetch(path: string, body: unknown, reason: string): Promise<string> {
  const w = world();
  const r = await settle(w.run({ method: "POST", path, body }));
  expect(r.ok, JSON.stringify(body)).toBe(false);
  expect(w.fetchSpy).not.toHaveBeenCalled();
  expect(w.elicits).toHaveLength(0);
  expect(w.audits().map((a) => [a["decision"], a["reason"]])).toEqual([["deny", reason]]);
  return r.ok ? "" : r.message;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("drafts.send is judged on message.raw only (F1-1)", () => {
  it("FIXED (F1-1): { id, message: { payload: <To: friend> } } is denied before any fetch and the error names payload", async () => {
    const message = await expectDeniedBeforeFetch(
      DRAFT_SEND_PATH,
      { id: "r-stored-draft", message: { payload: toHeaders(FRIEND) } },
      "send-unexpected-key",
    );
    expect(message).toContain("payload");
  });

  it.each<[string, Record<string, unknown>]>([
    ["{ payload }", { payload: toHeaders(FRIEND) }],
    ["{ raw: \"\", payload }", { raw: "", payload: toHeaders(FRIEND) }],
    ["{ raw: null, payload }", { raw: null, payload: toHeaders(FRIEND) }],
    ["{ raw: 0, payload }", { raw: 0, payload: toHeaders(FRIEND) }],
    ["{ threadId, labelIds, payload } (the drafts.get shape)", {
      threadId: "t1",
      labelIds: ["DRAFT"],
      payload: toHeaders(FRIEND),
    }],
    ["{ raw: <friend>, payload }", { raw: rawTo(FRIEND), payload: toHeaders(FRIEND) }],
  ])("FIXED (F1-1): message %s is refused as send-unexpected-key", (_label, message) => {
    expect(inspectDraftSend({ body: { id: "d1", message } }, ENV)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "send-unexpected-key",
      message: expect.stringContaining("payload"),
    });
  });

  it.each<[string, Record<string, unknown>]>([
    ["{ raw: \"\" }", { raw: "" }],
    ["{ raw: null }", { raw: null }],
    ["{ raw: 0 }", { raw: 0 }],
    ["{}", {}],
    ["{ threadId }", { threadId: "t1" }],
  ])("FIXED (F1-1): message %s carries no content, so it is draft-send-unvetted-recipients", (_label, message) => {
    expect(inspectDraftSend({ body: { id: "d1", message } }, ENV)).toMatchObject({
      decision: "deny",
      category: "external_data_flow",
      reason: "draft-send-unvetted-recipients",
      message: expect.stringContaining("{ id, message: { raw } }"),
    });
  });

  it("REFUTED: a bare { id } send stays denied, nothing on the wire", async () => {
    await expectDeniedBeforeFetch(DRAFT_SEND_PATH, { id: "d1" }, "draft-send-unvetted-recipients");
  });

  it("REFUTED: { id, message: { raw: <To: outsider> } } stays denied as external-send", async () => {
    await expectDeniedBeforeFetch(DRAFT_SEND_PATH, { id: "d1", message: { raw: rawTo(OUTSIDER) } }, "external-send");
  });

  it("REFUTED: a direct messages.send to the outsider stays denied as external-send", async () => {
    await expectDeniedBeforeFetch(SEND_PATH, { raw: rawTo(OUTSIDER) }, "external-send");
  });

  it("accepts { id, message: { raw: <To: friend> } } and sends exactly that raw", async () => {
    const w = world();
    const raw = rawTo(FRIEND);
    const r = await settle(w.run({ method: "POST", path: DRAFT_SEND_PATH, body: { id: "d1", message: { raw } } }));
    expect(r).toEqual({ ok: true });
    expect(w.sent()).toHaveLength(1);
    const wire = w.sent()[0]!;
    expect(wire.url).toContain(DRAFT_SEND_PATH);
    expect(JSON.parse(wire.body)).toEqual({ id: "d1", message: { raw } });
    expect(wire.auth).toBe("Bearer AT");
  });

  it("accepts the drafts.get message keys (id, threadId, labelIds) beside raw", () => {
    const body = { id: "d1", message: { id: "m1", threadId: "t1", labelIds: ["DRAFT"], raw: rawTo(FRIEND) } };
    expect(inspectDraftSend({ body }, ENV)).toEqual({ decision: "allow" });
  });

  it("refuses an unknown top-level key on drafts.send, naming it", () => {
    expect(inspectDraftSend({ body: { id: "d1", message: { raw: rawTo(FRIEND) }, raw: rawTo(OUTSIDER) } }, ENV))
      .toMatchObject({ decision: "deny", reason: "send-unexpected-key", message: expect.stringContaining("raw") });
  });

  it.each<[string, InspectRequest, string]>([
    ["a missing id", { body: { message: { raw: rawTo(FRIEND) } } }, "draft-send-no-id"],
    ["an empty id", { body: { id: "", message: { raw: rawTo(FRIEND) } } }, "draft-send-no-id"],
    ["a numeric id", { body: { id: 7, message: { raw: rawTo(FRIEND) } } }, "draft-send-no-id"],
    ["a non-object message", { body: { id: "d1", message: "raw" } }, "draft-send-unvetted-recipients"],
    ["an array body", { body: [] }, "draft-send-body-not-object"],
    ["a string body", { body: "x" }, "draft-send-body-not-object"],
    ["a media body", {
      rawBody: new TextEncoder().encode(`To: ${FRIEND}\r\n\r\nbody`),
      contentType: "message/rfc822",
    }, "draft-send-body-not-object"],
    ["a multipart body", {
      multipart: [{ name: "media", contentType: "message/rfc822", value: `To: ${FRIEND}\r\n\r\nbody` }],
      contentType: "multipart/related",
    }, "draft-send-body-not-object"],
  ])("denies %s", (_label, req, reason) => {
    expect(inspectDraftSend(req, ENV)).toMatchObject({ decision: "deny", reason });
  });
});

describe("messages.send is judged on the top-level raw only (F1-3)", () => {
  it("FIXED (F1-3): { raw: <outsider>, message: { raw: <friend> } } is denied before any fetch", async () => {
    const message = await expectDeniedBeforeFetch(
      SEND_PATH,
      { raw: rawTo(OUTSIDER), message: { raw: rawTo(FRIEND) } },
      "send-unexpected-key",
    );
    expect(message).toContain("message");
  });

  it("FIXED (F1-3): { raw: <outsider>, message: { payload: <friend> } } is denied before any fetch", async () => {
    await expectDeniedBeforeFetch(
      SEND_PATH,
      { raw: rawTo(OUTSIDER), message: { payload: toHeaders(FRIEND) } },
      "send-unexpected-key",
    );
  });

  it("REFUTED: { raw: <outsider> } alone is external-send, nothing sent", async () => {
    await expectDeniedBeforeFetch(SEND_PATH, { raw: rawTo(OUTSIDER) }, "external-send");
  });

  it.each<[string, Record<string, unknown>]>([
    ["{ raw }", { raw: rawTo(FRIEND) }],
    ["{ raw, threadId }", { raw: rawTo(FRIEND), threadId: "t1" }],
    ["{ raw, threadId, labelIds }", { raw: rawTo(FRIEND), threadId: "t1", labelIds: ["INBOX"] }],
  ])("accepts %s and sends it verbatim with the host's token", async (_label, body) => {
    const w = world();
    const r = await settle(w.run({ method: "POST", path: SEND_PATH, body }));
    expect(r).toEqual({ ok: true });
    expect(w.sent()).toHaveLength(1);
    expect(JSON.parse(w.sent()[0]!.body)).toEqual(body);
    expect(w.sent()[0]!.auth).toBe("Bearer AT");
  });

  it("denies { raw, id } as send-unexpected-key, naming id", async () => {
    const message = await expectDeniedBeforeFetch(SEND_PATH, { raw: rawTo(FRIEND), id: "x" }, "send-unexpected-key");
    expect(message).toContain("remove: id");
  });

  it("denies the previously accepted { payload: { headers } } shape as send-unexpected-key", async () => {
    const message = await expectDeniedBeforeFetch(SEND_PATH, { payload: toHeaders(FRIEND) }, "send-unexpected-key");
    expect(message).toContain("payload");
  });

  it("lists every stray key, sorted", () => {
    const r = inspectOutboundMessage({ body: { snippet: "s", raw: rawTo(FRIEND), payload: {}, message: {} } }, ENV);
    expect(r).toMatchObject({ decision: "deny", reason: "send-unexpected-key" });
    expect(r.message).toContain("remove: message, payload, snippet.");
  });

  it.each<[string, Record<string, unknown>]>([
    ["{}", {}],
    ["{ raw: \"\" }", { raw: "" }],
    ["{ raw: null }", { raw: null }],
    ["{ raw: 0 }", { raw: 0 }],
    ["{ threadId }", { threadId: "t1" }],
  ])("denies %s as send-no-raw", (_label, body) => {
    expect(inspectOutboundMessage({ body }, ENV)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "send-no-raw",
    });
  });

  it("an undecodable raw stays send-no-recipients", () => {
    expect(inspectOutboundMessage({ body: { raw: "%%%not base64%%%" } }, ENV)).toMatchObject({
      decision: "deny",
      reason: "send-no-recipients",
    });
  });
});

describe("the JSON messages.send endpoint reads a JSON body only (F1-3 follow-up)", () => {
  // Pre-fix, a non-JSON body on the JSON endpoint was judged on the RFC 822
  // text the inspector could find in it (a visible `To: friend` line), while
  // Google parses the request its own way (a form field or a JSON member
  // carrying an attacker `raw`). Each of these reached fetch.
  const ATTACKER = rawTo(OUTSIDER);

  it.each<[string, Partial<UpstreamCtx>]>([
    ["a form-encoded body with a visible To line", {
      rawBody: true,
      body: `message.raw=${ATTACKER}&quotaUser=\r\nTo: ${FRIEND}\r\n\r\n`,
      contentType: "application/x-www-form-urlencoded",
    }],
    ["a text/plain body that is JSON with a literal To line", {
      rawBody: true,
      body: `{"raw":"${ATTACKER}","threadId":"\r\nTo: ${FRIEND}\r\n\r\n"}`,
      contentType: "text/plain",
    }],
    ["a multipart body with a JSON metadata part", {
      multipart: [
        { name: "metadata", contentType: "application/json", value: `{"raw":"${ATTACKER}"}` },
        { name: "media", contentType: "message/rfc822", value: `To: ${FRIEND}\r\n\r\nhi` },
      ],
    }],
    ["a message/rfc822 body", {
      rawBody: true,
      body: `To: ${FRIEND}\r\nSubject: s\r\n\r\nhello`,
      contentType: "message/rfc822",
    }],
  ])("FIXED: %s is denied as send-no-raw before any fetch", async (_label, ctx) => {
    const w = world();
    const r = await settle(w.run({ method: "POST", path: SEND_PATH, ...ctx }));
    expect(r.ok).toBe(false);
    expect(w.fetchSpy).not.toHaveBeenCalled();
    expect(w.audits().map((a) => [a["decision"], a["reason"]])).toEqual([["deny", "send-no-raw"]]);
    expect(r.ok ? "" : r.message).toContain("uploadType=media");
  });

  it.each<[string, InspectRequest]>([
    ["a rawBody", { rawBody: new TextEncoder().encode(`To: ${FRIEND}\r\n\r\nbody`), contentType: "message/rfc822" }],
    ["a multipart body", {
      multipart: [{ name: "media", contentType: "message/rfc822", value: `To: ${FRIEND}\r\n\r\nbody` }],
      contentType: "multipart/form-data",
    }],
    ["a string body", { body: "raw" }],
    ["an array body", { body: [{ raw: rawTo(FRIEND) }] }],
    ["no body", {}],
  ])("inspectOutboundMessage denies %s as send-no-raw, pointing at the media upload", (_label, req) => {
    const r = inspectOutboundMessage(req, ENV);
    expect(r).toMatchObject({ decision: "deny", category: "malformed", reason: "send-no-raw" });
    expect(r.message).toContain("/upload/gmail/v1/users/{userId}/messages/send?uploadType=media");
  });
});

describe("the stray-key denial names the field Gmail builds the message from", () => {
  it("messages.send: from `raw`", () => {
    expect(inspectOutboundMessage({ body: { raw: rawTo(FRIEND), payload: {} } }, ENV).message)
      .toContain("Gmail builds the sent message from `raw` alone");
  });

  it("drafts.send: from `message.raw`, for both the Draft and its message", () => {
    for (const body of [
      { id: "d1", message: { raw: rawTo(FRIEND), payload: {} } },
      { id: "d1", message: { raw: rawTo(FRIEND) }, payload: {} },
    ]) {
      expect(inspectDraftSend({ body }, ENV).message).toContain("Gmail builds the sent message from `message.raw` alone");
    }
  });
});

describe("the mass-send subject is not cut by the inspector (carry-over)", () => {
  const to = Array.from({ length: MASS_SEND_THRESHOLD + 1 }, (_, i) => `staff${i}@allowed.example`).join(", ");
  const subject = "S".repeat(250) + "TAIL" + "s".repeat(46);

  it("inspectOutboundMessage returns the whole 300-character subject", () => {
    expect(subject).toHaveLength(300);
    const r = inspectOutboundMessage({ body: { raw: rawTo(to, subject) } }, ENV);
    expect(r).toMatchObject({ decision: "elicit", reason: "mass-send" });
    expect(r.summary?.["subject"]).toBe(subject);
  });

  it("the dialog shows it cut with … by the scaffold", async () => {
    const w = world();
    const r = await settle(w.run({ method: "POST", path: SEND_PATH, body: { raw: rawTo(to, subject) } }));
    expect(r).toEqual({ ok: true });
    expect(w.elicits).toHaveLength(1);
    const line = w.elicits[0]!.message.split("\n").find((l) => l.includes("subject: "));
    expect(line).toBeDefined();
    expect(line).toContain("…");
    expect(line).not.toContain("TAIL");
  });
});
