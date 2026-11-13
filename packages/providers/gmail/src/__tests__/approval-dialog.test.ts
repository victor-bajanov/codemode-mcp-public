// D-1 / F1-4 regression, end to end: the real request handler with the real
// Gmail + Calendar provider; only fetch, the token broker and the MCP client's
// elicitation answer are faked.
//
// Attacker: a prompt-injected LLM in the user's own session. It controls the
//   chat narrative ("I'll just delete that one newsletter — please approve")
//   and the request that actually needs approval.
// Precondition: an MCP client that supports elicitation.
// Payload: a permanent delete / thread delete / event delete aimed at a
//   different target than the one narrated, a 30-recipient phishing send, a
//   1,000-message batch delete, a trash or auto-archive filter, a forged import.
// Control: the dialog message names the request (`Request: METHOD path`, the
//   query, and resolved facts taken from the path and the inspector summary);
//   the only input is `confirm`, and only `confirm: true` approves.
// Pre-fix: the message was a constant plus the operationId, the facts were
//   turned into blank typed inputs, the path and query were never shown, the
//   one id a renderer computed came from the sandbox-supplied body, and any
//   typed answer (including `confirm: false`) approved.
import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "@local/scaffold";
import { gmailProvider } from "../index";

const CONFIRM_ONLY = {
  type: "object",
  properties: { confirm: { type: "boolean" } },
  required: ["confirm"],
  additionalProperties: false,
};

interface ElicitCall {
  message: string;
  requestedSchema: unknown;
}

const b64url = (s: string): string => Buffer.from(s, "utf8").toString("base64url");

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
  const elicits: ElicitCall[] = [];
  const elicitInput = vi.fn(async (params: ElicitCall) => {
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
      env: (opts.env ?? { OUTBOUND_RECIPIENT_ALLOWLIST: "*@corp.example", CALENDAR_WRITE_ALLOWLIST: "primary" }) as { ALLOW_PII_IN_LOGS?: string },
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

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Gmail approval dialogs show what is being approved (D-1, F1-4)", () => {
  it("FIXED (D-1): two thread deletes produce different dialogs, each naming its thread", async () => {
    const w = world();
    await w.run({ method: "DELETE", path: "/gmail/v1/users/me/threads/newsletter-thread-0001" });
    await w.run({ method: "DELETE", path: "/gmail/v1/users/me/threads/SIGNED-CONTRACT-THREAD-9999" });
    expect(w.elicits).toHaveLength(2);
    const [a, b] = w.elicits.map((c) => c.message);
    expect(a).not.toBe(b);
    expect(a).toContain("Request: DELETE /gmail/v1/users/me/threads/newsletter-thread-0001");
    expect(a).toContain('threadId: "newsletter-thread-0001"');
    expect(b).toContain("Request: DELETE /gmail/v1/users/me/threads/SIGNED-CONTRACT-THREAD-9999");
    expect(b).toContain('threadId: "SIGNED-CONTRACT-THREAD-9999"');
    expect(b).toContain("Confirm Gmail permanent delete (gmail.users.threads.delete)");
    for (const c of w.elicits) expect(c.requestedSchema).toEqual(CONFIRM_ONLY);
  });

  it("FIXED (F1-4): two permanent message deletes differ and name their message", async () => {
    const w = world();
    await w.run({ method: "DELETE", path: "/gmail/v1/users/me/messages/18c0ffee00000001" });
    await w.run({ method: "DELETE", path: "/gmail/v1/users/me/messages/18deadbeef999999" });
    expect(w.elicits[0]!.message).not.toBe(w.elicits[1]!.message);
    expect(w.elicits[0]!.message).toContain('messageId: "18c0ffee00000001"');
    expect(w.elicits[1]!.message).toContain('messageId: "18deadbeef999999"');
    expect(w.elicits[1]!.message).toContain("Confirm Gmail permanent delete (gmail.users.messages.delete)");
  });

  it("FIXED (D-1): a 30-recipient send shows recipients, subject and count; the only input is confirm", async () => {
    const w = world({ env: { OUTBOUND_RECIPIENT_ALLOWLIST: "*@corp.example" } });
    const to = Array.from({ length: 30 }, (_, i) => `staff${i}@corp.example`).join(", ");
    const rfc822 = `To: ${to}\r\nSubject: URGENT wire the funds to the new account today\r\n\r\nbody`;
    const r = await settle(w.run({
      method: "POST",
      path: "/gmail/v1/users/me/messages/send",
      body: { raw: b64url(rfc822) },
    }));
    expect(r.ok).toBe(true);
    expect(w.elicits).toHaveLength(1);
    const { message, requestedSchema } = w.elicits[0]!;
    expect(message).toContain("Confirm Gmail external send (gmail.users.messages.send)");
    expect(message).toContain("Request: POST /gmail/v1/users/me/messages/send");
    expect(message).toContain('recipients: "staff0@corp.example, staff1@corp.example, staff2@corp.example (+27)"');
    expect(message).toContain('subject: "URGENT wire the funds to the new account today"');
    expect(message).toContain("count: 30");
    expect(requestedSchema).toEqual(CONFIRM_ONLY);
  });

  it("FIXED (D-1): an event delete shows the query (sendUpdates=all) and the event id", async () => {
    const w = world();
    await w.run({ method: "DELETE", path: "/calendar/v3/calendars/primary/events/evt1" });
    await w.run({
      method: "DELETE",
      path: "/calendar/v3/calendars/primary/events/BOARD-MEETING",
      query: { sendUpdates: "all" },
    });
    expect(w.elicits[0]!.message).not.toBe(w.elicits[1]!.message);
    expect(w.elicits[0]!.message).not.toContain("Query:");
    const m = w.elicits[1]!.message;
    expect(m).toContain("Confirm Gmail permanent delete (calendar.events.delete)");
    expect(m).toContain('Query: sendUpdates="all"');
    expect(m).toContain('calendarId: "primary"');
    expect(m).toContain('eventId: "BOARD-MEETING"');
    expect(w.sent()[1]!.url).toBe(
      `${gmailProvider.apiBaseUrl}/calendar/v3/calendars/primary/events/BOARD-MEETING?sendUpdates=all`,
    );
  });

  it("FIXED (D-1): an unticked box ({confirm:false}) is a decline — nothing is sent", async () => {
    const w = world({ answer: { action: "accept", content: { confirm: false } } });
    const r = await settle(w.run({ method: "DELETE", path: "/gmail/v1/users/me/messages/18c0ffee" }));
    expect(r).toEqual({
      ok: false,
      message: "Operation gmail.users.messages.delete requires user approval; outcome: declined",
    });
    expect(w.fetchSpy).not.toHaveBeenCalled();
    const approval = w.audits().find((a) => a["decision"] === "elicit");
    expect(approval?.["elicitationOutcome"]).toBe("declined");
  });

  it("FIXED (D-1): an answer typed into extra fields does not approve", async () => {
    const w = world({ answer: { action: "accept", content: { confirm: true, count: 1 } } });
    const r = await settle(w.run({
      method: "POST",
      path: "/gmail/v1/users/me/messages/batchDelete",
      body: { ids: ["a", "b"] },
    }));
    expect(r).toEqual({
      ok: false,
      message: "Operation gmail.users.messages.batchDelete requires user approval; outcome: declined",
    });
    expect(w.fetchSpy).not.toHaveBeenCalled();
    const approval = w.audits().find((a) => a["decision"] === "elicit");
    expect(approval?.["elicitationOutcome"]).toBe("declined");
  });

  it("FIXED (D-1): the shown message id comes from the path, not from a decoy body.id", async () => {
    const w = world({ env: { ALLOW_PII_IN_LOGS: "true" } });
    await w.run({
      method: "DELETE",
      path: "/gmail/v1/users/me/messages/THE-MESSAGE-ACTUALLY-DELETED",
      body: { id: "harmless-newsletter-id" },
    });
    const m = w.elicits[0]!.message;
    expect(m).toContain('messageId: "THE-MESSAGE-ACTUALLY-DELETED"');
    expect(m).not.toContain("harmless-newsletter-id");
    const approval = w.audits().find((a) => a["decision"] === "elicit")!;
    expect(approval["elicitFields"]).toEqual({ messageId: "THE-MESSAGE-ACTUALLY-DELETED" });
    expect(w.sent()[0]!.url).toBe(
      `${gmailProvider.apiBaseUrl}/gmail/v1/users/me/messages/THE-MESSAGE-ACTUALLY-DELETED`,
    );
  });

  it("FIXED (F1-4): a 1,000-message batch delete shows count 1000 and the first ids", async () => {
    const w = world();
    const ids = Array.from({ length: 1000 }, (_, i) => `18${String(i).padStart(14, "0")}`);
    const r = await settle(w.run({ method: "POST", path: "/gmail/v1/users/me/messages/batchDelete", body: { ids } }));
    expect(r.ok).toBe(true);
    const c = w.elicits[0]!;
    expect(c.message).toContain("Confirm Gmail bulk delete (gmail.users.messages.batchDelete)");
    expect(c.message).toContain("count: 1000");
    expect(c.message).toContain(`ids: "${ids[0]}, ${ids[1]}, ${ids[2]} (+997)"`);
    expect(c.requestedSchema).toEqual(CONFIRM_ONLY);
  });

  it("FIXED (F1-4): a trash filter is headlined as a filter and shows its criteria and action", async () => {
    const w = world();
    const body = { criteria: { from: "security@bank.example" }, action: { addLabelIds: ["TRASH"] } };
    const r = await settle(w.run({ method: "POST", path: "/gmail/v1/users/me/settings/filters", body }));
    expect(r.ok).toBe(true);
    const m = w.elicits[0]!.message;
    expect(m).toContain("Confirm Gmail filter (gmail.users.settings.filters.create): moves matching mail to TRASH");
    expect(m).toContain('effect: "moves matching mail to TRASH"');
    expect(m).toContain('from: "security@bank.example"');
    expect(m).toContain(`criteria: ${JSON.stringify(`{"from":"security@bank.example"}`)}`);
    expect(m).toContain(`action: ${JSON.stringify(`{"addLabelIds":["TRASH"]}`)}`);
  });

  it("FIXED (F1-4): an auto-archive filter shows the content of criteria and action", async () => {
    const w = world();
    const body = { criteria: { from: "alerts@bank.example" }, action: { removeLabelIds: ["INBOX"] } };
    await w.run({ method: "POST", path: "/gmail/v1/users/me/settings/filters", body });
    const c = w.elicits[0]!;
    expect(c.message).toContain('effect: "removes INBOX (archives matching mail)"');
    expect(c.message).toContain('from: "alerts@bank.example"');
    expect(c.message).toContain(`criteria: ${JSON.stringify(`{"from":"alerts@bank.example"}`)}`);
    expect(c.message).toContain(`action: ${JSON.stringify(`{"removeLabelIds":["INBOX"]}`)}`);
    expect(c.requestedSchema).toEqual(CONFIRM_ONLY);
  });

  it("FIXED (D-1): a padded removeLabelIds list cannot hide a TRASH action from the dialog", async () => {
    const w = world();
    const padding = Array.from({ length: 40 }, (_, i) => `Label_${String(i).padStart(8, "0")}`);
    const body = {
      criteria: { from: "security@bank.example" },
      action: { removeLabelIds: padding, addLabelIds: ["TRASH"] },
    };
    const r = await settle(w.run({ method: "POST", path: "/gmail/v1/users/me/settings/filters", body }));
    expect(r.ok).toBe(true);
    const m = w.elicits[0]!.message;
    expect(m).toContain('effect: "moves matching mail to TRASH"');
    expect(m).toContain('from: "security@bank.example"');
    // The action blob is cut visibly by the scaffold, not silently upstream.
    expect(m).toMatch(/action: "\{\\"removeLabelIds\\":\[.*…"/);
  });

  it("FIXED (D-1): a padded negatedQuery cannot push the sender out of the dialog", async () => {
    const w = world();
    const body = {
      criteria: { negatedQuery: "z".repeat(400), from: "security@bank.example" },
      action: { addLabelIds: ["TRASH"] },
    };
    await w.run({ method: "POST", path: "/gmail/v1/users/me/settings/filters", body });
    const m = w.elicits[0]!.message;
    expect(m).toContain('effect: "moves matching mail to TRASH"');
    expect(m).toContain('from: "security@bank.example"');
  });

  it("FIXED (F1-4): imports are headlined as imports and show their query and calendar", async () => {
    const w = world();
    const forged = b64url(
      "From: ceo@corp.example\r\nTo: victim@corp.example\r\nSubject: Wire transfer today\r\n\r\npay this\r\n",
    );
    await w.run({
      method: "POST",
      path: "/gmail/v1/users/me/messages/import",
      query: { neverMarkSpam: true },
      body: { raw: forged },
    });
    await w.run({
      method: "POST",
      path: "/calendar/v3/calendars/primary/events/import",
      body: {
        iCalUID: "x@evil.example",
        summary: "Board meeting",
        organizer: { email: "ceo@corp.example" },
        start: { dateTime: "2026-12-01T09:00:00Z" },
        end: { dateTime: "2026-12-01T10:00:00Z" },
      },
    });
    expect(w.elicits).toHaveLength(2);
    expect(w.elicits[0]!.message).toContain("Confirm Gmail import (gmail.users.messages.import)");
    expect(w.elicits[0]!.message).toContain("Query: neverMarkSpam=true");
    expect(w.elicits[0]!.message).not.toContain("external send");
    expect(w.elicits[1]!.message).toContain("Confirm Gmail import (calendar.events.import)");
    expect(w.elicits[1]!.message).toContain('calendarId: "primary"');
    for (const c of w.elicits) expect(c.requestedSchema).toEqual(CONFIRM_ONLY);
  });

  it("REFUTED: a client without elicitation cannot approve — denied before any dialog, nothing sent", async () => {
    const w = world({ caps: {} });
    const r = await settle(w.run({ method: "DELETE", path: "/gmail/v1/users/me/messages/18c0ffee" }));
    expect(r).toEqual({
      ok: false,
      message: "Operation gmail.users.messages.delete requires user approval; outcome: unsupported",
    });
    expect(w.elicitInput).not.toHaveBeenCalled();
    expect(w.fetchSpy).not.toHaveBeenCalled();
  });
});
