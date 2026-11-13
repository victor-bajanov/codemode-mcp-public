// packages/providers/gmail/src/__tests__/header-audit-gaps.test.ts
//
// D-6 (2026-11 review, wave 4) end to end against the REAL Gmail + Calendar
// provider: every refusal of sandbox-supplied `headers` is on record, header
// names are validated at entry, and the credential/project-attribution
// headers (the header twin of the refused `key` query parameter, wave-1 W4
// note) are forbidden.
//
// Attacker: (3) a prompt-injected / malicious LLM inside a valid session.
// Precondition: a session; a deployment whose allow-list admits the calendar
//   ids used below.
// Payloads: `Authorization: Bearer <stolen>` and `X-HTTP-Method-Override` on
//   allowed reads; `If-Match` on the gated permanent delete; a header name
//   with a trailing space, an inner space, an empty name, a name with CR LF,
//   a 257-char name; a value with LF, a 5 000-char value, a value above
//   U+00FF; 33 headers; `X-Goog-Api-Key`, `X-Goog-User-Project`,
//   `x-api-key`; and two Calendar moves that differ only in the query.
// Control: `headerProblem` at entry (before surface review, any approval
//   dialog and the token mint) refuses with a ToolError and one deny line
//   whose `reason` says what happened (`forbidden-header`,
//   `invalid-header-name`, `invalid-header-value`, `too-many-headers`,
//   `headers-on-gated-op`); names and values are never logged; nothing
//   reaches the wire. `queryKeys` (wave 1, D-2) distinguishes requests that
//   differ only in the query.
// Why the pre-fix code failed it: `assertAllowedCtxHeaders` threw with no
//   audit line (probing for an auth or method override left no trace); an
//   invalid header NAME was only caught by `fetch`, after surface review,
//   after any approval and after the access token was minted, as a raw
//   TypeError with no line; the credential headers were allowed.
//
// Harness: the real request handler with the real provider; only fetch, the
// broker and the MCP client's elicitation answer are faked (as in
// approval-dialog.test.ts). Hosts and ids are invented.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type HandleArgs, type UpstreamCtx } from "@local/scaffold";
import { gmailProvider } from "../index";

type Line = Record<string, unknown>;

function world(opts: { env?: Record<string, string> } = {}) {
  const fetchSpy = vi.fn<typeof fetch>(async () =>
    new Response(JSON.stringify({ id: "upstream-ok" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
  vi.stubGlobal("fetch", fetchSpy);
  const raw: string[] = [];
  vi.spyOn(console, "log").mockImplementation((s: unknown) => {
    if (typeof s === "string" && s.startsWith("AUDIT ")) raw.push(s);
  });
  const audits = (): Line[] => raw.map((s) => JSON.parse(s.slice(6)) as Line);
  const elicits: unknown[] = [];
  const elicitInput = vi.fn(async (params: unknown) => {
    elicits.push(params);
    return { action: "accept", content: { confirm: true } };
  });
  const mint = vi.fn(async () => "AT-of-user");
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
        broker: { getOrRefreshAccessToken: mint },
      },
      audit: {},
      env: (opts.env ?? {
        OUTBOUND_RECIPIENT_ALLOWLIST: "*@corp.example",
        CALENDAR_WRITE_ALLOWLIST: "primary,team-cal@group.calendar.example",
      }) as { ALLOW_PII_IN_LOGS?: string },
      ...(gmailProvider.elicitRenderers ? { elicitRenderers: gmailProvider.elicitRenderers } : {}),
    } as HandleArgs<Record<string, unknown>>);
  const wire = () =>
    fetchSpy.mock.calls.map(([url, init]) => {
      const headers: Record<string, string> = {};
      new Headers(init?.headers).forEach((v, k) => {
        headers[k] = v;
      });
      return { method: String(init?.method ?? "GET"), url: String(url), headers };
    });
  return { run, elicits, mint, raw, audits, wire };
}

async function settle(p: Promise<unknown>): Promise<{ ok: true } | { ok: false; name: string; message: string }> {
  try {
    await p;
    return { ok: true };
  } catch (e) {
    return { ok: false, name: e instanceof Error ? e.name : typeof e, message: e instanceof Error ? e.message : String(e) };
  }
}

/** No line may carry any header name or value from the request. */
function expectNoHeaderText(raw: string[], ...fragments: string[]): void {
  for (const s of raw) for (const f of fragments) expect(s).not.toContain(f);
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("D-6: header refusals are audited, by reason only", () => {
  it("FIXED (D-6b): Authorization and X-HTTP-Method-Override on reads, If-Match on the gated delete → three deny lines, nothing on the wire, no dialog, no mint", async () => {
    const w = world();
    const a = await settle(w.run({ method: "GET", path: "/gmail/v1/users/me/profile", headers: { Authorization: "Bearer stolen-token-value" } }));
    const b = await settle(w.run({ method: "GET", path: "/gmail/v1/users/me/messages/msg-0001", headers: { "X-HTTP-Method-Override": "PATCH" } }));
    const c = await settle(w.run({ method: "DELETE", path: "/gmail/v1/users/me/messages/msg-0001", headers: { "If-Match": "etag-value-1" } }));
    // REFUTED: the model-facing texts are unchanged.
    expect(a).toMatchObject({ ok: false, name: "ToolError", message: 'Header "Authorization" cannot be set from sandbox code' });
    expect(b).toMatchObject({ ok: false, name: "ToolError", message: 'Header "X-HTTP-Method-Override" cannot be set from sandbox code' });
    expect(c).toMatchObject({ ok: false, name: "ToolError" });
    expect((c as { message: string }).message).toMatch(/subject to inspection\/approval/);

    expect(w.wire()).toHaveLength(0);
    expect(w.elicits).toHaveLength(0);
    expect(w.mint).not.toHaveBeenCalled();
    const lines = w.audits();
    expect(lines).toHaveLength(3);
    expect(lines[0]).toMatchObject({ deployment: "test", method: "GET", path: "/gmail/v1/users/me/profile", decision: "deny", category: "malformed", reason: "forbidden-header" });
    expect(lines[0]).not.toHaveProperty("operationId");
    expect(lines[1]).toMatchObject({ method: "GET", path: "/gmail/v1/users/me/messages/msg-0001", decision: "deny", category: "malformed", reason: "forbidden-header" });
    expect(lines[2]).toMatchObject({
      method: "DELETE",
      path: "/gmail/v1/users/me/messages/msg-0001",
      operationId: "gmail.users.messages.delete",
      decision: "deny",
      category: "malformed",
      reason: "headers-on-gated-op",
    });
    expectNoHeaderText(w.raw, "Authorization", "authorization", "stolen", "Method-Override", "PATCH", "If-Match", "if-match", "etag-value");
  });

  it("FIXED (D-6c): an invalid header name is a ToolError at entry with a deny line, before the mint — not a raw TypeError from fetch", async () => {
    const w = world();
    const r = await settle(w.run({ method: "GET", path: "/gmail/v1/users/me/profile", headers: { "X-HTTP-Method-Override ": "DELETE" } }));
    expect(r).toMatchObject({ ok: false, name: "ToolError" });
    expect((r as { message: string }).message).toMatch(/not a valid HTTP header name/);
    expect(w.mint).not.toHaveBeenCalled();
    expect(w.wire()).toHaveLength(0);
    expect(w.audits()).toEqual([
      expect.objectContaining({ method: "GET", path: "/gmail/v1/users/me/profile", decision: "deny", category: "malformed", reason: "invalid-header-name" }),
    ]);
    expectNoHeaderText(w.raw, "Method-Override", "DELETE");
  });

  it.each([
    ["an inner space", { "X Bad": "1" }, "invalid-header-name"],
    ["an empty name", { "": "1" }, "invalid-header-name"],
    ["CR LF in the name", { "Accept\r\n": "1" }, "invalid-header-name"],
    ["a 257-char name", { ["X-" + "n".repeat(255)]: "1" }, "invalid-header-name"],
    ["a value with LF", { "X-Note": "a\nb" }, "invalid-header-value"],
    ["a 5 000-char value", { "X-Note": "v".repeat(5_000) }, "invalid-header-value"],
    ["a value above U+00FF", { "X-Note": "cafē" }, "invalid-header-value"],
    ["a non-string value", { "X-Note": 42 as unknown as string }, "invalid-header-value"],
    ["33 headers", Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`X-H-${i}`, "1"])), "too-many-headers"],
  ])("FIXED (D-6c): %s → ToolError, one deny line, no mint, nothing on the wire", async (_label, headers, reason) => {
    const w = world();
    const r = await settle(w.run({ method: "GET", path: "/gmail/v1/users/me/profile", headers }));
    expect(r).toMatchObject({ ok: false, name: "ToolError" });
    expect(w.mint).not.toHaveBeenCalled();
    expect(w.wire()).toHaveLength(0);
    expect(w.audits()).toEqual([expect.objectContaining({ decision: "deny", category: "malformed", reason })]);
    expectNoHeaderText(w.raw, "X-Note", "X-H-", "X Bad", "nnnnnnnn", "vvvvvvvv", "caf");
  });

  it("FIXED (W4 header twin): X-Goog-Api-Key, X-Goog-User-Project and x-api-key are forbidden on a plain-allow read; REFUTED: Accept still passes", async () => {
    const w = world();
    for (const headers of [
      { "X-Goog-Api-Key": "AIzaInventedKeyValue000000000000000000" },
      { "X-Goog-User-Project": "billing-project-42" },
      { "x-api-key": "inventedkey" },
      { "X-Goog-AuthUser": "1" },
      { "X-Auth-Token": "t" },
    ]) {
      const r = await settle(w.run({ method: "GET", path: "/gmail/v1/users/me/profile", headers }));
      expect(r).toMatchObject({ ok: false, name: "ToolError" });
      expect((r as { message: string }).message).toMatch(/cannot be set from sandbox code/);
    }
    expect(w.wire()).toHaveLength(0);
    expect(w.mint).not.toHaveBeenCalled();
    const lines = w.audits();
    expect(lines).toHaveLength(5);
    for (const l of lines) expect(l).toMatchObject({ decision: "deny", category: "malformed", reason: "forbidden-header" });
    expectNoHeaderText(w.raw, "Goog", "AIza", "billing-project", "api-key", "inventedkey", "AuthUser", "Auth-Token");

    // REFUTED: an ordinary header still rides on the allow op, under the broker's bearer.
    const ok = (await w.run({ method: "GET", path: "/gmail/v1/users/me/profile", headers: { Accept: "application/json", "Idempotency-Key": "idem-1" } })) as { success: boolean };
    expect(ok.success).toBe(true);
    expect(w.wire()).toHaveLength(1);
    expect(w.wire()[0]!.headers).toMatchObject({ accept: "application/json", "idempotency-key": "idem-1", authorization: "Bearer AT-of-user" });
    expect(w.audits().at(-1)).toMatchObject({ operationId: "gmail.users.getProfile", decision: "allow", upstreamStatus: 200 });
    expectNoHeaderText(w.raw, "idem-1", "AT-of-user");
  });

  it("REFUTED (D-6a, wave 1): two Calendar moves that differ only in the query leave different lines: queryKeys, never the values", async () => {
    const w = world();
    await w.run({ method: "POST", path: "/calendar/v3/calendars/primary/events/evt-1/move", query: { destination: "primary" } });
    await w.run({
      method: "POST",
      path: "/calendar/v3/calendars/primary/events/evt-1/move",
      query: { destination: "team-cal@group.calendar.example", sendUpdates: "all" },
    });
    expect(w.wire()).toHaveLength(2);
    expect(w.wire()[0]!.url).not.toBe(w.wire()[1]!.url);
    const lines = w.audits();
    expect(lines).toHaveLength(2);
    for (const l of lines) expect(l).toMatchObject({ operationId: "calendar.events.move", decision: "allow", upstreamStatus: 200 });
    expect(lines[0]!.queryKeys).toEqual(["destination"]);
    expect(lines[1]!.queryKeys).toEqual(["destination", "sendUpdates"]);
    expectNoHeaderText(w.raw, "team-cal", "primary\"", "all\"");
  });
});
