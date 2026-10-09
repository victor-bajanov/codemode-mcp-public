// B4 — Query-string smuggling through a trailing path parameter.
//
// `InspectRequest.query` is documented (packages/shared/src/surface-review.ts)
// as "always the outbound query". deriveInspectRequest only copies `ctx.query`;
// but `new URL(path, base)` splits a `?` found inside the LAST path segment into
// the URL's search string. resolveOperation accepts `?` inside a `{param}`
// segment, so a request can carry query parameters the inspector (and the
// elicit dialog, which renders ctx.query) never see.
//
// Impact today: no bundled inspector keys on query (verified by grep), so this
// is a contract gap rather than a demonstrated policy bypass. It becomes a
// bypass the moment an inspector relies on a query parameter (e.g. Calendar
// `sendUpdates`, Gmail `deleteOnly`).
//
// Status: FIXED (F-6) — a `?` or `#` (literal or percent-encoded) in any
// path segment is refused before review, inspection or fetch.
//
// Fix (2026-10-08): `hasUnsafePathSegment` (path-matcher.ts) rejects the path
// with a `url_safety` / `unsafe-path-segment` audit line, the wire path is
// rebuilt from the matched template, and `buildUpstreamUrl` refuses any path
// whose parsed URL carries a search or hash. Query parameters travel only via
// `ctx.query`, which the inspector and the elicit dialog see. The original
// payloads are kept as regression inputs.
import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest } from "../../request-handler";
import { gmailProvider } from "../../../../providers/gmail/src/index";

function fakeBroker() {
  return { async getOrRefreshAccessToken() { return "AT"; } };
}

describe("B4 — query smuggling via `?` in a trailing path param (FIXED F-6)", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("FIXED (F-6): a `?` in a trailing path param is refused — the inspector never runs, nothing is sent", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetchSpy);
    const entry = gmailProvider.surfaceReview["calendar.events.patch"]!;
    const seen: unknown[] = [];
    const spiedReview = {
      ...gmailProvider.surfaceReview,
      "calendar.events.patch": {
        ...entry,
        inspect: (req: Parameters<NonNullable<typeof entry.inspect>>[0], env?: Parameters<NonNullable<typeof entry.inspect>>[1]) => {
          seen.push(req.query);
          return entry.inspect!(req, env);
        },
      },
    };
    await expect(handleUpstreamRequest({
      ctx: {
        method: "PATCH",
        path: "/calendar/v3/calendars/primary/events/evt1?sendUpdates=all&conferenceDataVersion=1",
        body: { summary: "renamed" },
      },
      spec: gmailProvider.spec,
      surfaceReview: spiedReview,
      apiBaseUrl: gmailProvider.apiBaseUrl,
      deploymentName: "poc",
      props: { userId: "u1", refreshToken: "RT" },
      server: {} as never,
      oauth: {
        refreshTokenAccessor: (p) => p.refreshToken as string,
        userIdAccessor: (p) => p.userId as string | undefined,
        broker: fakeBroker(),
      },
      audit: {},
      env: {},
    })).rejects.toThrow(/disallowed segment/);
    expect(seen).toEqual([]);                                // inspector never reached
    expect(fetchSpy).not.toHaveBeenCalled();
    const audits = logSpy.mock.calls
      .map((c) => c[0])
      .filter((x: unknown): x is string => typeof x === "string" && x.startsWith("AUDIT "))
      .map((x) => JSON.parse(x.slice(6)) as Record<string, unknown>);
    expect(audits.at(-1)).toMatchObject({ decision: "deny", category: "url_safety", reason: "unsafe-path-segment" });
  });

  it("contrast: the same parameters passed via ctx.query ARE visible to the inspector", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 200 })));
    const entry = gmailProvider.surfaceReview["calendar.events.patch"]!;
    const seen: unknown[] = [];
    await handleUpstreamRequest({
      ctx: { method: "PATCH", path: "/calendar/v3/calendars/primary/events/evt1", query: { sendUpdates: "all" }, body: {} },
      spec: gmailProvider.spec,
      surfaceReview: { ...gmailProvider.surfaceReview, "calendar.events.patch": { ...entry, inspect: (req, env) => { seen.push(req.query); return entry.inspect!(req, env); } } },
      apiBaseUrl: gmailProvider.apiBaseUrl,
      deploymentName: "poc",
      props: { userId: "u1", refreshToken: "RT" },
      server: {} as never,
      oauth: { refreshTokenAccessor: (p) => p.refreshToken as string, userIdAccessor: (p) => p.userId as string | undefined, broker: fakeBroker() },
      audit: {},
      env: {},
    });
    expect(seen).toEqual([{ sendUpdates: "all" }]);
  });

  it("FIXED (F-6): a `?` in a NON-trailing param no longer truncates the wire path — refused before any fetch", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    // Used to resolve to gmail.users.messages.get (allow) and go out as
    // GET /gmail/v1/users/me (getProfile) with the rest as query.
    await expect(handleUpstreamRequest({
      ctx: { method: "GET", path: "/gmail/v1/users/me?x=1/messages/abc" },
      spec: gmailProvider.spec, surfaceReview: gmailProvider.surfaceReview, apiBaseUrl: gmailProvider.apiBaseUrl,
      deploymentName: "poc", props: { userId: "u1", refreshToken: "RT" }, server: {} as never,
      oauth: { refreshTokenAccessor: (p) => p.refreshToken as string, userIdAccessor: (p) => p.userId as string | undefined, broker: fakeBroker() },
      audit: {}, env: {},
    })).rejects.toThrow(/disallowed segment/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
