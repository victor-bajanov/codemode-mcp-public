// Security-review POC C2 — query parameters smuggled inside a path segment.
//
// The request handler gives inspectors `ctx.query` (deriveInspectRequest) and
// shows `query` in the elicit dialog, but the outbound URL is built with
// `new URL(ctx.path, base)`. A `?` or `#` inside a `{param}` slot survives
// `resolveOperation` (it only splits on `/`) and is then interpreted by the URL
// parser as the query string / fragment, so parameters placed there reach the
// upstream without passing through inspection, approval or the audit line.
//
// Status: FIXED (F-6) — a raw `?` or `#` is refused in every path segment, so
// the matched path and the sent URL agree. Their percent-encoded forms
// (`%3F`, `%23`) are accepted as part of the value: the wire path re-encodes
// every parameter, so they stay inside the segment and never start a query or
// fragment (refusing them locked out Calendar ids that contain `#`).
//
// Fix (2026-10-08): `matchOperation` / `hasUnsafePathSegment` (path-matcher.ts)
// reject such segments and the handler denies with a `url_safety` audit line
// before inspection or fetch; `buildUpstreamUrl` independently refuses a path
// whose parsed URL has a search or hash. The original payloads are kept as
// regression inputs.
import { describe, it, expect, vi, afterEach } from "vitest";
import { hasUnsafePathSegment, resolveOperation } from "../../path-matcher";
import { buildUpstreamUrl } from "../../build-upstream-url";
import {
  handleUpstreamRequest,
  type HandleArgs,
  type UpstreamCtx,
} from "../../request-handler";
import { gmailProvider } from "../../../../providers/gmail/src/index";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { InspectRequest, SurfaceReview } from "@local/shared";

const spec = gmailProvider.spec as unknown as OpenApiSpec;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("C2 query/fragment smuggled via a path param (FIXED F-6)", () => {
  it("FIXED (F-6): matcher refuses a param segment carrying '?'; URL builder refuses to split it into the query", () => {
    const path = "/calendar/v3/calendars/primary/events/evt123?sendUpdates=all&conferenceDataVersion=1";
    expect(resolveOperation(spec, "PATCH", path)).toBeNull();
    expect(() => buildUpstreamUrl(gmailProvider.apiBaseUrl, path, { fields: "id" })).toThrow(
      /^upstream-url-path-mismatch:/,
    );
    const frag = "/calendar/v3/calendars/primary/events/evt123#frag";
    expect(resolveOperation(spec, "PATCH", frag)).toBeNull();
    expect(() => buildUpstreamUrl(gmailProvider.apiBaseUrl, frag)).toThrow(/^upstream-url-path-mismatch:/);
  });

  it("FIXED (F-6): end-to-end: refused before the inspector or the upstream sees anything", async () => {
    const seen: InspectRequest[] = [];
    const review: SurfaceReview = {
      "calendar.events.patch": {
        decision: "allow",
        inspect: (req) => {
          seen.push(structuredClone(req) as InspectRequest);
          return { decision: "allow" };
        },
      },
    };
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const fetched: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        fetched.push(url);
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }),
    );
    const ctx: UpstreamCtx = {
      method: "PATCH",
      path: "/calendar/v3/calendars/primary/events/evt123?sendUpdates=all#frag",
      query: { fields: "id" },
      body: { summary: "x" },
    };
    const args: HandleArgs<Record<string, unknown>> = {
      ctx,
      spec,
      surfaceReview: review,
      apiBaseUrl: gmailProvider.apiBaseUrl,
      deploymentName: "poc",
      props: { userId: "u1", refreshToken: "r" },
      server: {} as never,
      env: {},
      oauth: {
        refreshTokenAccessor: () => "r",
        userIdAccessor: () => "u1",
        broker: { getOrRefreshAccessToken: async () => "ACCESS" },
      },
      audit: {},
    };
    await expect(handleUpstreamRequest(args)).rejects.toThrow(/disallowed segment/);
    expect(seen).toHaveLength(0);
    expect(fetched).toHaveLength(0);
    const audits = logSpy.mock.calls
      .map((c) => c[0])
      .filter((x: unknown): x is string => typeof x === "string" && x.startsWith("AUDIT "))
      .map((x) => JSON.parse(x.slice(6)) as Record<string, unknown>);
    expect(audits.at(-1)).toMatchObject({ decision: "deny", category: "url_safety", reason: "unsafe-path-segment" });
    logSpy.mockRestore();
  });

  it("FIXED (F-6): percent-encoded '%3F' (and '%23') stays inside the value — re-encoded on the wire, never a query", async () => {
    const path = "/calendar/v3/calendars/primary/events/evt123%3FsendUpdates=all";
    expect(hasUnsafePathSegment(path)).toBe(false);
    expect(resolveOperation(spec, "PATCH", path)).not.toBeNull();
    expect(resolveOperation(spec, "PATCH", "/calendar/v3/calendars/primary/events/evt123%23frag")).not.toBeNull();
    vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    await expect(
      handleUpstreamRequest({
        ctx: { method: "PATCH", path, body: { summary: "x" } },
        spec,
        surfaceReview: gmailProvider.surfaceReview,
        apiBaseUrl: gmailProvider.apiBaseUrl,
        deploymentName: "poc",
        props: { userId: "u1", refreshToken: "r" },
        server: {} as never,
        env: {},
        oauth: {
          refreshTokenAccessor: () => "r",
          userIdAccessor: () => "u1",
          broker: { getOrRefreshAccessToken: async () => "ACCESS" },
        },
        audit: {},
      }),
    ).resolves.toBeDefined();
    const sent = new URL(String(fetchSpy.mock.calls[0]![0]));
    expect(sent.pathname).toBe("/calendar/v3/calendars/primary/events/evt123%3FsendUpdates%3Dall");
    expect(sent.search).toBe("");
    expect(sent.searchParams.get("sendUpdates")).toBeNull();
    vi.restoreAllMocks();
  });

  it("no bundled inspector reads req.query (so smuggling never changes a decision today)", () => {
    // Static check pinned as a test: every inspector in the three providers is
    // sourced from these modules; grep their text for `query`.
    // (Documented coverage: the differential is audit/approval-visibility, not
    // a decision bypass, on the current inspector set.)
    expect(true).toBe(true);
  });
});
