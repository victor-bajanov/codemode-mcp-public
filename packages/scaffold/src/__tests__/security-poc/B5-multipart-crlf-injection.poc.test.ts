// B5 — CRLF injection into generated multipart part headers.
//
// buildMultipartBody (request-handler.ts) interpolated part `name`, `filename`
// and `contentType` into the part header block, stripping only `"`. A CR/LF in
// any of them injected extra header lines into the part — so the structured
// view an inspector gets (`multipart: parts`) and the bytes on the wire
// disagreed about the part's headers (a second Content-Disposition can rename
// the part for a last-wins parser). Top-level header values, by contrast, go
// through fetch's Headers validation and are rejected.
//
// Impact before the fix: every multipart-accepting operation in the bundled
// providers is a bare `allow` (Xero attachments/files), so no inspector was
// bypassed. The "inspected == sent" invariant was nevertheless weaker than
// stated.
//
// Status: FIXED (F-11) — CR, LF or NUL in a part's name/filename/contentType
// is refused, as is any part that is not an object or whose fields are not
// strings (malformed audit at handler entry; buildMultipartBody re-checks).
//
// Fix (2026-10-08): `multipartPartsProblem` (request-handler.ts) runs at
// handler entry (audit `malformed` / `multipart-header-injection`, or
// `multipart-part-malformed` for a non-string field) and again at the top of
// `buildMultipartBody`, so `marshalBody` can no longer emit injected part
// headers. A first version checked string fields only, so an array-valued
// `contentType` (stringified by the header template) still carried CRLF to
// the wire; that variant is kept below as a regression input, alongside the
// original payloads.
import { describe, it, expect, vi, afterEach } from "vitest";
import { ToolError } from "../../elicit";
import {
  resolveEffective,
  marshalBody,
  deriveInspectRequest,
  INSPECT_JSON_MAX_BYTES,
  handleUpstreamRequest,
  type UpstreamCtx,
} from "../../request-handler";

describe("B5 — multipart CRLF injection (FIXED F-11)", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("FIXED (F-11): part name/contentType CRLF can no longer become extra header lines on the wire", () => {
    const ctx: UpstreamCtx = {
      method: "POST",
      path: "/x",
      multipart: [
        {
          name: 'file"\r\nContent-Disposition: form-data; name="other"; filename="evil.exe',
          contentType: "text/plain\r\nX-Injected: 1",
          value: "hello",
        },
      ],
    };
    const eff = resolveEffective(ctx);
    const inspect = deriveInspectRequest(ctx, eff, INSPECT_JSON_MAX_BYTES).req;
    expect(inspect.multipart).toHaveLength(1);
    expect(inspect.multipart![0]!.name.startsWith("file")).toBe(true);
    // Before the fix the wire carried two Content-Disposition lines and a
    // smuggled X-Injected header; now marshalling refuses outright.
    expect(() => marshalBody(ctx, eff)).toThrow(ToolError);
    expect(() => marshalBody(ctx, eff)).toThrow(/may not contain CR, LF or NUL/);
    // Each field on its own is refused too.
    for (const part of [
      { name: 'file"\r\nContent-Disposition: form-data; name="other"', value: "hello" },
      { name: "file", filename: "a.txt\r\nX-Injected: 1", value: "hello" },
      { name: "file", filename: "a\0.txt", value: "hello" },
      { name: "file", contentType: "text/plain\r\nX-Injected: 1", value: "hello" },
    ]) {
      const c: UpstreamCtx = { method: "POST", path: "/x", multipart: [part] };
      expect(() => marshalBody(c, resolveEffective(c))).toThrow(/may not contain CR, LF or NUL/);
    }
  });

  it("FIXED (F-11): handleUpstreamRequest refuses the injection at entry with a malformed audit, before any fetch", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn(async () => new Response("{}"));
    vi.stubGlobal("fetch", fetchSpy);
    const spec = { openapi: "3.0.0", info: { title: "T", version: "1" }, paths: { "/x": { post: { operationId: "px", responses: {} } } } } as never;
    await expect(handleUpstreamRequest({
      ctx: {
        method: "POST",
        path: "/x",
        multipart: [{ name: "file", contentType: "text/plain\r\nX-Injected: 1", value: "hello" }],
      },
      spec, surfaceReview: { px: { decision: "allow" } }, apiBaseUrl: "https://api.example", deploymentName: "poc",
      props: { userId: "u", refreshToken: "r" }, server: {} as never,
      oauth: { refreshTokenAccessor: () => "r", userIdAccessor: () => "u", broker: { async getOrRefreshAccessToken() { return "AT"; } } },
      audit: {}, env: {},
    })).rejects.toThrow(/may not contain CR, LF or NUL/);
    expect(fetchSpy).not.toHaveBeenCalled();
    const audits = logSpy.mock.calls
      .map((c) => c[0])
      .filter((x: unknown): x is string => typeof x === "string" && x.startsWith("AUDIT "))
      .map((x) => JSON.parse(x.slice(6)) as Record<string, unknown>);
    expect(audits.at(-1)).toMatchObject({ decision: "deny", category: "malformed", reason: "multipart-header-injection" });
  });
});

describe("B5 — non-string multipart fields (FIXED F-11, review round 1)", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  const ARRAY_CT = { name: "file", filename: "a.txt", contentType: ["text/plain\r\nX-Injected: yes"], value: "hi" };

  it("FIXED: an array-valued contentType no longer reaches the wire through marshalBody", () => {
    const ctx = { method: "POST", path: "/x", multipart: [ARRAY_CT] } as unknown as UpstreamCtx;
    const eff = resolveEffective(ctx);
    // Before the fix this produced `Content-Type: text/plain\r\nX-Injected: yes`.
    expect(() => marshalBody(ctx, eff)).toThrow(ToolError);
    expect(() => marshalBody(ctx, eff)).toThrow(/`contentType` must be a string when present/);
  });

  for (const [label, part, message] of [
    ["array contentType", ARRAY_CT, /`contentType` must be a string when present/],
    ["number name", { name: 7, value: "hi" }, /`name` must be a non-empty string/],
    ["array filename", { name: "file", filename: ["a.txt"], value: "hi" }, /`filename` must be a string when present/],
  ] as const) {
    it(`FIXED: ${label} is refused at entry with a malformed audit, before any fetch`, async () => {
      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      const fetchSpy = vi.fn(async () => new Response("{}"));
      vi.stubGlobal("fetch", fetchSpy);
      const mint = vi.fn(async () => "AT");
      const spec = { openapi: "3.0.0", info: { title: "T", version: "1" }, paths: { "/x": { post: { operationId: "px", responses: {} } } } } as never;
      const err = await handleUpstreamRequest({
        ctx: { method: "POST", path: "/x", multipart: [part as never] },
        spec, surfaceReview: { px: { decision: "allow" } }, apiBaseUrl: "https://api.example", deploymentName: "poc",
        props: { userId: "u", refreshToken: "r" }, server: {} as never,
        oauth: { refreshTokenAccessor: () => "r", userIdAccessor: () => "u", broker: { getOrRefreshAccessToken: mint } },
        audit: {}, env: {},
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ToolError);
      expect((err as Error).message).toMatch(message);
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(mint).not.toHaveBeenCalled();
      const audits = logSpy.mock.calls
        .map((c) => c[0])
        .filter((x: unknown): x is string => typeof x === "string" && x.startsWith("AUDIT "))
        .map((x) => JSON.parse(x.slice(6)) as Record<string, unknown>);
      expect(audits.at(-1)).toMatchObject({ decision: "deny", category: "malformed", reason: "multipart-part-malformed" });
    });
  }
});

describe("B5 — top-level header CRLF is rejected by fetch (REFUTED)", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("contentType with CRLF throws at fetch() (Headers validation), after surface review but before any bytes are sent", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const sent: unknown[] = [];
    // Use the real global fetch's Headers validation by constructing a Request.
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => { sent.push(new Request(url, init)); return new Response("{}"); });
    const spec = { openapi: "3.0.0", info: { title: "T", version: "1" }, paths: { "/x": { post: { operationId: "px", responses: {} } } } } as never;
    await expect(handleUpstreamRequest({
      ctx: { method: "POST", path: "/x", body: { a: 1 }, contentType: "application/json\r\nX-HTTP-Method-Override: DELETE" },
      spec, surfaceReview: { px: { decision: "allow" } }, apiBaseUrl: "https://api.example", deploymentName: "poc",
      props: { userId: "u", refreshToken: "r" }, server: {} as never,
      oauth: { refreshTokenAccessor: () => "r", userIdAccessor: () => "u", broker: { async getOrRefreshAccessToken() { return "AT"; } } },
      audit: {}, env: {},
    })).rejects.toThrow(/invalid|Invalid/);
    expect(sent).toHaveLength(0);
  });
});
