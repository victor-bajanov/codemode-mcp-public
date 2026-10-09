// B6 — Smuggling typed arrays into ctx.body through codemode's binary codec.
//
// The sandbox→host RPC carries JSON, but the host-side ToolDispatcher.call
// parses it with `parseForCodemode`, which revives any object of the form
// `{ "__codemode_binary_v1__": "Uint8Array"|"ArrayBuffer"|…, data: <b64> }`
// into a real Uint8Array / ArrayBuffer. Sandbox code can therefore place typed
// arrays anywhere inside ctx.body / ctx.query, contradicting the handler's
// former assumption that bodies are plain JSON ("the RPC rejects typed-array
// views").
//
// What happened before the fix:
//   • deepFreeze returns views unfrozen (by design) — inspectors could mutate
//     them, but inspectors are trusted provider code.
//   • JSON.stringify serialises a Uint8Array as {"0":104,"1":105} and an
//     ArrayBuffer as {} — so the inspector's view (a Uint8Array) and the wire
//     bytes (an index-keyed object) were different representations of one
//     value. No bundled inspector treats a non-string as a pass, so no bypass.
//   • rawBody:true + typed-array body → ToolError (guard held).
//
// Status: FIXED (F-19) — an ArrayBuffer/view anywhere in ctx.body, ctx.query
// or ctx.multipart is refused at handler entry with a malformed audit line.
//
// Fix (2026-10-08): `containsBinaryValue` (request-handler.ts) walks body,
// query and multipart before anything else and throws a ToolError pointing at
// `bodyBase64` / `multipart[].bodyBase64`. The codec still revives tagged
// values (test 1, kept as context); the handler simply no longer accepts them.
import { describe, it, expect, vi, afterEach } from "vitest";
import { ToolDispatcher } from "@cloudflare/codemode";
import { handleUpstreamRequest } from "../../request-handler";

const TAG = "__codemode_binary_v1__";
const BINARY_REJECTED =
  "Binary values (Uint8Array/ArrayBuffer) are not accepted in body, query or multipart; send bytes with bodyBase64 or multipart[].bodyBase64";

function argsWith(ctx: unknown, inspect: (req: { body?: unknown }) => { decision: "allow" | "deny" }) {
  return {
    ctx: ctx as never,
    spec: { openapi: "3.0.0", info: { title: "T", version: "1" }, paths: { "/x": { post: { operationId: "px", responses: {} } } } } as never,
    surfaceReview: { px: { decision: "allow" as const, inspect } },
    apiBaseUrl: "https://api.example", deploymentName: "poc",
    props: { userId: "u", refreshToken: "r" }, server: {} as never,
    oauth: { refreshTokenAccessor: () => "r", userIdAccessor: () => "u", broker: { async getOrRefreshAccessToken() { return "AT"; } } },
    audit: {}, env: {},
  };
}

describe("B6 — binary tag smuggling (FIXED F-19)", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it("host-side ToolDispatcher revives a tagged object inside ctx.body into a Uint8Array", async () => {
    let received: unknown;
    const d = new ToolDispatcher({ request: async (ctx: unknown) => { received = ctx; return "ok"; } });
    const argsJson = JSON.stringify([{ method: "POST", path: "/x", body: { raw: { [TAG]: "Uint8Array", data: btoa("hi") } } }]);
    await d.call("request", argsJson);
    const body = (received as { body: { raw: unknown } }).body;
    expect(body.raw).toBeInstanceOf(Uint8Array);
    expect(Array.from(body.raw as Uint8Array)).toEqual([104, 105]);
  });

  it("FIXED (F-19): a revived Uint8Array in ctx.body is refused — the inspector never sees it, nothing is sent", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const seen: unknown[] = [];
    const body = { raw: new Uint8Array([104, 105]) }; // what parseForCodemode produced
    await expect(handleUpstreamRequest(argsWith({ method: "POST", path: "/x", body }, (req) => {
      seen.push((req.body as { raw: unknown }).raw);
      return { decision: "allow" };
    }))).rejects.toThrow(BINARY_REJECTED);
    expect(seen).toHaveLength(0);
    expect(fetchSpy).not.toHaveBeenCalled();
    const audits = logSpy.mock.calls
      .map((c) => c[0])
      .filter((x: unknown): x is string => typeof x === "string" && x.startsWith("AUDIT "))
      .map((x) => JSON.parse(x.slice(6)) as Record<string, unknown>);
    expect(audits.at(-1)).toMatchObject({ decision: "deny", category: "malformed", reason: "binary-value-in-request" });
  });

  it("FIXED (F-19): an ArrayBuffer in ctx.body (or ctx.query) is refused — no `{}` on the wire", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const seen: unknown[] = [];
    await expect(handleUpstreamRequest(argsWith({ method: "POST", path: "/x", body: { raw: new Uint8Array([1, 2, 3]).buffer } }, (req) => {
      seen.push((req.body as { raw: unknown }).raw);
      return { decision: "allow" };
    }))).rejects.toThrow(BINARY_REJECTED);
    await expect(
      handleUpstreamRequest(argsWith({ method: "POST", path: "/x", query: { q: new Uint8Array([1]).buffer } }, () => ({ decision: "allow" }))),
    ).rejects.toThrow(BINARY_REJECTED);
    expect(seen).toHaveLength(0);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("FIXED (F-19): rawBody:true with a smuggled typed array is refused at entry with the binary-value message", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    await expect(
      handleUpstreamRequest(argsWith({ method: "POST", path: "/x", rawBody: true, body: new Uint8Array([1]) }, () => ({ decision: "allow" }))),
    ).rejects.toThrow(BINARY_REJECTED);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
