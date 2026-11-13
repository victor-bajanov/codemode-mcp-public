// packages/scaffold/src/__tests__/header-policy.test.ts
//
// D-6 (2026-11 review) and the wave-1 W4 header twin: sandbox-supplied
// `codemode.request` headers.
//
// Attacker: LLM-authored sandbox code calling `codemode.request` with a
// `headers` object it fully controls (names and values).
// Precondition: any operation the deployment exposes; a gated (inspected /
// approval) one for the gated-op refusal.
// Payloads: `Authorization` / `X-HTTP-Method-Override` / `If-Match` on a gated
// op; `"X-HTTP-Method-Override "` (trailing space) and other names outside the
// RFC 7230 token grammar; values with CR/LF/NUL or over 4096 chars; 33 headers;
// Google credential / project-attribution headers (`X-Goog-Api-Key`,
// `X-Goog-User-Project`, `x-api-key`, …) on a plain-allow read.
// Control: `headerProblem` (pure) at entry, before any match, mint or fetch;
// every refusal writes one deny line with category `malformed` and a fixed
// reason, never a header name or value; the gated-op refusal is audited too.
// Why the pre-fix code failed it: `assertAllowedCtxHeaders` threw without an
// audit line, the gated-op refusal threw without one, an invalid name reached
// `fetch` after the token mint and surfaced as a raw TypeError, and the
// credential headers of the refused `key` query parameter were let through.

import { afterEach, describe, expect, it, vi } from "vitest";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReview } from "@local/shared";
import { handleUpstreamRequest, headerProblem, type UpstreamCtx } from "../request-handler";
import { ToolError } from "../elicit";

const SPEC: OpenApiSpec = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/profile": { get: { operationId: "getProfile", responses: { "200": { description: "OK" } } } },
    "/messages/{id}": {
      delete: {
        operationId: "deleteMessage",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        responses: { "200": { description: "OK" } },
      },
    },
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;

const SR: SurfaceReview = {
  getProfile: { decision: "allow", category: "standard_read" },
  deleteMessage: { decision: "elicit", category: "destructive" },
} as unknown as SurfaceReview;

function harness(ctx: UpstreamCtx) {
  const lines: Array<Record<string, unknown>> = [];
  const raw: string[] = [];
  vi.spyOn(console, "log").mockImplementation((s: unknown) => {
    if (typeof s === "string" && s.startsWith("AUDIT ")) {
      raw.push(s);
      lines.push(JSON.parse(s.slice(6)) as Record<string, unknown>);
    }
  });
  const fetchSpy = vi.fn<typeof fetch>(async () =>
    new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } }),
  );
  vi.stubGlobal("fetch", fetchSpy);
  const mint = vi.fn(async () => "AT-x");
  const args = {
    ctx,
    spec: SPEC,
    surfaceReview: SR,
    apiBaseUrl: "https://api.example.com",
    deploymentName: "test",
    server: {} as never,
    props: { userId: "u1", refreshToken: "RT" },
    oauth: {
      refreshTokenAccessor: (p: Record<string, unknown>) => p.refreshToken as string,
      userIdAccessor: (p: Record<string, unknown>) => p.userId as string | undefined,
      broker: { getOrRefreshAccessToken: mint },
    },
    audit: {},
    env: {},
  };
  return { args, lines, raw, fetchSpy, mint };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("headerProblem (pure)", () => {
  it("accepts ordinary headers", () => {
    expect(headerProblem(undefined)).toBeUndefined();
    expect(headerProblem({})).toBeUndefined();
    expect(headerProblem({ Accept: "application/json", "Idempotency-Key": "k1", Prefer: "x" })).toBeUndefined();
  });

  it.each([
    ["X-HTTP-Method-Override "],
    ["X Bad"],
    [""],
    ["Accept\r\n"],
    ["Accept:"],
    ["Ünicode"],
  ])("FIXED (D-6): name %j → invalid-header-name", (name) => {
    expect(headerProblem({ [name]: "x" })?.reason).toBe("invalid-header-name");
  });

  it.each([
    ["a\nb"],
    ["a\rb"],
    ["a\0b"],
    ["€"],
    ["x".repeat(4097)],
  ])("FIXED (D-6): value %# → invalid-header-value", (value) => {
    expect(headerProblem({ Accept: value })?.reason).toBe("invalid-header-value");
  });

  it("FIXED (D-6): a header name over 256 chars → invalid-header-name; 256 pass", () => {
    expect(headerProblem({ ["X" + "a".repeat(255)]: "v" })).toBeUndefined();
    expect(headerProblem({ ["X" + "a".repeat(256)]: "v" })?.reason).toBe("invalid-header-name");
  });

  it("a 4096-char value is accepted; a non-string value is refused", () => {
    expect(headerProblem({ Accept: "x".repeat(4096) })).toBeUndefined();
    expect(headerProblem({ Accept: 42 as unknown as string })?.reason).toBe("invalid-header-value");
  });

  it("FIXED (D-6): 33 headers → too-many-headers; 32 pass", () => {
    const h = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`X-H${i}`, "v"]));
    expect(headerProblem(h(32))).toBeUndefined();
    expect(headerProblem(h(33))?.reason).toBe("too-many-headers");
  });

  it.each([
    "x-goog-api-key",
    "X-Goog-User-Project",
    "x-goog-authuser",
    "x-goog-iam-authorization-token",
    "x-goog-iam-authority-selector",
    "X-Api-Key",
    "api-key",
    "x-auth-token",
    "Authorization",
    "X-HTTP-Method-Override",
  ])("FIXED (W4 header twin): %s → forbidden-header", (name) => {
    expect(headerProblem({ [name]: "v" })?.reason).toBe("forbidden-header");
  });

  it("content-type and duplicates keep their own reasons and messages", () => {
    expect(headerProblem({ "Content-Type": "text/plain" })).toMatchObject({
      reason: "content-type-header",
      message: expect.stringMatching(/use the `contentType` option/),
    });
    expect(headerProblem({ Accept: "a", ACCEPT: "b" })).toMatchObject({
      reason: "duplicate-header",
      message: expect.stringMatching(/appears more than once/),
    });
    expect(headerProblem({ Cookie: "c" })?.message).toBe('Header "Cookie" cannot be set from sandbox code');
  });

  it("a non-object headers value is refused", () => {
    expect(headerProblem("Accept: x" as unknown as Record<string, string>)?.reason).toBe("invalid-header-value");
    expect(headerProblem(["x"] as unknown as Record<string, string>)?.reason).toBe("invalid-header-value");
  });
});

describe("handler: every header refusal is audited by reason only", () => {
  const cases: Array<[string, Record<string, string>, string]> = [
    ["trailing-space name", { "X-HTTP-Method-Override ": "DELETE" }, "invalid-header-name"],
    ["space in name", { "X Bad": "1" }, "invalid-header-name"],
    ["CRLF in name", { "Accept\r\n": "1" }, "invalid-header-name"],
    ["LF in value", { Accept: "a\nInjected: 1" }, "invalid-header-value"],
    ["5000-char value", { Accept: "v".repeat(5000) }, "invalid-header-value"],
    ["33 headers", Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`X-H${i}`, "v"])), "too-many-headers"],
    ["X-Goog-Api-Key", { "X-Goog-Api-Key": "AIzaSyFAKEFAKEFAKE" }, "forbidden-header"],
    ["X-Goog-User-Project", { "X-Goog-User-Project": "p" }, "forbidden-header"],
    ["x-api-key", { "x-api-key": "k" }, "forbidden-header"],
    ["Authorization", { Authorization: "Bearer stolen" }, "forbidden-header"],
    ["Content-Type", { "Content-Type": "text/plain" }, "content-type-header"],
    ["two casings", { Accept: "a", ACCEPT: "b" }, "duplicate-header"],
  ];

  it.each(cases)("FIXED (D-6): %s → ToolError, one deny line, no mint, no fetch", async (_label, headers, reason) => {
    const h = harness({ method: "GET", path: "/profile", headers });
    const err = await handleUpstreamRequest(h.args).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolError);
    expect((err as Error).name).toBe("ToolError");
    expect(h.lines).toHaveLength(1);
    expect(h.lines[0]).toMatchObject({ decision: "deny", category: "malformed", reason, method: "GET", path: "/profile" });
    expect(h.mint).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
    for (const [name, value] of Object.entries(headers)) {
      if (name.length > 3) expect(h.raw[0]).not.toContain(name.trim());
      if (value.length > 3) expect(h.raw[0]).not.toContain(value.slice(0, 20));
    }
  });

  it("FIXED (D-6): Authorization / X-HTTP-Method-Override / If-Match on a gated DELETE → forbidden, forbidden, headers-on-gated-op", async () => {
    const reasons: unknown[] = [];
    for (const headers of [{ Authorization: "Bearer x" }, { "X-HTTP-Method-Override": "GET" }, { "If-Match": "etag-1" }]) {
      const h = harness({ method: "DELETE", path: "/messages/x", headers });
      const err = await handleUpstreamRequest(h.args).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ToolError);
      expect(h.lines).toHaveLength(1);
      expect(h.raw[0]).not.toMatch(/If-Match|etag-1|Bearer x|Method-Override"/i);
      expect(h.mint).not.toHaveBeenCalled();
      expect(h.fetchSpy).not.toHaveBeenCalled();
      reasons.push(h.lines[0]!.reason);
      vi.restoreAllMocks();
    }
    expect(reasons).toEqual(["forbidden-header", "forbidden-header", "headers-on-gated-op"]);
  });

  it("REFUTED: the gated-op refusal keeps its ToolError text and carries the operationId", async () => {
    const h = harness({ method: "DELETE", path: "/messages/x", headers: { "If-Match": "e" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/subject to inspection\/approval/);
    expect(h.lines[0]).toMatchObject({ operationId: "deleteMessage", category: "malformed", reason: "headers-on-gated-op" });
  });

  it("REFUTED: Accept (and Idempotency-Key) still pass on the plain-allow read", async () => {
    const h = harness({ method: "GET", path: "/profile", headers: { Accept: "application/json", "Idempotency-Key": "k" } });
    await expect(handleUpstreamRequest(h.args)).resolves.toMatchObject({ success: true });
    const init = h.fetchSpy.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>).Accept).toBe("application/json");
    expect(h.lines.at(-1)).toMatchObject({ decision: "allow", operationId: "getProfile" });
  });
});
