// packages/scaffold/src/__tests__/query-names.test.ts
//
// D-2 (Medium) regression, handler level over a fake spec: query parameter
// names were never checked.
//
// Attacker: code running in the sandbox (prompt-injected model) with a valid
//   session.
// Precondition: none beyond a session; any operation the surface review
//   allows, inspects or gates behind approval.
// Payloads: system parameters that override the method or headers
//   (`$httpMethod=DELETE`, `$httpHeaders=...`), sandbox-supplied credentials
//   (`access_token`, `oauth_token`, `key`), method-override names, names the
//   operation never declared, and non-primitive values.
// Control: after the operation is matched and its surface-review entry found,
//   and before the URL is built (so before inspection, approval and token
//   mint), every query name must be declared by the operation (inline or via
//   `#/components/parameters/*`) or be one of the provider's
//   `standardQueryParams`; a hard deny-list wins over any declaration; values
//   must be primitive. Every audit line after the match carries the sorted
//   `queryKeys` (names, never values).
// Why the pre-fix code failed: `buildUpstreamUrl` copied every key onto the
//   wire, inspectors and the approval dialog never saw the names, and the
//   audit line recorded no query at all, so `$httpMethod=DELETE` on a plain
//   read was logged as a harmless read.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "../request-handler";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReview } from "@local/shared";

const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  components: {
    schemas: {},
    parameters: {
      Page: { name: "page", in: "query", schema: { type: "integer" } },
    },
  },
  paths: {
    "/things": {
      get: {
        operationId: "listThings",
        parameters: [
          { $ref: "#/components/parameters/Page" },
          { $ref: "#/components/parameters/Missing" },
          { name: "where", in: "query", schema: { type: "string" } },
        ],
        responses: { "200": { description: "OK" } },
      },
    },
    "/things/{id}": {
      get: {
        operationId: "getThing",
        parameters: [
          { name: "id", in: "path", required: true, schema: { type: "string" } },
          { name: "q", in: "query", schema: { type: "string" } },
          { name: "format", in: "query", schema: { type: "string" } },
          { name: "X-Header", in: "header", schema: { type: "string" } },
        ],
        responses: { "200": { description: "OK" } },
      },
      delete: {
        operationId: "deleteThing",
        parameters: [
          { name: "id", in: "path", required: true, schema: { type: "string" } },
          { name: "sendUpdates", in: "query", schema: { type: "string" } },
        ],
        responses: { "204": { description: "OK" } },
      },
    },
    "/things/{id}/send": {
      post: {
        operationId: "sendThing",
        parameters: [
          { name: "id", in: "path", required: true, schema: { type: "string" } },
          { name: "notify", in: "query", schema: { type: "string" } },
          // Declared, but on the hard deny-list: the declaration does not help.
          { name: "access_token", in: "query", schema: { type: "string" } },
        ],
        requestBody: { content: { "application/json": { schema: { type: "object" } } } },
        responses: { "200": { description: "OK" } },
      },
    },
    // Listed first so the WIRE path "/items/labels/1" resolves here, while the
    // raw path "/items/lab%65ls/1" matches getItem below.
    "/items/labels/{id}": {
      get: {
        operationId: "getLabelItem",
        parameters: [{ name: "q", in: "query", schema: { type: "string" } }],
        responses: { "200": { description: "OK" } },
      },
    },
    "/items/{kind}/{id}": {
      get: {
        operationId: "getItem",
        parameters: [{ name: "q", in: "query", schema: { type: "string" } }],
        responses: { "200": { description: "OK" } },
      },
    },
    // A literal the URL parser percent-encodes: the template-built wire path
    // is rewritten, so buildUpstreamUrl refuses it (url_safety).
    "/odd path/{id}": {
      get: {
        operationId: "oddThing",
        parameters: [{ name: "q", in: "query", schema: { type: "string" } }],
        responses: { "200": { description: "OK" } },
      },
    },
    "/denied/{id}": {
      get: {
        operationId: "deniedThing",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        responses: { "200": { description: "OK" } },
      },
    },
  },
} as unknown as OpenApiSpec;

const inspectSpy = vi.fn((req: { body?: unknown }) =>
  (req.body as { to?: string } | undefined)?.to === "blocked@x.example"
    ? { decision: "deny" as const, category: "inspector", reason: "blocked-recipient" }
    : { decision: "allow" as const },
);

const SR: SurfaceReview = {
  listThings: { decision: "allow", category: "standard_read" },
  getThing: { decision: "allow", category: "standard_read" },
  deleteThing: { decision: "elicit", category: "irreversible" },
  sendThing: { decision: "allow", category: "external_data_flow", inspect: inspectSpy as never },
  deniedThing: { decision: "deny", category: "irreversible" },
  getLabelItem: { decision: "allow", category: "standard_read" },
  getItem: { decision: "allow", category: "standard_read" },
  oddThing: { decision: "allow", category: "standard_read" },
};

const SECRET_VALUE = "SECRET-QUERY-VALUE-7731";

function harness(
  ctx: UpstreamCtx,
  opts: {
    standardQueryParams?: readonly string[];
    answer?: unknown;
    response?: () => Response;
    extra?: Record<string, unknown>;
  } = {},
) {
  const fetchSpy = vi.fn<typeof fetch>(
    async () =>
      opts.response?.() ??
      new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } }),
  );
  vi.stubGlobal("fetch", fetchSpy);
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  const elicitInput = vi.fn(async () => opts.answer ?? { action: "accept", content: { confirm: true } });
  const mint = vi.fn(async () => "AT");
  return {
    fetchSpy,
    elicitInput,
    mint,
    audit: () =>
      logSpy.mock.calls
        .map((c) => c[0])
        .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
        .map((s) => JSON.parse(s.slice(6)) as Record<string, unknown>),
    rawAudit: () =>
      logSpy.mock.calls
        .map((c) => c[0])
        .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
        .join("\n"),
    url: () => new URL(String(fetchSpy.mock.calls[0]![0])),
    args: {
      ctx,
      spec: SPEC,
      surfaceReview: SR,
      apiBaseUrl: "https://api.example.com",
      deploymentName: "test",
      props: { refreshToken: "RT-1", userId: "u" },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: { server: { getClientCapabilities: () => ({ elicitation: {} }), elicitInput } } as any,
      env: { ALLOW_PII_IN_LOGS: "true" } as { ALLOW_PII_IN_LOGS?: string },
      audit: {},
      oauth: {
        refreshTokenAccessor: () => "RT-1",
        userIdAccessor: () => "u",
        broker: { getOrRefreshAccessToken: mint },
      },
      ...(opts.standardQueryParams ? { standardQueryParams: opts.standardQueryParams } : {}),
      ...opts.extra,
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  inspectSpy.mockClear();
});

describe("D-2 query names: forbidden system parameters, credentials and overrides", () => {
  it("FIXED (D-2): $httpMethod=DELETE on a plain read is refused before the URL is built; the deny line carries queryKeys", async () => {
    const h = harness({ method: "GET", path: "/things/18c0ffee", query: { $httpMethod: "DELETE" } as never });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow('Query parameter "$httpMethod" cannot be set from sandbox code');
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.mint).not.toHaveBeenCalled();
    expect(h.audit().at(-1)).toMatchObject({
      operationId: "getThing",
      decision: "deny",
      category: "url_safety",
      reason: "forbidden-query-param",
      queryKeys: ["$httpMethod"],
    });
    expect(h.rawAudit()).not.toContain("DELETE");
  });

  const FORBIDDEN = [
    "$httpHeaders",
    "$.xgafv",
    "access_token",
    "ACCESS_TOKEN",
    "oauth_token",
    "key",
    "Key",
    "api_key",
    "apikey",
    "token",
    "bearer",
    "authorization",
    "_method",
    "method",
    "httpMethod",
    "X-HTTP-Method-Override",
  ];
  for (const name of FORBIDDEN) {
    it(`FIXED (D-2): "${name}" is refused (forbidden-query-param), nothing sent`, async () => {
      const h = harness({ method: "GET", path: "/things/1", query: { [name]: SECRET_VALUE } as never });
      await expect(handleUpstreamRequest(h.args)).rejects.toThrow(`Query parameter "${name}" cannot be set from sandbox code`);
      expect(h.fetchSpy).not.toHaveBeenCalled();
      expect(h.audit().at(-1)).toMatchObject({ decision: "deny", reason: "forbidden-query-param", queryKeys: [name] });
      expect(h.rawAudit()).not.toContain(SECRET_VALUE);
    });
  }

  it("FIXED (D-2): a forbidden name wins even when the operation declares it", async () => {
    const h = harness({ method: "POST", path: "/things/1/send", body: { to: "a@x.example" }, query: { access_token: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/cannot be set from sandbox code/);
    expect(inspectSpy).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
  });

  it("FIXED (D-2): on an INSPECTED operation $httpHeaders/$httpMethod are refused before the inspector runs", async () => {
    const h = harness({
      method: "POST",
      path: "/things/1/send",
      body: { to: "a@x.example" },
      query: { $httpHeaders: "Content-Type:message/rfc822\r\n", $httpMethod: "PUT" } as never,
    });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/cannot be set from sandbox code/);
    expect(inspectSpy).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit().at(-1)).toMatchObject({
      operationId: "sendThing",
      reason: "forbidden-query-param",
      queryKeys: ["$httpHeaders", "$httpMethod"],
    });
  });

  it("FIXED (D-2): on an APPROVAL operation a refused query never reaches the dialog", async () => {
    const h = harness({ method: "DELETE", path: "/things/1", query: { sendUpdates: "all", $httpMethod: "GET" } as never });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/cannot be set from sandbox code/);
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
  });
});

describe("D-2 query names: only declared or provider-standard names", () => {
  it("FIXED (D-2): an undeclared name is refused and the message lists what the operation accepts (names only)", async () => {
    const h = harness(
      { method: "GET", path: "/things/1", query: { notAParameterOfThisOperation: SECRET_VALUE } },
      { standardQueryParams: ["fields"] },
    );
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
      'Operation getThing does not accept query parameter "notAParameterOfThisOperation"; it accepts: fields, format, q',
    );
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit().at(-1)).toMatchObject({
      operationId: "getThing",
      decision: "deny",
      category: "url_safety",
      reason: "undeclared-query-param",
      queryKeys: ["notAParameterOfThisOperation"],
    });
    expect(h.rawAudit()).not.toContain(SECRET_VALUE);
  });

  it("FIXED (D-2): a header parameter's name is not a query name", async () => {
    const h = harness({ method: "GET", path: "/things/1", query: { "X-Header": "v" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/does not accept query parameter "X-Header"/);
  });

  it("FIXED (D-2): names are compared exactly (case-sensitive)", async () => {
    const h = harness({ method: "GET", path: "/things/1", query: { Q: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/does not accept query parameter "Q"/);
  });

  it("FIXED (D-2): a provider-standard name is refused when the provider does not list it", async () => {
    const h = harness({ method: "GET", path: "/things/1", query: { fields: "id" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/does not accept query parameter "fields"; it accepts: format, q/);
  });

  it("FIXED (D-2): an unresolvable $ref declares nothing", async () => {
    const h = harness({ method: "GET", path: "/things", query: { Missing: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/does not accept query parameter "Missing"/);
  });

  it("FIXED (D-2): non-primitive values (object, array, null) are refused as malformed", async () => {
    for (const value of [{ a: 1 }, ["a", "b"], null]) {
      const h = harness({ method: "GET", path: "/things/1", query: { q: value } as never });
      await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
        'Operation getThing: query parameter "q" must be a string, number or boolean',
      );
      expect(h.fetchSpy).not.toHaveBeenCalled();
      expect(h.audit().at(-1)).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "query-value-not-primitive",
        queryKeys: ["q"],
      });
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it("control: declared names, a $ref-declared name and a provider-standard name are forwarded", async () => {
    const h = harness(
      { method: "GET", path: "/things/1", query: { q: "x", format: "full", fields: "id" } },
      { standardQueryParams: ["fields"] },
    );
    await handleUpstreamRequest(h.args);
    expect(h.url().search).toBe("?q=x&format=full&fields=id");

    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    const h2 = harness({ method: "GET", path: "/things", query: { where: "Status==\"OPEN\"", page: 2 } });
    await handleUpstreamRequest(h2.args);
    expect(h2.url().searchParams.get("page")).toBe("2");
    expect(h2.url().searchParams.get("where")).toBe('Status=="OPEN"');
  });

  it("control: keys whose value is undefined are ignored (not checked, not sent, not audited)", async () => {
    const h = harness({ method: "GET", path: "/things/1", query: { q: "x", bogus: undefined, $httpMethod: undefined } as never });
    await handleUpstreamRequest(h.args);
    expect(h.url().search).toBe("?q=x");
    expect(h.audit().at(-1)).toMatchObject({ decision: "allow", queryKeys: ["q"] });
  });
});

describe("D-2 audit: queryKeys on every line after the match, names only", () => {
  it("allow line: sorted keys, values never logged", async () => {
    const h = harness({ method: "GET", path: "/things/1", query: { q: SECRET_VALUE, format: "full" } });
    await handleUpstreamRequest(h.args);
    expect(h.audit().at(-1)).toMatchObject({ decision: "allow", upstreamStatus: 200, queryKeys: ["format", "q"] });
    expect(h.rawAudit()).not.toContain(SECRET_VALUE);
  });

  it("no query: no queryKeys field", async () => {
    const h = harness({ method: "GET", path: "/things/1" });
    await handleUpstreamRequest(h.args);
    expect(h.audit().at(-1)).not.toHaveProperty("queryKeys");
  });

  it("elicit lines (accepted and declined) carry queryKeys", async () => {
    const h = harness({ method: "DELETE", path: "/things/1", query: { sendUpdates: SECRET_VALUE } });
    await handleUpstreamRequest(h.args);
    const lines = h.audit();
    expect(lines.find((l) => l.decision === "elicit")).toMatchObject({
      elicitationOutcome: "accepted",
      queryKeys: ["sendUpdates"],
    });
    expect(lines.at(-1)).toMatchObject({ decision: "allow", queryKeys: ["sendUpdates"] });

    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    const h2 = harness(
      { method: "DELETE", path: "/things/1", query: { sendUpdates: "all" } },
      { answer: { action: "decline" } },
    );
    await expect(handleUpstreamRequest(h2.args)).rejects.toThrow(/outcome: declined/);
    expect(h2.audit().at(-1)).toMatchObject({ decision: "elicit", elicitationOutcome: "declined", queryKeys: ["sendUpdates"] });
  });

  it("inspector deny line carries queryKeys", async () => {
    const h = harness({ method: "POST", path: "/things/1/send", body: { to: "blocked@x.example" }, query: { notify: "all" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/denied/);
    expect(h.audit().at(-1)).toMatchObject({ decision: "deny", reason: "blocked-recipient", queryKeys: ["notify"] });
  });

  it("gated malformed line carries queryKeys", async () => {
    const h = harness({
      method: "POST",
      path: "/things/1/send",
      body: { to: "a@x.example" },
      bodyBase64: "AA==",
      query: { notify: "all" },
    });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/denied/);
    expect(h.audit().at(-1)).toMatchObject({ category: "malformed", reason: "multiple-body-channels", queryKeys: ["notify"] });
  });

  it("surface-review deny line carries queryKeys", async () => {
    const h = harness({ method: "GET", path: "/denied/1", query: { anything: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/denied by surface review/);
    expect(h.audit().at(-1)).toMatchObject({ operationId: "deniedThing", decision: "deny", queryKeys: ["anything"] });
  });

  it("url_safety line from the URL build carries queryKeys", async () => {
    const h = harness({ method: "GET", path: "/odd path/1", query: { q: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/upstream-url-path-mismatch/);
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit().at(-1)).toMatchObject({ category: "url_safety", operationId: "oddThing", queryKeys: ["q"] });
  });

  it("operation-mismatch-after-url-build line carries queryKeys", async () => {
    const h = harness({ method: "GET", path: "/items/lab%65ls/1", query: { q: "x" } });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/different operation/);
    expect(h.audit().at(-1)).toMatchObject({
      reason: "operation-mismatch-after-url-build",
      operationId: "getItem",
      queryKeys: ["q"],
    });
  });

  it("3xx (redirect refused) line carries queryKeys", async () => {
    const h = harness(
      { method: "GET", path: "/things/1", query: { q: "x" } },
      { response: () => new Response(null, { status: 302, headers: { location: "https://elsewhere.example/" } }) },
    );
    const res = (await handleUpstreamRequest(h.args)) as { success: boolean };
    expect(res.success).toBe(false);
    expect(h.audit().at(-1)).toMatchObject({ decision: "allow", upstreamStatus: 302, queryKeys: ["q"] });
  });

  it("returnAs:\"stage\" line carries queryKeys", async () => {
    const h = harness(
      { method: "GET", path: "/things/1", query: { q: "x" }, returnAs: "stage" },
      {
        response: () => new Response("0123456789", { status: 200, headers: { "content-length": "10" } }),
        // Declared length over the cap: refused (413) without touching storage.
        extra: { stagingStore: { config: { maxBytes: 1 } } },
      },
    );
    const res = (await handleUpstreamRequest(h.args)) as { success: boolean; status: number };
    expect(res).toMatchObject({ success: false, status: 413 });
    expect(h.audit().at(-1)).toMatchObject({ decision: "allow", upstreamStatus: 200, queryKeys: ["q"] });
  });

  it("FIXED (audit bound): 3000 undeclared names: audit line < 8 KB and queryKeyCount === 3000", async () => {
    const query: Record<string, string> = {};
    for (let i = 0; i < 3000; i++) query[`k${String(i).padStart(4, "0")}${"x".repeat(995)}`] = "v";
    const h = harness({ method: "GET", path: "/things/1", query });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/does not accept query parameter/);
    const raw = h.rawAudit();
    expect(new TextEncoder().encode(raw).byteLength).toBeLessThan(8 * 1024);
    const line = h.audit().at(-1)!;
    expect(line).toMatchObject({ reason: "undeclared-query-param", queryKeyCount: 3000 });
    const keys = line.queryKeys as string[];
    expect(keys).toHaveLength(32);
    for (const k of keys) {
      expect(Array.from(k).length).toBeLessThanOrEqual(64);
      expect(k.endsWith("…")).toBe(true);
    }
    // The first 32 sorted names, truncated visibly.
    expect(keys[0]).toBe("k0000" + "x".repeat(58) + "…");
    expect(keys[31]!.startsWith("k0031")).toBe(true);
  });

  it("a short key set is audited whole, with queryKeyCount (allow and elicit lines)", async () => {
    const h = harness({ method: "GET", path: "/things/1", query: { q: "x", format: "full" } });
    await handleUpstreamRequest(h.args);
    expect(h.audit().at(-1)).toMatchObject({ queryKeys: ["format", "q"], queryKeyCount: 2 });

    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    const h2 = harness({ method: "DELETE", path: "/things/1", query: { sendUpdates: "all" } });
    await handleUpstreamRequest(h2.args);
    expect(h2.audit().find((l) => l.decision === "elicit")).toMatchObject({ queryKeys: ["sendUpdates"], queryKeyCount: 1 });
  });
});
