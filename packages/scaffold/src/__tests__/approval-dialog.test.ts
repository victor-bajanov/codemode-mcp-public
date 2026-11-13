// packages/scaffold/src/__tests__/approval-dialog.test.ts
//
// D-1 (High) regression: approval dialogs carried nothing, and any typed
// answer approved.
//
// Attacker: code running in the sandbox (prompt-injected model) that calls
//   an approval-gated (`decision: "elicit"`) operation.
// Precondition: the MCP client supports elicitation and the user approves
//   what the dialog shows.
// Payloads: (1) two different targets of the same operation, (2) a query
//   that changes the operation's reach, (3) an accept carrying
//   `{ confirm: false }`, (4) a raw non-JSON or inline multipart body on an
//   approval-only operation, (5) a dialog-layout attack via bidi/newline
//   characters in the path, the query or an inspector fact, (6) a client
//   without elicitation support or without a capabilities accessor.
// Control: the scaffold composes the dialog (headline, `Request: METHOD
//   path`, `Query:`, renderer facts, attachments, fixed trailer), the
//   requested schema is the constant confirm-only form, only
//   `{ confirm: true }` approves, opaque bodies on approval-only operations
//   are denied before any dialog, and a client that cannot be asked is
//   denied (fail-closed).
// Why the pre-fix code failed: the message was a constant plus the
//   operationId (two deletes were byte-identical), the facts were turned
//   into typed inputs whose values the user could edit and whose truth was
//   never checked (`{confirm:false}` approved), raw bytes were approvable as
//   "cannot be shown", and a missing capabilities accessor was fail-open.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "../request-handler";
import { getOrRefreshAccessToken } from "../refresh";
import { composeDialogMessage, sanitiseDialogText, CONFIRM_SCHEMA } from "../elicit";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { ElicitRenderer, SurfaceReview } from "@local/shared";

const TRAILER = "Approve only if this is exactly the request you intended.";

describe("sanitiseDialogText", () => {
  it("replaces C0, C1, line/paragraph separators and bidi controls with spaces", () => {
    const evil = "a\nb\rc\u0000d\u007fe\u0085f\u2028g\u2029h\u202Ai\u202Ej\u2066k\u2069l";
    expect(sanitiseDialogText(evil, 100)).toBe("a b c d e f g h i j k l");
  });

  it("keeps ordinary text, including non-ASCII letters, untouched", () => {
    expect(sanitiseDialogText("Zoë — 99,999.00 €", 100)).toBe("Zoë — 99,999.00 €");
  });

  it("cuts at a code-point budget and appends an ellipsis", () => {
    expect(sanitiseDialogText("abcdef", 3)).toBe("abc…");
    expect(sanitiseDialogText("abc", 3)).toBe("abc");
    expect(sanitiseDialogText("😀😀😀", 2)).toBe("😀😀…");
  });

  // Every format/control/separator class is neutralised, built with
  // String.fromCodePoint so this file carries no literal invisible characters.
  const U = (...cps: number[]): string => String.fromCodePoint(...cps);
  const classes: Array<[string, number]> = [
    ["LRM", 0x200e], ["RLM", 0x200f], ["ALM", 0x061c],
    ["zero-width space", 0x200b], ["zero-width joiner", 0x200d], ["word joiner", 0x2060],
    ["BOM", 0xfeff], ["soft hyphen", 0x00ad],
    ["tag LATIN CAPITAL A", 0xe0041], ["tag cancel", 0xe007f],
    ["interlinear anchor", 0xfff9], ["interlinear separator", 0xfffa], ["interlinear terminator", 0xfffb],
    ["tab", 0x09], ["NEL", 0x85], ["line separator", 0x2028], ["paragraph separator", 0x2029],
  ];
  for (const [name, cp] of classes) {
    it(`FIXED (D-1): neutralises ${name} (U+${cp.toString(16).toUpperCase().padStart(4, "0")})`, () => {
      expect(sanitiseDialogText(`a${U(cp)}b`, 100)).toBe("a b");
    });
  }

  const fillers: Array<[string, number]> = [
    ["Hangul filler", 0x3164], ["Hangul choseong filler", 0x115f], ["Hangul jungseong filler", 0x1160],
    ["halfwidth Hangul filler", 0xffa0], ["Braille blank", 0x2800], ["Mongolian vowel separator", 0x180e],
  ];
  for (const [name, cp] of fillers) {
    it(`FIXED (D-1): treats the invisible ${name} (U+${cp.toString(16).toUpperCase().padStart(4, "0")}) as whitespace`, () => {
      expect(sanitiseDialogText(`a${U(cp)}${U(cp)} ${U(cp)}b`, 100)).toBe("a b");
    });
  }

  it("FIXED (D-1): invisible filler padding cannot push the tail of a fact out of the dialog", () => {
    const value = "newsletter@shop.example" + U(0x3164).repeat(220) + " OR security@bank.example";
    const msg = composeDialogMessage({ headline: "H", method: "POST", path: "/x", facts: { criteria: value } });
    expect(msg.split("\n")).toContain('criteria: "newsletter@shop.example OR security@bank.example"');
  });

  it("FIXED (D-1): collapses whitespace runs (incl. NBSP and ideographic space) so a fact cannot be pushed onto a visual line of its own", () => {
    expect(sanitiseDialogText("x" + " ".repeat(150) + "count: 2", 200)).toBe("x count: 2");
    expect(sanitiseDialogText(`a${U(0xa0, 0x3000, 0x2003)}b`, 100)).toBe("a b");
    expect(sanitiseDialogText(`a ${U(0x200e)} ${U(0xe0041)}\t b`, 100)).toBe("a b");
  });
});

describe("composeDialogMessage", () => {
  it("lays out headline, request, query, facts, attachments and the trailer in that order", () => {
    const msg = composeDialogMessage({
      headline: "Confirm thing send (sendThing)",
      method: "POST",
      path: "/things/T-1/send",
      query: { notify: "all", dryRun: false, limit: 3, unset: undefined },
      facts: { recipients: "a@corp.example", count: 30, urgent: true, archived: false },
      attachments: "report.pdf (12 bytes)",
    });
    expect(msg).toBe([
      "Confirm thing send (sendThing)",
      "Request: POST /things/T-1/send",
      'Query: notify="all"; dryRun=false; limit=3',
      'recipients: "a@corp.example"',
      "count: 30",
      "urgent: yes",
      "archived: no",
      "Attachments: report.pdf (12 bytes)",
      TRAILER,
    ].join("\n"));
  });

  it("omits empty lines (no query, no facts, no attachments, empty headline)", () => {
    expect(
      composeDialogMessage({ headline: "", method: "DELETE", path: "/x", query: { a: undefined }, facts: {}, attachments: "" }),
    ).toBe(["Request: DELETE /x", TRAILER].join("\n"));
  });

  it("shows at most 8 facts, in renderer order", () => {
    const facts: Record<string, number> = {};
    for (let i = 0; i < 12; i++) facts[`f${i}`] = i;
    const lines = composeDialogMessage({ headline: "H", method: "POST", path: "/x", facts }).split("\n");
    expect(lines.filter((l) => /^f\d+: /.test(l))).toEqual(
      ["f0: 0", "f1: 1", "f2: 2", "f3: 3", "f4: 4", "f5: 5", "f6: 6", "f7: 7"],
    );
  });

  it("bounds every part: headline 200, path 300, query key 40 / value 200, fact label 40 / value 200", () => {
    const msg = composeDialogMessage({
      headline: "h".repeat(250),
      method: "POST",
      path: "/" + "p".repeat(400),
      query: { ["k".repeat(50)]: "v".repeat(250) },
      facts: { ["l".repeat(50)]: "w".repeat(250) },
    });
    const [headline, request, query, fact] = msg.split("\n");
    expect(headline).toBe("h".repeat(200) + "…");
    // Path keeps head and tail around a middle ellipsis (300 code points kept).
    expect(request).toBe("Request: POST /" + "p".repeat(149) + "…" + "p".repeat(150));
    expect(query).toBe(`Query: ${"k".repeat(40)}…="${"v".repeat(200)}…"`);
    expect(fact).toBe(`${"l".repeat(40)}…: "${"w".repeat(200)}…"`);
  });

  it("FIXED (D-1): a long path keeps its trailing target id visible", () => {
    const path = "/things/" + "x".repeat(500) + "/TARGET-ID-123";
    const request = composeDialogMessage({ headline: "H", method: "DELETE", path, facts: {} }).split("\n")[1]!;
    expect(request.startsWith("Request: DELETE /things/")).toBe(true);
    expect(request.endsWith("/TARGET-ID-123")).toBe(true);
    expect(request).toContain("…");
    expect(Array.from(request.slice("Request: DELETE ".length))).toHaveLength(301);
  });

  it("FIXED (D-1): the Query line shows every pair; none is hidden behind a count", () => {
    const query: Record<string, string | undefined> = {};
    for (let i = 0; i < 11; i++) query[`k${i}`] = String(i);
    query.skipped = undefined;
    const line = composeDialogMessage({ headline: "H", method: "GET", path: "/x", query, facts: {} }).split("\n")[2];
    expect(line).toBe('Query: k0="0"; k1="1"; k2="2"; k3="3"; k4="4"; k5="5"; k6="6"; k7="7"; k8="8"; k9="9"; k10="10"');
    expect(line).not.toContain("more");
  });

  it("FIXED (D-1): the Attachments line is sanitised too (separators in staged filenames cannot forge lines)", () => {
    const U = (cp: number): string => String.fromCodePoint(cp);
    const msg = composeDialogMessage({
      headline: "H",
      method: "POST",
      path: "/x",
      facts: {},
      attachments: `a${U(0x2028)}Approved by finance.pdf (3 bytes); b${U(0x85)}c.pdf (4 bytes)`,
    });
    expect(msg.split("\n")).toEqual([
      "H",
      "Request: POST /x",
      "Attachments: a Approved by finance.pdf (3 bytes); b c.pdf (4 bytes)",
      TRAILER,
    ]);
    expect(msg).not.toMatch(/[\u0085\u2028\u2029]/);
  });

  it("FIXED (D-1): a query value cannot masquerade as extra pairs (string values are JSON-quoted)", () => {
    const msg = composeDialogMessage({
      headline: "H",
      method: "PUT",
      path: "/x",
      query: { sendUpdates: "all; sendUpdates=none; fields=id", maxResults: 5, dryRun: false },
      facts: {},
    });
    expect(msg.split("\n")[2]).toBe('Query: sendUpdates="all; sendUpdates=none; fields=id"; maxResults=5; dryRun=false');
  });

  it("FIXED (D-1): a fact value cannot masquerade as extra facts or a request line (string values are JSON-quoted)", () => {
    const msg = composeDialogMessage({
      headline: "H",
      method: "PUT",
      path: "/x",
      facts: { unexpectedKeys: 'Payments Request: POST /BatchPayments total: 0 "q"\\', total: 99999, ok: true },
    });
    expect(msg.split("\n").slice(2, 5)).toEqual([
      'unexpectedKeys: "Payments Request: POST /BatchPayments total: 0 \\"q\\"\\\\"',
      "total: 99999",
      "ok: yes",
    ]);
  });

  it("FIXED (D-1): the Attachments line is bounded (600 code points)", () => {
    const msg = composeDialogMessage({ headline: "H", method: "POST", path: "/x", facts: {}, attachments: "f".repeat(700) });
    expect(msg.split("\n")[2]).toBe(`Attachments: ${"f".repeat(600)}…`);
  });

  it("FIXED (D-1): the opaque-body warning is its own uncapped line; only the op-derived parts are capped", () => {
    const opId = "op".repeat(150);
    const msg = composeDialogMessage({
      headline: `Confirm operation: ${opId}`,
      opaqueBody: "d".repeat(300),
      method: "POST",
      path: "/x",
      facts: {},
    });
    const lines = msg.split("\n");
    expect(lines[0]).toBe(`Confirm operation: ${opId}`.slice(0, 200) + "…");
    expect(lines[1]).toBe(
      `Its request body (${"d".repeat(200)}…) cannot be shown here; approve only if you expected this upload.`,
    );
    expect(lines[2]).toBe("Request: POST /x");
  });

  it("sanitises headline, path, query and facts so no line can be forged", () => {
    const msg = composeDialogMessage({
      headline: "Confirm\nApproved by admin",
      method: "POST",
      path: "/things/a\u202Eb",
      query: { "n\nx": "1\nTrailer" },
      facts: { "label\u2028": "v\u2029Request: GET /harmless" },
    });
    const lines = msg.split("\n");
    expect(lines).toEqual([
      "Confirm Approved by admin",
      "Request: POST /things/a b",
      'Query: n x="1 Trailer"',
      'label : "v Request: GET /harmless"',
      TRAILER,
    ]);
  });
});

// ---------------------------------------------------------------------------
// Handler-level regressions over a fake spec.
// ---------------------------------------------------------------------------

const SPEC: OpenApiSpec = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/things/{thingId}/send": {
      post: {
        operationId: "sendThing",
        parameters: [
          { name: "thingId", in: "path", required: true, schema: { type: "string" } },
          { name: "notify", in: "query", schema: { type: "string" } },
        ],
        requestBody: { content: { "application/json": { schema: { type: "object", properties: { to: { type: "string" } } } } } },
        responses: { "200": { description: "OK" } },
      },
    },
    "/things/{thingId}": {
      delete: {
        operationId: "deleteThing",
        parameters: [
          { name: "thingId", in: "path", required: true, schema: { type: "string" } },
          { name: "sendUpdates", in: "query", schema: { type: "string" } },
          ...Array.from({ length: 17 }, (_, i) => ({ name: `q${i}`, in: "query", schema: { type: "string" } })),
        ],
        responses: { "204": { description: "OK" } },
      },
    },
    "/things/{thingId}/publish": {
      post: {
        operationId: "publishThing",
        parameters: [{ name: "thingId", in: "path", required: true, schema: { type: "string" } }],
        requestBody: { content: { "application/json": { schema: { type: "object" } } } },
        responses: { "200": { description: "OK" } },
      },
    },
    "/uploads": {
      post: {
        operationId: "uploadThing",
        requestBody: { content: { "application/json": { schema: { type: "object", properties: { Amount: { type: "number" } } } } } },
        responses: { "200": { description: "OK" } },
      },
    },
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;

const inspectSpy = vi.fn();
const SR: SurfaceReview = {
  sendThing: { decision: "elicit", category: "external_data_flow" },
  deleteThing: { decision: "elicit", category: "irreversible" },
  publishThing: {
    decision: "allow",
    inspect: (req) => {
      inspectSpy(req);
      return {
        decision: "elicit",
        category: "persistent_state",
        reason: "publish",
        summary: { audience: "everyone\u202E (internal only)", count: 1000 },
      };
    },
  },
  uploadThing: { decision: "elicit", category: "financial_legal" },
};

// Renderer for one category only: it reads the target from pathParams,
// never from the sandbox body.
const RENDERERS: Partial<Record<string, ElicitRenderer>> = {
  external_data_flow: (input) => ({
    headline: `Confirm thing send (${input.operationId})`,
    facts: {
      thingId: input.pathParams.thingId ?? "",
      ...(input.body && typeof (input.body as { to?: unknown }).to === "string"
        ? { to: (input.body as { to: string }).to }
        : {}),
    },
  }),
};

function makeFakeBroker() {
  const data = new Map<string, unknown>();
  const storage = {
    get: async <T>(k: string) => data.get(k) as T | undefined,
    put: async <T>(k: string, v: T) => { data.set(k, v); },
  };
  return {
    async getOrRefreshAccessToken(args: { userId: string; refreshToken: string }) {
      return getOrRefreshAccessToken({
        storage,
        rotation: "static",
        refreshToken: args.refreshToken,
        clientId: "CID",
        clientSecret: "CSEC",
        tokenUrl: "https://api.example.com/token",
      });
    },
  };
}

function harness(
  ctx: UpstreamCtx,
  opts: {
    answer?: unknown;
    server?: unknown;
  } = {},
) {
  const fetchSpy = vi.fn<typeof fetch>(async (url: RequestInfo | URL) => {
    const u = typeof url === "string" ? url : url.toString();
    if (u.includes("/token")) {
      return new Response(JSON.stringify({ access_token: "AT-x", expires_in: 3600 }), { status: 200 });
    }
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchSpy);
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  const elicitInput = vi.fn(async (_params: unknown, _options?: unknown) =>
    opts.answer ?? { action: "accept", content: { confirm: true } });
  const server = opts.server ?? { server: { getClientCapabilities: () => ({ elicitation: {} }), elicitInput } };
  return {
    fetchSpy,
    elicitInput,
    audit: () =>
      logSpy.mock.calls
        .map((c) => c[0])
        .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
        .map((s) => JSON.parse(s.slice(6)) as Record<string, unknown>),
    upstreamCalls: () => fetchSpy.mock.calls.filter((c) => !String(c[0]).includes("/token")),
    messages: () => elicitInput.mock.calls.map((c) => (c[0] as { message: string }).message),
    args: {
      ctx,
      spec: SPEC,
      surfaceReview: SR,
      elicitRenderers: RENDERERS,
      apiBaseUrl: "https://api.example.com",
      deploymentName: "test",
      props: { refreshToken: "RT-1", userId: "test-user" },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: server as any,
      env: { ALLOW_PII_IN_LOGS: "true" } as { ALLOW_PII_IN_LOGS?: string },
      audit: {},
      oauth: {
        refreshTokenAccessor: (p: Record<string, unknown>) => p.refreshToken as string,
        userIdAccessor: (p: Record<string, unknown>) => p.userId as string | undefined,
        broker: makeFakeBroker(),
      },
    },
  };
}

describe("D-1 approval dialog through handleUpstreamRequest", () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); inspectSpy.mockReset(); });

  it("FIXED (D-1): two deletes of different targets produce different dialogs naming the request", async () => {
    const a = harness({ method: "DELETE", path: "/things/HARMLESS-1" });
    await handleUpstreamRequest(a.args);
    const b = harness({ method: "DELETE", path: "/things/BOARD-MEETING", query: { sendUpdates: "all" } });
    await handleUpstreamRequest(b.args);
    const [ma] = a.messages();
    const [mb] = b.messages();
    expect(ma).not.toBe(mb);
    expect(ma).toBe(["Confirm operation: deleteThing", "Request: DELETE /things/HARMLESS-1", TRAILER].join("\n"));
    expect(mb).toBe([
      "Confirm operation: deleteThing",
      "Request: DELETE /things/BOARD-MEETING",
      'Query: sendUpdates="all"',
      TRAILER,
    ].join("\n"));
  });

  it("FIXED (D-1): the requested schema is the constant confirm-only form, whatever the renderer returns", async () => {
    const h = harness({ method: "POST", path: "/things/T-9/send", body: { to: "victim@corp.example" } });
    await handleUpstreamRequest(h.args);
    const params = h.elicitInput.mock.calls[0]![0] as { requestedSchema: unknown };
    expect(params.requestedSchema).toEqual(CONFIRM_SCHEMA);
  });

  it("FIXED (D-1): renderers get the decoded path params, so the target shown is the one sent (not a body decoy)", async () => {
    const h = harness({
      method: "POST",
      path: "/things/THE-THING%20ACTUALLY-SENT/send",
      query: { notify: "everyone" },
      body: { to: "victim@corp.example", id: "harmless-newsletter-id" },
    });
    await handleUpstreamRequest(h.args);
    const [msg] = h.messages();
    expect(msg).toBe([
      "Confirm thing send (sendThing)",
      "Request: POST /things/THE-THING%20ACTUALLY-SENT/send",
      'Query: notify="everyone"',
      'thingId: "THE-THING ACTUALLY-SENT"',
      'to: "victim@corp.example"',
      TRAILER,
    ].join("\n"));
    expect(msg).not.toContain("harmless-newsletter-id");
    expect(h.audit().find((l) => l.elicitationOutcome === "accepted")).toMatchObject({
      elicitFields: { thingId: "THE-THING ACTUALLY-SENT", to: "victim@corp.example" },
    });
  });

  it("FIXED (D-1): inspector facts reach the dialog (no renderer), sanitised against layout attacks", async () => {
    const h = harness({ method: "POST", path: "/things/T\u202E1/publish", body: { title: "x" } });
    await handleUpstreamRequest(h.args);
    expect(inspectSpy).toHaveBeenCalledTimes(1);
    const [msg] = h.messages();
    expect(msg).toBe([
      "Confirm operation: publishThing",
      "Request: POST /things/T 1/publish",
      'audience: "everyone (internal only)"',
      "count: 1000",
      // The walker adds body properties declared by the schema only; this op declares none.
      TRAILER,
    ].join("\n"));
    expect(msg).not.toMatch(/[\u202A-\u202E\u2066-\u2069]/);
  });

  for (const content of [{ confirm: false }, { confirm: true, extra: 1 }, { confirm: "true" }, {}]) {
    it(`FIXED (D-1): accept with ${JSON.stringify(content)} is a decline — no token, no fetch, audit declined`, async () => {
      const h = harness(
        { method: "DELETE", path: "/things/BOARD-MEETING" },
        { answer: { action: "accept", content } },
      );
      await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
        "Operation deleteThing requires user approval; outcome: declined",
      );
      expect(h.fetchSpy).not.toHaveBeenCalled();
      expect(h.audit().at(-1)).toMatchObject({ decision: "elicit", elicitationOutcome: "declined" });
    });
  }

  it("FIXED (D-1): a meaningful query pair placed last among 10 is still shown", async () => {
    const query: Record<string, string> = {};
    for (let i = 0; i < 9; i++) query[`q${i}`] = "x";
    query.sendUpdates = "all";
    const h = harness({ method: "DELETE", path: "/things/BOARD-MEETING", query });
    await handleUpstreamRequest(h.args);
    const queryLine = h.messages()[0]!.split("\n").find((l) => l.startsWith("Query: "))!;
    expect(queryLine.endsWith('; sendUpdates="all"')).toBe(true);
    expect(queryLine.split("; ")).toHaveLength(10);
  });

  it("FIXED (D-1): an approval request with more than 16 query pairs is denied before any dialog", async () => {
    const query: Record<string, string | undefined> = { unset: undefined };
    for (let i = 0; i < 17; i++) query[`q${i}`] = "x";
    const h = harness({ method: "DELETE", path: "/things/BOARD-MEETING", query });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
      "Operation deleteThing requires approval but its query has 17 parameters; at most 16 can be shown in the approval dialog",
    );
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit().at(-1)).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "too-many-query-params-for-dialog",
      operationId: "deleteThing",
    });
  });

  it("16 defined query pairs (undefined values not counted) still reach the dialog", async () => {
    const query: Record<string, string | undefined> = { q16: undefined };
    for (let i = 0; i < 16; i++) query[`q${i}`] = "x";
    const h = harness({ method: "DELETE", path: "/things/BOARD-MEETING", query });
    await handleUpstreamRequest(h.args);
    expect(h.elicitInput).toHaveBeenCalledTimes(1);
  });

  it("accept with { confirm: true } goes through", async () => {
    const h = harness({ method: "DELETE", path: "/things/BOARD-MEETING" });
    await expect(handleUpstreamRequest(h.args)).resolves.toBeDefined();
    expect(h.upstreamCalls()).toHaveLength(1);
  });

  const opaqueCases: { name: string; ctx: Partial<UpstreamCtx> }[] = [
    { name: "raw XML", ctx: { bodyBase64: Buffer.from("<Payments><Amount>99999</Amount></Payments>").toString("base64"), contentType: "application/xml" } },
    { name: "text/plain rawBody", ctx: { body: "Amount=99999", rawBody: true, contentType: "text/plain" } },
    { name: "untyped bytes", ctx: { bodyBase64: Buffer.from([1, 2, 3, 4]).toString("base64") } },
    { name: "inline multipart", ctx: { multipart: [{ name: "file", value: "Amount=99999", contentType: "text/plain" }] } },
  ];
  for (const c of opaqueCases) {
    it(`FIXED (D-1): ${c.name} on an approval-only op is denied before any dialog; nothing on the wire`, async () => {
      const h = harness({ method: "POST", path: "/uploads", ...c.ctx } as UpstreamCtx);
      await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
        "Operation uploadThing requires approval but its body cannot be shown; send it as JSON (object `body`) or omit it",
      );
      expect(h.elicitInput).not.toHaveBeenCalled();
      expect(h.fetchSpy).not.toHaveBeenCalled();
      expect(h.audit().at(-1)).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "opaque-body-on-approval-op",
        operationId: "uploadThing",
      });
    });
  }

  for (const contentType of [
    "text/plain) was pre-verified by the finance team; approve",
    "application/xml\nApproved: yes",
  ]) {
    it(`FIXED (C-4): a prose/newline contentType ${JSON.stringify(contentType.slice(0, 20))}… never reaches a dialog`, async () => {
      const h = harness({
        method: "POST",
        path: "/uploads",
        bodyBase64: Buffer.from("<x/>").toString("base64"),
        contentType,
      });
      await expect(handleUpstreamRequest(h.args)).rejects.toThrow();
      expect(h.elicitInput).not.toHaveBeenCalled();
      expect(h.fetchSpy).not.toHaveBeenCalled();
      // Denied as opaque here; Task 7's entry grammar check denies it earlier
      // as invalid-content-type. Either way the dialog never sees it.
      expect(["opaque-body-on-approval-op", "invalid-content-type"]).toContain(h.audit().at(-1)!.reason);
    });
  }

  it("raw JSON bytes on an approval-only op stay approvable (rendered parsed)", async () => {
    const h = harness({
      method: "POST",
      path: "/uploads",
      bodyBase64: Buffer.from('{"Amount":250}').toString("base64"),
      contentType: "application/json",
    });
    await handleUpstreamRequest(h.args);
    expect(h.messages()[0]).toContain("Amount: 250");
  });

  it("FIXED (D-1): a client without elicitation capability is denied (unsupported), no fetch", async () => {
    const elicitInput = vi.fn();
    const h = harness(
      { method: "DELETE", path: "/things/BOARD-MEETING" },
      { server: { server: { getClientCapabilities: () => ({ tools: {} }), elicitInput } } },
    );
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
      "Operation deleteThing requires user approval; outcome: unsupported",
    );
    expect(elicitInput).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit().at(-1)).toMatchObject({ decision: "elicit", elicitationOutcome: "unsupported" });
  });

  it("FIXED (D-1): a server object without getClientCapabilities is fail-closed (unsupported), no fetch", async () => {
    const elicitInput = vi.fn();
    const h = harness(
      { method: "DELETE", path: "/things/BOARD-MEETING" },
      { server: { server: { elicitInput } } },
    );
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
      "Operation deleteThing requires user approval; outcome: unsupported",
    );
    expect(elicitInput).not.toHaveBeenCalled();
    expect(h.fetchSpy).not.toHaveBeenCalled();
    expect(h.audit().at(-1)).toMatchObject({ elicitationOutcome: "unsupported" });
  });
});
