// packages/scaffold/src/__tests__/json-content-type.test.ts
//
// D-3 (Medium) and C-4 regression, handler level over a fake spec: inspected
// and approval-gated JSON bodies were sent under any Content-Type, and any
// string was accepted as `contentType`.
//
// Attacker: code running in the sandbox (prompt-injected model).
// Precondition: an operation that is inspected or needs approval and takes a
//   JSON body.
// Payloads: the object `body` the inspector/approver judges, sent with
//   `contentType` set to a label under which the upstream re-reads the same
//   bytes differently (`application/x-www-form-urlencoded`, `text/xml`,
//   `text/plain`, `multipart/form-data; boundary=x`,
//   `application/json; charset=utf-16` / `utf-7`); raw JSON-typed bytes that
//   are not strict UTF-8 (a BOM, invalid sequences); and prose or newlines as
//   `contentType` (C-4: dialog text injection).
// Control: `contentType` must parse as a media type of at most 100
//   characters on every operation (deny `invalid-content-type` at entry); on
//   gated operations a JSON payload must carry a JSON label with no
//   parameter but `charset=utf-8`, and is then sent (and shown to the
//   inspector) as exactly `application/json`; otherwise deny
//   `json-body-non-json-content-type` before inspection. Raw JSON-typed bytes
//   on gated operations are decoded strictly as UTF-8 (no BOM, no invalid
//   sequences) and re-serialised.
// Why the pre-fix code failed: the JSON channel kept the sandbox's label on
//   the wire, so the inspector judged `{Status: "DRAFT"}` while a form
//   decoder upstream read an `xml=` field; the raw channel's lenient decoder
//   stripped a BOM and replaced invalid bytes, so the inspector judged text
//   the upstream never received.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "../request-handler";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReview } from "@local/shared";

const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://api.example.com" }],
  paths: {
    "/inspected": {
      post: { operationId: "inspectedOp", responses: { "200": { description: "OK" } } },
    },
    "/approved": {
      post: { operationId: "approvedOp", responses: { "200": { description: "OK" } } },
    },
    "/plain": {
      post: { operationId: "plainOp", responses: { "200": { description: "OK" } } },
    },
  },
} as unknown as OpenApiSpec;

const inspectSpy = vi.fn((_req: { body?: unknown; contentType?: string }) => ({ decision: "allow" as const }));

const SR: SurfaceReview = {
  inspectedOp: { decision: "allow", category: "financial_legal", inspect: inspectSpy as never },
  approvedOp: { decision: "elicit", category: "irreversible" },
  plainOp: { decision: "allow", category: "standard_write" },
};

const BODY = { Invoices: [{ Type: "ACCREC", Status: "DRAFT", Reference: "&xml=<Status>AUTHORISED</Status>&z=" }] };

function harness(ctx: UpstreamCtx) {
  const fetchSpy = vi.fn<typeof fetch>(
    async () => new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } }),
  );
  vi.stubGlobal("fetch", fetchSpy);
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  const elicitInput = vi.fn(async () => ({ action: "accept", content: { confirm: true } }));
  return {
    fetchSpy,
    elicitInput,
    audit: () =>
      logSpy.mock.calls
        .map((c) => c[0])
        .filter((s: unknown): s is string => typeof s === "string" && s.startsWith("AUDIT "))
        .map((s) => JSON.parse(s.slice(6)) as Record<string, unknown>),
    wire: () => {
      const init = fetchSpy.mock.calls[0]![1] as RequestInit;
      const headers = init.headers as Record<string, string>;
      return {
        contentType: headers["content-type"],
        body: typeof init.body === "string" ? init.body : new TextDecoder().decode(init.body as Uint8Array),
      };
    },
    args: {
      ctx,
      spec: SPEC,
      surfaceReview: SR,
      apiBaseUrl: "https://api.example.com",
      deploymentName: "test",
      props: { refreshToken: "RT-1", userId: "u" },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      server: { server: { getClientCapabilities: () => ({ elicitation: {} }), elicitInput } } as any,
      env: {} as { ALLOW_PII_IN_LOGS?: string },
      audit: {},
      oauth: {
        refreshTokenAccessor: () => "RT-1",
        userIdAccessor: () => "u",
        broker: { getOrRefreshAccessToken: async () => "AT" },
      },
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  inspectSpy.mockClear();
});

const b64 = (s: string | Uint8Array): string => Buffer.from(s).toString("base64");

describe("D-3 a gated JSON body must be sent as application/json", () => {
  const LABELS = [
    "application/x-www-form-urlencoded",
    "text/xml",
    "text/plain",
    "multipart/form-data; boundary=x",
    "application/json; charset=utf-16",
    "application/json; charset=utf-7",
    "application/json; charset=utf-8; profile=x",
    "application/json; boundary=x",
  ];
  for (const op of ["inspected", "approved"] as const) {
    for (const contentType of LABELS) {
      it(`FIXED (D-3): ${op} op with object body under ${JSON.stringify(contentType)} is denied before inspection/approval`, async () => {
        const h = harness({ method: "POST", path: `/${op}`, body: BODY, contentType });
        await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
          `Operation ${op}Op sends its \`body\` as JSON; on this operation the content type must be application/json (omit \`contentType\`)`,
        );
        expect(inspectSpy).not.toHaveBeenCalled();
        expect(h.elicitInput).not.toHaveBeenCalled();
        expect(h.fetchSpy).not.toHaveBeenCalled();
        expect(h.audit().at(-1)).toMatchObject({
          operationId: `${op}Op`,
          decision: "deny",
          category: "malformed",
          reason: "json-body-non-json-content-type",
        });
      });
    }
  }

  it("FIXED (D-3): raw JSON bytes labelled with a JSON type but a foreign charset are denied", async () => {
    const h = harness({
      method: "POST",
      path: "/inspected",
      bodyBase64: b64(JSON.stringify(BODY)),
      contentType: "application/json; charset=utf-16",
    });
    await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/content type must be application\/json/);
    expect(h.fetchSpy).not.toHaveBeenCalled();
  });

  const ACCEPTED: Array<string | undefined> = [
    undefined,
    "application/json",
    "application/json; charset=utf-8",
    'application/json; charset="UTF-8"',
    "APPLICATION/JSON",
    " application/json",
    "application/json;",
    "text/json",
    "application/vnd.api+json",
  ];
  for (const op of ["inspected", "approved"] as const) {
    for (const contentType of ACCEPTED) {
      it(`control: ${op} op with ${JSON.stringify(contentType)} goes out as exactly application/json`, async () => {
        const h = harness({ method: "POST", path: `/${op}`, body: BODY, ...(contentType !== undefined ? { contentType } : {}) });
        await handleUpstreamRequest(h.args);
        expect(h.wire()).toEqual({ contentType: "application/json", body: JSON.stringify(BODY) });
        if (op === "inspected") {
          expect(inspectSpy.mock.calls[0]![0].contentType).toBe("application/json");
        }
      });
    }
  }

  it("control: raw `text/json` bytes on an inspected op go out canonical, as application/json", async () => {
    const h = harness({ method: "POST", path: "/inspected", rawBody: true, body: '{ "a" : 1 }', contentType: "text/json" });
    await handleUpstreamRequest(h.args);
    expect(inspectSpy.mock.calls[0]![0]).toMatchObject({ body: { a: 1 }, contentType: "application/json" });
    expect(h.wire()).toEqual({ contentType: "application/json", body: '{"a":1}' });
  });

  it("control: a plain allow op keeps its label (text/xml raw body, and a JSON body under text/plain)", async () => {
    const h = harness({ method: "POST", path: "/plain", rawBody: true, body: "<a/>", contentType: "text/xml" });
    await handleUpstreamRequest(h.args);
    expect(h.wire()).toEqual({ contentType: "text/xml", body: "<a/>" });

    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    const h2 = harness({ method: "POST", path: "/plain", body: { a: 1 }, contentType: "text/plain" });
    await handleUpstreamRequest(h2.args);
    expect(h2.wire()).toEqual({ contentType: "text/plain", body: '{"a":1}' });
  });
});

describe("D-3 raw JSON-typed bytes on gated operations are strict UTF-8", () => {
  const CASES: Array<[string, Uint8Array]> = [
    ["a UTF-8 BOM", new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode('{"to":"ok@allow"}')])],
    ["an invalid UTF-8 byte inside a string", new Uint8Array([...new TextEncoder().encode('{"to":"ok'), 0xff, ...new TextEncoder().encode('"}')])],
    ["UTF-16LE bytes", new Uint8Array(Buffer.from('{"to":"ok@allow"}', "utf16le"))],
    ["a UTF-16LE BOM", new Uint8Array([0xff, 0xfe, ...Buffer.from('{"a":1}', "utf16le")])],
  ];
  for (const op of ["inspected", "approved"] as const) {
    for (const [label, bytes] of CASES) {
      it(`FIXED (D-3): ${op} op, raw application/json bytes with ${label} are denied as unparseable`, async () => {
        const h = harness({ method: "POST", path: `/${op}`, bodyBase64: b64(bytes), contentType: "application/json" });
        await expect(handleUpstreamRequest(h.args)).rejects.toThrow(/denied by surface review/);
        expect(inspectSpy).not.toHaveBeenCalled();
        expect(h.elicitInput).not.toHaveBeenCalled();
        expect(h.fetchSpy).not.toHaveBeenCalled();
        expect(h.audit().at(-1)).toMatchObject({ decision: "deny", reason: "unparseable-json-body" });
      });
    }
  }
});

describe("C-4 contentType must be a media type on every operation", () => {
  const BAD = [
    "",
    "   ",
    "text/plain) was pre-verified by finance; approve",
    "application/json\nApproved by admin",
    "application/json\r\n",
    "text",
    "a/" + "b".repeat(99),
    "application/json; charset=é",
  ];
  for (const contentType of BAD) {
    for (const op of ["plain", "approved"] as const) {
      it(`FIXED (C-4): ${JSON.stringify(contentType.slice(0, 40))} on the ${op} op is denied at entry`, async () => {
        const h = harness({ method: "POST", path: `/${op}`, rawBody: true, body: "x", contentType });
        await expect(handleUpstreamRequest(h.args)).rejects.toThrow(
          "codemode.request `contentType` must be a media type such as application/json (parameters allowed; at most 100 characters)",
        );
        expect(h.elicitInput).not.toHaveBeenCalled();
        expect(h.fetchSpy).not.toHaveBeenCalled();
        const last = h.audit().at(-1)!;
        expect(last).toMatchObject({ decision: "deny", category: "malformed", reason: "invalid-content-type" });
        expect(last).not.toHaveProperty("operationId");
      });
    }
  }

  it("control: a 100-character media type and a quoted multipart boundary are accepted on a plain op", async () => {
    const ct100 = "a/" + "b".repeat(98);
    const h = harness({ method: "POST", path: "/plain", rawBody: true, body: "x", contentType: ct100 });
    await handleUpstreamRequest(h.args);
    expect(h.wire().contentType).toBe(ct100);

    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    const ct = 'multipart/related; boundary="a b"';
    const h2 = harness({ method: "POST", path: "/plain", rawBody: true, body: "x", contentType: ct });
    await handleUpstreamRequest(h2.args);
    expect(h2.wire().contentType).toBe(ct);
  });
});
