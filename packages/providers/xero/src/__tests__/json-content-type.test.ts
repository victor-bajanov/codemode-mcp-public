// D-3 (Medium) regression, end to end with the real Xero provider: inspected
// JSON bodies were sent under any Content-Type.
//
// Attacker: code running in the sandbox (prompt-injected model).
// Precondition: an inspected JSON operation (createInvoices: draft-status
//   inspector; createBankTransactions).
// Payload: a DRAFT invoice the inspector allows whose Reference carries
//   `&xml=<Invoices>…<Status>AUTHORISED</Status>…&z=`, sent as
//   `application/x-www-form-urlencoded`, so a form decoder upstream reads an
//   `xml` field holding an AUTHORISED payable; and the same bodies under
//   XML, text, multipart and UTF-16/UTF-7 labels.
// Control: on a gated operation a JSON body must be labelled JSON with no
//   parameter but `charset=utf-8`; it goes out as exactly `application/json`;
//   anything else is denied before the inspector runs.
// Why the pre-fix code failed: the inspector judged the JSON object while the
//   wire kept the sandbox's label.

import { afterEach, describe, expect, it, vi } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "@local/scaffold";
import { xeroProvider, type XeroProps } from "../index";

function run(ctx: UpstreamCtx) {
  const fetchSpy = vi.fn<typeof fetch>(async () => new Response('{"Status":"OK"}', { status: 200 }));
  vi.stubGlobal("fetch", fetchSpy);
  const audits: Array<Record<string, unknown>> = [];
  vi.spyOn(console, "log").mockImplementation((line: unknown) => {
    if (typeof line === "string" && line.startsWith("AUDIT ")) audits.push(JSON.parse(line.slice(6)) as Record<string, unknown>);
  });
  const props: XeroProps = { refreshToken: "rt", tenantId: "tenant-a", userId: "user-a" };
  const promise = handleUpstreamRequest<XeroProps>({
    ctx,
    spec: xeroProvider.spec,
    surfaceReview: xeroProvider.surfaceReview,
    apiBaseUrl: xeroProvider.apiBaseUrl,
    deploymentName: "test",
    props,
    server: {} as never,
    oauth: {
      refreshTokenAccessor: (p) => p.refreshToken,
      userIdAccessor: (p) => p.userId,
      broker: { getOrRefreshAccessToken: async () => "AT" },
    },
    ...(xeroProvider.requestHeaders ? { requestHeaders: xeroProvider.requestHeaders } : {}),
    audit: {},
    env: {},
  });
  return {
    promise,
    fetchSpy,
    audits,
    wire: () => {
      const init = fetchSpy.mock.calls[0]![1] as RequestInit;
      return { contentType: (init.headers as Record<string, string>)["content-type"], body: init.body };
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const DENIED = /sends its `body` as JSON; on this operation the content type must be application\/json/;

const SMUGGLED =
  "<Invoices><Invoice><Type>ACCPAY</Type><Status>AUTHORISED</Status>" +
  "<Contact><Name>Attacker Pty Ltd</Name></Contact></Invoice></Invoices>";
const DRAFT = { Invoices: [{ Type: "ACCREC", Status: "DRAFT", Reference: `&xml=${SMUGGLED}&z=` }] };

describe("Xero provider: gated JSON bodies are sent as application/json (D-3)", () => {
  it("FIXED (D-3): createInvoices DRAFT under application/x-www-form-urlencoded is denied before inspection; nothing sent", async () => {
    const r = run({ method: "PUT", path: "/api.xro/2.0/Invoices", contentType: "application/x-www-form-urlencoded", body: DRAFT });
    await expect(r.promise).rejects.toThrow(DENIED);
    expect(r.fetchSpy).not.toHaveBeenCalled();
    expect(r.audits.at(-1)).toMatchObject({
      operationId: "xero.accounting.createInvoices",
      decision: "deny",
      category: "malformed",
      reason: "json-body-non-json-content-type",
    });
  });

  const LABELS = [
    "text/xml",
    "text/plain",
    "multipart/form-data; boundary=x",
    "application/json; charset=utf-16",
    "application/json; charset=utf-7",
  ];
  for (const contentType of LABELS) {
    it(`FIXED (D-3): createBankTransactions under ${JSON.stringify(contentType)} is denied`, async () => {
      const r = run({
        method: "PUT",
        path: "/api.xro/2.0/BankTransactions",
        contentType,
        body: { BankTransactions: [{ Type: "SPEND" }] },
      });
      await expect(r.promise).rejects.toThrow(DENIED);
      expect(r.fetchSpy).not.toHaveBeenCalled();
    });
  }

  it("control: the DRAFT under 'application/json; charset=utf-8' goes out as exactly application/json, body unchanged", async () => {
    const r = run({ method: "PUT", path: "/api.xro/2.0/Invoices", contentType: "application/json; charset=utf-8", body: DRAFT });
    await r.promise;
    expect(r.wire()).toEqual({ contentType: "application/json", body: JSON.stringify(DRAFT) });
  });
});
