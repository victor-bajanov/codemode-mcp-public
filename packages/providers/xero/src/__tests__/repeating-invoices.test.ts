// F2-2 regression, end to end: the real request handler with the real Xero
// provider (spec, surface review, repeating-invoice inspector, stored-status
// hook, requestHeaders hook). Only the edges are mocked: upstream `fetch`
// (routed by URL so `GET …/RepeatingInvoices/<id>` answers the configured
// stored template), the token broker, and the MCP server's `elicitInput`.
//
// Attacker: a prompt-injected LLM in a legitimate Xero user's session.
// Precondition: a connected Xero tenant; for the by-id cases an existing
//   (AUTHORISED) template whose id any read lists.
// Payload: `PUT /RepeatingInvoices` with `Status: "AUTHORISED"`,
//   `ApprovedForSending`, `IncludePDF` and `MarkAsSent` set, an inline
//   `Contact` carrying the attacker's `EmailAddress`, and a line item that
//   carries data out in its description — a template Xero posts AND emails
//   every period, with no invoice gate ever consulted; an ACCPAY recurring
//   bill whose inline Contact carries the attacker's bank details; a by-id
//   `POST /RepeatingInvoices/<id>` with `Status: "DELETED"`; and a draft
//   edit of a stored AUTHORISED template.
// Control: the three repeating-invoice entries run
//   `inspectRepeatingInvoiceDraft` (explicit `Status: "DRAFT"` only —
//   `repeating-status-required` / `repeating-not-draft`; no send flags —
//   `repeating-send-flag`; no payee fields on the inline Contact —
//   `repeating-inline-contact-details`; body id tied to the path id) and
//   `inspectStoredRepeatingInvoice` (reads the stored template through the
//   same handler, bearer token and tenant header, and denies unless it is
//   DRAFT — `repeating-not-draft-upstream`). Every outcome is a deny, never
//   a dialog: no approval can make an auto-sending template safe.
// Pre-fix: `createRepeatingInvoices`, `updateOrCreateRepeatingInvoices` and
//   `updateRepeatingInvoice` were bare `{ decision: "allow", category:
//   "standard_write" }`: no inspector, no read, the PUT left the Worker with
//   a plain `allow` audit line. Each `FIXED` probe asserts the deny reason
//   or the GET, so it fails against those entries (verified by reverting the
//   three entries to the bare allow and watching the suite fail). The deny
//   probes assert the audit `reason` so a deny from another control (D-2
//   query policy, D-3 canonical JSON, "not in surface review") cannot pass
//   them. The one-off invoice controls (`REFUTED`) pin that the invoice gates
//   the template skipped are themselves unchanged.

import { afterEach, describe, expect, it, vi } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "@local/scaffold";
import { xeroProvider, type XeroProps } from "../index";

interface Dialog {
  message: string;
}

interface Wire {
  url: string;
  method: string;
  body: string | undefined;
  headers: Record<string, string>;
}

interface Answer {
  status: number;
  body: unknown;
}

const REPEATING_PATH = "/api.xro/2.0/RepeatingInvoices";
const REPEATING_URL = `${xeroProvider.apiBaseUrl}${REPEATING_PATH}`;
const INVOICES_PATH = "/api.xro/2.0/Invoices";
const OP_PUT = "xero.accounting.createRepeatingInvoices";
const OP_POST = "xero.accounting.updateOrCreateRepeatingInvoices";
const OP_BY_ID = "xero.accounting.updateRepeatingInvoice";

// Invented ids (GUID-shaped so they look like Xero's).
const TEMPLATE_ID = "4e9e4e9e-0000-4000-8000-000000000001";
const OTHER_TEMPLATE = "4e9e4e9e-0000-4000-8000-000000000002";
const CUSTOMER_ID = "c0ffee00-1111-4222-8333-000000000001";

function harness(opts: {
  capabilities?: Record<string, unknown>;
  routes?: (method: string, url: string) => Answer | undefined;
} = {}) {
  const dialogs: Dialog[] = [];
  const wire: Wire[] = [];
  const audits: Array<Record<string, unknown>> = [];

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const b = init?.body;
      const body =
        typeof b === "string" ? b
          : b instanceof Uint8Array ? new TextDecoder().decode(b)
            : b == null ? undefined : String(b);
      const method = String(init?.method);
      wire.push({ url: String(url), method, body, headers: { ...(init?.headers as Record<string, string>) } });
      const routed = opts.routes?.(method, String(url)) ?? { status: 200, body: { Status: "OK" } };
      return new Response(JSON.stringify(routed.body), {
        status: routed.status,
        headers: { "content-type": "application/json" },
      });
    }),
  );
  vi.spyOn(console, "log").mockImplementation((line: unknown) => {
    if (typeof line === "string" && line.startsWith("AUDIT ")) {
      audits.push(JSON.parse(line.slice(6)) as Record<string, unknown>);
    }
  });

  const elicitInput = vi.fn(async (params: unknown) => {
    dialogs.push(params as Dialog);
    return { action: "accept", content: { confirm: true } };
  });
  const server = {
    server: {
      getClientCapabilities: () => opts.capabilities ?? { elicitation: {} },
      elicitInput,
    },
  };
  const props: XeroProps = { refreshToken: "rt", tenantId: "tenant-a", userId: "user-a" };

  const call = (ctx: UpstreamCtx) =>
    handleUpstreamRequest<XeroProps>({
      ctx,
      spec: xeroProvider.spec,
      surfaceReview: xeroProvider.surfaceReview,
      apiBaseUrl: xeroProvider.apiBaseUrl,
      deploymentName: "test",
      props,
      server: server as never,
      oauth: {
        refreshTokenAccessor: (p) => p.refreshToken,
        userIdAccessor: (p) => p.userId,
        broker: { getOrRefreshAccessToken: async () => "AT" },
      },
      ...(xeroProvider.requestHeaders ? { requestHeaders: xeroProvider.requestHeaders } : {}),
      ...(xeroProvider.elicitRenderers ? { elicitRenderers: xeroProvider.elicitRenderers } : {}),
      audit: {},
      env: { ALLOW_PII_IN_LOGS: "true" },
    });

  const writes = () => wire.filter((w) => w.method !== "GET");
  return { call, dialogs, wire, audits, elicitInput, writes };
}

/** Routes `GET …/RepeatingInvoices/<id>` to a stored template with `status`. */
function storedTemplate(status: string, id = TEMPLATE_ID) {
  return (method: string, url: string): Answer | undefined => {
    if (method !== "GET" || url !== `${REPEATING_URL}/${id}`) return undefined;
    return { status: 200, body: { RepeatingInvoices: [{ RepeatingInvoiceID: id, Status: status }] } };
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// The review's payload: an auto-posting, auto-emailing template to the attacker's address.
const schedule = { Period: 1, Unit: "MONTHLY", DueDate: 7, DueDateType: "DAYSAFTERBILLDATE", StartDate: "2026-12-01" };
const exfilLine = { Description: "Services (ref: see attached ledger extract)", Quantity: 1, UnitAmount: 1, AccountCode: "200" };
const autoSendTemplate = {
  RepeatingInvoices: [{
    Type: "ACCREC",
    Status: "AUTHORISED",
    ApprovedForSending: true,
    IncludePDF: true,
    MarkAsSent: true,
    Contact: { Name: "Mallory Consulting", EmailAddress: "drop@attacker.example" },
    Schedule: schedule,
    LineItems: [exfilLine],
  }],
};

async function expectDeny(h: ReturnType<typeof harness>, ctx: UpstreamCtx, reason: string, message: RegExp, operationId: string) {
  await expect(h.call(ctx)).rejects.toThrow(message);
  expect(h.writes()).toHaveLength(0);
  expect(h.elicitInput).not.toHaveBeenCalled();
  expect(h.audits.at(-1)).toMatchObject({ operationId, decision: "deny", reason });
}

describe("an auto-sending template is denied at every step of the attacker's retreat (F2-2)", () => {
  it("FIXED (F2-2): the AUTHORISED, approved-for-sending template is denied `repeating-not-draft`; nothing sent, no dialog, no read", async () => {
    const h = harness();
    await expectDeny(h, { method: "PUT", path: REPEATING_PATH, body: autoSendTemplate }, "repeating-not-draft", /Only DRAFT repeating-invoice templates/, OP_PUT);
    expect(h.wire).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ category: "irreversible" });
  });

  it("FIXED (F2-2): the same on POST /RepeatingInvoices is denied the same way", async () => {
    const h = harness();
    await expectDeny(h, { method: "POST", path: REPEATING_PATH, body: autoSendTemplate }, "repeating-not-draft", /Only DRAFT repeating-invoice templates/, OP_POST);
    expect(h.wire).toHaveLength(0);
  });

  it("FIXED (F2-2): as DRAFT but still approved for sending → `repeating-send-flag` naming the flag", async () => {
    const h = harness();
    const body = { RepeatingInvoices: [{ ...autoSendTemplate.RepeatingInvoices[0], Status: "DRAFT" }] };
    await expectDeny(h, { method: "PUT", path: REPEATING_PATH, body }, "repeating-send-flag", /ApprovedForSending set: it makes Xero email/, OP_PUT);
    expect(h.audits.at(-1)).toMatchObject({ category: "external_data_flow" });
    expect(h.wire).toHaveLength(0);
  });

  it("FIXED (F2-2): each send flag alone is denied, including the lenient spellings Xero accepts", async () => {
    const h = harness();
    const base = { Type: "ACCREC", Status: "DRAFT", Contact: { ContactID: CUSTOMER_ID }, Schedule: schedule, LineItems: [exfilLine] };
    for (const flag of [{ ApprovedForSending: true }, { SendCopy: 1 }, { MarkAsSent: "true" }, { IncludePDF: "false" }, { approvedforsending: true }]) {
      await expect(h.call({ method: "PUT", path: REPEATING_PATH, body: { RepeatingInvoices: [{ ...base, ...flag }] } }), JSON.stringify(flag))
        .rejects.toThrow(/makes Xero email the generated invoices/);
      expect(h.audits.at(-1), JSON.stringify(flag)).toMatchObject({ decision: "deny", reason: "repeating-send-flag" });
    }
    expect(h.wire).toHaveLength(0);
  });

  it("FIXED (F2-1/F2-2): with the flags removed, the inline Contact's EmailAddress is denied `repeating-inline-contact-details`", async () => {
    const h = harness();
    const { ApprovedForSending: _a, IncludePDF: _i, MarkAsSent: _m, ...rest } = autoSendTemplate.RepeatingInvoices[0]!;
    const body = { RepeatingInvoices: [{ ...rest, Status: "DRAFT" }] };
    await expectDeny(h, { method: "PUT", path: REPEATING_PATH, body }, "repeating-inline-contact-details", /inline Contact may not carry EmailAddress/, OP_PUT);
    expect(h.audits.at(-1)).toMatchObject({ category: "financial_legal" });
    expect(h.wire).toHaveLength(0);
  });

  it("REFUTED: the accepted draft shape (DRAFT, no flags, Contact by id) is sent — exactly one fetch, the PUT, no read", async () => {
    const h = harness();
    const body = { RepeatingInvoices: [{ Type: "ACCREC", Status: "DRAFT", Contact: { ContactID: CUSTOMER_ID }, Schedule: schedule, LineItems: [exfilLine] }] };
    await h.call({ method: "PUT", path: REPEATING_PATH, body });
    expect(h.wire.map((w) => [w.method, w.url])).toEqual([["PUT", REPEATING_URL]]);
    expect(JSON.parse(h.wire[0]!.body!)).toEqual(body);
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.audits).toHaveLength(1);
    expect(h.audits[0]).toMatchObject({ operationId: OP_PUT, decision: "allow" });
  });

  it("FIXED (F2-2): a template with no Status is denied `repeating-status-required` (omitting it no longer means anything)", async () => {
    const h = harness();
    const body = { RepeatingInvoices: [{ Type: "ACCREC", Contact: { ContactID: CUSTOMER_ID }, Schedule: schedule, LineItems: [exfilLine] }] };
    await expectDeny(h, { method: "PUT", path: REPEATING_PATH, body }, "repeating-status-required", /without an explicit Status/, OP_PUT);
  });
});

describe("a recurring supplier bill with the attacker's bank details (F2-2, F2-1)", () => {
  const recurringBill = (status: string) => ({
    RepeatingInvoices: [{
      Type: "ACCPAY",
      Status: status,
      Contact: { Name: "Acme Supplies", BankAccountDetails: "062-000 13371337" },
      Schedule: schedule,
      LineItems: [{ Description: "Monthly retainer", Quantity: 1, UnitAmount: 4850, AccountCode: "400" }],
    }],
  });

  it("FIXED (F2-2): as AUTHORISED it is denied `repeating-not-draft`", async () => {
    const h = harness();
    await expectDeny(h, { method: "PUT", path: REPEATING_PATH, body: recurringBill("AUTHORISED") }, "repeating-not-draft", /Only DRAFT repeating-invoice templates/, OP_PUT);
  });

  it("FIXED (F2-1): as DRAFT the inline bank details are denied `repeating-inline-contact-details`", async () => {
    const h = harness();
    await expectDeny(h, { method: "PUT", path: REPEATING_PATH, body: recurringBill("DRAFT") }, "repeating-inline-contact-details", /inline Contact may not carry BankAccountDetails/, OP_PUT);
  });
});

describe("the stored template is read before a by-id edit (F2-2)", () => {
  it("FIXED (F2-2): `Status: \"DELETED\"` on the by-id endpoint is denied `repeating-not-draft`; nothing sent, no read", async () => {
    const h = harness({ routes: storedTemplate("AUTHORISED") });
    await expectDeny(h, { method: "POST", path: `${REPEATING_PATH}/${TEMPLATE_ID}`, body: { RepeatingInvoices: [{ Status: "DELETED" }] } }, "repeating-not-draft", /DELETED removes the template/, OP_BY_ID);
    expect(h.wire).toHaveLength(0);
  });

  it("FIXED (F2-2): a DRAFT edit of a stored AUTHORISED template reads it (bearer + tenant header) then denies `repeating-not-draft-upstream`", async () => {
    const h = harness({ routes: storedTemplate("AUTHORISED") });
    await expect(h.call({ method: "POST", path: `${REPEATING_PATH}/${TEMPLATE_ID}`, body: { RepeatingInvoices: [{ Status: "DRAFT", Reference: "x" }] } }))
      .rejects.toThrow(/not a draft in Xero \(its stored Status is not DRAFT\)/);
    expect(h.wire.map((w) => [w.method, w.url])).toEqual([["GET", `${REPEATING_URL}/${TEMPLATE_ID}`]]);
    expect(h.wire[0]!.headers["Authorization"]).toBe("Bearer AT");
    expect(h.wire[0]!.headers["xero-tenant-id"]).toBe("tenant-a");
    expect(h.audits.map((a) => [a.operationId, a.decision])).toEqual([
      ["xero.accounting.getRepeatingInvoice", "allow"],
      [OP_BY_ID, "deny"],
    ]);
    expect(h.audits[1]).toMatchObject({ category: "irreversible", reason: "repeating-not-draft-upstream" });
  });

  it("FIXED (F2-2): a stored SUBMITTED template is not a draft for the repeating hook (allowed = DRAFT only)", async () => {
    const h = harness({ routes: storedTemplate("SUBMITTED") });
    await expect(h.call({ method: "POST", path: `${REPEATING_PATH}/${TEMPLATE_ID}`, body: { RepeatingInvoices: [{ Status: "DRAFT", Reference: "x" }] } }))
      .rejects.toThrow(/not a draft in Xero/);
    expect(h.writes()).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ reason: "repeating-not-draft-upstream" });
  });

  it("FIXED (F2-2): a DRAFT edit of a stored DRAFT template is read then sent unchanged", async () => {
    const h = harness({ routes: storedTemplate("DRAFT") });
    const body = { RepeatingInvoices: [{ Status: "DRAFT", Reference: "x" }] };
    await h.call({ method: "POST", path: `${REPEATING_PATH}/${TEMPLATE_ID}`, body });
    expect(h.wire.map((w) => [w.method, w.url])).toEqual([
      ["GET", `${REPEATING_URL}/${TEMPLATE_ID}`],
      ["POST", `${REPEATING_URL}/${TEMPLATE_ID}`],
    ]);
    expect(JSON.parse(h.writes()[0]!.body!)).toEqual(body);
    expect(h.audits.map((a) => a.decision)).toEqual(["allow", "allow"]);
  });

  it("FIXED (F2-2): a by-id body naming another template is denied `repeating-id-mismatch` before any read", async () => {
    const h = harness({ routes: storedTemplate("DRAFT") });
    await expectDeny(
      h,
      { method: "POST", path: `${REPEATING_PATH}/${TEMPLATE_ID}`, body: { RepeatingInvoices: [{ RepeatingInvoiceID: OTHER_TEMPLATE, Status: "DRAFT" }] } },
      "repeating-id-mismatch",
      /must match the repeating invoice in the path/,
      OP_BY_ID,
    );
    expect(h.wire).toHaveLength(0);
  });

  it("FIXED (F2-2): a bulk POST naming a stored AUTHORISED template by `ID` is read by that id and denied", async () => {
    const h = harness({ routes: storedTemplate("AUTHORISED") });
    await expect(h.call({ method: "POST", path: REPEATING_PATH, body: { RepeatingInvoices: [{ ID: TEMPLATE_ID, Status: "DRAFT", Reference: "x" }] } }))
      .rejects.toThrow(/not a draft in Xero/);
    expect(h.wire.map((w) => [w.method, w.url])).toEqual([["GET", `${REPEATING_URL}/${TEMPLATE_ID}`]]);
    expect(h.audits.at(-1)).toMatchObject({ operationId: OP_POST, reason: "repeating-not-draft-upstream" });
  });
});

describe("the one-off invoice gates the template skipped are unchanged (controls)", () => {
  const line = { Description: "x", Quantity: 1, UnitAmount: 1, AccountCode: "200" };

  it("REFUTED: a one-off AUTHORISED invoice is denied `invoice-not-draft`", async () => {
    const h = harness();
    await expect(h.call({ method: "PUT", path: INVOICES_PATH, body: { Invoices: [{ Type: "ACCREC", Status: "AUTHORISED", Contact: { ContactID: CUSTOMER_ID }, LineItems: [line] }] } }))
      .rejects.toThrow(/Only DRAFT or SUBMITTED invoices/);
    expect(h.audits.at(-1)).toMatchObject({ decision: "deny", reason: "invoice-not-draft" });
    expect(h.wire).toHaveLength(0);
  });

  it("REFUTED: `SentToContact: true` on a draft invoice is denied `invoice-sent-to-contact`", async () => {
    const h = harness();
    await expect(h.call({ method: "PUT", path: INVOICES_PATH, body: { Invoices: [{ Type: "ACCREC", Status: "DRAFT", SentToContact: true, Contact: { ContactID: CUSTOMER_ID }, LineItems: [line] }] } }))
      .rejects.toThrow(/SentToContact/);
    expect(h.audits.at(-1)).toMatchObject({ decision: "deny", reason: "invoice-sent-to-contact" });
    expect(h.wire).toHaveLength(0);
  });

  it("REFUTED: emailing an invoice asks first (and is denied where the client cannot ask)", async () => {
    const asks = harness();
    await asks.call({ method: "POST", path: `${INVOICES_PATH}/${TEMPLATE_ID}/Email`, body: {} });
    expect(asks.dialogs).toHaveLength(1);
    expect(asks.dialogs[0]!.message).toContain("Confirm Xero email invoice");
    vi.restoreAllMocks();
    vi.unstubAllGlobals();

    const cannot = harness({ capabilities: {} });
    await expect(cannot.call({ method: "POST", path: `${INVOICES_PATH}/${TEMPLATE_ID}/Email`, body: {} }))
      .rejects.toThrow(/outcome: unsupported/);
    expect(cannot.wire).toHaveLength(0);
  });
});
