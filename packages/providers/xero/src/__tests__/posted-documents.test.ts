// F2-4 regression, end to end: the real request handler with the real Xero
// provider (spec, surface review, draft inspector, stored-status hook,
// requestHeaders hook). Only the edges are mocked: upstream `fetch` (routed
// by URL so `GET …/Invoices/<id>` answers the configured stored document),
// the token broker, and the MCP server's `elicitInput` (never called here:
// every outcome is an allow or a deny).
//
// Attacker: a prompt-injected LLM in a legitimate Xero user's session.
// Precondition: an approved (AUTHORISED) supplier bill exists; the attacker
//   knows its InvoiceID (any read lists it) and has created a contact of
//   their own (creates are open).
// Payload: `POST /Invoices` (updateOrCreateInvoices) carrying the approved
//   bill's `InvoiceID`, the attacker's `Contact`, the attacker's `LineItems`
//   (48,500) and `DueDate`, with NO `Status` — the shape the old client note
//   recommended for "update preserving the current status"; then the
//   attacker's next move, the same body with `Status: "DRAFT"`; then a by-id
//   `POST /Invoices/<approved>` whose body names another id.
// Control: `inspectInvoiceDraft` requires an explicit DRAFT/SUBMITTED
//   `Status` on every item (`invoice-status-required`), ties a body id to
//   the path id (`invoice-id-mismatch`) and refuses an inline Contact with
//   payee fields (`invoice-inline-contact-details`); `inspectStoredInvoice`
//   reads every named document first (`GET /Invoices/{id}` through the same
//   handler, bearer token and tenant header) and denies unless the stored
//   `Status` is DRAFT or SUBMITTED (`invoice-not-draft-upstream`); a 404,
//   another non-2xx or more than four documents deny. Credit notes twin it.
// Pre-fix: `drafts.ts` allowed any item with a non-empty id string and no
//   `Status` ("Xero keeps the status and refuses edits to posted records" —
//   an unverified upstream belief), never compared the body id with the path
//   id, and no stored read existed: the POST left the Worker with a plain
//   `allow` audit line. Each `FIXED` probe asserts the specific deny reason
//   or the GET, so it fails against that code (verified by unwiring the
//   stored-status hook from the invoice entries and by restoring the
//   status-less-with-id allow in `drafts.ts`, and watching the suite fail).
//   The deny probes assert the audit `reason` so a deny from another control
//   (D-2 query policy, D-3 canonical JSON, "not in surface review") cannot
//   pass them.

import { afterEach, describe, expect, it, vi } from "vitest";
import { handleUpstreamRequest, type UpstreamCtx } from "@local/scaffold";
import { xeroProvider, type XeroProps } from "../index";
import { surfaceReview } from "../surface-review";

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

const INVOICES_PATH = "/api.xro/2.0/Invoices";
const INVOICES_URL = `${xeroProvider.apiBaseUrl}${INVOICES_PATH}`;
const CREDIT_NOTES_PATH = "/api.xro/2.0/CreditNotes";
const CREDIT_NOTES_URL = `${xeroProvider.apiBaseUrl}${CREDIT_NOTES_PATH}`;

// Invented ids (GUID-shaped so they look like Xero's).
const APPROVED_BILL = "b111b111-0000-4000-8000-000000000001";
const OTHER_INVOICE = "b111b111-0000-4000-8000-000000000002";
const ATTACKER_CONTACT = "c0ffee00-1111-4222-8333-0000000000ee";
const SUPPLIER_CONTACT = "c0ffee00-1111-4222-8333-000000000001";
const CREDIT_NOTE = "cccccccc-0000-4000-8000-000000000001";

function harness(opts: {
  capabilities?: Record<string, unknown>;
  /** Answers a request by method and URL; undefined → `200 {"Status":"OK"}`. */
  routes?: (method: string, url: string) => Answer | undefined;
} = {}) {
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

  const elicitInput = vi.fn(async () => ({ action: "accept", content: { confirm: true } }));
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
  const reads = () => wire.filter((w) => w.method === "GET");
  return { call, wire, audits, elicitInput, writes, reads };
}

/** Routes `GET <collectionUrl>/<id>` to a stored document with `status`
 *  (or to an HTTP status when `status` is a number). */
function stored(collectionUrl: string, wrapper: string, idField: string, docs: Record<string, string | number>) {
  return (method: string, url: string): Answer | undefined => {
    if (method !== "GET") return undefined;
    for (const [id, status] of Object.entries(docs)) {
      if (url !== `${collectionUrl}/${id}`) continue;
      if (typeof status === "number") return { status, body: { Title: "nope" } };
      return { status: 200, body: { [wrapper]: [{ [idField]: id, Status: status }] } };
    }
    return undefined;
  };
}

const storedInvoices = (docs: Record<string, string | number>) => stored(INVOICES_URL, "Invoices", "InvoiceID", docs);
const storedCreditNotes = (docs: Record<string, string | number>) => stored(CREDIT_NOTES_URL, "CreditNotes", "CreditNoteID", docs);

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// The review's payload: rewrite the approved bill to the attacker's contact and amount.
const attackerLines = [{ Description: "Consulting services", Quantity: 1, UnitAmount: 48500, AccountCode: "400" }];
const rewriteNoStatus = {
  Invoices: [{ InvoiceID: APPROVED_BILL, Contact: { ContactID: ATTACKER_CONTACT }, LineItems: attackerLines, DueDate: "2026-11-17" }],
};
const rewriteAsDraft = { Invoices: [{ ...rewriteNoStatus.Invoices[0], Status: "DRAFT" }] };

describe("the client note no longer promises a status-less update (F2-4)", () => {
  it("FIXED (F2-4): the invoice and credit-note notes say Status is required and no longer say it may be omitted", () => {
    for (const id of [
      "xero.accounting.createInvoices",
      "xero.accounting.updateOrCreateInvoices",
      "xero.accounting.updateInvoice",
      "xero.accounting.createCreditNotes",
      "xero.accounting.updateOrCreateCreditNotes",
      "xero.accounting.updateCreditNote",
    ]) {
      const note = surfaceReview[id]?.clientNote ?? "";
      expect(note, id).toMatch(/`Status` is required/);
      expect(note, id).not.toMatch(/may be omitted/i);
      expect(note, id).toMatch(/read from Xero before/);
      expect(note, id).toMatch(/must equal the path id/);
    }
  });

  it("REFUTED: the not-draft deny message is unchanged (control)", async () => {
    const h = harness();
    await expect(h.call({ method: "POST", path: INVOICES_PATH, body: { Invoices: [{ ...rewriteNoStatus.Invoices[0], Status: "AUTHORISED" }] } }))
      .rejects.toThrow(/Authorised, paid, voided and deleted invoices are immutable here/);
    expect(h.audits.at(-1)).toMatchObject({ decision: "deny", reason: "invoice-not-draft" });
    expect(h.wire).toHaveLength(0);
  });
});

describe("a status-less update of a posted bill is denied before any send (F2-4)", () => {
  it("FIXED (F2-4): the rewrite with no Status is denied `invoice-status-required`; no GET, nothing sent", async () => {
    const h = harness({ routes: storedInvoices({ [APPROVED_BILL]: "AUTHORISED" }) });
    await expect(h.call({ method: "POST", path: INVOICES_PATH, body: rewriteNoStatus }))
      .rejects.toThrow(/without an explicit Status/);
    expect(h.wire).toHaveLength(0);
    expect(h.elicitInput).not.toHaveBeenCalled();
    expect(h.audits.at(-1)).toMatchObject({
      operationId: "xero.accounting.updateOrCreateInvoices",
      decision: "deny",
      category: "irreversible",
      reason: "invoice-status-required",
    });
  });

  it("FIXED (F2-4): `Status: null` and a flat by-id body with no Status are denied the same way", async () => {
    const h = harness();
    await expect(h.call({ method: "POST", path: INVOICES_PATH, body: { Invoices: [{ ...rewriteNoStatus.Invoices[0], Status: null }] } }))
      .rejects.toThrow(/without an explicit Status/);
    await expect(h.call({ method: "POST", path: `${INVOICES_PATH}/${APPROVED_BILL}`, body: { Contact: { ContactID: ATTACKER_CONTACT }, LineItems: attackerLines } }))
      .rejects.toThrow(/without an explicit Status/);
    expect(h.audits.map((a) => a.reason)).toEqual(["invoice-status-required", "invoice-status-required"]);
    expect(h.wire).toHaveLength(0);
  });

  it("FIXED (F2-4): the credit-note twin with no Status is denied `creditnote-status-required`", async () => {
    const h = harness();
    await expect(h.call({
      method: "POST",
      path: CREDIT_NOTES_PATH,
      body: { CreditNotes: [{ CreditNoteID: CREDIT_NOTE, Contact: { ContactID: ATTACKER_CONTACT }, LineItems: attackerLines }] },
    })).rejects.toThrow(/without an explicit Status/);
    expect(h.wire).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ operationId: "xero.accounting.updateOrCreateCreditNotes", decision: "deny", reason: "creditnote-status-required" });
  });
});

describe("the stored document is read before an update is sent (F2-4)", () => {
  it("FIXED (F2-4): the rewrite as DRAFT reads the stored bill (bearer + tenant header); stored AUTHORISED → denied `invoice-not-draft-upstream`, POST not sent", async () => {
    const h = harness({ routes: storedInvoices({ [APPROVED_BILL]: "AUTHORISED" }) });
    await expect(h.call({ method: "POST", path: INVOICES_PATH, body: rewriteAsDraft }))
      .rejects.toThrow(/not a draft in Xero/);

    expect(h.wire.map((w) => w.method)).toEqual(["GET"]);
    const read = h.reads()[0]!;
    expect(read.url).toBe(`${INVOICES_URL}/${APPROVED_BILL}`);
    expect(read.headers["Authorization"]).toBe("Bearer AT");
    expect(read.headers["xero-tenant-id"]).toBe("tenant-a");
    expect(h.elicitInput).not.toHaveBeenCalled();

    // Audit: the GET's own allow line, then the POST's deny with the hook's reason.
    expect(h.audits.map((a) => [a.operationId, a.decision])).toEqual([
      ["xero.accounting.getInvoice", "allow"],
      ["xero.accounting.updateOrCreateInvoices", "deny"],
    ]);
    expect(h.audits[0]).toMatchObject({ method: "GET", upstreamStatus: 200 });
    expect(h.audits[1]).toMatchObject({ category: "irreversible", reason: "invoice-not-draft-upstream" });
  });

  it("FIXED (F2-4): the deny names no stored value (the stored status stays out of the model's view)", async () => {
    const h = harness({ routes: storedInvoices({ [APPROVED_BILL]: "AUTHORISED" }) });
    await expect(h.call({ method: "POST", path: INVOICES_PATH, body: rewriteAsDraft }))
      .rejects.not.toThrow(/AUTHORISED/);
  });

  it("FIXED (F2-4): stored PAID, VOIDED and DELETED are denied too; stored DRAFT and submitted (lower case) let the POST through unchanged", async () => {
    for (const status of ["PAID", "VOIDED", "DELETED"]) {
      const h = harness({ routes: storedInvoices({ [APPROVED_BILL]: status }) });
      await expect(h.call({ method: "POST", path: INVOICES_PATH, body: rewriteAsDraft })).rejects.toThrow(/not a draft in Xero/);
      expect(h.writes(), status).toHaveLength(0);
      expect(h.audits.at(-1), status).toMatchObject({ decision: "deny", reason: "invoice-not-draft-upstream" });
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
    for (const status of ["DRAFT", "submitted"]) {
      const h = harness({ routes: storedInvoices({ [APPROVED_BILL]: status }) });
      await h.call({ method: "POST", path: INVOICES_PATH, body: rewriteAsDraft });
      expect(h.wire.map((w) => w.method), status).toEqual(["GET", "POST"]);
      expect(JSON.parse(h.writes()[0]!.body!), status).toEqual(rewriteAsDraft);
      expect(h.audits.map((a) => a.decision), status).toEqual(["allow", "allow"]);
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });

  it("FIXED (F2-4): a 404 on the id denies `invoice-not-found`; a 500 denies `invoice-read-failed` with the status only", async () => {
    const h404 = harness({ routes: storedInvoices({ [APPROVED_BILL]: 404 }) });
    await expect(h404.call({ method: "POST", path: INVOICES_PATH, body: rewriteAsDraft })).rejects.toThrow(/was not found in Xero/);
    expect(h404.writes()).toHaveLength(0);
    expect(h404.audits.at(-1)).toMatchObject({ decision: "deny", reason: "invoice-not-found" });
    vi.restoreAllMocks();
    vi.unstubAllGlobals();

    const h500 = harness({ routes: storedInvoices({ [APPROVED_BILL]: 500 }) });
    await expect(h500.call({ method: "POST", path: INVOICES_PATH, body: rewriteAsDraft })).rejects.toThrow(/upstream status 500/);
    await expect(h500.call({ method: "POST", path: INVOICES_PATH, body: rewriteAsDraft })).rejects.not.toThrow(/nope/);
    expect(h500.writes()).toHaveLength(0);
    expect(h500.audits.filter((a) => a.decision === "deny").map((a) => a.reason)).toEqual(["invoice-read-failed", "invoice-read-failed"]);
  });

  it("FIXED (F2-4): the credit-note twin as DRAFT on a stored AUTHORISED credit note is read then denied `creditnote-not-draft-upstream`", async () => {
    const h = harness({ routes: storedCreditNotes({ [CREDIT_NOTE]: "AUTHORISED" }) });
    await expect(h.call({
      method: "POST",
      path: CREDIT_NOTES_PATH,
      body: { CreditNotes: [{ CreditNoteID: CREDIT_NOTE, Status: "DRAFT", Contact: { ContactID: ATTACKER_CONTACT }, LineItems: attackerLines }] },
    })).rejects.toThrow(/not a draft in Xero/);
    expect(h.wire.map((w) => [w.method, w.url])).toEqual([["GET", `${CREDIT_NOTES_URL}/${CREDIT_NOTE}`]]);
    expect(h.audits.map((a) => [a.operationId, a.decision])).toEqual([
      ["xero.accounting.getCreditNote", "allow"],
      ["xero.accounting.updateOrCreateCreditNotes", "deny"],
    ]);
    expect(h.audits[1]).toMatchObject({ reason: "creditnote-not-draft-upstream" });
  });

  it("FIXED (F2-4): five distinct ids are denied `invoice-too-many-updates` with no GET; four are read (four GETs) then sent", async () => {
    const ids = [1, 2, 3, 4, 5].map((n) => `b111b111-0000-4000-8000-00000000000${n}`);
    const item = (id: string) => ({ InvoiceID: id, Status: "DRAFT", Reference: "x" });
    const hFive = harness({ routes: storedInvoices(Object.fromEntries(ids.map((id) => [id, "DRAFT"]))) });
    await expect(hFive.call({ method: "PUT", path: INVOICES_PATH, body: { Invoices: ids.map(item) } }))
      .rejects.toThrow(/^At most 4 invoices/);
    expect(hFive.wire).toHaveLength(0);
    expect(hFive.audits.at(-1)).toMatchObject({ decision: "deny", reason: "invoice-too-many-updates" });
    vi.restoreAllMocks();
    vi.unstubAllGlobals();

    const hFour = harness({ routes: storedInvoices(Object.fromEntries(ids.map((id) => [id, "DRAFT"]))) });
    await hFour.call({ method: "PUT", path: INVOICES_PATH, body: { Invoices: ids.slice(0, 4).map(item) } });
    expect(hFour.wire.map((w) => w.method)).toEqual(["GET", "GET", "GET", "GET", "PUT"]);
    expect(hFour.reads().map((r) => r.url)).toEqual(ids.slice(0, 4).map((id) => `${INVOICES_URL}/${id}`));
  });
});

describe("the by-id endpoint ties the body to the path (F2-4)", () => {
  it("FIXED (F2-4): a body naming another invoice is denied `invoice-id-mismatch` before any GET", async () => {
    const h = harness({ routes: storedInvoices({ [APPROVED_BILL]: "DRAFT", [OTHER_INVOICE]: "DRAFT" }) });
    await expect(h.call({
      method: "POST",
      path: `${INVOICES_PATH}/${APPROVED_BILL}`,
      body: { InvoiceID: OTHER_INVOICE, Status: "DRAFT", Contact: { ContactID: ATTACKER_CONTACT }, LineItems: attackerLines },
    })).rejects.toThrow(/must match the invoice in the path/);
    expect(h.wire).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ operationId: "xero.accounting.updateInvoice", decision: "deny", reason: "invoice-id-mismatch" });
  });

  it("FIXED (F2-4): with the matching id (in another letter case) the GET reads the PATH id; stored AUTHORISED → denied, stored DRAFT → sent", async () => {
    const upper = APPROVED_BILL.toUpperCase();
    const body = { InvoiceID: upper, Status: "DRAFT", Reference: "x" };

    const hDenied = harness({ routes: storedInvoices({ [APPROVED_BILL]: "AUTHORISED" }) });
    await expect(hDenied.call({ method: "POST", path: `${INVOICES_PATH}/${APPROVED_BILL}`, body })).rejects.toThrow(/not a draft in Xero/);
    expect(hDenied.wire.map((w) => [w.method, w.url])).toEqual([["GET", `${INVOICES_URL}/${APPROVED_BILL}`]]);
    expect(hDenied.audits.at(-1)).toMatchObject({ operationId: "xero.accounting.updateInvoice", decision: "deny", reason: "invoice-not-draft-upstream" });
    vi.restoreAllMocks();
    vi.unstubAllGlobals();

    const hSent = harness({ routes: storedInvoices({ [APPROVED_BILL]: "DRAFT" }) });
    await hSent.call({ method: "POST", path: `${INVOICES_PATH}/${APPROVED_BILL}`, body });
    expect(hSent.wire.map((w) => [w.method, w.url])).toEqual([
      ["GET", `${INVOICES_URL}/${APPROVED_BILL}`],
      ["POST", `${INVOICES_URL}/${APPROVED_BILL}`],
    ]);
    expect(JSON.parse(hSent.writes()[0]!.body!)).toEqual(body);
  });

  it("FIXED (F2-4): a by-id body with no id is still read by the path id", async () => {
    const h = harness({ routes: storedInvoices({ [APPROVED_BILL]: "AUTHORISED" }) });
    await expect(h.call({ method: "POST", path: `${INVOICES_PATH}/${APPROVED_BILL}`, body: { Status: "DRAFT", LineItems: attackerLines } }))
      .rejects.toThrow(/not a draft in Xero/);
    expect(h.wire.map((w) => [w.method, w.url])).toEqual([["GET", `${INVOICES_URL}/${APPROVED_BILL}`]]);
    expect(h.audits.at(-1)).toMatchObject({ reason: "invoice-not-draft-upstream" });
  });
});

describe("inline contacts and creates", () => {
  it("FIXED (F2-1): a DRAFT invoice whose inline Contact carries bank details is denied `invoice-inline-contact-details`; nothing sent", async () => {
    const h = harness();
    await expect(h.call({
      method: "PUT",
      path: INVOICES_PATH,
      body: { Invoices: [{ Type: "ACCPAY", Status: "DRAFT", Contact: { ContactID: SUPPLIER_CONTACT, BankAccountDetails: "062-000 13371337" }, LineItems: attackerLines }] },
    })).rejects.toThrow(/inline Contact may not carry BankAccountDetails/);
    expect(h.wire).toHaveLength(0);
    expect(h.audits.at(-1)).toMatchObject({ decision: "deny", category: "financial_legal", reason: "invoice-inline-contact-details" });
  });

  it("REFUTED: a pure DRAFT create referencing the contact by id pays no lookup — exactly one fetch, the PUT", async () => {
    const h = harness();
    const create = { Invoices: [{ Type: "ACCPAY", Status: "DRAFT", Contact: { ContactID: SUPPLIER_CONTACT }, LineItems: attackerLines }] };
    await h.call({ method: "PUT", path: INVOICES_PATH, body: create });
    expect(h.wire.map((w) => [w.method, w.url])).toEqual([["PUT", INVOICES_URL]]);
    expect(JSON.parse(h.wire[0]!.body!)).toEqual(create);
    expect(h.audits).toHaveLength(1);
    expect(h.audits[0]).toMatchObject({ operationId: "xero.accounting.createInvoices", decision: "allow" });
  });
});
