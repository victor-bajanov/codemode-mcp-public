// packages/providers/xero/src/__tests__/stored-status.test.ts
//
// F2-4 / F2-2 (High): the stored-status `inspectUpstream` hooks for invoices,
// credit notes and repeating-invoice templates.
//
// Attacker: a prompt-injected model in the sandbox. Precondition: an
// authorised (posted) invoice, bill, credit note or repeating-invoice template
// exists in the organisation. Payload: an update that names the posted
// document's id with `Status: "DRAFT"` (the explicit status the sync inspector
// now requires), e.g. to repoint an approved bill at another contact or swap
// its line items. Control: before the write is sent, the host reads the
// stored document through the scaffold's upstream lookup (a plain-allow GET
// of getInvoice / getCreditNote / getRepeatingInvoice) and denies unless the
// stored Status is DRAFT or SUBMITTED (DRAFT only for repeating templates).
// Why the pre-fix code failed it: there was no read at all; the inspector
// trusted Xero to refuse edits to posted records.
//
// The lookup is faked here (direct calls); the end-to-end path through the
// request handler is covered separately.

import { describe, it, expect } from "vitest";
import type { InspectRequest, UpstreamLookup, UpstreamLookupResult } from "@local/shared";
import { MAX_UPSTREAM_LOOKUPS } from "@local/scaffold";
import {
  MAX_STORED_LOOKUPS,
  inspectStoredCreditNote,
  inspectStoredInvoice,
  inspectStoredRepeatingInvoice,
} from "../inspectors/stored-status";

const ID = "8576f4cf-e24d-4e3a-83ff-c6f30418a7de";
const ID2 = "0f3d1c2e-4b5a-4c6d-8e7f-9a0b1c2d3e4f";
const ID3 = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const ID4 = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";
const ID5 = "3c4d5e6f-7a8b-4c9d-0e1f-2a3b4c5d6e7f";

type Answer = UpstreamLookupResult | ((path: string) => UpstreamLookupResult);

/** A fake lookup that records every path and answers `answer` (or by path). */
function fakeLookup(answer: Answer): UpstreamLookup & { paths: string[] } {
  const paths: string[] = [];
  return {
    paths,
    async get(path: string) {
      paths.push(path);
      return typeof answer === "function" ? answer(path) : answer;
    },
  };
}

const storedInvoice = (Status: unknown, id = ID): UpstreamLookupResult => ({
  status: 200,
  body: { Invoices: [{ InvoiceID: id, Status }] },
});

const invoiceReq = (items: Record<string, unknown>[], extra: Partial<InspectRequest> = {}): InspectRequest => ({
  body: { Invoices: items },
  ...extra,
});

describe("inspectStoredInvoice (F2-4)", () => {
  it("re-exports the scaffold's lookup cap", () => {
    expect(MAX_STORED_LOOKUPS).toBe(MAX_UPSTREAM_LOOKUPS);
  });

  it("pure creates (no InvoiceID) are allowed with no lookup", async () => {
    const lookup = fakeLookup(storedInvoice("AUTHORISED"));
    const res = await inspectStoredInvoice(
      invoiceReq([{ Type: "ACCREC", Status: "DRAFT", Contact: { ContactID: ID2 } }, { InvoiceID: "", Status: "DRAFT" }]),
      lookup,
    );
    expect(res).toEqual({ decision: "allow" });
    expect(lookup.paths).toEqual([]);
  });

  it("FIXED (F2-4): an update of a stored AUTHORISED invoice is denied after reading it", async () => {
    const lookup = fakeLookup(storedInvoice("AUTHORISED"));
    const res = await inspectStoredInvoice(
      invoiceReq([{ InvoiceID: ID, Status: "DRAFT", Contact: { ContactID: ID2 }, LineItems: [{ UnitAmount: 48500 }] }]),
      lookup,
    );
    expect(res).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft-upstream" });
    expect(lookup.paths).toEqual([`/api.xro/2.0/Invoices/${ID}`]);
  });

  it.each(["PAID", "VOIDED", "DELETED"])("FIXED (F2-4): a stored %s invoice is denied", async (status) => {
    const res = await inspectStoredInvoice(invoiceReq([{ InvoiceID: ID, Status: "DRAFT" }]), fakeLookup(storedInvoice(status)));
    expect(res).toMatchObject({ decision: "deny", reason: "invoice-not-draft-upstream" });
  });

  it("never copies the stored status into the message", async () => {
    const res = await inspectStoredInvoice(
      invoiceReq([{ InvoiceID: ID, Status: "DRAFT" }]),
      fakeLookup(storedInvoice("ZZ-STORED-VALUE")),
    );
    expect(res).toMatchObject({ decision: "deny", reason: "invoice-not-draft-upstream" });
    expect(res.message).toBeDefined();
    expect(res.message).not.toContain("ZZ-STORED-VALUE");
    expect(res.message).toContain("DRAFT or SUBMITTED");
  });

  it.each(["DRAFT", "SUBMITTED", "submitted", "Draft"])("allows a stored %s invoice", async (status) => {
    const lookup = fakeLookup(storedInvoice(status));
    const res = await inspectStoredInvoice(invoiceReq([{ InvoiceID: ID, Status: "DRAFT" }]), lookup);
    expect(res).toEqual({ decision: "allow" });
    expect(lookup.paths).toEqual([`/api.xro/2.0/Invoices/${ID}`]);
  });

  it("FIXED (F2-4): a made-up id (\"x\") that Xero does not know is denied invoice-not-found", async () => {
    const lookup = fakeLookup({ status: 404, body: "Not Found" });
    const res = await inspectStoredInvoice(invoiceReq([{ InvoiceID: "x", Type: "ACCPAY", Status: "DRAFT" }]), lookup);
    expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-not-found" });
    expect(lookup.paths).toEqual(["/api.xro/2.0/Invoices/x"]);
  });

  it("denies invoice-read-failed on another non-2xx, naming only the status", async () => {
    const res = await inspectStoredInvoice(
      invoiceReq([{ InvoiceID: ID, Status: "DRAFT" }]),
      fakeLookup({ status: 500, body: { Message: "ZZ-UPSTREAM-TEXT" } }),
    );
    expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-read-failed" });
    expect(res.message).toContain("500");
    expect(res.message).not.toContain("ZZ-UPSTREAM-TEXT");
  });

  it.each([
    ["an empty Invoices array", { Invoices: [] }],
    ["two invoices", { Invoices: [{ InvoiceID: ID, Status: "DRAFT" }, { InvoiceID: ID2, Status: "DRAFT" }] }],
    ["a missing Status", { Invoices: [{ InvoiceID: ID }] }],
    ["a non-string Status", { Invoices: [{ InvoiceID: ID, Status: 1 }] }],
    ["no Invoices wrapper", { Status: "DRAFT" }],
    ["a non-object item", { Invoices: ["DRAFT"] }],
    ["a text body", "DRAFT"],
  ])("denies invoice-read-unreadable on %s", async (_label, body) => {
    const res = await inspectStoredInvoice(
      invoiceReq([{ InvoiceID: ID, Status: "DRAFT" }]),
      fakeLookup({ status: 200, body }),
    );
    expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-read-unreadable" });
  });

  it("reads at most four existing invoices: five distinct ids are denied before any lookup", async () => {
    const lookup = fakeLookup(storedInvoice("DRAFT"));
    const res = await inspectStoredInvoice(
      invoiceReq([ID, ID2, ID3, ID4, ID5].map((InvoiceID) => ({ InvoiceID, Status: "DRAFT" }))),
      lookup,
    );
    expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-too-many-updates" });
    expect(res.message).toContain("At most 4 invoices carrying InvoiceID or InvoiceNumber");
    expect(lookup.paths).toEqual([]);
  });

  it("reads each of four distinct ids once, in order", async () => {
    const lookup = fakeLookup((path) => storedInvoice("DRAFT", path.split("/").pop()));
    const res = await inspectStoredInvoice(
      invoiceReq([ID, ID2, ID3, ID4].map((InvoiceID) => ({ InvoiceID, Status: "DRAFT" }))),
      lookup,
    );
    expect(res).toEqual({ decision: "allow" });
    expect(lookup.paths).toEqual([ID, ID2, ID3, ID4].map((id) => `/api.xro/2.0/Invoices/${id}`));
  });

  it("reads the same id once (distinct after trim and lower-case), encoding the first spelling", async () => {
    const lookup = fakeLookup(storedInvoice("DRAFT"));
    const res = await inspectStoredInvoice(
      invoiceReq([
        { InvoiceID: ID, Status: "DRAFT" },
        { InvoiceID: ` ${ID.toUpperCase()} `, Status: "DRAFT" },
      ]),
      lookup,
    );
    expect(res).toEqual({ decision: "allow" });
    expect(lookup.paths).toEqual([`/api.xro/2.0/Invoices/${ID}`]);
  });

  it("stops at the first denied read", async () => {
    const lookup = fakeLookup((path) => storedInvoice(path.endsWith(ID) ? "AUTHORISED" : "DRAFT"));
    const res = await inspectStoredInvoice(
      invoiceReq([{ InvoiceID: ID, Status: "DRAFT" }, { InvoiceID: ID2, Status: "DRAFT" }]),
      lookup,
    );
    expect(res).toMatchObject({ decision: "deny", reason: "invoice-not-draft-upstream" });
    expect(lookup.paths).toEqual([`/api.xro/2.0/Invoices/${ID}`]);
  });

  it("denies a stored-draft batch if any one of them is posted", async () => {
    const lookup = fakeLookup((path) => storedInvoice(path.endsWith(ID2) ? "PAID" : "DRAFT"));
    const res = await inspectStoredInvoice(
      invoiceReq([{ InvoiceID: ID, Status: "DRAFT" }, { InvoiceID: ID2, Status: "DRAFT" }]),
      lookup,
    );
    expect(res).toMatchObject({ decision: "deny", reason: "invoice-not-draft-upstream" });
    expect(lookup.paths).toHaveLength(2);
  });

  it("reads the id key case-insensitively and a flat by-id body", async () => {
    const a = fakeLookup(storedInvoice("AUTHORISED"));
    expect(await inspectStoredInvoice({ body: { invoices: [{ invoiceid: ID, Status: "DRAFT" }] } }, a)).toMatchObject({
      decision: "deny",
      reason: "invoice-not-draft-upstream",
    });
    expect(a.paths).toEqual([`/api.xro/2.0/Invoices/${ID}`]);
    const b = fakeLookup(storedInvoice("AUTHORISED"));
    expect(await inspectStoredInvoice({ body: { InvoiceID: ID, Status: "DRAFT" } }, b)).toMatchObject({
      decision: "deny",
      reason: "invoice-not-draft-upstream",
    });
    expect(b.paths).toEqual([`/api.xro/2.0/Invoices/${ID}`]);
  });

  it("on the by-id endpoint reads the PATH id (encoded), even with no id in the body", async () => {
    const lookup = fakeLookup(storedInvoice("AUTHORISED"));
    const res = await inspectStoredInvoice(
      { body: { Status: "DRAFT", Reference: "x" }, pathParams: { InvoiceID: "a/b#c?d" } },
      lookup,
    );
    expect(res).toMatchObject({ decision: "deny", reason: "invoice-not-draft-upstream" });
    expect(lookup.paths).toEqual(["/api.xro/2.0/Invoices/a%2Fb%23c%3Fd"]);
  });

  it("on the by-id endpoint reads only the path id, once", async () => {
    const lookup = fakeLookup(storedInvoice("DRAFT"));
    const res = await inspectStoredInvoice(
      { body: { InvoiceID: ID.toUpperCase(), Status: "DRAFT" }, pathParams: { InvoiceID: ID } },
      lookup,
    );
    expect(res).toEqual({ decision: "allow" });
    expect(lookup.paths).toEqual([`/api.xro/2.0/Invoices/${ID}`]);
  });

  it("fails closed on a body the sync inspector would have refused", async () => {
    const lookup = fakeLookup(storedInvoice("DRAFT"));
    for (const body of [undefined, {}, { Invoices: [] }, { Invoices: {} }, { Invoices: [1] }]) {
      expect(await inspectStoredInvoice({ body }, lookup)).toMatchObject({ decision: "deny", reason: "invoice-no-payload" });
    }
    expect(
      await inspectStoredInvoice({ body: { Invoices: [{ InvoiceID: ID, invoiceID: ID2, Status: "DRAFT" }] } }, lookup),
    ).toMatchObject({ decision: "deny", reason: "invoice-ambiguous-key" });
    expect(lookup.paths).toEqual([]);
  });

  it("lets a lookup failure propagate (the scaffold denies the write)", async () => {
    const lookup: UpstreamLookup = {
      async get() {
        throw new Error("refused");
      },
    };
    await expect(inspectStoredInvoice(invoiceReq([{ InvoiceID: ID, Status: "DRAFT" }]), lookup)).rejects.toThrow();
  });
});

describe("inspectStoredCreditNote (F2-4)", () => {
  const stored = (Status: unknown): UpstreamLookupResult => ({
    status: 200,
    body: { CreditNotes: [{ CreditNoteID: ID, Status }] },
  });

  it("FIXED (F2-4): a stored AUTHORISED credit note is denied after reading it", async () => {
    const lookup = fakeLookup(stored("AUTHORISED"));
    const res = await inspectStoredCreditNote({ body: { CreditNotes: [{ CreditNoteID: ID, Status: "DRAFT" }] } }, lookup);
    expect(res).toMatchObject({ decision: "deny", category: "irreversible", reason: "creditnote-not-draft-upstream" });
    expect(lookup.paths).toEqual([`/api.xro/2.0/CreditNotes/${ID}`]);
  });

  it("allows a stored SUBMITTED credit note", async () => {
    expect(
      await inspectStoredCreditNote({ body: { CreditNotes: [{ CreditNoteID: ID, Status: "DRAFT" }] } }, fakeLookup(stored("SUBMITTED"))),
    ).toEqual({ decision: "allow" });
  });

  it("FIXED (F2-4): a made-up id is denied creditnote-not-found", async () => {
    expect(
      await inspectStoredCreditNote(
        { body: { CreditNotes: [{ CreditNoteID: "x", Status: "DRAFT" }] } },
        fakeLookup({ status: 404, body: null }),
      ),
    ).toMatchObject({ decision: "deny", reason: "creditnote-not-found" });
  });

  it("reads the path id on updateCreditNote", async () => {
    const lookup = fakeLookup(stored("DRAFT"));
    await inspectStoredCreditNote({ body: { Status: "DRAFT" }, pathParams: { CreditNoteID: ID } }, lookup);
    expect(lookup.paths).toEqual([`/api.xro/2.0/CreditNotes/${ID}`]);
  });

  it("denies creditnote-read-unreadable when the answer is an Invoices wrapper", async () => {
    expect(
      await inspectStoredCreditNote(
        { body: { CreditNotes: [{ CreditNoteID: ID, Status: "DRAFT" }] } },
        fakeLookup(storedInvoice("DRAFT")),
      ),
    ).toMatchObject({ decision: "deny", reason: "creditnote-read-unreadable" });
  });
});

describe("inspectStoredRepeatingInvoice (F2-2)", () => {
  const stored = (Status: unknown): UpstreamLookupResult => ({
    status: 200,
    body: { RepeatingInvoices: [{ RepeatingInvoiceID: ID, ID, Status }] },
  });
  const req = (item: Record<string, unknown>): InspectRequest => ({ body: { RepeatingInvoices: [item] } });

  it("FIXED (F2-2): editing a stored AUTHORISED template is denied", async () => {
    const lookup = fakeLookup(stored("AUTHORISED"));
    const res = await inspectStoredRepeatingInvoice(req({ RepeatingInvoiceID: ID, Status: "DRAFT", Reference: "x" }), lookup);
    expect(res).toMatchObject({ decision: "deny", category: "irreversible", reason: "repeating-not-draft-upstream" });
    expect(res.message).toContain("DRAFT");
    expect(res.message).not.toContain("SUBMITTED");
    expect(lookup.paths).toEqual([`/api.xro/2.0/RepeatingInvoices/${ID}`]);
  });

  it("allows only DRAFT: a stored SUBMITTED template is denied", async () => {
    expect(
      await inspectStoredRepeatingInvoice(req({ RepeatingInvoiceID: ID, Status: "DRAFT" }), fakeLookup(stored("SUBMITTED"))),
    ).toMatchObject({ decision: "deny", reason: "repeating-not-draft-upstream" });
  });

  it("allows an edit of a stored DRAFT template", async () => {
    expect(
      await inspectStoredRepeatingInvoice(req({ RepeatingInvoiceID: ID, Status: "DRAFT" }), fakeLookup(stored("DRAFT"))),
    ).toEqual({ decision: "allow" });
  });

  it("FIXED (F2-2): an item keyed by the schema's other id field `ID` is read too", async () => {
    const lookup = fakeLookup(stored("AUTHORISED"));
    const res = await inspectStoredRepeatingInvoice(req({ id: ID, Status: "DRAFT" }), lookup);
    expect(res).toMatchObject({ decision: "deny", reason: "repeating-not-draft-upstream" });
    expect(lookup.paths).toEqual([`/api.xro/2.0/RepeatingInvoices/${ID}`]);
  });

  it("reads one template when RepeatingInvoiceID and ID name the same one", async () => {
    const lookup = fakeLookup(stored("DRAFT"));
    await inspectStoredRepeatingInvoice(req({ RepeatingInvoiceID: ID, ID: ID.toUpperCase(), Status: "DRAFT" }), lookup);
    expect(lookup.paths).toEqual([`/api.xro/2.0/RepeatingInvoices/${ID}`]);
  });

  it("reads the path id on updateRepeatingInvoice", async () => {
    const lookup = fakeLookup(stored("AUTHORISED"));
    const res = await inspectStoredRepeatingInvoice(
      { body: { RepeatingInvoices: [{ Status: "DRAFT", Reference: "x" }] }, pathParams: { RepeatingInvoiceID: ID } },
      lookup,
    );
    expect(res).toMatchObject({ decision: "deny", reason: "repeating-not-draft-upstream" });
    expect(lookup.paths).toEqual([`/api.xro/2.0/RepeatingInvoices/${ID}`]);
  });

  it("creates pay no lookup", async () => {
    const lookup = fakeLookup(stored("AUTHORISED"));
    expect(await inspectStoredRepeatingInvoice(req({ Status: "DRAFT", Type: "ACCREC" }), lookup)).toEqual({
      decision: "allow",
    });
    expect(lookup.paths).toEqual([]);
  });
});

// Xero may key an update on InvoiceNumber / CreditNoteNumber (unverified). An
// item carrying a number and no id is therefore read by number first: a 404 is
// a create; a found document must itself be a draft. Fail closed: the cost is
// one GET per numbered create, and a bill whose supplier reference equals an
// existing posted bill's number cannot be created here (accepted trade-off).
describe("number-keyed items (F2-4)", () => {
  const byNumber = (path: string, status: unknown): UpstreamLookupResult => ({
    status: 200,
    body: { Invoices: [{ InvoiceID: ID, InvoiceNumber: decodeURIComponent(path.split("/").pop()!), Status: status }] },
  });

  it("FIXED (F2-4): the number of an AUTHORISED invoice is denied invoice-number-matches-posted", async () => {
    const lookup = fakeLookup((path) => byNumber(path, "AUTHORISED"));
    const res = await inspectStoredInvoice(
      invoiceReq([{ InvoiceNumber: "INV-0042", Status: "DRAFT", LineItems: [{ UnitAmount: 48500 }] }]),
      lookup,
    );
    expect(res).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-number-matches-posted" });
    expect(res.message).toContain("InvoiceID");
    expect(res.message).not.toContain("INV-0042");
    expect(lookup.paths).toEqual(["/api.xro/2.0/Invoices/INV-0042"]);
  });

  it("an unknown number (404) is a create and is allowed", async () => {
    const lookup = fakeLookup({ status: 404, body: null });
    const res = await inspectStoredInvoice(invoiceReq([{ Type: "ACCPAY", InvoiceNumber: "SUP 7/1#a", Status: "DRAFT" }]), lookup);
    expect(res).toEqual({ decision: "allow" });
    expect(lookup.paths).toEqual(["/api.xro/2.0/Invoices/SUP%207%2F1%23a"]);
  });

  it.each(["DRAFT", "submitted"])("allows a number that matches a stored %s invoice", async (status) => {
    expect(
      await inspectStoredInvoice(invoiceReq([{ InvoiceNumber: "INV-1", Status: "DRAFT" }]), fakeLookup((p) => byNumber(p, status))),
    ).toEqual({ decision: "allow" });
  });

  it.each([
    ["two matches", { Invoices: [{ Status: "DRAFT" }, { Status: "DRAFT" }] }],
    ["an empty list", { Invoices: [] }],
    ["no Status", { Invoices: [{ InvoiceID: ID }] }],
    ["a text body", "nope"],
  ])("denies invoice-number-matches-posted on %s", async (_label, body) => {
    expect(
      await inspectStoredInvoice(invoiceReq([{ InvoiceNumber: "INV-1", Status: "DRAFT" }]), fakeLookup({ status: 200, body })),
    ).toMatchObject({ decision: "deny", reason: "invoice-number-matches-posted" });
  });

  it("denies invoice-read-failed on another non-2xx", async () => {
    expect(
      await inspectStoredInvoice(invoiceReq([{ InvoiceNumber: "INV-1", Status: "DRAFT" }]), fakeLookup({ status: 503, body: null })),
    ).toMatchObject({ decision: "deny", reason: "invoice-read-failed" });
  });

  it("an item with an id is read by id only, never by its number", async () => {
    const lookup = fakeLookup(storedInvoice("DRAFT"));
    await inspectStoredInvoice(invoiceReq([{ InvoiceID: ID, InvoiceNumber: "INV-1", Status: "DRAFT" }]), lookup);
    expect(lookup.paths).toEqual([`/api.xro/2.0/Invoices/${ID}`]);
  });

  it("the by-id endpoint reads only the path id", async () => {
    const lookup = fakeLookup(storedInvoice("DRAFT"));
    await inspectStoredInvoice({ body: { InvoiceNumber: "INV-1", Status: "DRAFT" }, pathParams: { InvoiceID: ID } }, lookup);
    expect(lookup.paths).toEqual([`/api.xro/2.0/Invoices/${ID}`]);
  });

  it("FIXED (F2-4 review): the by-id endpoint denies more than one item before any read", async () => {
    const lookup = fakeLookup(storedInvoice("DRAFT"));
    const res = await inspectStoredInvoice(
      { body: { Invoices: [{ InvoiceID: ID, Status: "DRAFT" }, { InvoiceNumber: "INV-POSTED", Status: "DRAFT" }] }, pathParams: { InvoiceID: ID } },
      lookup,
    );
    expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-by-id-multiple-items" });
    expect(lookup.paths).toEqual([]);
    const rep = fakeLookup({ status: 200, body: { RepeatingInvoices: [{ Status: "DRAFT" }] } });
    expect(
      await inspectStoredRepeatingInvoice(
        { body: { RepeatingInvoices: [{ Status: "DRAFT" }, { Status: "DRAFT" }] }, pathParams: { RepeatingInvoiceID: ID } },
        rep,
      ),
    ).toMatchObject({ decision: "deny", reason: "repeating-by-id-multiple-items" });
    expect(rep.paths).toEqual([]);
  });

  it("FIXED (F2-4 review): a key beside the wrapper is denied with no read, on the bulk and by-id endpoints", async () => {
    const lookup = fakeLookup(storedInvoice("DRAFT"));
    const body = { Invoices: [{ Status: "DRAFT" }], InvoiceID: ID, Status: "AUTHORISED" };
    expect(await inspectStoredInvoice({ body }, lookup)).toMatchObject({ decision: "deny", reason: "invoice-unexpected-key" });
    expect(await inspectStoredInvoice({ body, pathParams: { InvoiceID: ID } }, lookup)).toMatchObject({
      decision: "deny",
      reason: "invoice-unexpected-key",
    });
    expect(lookup.paths).toEqual([]);
  });

  it("FIXED (F2-4 review): a number with surrounding whitespace is denied before the by-number read", async () => {
    const lookup = fakeLookup({ status: 404, body: null });
    for (const InvoiceNumber of ["INV-1 ", " INV-1"]) {
      expect(await inspectStoredInvoice(invoiceReq([{ InvoiceNumber, Status: "DRAFT" }]), lookup)).toMatchObject({
        decision: "deny",
        reason: "invoice-bad-number",
      });
    }
    expect(
      await inspectStoredCreditNote({ body: { CreditNotes: [{ CreditNoteNumber: "CN-1 ", Status: "DRAFT" }] } }, lookup),
    ).toMatchObject({ decision: "deny", reason: "creditnote-bad-number" });
    expect(lookup.paths).toEqual([]);
  });

  it("numbers and ids share the four-read cap: more than four distinct targets are denied before any read", async () => {
    const lookup = fakeLookup({ status: 404, body: null });
    const res = await inspectStoredInvoice(
      invoiceReq([
        { InvoiceID: ID, Status: "DRAFT" },
        { InvoiceID: ID2, Status: "DRAFT" },
        { InvoiceNumber: "INV-1", Status: "DRAFT" },
        { InvoiceNumber: "INV-2", Status: "DRAFT" },
        { InvoiceNumber: "INV-3", Status: "DRAFT" },
      ]),
      lookup,
    );
    expect(res).toMatchObject({ decision: "deny", reason: "invoice-too-many-updates" });
    expect(lookup.paths).toEqual([]);
  });

  it("reads a repeated number once (exact spelling), a differently-cased one again", async () => {
    const lookup = fakeLookup({ status: 404, body: null });
    await inspectStoredInvoice(
      invoiceReq([
        { InvoiceNumber: "INV-1", Status: "DRAFT" },
        { InvoiceNumber: "INV-1", Status: "DRAFT" },
        { invoicenumber: "inv-1", Status: "DRAFT" },
      ]),
      lookup,
    );
    expect(lookup.paths).toEqual(["/api.xro/2.0/Invoices/INV-1", "/api.xro/2.0/Invoices/inv-1"]);
  });

  it("fails closed on two spellings of the number or a non-string number", async () => {
    const lookup = fakeLookup({ status: 404, body: null });
    expect(
      await inspectStoredInvoice(invoiceReq([{ InvoiceNumber: "A", invoicenumber: "B", Status: "DRAFT" }]), lookup),
    ).toMatchObject({ decision: "deny", reason: "invoice-ambiguous-key" });
    expect(await inspectStoredInvoice(invoiceReq([{ InvoiceNumber: 42, Status: "DRAFT" }]), lookup)).toMatchObject({
      decision: "deny",
      reason: "invoice-bad-number",
    });
    expect(lookup.paths).toEqual([]);
  });

  it("empty or null numbers are not looked up", async () => {
    const lookup = fakeLookup({ status: 404, body: null });
    expect(
      await inspectStoredInvoice(invoiceReq([{ InvoiceNumber: "", Status: "DRAFT" }, { InvoiceNumber: null, Status: "DRAFT" }]), lookup),
    ).toEqual({ decision: "allow" });
    expect(lookup.paths).toEqual([]);
  });

  it("FIXED (F2-4): a credit note number matching an AUTHORISED credit note is denied", async () => {
    const lookup = fakeLookup({ status: 200, body: { CreditNotes: [{ CreditNoteID: ID, Status: "AUTHORISED" }] } });
    const res = await inspectStoredCreditNote({ body: { CreditNotes: [{ CreditNoteNumber: "CN-9", Status: "DRAFT" }] } }, lookup);
    expect(res).toMatchObject({ decision: "deny", reason: "creditnote-number-matches-posted" });
    expect(lookup.paths).toEqual(["/api.xro/2.0/CreditNotes/CN-9"]);
  });

  it("repeating templates have no number key: an InvoiceNumber there is not looked up", async () => {
    const lookup = fakeLookup({ status: 404, body: null });
    expect(
      await inspectStoredRepeatingInvoice({ body: { RepeatingInvoices: [{ InvoiceNumber: "X", Status: "DRAFT" }] } }, lookup),
    ).toEqual({ decision: "allow" });
    expect(lookup.paths).toEqual([]);
  });
});
