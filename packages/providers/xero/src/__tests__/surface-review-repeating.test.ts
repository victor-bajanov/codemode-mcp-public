// packages/providers/xero/src/__tests__/surface-review-repeating.test.ts
//
// F2-2 (High): repeating-invoice templates skipped every invoice gate.
//
// Attacker: a prompt-injected model in the sandbox. Precondition: none (the
// three template writes, createRepeatingInvoices / updateOrCreateRepeatingInvoices
// / updateRepeatingInvoice, were bare allows). Payload: a template with
// `Status: "AUTHORISED"`, `ApprovedForSending: true`, `IncludePDF: true`,
// `MarkAsSent: true` and an inline `Contact` carrying an attacker's
// `EmailAddress`, so Xero posts and emails an invoice every period; or an
// edit/delete of an existing authorised template. Control:
// `inspectRepeatingInvoiceDraft` admits only explicit DRAFT templates with no
// send flags and no sensitive inline contact details (and the stored-status
// hook, stored-status.test.ts, reads an existing template first). Why the
// pre-fix code failed it: no inspector was wired, so every body was sent.

import { describe, it, expect } from "vitest";
import { inspectRepeatingInvoiceDraft } from "../inspectors/repeating-invoices";

const ID = "8576f4cf-e24d-4e3a-83ff-c6f30418a7de";
const OTHER = "0f3d1c2e-4b5a-4c6d-8e7f-9a0b1c2d3e4f";

const ATTACK = {
  Type: "ACCREC",
  Status: "AUTHORISED",
  ApprovedForSending: true,
  IncludePDF: true,
  MarkAsSent: true,
  Contact: { Name: "Mallory Consulting", EmailAddress: "drop@attacker.example" },
  Schedule: { Period: 1, Unit: "MONTHLY", DueDate: 20, DueDateType: "OFFOLLOWINGMONTH", StartDate: "2026-12-01" },
  LineItems: [{ Description: "EXFIL", Quantity: 1, UnitAmount: 1, AccountCode: "200" }],
};

const one = (item: Record<string, unknown>) => ({ body: { RepeatingInvoices: [item] } });

describe("inspectRepeatingInvoiceDraft (F2-2)", () => {
  it("FIXED (F2-2): the auto-sending AUTHORISED template is denied repeating-not-draft", () => {
    const res = inspectRepeatingInvoiceDraft(one(ATTACK));
    expect(res).toMatchObject({ decision: "deny", category: "irreversible", reason: "repeating-not-draft" });
    expect(res.message).toContain('"AUTHORISED"');
  });

  it("FIXED (F2-2): as DRAFT it is denied for the send flags, naming the key", () => {
    const res = inspectRepeatingInvoiceDraft(one({ ...ATTACK, Status: "DRAFT" }));
    expect(res).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "repeating-send-flag" });
    expect(res.message).toContain("ApprovedForSending");
  });

  it.each(["ApprovedForSending", "SendCopy", "MarkAsSent", "IncludePDF"])("denies %s: true on a DRAFT", (key) => {
    const res = inspectRepeatingInvoiceDraft(one({ Status: "DRAFT", [key]: true }));
    expect(res).toMatchObject({ decision: "deny", reason: "repeating-send-flag" });
    expect(res.message).toContain(key);
  });

  it("FIXED (F2-1/F2-2): with the flags removed the inline contact EmailAddress is denied", () => {
    const { ApprovedForSending: _a, IncludePDF: _i, MarkAsSent: _m, ...noFlags } = ATTACK;
    const res = inspectRepeatingInvoiceDraft(one({ ...noFlags, Status: "DRAFT" }));
    expect(res).toMatchObject({ decision: "deny", category: "financial_legal", reason: "repeating-inline-contact-details" });
    expect(res.message).toContain("EmailAddress");
  });

  it("accepts the draft shape: DRAFT, Contact by ContactID, no send flags", () => {
    const { ApprovedForSending: _a, IncludePDF: _i, MarkAsSent: _m, Contact: _c, ...rest } = ATTACK;
    expect(inspectRepeatingInvoiceDraft(one({ ...rest, Status: "DRAFT", Contact: { ContactID: ID } }))).toEqual({
      decision: "allow",
    });
  });

  it("FIXED (F2-2): an ACCPAY recurring bill carrying payee bank details", () => {
    const bill = { Type: "ACCPAY", Contact: { Name: "Acme Supplies", BankAccountDetails: "062-000 13371337" } };
    expect(inspectRepeatingInvoiceDraft(one({ ...bill, Status: "AUTHORISED" }))).toMatchObject({
      decision: "deny",
      reason: "repeating-not-draft",
    });
    expect(inspectRepeatingInvoiceDraft(one({ ...bill, Status: "DRAFT" }))).toMatchObject({
      decision: "deny",
      reason: "repeating-inline-contact-details",
    });
  });

  it("FIXED (F2-2): a by-id DELETED is denied repeating-not-draft", () => {
    expect(
      inspectRepeatingInvoiceDraft({ body: { RepeatingInvoices: [{ Status: "DELETED" }] }, pathParams: { RepeatingInvoiceID: ID } }),
    ).toMatchObject({ decision: "deny", reason: "repeating-not-draft" });
  });

  it("FIXED (F2-2): an omitted or null Status is denied repeating-status-required", () => {
    for (const item of [{ RepeatingInvoiceID: ID, Reference: "x" }, { Status: null }]) {
      expect(inspectRepeatingInvoiceDraft(one(item))).toMatchObject({
        decision: "deny",
        category: "irreversible",
        reason: "repeating-status-required",
      });
    }
  });

  it("denies SUBMITTED (not a template status) as not draft", () => {
    expect(inspectRepeatingInvoiceDraft(one({ Status: "SUBMITTED" }))).toMatchObject({ reason: "repeating-not-draft" });
  });

  // === lenient parsing (Xero reads keys case-insensitively, coerces booleans) ===

  it("reads status: \"draft\" as DRAFT and a flat body as one item", () => {
    expect(inspectRepeatingInvoiceDraft(one({ status: "draft" }))).toEqual({ decision: "allow" });
    expect(inspectRepeatingInvoiceDraft({ body: { Status: "DRAFT", Reference: "x" } })).toEqual({ decision: "allow" });
    expect(inspectRepeatingInvoiceDraft({ body: { repeatinginvoices: [{ Status: "AUTHORISED" }] } })).toMatchObject({
      reason: "repeating-not-draft",
    });
  });

  it.each([
    ["approvedforsending: \"true\"", { approvedforsending: "true" }],
    ["SendCopy: 1", { SendCopy: 1 }],
    ["includePdf: \"false\"", { includePdf: "false" }],
  ])("denies %s (lenient boolean, fail closed)", (_label, flags) => {
    expect(inspectRepeatingInvoiceDraft(one({ Status: "DRAFT", ...flags }))).toMatchObject({ reason: "repeating-send-flag" });
  });

  it.each([["false", false], ["null", null]])("allows a send flag set to %s", (_label, value) => {
    expect(
      inspectRepeatingInvoiceDraft(one({ Status: "DRAFT", ApprovedForSending: value, SendCopy: value, MarkAsSent: value, IncludePDF: value })),
    ).toEqual({ decision: "allow" });
  });

  it.each([
    ["Status", { Status: "DRAFT", status: "AUTHORISED" }],
    ["ApprovedForSending", { Status: "DRAFT", ApprovedForSending: false, approvedForSending: true }],
    ["RepeatingInvoiceID", { Status: "DRAFT", RepeatingInvoiceID: ID, repeatinginvoiceid: OTHER }],
    ["ID", { Status: "DRAFT", ID, id: OTHER }],
  ])("denies two spellings of %s as ambiguous, naming the key", (key, item) => {
    const res = inspectRepeatingInvoiceDraft(one(item));
    expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "repeating-ambiguous-key" });
    expect(res.message).toContain(`"${key}"`);
  });

  it("denies two spellings of the wrapper as ambiguous", () => {
    expect(
      inspectRepeatingInvoiceDraft({ body: { RepeatingInvoices: [{ Status: "DRAFT" }], repeatingInvoices: [{ Status: "DRAFT" }] } }),
    ).toMatchObject({ reason: "repeating-ambiguous-key" });
  });

  it.each([
    ["{}", {}],
    ["no body", undefined],
    ["an empty wrapper", { RepeatingInvoices: [] }],
    ["a non-array wrapper", { RepeatingInvoices: {} }],
    ["a non-object item", { RepeatingInvoices: ["DRAFT"] }],
  ])("denies %s as repeating-no-payload", (_label, body) => {
    expect(inspectRepeatingInvoiceDraft({ body })).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "repeating-no-payload",
    });
  });

  it("is most-restrictive across a batch", () => {
    expect(
      inspectRepeatingInvoiceDraft({ body: { RepeatingInvoices: [{ Status: "DRAFT" }, { Status: "AUTHORISED" }] } }),
    ).toMatchObject({ reason: "repeating-not-draft" });
  });

  // === ids ===

  it("denies RepeatingInvoiceID and ID naming different templates", () => {
    expect(inspectRepeatingInvoiceDraft(one({ Status: "DRAFT", RepeatingInvoiceID: ID, ID: OTHER }))).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "repeating-id-mismatch",
    });
    expect(inspectRepeatingInvoiceDraft(one({ Status: "DRAFT", RepeatingInvoiceID: ID, ID: ` ${ID.toUpperCase()} ` }))).toEqual({
      decision: "allow",
    });
  });

  it("ties the body id (RepeatingInvoiceID, else ID) to the path id on the by-id endpoint", () => {
    const by = (item: Record<string, unknown>) =>
      inspectRepeatingInvoiceDraft({ body: { RepeatingInvoices: [item] }, pathParams: { RepeatingInvoiceID: ID } });
    expect(by({ Status: "DRAFT", RepeatingInvoiceID: OTHER })).toMatchObject({ reason: "repeating-id-mismatch" });
    expect(by({ Status: "DRAFT", ID: OTHER })).toMatchObject({ reason: "repeating-id-mismatch" });
    expect(by({ Status: "DRAFT", RepeatingInvoiceID: ID.toUpperCase() })).toEqual({ decision: "allow" });
    expect(by({ Status: "DRAFT" })).toEqual({ decision: "allow" });
  });

  it("FIXED (F2-2 review): denies more than one item on the by-id endpoint", () => {
    expect(
      inspectRepeatingInvoiceDraft({
        body: { RepeatingInvoices: [{ Status: "DRAFT", RepeatingInvoiceID: ID }, { Status: "DRAFT" }] },
        pathParams: { RepeatingInvoiceID: ID },
      }),
    ).toMatchObject({ decision: "deny", category: "malformed", reason: "repeating-by-id-multiple-items" });
  });

  it("FIXED (F2-2 review): denies a key beside the RepeatingInvoices wrapper", () => {
    expect(
      inspectRepeatingInvoiceDraft({ body: { RepeatingInvoices: [{ Status: "DRAFT" }], Status: "AUTHORISED" } }),
    ).toMatchObject({ decision: "deny", category: "malformed", reason: "repeating-unexpected-key" });
  });

  it("FIXED (F2-2 review): denies a Status that is not a string", () => {
    for (const Status of [["DRAFT"], { s: "DRAFT" }, 0]) {
      expect(inspectRepeatingInvoiceDraft(one({ Status }))).toMatchObject({
        decision: "deny",
        category: "malformed",
        reason: "repeating-bad-status",
      });
    }
  });

  it("denies a present id that is not a string", () => {
    expect(inspectRepeatingInvoiceDraft(one({ Status: "DRAFT", RepeatingInvoiceID: 5 }))).toMatchObject({
      reason: "repeating-bad-id",
    });
    expect(inspectRepeatingInvoiceDraft(one({ Status: "DRAFT", ID: {} }))).toMatchObject({ reason: "repeating-bad-id" });
  });
});

describe("a flat body keyed by the singular root is refused (wave 3 review)", () => {
  it("FIXED: `{ RepeatingInvoice: { … } }` is denied repeating-unexpected-key", () => {
    for (const key of ["RepeatingInvoice", "repeatinginvoice"]) {
      expect(inspectRepeatingInvoiceDraft({ body: { [key]: { RepeatingInvoiceID: ID, Status: "DRAFT" } } }), key)
        .toMatchObject({ decision: "deny", reason: "repeating-unexpected-key" });
    }
  });
});
