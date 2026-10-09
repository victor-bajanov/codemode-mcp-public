// Security-review POC C6 — Xero draft-status and bank-transaction inspectors
// read `Status`, `SentToContact`, `Type` and `IsReconciled` by EXACT key name,
// while Xero's JSON deserialiser (ASP.NET / Newtonsoft on the Xero side) is
// documented as case-insensitive for property names and coerces "true" to a
// boolean. A payload that spells the gated property in a different case, or
// supplies a boolean as a string, is therefore judged as if the property were
// absent/false, while Xero applies it.
//
// Status: FIXED (F-10) — gated keys (wrappers, Status, ids, SentToContact,
// Type, IsReconciled) are now read case-insensitively via inspectors/keys.ts,
// two spellings of one gated key are denied as `<prefix>-ambiguous-key`, and a
// gated boolean counts as set unless it is absent, null or false. The attack
// payloads below are kept as regression inputs and now assert `deny`; the
// former "lower-case `type` is denied" control now asserts that `type` is read
// case-insensitively (SPEND allowed, TRANSFER denied).
import { describe, it, expect } from "vitest";
import { inspectInvoiceDraft, inspectCreditNoteDraft } from "../../inspectors/drafts";
import { inspectBankTxCreate } from "../../inspectors/bank-transactions";

describe("C6a invoice/credit-note draft inspector", () => {
  it("baseline: Status AUTHORISED on an update is denied", () => {
    const r = inspectInvoiceDraft({ body: { Invoices: [{ InvoiceID: "abc", Status: "AUTHORISED" }] } });
    expect(r.decision).toBe("deny");
  });
  it("FIXED (F-10): lower-case `status` key is read as Status → AUTHORISED denied", () => {
    const r = inspectInvoiceDraft({ body: { Invoices: [{ InvoiceID: "abc", status: "AUTHORISED" }] } });
    expect(r).toMatchObject({ decision: "deny", reason: "invoice-not-draft" });
  });
  it("baseline: SentToContact true is denied", () => {
    const r = inspectInvoiceDraft({ body: { Invoices: [{ InvoiceID: "abc", Status: "DRAFT", SentToContact: true }] } });
    expect(r.decision).toBe("deny");
  });
  it("FIXED (F-10): SentToContact as the string \"true\" is denied", () => {
    const r = inspectInvoiceDraft({ body: { Invoices: [{ InvoiceID: "abc", Status: "DRAFT", SentToContact: "true" }] } });
    expect(r).toMatchObject({ decision: "deny", reason: "invoice-sent-to-contact" });
  });
  it("FIXED (F-10): sentToContact (lower-case key) is denied", () => {
    const r = inspectCreditNoteDraft({ body: { CreditNotes: [{ CreditNoteID: "abc", Status: "DRAFT", sentToContact: true }] } });
    expect(r).toMatchObject({ decision: "deny", reason: "creditnote-sent-to-contact" });
  });
});

describe("C6b bank-transaction inspector", () => {
  it("baseline: Status VOIDED is denied", () => {
    const r = inspectBankTxCreate({ body: { BankTransactions: [{ Type: "SPEND", Status: "VOIDED" }] } });
    expect(r.decision).toBe("deny");
  });
  it("FIXED (F-10): lower-case `status` VOIDED is denied", () => {
    const r = inspectBankTxCreate({ body: { BankTransactions: [{ Type: "SPEND", status: "VOIDED" }] } });
    expect(r).toMatchObject({ decision: "deny", reason: "banktx-disallowed-status" });
  });
  it("FIXED (F-10): IsReconciled as the string \"true\" is denied", () => {
    const r = inspectBankTxCreate({ body: { BankTransactions: [{ Type: "SPEND", IsReconciled: "true" }] } });
    expect(r).toMatchObject({ decision: "deny", reason: "banktx-reconciled" });
  });
  it("control: lower-case `type` is read case-insensitively (SPEND allowed, TRANSFER denied)", () => {
    expect(inspectBankTxCreate({ body: { BankTransactions: [{ type: "SPEND" }] } }).decision).toBe("allow");
    const r = inspectBankTxCreate({ body: { BankTransactions: [{ type: "TRANSFER" }] } });
    expect(r).toMatchObject({ decision: "deny", reason: "banktx-disallowed-type" });
  });
});
