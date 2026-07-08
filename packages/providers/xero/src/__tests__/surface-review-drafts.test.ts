// packages/providers/xero/src/__tests__/surface-review-drafts.test.ts
//
// Inspector for createInvoices / updateOrCreateInvoices.
// Both ACCREC (invoices to clients) and ACCPAY (bills from suppliers) come through the
// same endpoint; the body's `Type` field distinguishes them and is not what we gate on.
//
// Policy:
//   - Status ∈ {DRAFT, SUBMITTED} → allow.
//   - Status omitted + InvoiceID present → allow (update preserving existing state).
//   - Status omitted + no InvoiceID → deny (would be a create with no explicit state).
//   - any other Status (AUTHORISED, PAID, VOIDED, DELETED) → deny.
//   - SentToContact === true → deny regardless of Status.

import { describe, it, expect } from "vitest";
import { inspectInvoiceDraft } from "../inspectors/drafts";

describe("inspectInvoiceDraft", () => {
  it("allows a DRAFT ACCREC invoice", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCREC", Status: "DRAFT", Contact: { Name: "Acme" } }] },
    })).toEqual({ decision: "allow" });
  });

  it("allows a SUBMITTED ACCPAY bill", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCPAY", Status: "SUBMITTED", Contact: { Name: "Supplier" } }] },
    })).toEqual({ decision: "allow" });
  });

  it("allows a DRAFT ACCPAY bill", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCPAY", Status: "DRAFT", Contact: { Name: "Supplier" } }] },
    })).toEqual({ decision: "allow" });
  });

  it("denies an AUTHORISED invoice (irreversible — issued to ledger)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCREC", Status: "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  it("denies a PAID invoice", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCREC", Status: "PAID" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  it("denies SentToContact:true (mail-out trigger; off-channel exfil)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCREC", Status: "DRAFT", SentToContact: true }] },
    })).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "invoice-sent-to-contact" });
  });

  it("denies when Status is missing", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCREC" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  it("denies when Invoices array is empty", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [] },
    })).toMatchObject({ decision: "deny", category: "malformed", reason: "invoice-no-payload" });
  });

  it("denies when Invoices key is missing", () => {
    expect(inspectInvoiceDraft({ body: {} })).toMatchObject({
      decision: "deny", category: "malformed", reason: "invoice-no-payload",
    });
  });

  it("denies when ANY invoice in a batch is non-draft (most-restrictive across the batch)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Status: "DRAFT" }, { Status: "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", reason: "invoice-not-draft" });
  });

  it("treats Status case-insensitively (Xero may return mixed case)", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Status: "draft" }] },
    })).toEqual({ decision: "allow" });
  });

  // === Status-omitted updates: InvoiceID signals "preserve existing state" ===

  it("allows a bulk update with InvoiceID and no Status (preserve existing state)", () => {
    expect(inspectInvoiceDraft({
      body: {
        Invoices: [{
          InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de",
          LineAmountTypes: "Exclusive",
          LineItems: [{ Description: "edit", Quantity: 1, UnitAmount: 28.23, AccountCode: "490" }],
        }],
      },
    })).toEqual({ decision: "allow" });
  });

  it("allows an ACCPAY bulk update with InvoiceID and no Status", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ Type: "ACCPAY", InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de" }] },
    })).toEqual({ decision: "allow" });
  });

  it("still denies a bulk update when InvoiceID is present but Status is AUTHORISED", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de", Status: "AUTHORISED" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  it("still denies SentToContact:true even on a Status-omitted update", () => {
    expect(inspectInvoiceDraft({
      body: {
        Invoices: [{
          InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de",
          SentToContact: true,
        }],
      },
    })).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "invoice-sent-to-contact" });
  });

  it("denies a bulk update with empty-string InvoiceID and no Status", () => {
    expect(inspectInvoiceDraft({
      body: { Invoices: [{ InvoiceID: "" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  it("denies a batch where one item has InvoiceID+no-Status and another has no InvoiceID and no Status", () => {
    expect(inspectInvoiceDraft({
      body: {
        Invoices: [
          { InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de" },
          { Type: "ACCREC" },
        ],
      },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  // === Singular by-ID update (POST /Invoices/{ID}) — flat body, no Invoices wrapper ===

  it("allows a DRAFT singular flat-body invoice", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC", Status: "DRAFT", Contact: { Name: "Acme" } },
    })).toEqual({ decision: "allow" });
  });

  it("allows a SUBMITTED singular flat-body invoice", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC", Status: "SUBMITTED" },
    })).toEqual({ decision: "allow" });
  });

  it("denies an AUTHORISED singular flat-body invoice", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC", Status: "AUTHORISED" },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  it("denies a singular flat-body invoice with SentToContact:true", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC", Status: "DRAFT", SentToContact: true },
    })).toMatchObject({ decision: "deny", category: "external_data_flow", reason: "invoice-sent-to-contact" });
  });

  it("denies a singular flat-body invoice with no Status and no InvoiceID", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC" },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });

  it("allows a singular flat-body update with InvoiceID and no Status", () => {
    expect(inspectInvoiceDraft({
      body: {
        Type: "ACCREC",
        InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de",
        LineItems: [{ Description: "edit", Quantity: 1, UnitAmount: 10, AccountCode: "490" }],
      },
    })).toEqual({ decision: "allow" });
  });

  it("still denies a singular flat-body update when InvoiceID is present but Status is AUTHORISED", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC", InvoiceID: "8576f4cf-e24d-4e3a-83ff-c6f30418a7de", Status: "AUTHORISED" },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });
});
