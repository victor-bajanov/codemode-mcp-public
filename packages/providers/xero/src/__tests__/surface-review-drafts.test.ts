// packages/providers/xero/src/__tests__/surface-review-drafts.test.ts
//
// Inspector for createInvoices / updateOrCreateInvoices.
// Both ACCREC (invoices to clients) and ACCPAY (bills from suppliers) come through the
// same endpoint; the body's `Type` field distinguishes them and is not what we gate on.
//
// Policy: only allow Status ∈ {DRAFT, SUBMITTED} and SentToContact !== true.

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

  it("denies a singular flat-body invoice with no Status", () => {
    expect(inspectInvoiceDraft({
      body: { Type: "ACCREC" },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "invoice-not-draft" });
  });
});
