// Provider-wide surface-review invariants (identity match against merged spec,
// Tier-3 reasoning presence, inspectors-on-body-methods). Implementation lives
// in @local/scaffold/testing so all providers share the same battery.

import { describe, it, expect } from "vitest";
import { providerSurfaceReviewTests } from "@local/scaffold/testing";
import { xeroProvider } from "../index";
import { surfaceReview } from "../surface-review";
import { inspectInvoiceDraft, inspectCreditNoteDraft } from "../inspectors/drafts";
import { inspectStoredInvoice, inspectStoredCreditNote, inspectStoredRepeatingInvoice } from "../inspectors/stored-status";
import { inspectRepeatingInvoiceDraft } from "../inspectors/repeating-invoices";
import { inspectContactWrite, inspectStoredContact } from "../inspectors/contacts";
import { inspectAttachmentUpload } from "../inspectors/attachments";
import { contactChange } from "../elicit-renderers";

providerSurfaceReviewTests(xeroProvider);

// Provider-specific extras retained from the original test file:
describe("xero-specific surface-review entries", () => {
  it("explicitly-listed Tier-2/Tier-3 entries are present", () => {
    const explicit = [
      // Tier 2
      "xero.accounting.emailInvoice",
      "xero.accounting.createBatchPayment",
      "xero.payroll.au.createEmployee",
      "xero.payroll.au.updateEmployee",
      "xero.payroll.au.createPayRun",
      "xero.payroll.au.updatePayRun",
      // Tier 3
      "xero.accounting.deleteTrackingCategory",
      "xero.accounting.updateTaxRate",
      "xero.accounting.deleteAccount",
      "xero.accounting.createPaymentService",
      "xero.accounting.createBrandingThemePaymentServices",
    ];
    for (const id of explicit) {
      expect(surfaceReview[id], `expected ${id} in surface review`).toBeDefined();
    }
  });

  it("updateInvoice is wired to the draft inspector", () => {
    const entry = surfaceReview["xero.accounting.updateInvoice"];
    expect(entry).toBeDefined();
    expect(entry?.decision).toBe("allow");
    expect(entry?.inspect).toBe(inspectInvoiceDraft);
  });

  it("credit-note create/update endpoints are wired to the credit-note draft inspector", () => {
    for (const id of [
      "xero.accounting.createCreditNotes",
      "xero.accounting.updateOrCreateCreditNotes",
      "xero.accounting.updateCreditNote",
    ]) {
      const entry = surfaceReview[id];
      expect(entry, `expected ${id} in surface review`).toBeDefined();
      expect(entry?.decision).toBe("allow");
      expect(entry?.inspect, `${id} should use inspectCreditNoteDraft`).toBe(inspectCreditNoteDraft);
    }
  });

  // F2-5 (wave 3): the attachment uploads were bare standard_write allows with
  // the inspector wired nowhere; IncludeOnline then published any file on the
  // customer's online invoice. Now all four run the inspector, and accept a
  // composed staged body (the provider hint tells the model to upload that way).
  it("FIXED (F2-5): invoice and credit-note attachment uploads (the PUTs) run the attachment inspector and accept staged bodies", () => {
    for (const id of [
      "xero.accounting.createInvoiceAttachmentByFileName",
      "xero.accounting.createCreditNoteAttachmentByFileName",
    ]) {
      const entry = surfaceReview[id];
      expect(entry, `expected ${id} in surface review`).toBeDefined();
      expect(entry?.decision, id).toBe("allow");
      expect(entry?.inspect, `${id} should use inspectAttachmentUpload`).toBe(inspectAttachmentUpload);
      expect(entry?.acceptsStaged, id).toBe(true);
      expect(entry?.clientNote?.trim(), id).toBeTruthy();
    }
  });

  it("the Files API upload stays a bare allow (out of scope, not customer-facing)", () => {
    for (const id of ["xero.files.uploadFile", "xero.files.createFolder"]) {
      const entry = surfaceReview[id];
      expect(entry?.decision, id).toBe("allow");
      expect(entry?.inspect, id).toBeUndefined();
    }
  });

  // F2-4 (wave 3): an update with no Status was allowed on the belief that Xero
  // refuses edits to posted documents. The stored document is now read first.
  it("FIXED (F2-4): invoice and credit-note writes read the stored document before sending", () => {
    for (const id of [
      "xero.accounting.createInvoices",
      "xero.accounting.updateOrCreateInvoices",
      "xero.accounting.updateInvoice",
    ]) {
      expect(surfaceReview[id]?.inspect, id).toBe(inspectInvoiceDraft);
      expect(surfaceReview[id]?.inspectUpstream, id).toBe(inspectStoredInvoice);
    }
    for (const id of [
      "xero.accounting.createCreditNotes",
      "xero.accounting.updateOrCreateCreditNotes",
      "xero.accounting.updateCreditNote",
    ]) {
      expect(surfaceReview[id]?.inspect, id).toBe(inspectCreditNoteDraft);
      expect(surfaceReview[id]?.inspectUpstream, id).toBe(inspectStoredCreditNote);
    }
  });

  // F2-2 (wave 3): the three repeating-invoice writes were bare allows, so an
  // AUTHORISED, approved-for-sending template skipped every invoice gate.
  it("FIXED (F2-2): repeating-invoice writes run the draft-only inspector and the stored-template read", () => {
    for (const id of [
      "xero.accounting.createRepeatingInvoices",
      "xero.accounting.updateOrCreateRepeatingInvoices",
      "xero.accounting.updateRepeatingInvoice",
    ]) {
      const entry = surfaceReview[id];
      expect(entry?.decision, id).toBe("allow");
      expect(entry?.inspect, id).toBe(inspectRepeatingInvoiceDraft);
      expect(entry?.inspectUpstream, id).toBe(inspectStoredRepeatingInvoice);
      expect(entry?.clientNote?.trim(), id).toBeTruthy();
    }
  });

  // F2-1 (wave 3): the two contact writes were bare allows, so one POST with a
  // ContactID repointed a supplier's bank account with a plain allow audit line.
  it("FIXED (F2-1): contact writes run the contact inspector, the stored-contact read and the change dialog", () => {
    for (const id of ["xero.accounting.createContacts", "xero.accounting.updateOrCreateContacts"]) {
      const entry = surfaceReview[id];
      expect(entry?.decision, id).toBe("allow");
      expect(entry?.category, id).toBeUndefined();
      expect(entry?.inspect, id).toBe(inspectContactWrite);
      expect(entry?.inspectUpstream, id).toBe(inspectStoredContact);
      expect(entry?.elicit, id).toBe(contactChange);
      expect(entry?.clientNote?.trim(), id).toBeTruthy();
    }
  });

  it("the other contact, history, allocation and attachment-update write routes stay out of the surface review (denied)", () => {
    for (const id of [
      "xero.accounting.updateContact",
      "xero.accounting.createContactGroupContacts",
      "xero.accounting.deleteContactGroupContact",
      "xero.accounting.deleteContactGroupContacts",
      "xero.accounting.createContactGroup",
      "xero.accounting.updateContactGroup",
      "xero.accounting.createContactHistory",
      "xero.accounting.createContactAttachmentByFileName",
      "xero.accounting.updateContactAttachmentByFileName",
      // Other write routes beside the wave-3 surface that are correctly absent:
      "xero.accounting.createInvoiceHistory",
      "xero.accounting.createCreditNoteHistory",
      "xero.accounting.createRepeatingInvoiceHistory",
      "xero.accounting.createRepeatingInvoiceAttachmentByFileName",
      "xero.accounting.updateRepeatingInvoiceAttachmentByFileName",
      "xero.accounting.createCreditNoteAllocation",
      // Wave-3 review: a bytes update (POST) can overwrite an attachment already
      // published online, and IncludeOnline cannot be checked or reset there.
      "xero.accounting.updateInvoiceAttachmentByFileName",
      "xero.accounting.updateCreditNoteAttachmentByFileName",
    ]) {
      expect(surfaceReview[id], id).toBeUndefined();
    }
  });
});
