// Provider-wide surface-review invariants (identity match against merged spec,
// Tier-3 reasoning presence, inspectors-on-body-methods). Implementation lives
// in @local/scaffold/testing so all providers share the same battery.

import { describe, it, expect } from "vitest";
import { providerSurfaceReviewTests } from "@local/scaffold/testing";
import { xeroProvider } from "../index";
import { surfaceReview } from "../surface-review";
import { inspectInvoiceDraft } from "../inspectors/drafts";

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
});
