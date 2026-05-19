import type { SurfaceReview } from "@local/shared";
import { inspectInvoiceDraft } from "./inspectors/drafts.js";
import { inspectBankTxCreate } from "./inspectors/bank-transactions.js";

import specJson from "./spec.json" with { type: "json" };

interface SpecLike {
  paths: Record<string, Record<string, { operationId?: string }>>;
}

// HTTP method keys we recognise on a path-item; everything else (e.g. "parameters") is skipped.
const HTTP_METHODS = new Set(["get", "put", "post", "delete", "options", "head", "patch", "trace"]);

function buildReadAllows(): Record<string, { decision: "allow"; category: "standard_read" }> {
  const out: Record<string, { decision: "allow"; category: "standard_read" }> = {};
  for (const [, methods] of Object.entries((specJson as SpecLike).paths)) {
    const get = methods["get"];
    if (get && typeof get.operationId === "string") {
      const id = get.operationId;
      if (id.startsWith("xero.accounting.") || id.startsWith("xero.files.") || id.startsWith("xero.payroll.au.")) {
        out[id] = { decision: "allow", category: "standard_read" };
      }
    }
  }
  return out;
}

const TIER_1_ALLOW_INSPECT_OR_BARE: SurfaceReview = {
  "xero.accounting.createInvoices":              { decision: "allow", inspect: inspectInvoiceDraft },
  "xero.accounting.updateOrCreateInvoices":      { decision: "allow", inspect: inspectInvoiceDraft },
  // updateInvoice (singular, by ID) shares the inspector. Xero has no separate
  // delete/void operation — voiding/deleting flows through this endpoint by
  // setting Status to VOIDED/DELETED, which the inspector denies (only allows
  // Status ∈ {DRAFT, SUBMITTED}).
  "xero.accounting.updateInvoice":               { decision: "allow", inspect: inspectInvoiceDraft },
  "xero.accounting.createContacts":              { decision: "allow", category: "standard_write" },
  "xero.accounting.updateOrCreateContacts":      { decision: "allow", category: "standard_write" },
  "xero.accounting.createRepeatingInvoices":         { decision: "allow", category: "standard_write" },
  "xero.accounting.updateRepeatingInvoice":          { decision: "allow", category: "standard_write" },
  "xero.accounting.updateOrCreateRepeatingInvoices": { decision: "allow", category: "standard_write" },
  "xero.accounting.createBankTransactions":      { decision: "allow", inspect: inspectBankTxCreate },
  "xero.accounting.updateBankTransaction":       { decision: "allow", inspect: inspectBankTxCreate },
  // Attachment uploads are bare allows: the inspector relied on contentType/rawBody,
  // which the request-handler does not currently surface to inspectors (only body+query
  // are passed). Re-wire the inspector once the handler forwards request bytes.
  "xero.accounting.createInvoiceAttachmentByFileName":      { decision: "allow", category: "standard_write" },
  "xero.accounting.updateInvoiceAttachmentByFileName":      { decision: "allow", category: "standard_write" },
  "xero.files.uploadFile":                       { decision: "allow", category: "standard_write" },
  "xero.files.createFolder":                     { decision: "allow", category: "standard_write" },
};

// Tier-2 (elicit): short-circuits to deny in slice 2 (live elicitation lands in slice 3).
// Listed explicitly so audit logs say `decision=elicit elicitationOutcome=unsupported reason=<op>`
// rather than the vaguer "operation not in surface review".
//
// NB: The plan's original list referenced operationIds that don't exist in the actual Xero spec —
// `deleteInvoice`/`voidInvoice`/`deleteContact`/`deleteBankTransaction`/`createEmployees` (plural).
// Xero handles those mutations through Update operations on the same resources. Removed from
// this list. Substituted: createBatchPayment (singular, real id) and createEmployee (singular).
const TIER_2_ELICIT: SurfaceReview = {
  "xero.accounting.emailInvoice":                { decision: "elicit", category: "external_data_flow" },
  "xero.accounting.createBatchPayment":          { decision: "elicit", category: "financial_legal" },
  "xero.payroll.au.createEmployee":              { decision: "elicit", category: "persistent_state" },
  "xero.payroll.au.updateEmployee":              { decision: "elicit", category: "persistent_state" },
  "xero.payroll.au.createPayRun":                { decision: "elicit", category: "financial_legal" },
  "xero.payroll.au.updatePayRun":                { decision: "elicit", category: "financial_legal" },
};

// Tier-3 (deny): capability-escalation; never elicit-able.
// Reduced from plan: createUsers/deleteUsers/archiveTrackingCategory/deleteTaxRate/updateOrganisation/
// deletePayrollCalendar/updatePaymentService/deletePaymentService/updateSettings — all DOM-checked,
// none exist as operationIds in the merged Xero spec. createPaymentService moved from payroll.au
// to accounting (where it actually lives).
const TIER_3_DENY: SurfaceReview = {
  "xero.accounting.deleteTrackingCategory":      { decision: "deny", category: "irreversible",
                                                     reasoning: "Tracking-category deletion cascades through historic transactions; manual undo only." },
  "xero.accounting.updateTaxRate":               { decision: "deny", category: "irreversible",
                                                     reasoning: "Tax-rate updates trigger Xero-side recalculation of historic transactions." },
  "xero.accounting.deleteAccount":               { decision: "deny", category: "irreversible",
                                                     reasoning: "Chart-of-accounts deletion cascades; manual undo only." },
  "xero.accounting.createPaymentService":        { decision: "deny", category: "capability_escalation",
                                                     reasoning: "Payment services configure outbound bank rails; not elicit-recoverable." },
  "xero.accounting.createBrandingThemePaymentServices": { decision: "deny", category: "capability_escalation",
                                                     reasoning: "Linking a payment service to a branding theme exposes outbound bank rails on customer-facing invoices; not elicit-recoverable." },
};

export const surfaceReview: SurfaceReview = Object.freeze({
  ...buildReadAllows(),
  ...TIER_1_ALLOW_INSPECT_OR_BARE,
  ...TIER_2_ELICIT,
  ...TIER_3_DENY,
});
