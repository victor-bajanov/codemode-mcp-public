// packages/providers/xero/src/inspectors/drafts.ts
import type { InspectRequest, InspectResult } from "@local/shared";

export function inspectInvoiceDraft(req: InspectRequest): InspectResult {
  const body = req.body;
  if (!body || typeof body !== "object") {
    return { decision: "deny", category: "malformed", reason: "invoice-no-payload" };
  }
  const bodyObj = body as Record<string, unknown>;
  // Bulk endpoints (createInvoices, updateOrCreateInvoices) send { Invoices: [...] };
  // singular by-ID endpoint (updateInvoice) sends a flat invoice object.
  // An empty body {} (no Invoices key, no invoice fields) is treated as no-payload.
  let invoices: unknown[];
  if (Array.isArray(bodyObj["Invoices"])) {
    invoices = bodyObj["Invoices"] as unknown[];
  } else if (Object.keys(bodyObj).length === 0) {
    return { decision: "deny", category: "malformed", reason: "invoice-no-payload" };
  } else {
    invoices = [body];
  }
  if (invoices.length === 0) {
    return { decision: "deny", category: "malformed", reason: "invoice-no-payload" };
  }
  for (const inv of invoices) {
    if (!inv || typeof inv !== "object") {
      return { decision: "deny", category: "malformed", reason: "invoice-no-payload" };
    }
    const status = String((inv as Record<string, unknown>)["Status"] ?? "").toUpperCase();
    if (status !== "DRAFT" && status !== "SUBMITTED") {
      return { decision: "deny", category: "irreversible", reason: "invoice-not-draft" };
    }
    if ((inv as Record<string, unknown>)["SentToContact"] === true) {
      return { decision: "deny", category: "external_data_flow", reason: "invoice-sent-to-contact" };
    }
  }
  return { decision: "allow" };
}
