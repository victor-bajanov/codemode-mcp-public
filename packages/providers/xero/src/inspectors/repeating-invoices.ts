// packages/providers/xero/src/inspectors/repeating-invoices.ts
//
// Draft-only inspector for repeating-invoice templates (security review F2-2):
// createRepeatingInvoices (PUT), updateOrCreateRepeatingInvoices (POST) and
// updateRepeatingInvoice (POST by id). A template is the twin of an invoice
// that Xero acts on every period: AUTHORISED makes Xero post an invoice each
// period (and email it when approved for sending), DELETED removes it. So:
//
//   - Status is required and must be DRAFT (case-insensitive) → else deny.
//   - ApprovedForSending, SendCopy, MarkAsSent, IncludePDF set (anything but
//     absent/null/false, ./keys isTruthyFlag) → deny: they make Xero email
//     the generated invoices.
//   - id: RepeatingInvoiceID, else ID (the schema has both); both present and
//     naming different templates → deny; a present non-string id → deny; on
//     the by-id endpoint the body id must equal the path id.
//   - the inline Contact may not carry sensitive contact fields (F2-1).
//   - a Status that is not a string, any key beside the wrapper, or more
//     than one item on the by-id endpoint → deny.
//
// Every case is a deny: no approval dialog can make an auto-sending template
// safe. The stored template is read before an update by the stored-status
// hook (./stored-status.ts, `inspectStoredRepeatingInvoice`). Keys are read
// case-insensitively as Xero does; two spellings of a gated key are denied.

import type { InspectRequest, InspectResult } from "@local/shared";
import { inlineContactDeny, inlineContactProblem } from "./contact-fields.js";
import { normId, readItems } from "./drafts.js";
import { ambiguousKeyDeny, getCaseInsensitive, isTruthyFlag } from "./keys.js";

const SEND_FLAGS = ["ApprovedForSending", "SendCopy", "MarkAsSent", "IncludePDF"] as const;

const noPayload: InspectResult = {
  decision: "deny",
  category: "malformed",
  reason: "repeating-no-payload",
  message:
    'No repeating invoice payload found. Send a non-empty "RepeatingInvoices" array (bulk) or a single ' +
    "repeating invoice object (by-id update).",
};

const statusRequired: InspectResult = {
  decision: "deny",
  category: "irreversible",
  reason: "repeating-status-required",
  message:
    'Refusing to create or modify a repeating invoice template without an explicit Status: set it to "DRAFT". ' +
    "The stored template is checked before sending, and one that is not a draft is refused.",
};

const multipleItems: InspectResult = {
  decision: "deny",
  category: "malformed",
  reason: "repeating-by-id-multiple-items",
  message:
    "The by-id update modifies one repeating invoice template (the one in the path); send exactly one item, or use " +
    "the bulk endpoint for several.",
};

const unexpectedKey: InspectResult = {
  decision: "deny",
  category: "malformed",
  reason: "repeating-unexpected-key",
  message:
    'Refusing a repeating invoice payload with other keys beside "RepeatingInvoices": put every field inside the ' +
    "template items.",
};

const badStatus: InspectResult = {
  decision: "deny",
  category: "malformed",
  reason: "repeating-bad-status",
  message: 'Status must be the string "DRAFT".',
};

const idMismatch: InspectResult = {
  decision: "deny",
  category: "malformed",
  reason: "repeating-id-mismatch",
  message:
    "The body's RepeatingInvoiceID (or ID) must name one template, and on the by-id endpoint it must match the " +
    "repeating invoice in the path; send the same id (or omit it from the body).",
};

const badId: InspectResult = {
  decision: "deny",
  category: "malformed",
  reason: "repeating-bad-id",
  message: "RepeatingInvoiceID and ID must be strings (the template's Xero id) when present.",
};

function notDraft(statusShown: string): InspectResult {
  return {
    decision: "deny",
    category: "irreversible",
    reason: "repeating-not-draft",
    message:
      "Only DRAFT repeating-invoice templates can be created or modified through this API; this one has Status " +
      `"${statusShown}". AUTHORISED makes Xero post (and, when approved for sending, email) an invoice every ` +
      "period, and DELETED removes the template.",
  };
}

function sendFlag(key: string): InspectResult {
  return {
    decision: "deny",
    category: "external_data_flow",
    reason: "repeating-send-flag",
    message: `Refusing a repeating invoice template with ${key} set: it makes Xero email the generated invoices; omit it.`,
  };
}

const ambiguous = (key: string): InspectResult =>
  ambiguousKeyDeny("repeating-ambiguous-key", "a repeating invoice", key);

export function inspectRepeatingInvoiceDraft(req: InspectRequest): InspectResult {
  const read = readItems(req.body, "RepeatingInvoices");
  if (!read.ok) {
    if (read.reason === "ambiguous-wrapper") return ambiguous("RepeatingInvoices");
    return read.reason === "unexpected-key" ? unexpectedKey : noPayload;
  }
  const pathId = req.pathParams?.["RepeatingInvoiceID"];
  const tiedTo = typeof pathId === "string" && pathId.length > 0 ? normId(pathId) : undefined;
  // The stored-status hook reads only the path id on the by-id endpoint.
  if (tiedTo !== undefined && read.items.length > 1) return multipleItems;
  for (const item of read.items) {
    const status = getCaseInsensitive(item, "Status");
    if (status.ambiguous) return ambiguous("Status");
    const flags = SEND_FLAGS.map((key) => ({ key, r: getCaseInsensitive(item, key) }));
    for (const { key, r } of flags) if (r.ambiguous) return ambiguous(key);
    const ids: string[] = [];
    for (const key of ["RepeatingInvoiceID", "ID"]) {
      const r = getCaseInsensitive(item, key);
      if (r.ambiguous) return ambiguous(key);
      if (r.value === undefined || r.value === null) continue;
      if (typeof r.value !== "string") return badId;
      if (r.value.length > 0) ids.push(normId(r.value));
    }

    if (status.value !== undefined && status.value !== null && typeof status.value !== "string") return badStatus;
    const value = status.value ?? "";
    if (value === "") return statusRequired;
    if (value.toUpperCase() !== "DRAFT") return notDraft(value.toUpperCase());
    for (const { key, r } of flags) if (isTruthyFlag(r.value)) return sendFlag(key);
    if (ids.length === 2 && ids[0] !== ids[1]) return idMismatch;
    if (tiedTo !== undefined && ids.some((id) => id !== tiedTo)) return idMismatch;
    const contactFields = inlineContactProblem(item);
    if (contactFields !== null) return inlineContactDeny("repeating-inline-contact-details", "repeating invoice", contactFields);
  }
  return { decision: "allow" };
}
