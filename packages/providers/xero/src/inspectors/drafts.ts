// packages/providers/xero/src/inspectors/drafts.ts
//
// Status-gating inspector shared by invoices and credit notes. Both resources
// have the identical mutation surface (bulk PUT/POST with an array wrapper, a
// singular by-ID POST with a flat body) and the same Status lifecycle, so the
// policy is factored once and parameterised per resource.
//
// Policy (per item, most-restrictive across a batch):
//   - Status ∈ {DRAFT, SUBMITTED} → allow.
//   - Status omitted + <id> present → allow (update preserving existing state;
//     Xero keeps current Status on upsert when omitted). Unblocks edits to line
//     items on a draft without re-stating Status. If the id points at a posted
//     record, Xero itself rejects the mutation server-side.
//   - Status omitted + no <id> → deny (this is a create; force the caller to be
//     explicit so AUTHORISED-by-default surprises can't sneak through).
//   - any other value (AUTHORISED, PAID, VOIDED, DELETED) → deny.
//   - SentToContact set → deny regardless of Status (triggers an email send).
//
// Key case and lenient booleans (security review F-10): Xero's .NET JSON
// deserialiser matches property names case-insensitively and coerces "true"
// to a boolean, so every gated key (the bulk wrapper, Status, the id field,
// SentToContact) is read case-insensitively via ./keys, a body carrying two
// spellings of one gated key is denied as ambiguous, and SentToContact counts
// as set unless it is absent, null or false (so "true", 1 and even "false"
// are denied). A body that carries the wrapper under any casing is bulk.
//
// Denials carry a human-readable `message` so the caller sees *why* the request
// was blocked instead of the opaque "denied by surface review"; `reason` stays a
// terse, greppable code for audit logs.
import type { InspectRequest, InspectResult } from "@local/shared";
import { getCaseInsensitive, isTruthyFlag } from "./keys.js";

interface DraftResourceConfig {
  /** Request-body wrapper key for the bulk endpoints, e.g. "Invoices". */
  arrayKey: string;
  /** Primary-key field used to detect a state-preserving update, e.g. "InvoiceID". */
  idField: string;
  /** Singular noun for caller-facing messages, e.g. "invoice". */
  label: string;
  /** Prefix for the terse audit `reason` codes, e.g. "invoice". */
  reasonPrefix: string;
}

function makeDraftStatusInspector(cfg: DraftResourceConfig) {
  const REASON_NO_PAYLOAD = `${cfg.reasonPrefix}-no-payload`;
  const REASON_NOT_DRAFT = `${cfg.reasonPrefix}-not-draft`;
  const REASON_SENT = `${cfg.reasonPrefix}-sent-to-contact`;
  const REASON_AMBIGUOUS = `${cfg.reasonPrefix}-ambiguous-key`;

  const noPayload: InspectResult = {
    decision: "deny",
    category: "malformed",
    reason: REASON_NO_PAYLOAD,
    message:
      `No ${cfg.label} payload found. Send a non-empty "${cfg.arrayKey}" array ` +
      `(bulk) or a single ${cfg.label} object (by-id update).`,
  };

  function denyNotDraft(statusShown: string): InspectResult {
    return {
      decision: "deny",
      category: "irreversible",
      reason: REASON_NOT_DRAFT,
      message:
        `Only DRAFT or SUBMITTED ${cfg.label}s can be created or modified through this API; ` +
        `this ${cfg.label} has Status "${statusShown}". Authorised, paid, voided and deleted ` +
        `${cfg.label}s are immutable here (the change is irreversible), so the request was denied.`,
    };
  }

  const denyCreateNeedsStatus: InspectResult = {
    decision: "deny",
    category: "irreversible",
    reason: REASON_NOT_DRAFT,
    message:
      `Refusing to create a ${cfg.label} without an explicit Status: only DRAFT or SUBMITTED ` +
      `are allowed, and omitting Status would post it as AUTHORISED (irreversible). ` +
      `Set Status to "DRAFT" or "SUBMITTED", or include "${cfg.idField}" to update an existing draft.`,
  };

  const denySent: InspectResult = {
    decision: "deny",
    category: "external_data_flow",
    reason: REASON_SENT,
    message:
      `Refusing to set SentToContact=true on a ${cfg.label}: that makes Xero email the ` +
      `${cfg.label} to the contact (an external send). Create or modify it without ` +
      `SentToContact, then send it deliberately.`,
  };

  function denyAmbiguous(key: string): InspectResult {
    return {
      decision: "deny",
      category: "malformed",
      reason: REASON_AMBIGUOUS,
      message:
        `Refusing a ${cfg.label} payload that spells "${key}" more than one way (keys differing ` +
        `only by letter case, or a non-ASCII lookalike). Xero matches property names ` +
        `case-insensitively, so which value it would apply is unclear. Send "${key}" exactly once.`,
    };
  }

  return function inspect(req: InspectRequest): InspectResult {
    const body = req.body;
    if (!body || typeof body !== "object") {
      return noPayload;
    }
    const bodyObj = body as Record<string, unknown>;
    // Bulk endpoints send { [arrayKey]: [...] }; the singular by-ID endpoint sends
    // a flat object. An empty body {} is treated as no-payload. The wrapper is
    // matched under any casing (Xero reads "invoices" as "Invoices"); once it is
    // present the body is bulk, and a non-array wrapper is no payload rather than
    // a flat item that the inspector and Xero would read differently.
    const wrapper = getCaseInsensitive(bodyObj, cfg.arrayKey);
    if (wrapper.ambiguous) {
      return denyAmbiguous(cfg.arrayKey);
    }
    let items: unknown[];
    if (wrapper.present) {
      if (!Array.isArray(wrapper.value)) {
        return noPayload;
      }
      items = wrapper.value;
    } else if (Object.keys(bodyObj).length === 0) {
      return noPayload;
    } else {
      items = [body];
    }
    if (items.length === 0) {
      return noPayload;
    }
    for (const item of items) {
      if (!item || typeof item !== "object") {
        return noPayload;
      }
      const itemObj = item as Record<string, unknown>;
      const statusKey = getCaseInsensitive(itemObj, "Status");
      const idKey = getCaseInsensitive(itemObj, cfg.idField);
      const sentKey = getCaseInsensitive(itemObj, "SentToContact");
      if (statusKey.ambiguous) return denyAmbiguous("Status");
      if (idKey.ambiguous) return denyAmbiguous(cfg.idField);
      if (sentKey.ambiguous) return denyAmbiguous("SentToContact");
      // A null Status is treated like an absent one (Xero ignores it on update).
      const status = String(statusKey.value ?? "").toUpperCase();
      const id = idKey.value;
      const hasId = typeof id === "string" && id.length > 0;
      if (status === "") {
        if (!hasId) {
          return denyCreateNeedsStatus;
        }
      } else if (status !== "DRAFT" && status !== "SUBMITTED") {
        return denyNotDraft(status);
      }
      if (isTruthyFlag(sentKey.value)) {
        return denySent;
      }
    }
    return { decision: "allow" };
  };
}

export const inspectInvoiceDraft = makeDraftStatusInspector({
  arrayKey: "Invoices",
  idField: "InvoiceID",
  label: "invoice",
  reasonPrefix: "invoice",
});

export const inspectCreditNoteDraft = makeDraftStatusInspector({
  arrayKey: "CreditNotes",
  idField: "CreditNoteID",
  label: "credit note",
  reasonPrefix: "creditnote",
});
