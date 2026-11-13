// packages/providers/xero/src/inspectors/drafts.ts
//
// Status-gating inspector shared by invoices and credit notes. Both resources
// have the identical mutation surface (bulk PUT/POST with an array wrapper, a
// singular by-ID POST with a flat body) and the same Status lifecycle, so the
// policy is factored once and parameterised per resource.
//
// Policy (per item, most-restrictive across a batch):
//   - Status ∈ {DRAFT, SUBMITTED} → allow.
//   - Status omitted (or null) → deny `<prefix>-status-required`, with or
//     without an id (security review F2-4). Omitting Status used to mean
//     "update preserving the current status" on the belief that Xero refuses
//     edits to posted records; that belief let a status-less update of an
//     authorised invoice through. Whether the STORED document is a draft is
//     checked host-side by the stored-status hook (./stored-status.ts).
//   - any other value (AUTHORISED, PAID, VOIDED, DELETED) → deny.
//   - SentToContact set → deny regardless of Status (triggers an email send).
//   - By-id endpoint (`pathParams[idField]` set): a body id must equal the
//     path id (trimmed, case-insensitive), so the hook's read of the path id
//     is a read of what is written (`<prefix>-id-mismatch`).
//   - A present id that is not a string → deny `<prefix>-bad-id` (the hook
//     could not read the document it names).
//   - The inline `Contact` may not carry sensitive contact fields
//     (./contact-fields.ts; F2-1) → deny `<prefix>-inline-contact-details`.
//   - By-id endpoint: exactly one item (`<prefix>-by-id-multiple-items`); the
//     hook reads only the path id. Any key beside the bulk wrapper →
//     `<prefix>-unexpected-key`. A Status that is not a string →
//     `<prefix>-bad-status`. An InvoiceNumber / CreditNoteNumber that is not a
//     string or has surrounding whitespace → `<prefix>-bad-number` (the hook
//     reads id-less numbered items by that exact number).
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
import { inlineContactDeny, inlineContactProblem } from "./contact-fields.js";
import { ambiguousKeyDeny, getCaseInsensitive, isRecord, isTruthyFlag } from "./keys.js";

export type ItemsRead =
  | { ok: true; items: Record<string, unknown>[] }
  | { ok: false; reason: "no-payload" | "ambiguous-wrapper" | "unexpected-key" };

/** Bulk `{ [wrapper]: [...] }` (wrapper matched case-insensitively) or one flat object; `{}`,
 *  an empty/non-array wrapper and a non-object item are `no-payload`; any other key beside the
 *  wrapper is `unexpected-key` (the spec puts only response fields there, and whether Xero
 *  reads flat fields next to a wrapper is unverified, so fail closed). A flat object carrying
 *  the wrapper's singular (`Contact`, `Invoice`, `CreditNote`, `RepeatingInvoice`, any casing)
 *  is `unexpected-key` too: that was the XML-era root element, and whether Xero still unwraps
 *  it is unverified. None of the four schemas has a property of that name (an invoice's inline
 *  `Contact` is not the singular of `Invoices`). */
export function readItems(body: unknown, wrapper: string): ItemsRead {
  if (!isRecord(body)) return { ok: false, reason: "no-payload" };
  // Bulk endpoints send { [wrapper]: [...] }; the singular by-ID endpoint sends
  // a flat object. The wrapper is matched under any casing (Xero reads
  // "invoices" as "Invoices"); once it is present the body is bulk, and a
  // non-array wrapper is no payload rather than a flat item that the
  // inspector and Xero would read differently.
  const w = getCaseInsensitive(body, wrapper);
  if (w.ambiguous) return { ok: false, reason: "ambiguous-wrapper" };
  if (w.present && Object.keys(body).length > 1) return { ok: false, reason: "unexpected-key" };
  let items: unknown[];
  if (w.present) {
    if (!Array.isArray(w.value)) return { ok: false, reason: "no-payload" };
    items = w.value;
  } else if (Object.keys(body).length === 0) {
    return { ok: false, reason: "no-payload" };
  } else {
    const singular = wrapper.replace(/s$/, "");
    if (singular !== wrapper && getCaseInsensitive(body, singular).present) return { ok: false, reason: "unexpected-key" };
    items = [body];
  }
  if (items.length === 0 || !items.every(isRecord)) return { ok: false, reason: "no-payload" };
  return { ok: true, items };
}

/** A document number Xero might key an update on (`InvoiceNumber`, `CreditNoteNumber`): absent,
 *  null or a string with no surrounding whitespace is fine; anything else fails closed (the
 *  by-number stored read uses the exact value, while Xero may trim it when matching). */
export function badNumber(value: unknown): boolean {
  if (value === undefined || value === null) return false;
  return typeof value !== "string" || value.trim() !== value;
}

/** Trimmed, lower-cased id for comparisons (Xero ids are GUIDs). */
export function normId(id: string): string {
  return id.trim().toLowerCase();
}

interface DraftResourceConfig {
  /** Request-body wrapper key for the bulk endpoints, e.g. "Invoices". */
  arrayKey: string;
  /** Primary-key field (body and by-id path parameter), e.g. "InvoiceID". */
  idField: string;
  /** Number field Xero may also key an update on, e.g. "InvoiceNumber". */
  numberField: string;
  /** Singular noun for caller-facing messages, e.g. "invoice". */
  label: string;
  /** Indefinite article for `label` ("an invoice", "a credit note"). */
  article: "a" | "an";
  /** Prefix for the terse audit `reason` codes, e.g. "invoice". */
  reasonPrefix: string;
}

function makeDraftStatusInspector(cfg: DraftResourceConfig) {
  const REASON_NO_PAYLOAD = `${cfg.reasonPrefix}-no-payload`;
  const REASON_NOT_DRAFT = `${cfg.reasonPrefix}-not-draft`;
  const REASON_STATUS_REQUIRED = `${cfg.reasonPrefix}-status-required`;
  const REASON_SENT = `${cfg.reasonPrefix}-sent-to-contact`;
  const REASON_AMBIGUOUS = `${cfg.reasonPrefix}-ambiguous-key`;
  const aLabel = `${cfg.article} ${cfg.label}`;
  const REASON_ID_MISMATCH = `${cfg.reasonPrefix}-id-mismatch`;
  const REASON_BAD_ID = `${cfg.reasonPrefix}-bad-id`;
  const REASON_INLINE_CONTACT = `${cfg.reasonPrefix}-inline-contact-details`;
  const REASON_MULTIPLE = `${cfg.reasonPrefix}-by-id-multiple-items`;
  const REASON_UNEXPECTED_KEY = `${cfg.reasonPrefix}-unexpected-key`;
  const REASON_BAD_NUMBER = `${cfg.reasonPrefix}-bad-number`;
  const REASON_BAD_STATUS = `${cfg.reasonPrefix}-bad-status`;

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

  const denyStatusRequired: InspectResult = {
    decision: "deny",
    category: "irreversible",
    reason: REASON_STATUS_REQUIRED,
    message:
      `Refusing to create or modify ${aLabel} without an explicit Status: set it to "DRAFT" or ` +
      `"SUBMITTED". Omitting Status no longer means "keep the current status"; the stored ${cfg.label} ` +
      `is checked before sending, and one that is authorised, paid, voided or deleted is refused.`,
  };

  const denyIdMismatch: InspectResult = {
    decision: "deny",
    category: "malformed",
    reason: REASON_ID_MISMATCH,
    message:
      `The body's ${cfg.idField} must match the ${cfg.label} in the path; send the by-id update with ` +
      `the same id (or omit it from the body).`,
  };

  const denyBadId: InspectResult = {
    decision: "deny",
    category: "malformed",
    reason: REASON_BAD_ID,
    message: `${cfg.idField} must be a string (the ${cfg.label}'s Xero id) when present.`,
  };

  const denyMultiple: InspectResult = {
    decision: "deny",
    category: "malformed",
    reason: REASON_MULTIPLE,
    message:
      `The by-id update modifies one ${cfg.label} (the one in the path); send exactly one item, or use the ` +
      `bulk endpoint for several.`,
  };

  const denyUnexpectedKey: InspectResult = {
    decision: "deny",
    category: "malformed",
    reason: REASON_UNEXPECTED_KEY,
    message:
      `Refusing ${aLabel} payload with other keys beside "${cfg.arrayKey}": put every field inside ` +
      `the ${cfg.label} items.`,
  };

  const denyBadNumber: InspectResult = {
    decision: "deny",
    category: "malformed",
    reason: REASON_BAD_NUMBER,
    message: `${cfg.numberField} must be a string with no leading or trailing spaces when present.`,
  };

  const denyBadStatus: InspectResult = {
    decision: "deny",
    category: "malformed",
    reason: REASON_BAD_STATUS,
    message: `Status must be a string ("DRAFT" or "SUBMITTED").`,
  };

  const denySent: InspectResult = {
    decision: "deny",
    category: "external_data_flow",
    reason: REASON_SENT,
    message:
      `Refusing to set SentToContact=true on ${aLabel}: that makes Xero email the ` +
      `${cfg.label} to the contact (an external send). Create or modify it without ` +
      `SentToContact, then send it deliberately.`,
  };

  const denyAmbiguous = (key: string): InspectResult => ambiguousKeyDeny(REASON_AMBIGUOUS, aLabel, key);

  return function inspect(req: InspectRequest): InspectResult {
    const read = readItems(req.body, cfg.arrayKey);
    if (!read.ok) {
      if (read.reason === "ambiguous-wrapper") return denyAmbiguous(cfg.arrayKey);
      return read.reason === "unexpected-key" ? denyUnexpectedKey : noPayload;
    }
    const pathId = req.pathParams?.[cfg.idField];
    const tiedTo = typeof pathId === "string" && pathId.length > 0 ? normId(pathId) : undefined;
    // The stored-status hook reads only the path id on the by-id endpoint, so
    // a second item there (e.g. one keyed by number) would go unread.
    if (tiedTo !== undefined && read.items.length > 1) return denyMultiple;
    for (const item of read.items) {
      const statusKey = getCaseInsensitive(item, "Status");
      const idKey = getCaseInsensitive(item, cfg.idField);
      const sentKey = getCaseInsensitive(item, "SentToContact");
      const numberKey = getCaseInsensitive(item, cfg.numberField);
      if (statusKey.ambiguous) return denyAmbiguous("Status");
      if (idKey.ambiguous) return denyAmbiguous(cfg.idField);
      if (sentKey.ambiguous) return denyAmbiguous("SentToContact");
      if (numberKey.ambiguous) return denyAmbiguous(cfg.numberField);
      // A null Status is treated like an absent one: both are refused.
      if (statusKey.value !== undefined && statusKey.value !== null && typeof statusKey.value !== "string") {
        return denyBadStatus;
      }
      const status = (statusKey.value ?? "").toUpperCase();
      if (status === "") return denyStatusRequired;
      if (status !== "DRAFT" && status !== "SUBMITTED") return denyNotDraft(status);
      if (isTruthyFlag(sentKey.value)) return denySent;
      if (badNumber(numberKey.value)) return denyBadNumber;
      const id = idKey.value;
      if (id !== undefined && id !== null && typeof id !== "string") return denyBadId;
      if (tiedTo !== undefined && typeof id === "string" && id.length > 0 && normId(id) !== tiedTo) {
        return denyIdMismatch;
      }
      const contactFields = inlineContactProblem(item);
      if (contactFields !== null) return inlineContactDeny(REASON_INLINE_CONTACT, cfg.label, contactFields);
    }
    return { decision: "allow" };
  };
}

export const inspectInvoiceDraft = makeDraftStatusInspector({
  arrayKey: "Invoices",
  idField: "InvoiceID",
  numberField: "InvoiceNumber",
  label: "invoice",
  article: "an",
  reasonPrefix: "invoice",
});

export const inspectCreditNoteDraft = makeDraftStatusInspector({
  arrayKey: "CreditNotes",
  idField: "CreditNoteID",
  numberField: "CreditNoteNumber",
  label: "credit note",
  article: "a",
  reasonPrefix: "creditnote",
});
