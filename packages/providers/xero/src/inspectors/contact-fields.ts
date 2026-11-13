// packages/providers/xero/src/inspectors/contact-fields.ts
//
// The contact properties that change where money or documents go, or whether
// the contact exists (security review F2-1), and the readers shared by the
// contacts inspector (inspectors/contacts.ts) and the document inspectors that
// see an inline `Contact` object (invoices, credit notes, repeating invoices).
//
// Keys are read the way Xero reads them: case-insensitively (./keys). A key
// spelt two ways, or only as a non-ASCII lookalike, is reported as ambiguous
// and the caller denies.

import type { InspectResult } from "@local/shared";
import { fold, getCaseInsensitive, isRecord } from "./keys.js";

/** Contact properties that change where money or documents go, or whether the
 *  contact exists. An edit carrying one needs approval (F2-1); an inline
 *  `Contact` on a document may not carry one. */
export const SENSITIVE_CONTACT_FIELDS = [
  "BankAccountDetails",
  "BatchPayments",
  "EmailAddress",
  "ContactStatus",
  "TaxNumber",
  "ContactPersons",
] as const;

export type SensitiveContactField = (typeof SENSITIVE_CONTACT_FIELDS)[number];

/** Contact properties whose CHANGE on an existing contact needs approval too
 *  (F2-1, user decision): a rename or a new Xero Network key makes a stored
 *  payee look like someone else. Edit-only: creates and inline `Contact`
 *  objects on documents are not judged on them (that is why they are not in
 *  `SENSITIVE_CONTACT_FIELDS`). "Change" means the body value differs from the
 *  stored one, so only the stored-contact read can decide. */
export const EDIT_GATED_CONTACT_FIELDS = ["Name", "XeroNetworkKey"] as const;

export type EditGatedContactField = (typeof EDIT_GATED_CONTACT_FIELDS)[number];

/** Which sensitive fields `obj` carries (case-insensitive), and which are
 *  ambiguous (two spellings / lookalike). A present key with value `null`
 *  counts as carried (it clears the field). Both lists are canonical names in
 *  `SENSITIVE_CONTACT_FIELDS` order. */
export function sensitiveContactKeys(obj: Record<string, unknown>): {
  present: string[];
  ambiguous: string[];
} {
  const present: string[] = [];
  const ambiguous: string[] = [];
  for (const field of SENSITIVE_CONTACT_FIELDS) {
    const r = getCaseInsensitive(obj, field);
    if (r.ambiguous) ambiguous.push(field);
    else if (r.present) present.push(field);
  }
  return { present, ambiguous };
}

/** `null` when `item.Contact` (case-insensitive) is absent, not an object, or
 *  carries no sensitive field; else the canonical names it carries (ambiguous
 *  ones included — the caller denies either way). When `Contact` itself is
 *  spelt more than one way, every spelling is judged (fail closed: Xero reads
 *  one of them and the inspector cannot tell which). */
export function inlineContactProblem(item: Record<string, unknown>): string[] | null {
  const target = fold("Contact");
  const found = new Set<string>();
  for (const key of Object.keys(item)) {
    if (fold(key) !== target) continue;
    const contact = item[key];
    if (!isRecord(contact)) continue;
    const { present, ambiguous } = sensitiveContactKeys(contact);
    for (const f of [...present, ...ambiguous]) found.add(f);
  }
  if (found.size === 0) return null;
  return SENSITIVE_CONTACT_FIELDS.filter((f) => found.has(f));
}

/** The deny for an inline `Contact` carrying `fields` (from
 *  `inlineContactProblem`); `owner` names the document, e.g. "invoice". */
export function inlineContactDeny(reason: string, owner: string, fields: string[]): InspectResult {
  return {
    decision: "deny",
    category: "financial_legal",
    reason,
    message:
      `The ${owner}'s inline Contact may not carry ${fields.join(", ")}; change the contact through ` +
      "/Contacts (where the change is approved), then reference it by ContactID.",
  };
}
