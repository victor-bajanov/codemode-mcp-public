// packages/providers/xero/src/inspectors/stored-status.ts
//
// Stored-status `inspectUpstream` hooks for invoices, credit notes and
// repeating-invoice templates (security review F2-4, F2-2).
//
// The sync inspectors (./drafts.ts, ./repeating-invoices.ts) judge only the
// request: an explicit DRAFT/SUBMITTED Status, no send flags. Whether the
// document an update names is itself still a draft is upstream state, and
// trusting Xero to refuse an edit of a posted document is the belief F2-4
// exposed. So before an update is sent, the host reads every existing
// document it names through the scaffold's upstream lookup (a plain-allow GET
// of getInvoice / getCreditNote / getRepeatingInvoice, same request handler,
// never the sandbox) and denies unless the stored Status is allowed. Nothing
// the sandbox can do moves a document out of DRAFT/SUBMITTED between the read
// and the write: every status transition is denied by the sync inspector.
//
// An item with no id but an `InvoiceNumber` / `CreditNoteNumber` is read by
// number too (Xero may key an update on it): 404 means a create; a found
// document must itself be a draft. Cost: one GET per numbered create, and a
// bill whose supplier reference equals a posted bill's number is refused.
//
// Every outcome other than "all stored documents are drafts" is a deny; the
// lookup's strings never reach `message` or `reason` (only the HTTP status
// does, on a failed read).

import type { InspectRequest, InspectResult, SurfaceReviewCategory, UpstreamLookup } from "@local/shared";
import { encodeLookupPath } from "@local/shared";
import { badNumber as isBadNumber, normId, readItems } from "./drafts.js";
import { getCaseInsensitive, isRecord } from "./keys.js";

export interface StoredStatusConfig {
  /** GET template of the plain-allow read, e.g. "/api.xro/2.0/Invoices/{InvoiceID}". */
  template: string;
  /** Wrapper key in the request body and in the GET response, e.g. "Invoices". */
  wrapper: string;
  /** Id field in the body, the path parameter name, and the template's parameter. */
  idField: string;
  /** Other body fields that also name the document (read when `idField` is
   *  absent), e.g. the repeating-invoice schema's `ID`. The sync inspector
   *  denies an item whose id fields disagree. */
  altIdFields?: readonly string[];
  /** Body field that may also key an update (Xero documents updates by
   *  `InvoiceNumber`; unverified, so fail closed): an item carrying it and no
   *  id is read by number first. 404 = a create; a found document must be
   *  allowed, else `<prefix>-number-matches-posted`. Ignored on the by-id
   *  endpoint (the path id is the target). */
  numberField?: string;
  /** Stored statuses (upper case) an update may target. */
  allowed: readonly string[];
  /** Singular noun for caller-facing messages, e.g. "invoice". */
  label: string;
  /** Indefinite article for `label` ("an invoice", "a credit note"). */
  article: "a" | "an";
  /** Prefix for the terse audit `reason` codes, e.g. "invoice". */
  reasonPrefix: string;
}

/** The scaffold's per-request lookup cap (MAX_UPSTREAM_LOOKUPS); restated
 *  here for the caller-facing message, and pinned equal by a test. */
export const MAX_STORED_LOOKUPS = 4;

export function makeStoredStatusHook(
  cfg: StoredStatusConfig,
): (req: InspectRequest, lookup: UpstreamLookup) => Promise<InspectResult> {
  const deny = (category: SurfaceReviewCategory, suffix: string, message: string): InspectResult => ({
    decision: "deny",
    category,
    reason: `${cfg.reasonPrefix}-${suffix}`,
    message,
  });
  const aLabel = `${cfg.article} ${cfg.label}`;

  const noPayload = deny(
    "malformed",
    "no-payload",
    `No ${cfg.label} payload found. Send a non-empty "${cfg.wrapper}" array (bulk) or a single ${cfg.label} object (by-id update).`,
  );
  const ambiguous = deny(
    "malformed",
    "ambiguous-key",
    `Refusing ${aLabel} payload that spells a key more than one way (keys differing only by letter case, or a non-ASCII lookalike).`,
  );
  const tooMany = deny(
    "malformed",
    "too-many-updates",
    `At most ${MAX_STORED_LOOKUPS} ${cfg.label}s carrying ${cfg.idField}${cfg.numberField ? ` or ${cfg.numberField}` : ""} ` +
      `can be sent in one request (each is read from Xero first, numbered creates included); split the batch.`,
  );
  const notFound = deny("malformed", "not-found", `The ${cfg.label} to modify was not found in Xero.`);
  const unreadable = deny(
    "malformed",
    "read-unreadable",
    `Reading the stored ${cfg.label} before the update returned an answer that could not be read, so the update was refused.`,
  );
  const notDraft = deny(
    "irreversible",
    "not-draft-upstream",
    `This ${cfg.label} is not a draft in Xero (its stored Status is not ${cfg.allowed.join(" or ")}), so it cannot be ` +
      `modified here; authorised, paid, voided and deleted ${cfg.label}s are immutable through this API.`,
  );
  const readFailed = (status: number): InspectResult =>
    deny(
      "malformed",
      "read-failed",
      `Reading the stored ${cfg.label} before the update failed (upstream status ${status}), so the update was refused.`,
    );

  const numberField = cfg.numberField;
  const numberMatchesPosted = deny(
    "irreversible",
    "number-matches-posted",
    `An existing ${cfg.label} with this ${numberField ?? "number"} is not a draft in Xero; include its ` +
      `${cfg.idField} to update a draft, or use a different ${numberField ?? "number"}.`,
  );
  const badNumber = deny(
    "malformed",
    "bad-number",
    `${numberField ?? "The number"} must be a string with no leading or trailing spaces when present.`,
  );
  const unexpectedKey = deny(
    "malformed",
    "unexpected-key",
    `Refusing ${aLabel} payload with other keys beside "${cfg.wrapper}": put every field inside the ${cfg.label} items.`,
  );
  const multipleItems = deny(
    "malformed",
    "by-id-multiple-items",
    `The by-id update modifies one ${cfg.label} (the one in the path); send exactly one item, or use the bulk endpoint for several.`,
  );

  const idFields = [cfg.idField, ...(cfg.altIdFields ?? [])];

  /** One stored read: by id (must exist) or by number (404 is a create). */
  type Target = { kind: "id" | "number"; value: string };

  /** The distinct documents the request may modify (original spelling), or the deny that stands. */
  function targets(req: InspectRequest): { targets: Target[] } | { deny: InspectResult } {
    const read = readItems(req.body, cfg.wrapper);
    if (!read.ok) {
      if (read.reason === "ambiguous-wrapper") return { deny: ambiguous };
      return { deny: read.reason === "unexpected-key" ? unexpectedKey : noPayload };
    }
    // By-id endpoint: the sync inspector tied every body id to the path id,
    // and only the path id is read, so the body must be that one document.
    const pathId = req.pathParams?.[cfg.idField];
    if (typeof pathId === "string" && pathId.length > 0) {
      if (read.items.length > 1) return { deny: multipleItems };
      return { targets: [{ kind: "id", value: pathId }] };
    }
    // Ids dedupe trimmed and lower-cased (GUIDs); numbers only by exact
    // spelling (whether Xero matches them case-insensitively is unknown, so
    // two spellings are two reads).
    const seen = new Set<string>();
    const out: Target[] = [];
    const add = (t: Target, key: string): void => {
      if (seen.has(key)) return;
      seen.add(key);
      out.push(t);
    };
    for (const item of read.items) {
      let keyed = false;
      for (const field of idFields) {
        const r = getCaseInsensitive(item, field);
        if (r.ambiguous) return { deny: ambiguous };
        if (typeof r.value === "string" && r.value.length > 0) {
          add({ kind: "id", value: r.value }, `id:${normId(r.value)}`);
          keyed = true;
          break;
        }
      }
      if (keyed || numberField === undefined) continue;
      const n = getCaseInsensitive(item, numberField);
      if (n.ambiguous) return { deny: ambiguous };
      if (isBadNumber(n.value)) return { deny: badNumber };
      if (typeof n.value === "string" && n.value.length > 0) add({ kind: "number", value: n.value }, `number:${n.value}`);
    }
    return { targets: out };
  }

  return async function inspectStored(req: InspectRequest, lookup: UpstreamLookup): Promise<InspectResult> {
    const t = targets(req);
    if ("deny" in t) return t.deny;
    if (t.targets.length === 0) return { decision: "allow" };
    if (t.targets.length > MAX_STORED_LOOKUPS) return tooMany;
    for (const { kind, value } of t.targets) {
      // pathParams and body values are decoded; the lookup takes an encoded
      // path, so the value is always exactly one segment.
      const r = await lookup.get(encodeLookupPath(cfg.template, { [cfg.idField]: value }));
      if (r.status === 404) {
        if (kind === "number") continue; // no document has this number: a create
        return notFound;
      }
      if (r.status < 200 || r.status > 299) return readFailed(r.status);
      const status = storedStatus(r.body);
      if (status === undefined) return kind === "number" ? numberMatchesPosted : unreadable;
      if (!cfg.allowed.includes(status.toUpperCase())) return kind === "number" ? numberMatchesPosted : notDraft;
    }
    return { decision: "allow" };
  };

  /** The single stored document's Status, or undefined when the answer is
   *  not exactly one document with a string Status. */
  function storedStatus(body: unknown): string | undefined {
    if (!isRecord(body)) return undefined;
    const list = body[cfg.wrapper];
    if (!Array.isArray(list) || list.length !== 1 || !isRecord(list[0])) return undefined;
    const status = list[0]["Status"];
    return typeof status === "string" ? status : undefined;
  }
}

export const inspectStoredInvoice = makeStoredStatusHook({
  template: "/api.xro/2.0/Invoices/{InvoiceID}",
  wrapper: "Invoices",
  idField: "InvoiceID",
  numberField: "InvoiceNumber",
  allowed: ["DRAFT", "SUBMITTED"],
  label: "invoice",
  article: "an",
  reasonPrefix: "invoice",
});

export const inspectStoredCreditNote = makeStoredStatusHook({
  template: "/api.xro/2.0/CreditNotes/{CreditNoteID}",
  wrapper: "CreditNotes",
  idField: "CreditNoteID",
  numberField: "CreditNoteNumber",
  allowed: ["DRAFT", "SUBMITTED"],
  label: "credit note",
  article: "a",
  reasonPrefix: "creditnote",
});

export const inspectStoredRepeatingInvoice = makeStoredStatusHook({
  template: "/api.xro/2.0/RepeatingInvoices/{RepeatingInvoiceID}",
  wrapper: "RepeatingInvoices",
  idField: "RepeatingInvoiceID",
  // The schema names a template by `RepeatingInvoiceID` or `ID`.
  altIdFields: ["ID"],
  allowed: ["DRAFT"],
  label: "repeating invoice",
  article: "a",
  reasonPrefix: "repeating",
});
