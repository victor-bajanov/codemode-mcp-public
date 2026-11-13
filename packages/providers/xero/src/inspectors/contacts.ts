// packages/providers/xero/src/inspectors/contacts.ts
//
// Contact writes (security review F2-1): `createContacts` (PUT /Contacts) and
// `updateOrCreateContacts` (POST /Contacts).
//
// Policy (the user's instruction: creates stay open, edits of payee/delivery
// details need approval):
//   - An item with neither `ContactID` nor `ContactNumber` is a create: allowed,
//     whatever fields it carries (no money is attached to a new contact; every
//     path that pays or bills it is gated elsewhere).
//   - An item carrying `ContactID` or `ContactNumber` is an edit. It is allowed
//     unless it carries a sensitive field (SENSITIVE_CONTACT_FIELDS), or
//     changes `Name` or `XeroNetworkKey` (EDIT_GATED_CONTACT_FIELDS: "changes"
//     = differs from the stored contact, so only the hook can tell). Either is
//     a gated edit: `elicit` (financial_legal). Claude.ai cannot elicit, so
//     there it is a deny (fail closed, accepted).
//   - The body may carry nothing beside the `Contacts` wrapper (a flat contact
//     beside it would be a second, unjudged reading of the request).
//   - An edit carrying a sensitive field, `Name` or `XeroNetworkKey` must be
//     the only item in the request, and every fact of its dialog must be shown
//     whole: at most eight facts, each at most FACT_VALUE_MAX code points
//     (the scaffold cuts longer ones), and at most LIST_MAX contact persons.
//   - `ContactNumber`-keyed items are treated as edits: whether Xero matches an
//     update on it is unverified, so the fail-closed reading costs one GET.
//
// `inspectStoredContact` (the `inspectUpstream` hook) reads the stored contact
// for a gated edit and re-states the summary as `old → new`. Stored strings
// go into `summary` only (shown to the user in the dialog), never into
// `message` or `reason` (seen by the model).
//
// Keys are read case-insensitively (./keys); any key spelt two ways is denied.
import {
  encodeLookupPath,
  type InspectRequest,
  type InspectResult,
  type Primitive,
  type UpstreamLookup,
} from "@local/shared";
import { cleanDialogText, FACT_VALUE_MAX, MAX_DIALOG_FACTS } from "@local/scaffold";
import { normId, readItems } from "./drafts.js";
import { ambiguousKeyDeny, getCaseInsensitive, isRecord } from "./keys.js";
import {
  EDIT_GATED_CONTACT_FIELDS,
  SENSITIVE_CONTACT_FIELDS,
  type EditGatedContactField,
  type SensitiveContactField,
} from "./contact-fields.js";

const LOOKUP_TEMPLATE = "/api.xro/2.0/Contacts/{ContactID}";
/** Most contact persons a gated edit may carry: each is shown in full. */
const LIST_MAX = 3;
const BATCH_PAYMENT_KEYS = ["BankAccountNumber", "BankAccountName", "Details", "Code", "Reference"] as const;
const STRING_FIELDS = new Set<SensitiveContactField>(["BankAccountDetails", "EmailAddress", "ContactStatus", "TaxNumber"]);

const SUMMARY_KEY: Record<SensitiveContactField, string> = {
  BankAccountDetails: "bankAccountDetails",
  BatchPayments: "batchPayments",
  EmailAddress: "emailAddress",
  ContactStatus: "contactStatus",
  TaxNumber: "taxNumber",
  ContactPersons: "contactPersons",
};

// --- results ----------------------------------------------------------------

function deny(category: "malformed" | "financial_legal", reason: string, message: string): InspectResult {
  return { decision: "deny", category, reason, message };
}

const NO_PAYLOAD = deny(
  "malformed",
  "contact-no-payload",
  'No contact payload found. Send a non-empty "Contacts" array of contact objects, or one contact object.',
);

const ambiguous = (key: string): InspectResult => ambiguousKeyDeny("contact-ambiguous-key", "a contact", key);

function badId(key: string): InspectResult {
  return deny("malformed", "contact-bad-id", `"${key}" must be a non-empty string when present.`);
}

function unreadableField(key: string): InspectResult {
  const shape =
    key === "BatchPayments"
      ? "an object"
      : key === "ContactPersons"
        ? "an array (each IncludeInEmails a boolean)"
        : "a string";
  return deny(
    "malformed",
    "contact-field-unreadable",
    `"${key}" must be ${shape} (or null to clear it); the value sent cannot be shown for approval.`,
  );
}

const ONE_PER_REQUEST = deny(
  "financial_legal",
  "contact-one-per-request",
  "A contact write that changes bank, batch-payment, email, status, tax-number or contact-person " +
    "details, or edits a contact and carries its name or Xero Network key, must carry exactly one " +
    "contact, so the approval dialog can show the change; send the other contacts separately.",
);

const UNEXPECTED_KEY = deny(
  "malformed",
  "contact-unexpected-key",
  'A contact write may carry only the "Contacts" array (or one flat contact object); remove the ' +
    "other top-level keys.",
);

const TOO_MANY_PERSONS = deny(
  "financial_legal",
  "contact-too-many-persons",
  `A contact edit may carry at most ${LIST_MAX} ContactPersons, so the approval dialog can show every ` +
    "one; change the contact persons in smaller steps.",
);

const TOO_MANY_FIELDS = deny(
  "financial_legal",
  "contact-too-many-fields",
  "This contact edit changes more fields than the approval dialog can show at once; send the change " +
    "in two requests.",
);

const VALUE_TOO_LONG = deny(
  "financial_legal",
  "contact-value-too-long",
  `A value in this contact change is too long to show in full in the approval dialog (old and new ` +
    `value together over ${FACT_VALUE_MAX} characters), so it cannot be approved; shorten it or ` +
    "change the contact in Xero directly.",
);

const NUMBER_MISMATCH = deny(
  "malformed",
  "contact-number-mismatch",
  "The ContactNumber sent does not match the stored contact's ContactNumber, so it is unclear which " +
    "contact this edits; send ContactID alone, or with the stored ContactNumber.",
);

// --- parsing ----------------------------------------------------------------

interface GatedEdit {
  item: Record<string, unknown>;
  /** The lookup key and value: `ContactID` when present, else `ContactNumber`. */
  keyedBy: "ContactID" | "ContactNumber";
  target: string;
  /** The body's `ContactNumber` when the item is keyed by `ContactID` and
   *  carries one too: the stored contact must carry the same number. */
  alsoNumber: string | undefined;
  /** Sensitive fields carried, canonical order, with their (unambiguous) values. */
  fields: Array<[SensitiveContactField, unknown]>;
  /** Edit-gated fields carried (Name, XeroNetworkKey), with their values. */
  gated: Array<[EditGatedContactField, unknown]>;
}

type Parsed =
  | { ok: true; items: Record<string, unknown>[]; edits: GatedEdit[] }
  | { ok: false; result: InspectResult };

/** A ContactPersons entry's email or IncludeInEmails, or a BatchPayments
 *  sub-key, is shown in the dialog: a key there spelt two ways is denied like
 *  a top-level one. */
function nestedAmbiguity(field: SensitiveContactField, value: unknown): string | undefined {
  if (field === "BatchPayments" && isRecord(value)) {
    for (const k of BATCH_PAYMENT_KEYS) {
      if (getCaseInsensitive(value, k).ambiguous) return `BatchPayments.${k}`;
    }
  }
  if (field === "ContactPersons" && Array.isArray(value)) {
    for (const p of value) {
      if (!isRecord(p)) continue;
      for (const k of ["EmailAddress", "IncludeInEmails"]) {
        if (getCaseInsensitive(p, k).ambiguous) return `ContactPersons.${k}`;
      }
    }
  }
  return undefined;
}

function fieldReadable(field: SensitiveContactField, value: unknown): boolean {
  if (value === null) return true;
  if (STRING_FIELDS.has(field)) return typeof value === "string";
  if (field === "BatchPayments") return isRecord(value);
  return Array.isArray(value); // ContactPersons
}

/** On an edit, each person's IncludeInEmails is shown: it must be a boolean
 *  (or null / absent) so the dialog's mark matches what Xero applies. */
function personsReadable(value: unknown): boolean {
  if (!Array.isArray(value)) return true;
  return value.every((p) => {
    if (!isRecord(p)) return true;
    const v = getCaseInsensitive(p, "IncludeInEmails").value;
    return v === undefined || v === null || typeof v === "boolean";
  });
}

function parse(body: unknown): Parsed {
  // Nothing may sit beside the wrapper: the Contacts schema's other
  // properties (pagination, Warnings) are response-only, and a flat contact
  // there (ContactID + BankAccountDetails) would be a second reading.
  const read = readItems(body, "Contacts");
  if (!read.ok) {
    if (read.reason === "ambiguous-wrapper") return { ok: false, result: ambiguous("Contacts") };
    return { ok: false, result: read.reason === "unexpected-key" ? UNEXPECTED_KEY : NO_PAYLOAD };
  }
  const items = read.items;
  const edits: GatedEdit[] = [];
  for (const item of items) {
    const id = getCaseInsensitive(item, "ContactID");
    const num = getCaseInsensitive(item, "ContactNumber");
    if (id.ambiguous) return { ok: false, result: ambiguous("ContactID") };
    if (num.ambiguous) return { ok: false, result: ambiguous("ContactNumber") };
    const fields: Array<[SensitiveContactField, unknown]> = [];
    for (const f of SENSITIVE_CONTACT_FIELDS) {
      const r = getCaseInsensitive(item, f);
      if (r.ambiguous) return { ok: false, result: ambiguous(f) };
      if (r.present) fields.push([f, r.value]);
    }
    const gated: Array<[EditGatedContactField, unknown]> = [];
    for (const f of EDIT_GATED_CONTACT_FIELDS) {
      const r = getCaseInsensitive(item, f);
      if (r.ambiguous) return { ok: false, result: ambiguous(f) };
      if (r.present) gated.push([f, r.value]);
    }
    for (const [key, r] of [["ContactID", id], ["ContactNumber", num]] as const) {
      if (r.present && (typeof r.value !== "string" || r.value.trim() === "")) {
        return { ok: false, result: badId(key) };
      }
    }
    for (const [f, v] of fields) {
      if (!fieldReadable(f, v)) return { ok: false, result: unreadableField(f) };
      const nested = nestedAmbiguity(f, v);
      if (nested !== undefined) return { ok: false, result: ambiguous(nested) };
    }
    const isEdit = id.present || num.present;
    if (!isEdit) continue;
    for (const [f, v] of fields) {
      if (f === "ContactPersons" && !personsReadable(v)) return { ok: false, result: unreadableField(f) };
    }
    for (const [f, v] of gated) {
      if (v !== null && typeof v !== "string") return { ok: false, result: unreadableField(f) };
    }
    if (fields.length > 0 || gated.length > 0) {
      edits.push({
        item,
        keyedBy: id.present ? "ContactID" : "ContactNumber",
        target: (id.present ? id.value : num.value) as string,
        alsoNumber: id.present && num.present ? (num.value as string) : undefined,
        fields,
        gated,
      });
    }
  }
  return { ok: true, items, edits };
}

// --- rendering ----------------------------------------------------------------

function primitiveText(v: unknown): string {
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return String(v);
  if (v === null) return "(cleared)";
  return "(unreadable)";
}

function listText(values: string[]): string {
  const shown = values.slice(0, LIST_MAX).join(", ");
  return values.length > LIST_MAX ? `${shown} (+${values.length - LIST_MAX})` : shown;
}

/** Display text of a field's value. `side` picks how an absent or empty value
 *  reads: a new `null` clears the field, an old one is `(none)`. The body's
 *  new ContactPersons list is never longer than LIST_MAX (denied before), so
 *  only a stored list can show ` (+N)`. */
function render(field: SensitiveContactField | EditGatedContactField, value: unknown, side: "old" | "new"): string {
  if (value === undefined || value === null) return side === "old" ? "(none)" : "(cleared)";
  const empty = side === "old" ? "(none)" : "(empty)";
  if (field === "BatchPayments") {
    if (!isRecord(value)) return "(unreadable)";
    const parts: string[] = [];
    for (const k of BATCH_PAYMENT_KEYS) {
      const r = getCaseInsensitive(value, k);
      if (r.ambiguous) parts.push(`${k}=(unreadable)`);
      else if (r.present) parts.push(`${k}=${primitiveText(r.value)}`);
    }
    return parts.length > 0 ? parts.join(", ") : empty;
  }
  if (field === "ContactPersons") {
    if (!Array.isArray(value)) return "(unreadable)";
    if (value.length === 0) return empty;
    return listText(
      value.map((p) => {
        if (!isRecord(p)) return "(no email)";
        const e = getCaseInsensitive(p, "EmailAddress");
        const inc = getCaseInsensitive(p, "IncludeInEmails");
        const email = !e.ambiguous && typeof e.value === "string" ? e.value : "(no email)";
        if (inc.ambiguous) return email;
        if (inc.value === true) return `${email} (in emails)`;
        // Absent on the body: Xero's default for a person is unverified.
        if (side === "new" && (inc.value === undefined || inc.value === null)) return `${email} (in emails?)`;
        return email;
      }),
    );
  }
  return typeof value === "string" ? value : "(unreadable)";
}

/** Whether the body's value of an edit-gated field differs from the stored one. */
function changes(bodyValue: unknown, storedValue: unknown): boolean {
  if (bodyValue === null) return !(storedValue === undefined || storedValue === null || storedValue === "");
  return storedValue !== bodyValue;
}

function contactIdFact(edit: GatedEdit): string {
  return edit.keyedBy === "ContactID" ? edit.target : `number ${edit.target}`;
}

/** What the dialog shows of the stored contact: no read yet (sync), a
 *  ContactNumber that does not exist (Xero creates it), or the stored one. */
type StoredView = { kind: "unread" } | { kind: "new" } | { kind: "stored"; contact: Record<string, unknown> };

/** Facts in dialog order: contactId, name, one per sensitive field, then
 *  xeroNetworkKey. Every fact but an unchanged stored name must fit the
 *  dialog uncut; `checked` lists them. */
function summary(edit: GatedEdit, view: StoredView): { facts: Record<string, Primitive>; checked: string[] } {
  const facts: Record<string, Primitive> = { contactId: contactIdFact(edit) };
  const checked = ["contactId"];
  const gated = new Map(edit.gated);
  const oldOf = (f: SensitiveContactField | EditGatedContactField): string =>
    view.kind === "stored" ? render(f, view.contact[f], "old") : "(none)";
  const change = (f: SensitiveContactField | EditGatedContactField, v: unknown): string =>
    view.kind === "unread" ? `→ ${render(f, v, "new")}` : `${oldOf(f)} → ${render(f, v, "new")}`;

  if (!gated.has("Name")) {
    facts.name = view.kind === "unread" ? "" : view.kind === "new" ? "(new contact)" : stringField(view.contact, "Name");
  } else {
    const v = gated.get("Name");
    if (view.kind === "unread") facts.name = `→ ${render("Name", v, "new")}`;
    else if (view.kind === "new") facts.name = `(new contact) → ${render("Name", v, "new")}`;
    else if (changes(v, view.contact["Name"])) facts.name = change("Name", v);
    else facts.name = stringField(view.contact, "Name");
    if (view.kind !== "stored" || changes(v, view.contact["Name"])) checked.push("name");
  }
  for (const [f, v] of edit.fields) {
    facts[SUMMARY_KEY[f]] = change(f, v);
    checked.push(SUMMARY_KEY[f]);
  }
  if (gated.has("XeroNetworkKey")) {
    facts.xeroNetworkKey = change("XeroNetworkKey", gated.get("XeroNetworkKey"));
    checked.push("xeroNetworkKey");
  }
  return { facts, checked };
}

function stringField(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  return typeof v === "string" ? v : "";
}

/** Code points the scaffold's dialog shows of `text` after cleaning. */
function shownLength(text: string): number {
  return Array.from(cleanDialogText(text)).length;
}

/** The elicit result, or a deny when the dialog could not show it whole (the
 *  scaffold shows the first MAX_DIALOG_FACTS facts and cuts each value at
 *  FACT_VALUE_MAX code points after cleaning). */
function elicitOrDeny(s: { facts: Record<string, Primitive>; checked: string[] }): InspectResult {
  if (Object.keys(s.facts).length > MAX_DIALOG_FACTS) return TOO_MANY_FIELDS;
  for (const k of s.checked) {
    if (shownLength(String(s.facts[k])) > FACT_VALUE_MAX) return VALUE_TOO_LONG;
  }
  return { decision: "elicit", category: "financial_legal", reason: "contact-sensitive-edit", summary: s.facts };
}

// --- inspectors -----------------------------------------------------------------

/** Sync inspector for `createContacts` / `updateOrCreateContacts`. */
export function inspectContactWrite(req: InspectRequest): InspectResult {
  const p = parse(req.body);
  if (!p.ok) return p.result;
  if (p.edits.length === 0) return { decision: "allow" };
  if (p.edits.length > 1 || p.items.length > 1) return ONE_PER_REQUEST;
  const edit = p.edits[0]!;
  // Name / XeroNetworkKey alone: only the stored read can tell whether they
  // change, so the hook decides (it may raise this to elicit, never lower it).
  if (edit.fields.length === 0) return { decision: "allow" };
  const persons = edit.fields.find(([f]) => f === "ContactPersons")?.[1];
  if (Array.isArray(persons) && persons.length > LIST_MAX) return TOO_MANY_PERSONS;
  return elicitOrDeny(summary(edit, { kind: "unread" }));
}

/** `inspectUpstream` hook: reads the stored contact of a gated edit so the
 *  dialog shows old → new, and decides whether a Name / XeroNetworkKey edit
 *  changes anything. No lookup for creates and plain edits. */
export async function inspectStoredContact(req: InspectRequest, lookup: UpstreamLookup): Promise<InspectResult> {
  // Re-judge with the sync rules (the hook only runs when they did not deny,
  // but it must never widen them).
  const sync = inspectContactWrite(req);
  if (sync.decision === "deny") return sync;
  const p = parse(req.body);
  if (!p.ok) return p.result;
  if (p.edits.length === 0) return { decision: "allow" };
  const edit = p.edits[0]!;

  const res = await lookup.get(encodeLookupPath(LOOKUP_TEMPLATE, { ContactID: edit.target }));
  if (res.status === 404) {
    if (edit.keyedBy === "ContactID") {
      return deny(
        "malformed",
        "contact-not-found",
        "No contact with this ContactID exists in Xero, so there is nothing to change; the request was denied.",
      );
    }
    // Keyed by ContactNumber only: no stored contact means Xero creates one,
    // and creates are open unless they carry a sensitive field.
    if (edit.fields.length === 0) return { decision: "allow" };
    return elicitOrDeny(summary(edit, { kind: "new" }));
  }
  if (res.status < 200 || res.status > 299) {
    return deny(
      "malformed",
      "contact-read-failed",
      `Reading the stored contact failed (HTTP ${res.status}), so the change cannot be shown for approval; the request was denied.`,
    );
  }
  const unreadable = deny(
    "malformed",
    "contact-read-unreadable",
    "The stored contact could not be read as expected, so the change cannot be shown for approval; the request was denied.",
  );
  const list = isRecord(res.body) ? res.body["Contacts"] : undefined;
  if (!Array.isArray(list) || list.length !== 1 || !isRecord(list[0])) return unreadable;
  const stored = list[0];
  // GET /Contacts/{x} matches a ContactID or a ContactNumber: the stored
  // contact must carry the requested key, or the dialog would show another one.
  // ContactID is a GUID (case-insensitive); ContactNumber is compared exactly,
  // since whether Xero matches it ignoring case is unverified (a false deny
  // is the safe miss).
  const sameKey = (key: "ContactID" | "ContactNumber", storedValue: unknown, wanted: string): boolean =>
    typeof storedValue === "string" &&
    (key === "ContactID" ? normId(storedValue) === normId(wanted) : storedValue === wanted);
  if (!sameKey(edit.keyedBy, stored[edit.keyedBy], edit.target)) return unreadable;
  if (edit.alsoNumber !== undefined && !sameKey("ContactNumber", stored["ContactNumber"], edit.alsoNumber)) return NUMBER_MISMATCH;

  const gatedChange = edit.gated.some(([f, v]) => changes(v, stored[f]));
  if (edit.fields.length === 0 && !gatedChange) return { decision: "allow" };
  return elicitOrDeny(summary(edit, { kind: "stored", contact: stored }));
}
