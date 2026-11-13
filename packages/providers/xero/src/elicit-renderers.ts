// Xero approval-dialog renderers (D-1). Each returns a headline and the
// resolved facts the dialog SHOWS (never inputs; the form is confirm-only and
// the scaffold adds the `Request: METHOD path` and `Query:` lines itself).
//
// Rules every renderer keeps:
// - Targets (invoice, employee, pay run) come from the decoded path
//   parameters, never from the body: the path is what goes on the wire.
// - Bodies are read the way Xero reads them: property names match
//   case-insensitively (inspectors/keys.ts). A key spelled twice, or only as a
//   non-ASCII lookalike, is unreadable: its value is left out (a total that
//   depends on it becomes "not numeric") and the key is listed under
//   `ambiguousKeys`.
// - Top-level body keys other than the expected collection are listed under
//   `unexpectedKeys`, so a decoy beside the real payload is visible (F2-3).
// - Inspector summary primitives are appended after the renderer's own facts
//   and never override them (wave 2/3 inspectors add their facts this way).

import type { ElicitRenderer, ElicitRendererInput, FormFields, Primitive } from "@local/shared";
import { ASCII_ONLY, fold, getCaseInsensitive } from "./inspectors/keys.js";

const LIST_MAX = 3;

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Body reader that records every key it could not read unambiguously. */
class Reader {
  readonly ambiguous = new Set<string>();

  get(obj: unknown, key: string): unknown {
    if (!isRecord(obj)) return undefined;
    const r = getCaseInsensitive(obj, key);
    if (r.ambiguous) {
      this.ambiguous.add(key);
      return undefined;
    }
    return r.value;
  }

  /** The first of `keys` present on `obj`, as display text. Lower-priority
   *  keys are consulted only while higher ones are absent: an ambiguous or
   *  non-primitive higher key yields `undefined`, never a fall-through. */
  label(obj: unknown, ...keys: string[]): string | undefined {
    if (!isRecord(obj)) return undefined;
    for (const k of keys) {
      const r = getCaseInsensitive(obj, k);
      if (!r.present) continue;
      if (r.ambiguous) {
        this.ambiguous.add(k);
        return undefined;
      }
      return typeof r.value === "string" || typeof r.value === "number" ? String(r.value) : undefined;
    }
    return undefined;
  }
}

/** First `LIST_MAX` distinct values, comma-joined, with ` (+N)` for the rest. */
function list(values: Iterable<string>): string | undefined {
  const distinct = [...new Set(values)];
  if (distinct.length === 0) return undefined;
  const shown = distinct.slice(0, LIST_MAX).join(", ");
  return distinct.length > LIST_MAX ? `${shown} (+${distinct.length - LIST_MAX})` : shown;
}

function setIfDefined(facts: FormFields, key: string, v: Primitive | undefined): void {
  if (v !== undefined) facts[key] = v;
}

/** Locate the collection Xero will read: the body itself when it is an array
 *  (the payroll spec shape), else the `wrapper` property (case-insensitive).
 *  Other top-level keys are reported as unexpected. */
function collection(
  body: unknown,
  wrapper: string,
  reader: Reader,
): { items: unknown[]; unexpected: string[] } {
  if (Array.isArray(body)) return { items: body, unexpected: [] };
  if (!isRecord(body)) return { items: [], unexpected: [] };
  const unexpected = Object.keys(body).filter((k) => fold(k) !== fold(wrapper));
  const v = reader.get(body, wrapper);
  return { items: Array.isArray(v) ? v : [], unexpected };
}

function finish(
  facts: FormFields,
  unexpected: string[],
  reader: Reader,
  summary: ElicitRendererInput["inspectorSummary"],
): FormFields {
  setIfDefined(facts, "unexpectedKeys", list(unexpected));
  setIfDefined(facts, "ambiguousKeys", list(reader.ambiguous));
  if (summary) {
    for (const [k, v] of Object.entries(summary)) {
      if (Object.hasOwn(facts, k)) continue;
      if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") facts[k] = v;
    }
  }
  return facts;
}

function roundAmount(n: number): number {
  return Math.round(n * 10_000) / 10_000;
}

// --- external_data_flow ---------------------------------------------------

const externalDataFlow: ElicitRenderer = (input) => {
  const facts: FormFields = {};
  setIfDefined(facts, "invoiceId", input.pathParams["InvoiceID"]);
  return {
    headline: `Confirm Xero email invoice (${input.operationId})`,
    facts: finish(facts, [], new Reader(), input.inspectorSummary),
  };
};

// --- financial_legal ------------------------------------------------------

/** Folded names of batch-level keys: beside the `BatchPayments` wrapper they
 *  make it unclear which payload Xero reads (the F2-3 decoy). */
const BATCH_LEVEL_KEYS = new Set(["account", "payments", "amount"]);

/** Folded BatchPayment schema properties a bare (unwrapped) batch may carry;
 *  any other top-level key is listed as unexpected. */
const BARE_BATCH_KEYS = new Set(
  ["Account", "Date", "DateString", "Reference", "Particulars", "Code", "Details", "Narrative", "Payments", "Amount"]
    .map(fold),
);

/** Payment targets with their id keys in priority order. */
const PAYMENT_TARGETS: ReadonlyArray<[string, string[]]> = [
  ["Invoice", ["InvoiceID", "InvoiceNumber"]],
  ["CreditNote", ["CreditNoteID", "CreditNoteNumber"]],
  ["Prepayment", ["PrepaymentID"]],
  ["Overpayment", ["OverpaymentID"]],
];

/** createBatchPayment: `{ BatchPayments: [{ Account, Payments: [{ Invoice,
 *  BankAccountNumber, Amount }] }] }`, or one bare batch object (read the way
 *  inspectors/drafts.ts reads a by-id body). Any shape the renderer cannot
 *  read as Xero would makes `total` "not numeric" and says why in `shape`:
 *  a dialog must never show a total of 0 for a body that pays money. */
function batchPaymentFacts(input: ElicitRendererInput): FormFields {
  const reader = new Reader();
  const shape = new Set<string>();
  const body = input.body;
  let batches: unknown[] = [];
  let unexpected: string[] = [];
  let shapeUnreadable = false;

  if (Array.isArray(body)) {
    shape.add("body is a list");
    batches = body;
  } else if (isRecord(body)) {
    // A non-ASCII top-level key may be a lookalike of a key Xero folds onto
    // (e.g. a zero-width space inside "BatchPayments"): unreadable.
    const nonAscii = Object.keys(body).filter((k) => !ASCII_ONLY.test(k));
    for (const k of nonAscii) reader.ambiguous.add(k);
    const wrapper = getCaseInsensitive(body, "BatchPayments");
    if (wrapper.present) {
      unexpected = Object.keys(body).filter(
        (k) => fold(k) !== fold("BatchPayments") && !nonAscii.includes(k),
      );
      if (unexpected.some((k) => BATCH_LEVEL_KEYS.has(fold(k)))) shape.add("batch keys beside BatchPayments");
      if (wrapper.ambiguous) reader.ambiguous.add("BatchPayments");
      else if (Array.isArray(wrapper.value)) batches = wrapper.value;
      else shape.add("BatchPayments is not a list");
    } else if (Object.keys(body).length > 0) {
      batches = [body];
      unexpected = Object.keys(body).filter((k) => !BARE_BATCH_KEYS.has(fold(k)) && !nonAscii.includes(k));
    }
    if (nonAscii.length > 0) shapeUnreadable = true;
  }

  const accounts: string[] = [];
  const bankAccounts: string[] = [];
  const targets: string[] = [];
  let payments = 0;
  let total = 0;
  let numeric = true;
  let nonPositive = 0;

  for (const batch of batches) {
    if (!isRecord(batch)) {
      shape.add("batch is not an object");
      continue;
    }
    const acct = reader.label(reader.get(batch, "Account"), "AccountID", "Code");
    if (acct !== undefined) accounts.push(acct);
    const ps = reader.get(batch, "Payments");
    if (ps === undefined) continue; // absent (no payments) or ambiguous (recorded)
    if (!Array.isArray(ps)) {
      shape.add("Payments is not a list");
      continue;
    }
    for (const p of ps) {
      payments += 1;
      if (!isRecord(p)) {
        shape.add("payment is not an object");
        continue;
      }
      const amount = reader.get(p, "Amount");
      if (typeof amount === "number" && Number.isFinite(amount)) {
        total += amount;
        if (amount <= 0) nonPositive += 1;
      } else {
        numeric = false;
      }
      const bank = reader.label(p, "BankAccountNumber");
      if (bank !== undefined) bankAccounts.push(bank);
      for (const [kind, idKeys] of PAYMENT_TARGETS) {
        const id = reader.label(reader.get(p, kind), ...idKeys);
        if (id !== undefined) targets.push(`${kind} ${id}`);
      }
    }
  }

  // An unreadable shape, wrapper, payment list or amount, or a zero/negative
  // amount netting against the rest, hides money from the sum.
  if (
    shape.size > 0 ||
    shapeUnreadable ||
    nonPositive > 0 ||
    ["BatchPayments", "Payments", "Amount"].some((k) => reader.ambiguous.has(k))
  ) {
    numeric = false;
  }
  const facts: FormFields = {
    batches: batches.length,
    payments,
    total: numeric ? roundAmount(total) : "not numeric",
  };
  // Warnings before the lists, so the 8-fact cap never hides them.
  if (nonPositive > 0) facts.nonPositiveAmounts = nonPositive;
  setIfDefined(facts, "shape", list(shape));
  setIfDefined(facts, "unexpectedKeys", list(unexpected));
  setIfDefined(facts, "ambiguousKeys", list(reader.ambiguous));
  setIfDefined(facts, "accounts", list(accounts));
  setIfDefined(facts, "bankAccounts", list(bankAccounts));
  setIfDefined(facts, "targets", list(targets));
  return finish(facts, [], reader, input.inspectorSummary);
}

/** createPayRun / updatePayRun: a top-level array of PayRun objects (the
 *  spec shape), or a `PayRuns` wrapper object. */
function payRunFacts(input: ElicitRendererInput): FormFields {
  const reader = new Reader();
  const facts: FormFields = {};
  setIfDefined(facts, "payRunId", input.pathParams["PayRunID"]);
  const { items, unexpected } = collection(input.body, "PayRuns", reader);
  facts.payRuns = items.length;
  const statuses: string[] = [];
  const periods: string[] = [];
  for (const run of items) {
    const s = reader.label(run, "PayRunStatus");
    if (s !== undefined) statuses.push(s);
    const start = reader.label(run, "PayRunPeriodStartDate");
    const end = reader.label(run, "PayRunPeriodEndDate");
    if (start !== undefined || end !== undefined) periods.push(`${start ?? "?"} to ${end ?? "?"}`);
  }
  setIfDefined(facts, "status", list(statuses));
  setIfDefined(facts, "period", list(periods));
  return finish(facts, unexpected, reader, input.inspectorSummary);
}

const BATCH_PAYMENT_OPS = new Set(["xero.accounting.createBatchPayment"]);
const PAY_RUN_OPS = new Set(["xero.payroll.au.createPayRun", "xero.payroll.au.updatePayRun"]);

const financialLegal: ElicitRenderer = (input) => {
  const headline = `Confirm Xero financial op (${input.operationId})`;
  if (BATCH_PAYMENT_OPS.has(input.operationId)) return { headline, facts: batchPaymentFacts(input) };
  if (PAY_RUN_OPS.has(input.operationId)) return { headline, facts: payRunFacts(input) };
  // Any other financial_legal operation: path targets and inspector facts.
  const facts: FormFields = { ...input.pathParams };
  return { headline, facts: finish(facts, [], new Reader(), input.inspectorSummary) };
};

// --- persistent_state -----------------------------------------------------

const SENSITIVE_EMPLOYEE_KEYS = new Set(
  ["BankAccounts", "TaxDeclaration", "SuperMemberships", "PayTemplate"].map(fold),
);

/** createEmployee / updateEmployee: a top-level array of Employee objects
 *  (the spec shape), or an `Employees` wrapper object. */
const persistentState: ElicitRenderer = (input) => {
  const reader = new Reader();
  const facts: FormFields = {};
  setIfDefined(facts, "employeeId", input.pathParams["EmployeeID"]);
  const { items, unexpected } = collection(input.body, "Employees", reader);
  facts.employees = items.length;
  const first = items[0];
  for (const key of ["FirstName", "LastName", "Email"]) {
    const v = reader.get(first, key);
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") facts[key] = v;
  }
  // Interim until wave 2/3 inspectors show old vs new values: every property
  // the first item writes, so e.g. a BankAccounts change is visible.
  // Sensitive properties (where pay goes, tax, super, pay template) first,
  // so the fact-value length cap never cuts them.
  if (isRecord(first)) {
    const keys = Object.keys(first);
    const sensitive = keys.filter((k) => SENSITIVE_EMPLOYEE_KEYS.has(fold(k)));
    const rest = keys.filter((k) => !SENSITIVE_EMPLOYEE_KEYS.has(fold(k)));
    setIfDefined(facts, "fields", [...sensitive, ...rest].join(", ") || undefined);
  }
  return {
    headline: `Confirm Xero employee mutation (${input.operationId})`,
    facts: finish(facts, unexpected, reader, input.inspectorSummary),
  };
};

// --- contact edits (per-op renderer) -------------------------------------

/** createContacts / updateOrCreateContacts (F2-1): the facts are the
 *  inspector's summary (contactId, name, then `old → new` per sensitive
 *  field) in its insertion order. A top-level key beside the `Contacts`
 *  wrapper is listed under `unexpectedKeys`; a flat contact body has none. */
export const contactChange: ElicitRenderer = (input) => {
  const reader = new Reader();
  let unexpected: string[] = [];
  const body = input.body;
  if (isRecord(body) && getCaseInsensitive(body, "Contacts").present) {
    unexpected = Object.keys(body).filter((k) => fold(k) !== fold("Contacts"));
  }
  return {
    headline: `Confirm Xero contact change (${input.operationId})`,
    facts: finish({}, unexpected, reader, input.inspectorSummary),
  };
};

export const xeroElicitRenderers: {
  external_data_flow: ElicitRenderer;
  financial_legal: ElicitRenderer;
  persistent_state: ElicitRenderer;
} = {
  external_data_flow: externalDataFlow,
  financial_legal: financialLegal,
  persistent_state: persistentState,
};
