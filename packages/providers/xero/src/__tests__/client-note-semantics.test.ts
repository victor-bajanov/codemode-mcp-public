// Semantic verification of Xero `clientNote` prose against the REAL inspectors.
//
// String matching was shown to accept notes stating the opposite of their
// inspector (e.g. "`IsReconciled: true` is allowed", or listing AUTHORISED as a
// permitted Status). So the value sets a note advertises are PARSED OUT of the
// prose and compared, value by value, against what the inspector actually
// returns for a request carrying that value. Adding a value to the prose fails
// unless the inspector really accepts it, and removing one fails if it does.

import { describe, it, expect } from "vitest";
import type { InspectRequest, InspectResult, SurfaceReviewEntry } from "@local/shared";
import { surfaceReview } from "../surface-review";

function run(opId: string, req: InspectRequest): InspectResult {
  const entry: SurfaceReviewEntry | undefined = surfaceReview[opId];
  if (!entry?.inspect) throw new Error(`${opId} has no inspector`);
  return entry.inspect(req);
}
const noteOf = (opId: string): string => surfaceReview[opId]?.clientNote ?? "";

/** Quoted UPPERCASE tokens inside the note's `must be "A" or "B"` clause. */
function advertisedValues(note: string, field: string): string[] {
  const clause = new RegExp(`\`${field}\`[^.]*?must be ([^.]*)\\.`).exec(note);
  if (!clause) throw new Error(`note has no \`${field}\` must-be clause: ${note.slice(0, 120)}`);
  return [...clause[1]!.matchAll(/"([A-Z]+)"/g)].map((m) => m[1]!);
}

const INVOICE_OPS = [
  "xero.accounting.createInvoices",
  "xero.accounting.updateOrCreateInvoices",
  "xero.accounting.updateInvoice",
];
const CREDIT_NOTE_OPS = [
  "xero.accounting.createCreditNotes",
  "xero.accounting.updateOrCreateCreditNotes",
  "xero.accounting.updateCreditNote",
];
const BANK_TX_OPS = [
  "xero.accounting.createBankTransactions",
  "xero.accounting.updateBankTransaction",
];

/** Every Status the Xero lifecycle can present, permitted or not. */
const ALL_STATUSES = ["DRAFT", "SUBMITTED", "AUTHORISED", "PAID", "VOIDED", "DELETED"];

describe("draft-status notes state what the draft inspectors do", () => {
  const cases = [
    { ops: INVOICE_OPS, arrayKey: "Invoices", idField: "InvoiceID" },
    { ops: CREDIT_NOTE_OPS, arrayKey: "CreditNotes", idField: "CreditNoteID" },
  ];

  it("the Status set the note advertises is EXACTLY the set the inspector allows", () => {
    for (const { ops, arrayKey, idField } of cases) {
      for (const op of ops) {
        const advertised = new Set(advertisedValues(noteOf(op), "Status"));
        for (const status of ALL_STATUSES) {
          const decision = run(op, { body: { [arrayKey]: [{ Status: status, [idField]: "id-1" }] } }).decision;
          const inspectorAllows = decision === "allow";
          expect(
            advertised.has(status),
            `${op}: note ${advertised.has(status) ? "advertises" : "omits"} ${status} but inspector returned ${decision}`,
          ).toBe(inspectorAllows);
        }
      }
    }
  });

  it("SentToContact: true is denied, and the note says denied", () => {
    for (const { ops, arrayKey, idField } of cases) {
      for (const op of ops) {
        const result = run(op, {
          body: { [arrayKey]: [{ Status: "DRAFT", [idField]: "id-1", SentToContact: true }] },
        });
        expect(result.decision, op).toBe("deny");
        expect(noteOf(op), op).toMatch(/`?SentToContact: true`? is denied/i);
        expect(noteOf(op), op).not.toMatch(/SentToContact[^.]*is allowed/i);
      }
    }
  });

  it("Status omitted needs the id IN THE BODY, exactly as the note claims", () => {
    for (const { ops, arrayKey, idField } of cases) {
      for (const op of ops) {
        expect(run(op, { body: { [arrayKey]: [{ [idField]: "id-1" }] } }).decision, `${op} with id`).toBe("allow");
        expect(run(op, { body: { [arrayKey]: [{}] } }).decision, `${op} without id`).toBe("deny");
        expect(noteOf(op), op).toContain(idField);
        expect(noteOf(op), op).toMatch(/read from the body, not the path/i);
      }
    }
  });

  it("an empty payload is denied, as the note claims", () => {
    for (const { ops } of cases) {
      for (const op of ops) {
        expect(run(op, { body: {} }).decision, op).toBe("deny");
        expect(noteOf(op), op).toMatch(/empty payload is denied/i);
      }
    }
  });
});

describe("bank-transaction notes state what inspectBankTxCreate does", () => {
  const ALL_TYPES = ["SPEND", "RECEIVE", "TRANSFER", "OVERPAYMENT", "PREPAYMENT"];

  it("the Type set the note advertises is EXACTLY the set the inspector allows", () => {
    for (const op of BANK_TX_OPS) {
      const advertised = new Set(advertisedValues(noteOf(op), "Type"));
      for (const type of ALL_TYPES) {
        const decision = run(op, { body: { BankTransactions: [{ Type: type }] } }).decision;
        expect(
          advertised.has(type),
          `${op}: note vs inspector disagree on Type ${type} (inspector: ${decision})`,
        ).toBe(decision === "allow");
      }
    }
  });

  it("the Status set the note advertises is EXACTLY the set the inspector allows", () => {
    for (const op of BANK_TX_OPS) {
      const advertised = new Set(advertisedValues(noteOf(op), "Status"));
      for (const status of ALL_STATUSES) {
        const decision = run(op, { body: { BankTransactions: [{ Type: "SPEND", Status: status }] } }).decision;
        expect(
          advertised.has(status),
          `${op}: note vs inspector disagree on Status ${status} (inspector: ${decision})`,
        ).toBe(decision === "allow");
      }
    }
  });

  it("IsReconciled: true is DENIED, and the note says denied — never allowed", () => {
    for (const op of BANK_TX_OPS) {
      const result = run(op, { body: { BankTransactions: [{ Type: "SPEND", IsReconciled: true }] } });
      expect(result.decision, op).toBe("deny");
      expect(noteOf(op), op).toMatch(/`?IsReconciled: true`? is denied/i);
      expect(noteOf(op), op).not.toMatch(/IsReconciled[^.]*is allowed/i);
    }
  });

  it("omitting Status is fine, as the note claims", () => {
    for (const op of BANK_TX_OPS) {
      expect(run(op, { body: { BankTransactions: [{ Type: "SPEND" }] } }).decision, op).toBe("allow");
      expect(noteOf(op), op).toMatch(/omitting it is fine/i);
    }
  });

  it("the BankTransactions wrapper is required, as the note claims", () => {
    for (const op of BANK_TX_OPS) {
      expect(run(op, { body: { Type: "SPEND" } }).decision, op).toBe("deny");
      expect(noteOf(op), op).toMatch(/requires a non-empty `?BankTransactions`? array/i);
    }
  });
});

// F-10: Xero's deserialiser matches property names case-insensitively and
// coerces "true", so a note's "is denied" claim must hold however the gated key
// is spelt and whichever lenient truthy value it carries, not only for the
// exact spelling the note uses.
describe("the notes' denial claims survive Xero's lenient parsing", () => {
  const draftCases = [
    { ops: INVOICE_OPS, arrayKey: "Invoices", idField: "InvoiceID" },
    { ops: CREDIT_NOTE_OPS, arrayKey: "CreditNotes", idField: "CreditNoteID" },
  ];

  it("a Status the note omits is denied under any key casing, wrapper casing included", () => {
    for (const { ops, arrayKey, idField } of draftCases) {
      for (const op of ops) {
        const advertised = new Set(advertisedValues(noteOf(op), "Status"));
        for (const status of ALL_STATUSES.filter((s) => !advertised.has(s))) {
          for (const statusKey of ["status", "STATUS"]) {
            for (const wrapper of [arrayKey, arrayKey.toLowerCase()]) {
              const decision = run(op, { body: { [wrapper]: [{ [statusKey]: status, [idField]: "id-1" }] } }).decision;
              expect(decision, `${op} ${wrapper}[].${statusKey}=${status}`).toBe("deny");
            }
          }
        }
      }
    }
  });

  it("SentToContact is denied for every lenient truthy spelling", () => {
    for (const { ops, arrayKey, idField } of draftCases) {
      for (const op of ops) {
        for (const [key, value] of [["SentToContact", "true"], ["SentToContact", 1], ["sentToContact", true]] as const) {
          const result = run(op, { body: { [arrayKey]: [{ Status: "DRAFT", [idField]: "id-1", [key]: value }] } });
          expect(result.decision, `${op} ${key}=${JSON.stringify(value)}`).toBe("deny");
        }
      }
    }
  });

  it("a Type or Status the bank-transaction note omits is denied under any key casing", () => {
    for (const op of BANK_TX_OPS) {
      expect(run(op, { body: { BankTransactions: [{ type: "TRANSFER" }] } }).decision, op).toBe("deny");
      const advertised = new Set(advertisedValues(noteOf(op), "Status"));
      for (const status of ALL_STATUSES.filter((s) => !advertised.has(s))) {
        const decision = run(op, { body: { banktransactions: [{ Type: "SPEND", status }] } }).decision;
        expect(decision, `${op} status=${status}`).toBe("deny");
      }
    }
  });

  it("IsReconciled is denied for every lenient truthy spelling", () => {
    for (const op of BANK_TX_OPS) {
      for (const [key, value] of [["IsReconciled", "true"], ["IsReconciled", 1], ["isReconciled", true]] as const) {
        const result = run(op, { body: { BankTransactions: [{ Type: "SPEND", [key]: value }] } });
        expect(result.decision, `${op} ${key}=${JSON.stringify(value)}`).toBe("deny");
      }
    }
  });
});

// MUST-FIX A: the journals note previously called `/Journals` "the manual-journals
// ledger" and steered the model away from it. `/Journals` is the general-ledger
// journal-lines endpoint (accounting.journals.read, ungranted); ManualJournals is
// a DIFFERENT endpoint whose scope IS granted and which works fine.
describe("the journals scope note names the right endpoint", () => {
  const JOURNAL_OPS = [
    "xero.accounting.getJournals",
    "xero.accounting.getJournal",
    "xero.accounting.getJournalByNumber",
  ];

  it("manual journals really are reachable, so the note must not disclaim them", () => {
    for (const id of ["xero.accounting.getManualJournals", "xero.accounting.getManualJournal"]) {
      expect(surfaceReview[id]?.decision, id).toBe("allow");
      expect(surfaceReview[id]?.clientNote, `${id} should be unblocked`).toBeUndefined();
    }
  });

  it("does not tell the model the manual-journals ledger is unavailable", () => {
    for (const id of JOURNAL_OPS) {
      const note = noteOf(id);
      expect(note, id).not.toMatch(/manual-journals ledger/i);
      expect(note, id).not.toMatch(/instead of the manual/i);
    }
  });

  it("describes /Journals as the general-ledger journal lines", () => {
    for (const id of JOURNAL_OPS) {
      expect(noteOf(id), id).toMatch(/general[- ]ledger/i);
    }
  });

  it("points at ManualJournals as the endpoint that DOES work", () => {
    for (const id of JOURNAL_OPS) {
      expect(noteOf(id), id).toMatch(/ManualJournals/);
    }
  });
});
