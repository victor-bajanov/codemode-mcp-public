// Semantic verification of Xero `clientNote` prose against the REAL inspectors.
//
// String matching was shown to accept notes stating the opposite of their
// inspector (e.g. "`IsReconciled: true` is allowed", or listing AUTHORISED as a
// permitted Status). So the value sets a note advertises are PARSED OUT of the
// prose and compared, value by value, against what the inspector actually
// returns for a request carrying that value. Adding a value to the prose fails
// unless the inspector really accepts it, and removing one fails if it does.

import { describe, it, expect } from "vitest";
import type {
  InspectRequest,
  InspectResult,
  SurfaceReviewEntry,
  UpstreamLookup,
  UpstreamLookupResult,
} from "@local/shared";
import { surfaceReview } from "../surface-review";

function run(opId: string, req: InspectRequest): InspectResult {
  const entry: SurfaceReviewEntry | undefined = surfaceReview[opId];
  if (!entry?.inspect) throw new Error(`${opId} has no inspector`);
  return entry.inspect(req);
}
const noteOf = (opId: string): string => surfaceReview[opId]?.clientNote ?? "";

/** Runs the entry's `inspectUpstream` hook against a fake lookup that answers
 *  every GET with `answer` (by path when a function) and records the paths. */
async function runHook(
  opId: string,
  req: InspectRequest,
  answer: UpstreamLookupResult | ((path: string) => UpstreamLookupResult),
): Promise<{ result: InspectResult; paths: string[] }> {
  const entry: SurfaceReviewEntry | undefined = surfaceReview[opId];
  if (!entry?.inspectUpstream) throw new Error(`${opId} has no inspectUpstream hook`);
  const paths: string[] = [];
  const lookup: UpstreamLookup = {
    get: async (path: string) => {
      paths.push(path);
      return typeof answer === "function" ? answer(path) : answer;
    },
  };
  return { result: await entry.inspectUpstream(req, lookup), paths };
}

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

  // F2-4 (wave 3): the note used to say Status may be omitted when the body
  // carries the id, and the inspector allowed exactly that — which edited
  // posted documents. Omitting Status is now denied with and without the id.
  it("FIXED (F2-4): Status omitted is denied with and without the id, and the note says Status is required", () => {
    for (const { ops, arrayKey, idField } of cases) {
      for (const op of ops) {
        const withId = run(op, { body: { [arrayKey]: [{ [idField]: "id-1" }] } });
        expect(withId.decision, `${op} with id`).toBe("deny");
        expect(withId.reason, `${op} with id`).toMatch(/-status-required$/);
        expect(run(op, { body: { [arrayKey]: [{}] } }).decision, `${op} without id`).toBe("deny");
        expect(run(op, { body: { [arrayKey]: [{ [idField]: "id-1", Status: null }] } }).decision, `${op} null`).toBe("deny");
        expect(noteOf(op), op).toMatch(/`Status` is required/);
        expect(noteOf(op), op).not.toMatch(/may be omitted/i);
        expect(noteOf(op), op).not.toMatch(/read from the body, not the path/i);
      }
    }
  });

  it("the by-id body id must equal the path id, as the note claims", () => {
    for (const { ops, arrayKey, idField } of cases) {
      const byId = ops[2]!;
      const pathParams = { [idField]: "path-id" };
      const mismatch = run(byId, { body: { [arrayKey]: [{ [idField]: "other-id", Status: "DRAFT" }] }, pathParams });
      expect(mismatch.decision, byId).toBe("deny");
      expect(mismatch.reason, byId).toMatch(/-id-mismatch$/);
      expect(run(byId, { body: { [arrayKey]: [{ [idField]: "PATH-ID", Status: "DRAFT" }] }, pathParams }).decision, byId).toBe("allow");
      expect(noteOf(byId), byId).toMatch(/must equal the path id/);
    }
  });

  it("an item carrying the id is read from Xero first and denied unless the stored document is DRAFT or SUBMITTED", async () => {
    for (const { ops, arrayKey, idField } of cases) {
      for (const op of ops) {
        const req = { body: { [arrayKey]: [{ [idField]: "id-1", Status: "DRAFT" }] } };
        for (const stored of ALL_STATUSES) {
          const { result, paths } = await runHook(op, req, {
            status: 200,
            body: { [arrayKey]: [{ [idField]: "id-1", Status: stored }] },
          });
          expect(paths.length, `${op} stored ${stored}`).toBe(1);
          const allowed = stored === "DRAFT" || stored === "SUBMITTED";
          expect(result.decision, `${op} stored ${stored}`).toBe(allowed ? "allow" : "deny");
        }
        expect(noteOf(op), op).toContain(`\`${idField}\` is read from Xero before sending`);
        expect(noteOf(op), op).toMatch(/stored [a-z ]+ is itself DRAFT or SUBMITTED/);
        expect(noteOf(op).toLowerCase(), op).toContain(`at most 4 items carrying \`${idField.toLowerCase()}\` or`);
      }
    }
  });

  it("an item with a document number and no id is read by that number first, as the note claims", async () => {
    const numbered = [
      { ops: INVOICE_OPS.slice(0, 2), arrayKey: "Invoices", numberField: "InvoiceNumber" },
      { ops: CREDIT_NOTE_OPS.slice(0, 2), arrayKey: "CreditNotes", numberField: "CreditNoteNumber" },
    ];
    for (const { ops, arrayKey, numberField } of numbered) {
      for (const op of ops) {
        const req = { body: { [arrayKey]: [{ [numberField]: "INV-0042", Status: "DRAFT" }] } };
        const created = await runHook(op, req, { status: 404, body: {} });
        expect(created.paths.length, op).toBe(1);
        expect(created.result.decision, `${op} 404 = create`).toBe("allow");
        const posted = await runHook(op, req, { status: 200, body: { [arrayKey]: [{ Status: "AUTHORISED" }] } });
        expect(posted.result.decision, `${op} posted`).toBe("deny");
        expect(noteOf(op), op).toContain(numberField);
      }
    }
  });

  it("numbered creates count toward the 4-read cap, as the note claims", async () => {
    const numbered = [
      { ops: INVOICE_OPS.slice(0, 2), arrayKey: "Invoices", idField: "InvoiceID", numberField: "InvoiceNumber" },
      { ops: CREDIT_NOTE_OPS.slice(0, 2), arrayKey: "CreditNotes", idField: "CreditNoteID", numberField: "CreditNoteNumber" },
    ];
    for (const { ops, arrayKey, idField, numberField } of numbered) {
      for (const op of ops) {
        const items = Array.from({ length: 5 }, (_, i) => ({ [numberField]: `N-${i}`, Status: "DRAFT" }));
        const { result, paths } = await runHook(op, { body: { [arrayKey]: items } }, { status: 404, body: {} });
        expect(paths, op).toEqual([]);
        expect(result.reason, op).toMatch(/-too-many-updates$/);
        expect(noteOf(op), op).toContain(`At most 4 items carrying \`${idField}\` or \`${numberField}\` per request`);
        expect(noteOf(op), op).toMatch(/numbered creates included/);
      }
    }
  });

  it("the ContactNumber-match rule is scoped to gated edits in the contact note", () => {
    for (const op of ["xero.accounting.createContacts", "xero.accounting.updateOrCreateContacts"]) {
      expect(noteOf(op), op).toMatch(/In such an edit, if both `ContactID` and `ContactNumber` are sent/);
    }
  });

  it("the inline Contact may not carry payee details, as the note claims", () => {
    for (const { ops, arrayKey } of cases) {
      for (const op of ops) {
        const result = run(op, {
          body: { [arrayKey]: [{ Status: "DRAFT", Contact: { ContactID: "c-1", BankAccountDetails: "062-000 1" } }] },
        });
        expect(result.decision, op).toBe("deny");
        expect(result.reason, op).toMatch(/-inline-contact-details$/);
        expect(noteOf(op), op).toMatch(/inline `Contact` may not carry bank/);
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

// F2-2 (wave 3): repeating-invoice templates were bare allows.
describe("repeating-invoice notes state what the repeating-invoice inspector and hook do", () => {
  const REPEATING_OPS = [
    "xero.accounting.createRepeatingInvoices",
    "xero.accounting.updateOrCreateRepeatingInvoices",
    "xero.accounting.updateRepeatingInvoice",
  ];

  it("only an explicit DRAFT Status is allowed, as the note claims", () => {
    for (const op of REPEATING_OPS) {
      for (const status of [...ALL_STATUSES, "draft"]) {
        const decision = run(op, { body: { RepeatingInvoices: [{ Status: status }] } }).decision;
        expect(decision, `${op} ${status}`).toBe(status.toUpperCase() === "DRAFT" ? "allow" : "deny");
      }
      expect(run(op, { body: { RepeatingInvoices: [{ Reference: "x" }] } }).decision, op).toBe("deny");
      expect(noteOf(op), op).toMatch(/must carry `Status: "DRAFT"`/);
      expect(noteOf(op), op).toMatch(/omitting it[^.]* are denied/);
    }
  });

  it("every send flag the note names is denied", () => {
    for (const op of REPEATING_OPS) {
      for (const flag of ["ApprovedForSending", "SendCopy", "MarkAsSent", "IncludePDF"]) {
        expect(run(op, { body: { RepeatingInvoices: [{ Status: "DRAFT", [flag]: true }] } }).decision, `${op} ${flag}`).toBe("deny");
        expect(noteOf(op), `${op} ${flag}`).toContain(`\`${flag}\``);
      }
    }
  });

  it("an item naming a template (RepeatingInvoiceID or ID) is read first and denied unless the stored template is DRAFT", async () => {
    for (const op of REPEATING_OPS) {
      for (const idKey of ["RepeatingInvoiceID", "ID"]) {
        const req = { body: { RepeatingInvoices: [{ [idKey]: "t-1", Status: "DRAFT" }] } };
        for (const [stored, expected] of [["DRAFT", "allow"], ["AUTHORISED", "deny"], ["DELETED", "deny"]] as const) {
          const { result, paths } = await runHook(op, req, {
            status: 200,
            body: { RepeatingInvoices: [{ RepeatingInvoiceID: "t-1", Status: stored }] },
          });
          expect(paths.length, `${op} ${idKey} ${stored}`).toBe(1);
          expect(result.decision, `${op} ${idKey} ${stored}`).toBe(expected);
        }
      }
      expect(noteOf(op), op).toMatch(/`RepeatingInvoiceID` \(or `ID`\) is read from Xero first/);
      expect(noteOf(op), op).toMatch(/at most 4/);
    }
  });

  it("nothing may sit beside RepeatingInvoices, and the by-id endpoint takes one item, as the note claims", () => {
    for (const op of REPEATING_OPS) {
      expect(run(op, { body: { RepeatingInvoices: [{ Status: "DRAFT" }], Status: "DRAFT" } }).decision, op).toBe("deny");
      expect(noteOf(op), op).toMatch(/nothing may sit beside `RepeatingInvoices`/i);
    }
    const byId = "xero.accounting.updateRepeatingInvoice";
    const two = run(byId, {
      body: { RepeatingInvoices: [{ Status: "DRAFT" }, { Status: "DRAFT" }] },
      pathParams: { RepeatingInvoiceID: "t-1" },
    });
    expect(two.decision).toBe("deny");
    expect(noteOf(byId)).toMatch(/by-id endpoint takes exactly one item/);
  });
});

// F2-1 (wave 3): contact writes were bare allows. User decision F2-1: an edit
// that changes Name or XeroNetworkKey needs approval too.
describe("contact notes state what the contact inspector and hook do", () => {
  const CONTACT_OPS = ["xero.accounting.createContacts", "xero.accounting.updateOrCreateContacts"];
  const ID = "6d5c1b0e-1111-4222-8333-944455556666";
  const stored = (extra: Record<string, unknown> = {}): UpstreamLookupResult => ({
    status: 200,
    body: { Contacts: [{ ContactID: ID, Name: "Acme Supplies", BankAccountDetails: "062-000 1111", ...extra }] },
  });

  it("creates are allowed with any fields, payee details included, and the note says so", () => {
    for (const op of CONTACT_OPS) {
      const req = { body: { Contacts: [{ Name: "New Co", EmailAddress: "a@b.example", BankAccountDetails: "1" }] } };
      expect(run(op, req).decision, op).toBe("allow");
      expect(noteOf(op), op).toMatch(/Creating contacts is allowed with any fields/);
    }
  });

  it("an edit carrying any sensitive field the note names asks for approval; a plain edit is allowed", () => {
    for (const op of CONTACT_OPS) {
      for (const [field, value] of [
        ["BankAccountDetails", "062-000 2"],
        ["BatchPayments", { BankAccountNumber: "062-000 2" }],
        ["EmailAddress", "x@attacker.example"],
        ["ContactStatus", "ARCHIVED"],
        ["TaxNumber", "12 345"],
        ["ContactPersons", [{ EmailAddress: "p@attacker.example", IncludeInEmails: true }]],
      ] as const) {
        expect(run(op, { body: { Contacts: [{ ContactID: ID, [field]: value }] } }).decision, `${op} ${field}`).toBe("elicit");
        expect(noteOf(op), `${op} ${field}`).toContain(`\`${field}\``);
      }
      expect(run(op, { body: { Contacts: [{ ContactID: ID, Phones: [] }] } }).decision, `${op} plain`).toBe("allow");
      expect(noteOf(op), op).toMatch(/user is asked to approve/);
    }
  });

  it("FIXED (F2-1, user decision): an edit that changes Name or XeroNetworkKey asks for approval; an unchanged echo is allowed", async () => {
    for (const op of CONTACT_OPS) {
      const rename = await runHook(op, { body: { Contacts: [{ ContactID: ID, Name: "Mallory Ltd" }] } }, stored());
      expect(rename.paths.length, op).toBe(1);
      expect(rename.result.decision, `${op} rename`).toBe("elicit");
      const echo = await runHook(op, { body: { Contacts: [{ ContactID: ID, Name: "Acme Supplies" }] } }, stored());
      expect(echo.result.decision, `${op} echo`).toBe("allow");
      const xnk = await runHook(op, { body: { Contacts: [{ ContactID: ID, XeroNetworkKey: "k-2" }] } }, stored());
      expect(xnk.result.decision, `${op} xnk`).toBe("elicit");
      expect(noteOf(op), op).toMatch(/changes `Name` or `XeroNetworkKey`/);
      expect(noteOf(op), op).toMatch(/unchanged/);
    }
  });

  it("a gated edit must be the only contact in its request, and nothing may sit beside Contacts", () => {
    for (const op of CONTACT_OPS) {
      const two = run(op, { body: { Contacts: [{ ContactID: ID, EmailAddress: "x@a.example" }, { Name: "B" }] } });
      expect(two.reason, op).toBe("contact-one-per-request");
      const renameBeside = run(op, { body: { Contacts: [{ ContactID: ID, Name: "X" }, { Name: "B" }] } });
      expect(renameBeside.reason, op).toBe("contact-one-per-request");
      expect(noteOf(op), op).toMatch(/exactly one contact per such request/);
      const beside = run(op, { body: { Contacts: [{ Name: "B" }], BankAccountDetails: "1" } });
      expect(beside.reason, op).toBe("contact-unexpected-key");
      expect(noteOf(op), op).toMatch(/nothing may sit beside the `Contacts` array/i);
    }
  });

  it("at most 3 ContactPersons per edit, and the number limit the note states matches", () => {
    for (const op of CONTACT_OPS) {
      const persons = (n: number) => Array.from({ length: n }, (_, i) => ({ EmailAddress: `p${i}@a.example`, IncludeInEmails: false }));
      expect(run(op, { body: { Contacts: [{ ContactID: ID, ContactPersons: persons(3) }] } }).decision, op).toBe("elicit");
      expect(run(op, { body: { Contacts: [{ ContactID: ID, ContactPersons: persons(4) }] } }).reason, op).toBe("contact-too-many-persons");
      expect(noteOf(op), op).toMatch(/at most 3 `ContactPersons`/);
    }
  });

  it("a ContactNumber sent beside ContactID must match the stored one, as the note claims", async () => {
    for (const op of CONTACT_OPS) {
      const req = { body: { Contacts: [{ ContactID: ID, ContactNumber: "N-2", EmailAddress: "x@a.example" }] } };
      const { result } = await runHook(op, req, stored({ ContactNumber: "N-1" }));
      expect(result.reason, op).toBe("contact-number-mismatch");
      expect(noteOf(op), op).toMatch(/`ContactNumber` must match the stored/);
    }
  });
});

// F2-5 (wave 3): attachment uploads were bare allows.
describe("attachment notes state what inspectAttachmentUpload does", () => {
  const ATTACHMENT_OPS = [
    "xero.accounting.createInvoiceAttachmentByFileName",
    "xero.accounting.createCreditNoteAttachmentByFileName",
  ];
  const pdf = { contentType: "application/pdf", rawBody: "%PDF-1.4" };

  it("IncludeOnline is denied, as the note claims; a plain upload is allowed", () => {
    for (const op of ATTACHMENT_OPS) {
      expect(run(op, pdf).decision, op).toBe("allow");
      expect(run(op, { ...pdf, query: { IncludeOnline: "true" } }).decision, op).toBe("deny");
      expect(noteOf(op), op).toMatch(/`IncludeOnline` is denied/);
    }
  });

  it("every MIME type the note lists is accepted, and one it does not list is denied", () => {
    for (const op of ATTACHMENT_OPS) {
      for (const ct of ["application/pdf", "image/png", "image/jpeg", "image/gif", "text/csv", "application/vnd.ms-excel", "application/msword"]) {
        expect(noteOf(op), `${op} ${ct}`).toContain(ct);
        expect(run(op, { ...pdf, contentType: ct }).decision, `${op} ${ct}`).toBe("allow");
      }
      expect(run(op, { ...pdf, contentType: "application/x-msdownload" }).decision, op).toBe("deny");
      expect(run(op, { body: { x: 1 }, contentType: "application/pdf" }).decision, op).toBe("deny");
      for (const ct of [
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      ]) {
        expect(noteOf(op), `${op} ${ct}`).toContain(ct);
      }
      expect(noteOf(op), op).toMatch(/JSON or multipart body/);
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
