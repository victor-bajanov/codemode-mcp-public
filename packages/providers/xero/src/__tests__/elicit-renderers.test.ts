// Unit tests for the Xero approval-dialog renderers (D-1). A renderer returns
// a headline and the resolved facts the dialog SHOWS; targets come from the
// path parameters, amounts/payees from the body the way Xero reads it (keys
// matched case-insensitively), and anything the renderer cannot read
// unambiguously is flagged rather than silently dropped.

import { describe, it, expect } from "vitest";
import type { ElicitRendererInput } from "@local/shared";
import { contactChange, xeroElicitRenderers } from "../elicit-renderers";

function input(partial: Partial<ElicitRendererInput> & { operationId: string }): ElicitRendererInput {
  return { method: "POST", path: "/", pathParams: {}, body: undefined, ...partial };
}

describe("xero elicit-renderers — external_data_flow (emailInvoice)", () => {
  const r = xeroElicitRenderers.external_data_flow;
  const op = "xero.accounting.emailInvoice";

  it("takes invoiceId from the path parameters", () => {
    const out = r(input({
      operationId: op,
      path: "/api.xro/2.0/Invoices/aaaa-1/Email",
      pathParams: { InvoiceID: "aaaa-1" },
      body: {},
    }));
    expect(out.headline).toBe(`Confirm Xero email invoice (${op})`);
    expect(out.facts).toEqual({ invoiceId: "aaaa-1" });
  });

  it("never takes the invoice id from the body", () => {
    const out = r(input({
      operationId: op,
      pathParams: { InvoiceID: "PATH-ID" },
      body: { InvoiceID: "BODY-DECOY", invoiceId: "BODY-DECOY" },
    }));
    expect(out.facts.invoiceId).toBe("PATH-ID");
    expect(JSON.stringify(out)).not.toContain("BODY-DECOY");
  });

  it("appends inspector summary primitives after the path facts (path wins)", () => {
    const out = r(input({
      operationId: op,
      pathParams: { InvoiceID: "PATH-ID" },
      inspectorSummary: { invoiceId: "SUMMARY-ID", to: "ap@supplier.example" },
    }));
    expect(out.facts).toEqual({ invoiceId: "PATH-ID", to: "ap@supplier.example" });
  });

  it("returns a headline and no confirm fact when nothing is known", () => {
    const out = r(input({ operationId: op }));
    expect(out.headline).toBe(`Confirm Xero email invoice (${op})`);
    expect(out.facts).toEqual({});
  });
});

describe("xero elicit-renderers — financial_legal: createBatchPayment", () => {
  const r = xeroElicitRenderers.financial_legal;
  const op = "xero.accounting.createBatchPayment";
  const realBatch = {
    BatchPayments: [
      {
        Account: { AccountID: "acct-operating" },
        Date: "2026-11-10",
        Reference: "Nov supplier run",
        Payments: [
          { Invoice: { InvoiceID: "inv-1" }, BankAccountNumber: "062-000 13371337", Amount: 92500 },
          { Invoice: { InvoiceID: "inv-2" }, BankAccountNumber: "062-000 13371337", Amount: 92500 },
        ],
      },
    ],
  };

  it("summarises the real BatchPayments[].Payments[] shape", () => {
    const out = r(input({ operationId: op, method: "PUT", body: realBatch }));
    expect(out.headline).toBe(`Confirm Xero financial op (${op})`);
    expect(out.facts).toEqual({
      batches: 1,
      payments: 2,
      total: 185000,
      accounts: "acct-operating",
      bankAccounts: "062-000 13371337",
      targets: "Invoice inv-1, Invoice inv-2",
    });
  });

  it("lists at most three distinct values with a (+N) suffix", () => {
    const body = {
      BatchPayments: [1, 2, 3, 4].map((i) => ({
        Account: { AccountID: `acct-${i}` },
        Payments: [{ Invoice: { InvoiceID: `inv-${i}` }, BankAccountNumber: `bank-${i}`, Amount: 1 }],
      })),
    };
    const out = r(input({ operationId: op, body }));
    expect(out.facts).toMatchObject({
      batches: 4,
      payments: 4,
      total: 4,
      accounts: "acct-1, acct-2, acct-3 (+1)",
      bankAccounts: "bank-1, bank-2, bank-3 (+1)",
      targets: "Invoice inv-1, Invoice inv-2, Invoice inv-3 (+1)",
    });
  });

  it("total is 'not numeric' when any Amount is missing or not a finite number", () => {
    for (const bad of [undefined, "92500", null, { v: 1 }, Number.POSITIVE_INFINITY]) {
      const body = { BatchPayments: [{ Payments: [{ Amount: 1 }, { Amount: bad }] }] };
      const out = r(input({ operationId: op, body }));
      expect(out.facts.total, String(bad)).toBe("not numeric");
    }
  });

  it("total has no floating-point noise", () => {
    const body = { BatchPayments: [{ Payments: [{ Amount: 0.1 }, { Amount: 0.2 }] }] };
    expect(r(input({ operationId: op, body })).facts.total).toBe(0.3);
  });

  it("a decoy top-level Payments key beside the wrapper is flagged and makes the total unreadable (F2-3 decoy)", () => {
    const out = r(input({ operationId: op, body: { ...realBatch, Payments: [{ Amount: 1 }] } }));
    expect(out.facts.total).toBe("not numeric");
    expect(out.facts.payments).toBe(2);
    expect(out.facts.unexpectedKeys).toBe("Payments");
    expect(out.facts.shape).toBe("batch keys beside BatchPayments");
  });

  it("a top-level Account beside the wrapper also makes the total unreadable", () => {
    const out = r(input({ operationId: op, body: { ...realBatch, account: { AccountID: "x" } } }));
    expect(out.facts.total).toBe("not numeric");
    expect(out.facts.unexpectedKeys).toBe("account");
  });

  it("reads keys case-insensitively, as Xero does", () => {
    const body = {
      batchpayments: [{
        account: { accountid: "acct-lower" },
        payments: [{ invoice: { invoiceid: "inv-lower" }, bankaccountnumber: "bank-lower", amount: 99999 }],
      }],
    };
    const out = r(input({ operationId: op, body }));
    expect(out.facts).toMatchObject({
      batches: 1, payments: 1, total: 99999,
      accounts: "acct-lower", bankAccounts: "bank-lower", targets: "Invoice inv-lower",
    });
    expect(out.facts.unexpectedKeys).toBeUndefined();
  });

  it("two spellings of Amount make the total unreadable and are flagged", () => {
    const body = { BatchPayments: [{ Payments: [{ Amount: 1, amount: 99999 }] }] };
    const out = r(input({ operationId: op, body }));
    expect(out.facts.total).toBe("not numeric");
    expect(out.facts.ambiguousKeys).toBe("Amount");
  });

  it("two spellings of a batch's Payments list make the total unreadable", () => {
    const body = { BatchPayments: [{ Payments: [{ Amount: 1 }], payments: [{ Amount: 99999 }] }] };
    const out = r(input({ operationId: op, body }));
    expect(out.facts.ambiguousKeys).toBe("Payments");
    expect(out.facts.total).toBe("not numeric");
  });

  it("two spellings of the BatchPayments wrapper are flagged", () => {
    const body = { BatchPayments: [{ Payments: [{ Amount: 1 }] }], batchPayments: [{ Payments: [{ Amount: 99999 }] }] };
    const out = r(input({ operationId: op, body }));
    expect(out.facts.ambiguousKeys).toBe("BatchPayments");
    expect(out.facts.total).toBe("not numeric");
  });

  it("falls back to Account.Code and Invoice.InvoiceNumber when ids are absent", () => {
    const body = {
      BatchPayments: [{
        Account: { Code: "090" },
        Payments: [{ Invoice: { InvoiceNumber: "INV-0042" }, Amount: 5 }],
      }],
    };
    const out = r(input({ operationId: op, body }));
    expect(out.facts).toMatchObject({ accounts: "090", targets: "Invoice INV-0042" });
  });

  it("does not use a payment-level InvoiceNumber", () => {
    const body = { BatchPayments: [{ Payments: [{ InvoiceNumber: "INV-DECOY", Amount: 5 }] }] };
    const out = r(input({ operationId: op, body }));
    expect(out.facts.targets).toBeUndefined();
    expect(JSON.stringify(out.facts)).not.toContain("INV-DECOY");
  });

  it("an ambiguous id never falls through to a lower-priority key", () => {
    const body = {
      BatchPayments: [{
        Account: { AccountID: "acct-a", accountid: "acct-b", Code: "090" },
        Payments: [{ Invoice: { InvoiceID: "inv-a", invoiceID: "inv-b", InvoiceNumber: "INV-DECOY" }, Amount: 5 }],
      }],
    };
    const out = r(input({ operationId: op, body }));
    expect(out.facts.accounts).toBeUndefined();
    expect(out.facts.targets).toBeUndefined();
    expect(out.facts.ambiguousKeys).toBe("AccountID, InvoiceID");
    expect(JSON.stringify(out.facts)).not.toContain("090");
    expect(JSON.stringify(out.facts)).not.toContain("INV-DECOY");
  });

  it("payments against credit notes, prepayments and overpayments name their target", () => {
    const body = {
      BatchPayments: [{
        Payments: [
          { CreditNote: { CreditNoteID: "cn-1" }, Amount: 5 },
          { Prepayment: { PrepaymentID: "pp-1" }, Amount: 5 },
          { Overpayment: { OverpaymentID: "op-1" }, Amount: 5 },
        ],
      }],
    };
    const out = r(input({ operationId: op, body }));
    expect(out.facts.targets).toBe("CreditNote cn-1, Prepayment pp-1, Overpayment op-1");
  });

  it("invoices and other targets share one `targets` fact, so a full numeric dialog fits 8 facts", () => {
    const body = {
      BatchPayments: [{
        Account: { AccountID: "acct-1" },
        Payments: [
          { Invoice: { InvoiceID: "inv-1" }, BankAccountNumber: "bank-1", Amount: 5 },
          { CreditNote: { CreditNoteID: "cn-1" }, BankAccountNumber: "bank-1", Amount: 5 },
        ],
      }],
    };
    const out = r(input({ operationId: op, body }));
    expect(out.facts).toEqual({
      batches: 1, payments: 2, total: 10,
      accounts: "acct-1", bankAccounts: "bank-1", targets: "Invoice inv-1, CreditNote cn-1",
    });
    expect(Object.keys(out.facts).length).toBeLessThanOrEqual(8);
  });

  it("a bare batch lists top-level keys that are not batch properties as unexpected", () => {
    const body = { account: { AccountID: "a" }, Date: "2026-11-10", Reference: "r", Payments: [{ Amount: 5 }], Decoy: 1 };
    const out = r(input({ operationId: op, body }));
    expect(out.facts).toMatchObject({ batches: 1, payments: 1, total: 5, unexpectedKeys: "Decoy" });
  });

  it("a zero-width-spaced BatchPayments key is ambiguous and forces total not numeric (never 0)", () => {
    const key = "BatchPay\u200Bments";
    const out = r(input({ operationId: op, body: { [key]: [{ Payments: [{ Amount: 99999 }] }] } }));
    expect(out.facts.total).toBe("not numeric");
    expect(out.facts.ambiguousKeys).toBe(key);
  });

  it("any Amount <= 0 makes the total unreadable and is counted", () => {
    const body = { BatchPayments: [{ Payments: [{ Amount: 100000 }, { Amount: -99999 }, { Amount: 0 }] }] };
    const out = r(input({ operationId: op, body }));
    expect(out.facts.total).toBe("not numeric");
    expect(out.facts.nonPositiveAmounts).toBe(2);
  });

  it("an empty or missing body yields zero counts and no throw", () => {
    expect(r(input({ operationId: op, body: undefined })).facts).toEqual({ batches: 0, payments: 0, total: 0 });
    expect(r(input({ operationId: op, body: {} })).facts).toEqual({ batches: 0, payments: 0, total: 0 });
  });

  it("a body without the wrapper is read as one bare batch (never total 0)", () => {
    const out = r(input({ operationId: op, body: { Account: { AccountID: "acct-x" }, Payments: [{ Amount: 100 }, { Amount: 50.5 }] } }));
    expect(out.facts).toMatchObject({ batches: 1, payments: 2, total: 150.5, accounts: "acct-x" });
    expect(out.facts.unexpectedKeys).toBeUndefined();
  });

  it("unrecognised shapes make the total unreadable and say why", () => {
    const cases: Array<[unknown, string]> = [
      [{ BatchPayments: { Payments: [{ Amount: 99999 }] } }, "BatchPayments is not a list"],
      [{ BatchPayments: [{ Payments: { Amount: 99999 } }] }, "Payments is not a list"],
      [[{ Payments: [{ Amount: 99999 }] }], "body is a list"],
      [{ BatchPayments: ["x"] }, "batch is not an object"],
      [{ BatchPayments: [{ Payments: ["x"] }] }, "payment is not an object"],
      [{ Payments: { Amount: 99999 } }, "Payments is not a list"],
    ];
    for (const [body, shape] of cases) {
      const out = r(input({ operationId: op, body }));
      expect(out.facts.total, JSON.stringify(body)).toBe("not numeric");
      expect(out.facts.shape, JSON.stringify(body)).toBe(shape);
    }
  });
});

describe("xero elicit-renderers — financial_legal: pay runs", () => {
  const r = xeroElicitRenderers.financial_legal;

  it("createPayRun: count, status and period of the spec's top-level array", () => {
    const out = r(input({
      operationId: "xero.payroll.au.createPayRun",
      body: [{ PayrollCalendarID: "cal-1", PayRunStatus: "DRAFT", PayRunPeriodStartDate: "2026-11-01", PayRunPeriodEndDate: "2026-11-14" }],
    }));
    expect(out.headline).toBe("Confirm Xero financial op (xero.payroll.au.createPayRun)");
    expect(out.facts).toEqual({ payRuns: 1, status: "DRAFT", period: "2026-11-01 to 2026-11-14" });
  });

  it("updatePayRun: payRunId from the path; every distinct status is shown", () => {
    const out = r(input({
      operationId: "xero.payroll.au.updatePayRun",
      pathParams: { PayRunID: "pr-1" },
      body: [{ PayRunStatus: "DRAFT" }, { payrunstatus: "POSTED" }],
    }));
    expect(out.facts).toEqual({ payRunId: "pr-1", payRuns: 2, status: "DRAFT, POSTED" });
  });

  it("accepts a PayRuns wrapper object and flags other top-level keys", () => {
    const out = r(input({
      operationId: "xero.payroll.au.createPayRun",
      body: { PayRuns: [{ PayRunStatus: "POSTED" }], Decoy: 1 },
    }));
    expect(out.facts).toMatchObject({ payRuns: 1, status: "POSTED", unexpectedKeys: "Decoy" });
  });

  it("no body yields payRuns: 0", () => {
    expect(r(input({ operationId: "xero.payroll.au.createPayRun" })).facts).toEqual({ payRuns: 0 });
  });
});

describe("xero elicit-renderers — persistent_state (employees)", () => {
  const r = xeroElicitRenderers.persistent_state;

  it("createEmployee: count plus FirstName/LastName/Email of the first (top-level array)", () => {
    const out = r(input({
      operationId: "xero.payroll.au.createEmployee",
      body: [{ FirstName: "Ada", LastName: "Lovelace", Email: "ada@x.example" }, { FirstName: "Bob" }],
    }));
    expect(out.headline).toBe("Confirm Xero employee mutation (xero.payroll.au.createEmployee)");
    expect(out.facts).toEqual({ employees: 2, FirstName: "Ada", LastName: "Lovelace", Email: "ada@x.example", fields: "FirstName, LastName, Email" });
  });

  it("updateEmployee: employeeId from the path, names read case-insensitively", () => {
    const out = r(input({
      operationId: "xero.payroll.au.updateEmployee",
      pathParams: { EmployeeID: "emp-1" },
      body: [{ firstname: "Ada", lastname: "Lovelace" }],
    }));
    expect(out.facts).toEqual({ employeeId: "emp-1", employees: 1, FirstName: "Ada", LastName: "Lovelace", fields: "firstname, lastname" });
  });

  it("lists the first employee's property names so a BankAccounts change is visible", () => {
    const out = r(input({
      operationId: "xero.payroll.au.updateEmployee",
      pathParams: { EmployeeID: "emp-1" },
      body: [{ FirstName: "Ada", BankAccounts: [{ BSB: "062000", AccountNumber: "13371337" }] }],
    }));
    expect(out.facts.fields).toBe("BankAccounts, FirstName");
  });

  it("lists sensitive employee properties first in `fields`", () => {
    const out = r(input({
      operationId: "xero.payroll.au.updateEmployee",
      body: [{ FirstName: "Ada", PayTemplate: {}, Email: "a@x.example", bankAccounts: [], TaxDeclaration: {}, SuperMemberships: [] }],
    }));
    expect(out.facts.fields).toBe("PayTemplate, bankAccounts, TaxDeclaration, SuperMemberships, FirstName, Email");
  });

  it("accepts an Employees wrapper object and flags other top-level keys", () => {
    const out = r(input({
      operationId: "xero.payroll.au.createEmployee",
      body: { Employees: [{ FirstName: "Ada" }], Extra: true },
    }));
    expect(out.facts).toMatchObject({ employees: 1, FirstName: "Ada", unexpectedKeys: "Extra" });
  });

  it("no body yields employees: 0 and no confirm fact", () => {
    const out = r(input({ operationId: "xero.payroll.au.createEmployee" }));
    expect(out.facts).toEqual({ employees: 0 });
  });
});

describe("xero elicit-renderers — contactChange (F2-1 contact edits)", () => {
  const op = "xero.accounting.updateOrCreateContacts";
  const summary = {
    contactId: "3f1c2a54-7b8e-4d2a-9c61-0e5d4b7a9f10",
    name: "Acme Supplies",
    emailAddress: "accounts@acme.example → accounts@attacker.example",
    contactStatus: "ACTIVE → ARCHIVED",
  };

  it("names the operation in the headline and keeps the summary's order", () => {
    const out = contactChange(input({
      operationId: op,
      body: { Contacts: [{ ContactID: summary.contactId, EmailAddress: "accounts@attacker.example" }] },
      inspectorSummary: summary,
    }));
    expect(out.headline).toBe(`Confirm Xero contact change (${op})`);
    expect(out.facts).toEqual(summary);
    expect(Object.keys(out.facts)).toEqual(["contactId", "name", "emailAddress", "contactStatus"]);
  });

  it("lists a decoy top-level key beside Contacts under unexpectedKeys", () => {
    const out = contactChange(input({
      operationId: op,
      body: { Contacts: [{ ContactID: "x" }], Payments: [{ Amount: 1 }] },
      inspectorSummary: summary,
    }));
    expect(out.facts.unexpectedKeys).toBe("Payments");
    expect(out.facts.contactStatus).toBe("ACTIVE → ARCHIVED");
  });

  it("does not list a flat contact body's own fields as unexpected", () => {
    const out = contactChange(input({
      operationId: op,
      body: { ContactID: "x", EmailAddress: "a@attacker.example" },
      inspectorSummary: summary,
    }));
    expect(out.facts.unexpectedKeys).toBeUndefined();
  });

  it("shows a rename, a Xero Network key change and marked contact persons as the inspector states them", () => {
    const changed = {
      contactId: summary.contactId,
      name: "Acme Supplies → Mallory Pty Ltd",
      contactPersons: "(none) → a@attacker.example (in emails)",
      xeroNetworkKey: "acme-key → attacker-key",
    };
    const out = contactChange(input({
      operationId: op,
      body: { Contacts: [{ ContactID: summary.contactId, Name: "Mallory Pty Ltd" }] },
      inspectorSummary: changed,
    }));
    expect(out.facts).toEqual(changed);
  });

  it("shows only the headline with no body and no summary", () => {
    const out = contactChange(input({ operationId: op }));
    expect(out).toEqual({ headline: `Confirm Xero contact change (${op})`, facts: {} });
  });
});
