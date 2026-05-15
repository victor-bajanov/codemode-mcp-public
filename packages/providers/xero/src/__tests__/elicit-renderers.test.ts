import { describe, it, expect } from "vitest";
import { xeroElicitRenderers } from "../elicit-renderers";

describe("xero elicit-renderers — external_data_flow (emailInvoice)", () => {
  const r = xeroElicitRenderers.external_data_flow!;

  it("surfaces invoiceId from operationId path interpolation", () => {
    const out = r({
      operationId: "xero.accounting.emailInvoice",
      body: undefined,
      inspectorSummary: { invoiceId: "abc-123" },
    });
    expect(out.fields).toMatchObject({ invoiceId: "abc-123" });
  });

  it("falls back to confirm when no inspectorSummary", () => {
    const out = r({ operationId: "xero.accounting.emailInvoice", body: undefined });
    expect(out.fields.confirm).toBe(true);
  });
});

describe("xero elicit-renderers — financial_legal", () => {
  const r = xeroElicitRenderers.financial_legal!;

  it("surfaces Payments count + total when computable", () => {
    const out = r({
      operationId: "xero.accounting.createBatchPayment",
      body: { Payments: [{ Amount: 100 }, { Amount: 50.5 }] },
    });
    expect(out.fields).toMatchObject({ count: 2, total: 150.5 });
  });

  it("falls back to count: 0 when array missing", () => {
    const out = r({ operationId: "xero.accounting.createBatchPayment", body: {} });
    expect(out.fields).toMatchObject({ count: 0 });
  });
});

describe("xero elicit-renderers — persistent_state", () => {
  const r = xeroElicitRenderers.persistent_state!;

  it("surfaces FirstName/LastName/Email of first employee", () => {
    const out = r({
      operationId: "xero.payroll.au.createEmployee",
      body: {
        Employees: [{ FirstName: "Ada", LastName: "Lovelace", Email: "ada@x.com" }],
      },
    });
    expect(out.fields).toMatchObject({
      FirstName: "Ada", LastName: "Lovelace", Email: "ada@x.com",
    });
  });
});
