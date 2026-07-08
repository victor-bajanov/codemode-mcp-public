// Bank-transaction inspector: only SPEND / RECEIVE allowed; IsReconciled must be false.
// Denies prepayment, overpayment, transfer.

import { describe, it, expect } from "vitest";
import { inspectBankTxCreate } from "../inspectors/bank-transactions";

describe("inspectBankTxCreate", () => {
  it("allows a SPEND tx with IsReconciled=false", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", IsReconciled: false }] },
    })).toEqual({ decision: "allow" });
  });

  it("allows a RECEIVE tx with IsReconciled=false", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "RECEIVE", IsReconciled: false }] },
    })).toEqual({ decision: "allow" });
  });

  it("allows when IsReconciled is omitted (defaults to false)", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND" }] },
    })).toEqual({ decision: "allow" });
  });

  it("denies SPEND-OVERPAYMENT", () => {
    const res = inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND-OVERPAYMENT" }] },
    });
    expect(res).toMatchObject({ decision: "deny", category: "irreversible", reason: "banktx-disallowed-type" });
    expect(res.message).toContain("SPEND or RECEIVE");
    expect(res.message).toContain("SPEND-OVERPAYMENT");
  });

  it("denies RECEIVE-OVERPAYMENT", () => {
    const res = inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "RECEIVE-OVERPAYMENT" }] },
    });
    expect(res).toMatchObject({ decision: "deny", reason: "banktx-disallowed-type" });
    expect(res.message).toContain("RECEIVE-OVERPAYMENT");
  });

  it("denies TRANSFER", () => {
    const res = inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "TRANSFER" }] },
    });
    expect(res).toMatchObject({ decision: "deny", reason: "banktx-disallowed-type" });
    expect(res.message).toContain("TRANSFER");
  });

  it("names the offending Type value in the disallowed-type message", () => {
    const res = inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "TRANSFER" }] },
    });
    expect(res.message).toBeTruthy();
    expect(res.message).toMatch(/SPEND or RECEIVE/);
    expect(res.message).toContain('"TRANSFER"');
  });

  it("denies any tx with IsReconciled=true", () => {
    const res = inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", IsReconciled: true }] },
    });
    expect(res).toMatchObject({ decision: "deny", category: "irreversible", reason: "banktx-reconciled" });
    expect(res.message).toContain("IsReconciled=true");
    expect(res.message).toMatch(/forged/);
  });

  it("denies when BankTransactions array is empty", () => {
    const res = inspectBankTxCreate({
      body: { BankTransactions: [] },
    });
    expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "banktx-no-payload" });
    expect(res.message).toContain('"BankTransactions"');
  });

  it("denies when key is missing", () => {
    const res = inspectBankTxCreate({ body: {} });
    expect(res).toMatchObject({
      decision: "deny", category: "malformed", reason: "banktx-no-payload",
    });
    expect(res.message).toContain('"BankTransactions"');
  });

  it("denies when body is missing/non-object", () => {
    const missing = inspectBankTxCreate({});
    expect(missing).toMatchObject({ decision: "deny", category: "malformed", reason: "banktx-no-payload" });
    expect(missing.message).toContain('"BankTransactions"');

    const nonObject = inspectBankTxCreate({ body: "not-an-object" });
    expect(nonObject).toMatchObject({ decision: "deny", category: "malformed", reason: "banktx-no-payload" });
    expect(nonObject.message).toContain('"BankTransactions"');
  });

  it("denies when BankTransactions is not an array", () => {
    const res = inspectBankTxCreate({ body: { BankTransactions: { Type: "SPEND" } } });
    expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "banktx-no-payload" });
    expect(res.message).toContain('"BankTransactions"');
  });

  it("denies when a tx entry is not an object", () => {
    const res = inspectBankTxCreate({ body: { BankTransactions: ["SPEND"] } });
    expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "banktx-no-payload" });
    expect(res.message).toContain('"BankTransactions"');
  });

  it("treats Type case-insensitively", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "spend" }] },
    })).toEqual({ decision: "allow" });
  });

  it("denies when ANY tx in a batch is disallowed (most-restrictive across the batch)", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND" }, { Type: "TRANSFER" }] },
    })).toMatchObject({ decision: "deny", reason: "banktx-disallowed-type" });
  });

  // Status-field tests: Xero has no separate `deleteBankTransaction` operation;
  // deletion happens via updateBankTransaction setting Status="DELETED" or "VOIDED".
  // The inspector must reject those transitions.
  it("allows when Status is omitted (defaults to AUTHORISED on create)", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND" }] },
    })).toEqual({ decision: "allow" });
  });

  it("allows when Status is explicitly AUTHORISED", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", Status: "AUTHORISED" }] },
    })).toEqual({ decision: "allow" });
  });

  it("denies when Status is DELETED (destructive update)", () => {
    const res = inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", Status: "DELETED" }] },
    });
    expect(res).toMatchObject({ decision: "deny", category: "irreversible", reason: "banktx-disallowed-status" });
    expect(res.message).toContain("AUTHORISED");
    expect(res.message).toContain("DELETED");
  });

  it("denies when Status is VOIDED", () => {
    const res = inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", Status: "VOIDED" }] },
    });
    expect(res).toMatchObject({ decision: "deny", category: "irreversible", reason: "banktx-disallowed-status" });
    expect(res.message).toContain("AUTHORISED");
    expect(res.message).toContain("VOIDED");
  });

  it("treats Status case-insensitively", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", Status: "deleted" }] },
    })).toMatchObject({ decision: "deny", reason: "banktx-disallowed-status" });
  });

  it("denies when ANY tx in a batch has destructive Status", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", Status: "AUTHORISED" }, { Type: "RECEIVE", Status: "DELETED" }] },
    })).toMatchObject({ decision: "deny", reason: "banktx-disallowed-status" });
  });
});
