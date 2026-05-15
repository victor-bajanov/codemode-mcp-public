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
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND-OVERPAYMENT" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "banktx-disallowed-type" });
  });

  it("denies RECEIVE-OVERPAYMENT", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "RECEIVE-OVERPAYMENT" }] },
    })).toMatchObject({ decision: "deny", reason: "banktx-disallowed-type" });
  });

  it("denies TRANSFER", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "TRANSFER" }] },
    })).toMatchObject({ decision: "deny", reason: "banktx-disallowed-type" });
  });

  it("denies any tx with IsReconciled=true", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", IsReconciled: true }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "banktx-reconciled" });
  });

  it("denies when BankTransactions array is empty", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [] },
    })).toMatchObject({ decision: "deny", category: "malformed", reason: "banktx-no-payload" });
  });

  it("denies when key is missing", () => {
    expect(inspectBankTxCreate({ body: {} })).toMatchObject({
      decision: "deny", category: "malformed", reason: "banktx-no-payload",
    });
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
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", Status: "DELETED" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "banktx-disallowed-status" });
  });

  it("denies when Status is VOIDED", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", Status: "VOIDED" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "banktx-disallowed-status" });
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
