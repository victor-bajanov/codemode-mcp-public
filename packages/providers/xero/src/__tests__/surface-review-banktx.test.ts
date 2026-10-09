// Bank-transaction inspector: only SPEND / RECEIVE allowed; IsReconciled must be false.
// Denies prepayment, overpayment, transfer.
// Gated keys (BankTransactions, Type, Status, IsReconciled) are read case-insensitively, as
// Xero does; two spellings of one gated key → deny banktx-ambiguous-key; IsReconciled counts
// as set unless absent/null/false (F-10).

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

  // === F-10: Xero reads property names case-insensitively and coerces "true" ===

  it("reads a lower-case type key: SPEND allowed, TRANSFER denied", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ type: "SPEND" }] },
    })).toEqual({ decision: "allow" });
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ type: "TRANSFER" }] },
    })).toMatchObject({ decision: "deny", reason: "banktx-disallowed-type" });
  });

  it.each(["status", "STATUS", "sTatus"])("reads a %s key as Status (VOIDED is denied)", (key) => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", [key]: "VOIDED" }] },
    })).toMatchObject({ decision: "deny", category: "irreversible", reason: "banktx-disallowed-status" });
  });

  it("still denies an explicit null Status (only absence means the default)", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", Status: null }] },
    })).toMatchObject({ decision: "deny", reason: "banktx-disallowed-status" });
  });

  it.each([
    ["Type", { Type: "SPEND", type: "TRANSFER" }],
    ["Status", { Type: "SPEND", Status: "AUTHORISED", status: "VOIDED" }],
    ["IsReconciled", { Type: "SPEND", IsReconciled: false, isreconciled: true }],
  ])("denies two spellings of %s as ambiguous", (key, tx) => {
    const res = inspectBankTxCreate({ body: { BankTransactions: [tx] } });
    expect(res).toMatchObject({ decision: "deny", category: "malformed", reason: "banktx-ambiguous-key" });
    expect(res.message).toContain(`"${key}"`);
  });

  it("denies a non-ASCII lookalike of Status as ambiguous (U+017F long s)", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", "\u017Ftatus": "VOIDED" }] },
    })).toMatchObject({ decision: "deny", reason: "banktx-ambiguous-key" });
  });

  it.each([["the string \"true\"", "true"], ["1", 1], ["0", 0], ["the string \"false\"", "false"]])(
    "denies IsReconciled given as %s (lenient boolean, fail closed)",
    (_label, value) => {
      expect(inspectBankTxCreate({
        body: { BankTransactions: [{ Type: "SPEND", IsReconciled: value }] },
      })).toMatchObject({ decision: "deny", category: "irreversible", reason: "banktx-reconciled" });
    },
  );

  it("allows IsReconciled: null", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", IsReconciled: null }] },
    })).toEqual({ decision: "allow" });
  });

  it("denies a lower-case isReconciled: true", () => {
    expect(inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND", isReconciled: true }] },
    })).toMatchObject({ decision: "deny", reason: "banktx-reconciled" });
  });

  it("reads the BankTransactions wrapper case-insensitively", () => {
    expect(inspectBankTxCreate({
      body: { banktransactions: [{ Type: "SPEND" }] },
    })).toEqual({ decision: "allow" });
    expect(inspectBankTxCreate({
      body: { bankTransactions: [{ Type: "SPEND", Status: "VOIDED" }] },
    })).toMatchObject({ decision: "deny", reason: "banktx-disallowed-status" });
  });

  it("denies two spellings of the BankTransactions wrapper as ambiguous", () => {
    const res = inspectBankTxCreate({
      body: { BankTransactions: [{ Type: "SPEND" }], banktransactions: [{ Type: "TRANSFER" }] },
    });
    expect(res).toMatchObject({ decision: "deny", reason: "banktx-ambiguous-key" });
    expect(res.message).toContain('"BankTransactions"');
  });
});
