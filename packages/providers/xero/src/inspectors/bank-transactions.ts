// Bank-transaction inspector wired into both createBankTransactions and
// updateBankTransaction. Xero has no separate delete/void op for bank
// transactions — destruction flows through updateBankTransaction setting
// Status: "DELETED" or "VOIDED". This inspector rejects those transitions.
//
// Key case and lenient booleans (security review F-10): Xero's .NET JSON
// deserialiser matches property names case-insensitively and coerces "true"
// to a boolean, so the gated keys (the BankTransactions wrapper, Type, Status,
// IsReconciled) are read case-insensitively via ./keys, a body carrying two
// spellings of one gated key is denied as ambiguous, and IsReconciled counts
// as set unless it is absent, null or false (so "true", 1 and even "false"
// are denied).
import type { InspectRequest, InspectResult } from "@local/shared";
import { getCaseInsensitive, isTruthyFlag } from "./keys.js";

const ALLOWED_TYPES = new Set(["SPEND", "RECEIVE"]);

// Status absent → Xero defaults to AUTHORISED on create. Anything else is a
// destructive transition (DELETED / VOIDED) that should not slip through.
const ALLOWED_STATUSES = new Set(["AUTHORISED"]);

// Denials carry a human-readable `message` so the caller sees *why* the request
// was blocked instead of the opaque "denied by surface review"; `reason` stays a
// terse, greppable code for audit logs.
const noPayload: InspectResult = {
  decision: "deny",
  category: "malformed",
  reason: "banktx-no-payload",
  message:
    `No bank-transaction payload found. Send a non-empty "BankTransactions" array ` +
    `of transaction objects.`,
};

function denyDisallowedType(typeShown: string): InspectResult {
  return {
    decision: "deny",
    category: "irreversible",
    reason: "banktx-disallowed-type",
    message:
      `Only SPEND or RECEIVE bank transactions can be created or modified through this API; ` +
      `this transaction has Type "${typeShown}". Other types (overpayments, prepayments, ` +
      `transfers) are not permitted here, so the request was denied.`,
  };
}

function denyDisallowedStatus(statusShown: string): InspectResult {
  return {
    decision: "deny",
    category: "irreversible",
    reason: "banktx-disallowed-status",
    message:
      `Only AUTHORISED bank transactions can be created or modified through this API; ` +
      `this transaction has Status "${statusShown}". Omitting Status is fine (Xero defaults ` +
      `it to AUTHORISED), but DELETED and VOIDED transitions delete or void the transaction ` +
      `(the change is irreversible) and are denied here.`,
  };
}

const denyReconciled: InspectResult = {
  decision: "deny",
  category: "irreversible",
  reason: "banktx-reconciled",
  message:
    `Refusing to create or modify a reconciled bank transaction (IsReconciled=true): ` +
    `reconciliation is a bank-matching state set when a transaction is matched against a ` +
    `real bank-statement line, and it must not be forged. Submit the transaction without ` +
    `IsReconciled (or IsReconciled=false) and let reconciliation happen through bank matching.`,
};

function denyAmbiguous(key: string): InspectResult {
  return {
    decision: "deny",
    category: "malformed",
    reason: "banktx-ambiguous-key",
    message:
      `Refusing a bank-transaction payload that spells "${key}" more than one way (keys ` +
      `differing only by letter case, or a non-ASCII lookalike). Xero matches property names ` +
      `case-insensitively, so which value it would apply is unclear. Send "${key}" exactly once.`,
  };
}

export function inspectBankTxCreate(req: InspectRequest): InspectResult {
  const body = req.body;
  if (!body || typeof body !== "object") {
    return noPayload;
  }
  const wrapper = getCaseInsensitive(body as Record<string, unknown>, "BankTransactions");
  if (wrapper.ambiguous) {
    return denyAmbiguous("BankTransactions");
  }
  const txs = wrapper.value;
  if (!Array.isArray(txs) || txs.length === 0) {
    return noPayload;
  }
  for (const tx of txs) {
    if (!tx || typeof tx !== "object") {
      return noPayload;
    }
    const txObj = tx as Record<string, unknown>;
    const typeKey = getCaseInsensitive(txObj, "Type");
    const statusKey = getCaseInsensitive(txObj, "Status");
    const reconciledKey = getCaseInsensitive(txObj, "IsReconciled");
    if (typeKey.ambiguous) return denyAmbiguous("Type");
    if (statusKey.ambiguous) return denyAmbiguous("Status");
    if (reconciledKey.ambiguous) return denyAmbiguous("IsReconciled");
    const type = String(typeKey.value ?? "").toUpperCase();
    if (!ALLOWED_TYPES.has(type)) {
      return denyDisallowedType(type);
    }
    // Only an absent Status means "default"; an explicit null is not AUTHORISED
    // and stays denied (fail closed), as before.
    const statusRaw = statusKey.value;
    if (statusRaw !== undefined) {
      const status = String(statusRaw).toUpperCase();
      if (!ALLOWED_STATUSES.has(status)) {
        return denyDisallowedStatus(status);
      }
    }
    if (isTruthyFlag(reconciledKey.value)) {
      return denyReconciled;
    }
  }
  return { decision: "allow" };
}
