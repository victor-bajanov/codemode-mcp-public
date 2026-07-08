// Bank-transaction inspector wired into both createBankTransactions and
// updateBankTransaction. Xero has no separate delete/void op for bank
// transactions — destruction flows through updateBankTransaction setting
// Status: "DELETED" or "VOIDED". This inspector rejects those transitions.
import type { InspectRequest, InspectResult } from "@local/shared";

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

export function inspectBankTxCreate(req: InspectRequest): InspectResult {
  const body = req.body;
  if (!body || typeof body !== "object") {
    return noPayload;
  }
  const txs = (body as Record<string, unknown>)["BankTransactions"];
  if (!Array.isArray(txs) || txs.length === 0) {
    return noPayload;
  }
  for (const tx of txs) {
    if (!tx || typeof tx !== "object") {
      return noPayload;
    }
    const txObj = tx as Record<string, unknown>;
    const type = String(txObj["Type"] ?? "").toUpperCase();
    if (!ALLOWED_TYPES.has(type)) {
      return denyDisallowedType(type);
    }
    const statusRaw = txObj["Status"];
    if (statusRaw !== undefined) {
      const status = String(statusRaw).toUpperCase();
      if (!ALLOWED_STATUSES.has(status)) {
        return denyDisallowedStatus(status);
      }
    }
    if (txObj["IsReconciled"] === true) {
      return denyReconciled;
    }
  }
  return { decision: "allow" };
}
