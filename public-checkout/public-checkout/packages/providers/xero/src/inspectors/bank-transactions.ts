// Bank-transaction inspector wired into both createBankTransactions and
// updateBankTransaction. Xero has no separate delete/void op for bank
// transactions — destruction flows through updateBankTransaction setting
// Status: "DELETED" or "VOIDED". This inspector rejects those transitions.
import type { InspectRequest, InspectResult } from "@local/shared";

const ALLOWED_TYPES = new Set(["SPEND", "RECEIVE"]);

// Status absent → Xero defaults to AUTHORISED on create. Anything else is a
// destructive transition (DELETED / VOIDED) that should not slip through.
const ALLOWED_STATUSES = new Set(["AUTHORISED"]);

export function inspectBankTxCreate(req: InspectRequest): InspectResult {
  const body = req.body;
  if (!body || typeof body !== "object") {
    return { decision: "deny", category: "malformed", reason: "banktx-no-payload" };
  }
  const txs = (body as Record<string, unknown>)["BankTransactions"];
  if (!Array.isArray(txs) || txs.length === 0) {
    return { decision: "deny", category: "malformed", reason: "banktx-no-payload" };
  }
  for (const tx of txs) {
    if (!tx || typeof tx !== "object") {
      return { decision: "deny", category: "malformed", reason: "banktx-no-payload" };
    }
    const txObj = tx as Record<string, unknown>;
    const type = String(txObj["Type"] ?? "").toUpperCase();
    if (!ALLOWED_TYPES.has(type)) {
      return { decision: "deny", category: "irreversible", reason: "banktx-disallowed-type" };
    }
    const statusRaw = txObj["Status"];
    if (statusRaw !== undefined) {
      const status = String(statusRaw).toUpperCase();
      if (!ALLOWED_STATUSES.has(status)) {
        return { decision: "deny", category: "irreversible", reason: "banktx-disallowed-status" };
      }
    }
    if (txObj["IsReconciled"] === true) {
      return { decision: "deny", category: "irreversible", reason: "banktx-reconciled" };
    }
  }
  return { decision: "allow" };
}
