import type { FormFields } from "@local/shared";

export interface AuditEntry {
  deployment: string;
  operationId?: string;
  method: string;
  path: string;
  decision: "allow" | "elicit" | "deny";
  elicitationOutcome?:
    | "accepted"
    | "declined"
    | "cancelled"
    | "timeout"
    | "transport-error"
    | "unsupported";
  /** Form fields shown to the user during elicitation (populated when we got past
   *  capability check + schema build, regardless of accept/decline). */
  elicitFields?: FormFields;
  category?: string;
  reason?: string;
  upstreamStatus?: number;
  /** Authenticated principal (OAuth `sub` or equivalent). */
  principalId?: string;
  /** Provider-specific identifier blob (e.g. { tenantId: "..." } for Xero). */
  context?: Record<string, string>;
  ts: string;
}

export function auditLog(entry: AuditEntry): void {
  console.log("AUDIT " + JSON.stringify(entry));
}

/**
 * Redact PII-bearing audit fields by default while preserving operational
 * metadata. Returns the entry untouched when `elicitFields` is absent
 * (no PII to redact). Otherwise replaces `elicitFields` with a stable
 * shape carrying `__redacted__: true`, the original key set, and
 * per-field length / count / collapsed-value stats — operational signal
 * without leaking recipient strings, subjects, or filter criteria.
 *
 * Number values are collapsed to `0` rather than preserved because the
 * counts (e.g. recipient count) are themselves operational-pattern
 * leakage. `keys` retains the field-name set so log readers know what
 * was elided.
 */
export function redactAuditEntry(entry: AuditEntry): AuditEntry {
  if (!entry.elicitFields) return entry;
  const keys = Object.keys(entry.elicitFields);
  const counts: Record<string, number> = {};
  for (const [k, v] of Object.entries(entry.elicitFields)) {
    if (typeof v === "string") counts[`${k}Length`] = v.length;
    else if (Array.isArray(v)) counts[`${k}Count`] = v.length;
    else if (typeof v === "number") counts[`${k}Value`] = 0;
  }
  // The redacted shape carries extra signal (`__redacted__`, `keys`) beyond
  // what `FormFields = Record<string, Primitive>` allows, so we cast through
  // `unknown`. Audit lines are JSON-serialised at the sink and consumers
  // read them by key — the shape is documented in SECURITY.md.
  const redacted = { __redacted__: true, keys, ...counts } as unknown as FormFields;
  const next: AuditEntry = { ...entry };
  next.elicitFields = redacted;
  return next;
}
