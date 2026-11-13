import type { FormFields } from "@local/shared";
import type { UpstreamRateLimit } from "./rate-limit.js";

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
  /** Sorted names of the request's query parameters (never their values),
   *  on every line emitted after the operation is matched (D-2). */
  queryKeys?: string[];
  /** The true number of query names; `queryKeys` is capped at 32 names of
   *  at most 64 code points each. */
  queryKeyCount?: number;
  upstreamStatus?: number;
  /** Upstream rate-limit state, recorded only when the upstream throttled us
   *  (429) — which limit was hit and how long it asked us to wait. Operational
   *  metadata, no PII. */
  rateLimit?: UpstreamRateLimit;
  /** Host-assembled sends (`composed` / `multipart[].staged`): how many
   *  staged files were attached, their plaintext bytes, and the exact
   *  outbound body length. Counters only — never a token or handle. */
  stagedCount?: number;
  stagedBytes?: number;
  assembledBytes?: number;
  /** Bytes of the assembled body the upstream connection accepted before it
   *  answered, and whether that was all of `assembledBytes`. A false
   *  `bodyComplete` with a 2xx `upstreamStatus` is a truncated send the
   *  upstream nonetheless accepted. */
  bodyBytesSent?: number;
  bodyComplete?: boolean;
  /** Authenticated principal (OAuth `sub` or equivalent). */
  principalId?: string;
  /** Provider-specific identifier blob (e.g. { tenantId: "..." } for Xero). */
  context?: Record<string, string>;
  ts: string;
  /** True length of `path` (code points) when the sink cut it (B-2). */
  pathLength?: number;
  /** "dispatch": written before a host-assembled body goes out (E-4). Absent on outcome lines. */
  phase?: "dispatch";
  /** "failed": the request was allowed but its dispatch/response handling threw; `reason` says why. */
  outcome?: "failed";
  /** Staging events (E-1): never a handle or token; `fileRef` is a digest of the handle. */
  staging?: StagingAudit;
  /** `fileRef`s of the staged files a host-assembled send attached. */
  stagedRefs?: string[];
}

export type StagingEvent = "register" | "upload" | "store" | "read" | "attach" | "download";
export interface StagingAudit {
  event: StagingEvent;
  fileRef?: string;
  byteLength?: number;
  status: number;
}

/** B-2: per-field caps in code points, applied by the one sink. A cut value
 *  is the first `max - 1` code points followed by `…` (so it is exactly
 *  `max` code points long). */
export const AUDIT_METHOD_MAX = 32;
export const AUDIT_PATH_MAX = 1024;
export const AUDIT_REASON_MAX = 128;
export const AUDIT_CATEGORY_MAX = 64;
export const AUDIT_OPERATION_ID_MAX = 256;

const ELLIPSIS = "…";

/** Returns `undefined` when `s` is within `max` code points, else the cut
 *  value and the true code-point length. Never splits a surrogate pair. */
function capString(s: string, max: number): { value: string; length: number } | undefined {
  // UTF-16 length bounds the code-point count from above.
  if (s.length <= max) return undefined;
  let count = 0;
  let cutAt = -1;
  for (let i = 0; i < s.length; ) {
    if (count === max - 1) cutAt = i;
    const c = s.charCodeAt(i);
    i += c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00 ? 2 : 1;
    count++;
  }
  if (count <= max) return undefined;
  return { value: s.slice(0, cutAt) + ELLIPSIS, length: count };
}

/**
 * B-2: cap the sandbox-reachable string fields of an audit entry: `method`,
 * `path`, `reason`, `category` and `operationId` (AUDIT_*_MAX code points
 * each). Every other field is left as is: arrays and objects (`queryKeys`,
 * `stagedRefs`, `context`, `staging`, …) are bounded by their producers,
 * not here. Caps count code points, not bytes: JSON escaping (C0 controls,
 * lone surrogates) can make a capped line several times its cap in bytes.
 * Pure: the input is not mutated; key order is preserved (a line within the
 * caps serialises byte-identically). Sets `pathLength` when `path` is cut.
 */
export function capAuditEntry(entry: AuditEntry): AuditEntry {
  const out: AuditEntry = { ...entry };
  const caps: Array<[keyof AuditEntry & ("method" | "reason" | "category" | "operationId"), number]> = [
    ["method", AUDIT_METHOD_MAX],
    ["reason", AUDIT_REASON_MAX],
    ["category", AUDIT_CATEGORY_MAX],
    ["operationId", AUDIT_OPERATION_ID_MAX],
  ];
  for (const [key, max] of caps) {
    const v = out[key];
    if (typeof v !== "string") continue;
    const cut = capString(v, max);
    if (cut) out[key] = cut.value;
  }
  if (typeof out.path === "string") {
    const cut = capString(out.path, AUDIT_PATH_MAX);
    if (cut) {
      out.path = cut.value;
      out.pathLength = cut.length;
    }
  }
  return out;
}

export function auditLog(entry: AuditEntry): void {
  // JSON.stringify leaves U+2028/U+2029 raw; a text viewer may break the line
  // there, so a sandbox-controlled path could render a fake "AUDIT {...}" line.
  const line = JSON.stringify(capAuditEntry(entry))
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
  console.log("AUDIT " + line);
}

export type AuditSink = (entry: Omit<AuditEntry, "deployment" | "ts">) => void;

/** One staging event line (E-1): an allowed event, or a deny with the fixed
 *  reason `staging-refused`. `fileRef`/`byteLength`/`principalId` only
 *  when known; never a handle or token. */
export function stagingAuditEntry(e: {
  method: string;
  path: string;
  operationId: string;
  allowed: boolean;
  principalId?: string | null | undefined;
  event: StagingEvent;
  fileRef?: string | undefined;
  byteLength?: number | undefined;
  status: number;
}): Omit<AuditEntry, "deployment" | "ts"> {
  return {
    method: e.method,
    path: e.path,
    operationId: e.operationId,
    decision: e.allowed ? "allow" : "deny",
    ...(e.allowed ? {} : { reason: "staging-refused" }),
    ...(e.principalId ? { principalId: e.principalId } : {}),
    staging: {
      event: e.event,
      ...(e.fileRef !== undefined ? { fileRef: e.fileRef } : {}),
      ...(e.byteLength !== undefined ? { byteLength: e.byteLength } : {}),
      status: e.status,
    },
  };
}

/**
 * Fills `deployment`/`ts`, defaults `principalId`/`context` (an entry's own
 * values win), and writes via `waitUntil` when given (else synchronously).
 * The write goes through `auditLog`, so every line is capped. It does not
 * redact: an entry carrying `elicitFields` must go through
 * `redactAuditEntry` first.
 */
export function createAuditSink(opts: {
  deployment: string;
  principalId?: string;
  context?: Record<string, string>;
  waitUntil?: (p: Promise<unknown>) => void;
}): AuditSink {
  return (entry) => {
    const full: AuditEntry = {
      deployment: opts.deployment,
      ...entry,
      ...(entry.principalId === undefined && opts.principalId !== undefined
        ? { principalId: opts.principalId }
        : {}),
      ...(entry.context === undefined && opts.context !== undefined ? { context: opts.context } : {}),
      ts: new Date().toISOString(),
    };
    if (opts.waitUntil) {
      opts.waitUntil(Promise.resolve().then(() => auditLog(full)));
    } else {
      auditLog(full);
    }
  };
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
