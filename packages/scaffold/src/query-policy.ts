// packages/scaffold/src/query-policy.ts
//
// D-2 — query parameter names. Sandbox code supplies `query` as a free-form
// record and `buildUpstreamUrl` copies every key onto the wire, so without a
// check an allowed read could carry a method override (`$httpMethod`), a
// header override (`$httpHeaders`), a credential parameter or any name the
// reviewed operation never declared. `checkQuery` is the pure policy the
// handler applies after matching the operation and before building the URL:
//
//   1. Values must be string | number | boolean (`undefined` keys are ignored,
//      as `buildUpstreamUrl` drops them). The one exception is a parameter
//      the operation declares as a comma-separated list (`schema.type:
//      "array"`, `explode: false`, style `form` or unset), which may take an
//      array of primitives; it goes on the wire comma-joined, as
//      `String(array)` always sent it.
//   2. A hard deny-list, case-insensitive, wins even over a declaration.
//   3. Every other name must be declared by the matched operation
//      (`in: "query"`, a `$ref` resolved against `components.parameters`) or
//      be one of the provider's `standardQueryParams`. Exact comparison.
//
// Messages and `keys` carry names only, never values.

import type { OpenApiOperation, OpenApiSpec } from "@local/spec-loaders-google-discovery";

export type QueryCheckResult =
  | { ok: true; keys: string[] }
  | {
      ok: false;
      category: "malformed" | "url_safety";
      reason: "query-value-not-primitive" | "forbidden-query-param" | "undeclared-query-param";
      message: string;
      /** Sorted names of every non-undefined key, for the audit line. */
      keys: string[];
    };

const FORBIDDEN_NAMES = new Set([
  // credentials
  "access_token",
  "oauth_token",
  "key",
  "api_key",
  "apikey",
  "token",
  "bearer",
  "authorization",
  // method override
  "_method",
  "method",
  "httpmethod",
  "x-http-method-override",
]);

/** True for names no operation may receive from sandbox code, whatever its
 *  spec declares: `$`-prefixed system parameters (Google's `$httpMethod`,
 *  `$httpHeaders`, …), credentials and method overrides. Case-insensitive. */
export function isForbiddenQueryName(name: string): boolean {
  const lower = name.toLowerCase();
  return lower.startsWith("$") || FORBIDDEN_NAMES.has(lower);
}

const PARAM_REF_RE = /^#\/components\/parameters\/(.+)$/;

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v !== null && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : undefined;
}

function resolveParameter(param: unknown, spec: OpenApiSpec): Record<string, unknown> | undefined {
  const p = asRecord(param);
  if (!p) return undefined;
  const ref = p.$ref;
  if (ref === undefined) return p;
  if (typeof ref !== "string") return undefined;
  const m = PARAM_REF_RE.exec(ref);
  if (!m) return undefined;
  const table = asRecord((spec.components as Record<string, unknown> | undefined)?.parameters);
  if (!table || !Object.prototype.hasOwnProperty.call(table, m[1]!)) return undefined;
  return asRecord(table[m[1]!]);
}

/** The operation's query parameter declarations by name (inline, or via a
 *  `$ref` into `spec.components.parameters`; an unresolvable `$ref`
 *  declares nothing; the first declaration of a name wins). Reads
 *  operation-level `parameters` only: a query parameter declared at
 *  path-item level is refused (fail-closed) until this is extended to merge
 *  those in. */
function declaredQueryParams(op: OpenApiOperation, spec: OpenApiSpec): Map<string, Record<string, unknown>> {
  const out = new Map<string, Record<string, unknown>>();
  const params: unknown = op.parameters;
  if (!Array.isArray(params)) return out;
  for (const raw of params) {
    const p = resolveParameter(raw, spec);
    if (p && p.in === "query" && typeof p.name === "string" && !out.has(p.name)) out.set(p.name, p);
  }
  return out;
}

/** Sorted, de-duplicated names the operation declares with `in: "query"`. */
export function declaredQueryNames(op: OpenApiOperation, spec: OpenApiSpec): string[] {
  return [...declaredQueryParams(op, spec).keys()].sort();
}

/** True for a declaration whose value is a comma-separated list on the
 *  wire: `schema.type: "array"` with `explode: false` and style `form`
 *  (the query default). Exploded arrays (repeated keys) cannot be sent. */
function isCommaListParam(p: Record<string, unknown> | undefined): boolean {
  if (!p) return false;
  const schema = asRecord(p.schema);
  return (
    schema?.type === "array" &&
    p.explode === false &&
    (p.style === undefined || p.style === "form")
  );
}

/** At most this many query names on an audit line, each at most
 *  `AUDIT_QUERY_KEY_MAX_CODE_POINTS` code points: the key set is
 *  sandbox-controlled, and an unbounded list would let one denied request
 *  write megabytes into the log sink. */
export const AUDIT_QUERY_KEYS_MAX = 32;
export const AUDIT_QUERY_KEY_MAX_CODE_POINTS = 64;

/** The bounded audit view of a sorted key set: the first 32 names, each cut
 *  to 64 code points with a visible `…`, plus `queryKeyCount`, the true
 *  number of names. Empty when there are no keys. The policy itself always
 *  judges the full set. */
export function auditQueryKeys(keys: readonly string[]): { queryKeys?: string[]; queryKeyCount?: number } {
  if (keys.length === 0) return {};
  const queryKeys = keys.slice(0, AUDIT_QUERY_KEYS_MAX).map((k) => {
    const cps = Array.from(k);
    return cps.length <= AUDIT_QUERY_KEY_MAX_CODE_POINTS
      ? k
      : cps.slice(0, AUDIT_QUERY_KEY_MAX_CODE_POINTS - 1).join("") + "…";
  });
  return { queryKeys, queryKeyCount: keys.length };
}

function isPrimitive(v: unknown): boolean {
  return typeof v === "string" || typeof v === "number" || typeof v === "boolean";
}

export function checkQuery(
  op: OpenApiOperation,
  spec: OpenApiSpec,
  query: Record<string, unknown> | undefined,
  standardQueryParams: readonly string[] | undefined,
): QueryCheckResult {
  const keys = query
    ? Object.keys(query)
        .filter((k) => query[k] !== undefined)
        .sort()
    : [];
  if (keys.length === 0) return { ok: true, keys };

  const opId = op.operationId;
  const declared = declaredQueryParams(op, spec);

  for (const k of keys) {
    const v = query![k];
    if (isPrimitive(v)) continue;
    // Own-property lookup only: `declared` is a Map, so inherited
    // Object.prototype names never resolve to a declaration.
    const list = Array.isArray(v) && isCommaListParam(declared.get(k));
    if (list && (v as unknown[]).every(isPrimitive)) continue;
    return {
      ok: false,
      category: "malformed",
      reason: "query-value-not-primitive",
      message: list
        ? `Operation ${opId}: query parameter "${k}" is a comma-separated list; its elements must be strings, numbers or booleans`
        : `Operation ${opId}: query parameter "${k}" must be a string, number or boolean` +
          (Array.isArray(v)
            ? "; this operation does not declare it as a comma-separated list, so pass one value per request"
            : ""),
      keys,
    };
  }

  for (const k of keys) {
    if (isForbiddenQueryName(k)) {
      return {
        ok: false,
        category: "url_safety",
        reason: "forbidden-query-param",
        message: `Query parameter "${k}" cannot be set from sandbox code`,
        keys,
      };
    }
  }

  const accepted = new Set<string>([
    ...declared.keys(),
    ...(standardQueryParams ?? []),
  ]);
  for (const k of keys) {
    if (!accepted.has(k)) {
      const list = [...accepted].filter((n) => !isForbiddenQueryName(n)).sort();
      return {
        ok: false,
        category: "url_safety",
        reason: "undeclared-query-param",
        message:
          `Operation ${opId} does not accept query parameter "${k}"; ` +
          (list.length > 0 ? `it accepts: ${list.join(", ")}` : "it accepts no query parameters"),
        keys,
      };
    }
  }

  return { ok: true, keys };
}
