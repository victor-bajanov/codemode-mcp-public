import type { ReadRateLimit, UpstreamRateLimit } from "@local/scaffold";

/** Xero's rate-limit response headers.
 *
 *  Xero returns the three remaining-call counters on EVERY response, and adds
 *  the problem/retry pair only when it throttles (HTTP 429):
 *
 *    X-DayLimit-Remaining      calls left in the tenant's daily quota (5,000/day)
 *    X-MinLimit-Remaining      calls left in the tenant's current minute (60/min)
 *    X-AppMinLimit-Remaining   calls left in the app-wide minute (10,000/min, all tenants)
 *    X-Rate-Limit-Problem      which of those was exceeded — "day" | "minute" | "appminute"
 *    Retry-After               seconds to wait before retrying
 *
 *  Xero's own 429 body is the bare string "oops, rate limit exceeded", which
 *  tells a caller nothing actionable — the reason and the wait are headers-only.
 *  The scaffold surfaces what we return here on the `codemode.request` envelope
 *  (`rateLimit`) and folds `message` into `errors[0].message` on a 429.
 */

const COUNTERS: Array<[header: string, key: string]> = [
  ["X-DayLimit-Remaining", "day"],
  ["X-MinLimit-Remaining", "minute"],
  ["X-AppMinLimit-Remaining", "appMinute"],
];

/** Human-readable expansion of `X-Rate-Limit-Problem`, keyed by its lowercased value. */
const LIMIT_DESCRIPTIONS: Record<string, string> = {
  minute: "per-minute limit (60 calls/minute per tenant)",
  day: "daily limit (5,000 calls/day per tenant)",
  appminute: "app-wide per-minute limit (10,000 calls/minute across all tenants)",
};

/** Parse `value` as a non-negative integer; undefined when absent or not a number. */
function readInt(value: string | null): number | undefined {
  if (value === null) return undefined;
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) return undefined;
  return Number(trimmed);
}

export const readXeroRateLimit: ReadRateLimit = ({ status, headers }) => {
  const remaining: Record<string, number> = {};
  for (const [header, key] of COUNTERS) {
    const n = readInt(headers.get(header));
    if (n !== undefined) remaining[key] = n;
  }
  const remainingField = Object.keys(remaining).length > 0 ? { remaining } : {};

  if (status !== 429) {
    // Nothing to say when upstream reported no counters (e.g. an error served
    // by a proxy in front of Xero) — leave the envelope shape untouched.
    return Object.keys(remaining).length > 0 ? { ...remainingField } : undefined;
  }

  // Xero sends the problem value lowercase; normalise anyway so an unexpected
  // casing still resolves to a description instead of falling through as unknown.
  const rawProblem = headers.get("X-Rate-Limit-Problem")?.trim().toLowerCase();
  const problem = rawProblem ? rawProblem : undefined;
  // Unrecognised values pass through verbatim rather than being dropped — a new
  // Xero limit should still reach the client, just without our prose.
  const limit = problem ? (LIMIT_DESCRIPTIONS[problem] ?? problem) : undefined;
  // Retry-After may in principle be an HTTP-date; Xero sends delta-seconds, and
  // we only report the form we can hand to a caller as a number.
  const retryAfterSeconds = readInt(headers.get("Retry-After"));

  const out: UpstreamRateLimit = {
    ...(problem ? { problem } : {}),
    ...(limit ? { limit } : {}),
    ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
    ...remainingField,
  };
  out.message =
    `Xero rate limit exceeded${limit ? `: ${limit}` : ""}.` +
    (retryAfterSeconds !== undefined
      ? ` Retry after ${retryAfterSeconds}s.`
      : " Retry-After was not supplied; back off before retrying.");
  return out;
};
