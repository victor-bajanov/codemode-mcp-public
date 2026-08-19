/** Upstream (provider API) rate-limit reporting.
 *
 *  Distinct from `oauth-hardening.ts`, which rate-limits *inbound* requests to
 *  our own OAuth endpoints. This module is about what the *upstream* API tells
 *  us: how much call budget is left, and — on a 429 — which limit was hit and
 *  how long to wait.
 *
 *  Providers own the header parsing (names and semantics differ per API) via
 *  `ApiProvider.readRateLimit`; the scaffold owns the transport: it puts the
 *  parsed value on the response envelope as `rateLimit` and folds the message
 *  into `errors[0].message` on a 429, so the MCP client learns the reason
 *  instead of an opaque "HTTP 429".
 */

/** Normalised upstream rate-limit state, as reported by the API's own headers. */
export interface UpstreamRateLimit {
  /** Raw upstream token for the limit that was exceeded (429 only), e.g.
   *  Xero's `X-Rate-Limit-Problem: minute`. Absent on non-429 responses and on
   *  a 429 whose headers omit it. */
  problem?: string;
  /** Human-readable expansion of `problem` (e.g. "per-minute limit (60
   *  calls/minute per tenant)"). Falls back to the raw token when the provider
   *  does not recognise it. */
  limit?: string;
  /** Seconds to wait before retrying, from `Retry-After` (429 only). Only set
   *  when the header carries a plain delta-seconds value. */
  retryAfterSeconds?: number;
  /** Remaining call budget per named window, e.g.
   *  `{ day: 4998, minute: 57, appMinute: 9970 }`. Keys are provider-defined;
   *  windows the upstream did not report are omitted. */
  remaining?: Record<string, number>;
  /** One-line, client-facing explanation. Set on a 429; this is what gets
   *  folded into the envelope's `errors[0].message`. */
  message?: string;
}

/** Provider hook: derive {@link UpstreamRateLimit} from an upstream response.
 *  Called for every upstream response (2xx included) so remaining-budget
 *  headers reach the client before it runs out. Return `undefined` when the
 *  response carries no rate-limit signal. */
export type ReadRateLimit = (
  res: { status: number; headers: Headers },
) => UpstreamRateLimit | undefined;
