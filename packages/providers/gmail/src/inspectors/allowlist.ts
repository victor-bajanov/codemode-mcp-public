/**
 * Outbound recipient allowlist for Gmail send / draft / sendAs / calendar
 * inspectors.
 *
 * The list is per-deployment: each worker declares its own entries in the
 * `OUTBOUND_RECIPIENT_ALLOWLIST` wrangler var (comma-separated), so two
 * deployments built from this provider can enforce different outbound
 * surfaces without forking the code. The request handler threads the worker
 * env into every inspector call; inspectors resolve the list via
 * `outboundAllowlistFromEnv`.
 *
 * Fail-closed semantics (there is no elicit middle tier for off-allowlist
 * recipients — Claude.ai does not support elicitation, so every request must
 * resolve to a hard allow or deny):
 *   - var unset / blank / non-string → empty list → every outbound recipient
 *     is denied (reads and non-outbound writes are unaffected)
 *   - any malformed entry → throw → the request errors before anything is sent
 *
 * Entry forms:
 *   - "*@<domain>"       → wildcard local-part; matches any address whose
 *                          domain (lowercased) exactly equals <domain>.
 *                          Subdomains are NOT matched (no implicit wildcard).
 *   - "<local>@<domain>" → exact-address; matches the literal lowercased
 *                          address. Plus-addressing is treated strictly:
 *                          "a+tag@x" does NOT match "a@x".
 */

export const OUTBOUND_RECIPIENT_ALLOWLIST_VAR = "OUTBOUND_RECIPIENT_ALLOWLIST";

/**
 * Throws if `entry` is not a syntactically valid allowlist entry.
 *
 * Valid forms: "*@<non-empty-domain>" or "<non-empty-local>@<non-empty-domain>".
 */
export function assertAllowlistEntry(entry: string): void {
  const at = entry.indexOf("@");
  if (at < 0) {
    throw new Error(`Invalid allowlist entry (no @): ${entry}`);
  }
  const local = entry.slice(0, at);
  const domain = entry.slice(at + 1);
  if (domain.length === 0) {
    throw new Error(`Invalid allowlist entry (empty domain): ${entry}`);
  }
  if (local.length === 0) {
    throw new Error(`Invalid allowlist entry (empty local): ${entry}`);
  }
}

// Memo for the last successfully parsed var value. The var is fixed for the
// lifetime of an isolate, so this hits on every call after the first; keyed by
// the raw string so tests exercising several envs still re-parse.
let cachedRaw: string | undefined;
let cachedList: readonly string[] = [];

/**
 * Resolve this deployment's outbound recipient allowlist from its wrangler
 * vars. Unset/blank → empty list (deny-all outbound). A malformed entry
 * throws — the surrounding request fails before anything is sent.
 */
export function outboundAllowlistFromEnv(
  env?: Readonly<Record<string, unknown>>,
): readonly string[] {
  const raw = env?.[OUTBOUND_RECIPIENT_ALLOWLIST_VAR];
  if (typeof raw !== "string" || raw.trim().length === 0) return [];
  if (raw === cachedRaw) return cachedList;
  const entries = raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const entry of entries) {
    assertAllowlistEntry(entry);
  }
  cachedRaw = raw;
  cachedList = Object.freeze(entries);
  return cachedList;
}

/**
 * Conservative addr-spec shape: exactly one `@`, a non-empty local part and
 * domain, and none of whitespace, control characters, angle brackets,
 * parentheses, square brackets, double quotes, commas, semicolons, colons or
 * backslashes on either side. Deliberately narrower than RFC 5322 — quoted
 * local parts, comments, domain literals and group syntax are all refused.
 */
const ADDR_SPEC_SHAPE = /^[^\s@<>()[\]",;:\\\x00-\x1f\x7f]+@[^\s@<>()[\]",;:\\\x00-\x1f\x7f]+$/;

/** True when `address` (already trimmed and lower-cased) has the plain
 *  addr-spec shape `isAllowedRecipient` requires. */
export function isPlainAddrSpec(address: string): boolean {
  return ADDR_SPEC_SHAPE.test(address);
}

/**
 * Returns true iff `address` matches at least one entry in `allowlist`.
 * Comparison is case-insensitive on both sides; plus-addressing is strict;
 * subdomain match is not implied. An empty allowlist matches nothing.
 *
 * The address must first pass `ADDR_SPEC_SHAPE` (one `@`, non-empty local and
 * domain, no whitespace, control characters, quotes, angle brackets, commas,
 * semicolons, colons, brackets or backslashes). Anything else fails closed
 * before matching, so `outsider@evil.example@allowed.example` is not read as
 * an `allowed.example` address and a quoted local part such as
 * `"a b"@allowed.example` is refused even though RFC 5322 permits it (F-18).
 */
export function isAllowedRecipient(address: string, allowlist: readonly string[]): boolean {
  const norm = address.trim().toLowerCase();
  if (norm.length === 0) return false;
  if (!isPlainAddrSpec(norm)) return false;
  for (const entry of allowlist) {
    const e = entry.toLowerCase();
    if (e.startsWith("*@")) {
      const domain = e.slice(2);
      const at = norm.lastIndexOf("@");
      if (at >= 0 && norm.slice(at + 1) === domain) return true;
    } else if (norm === e) {
      return true;
    }
  }
  return false;
}
