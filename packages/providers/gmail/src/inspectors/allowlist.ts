/**
 * Outbound recipient allowlist for Gmail send / draft inspectors.
 *
 * Entry forms:
 *   - "*@<domain>"       → wildcard local-part; matches any address whose
 *                          domain (lowercased) exactly equals <domain>.
 *                          Subdomains are NOT matched (no implicit wildcard).
 *   - "<local>@<domain>" → exact-address; matches the literal lowercased
 *                          address. Plus-addressing is treated strictly:
 *                          "a+tag@x" does NOT match "a@x".
 */

export const OUTBOUND_RECIPIENT_ALLOWLIST: readonly string[] = [
  "*@example.com",
  "adam@gmail.com",
] as const;

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

// Module-load validation: any malformed entry in the constant fails the import.
for (const entry of OUTBOUND_RECIPIENT_ALLOWLIST) {
  assertAllowlistEntry(entry);
}

/**
 * Returns true iff `address` matches at least one entry in
 * OUTBOUND_RECIPIENT_ALLOWLIST. Comparison is case-insensitive on both sides;
 * plus-addressing is strict; subdomain match is not implied.
 */
export function isAllowedRecipient(address: string): boolean {
  const norm = address.trim().toLowerCase();
  if (norm.length === 0) return false;
  for (const entry of OUTBOUND_RECIPIENT_ALLOWLIST) {
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
