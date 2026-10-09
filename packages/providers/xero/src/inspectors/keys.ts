// packages/providers/xero/src/inspectors/keys.ts
//
// Key-lookup helpers shared by the Xero inspectors (security review F-10).
//
// Xero deserialises request bodies with a .NET JSON parser that matches
// property names case-insensitively and coerces lenient booleans ("true", 1).
// An inspector that reads gated keys by exact name and booleans by `=== true`
// therefore judges `{"status": "AUTHORISED"}` or `{"SentToContact": "true"}` as
// if the property were absent or false, while Xero applies it. These helpers
// read gated keys the way Xero does and fail closed whenever the inspector
// cannot tell which value Xero would apply.

export interface CaseInsensitiveLookup {
  /** At least one key matching `key` (ignoring case) is present. */
  present: boolean;
  /** The value under the matching key; `undefined` when absent or ambiguous. */
  value: unknown;
  /** The inspector cannot tell which value Xero would read; callers deny. */
  ambiguous: boolean;
}

// Broad case fold. Upper-then-lower also folds the non-ASCII lookalikes that
// some case-insensitive comparers map onto ASCII letters (U+017F long s,
// U+0131 dotless i, U+212A Kelvin sign, the "st" ligatures), so they are
// caught as candidates rather than slipping past as unrelated keys.
function fold(s: string): string {
  return s.toUpperCase().toLowerCase();
}

const ASCII_ONLY = /^[\x00-\x7f]*$/;

/** Case-insensitive property lookup. `ambiguous` when two or more keys
 *  differing only by case are present (Xero's deserialiser would pick one;
 *  the inspector cannot know which), or when the only match is a non-ASCII
 *  lookalike (whether Xero folds it onto `key` depends on its comparer). */
export function getCaseInsensitive(
  obj: Record<string, unknown>,
  key: string,
): CaseInsensitiveLookup {
  const target = fold(key);
  const matches = Object.keys(obj).filter((k) => fold(k) === target);
  if (matches.length === 0) {
    return { present: false, value: undefined, ambiguous: false };
  }
  const only = matches[0]!;
  if (matches.length > 1 || !ASCII_ONLY.test(only)) {
    return { present: true, value: undefined, ambiguous: true };
  }
  return { present: true, value: obj[only], ambiguous: false };
}

/** A gated boolean counts as set unless it is undefined, null or false.
 *  Strings ("true", and even "false"), numbers and objects all count as set:
 *  Xero's coercion of them is not something the inspector should second-guess. */
export function isTruthyFlag(value: unknown): boolean {
  return value !== undefined && value !== null && value !== false;
}
