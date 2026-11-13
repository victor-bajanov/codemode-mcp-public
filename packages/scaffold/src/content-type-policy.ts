/**
 * Content-type policy for `codemode.request` (D-3, C-4).
 *
 * `parseMediaType` is the entry grammar check: only a syntactically valid
 * media type (RFC 7231 §3.1.1.1) of at most 100 characters can be carried
 * by a request, so no prose or control characters can be echoed anywhere.
 * `canonicalJsonContentType` decides whether a JSON body on a gated
 * operation may be sent: only a JSON essence with no parameters or exactly
 * `charset=utf-8` is accepted, and it is always sent as `application/json`
 * so the upstream reads the bytes the inspector judged.
 */

export interface MediaType {
  /** Lower-cased top-level type. */
  type: string;
  /** Lower-cased subtype. */
  subtype: string;
  /** Parameter names lower-cased; values unquoted, case kept. */
  params: Record<string, string>;
}

export const MAX_CONTENT_TYPE_LENGTH = 100;

// RFC 7230 §3.2.6 tchar.
const TOKEN = "[A-Za-z0-9!#$%&'*+.^_`|~-]+";
// quoted-string with qdtext / quoted-pair restricted to printable ASCII,
// SP and HTAB (obs-text refused: nothing legitimate needs it here).
const QUOTED = '"(?:[\\t \\x21\\x23-\\x5B\\x5D-\\x7E]|\\\\[\\t \\x21-\\x7E])*"';
const OWS = "[ \\t]*";
const ESSENCE_RE = new RegExp(`^(${TOKEN})/(${TOKEN})`);
// RFC 9110 §5.6.6: `*( OWS ";" OWS [ parameter ] )` — an empty parameter
// (`application/json;`) is allowed and contributes nothing.
const PARAM_RE = new RegExp(`${OWS};${OWS}(?:(${TOKEN})=(${TOKEN}|${QUOTED}))?`, "y");
// Edge whitespace is OWS only; CR/LF and every other control are refused.
const EDGE_OWS = /^[ \t]+|[ \t]+$/g;
// Anything outside printable ASCII + SP + HTAB.
const DISALLOWED_CHAR = /[^\t\x20-\x7E]/;

// JSON media-type essence: subtype `json`, `x-json`, or a `+json` / `+x-json`
// suffix, under any top-level type. Also request-handler's isJsonContentType
// rule (F-7), so the inspector and this policy agree on "is this JSON".
export const JSON_ESSENCE_RE = /^[\w.+-]+\/(?:[\w.+-]+\+)?(?:x-)?json$/i;

/** Parse a media type per RFC 7231, or `undefined` when it is not one. */
export function parseMediaType(s: string): MediaType | undefined {
  if (typeof s !== "string" || DISALLOWED_CHAR.test(s)) return undefined;
  const v = s.replace(EDGE_OWS, "");
  if (v.length === 0 || v.length > MAX_CONTENT_TYPE_LENGTH) return undefined;

  const essence = ESSENCE_RE.exec(v);
  if (!essence) return undefined;
  const params: Record<string, string> = Object.create(null) as Record<string, string>;
  let pos = essence[0].length;
  while (pos < v.length) {
    PARAM_RE.lastIndex = pos;
    const m = PARAM_RE.exec(v);
    if (!m) return undefined;
    pos = PARAM_RE.lastIndex;
    if (m[1] === undefined) continue;
    const name = m[1].toLowerCase();
    if (Object.prototype.hasOwnProperty.call(params, name)) return undefined;
    const raw = m[2]!;
    params[name] = raw.startsWith('"') ? raw.slice(1, -1).replace(/\\(.)/g, "$1") : raw;
  }
  return {
    type: essence[1]!.toLowerCase(),
    subtype: essence[2]!.toLowerCase(),
    params: { ...params },
  };
}

/**
 * `"application/json"` when `ct` is a JSON media type with no parameters or
 * only `charset=utf-8` (case-insensitive, quoted or not); `undefined` for
 * every other label, including unparseable ones.
 */
export function canonicalJsonContentType(ct: string): "application/json" | undefined {
  const mt = parseMediaType(ct);
  if (!mt) return undefined;
  if (!JSON_ESSENCE_RE.test(`${mt.type}/${mt.subtype}`)) return undefined;
  const names = Object.keys(mt.params);
  if (names.length === 0) return "application/json";
  if (names.length === 1 && names[0] === "charset" && mt.params.charset!.toLowerCase() === "utf-8") {
    return "application/json";
  }
  return undefined;
}
