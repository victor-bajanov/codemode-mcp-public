import { ToolError } from "./elicit";

/**
 * Build the upstream URL from provider base + resolved operation path,
 * and assert two invariants. Defence-in-depth on top of `matchOperation`,
 * which already refuses unsafe segments and derives the path from the
 * matched template.
 *
 * 1. Origin invariance. Catches paths that smuggle a host via
 *    scheme-relative ("//evil.com/x"), absolute ("http://evil.com/x"), or
 *    protocol-confusing ("/\\evil.com/x") forms. Throws `ToolError` with
 *    message prefix `upstream-url-origin-mismatch:` when
 *    `new URL(path, base).origin` differs from `new URL(base).origin`.
 * 2. Path invariance. The WHATWG parser collapses dot-segments (also
 *    `%2e`), turns `\` into `/`, strips tab/CR/LF, percent-encodes some
 *    characters and splits off `?query` / `#fragment` — any of which would
 *    send a different path from the one the operation was matched on.
 *    Throws `ToolError` with message prefix `upstream-url-path-mismatch:`
 *    unless the parsed pathname equals `path` exactly and the parsed URL has
 *    no search or hash (checked before `query` is applied). The path itself
 *    is not echoed: it may carry PII.
 *
 * `request-handler` tags the resulting audit entry with
 * `category: "url_safety"` so the event is greppable in production logs.
 *
 * Query semantics match the previous `URLSearchParams.set(k, String(v))`
 * loop: per-entry coerce, undefined values dropped.
 */
export function buildUpstreamUrl(
  base: string,
  path: string,
  query?: Record<string, string | number | boolean | undefined>,
): string {
  const baseUrl = new URL(base);
  const url = new URL(path, baseUrl);
  if (url.origin !== baseUrl.origin) {
    throw new ToolError(
      `upstream-url-origin-mismatch: Operation path resolved to a different origin than provider base. base=${baseUrl.origin} resolved=${url.origin}`,
    );
  }
  if (url.pathname !== path || url.search !== "" || url.hash !== "") {
    throw new ToolError(
      "upstream-url-path-mismatch: Operation path would be rewritten by the URL parser (dot-segments, backslashes, control characters, query or fragment syntax, or characters it percent-encodes)",
    );
  }
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined) continue;
      url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}
