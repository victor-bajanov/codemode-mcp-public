import { ToolError } from "./elicit";

/**
 * Build the upstream URL from provider base + resolved operation path,
 * and assert origin invariance. Defence-in-depth on top of
 * `resolveOperation`'s static path matching: catches paths that smuggle
 * a host via scheme-relative ("//evil.com/x"), absolute
 * ("http://evil.com/x"), or protocol-confusing forms.
 *
 * Throws `ToolError` with message prefix `upstream-url-origin-mismatch:`
 * when `new URL(path, base).origin` differs from `new URL(base).origin`.
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
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined) continue;
      url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}
