// Shape validation for the `composed` body channel (plan §2, D5/D6).
//
// Runs before any storage access: a malformed request costs no D1 read. The
// rules keep staged bytes structurally inert: base64 segments cannot carry
// CR/LF, `:` or `--`, so they can never form headers, blank lines or MIME
// boundaries; identity bytes can, so identity is allowed only as the whole
// body. U+FFFC is the inspection view's staged-slot sentinel, so text may not
// contain it (checked on the post-`JSON.parse` string, so escaped forms are
// caught too). Messages never echo a token, a handle or text content.

import { isPlausibleStagedRef, type StagedRef } from "../staging/staged-file";

export type StagedEncoding = "base64-lines" | "base64" | "identity";

export type Segment =
  | { kind: "text"; bytes: Uint8Array }
  | { kind: "staged"; ref: StagedRef; encoding: StagedEncoding; index: number };

export type ComposedReason =
  | "composed-malformed"
  | "composed-text-reserved-char"
  | "composed-text-not-well-formed"
  | "composed-identity-not-sole"
  | "multiple-body-channels";

export type ValidateComposedResult =
  | { ok: true; segments: Segment[] }
  | { ok: false; reason: ComposedReason; message: string };

export const COMPOSED_MAX_SEGMENTS = 32;
export const COMPOSED_MAX_TEXT_BYTES = 4 * 1024 * 1024;
/** OBJECT REPLACEMENT CHARACTER: the staged-slot sentinel of the inspection view. */
export const STAGED_SENTINEL = "￼";

const ENCODINGS: ReadonlySet<string> = new Set<StagedEncoding>(["base64-lines", "base64", "identity"]);
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const TEXT_ENCODER = new TextEncoder();

/** A plain JSON-style object: prototype Object.prototype or null, not an array. */
export function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** True when `v` is a plain object whose own keys are exactly `keys`. */
export function hasExactKeys(v: unknown, keys: readonly string[]): v is Record<string, unknown> {
  if (!isPlainObject(v)) return false;
  const own = Object.keys(v);
  return own.length === keys.length && keys.every((k) => Object.hasOwn(v, k));
}

/** A `{ file_handle, token }` reference with nothing else on it, passing the
 *  prefix/decoded-length pre-check. Returns a fresh copy, or null. */
export function parseStagedRef(v: unknown): StagedRef | null {
  if (!hasExactKeys(v, ["file_handle", "token"])) return null;
  if (!isPlausibleStagedRef(v)) return null;
  return { file_handle: v.file_handle, token: v.token };
}

export function isWellFormedText(s: string): boolean {
  const native = (s as unknown as { isWellFormed?: () => boolean }).isWellFormed;
  return typeof native === "function" ? native.call(s) : !LONE_SURROGATE.test(s);
}

function fail(reason: ComposedReason, message: string): ValidateComposedResult {
  return { ok: false, reason, message };
}

/**
 * Validate `ctx.composed` (and its exclusivity with every other body
 * channel). `ctx` is the sandbox-supplied request object; only `composed`,
 * `body`, `bodyBase64`, `rawBody` and `multipart` are read.
 */
export function validateComposed(ctx: unknown): ValidateComposedResult {
  const c = (ctx ?? {}) as Record<string, unknown>;
  if (
    (c.body !== undefined && c.body !== null) ||
    c.bodyBase64 !== undefined ||
    c.rawBody !== undefined ||
    c.multipart !== undefined
  ) {
    return fail(
      "multiple-body-channels",
      "`composed` cannot be combined with `body`, `bodyBase64`, `rawBody` or `multipart`",
    );
  }
  const composed = c.composed;
  if (!hasExactKeys(composed, ["segments"]) || !Array.isArray(composed.segments)) {
    return fail("composed-malformed", "`composed` must be an object of the form { segments: [...] }");
  }
  const raw: unknown[] = composed.segments;
  if (raw.length < 1 || raw.length > COMPOSED_MAX_SEGMENTS) {
    return fail("composed-malformed", `\`composed.segments\` must hold 1 to ${COMPOSED_MAX_SEGMENTS} segments`);
  }

  // Cheap bound first: every UTF-16 unit encodes to at least one byte.
  let textUnits = 0;
  for (const s of raw) {
    if (isPlainObject(s) && typeof s.text === "string") textUnits += s.text.length;
  }
  if (textUnits > COMPOSED_MAX_TEXT_BYTES) {
    return fail("composed-malformed", `\`composed\` text segments exceed ${COMPOSED_MAX_TEXT_BYTES} bytes in total`);
  }

  const segments: Segment[] = [];
  let textBytes = 0;
  for (let i = 0; i < raw.length; i++) {
    const s = raw[i];
    if (hasExactKeys(s, ["text"])) {
      const text = s.text;
      if (typeof text !== "string") {
        return fail("composed-malformed", `composed segment ${i}: \`text\` must be a string`);
      }
      if (text.includes(STAGED_SENTINEL)) {
        return fail(
          "composed-text-reserved-char",
          `composed segment ${i}: text may not contain U+FFFC (reserved for staged-file slots)`,
        );
      }
      if (!isWellFormedText(text)) {
        return fail(
          "composed-text-not-well-formed",
          `composed segment ${i}: text contains a lone surrogate (it would be sent as U+FFFD)`,
        );
      }
      const bytes = TEXT_ENCODER.encode(text);
      textBytes += bytes.byteLength;
      if (textBytes > COMPOSED_MAX_TEXT_BYTES) {
        return fail("composed-malformed", `\`composed\` text segments exceed ${COMPOSED_MAX_TEXT_BYTES} bytes in total`);
      }
      segments.push({ kind: "text", bytes });
      continue;
    }
    if (hasExactKeys(s, ["staged", "encoding"])) {
      const encoding = s.encoding;
      if (typeof encoding !== "string" || !ENCODINGS.has(encoding)) {
        return fail(
          "composed-malformed",
          `composed segment ${i}: \`encoding\` must be "base64-lines", "base64" or "identity"`,
        );
      }
      const ref = parseStagedRef(s.staged);
      if (!ref) {
        return fail(
          "composed-malformed",
          `composed segment ${i}: \`staged\` must be { file_handle, token } from register_file_handle or a staging call`,
        );
      }
      segments.push({ kind: "staged", ref, encoding: encoding as StagedEncoding, index: i });
      continue;
    }
    return fail(
      "composed-malformed",
      `composed segment ${i}: must be { text } or { staged: { file_handle, token }, encoding }`,
    );
  }
  if (segments.length > 1 && segments.some((s) => s.kind === "staged" && s.encoding === "identity")) {
    return fail(
      "composed-identity-not-sole",
      '`encoding: "identity"` is allowed only when the staged file is the whole body (a single segment)',
    );
  }
  return { ok: true, segments };
}
