import { decodeEncodedWords } from "./outbound.js";

/**
 * Send-path Subject normalizer (SurfaceReviewEntry.normalizeBody).
 *
 * The executeHint documents the correct one-pass UTF-8 + RFC 2047 idiom, but a
 * model composing `raw` in the sandbox can still improvise a double-wrapped
 * encoder — the 2026-08-25 MCP-v2 watch email shipped an em dash (U+2014) as
 * the bytes C3 83 C2 A2 C3 82 C2 80 C3 82 C2 94: UTF-8 → "read as Latin-1,
 * re-encode as UTF-8" applied twice, dumped raw into the header, rendering as
 * "Ã¢Â€Â”". Guidance alone demonstrably doesn't prevent this, so the provider
 * repairs the Subject host-side: for the same buggy input, the delivered mail
 * renders the intended text.
 *
 * What it does, given a `{ raw }` / `{ message: { raw } }` send or draft body:
 *   1. decode base64url `raw`, split off the RFC 822 header section;
 *   2. recover the logical Subject text (unfold, decode RFC 2047 words);
 *   3. unwind however many "UTF-8 bytes read as Latin-1 and re-encoded" layers
 *      it carries (strict-decode guarded — text that merely looks Latin-1-ish
 *      is left alone);
 *   4. re-emit it canonically: ASCII verbatim, anything else as folded RFC 2047
 *      UTF-8 B encoded-words (raw non-ASCII header bytes are what mail clients
 *      re-read as CP1252 — mojibake even when single-encoded correctly).
 *
 * Presentation-layer only: recipients, ids and the message body are untouched
 * (body bytes are spliced back verbatim), so the outbound inspector rules on
 * exactly what is sent. Every bail-out path returns undefined = "no change";
 * this must never block a send.
 */

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

function base64UrlToBytes(s: string): Uint8Array {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  // Chunked to stay clear of argument-count limits on large messages.
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Unwind N layers of "UTF-8 bytes read as Latin-1 and re-encoded as UTF-8".
 * A layer is undone only when the string is entirely ≤ U+00FF (i.e. could be a
 * byte string), contains at least one non-ASCII char, and those bytes decode
 * as STRICT UTF-8 — genuine Latin-1-looking text ("Ã la carte", "café") fails
 * the strict decode and is returned untouched. Exported for tests.
 */
export function repairMojibake(value: string): string {
  let s = value;
  // Two layers covers the observed double-encoding; 4 bounds any pathology.
  for (let i = 0; i < 4; i++) {
    if (!/[\u0080-\u00ff]/.test(s) || !/^[\u0000-\u00ff]*$/.test(s)) return s;
    const bytes = new Uint8Array(s.length);
    for (let j = 0; j < s.length; j++) bytes[j] = s.charCodeAt(j);
    let decoded: string;
    try {
      decoded = STRICT_UTF8.decode(bytes);
    } catch {
      return s;
    }
    if (decoded === s) return s;
    s = decoded;
  }
  return s;
}

/** Neutralize header-injection material a decoded encoded-word could smuggle:
 *  CR/LF and other control chars collapse to a space (mirrors optical's
 *  headerValue). */
function headerSafe(v: string): string {
  return v.replace(/[\r\n\x00-\x1F\x7F\u2028\u2029]+/g, " ").trim();
}

/**
 * RFC 2047 encoded-word encoding for a Subject value. ASCII passes through
 * unchanged. Non-ASCII is chunked into ≤45-byte UTF-8 groups (so each base64
 * encoded-word stays within the 75-char limit), split on code-point
 * boundaries, and folded with EOL + space. Exported for tests.
 */
export function encodeHeaderWord(value: string, eol = "\r\n"): string {
  if (/^[\x00-\x7F]*$/.test(value)) return value;
  const enc = new TextEncoder();
  const word = (bytes: number[]): string => {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return `=?UTF-8?B?${btoa(bin)}?=`;
  };
  const words: string[] = [];
  let buf: number[] = [];
  for (const ch of value) {
    const b = Array.from(enc.encode(ch));
    if (buf.length + b.length > 45) {
      words.push(word(buf));
      buf = [];
    }
    buf.push(...b);
  }
  if (buf.length) words.push(word(buf));
  return words.join(`${eol} `);
}

/** Byte offset of the header/body blank-line separator (start of "\r\n\r\n" or
 *  "\n\n"), or -1. Scans bytes, not text, so the body is never decoded. */
function headerEndOffset(bytes: Uint8Array): number {
  for (let i = 0; i + 1 < bytes.length; i++) {
    if (bytes[i] === 0x0a && bytes[i + 1] === 0x0a) return i;
    if (
      bytes[i] === 0x0d &&
      bytes[i + 1] === 0x0a &&
      bytes[i + 2] === 0x0d &&
      bytes[i + 3] === 0x0a
    ) {
      return i;
    }
  }
  return -1;
}

/** Repair the Subject header inside one base64url-encoded RFC 822 message.
 *  Returns the re-encoded raw, or undefined when nothing needs changing (or
 *  the message can't be confidently interpreted — every failure bails to
 *  "no change"). */
export function repairRawSubject(raw: string): string | undefined {
  let bytes: Uint8Array;
  try {
    bytes = base64UrlToBytes(raw);
  } catch {
    return undefined;
  }
  const headerEnd = headerEndOffset(bytes);
  if (headerEnd < 0) return undefined;

  // Strict decode: a header section that isn't valid UTF-8 (e.g. true Latin-1
  // bytes) can't be round-tripped losslessly through text — leave it alone.
  let headerText: string;
  try {
    headerText = STRICT_UTF8.decode(bytes.subarray(0, headerEnd));
  } catch {
    return undefined;
  }

  const eol = headerText.includes("\r\n") ? "\r\n" : "\n";
  const lines = headerText.split(/\r\n|\n/);
  let start = -1;
  let endEx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^subject:/i.test(lines[i]!)) {
      start = i;
      endEx = i + 1;
      // RFC 822 §3.1.1 folding: WSP-led lines continue the header.
      while (endEx < lines.length && /^[ \t]/.test(lines[endEx]!)) endEx++;
      break;
    }
  }
  if (start < 0) return undefined;

  const firstLine = lines[start]!;
  const unfolded = [
    firstLine.slice(firstLine.indexOf(":") + 1).trim(),
    ...lines.slice(start + 1, endEx).map((l) => l.trim()),
  ]
    .filter((s) => s.length > 0)
    .join(" ");

  // RFC 2047 §6.2: whitespace between adjacent encoded-words is not content —
  // collapse it so our own folded output round-trips without gaining spaces.
  const logical = decodeEncodedWords(unfolded.replace(/(\?=)\s+(=\?)/g, "$1$2"));
  const canonical = encodeHeaderWord(headerSafe(repairMojibake(logical)), eol);
  // Compare fold-insensitively: an already-canonical subject (possibly folded
  // across continuation lines) must round-trip to "no change".
  if (canonical.split(`${eol} `).join(" ") === unfolded) return undefined;

  const newLines = [...lines.slice(0, start), `Subject: ${canonical}`, ...lines.slice(endEx)];
  const newHeaderBytes = new TextEncoder().encode(newLines.join(eol));
  const tail = bytes.subarray(headerEnd); // blank-line separator + body, verbatim
  const out = new Uint8Array(newHeaderBytes.length + tail.length);
  out.set(newHeaderBytes, 0);
  out.set(tail, newHeaderBytes.length);
  return bytesToBase64Url(out);
}

/**
 * normalizeBody hook for messages.send / drafts.create / drafts.update /
 * drafts.send. Handles the two send-path body shapes — `{ raw }` and the Draft
 * wrapper `{ message: { raw } }` — and returns a shallow copy with the
 * repaired raw, or undefined to leave the request untouched.
 */
export function normalizeOutboundMessage(body: unknown): unknown {
  if (!isObject(body)) return undefined;
  if (typeof body["raw"] === "string") {
    const fixed = repairRawSubject(body["raw"]);
    return fixed === undefined ? undefined : { ...body, raw: fixed };
  }
  const message = body["message"];
  if (isObject(message) && typeof message["raw"] === "string") {
    const fixed = repairRawSubject(message["raw"]);
    return fixed === undefined ? undefined : { ...body, message: { ...message, raw: fixed } };
  }
  return undefined;
}
