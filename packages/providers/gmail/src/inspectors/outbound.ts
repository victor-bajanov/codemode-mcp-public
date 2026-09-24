import type { InspectEnv, InspectRequest, InspectResult } from "@local/shared";
import { isAllowedRecipient, outboundAllowlistFromEnv } from "./allowlist.js";

/** Strictly-greater-than threshold for mass-send elicitation. 26+ recipients elicits. */
export const MASS_SEND_THRESHOLD = 25;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/** Decode standard/url-safe base64 to its raw bytes via the global `atob`
 *  (available in both Node 18+ and Workers). */
function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/**
 * Decode a base64url-encoded string to its UTF-8 text. `atob` yields a binary
 * (Latin-1) string, so we must map it back to bytes and decode as UTF-8 —
 * otherwise a non-ASCII header (e.g. a Subject with an em dash "—") comes back
 * mojibake'd. Decoding is non-fatal: invalid sequences in the discarded body
 * region become U+FFFD rather than throwing.
 */
function base64UrlDecode(s: string): string {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return new TextDecoder("utf-8").decode(base64ToBytes(b64));
}

/**
 * Decode RFC 2047 encoded-words (`=?charset?B?...?=` / `=?charset?Q?...?=`)
 * embedded in a header value. Only UTF-8/US-ASCII charsets are decoded; any
 * other charset (or a malformed word) is left verbatim. Used for the
 * human-facing elicit summary so a correctly-encoded non-ASCII Subject shows
 * its real text instead of the raw encoded-word. Display-only — never feeds a
 * security decision. Also reused by the send normalizer (normalize-subject.ts)
 * to recover the logical subject text before mojibake repair.
 */
export function decodeEncodedWords(value: string): string {
  return value.replace(
    /=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g,
    (whole, charset: string, enc: string, text: string) => {
      if (!/^(utf-?8|us-ascii)$/i.test(charset)) return whole;
      try {
        let bytes: Uint8Array;
        if (enc.toUpperCase() === "B") {
          bytes = base64ToBytes(text);
        } else {
          // Q-encoding: `_` is a space, `=XX` is a hex byte, else literal.
          const out: number[] = [];
          for (let i = 0; i < text.length; i++) {
            const c = text[i]!;
            if (c === "_") {
              out.push(0x20);
            } else if (c === "=" && i + 2 < text.length) {
              out.push(parseInt(text.slice(i + 1, i + 3), 16));
              i += 2;
            } else {
              out.push(text.charCodeAt(i));
            }
          }
          bytes = new Uint8Array(out);
        }
        return new TextDecoder("utf-8").decode(bytes);
      } catch {
        return whole;
      }
    },
  );
}

/**
 * Split an RFC 822 address-list header value on commas. Trims each element,
 * filters empties. Does not handle quoted display names with embedded commas
 * — slice 1 inputs are simple `a@b, c@d` style. Bare-angle-bracket form
 * `Name <addr@host>` has its bracketed address extracted when present.
 */
function splitAddresses(headerValue: string): string[] {
  return headerValue
    .split(",")
    .map((part) => {
      const s = part.trim();
      const lt = s.indexOf("<");
      const gt = s.indexOf(">", lt + 1);
      if (lt >= 0 && gt > lt) {
        return s.slice(lt + 1, gt).trim();
      }
      return s;
    })
    .filter((s) => s.length > 0);
}

/**
 * Parse RFC 822 header section. Splits on the first blank line (CRLF or LF
 * variants), unfolds continuation lines (a line beginning with a space or tab
 * is a continuation of the previous header per RFC 822 §3.1.1 — dropping this
 * would hide a folded recipient list from the inspector while Gmail still
 * unfolds and sends to it), then walks each header line pulling `Name: Value`.
 * Header names are normalized to lowercase. Structured fields are not parsed
 * further — slice 1 fixtures are otherwise single-line.
 */
function parseHeaders(rfc822: string): Map<string, string> {
  const headers = new Map<string, string>();
  // Locate end of header section.
  let endIdx = rfc822.indexOf("\r\n\r\n");
  if (endIdx < 0) endIdx = rfc822.indexOf("\n\n");
  const headerSection = endIdx >= 0 ? rfc822.slice(0, endIdx) : rfc822;
  const rawLines = headerSection.split(/\r?\n/);
  const lines: string[] = [];
  for (const line of rawLines) {
    if ((line.startsWith(" ") || line.startsWith("\t")) && lines.length > 0) {
      lines[lines.length - 1] += " " + line.trim();
    } else {
      lines.push(line);
    }
  }
  for (const line of lines) {
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (name.length > 0) headers.set(name, value);
  }
  return headers;
}

/** Max bytes to decode when scanning an uploaded message for its header block.
 *  Headers precede the first blank line, so a small prefix suffices even for a
 *  50 MB attachment. */
const RFC822_HEADER_SCAN_BYTES = 64 * 1024;

/** Recipients (to/cc/bcc) parsed from raw RFC 822 header text. */
function recipientsFromRfc822(text: string): string[] {
  const headers = parseHeaders(text);
  const collected: string[] = [];
  for (const name of ["to", "cc", "bcc"] as const) {
    const v = headers.get(name);
    if (typeof v === "string" && v.length > 0) collected.push(...splitAddresses(v));
  }
  return Array.from(new Set(collected.map((s) => s.trim().toLowerCase()).filter((s) => s.length > 0)));
}

/** Subject parsed from raw RFC 822 header text (display-only, encoded-words decoded). */
function subjectFromRfc822(text: string): string {
  return decodeEncodedWords(parseHeaders(text).get("subject") ?? "");
}

/** Decode a bounded prefix of bytes as UTF-8 text (non-fatal). */
function bytesPrefixToText(bytes: Uint8Array): string {
  const slice = bytes.byteLength > RFC822_HEADER_SCAN_BYTES ? bytes.subarray(0, RFC822_HEADER_SCAN_BYTES) : bytes;
  return new TextDecoder("utf-8", { fatal: false, ignoreBOM: false }).decode(slice);
}

/** True when a multipart part's content-type is JSON metadata. */
function isJsonPart(contentType: string | undefined): boolean {
  return typeof contentType === "string" && /application\/(?:[\w.+-]+\+)?json\b/i.test(contentType);
}

/** True when the scanned prefix contains the header/body blank-line terminator
 *  (CRLF or LF variant). `parseHeaders` silently treats its *entire* input as
 *  the header section when no terminator is found, so a candidate whose real
 *  terminator falls past the scan window must be rejected here rather than
 *  handed to `parseHeaders` — otherwise a recipient header sitting beyond the
 *  scanned prefix (e.g. behind >64 KiB of padding) would go unseen while a
 *  visible, allowlisted header earlier in the prefix causes a false allow. */
function hasHeaderTerminatorWithinScan(text: string): boolean {
  return text.includes("\r\n\r\n") || text.includes("\n\n");
}

/** Locate the uploaded message text in a non-JSON effective payload
 *  (rawBody = uploadType=media; multipart = uploadType=multipart). Returns null
 *  when no candidate message can be found, its terminator falls outside the
 *  scanned prefix, or it fails to decode — caller fails closed in all cases. */
function rfc822FromNonJson(req: InspectRequest): string | null {
  if (req.rawBody !== undefined) {
    // Note: the string branch slices by UTF-16 code units, not bytes, unlike
    // the byte-array branch below. The scan window is generous enough for
    // header-only text that this distinction doesn't matter in practice.
    const text =
      typeof req.rawBody === "string"
        ? req.rawBody.slice(0, RFC822_HEADER_SCAN_BYTES)
        : bytesPrefixToText(req.rawBody instanceof Uint8Array ? req.rawBody : new Uint8Array(req.rawBody));
    return hasHeaderTerminatorWithinScan(text) ? text : null;
  }
  if (Array.isArray(req.multipart)) {
    const parts = req.multipart;
    const rfc822Part = parts.find((p) => (p.contentType ?? "").toLowerCase().includes("message/rfc822"));
    let chosen = rfc822Part;
    if (!chosen) {
      // No part is explicitly typed message/rfc822. Only fall back to a
      // single unambiguous non-JSON part; two or more candidates could
      // disagree with which part Gmail's media parser actually selects, so
      // fail closed rather than guess.
      const nonJsonParts = parts.filter((p) => !isJsonPart(p.contentType));
      if (nonJsonParts.length === 1) chosen = nonJsonParts[0];
    }
    if (!chosen) return null;

    let text: string | null = null;
    if (typeof chosen.value === "string") {
      text = chosen.value.slice(0, RFC822_HEADER_SCAN_BYTES);
    } else if (typeof chosen.bodyBase64 === "string") {
      // Bound the decode: 4 base64 chars → 3 bytes.
      const cap = Math.ceil(RFC822_HEADER_SCAN_BYTES / 3) * 4;
      try {
        text = bytesPrefixToText(base64ToBytes(chosen.bodyBase64.slice(0, cap)));
      } catch {
        return null;
      }
    }
    if (text === null) return null;
    return hasHeaderTerminatorWithinScan(text) ? text : null;
  }
  return null;
}

/** Shared decision from a recipient set + lazy subject getter. */
function decideRecipients(
  recipients: string[],
  allowlist: readonly string[],
  getSubject: () => string,
): InspectResult {
  for (const r of recipients) {
    if (!isAllowedRecipient(r, allowlist)) {
      return { decision: "deny", category: "external_data_flow", reason: "external-send" };
    }
  }
  if (recipients.length > MASS_SEND_THRESHOLD) {
    const subject = getSubject();
    return {
      decision: "elicit",
      category: "external_data_flow",
      reason: "mass-send",
      summary: {
        recipients:
          recipients.slice(0, 3).join(", ") + (recipients.length > 3 ? ` (+${recipients.length - 3})` : ""),
        subject: String(subject ?? "").slice(0, 200),
        count: recipients.length,
      },
    };
  }
  return { decision: "allow" };
}

/**
 * Extract the Subject header from a Gmail Message resource. Looks at
 * `message.raw` first; falls back to `message.payload.headers`. Returns an
 * empty string when no subject can be found.
 */
function extractSubject(message: Record<string, unknown>): string {
  const raw = message["raw"];
  if (typeof raw === "string" && raw.length > 0) {
    let decoded: string;
    try {
      decoded = base64UrlDecode(raw);
    } catch {
      decoded = "";
    }
    if (decoded.length > 0) {
      const headers = parseHeaders(decoded);
      return decodeEncodedWords(headers.get("subject") ?? "");
    }
  }
  const payload = message["payload"];
  if (isObject(payload)) {
    const headers = payload["headers"];
    if (Array.isArray(headers)) {
      for (const h of headers) {
        if (!isObject(h)) continue;
        const name = h["name"];
        const value = h["value"];
        if (typeof name === "string" && typeof value === "string" && name.toLowerCase() === "subject") {
          return decodeEncodedWords(value);
        }
      }
    }
  }
  return "";
}

/**
 * Extract recipient addresses from a Gmail Message resource. Looks at
 * `message.raw` (base64url-encoded RFC 822) first; falls back to
 * `message.payload.headers`. Returns deduplicated, lowercase-normalized
 * addresses.
 */
function extractRecipients(message: Record<string, unknown>): string[] {
  const collected: string[] = [];

  const raw = message["raw"];
  if (typeof raw === "string" && raw.length > 0) {
    let decoded: string;
    try {
      decoded = base64UrlDecode(raw);
    } catch {
      decoded = "";
    }
    if (decoded.length > 0) {
      const headers = parseHeaders(decoded);
      for (const name of ["to", "cc", "bcc"] as const) {
        const v = headers.get(name);
        if (typeof v === "string" && v.length > 0) {
          collected.push(...splitAddresses(v));
        }
      }
    }
  } else {
    const payload = message["payload"];
    if (isObject(payload)) {
      const headers = payload["headers"];
      if (Array.isArray(headers)) {
        for (const h of headers) {
          if (!isObject(h)) continue;
          const name = h["name"];
          const value = h["value"];
          if (typeof name !== "string" || typeof value !== "string") continue;
          const lower = name.toLowerCase();
          if (lower === "to" || lower === "cc" || lower === "bcc") {
            collected.push(...splitAddresses(value));
          }
        }
      }
    }
  }

  const normalized = collected
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
  return Array.from(new Set(normalized));
}

/**
 * Inspector for outbound Gmail sends: messages.send directly, and drafts.send
 * update-and-send bodies via `inspectDraftSend`. (drafts.create / drafts.update
 * are deliberately NOT inspected — a draft is inert until sent, so it may
 * address anyone; the allowlist bites at send time instead.)
 *
 * Dispatches by the *effective* payload channel (see `InspectRequest`):
 *
 *   JSON body (`req.body`):
 *     1. Body must be an object. (Otherwise → deny/malformed/send-no-recipients.)
 *     2. If body looks like a draft wrapper with no usable message (`id`
 *        present, no usable `message`), return deny/malformed/draft-update-no-message.
 *     3. Unwrap `body.message` if present (drafts.send update-and-send).
 *     4. Extract recipients from `raw` or `payload.headers`. Empty → deny/malformed.
 *
 *   Non-JSON payload (`req.rawBody` media upload, or `req.multipart` upload):
 *     Locate the uploaded RFC 822 message and extract recipients from its
 *     headers. No candidate message, or no recipients found → deny/malformed
 *     (fail closed).
 *
 *   Either path then applies the same recipient decision:
 *     5. Any recipient off the deployment's allowlist (from the
 *        OUTBOUND_RECIPIENT_ALLOWLIST var; missing env/var → empty list, so
 *        every recipient denies) → deny/external_data_flow/external-send.
 *        (Off-allowlist wins over mass-send.)
 *     6. Recipient count > MASS_SEND_THRESHOLD → elicit/mass-send.
 *     7. Otherwise → allow.
 */
export function inspectOutboundMessage(req: InspectRequest, env?: InspectEnv): InspectResult {
  const allowlist = outboundAllowlistFromEnv(env);
  if (isObject(req.body)) {
    const body = req.body;

    // Detect the Draft resource wrapper (drafts.send update-and-send).
    let message: Record<string, unknown>;
    if ("message" in body) {
      const inner = body["message"];
      if (!isObject(inner)) {
        if ("id" in body) {
          return {
            decision: "deny",
            category: "malformed",
            reason: "draft-update-no-message",
          };
        }
        return {
          decision: "deny",
          category: "malformed",
          reason: "send-no-recipients",
        };
      }
      message = inner;
    } else if ("id" in body && !("raw" in body) && !("payload" in body)) {
      // Bare {id} — drafts.update with no message provided.
      return {
        decision: "deny",
        category: "malformed",
        reason: "draft-update-no-message",
      };
    } else {
      message = body;
    }

    const recipients = extractRecipients(message);
    if (recipients.length === 0) {
      return { decision: "deny", category: "malformed", reason: "send-no-recipients" };
    }
    return decideRecipients(recipients, allowlist, () => extractSubject(message));
  }

  // Non-JSON effective payload: media upload (rawBody) or multipart upload.
  const text = rfc822FromNonJson(req);
  if (text === null) {
    return { decision: "deny", category: "malformed", reason: "send-no-recipients" };
  }
  const recipients = recipientsFromRfc822(text);
  if (recipients.length === 0) {
    return { decision: "deny", category: "malformed", reason: "send-no-recipients" };
  }
  return decideRecipients(recipients, allowlist, () => subjectFromRfc822(text));
}

/**
 * Inspector for `drafts.send`. Drafts are created and updated WITHOUT
 * recipient gating (a draft is inert, and may legitimately address anyone or
 * no one while being composed), so a stored draft's recipients are unvetted.
 * Inspectors are synchronous and see only the request, so a bare `{id}` send
 * — whose recipients live server-side in the stored draft — cannot be checked
 * against the allowlist and must fail closed.
 *
 * The workable send path is update-and-send: `{id, message}` replaces the
 * draft's content with the carried message before Gmail sends it, so the
 * carried recipients ARE the send's recipients. That shape (and any non-JSON
 * media/multipart channel) is delegated to `inspectOutboundMessage`, where
 * the allowlist and mass-send checks bite exactly as for messages.send.
 */
export function inspectDraftSend(req: InspectRequest, env?: InspectEnv): InspectResult {
  if (
    isObject(req.body) &&
    !("message" in req.body) &&
    !("raw" in req.body) &&
    !("payload" in req.body)
  ) {
    return {
      decision: "deny",
      category: "external_data_flow",
      reason: "draft-send-unvetted-recipients",
      message:
        "Refusing to send a draft by id alone: recipients are not checked at " +
        "draft time and the stored draft cannot be read at send time, so its " +
        "recipients cannot be verified against the outbound allowlist. Send " +
        "it as an update-and-send instead — POST the same drafts.send request " +
        "with { id, message: { raw } } carrying the full message — so the " +
        "recipients ride in the request and pass inspection.",
    };
  }
  return inspectOutboundMessage(req, env);
}
