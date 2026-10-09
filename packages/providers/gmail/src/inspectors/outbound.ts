import type { InspectEnv, InspectRequest, InspectResult } from "@local/shared";
import { isAllowedRecipient, isPlainAddrSpec, outboundAllowlistFromEnv } from "./allowlist.js";

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
 * Split an RFC 822 address-list header value on commas, trim each element and
 * drop empties. The split is naive (it does not know about quoted strings or
 * comments), so each element is then read conservatively and fails closed:
 *
 *   - an element containing `"`, `(` or `)` is returned unchanged. A quoted
 *     display-name or a CFWS comment can carry text that looks like an
 *     angle-addr but is not where the message goes: `"<ok@a>" <evil@x>` and
 *     `evil@x (<ok@a>)` are both delivered to evil@x. Returned unchanged, the
 *     element is not a plain addr-spec, so `isAllowedRecipient` refuses it and
 *     the send denies as external-send (F-3, F-18);
 *   - the angle-addr of `Name <addr@host>` is extracted only when the element
 *     has exactly one `<` and one `>`, the `>` is its last character, and the
 *     display-name before the `<` is an unquoted RFC 5322 phrase: atext,
 *     dots and whitespace only (non-ASCII allowed, as RFC 6532 does). A
 *     display-name holding `@`, `:`, `;`, `[`, `]`, `\` or `,` is not a
 *     phrase, and a mainstream parser reads `evil@x <ok@a>`, `evil@x: <ok@a>`
 *     or `g:evil@x; <ok@a>` as a message to evil@x (F-3);
 *   - anything else is returned unchanged (and so refused).
 *
 * Known false positive, accepted: a quoted display-name, including one with
 * an embedded comma such as `"Smith, John" <ok@a>`, is refused, as is a
 * display-name that repeats the address (`ok@a <ok@a>`).
 */
function splitAddresses(headerValue: string): string[] {
  return headerValue
    .split(",")
    .map((part) => {
      const s = part.trim();
      if (/["()]/.test(s)) return s;
      const lt = s.indexOf("<");
      if (lt < 0) return s;
      const gt = s.indexOf(">");
      const singleAngleAddr =
        lt === s.lastIndexOf("<") && gt === s.lastIndexOf(">") && gt === s.length - 1 && gt > lt;
      if (!singleAngleAddr) return s;
      if (!DISPLAY_NAME_PHRASE.test(s.slice(0, lt))) return s;
      return s.slice(lt + 1, gt).trim();
    })
    .filter((s) => s.length > 0);
}

/** An unquoted RFC 5322 display-name (possibly empty): atext, `.` (obs-phrase)
 *  and whitespace, plus non-ASCII text (RFC 6532). RFC 2047 encoded-words are
 *  made of atext, so they pass. Excludes the specials `@ : ; , [ ] \ < > " ( )`. */
const DISPLAY_NAME_PHRASE = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.\s\u0080-\uFFFF]*$/;

/** Normalise CRLF line endings to LF, so every RFC 822 reader in this module
 *  agrees on where lines (and the header block) end. A lone CR is NOT a line
 *  ending here: RFC 5322 does not define it as one and MIME readers disagree
 *  on it, so `lineEndingDecision` refuses any lone CR in the header block
 *  before this reading is relied on (F-3). */
function normaliseLineEndings(text: string): string {
  return text.replace(/\r\n/g, "\n");
}

/**
 * Deny when the header block's line endings are ambiguous. The header block is
 * found with CRLF and bare LF as the only line endings (as `parseHeaders`
 * reads it) and runs up to and including the first empty line, or over the
 * whole text when there is none. Within it:
 *
 *   - a CR not followed by LF is refused: some readers (Python's feedparser,
 *     JavaMail) treat a lone CR as a line break, others (MimeKit, many MTAs)
 *     as an ordinary character, so `To: a\r\rTo: b` is one To header, two,
 *     or a To followed by body depending on the reader;
 *   - CRLF mixed with bare LF is refused: a reader that detects the
 *     line-ending style from the first line would not see `\r\n\n` or
 *     `\n\r\n` as the end of the header block.
 *
 * Failing closed here, rather than picking one reading, keeps the inspector
 * from judging a recipient set Gmail's MTA might not use (F-3). The body is
 * not examined.
 */
function lineEndingDecision(text: string): InspectResult | null {
  const ambiguous: InspectResult = {
    decision: "deny",
    category: "malformed",
    reason: "ambiguous-line-ending",
    message:
      "The message header block has a bare CR or mixes CRLF with bare LF line endings; " +
      "end every header line, and the blank line after the headers, with CRLF",
  };
  const lineEnd = /\r?\n/g;
  let start = 0;
  let sawCrlf = false;
  let sawLf = false;
  let m: RegExpExecArray | null;
  while ((m = lineEnd.exec(text)) !== null) {
    const line = text.slice(start, m.index);
    if (line.includes("\r")) return ambiguous;
    if (m[0] === "\r\n") sawCrlf = true;
    else sawLf = true;
    if (sawCrlf && sawLf) return ambiguous;
    start = m.index + m[0].length;
    if (line.length === 0) return null; // the empty line ends the header block
  }
  // No empty line: the whole text is the header section.
  return text.slice(start).includes("\r") ? ambiguous : null;
}

/**
 * The header section's lines, unfolded. Line endings are normalised first
 * (CRLF becomes LF; callers deny a lone CR or mixed endings in the header
 * block via `lineEndingDecision` before relying on the result), and the
 * header section ends at the FIRST empty line, as RFC 5322 §2.1 requires; a
 * message that begins with an empty line has an empty header section.
 * Searching for one terminator style before the other would let a bare-LF
 * header block be extended into the body by a later CRLFCRLF, with body text
 * then parsed as headers (F-3).
 *
 * Continuation lines are unfolded (a line beginning with a space or tab is a
 * continuation of the previous header per RFC 822 §3.1.1 — dropping this
 * would hide a folded recipient list from the inspector while Gmail still
 * unfolds and sends to it).
 */
function unfoldedHeaderLines(rfc822: string): string[] {
  const text = normaliseLineEndings(rfc822);
  let headerSection: string;
  if (text.startsWith("\n")) {
    headerSection = "";
  } else {
    const endIdx = text.indexOf("\n\n");
    headerSection = endIdx >= 0 ? text.slice(0, endIdx) : text;
  }
  if (headerSection.length === 0) return [];
  const lines: string[] = [];
  for (const line of headerSection.split("\n")) {
    if ((line.startsWith(" ") || line.startsWith("\t")) && lines.length > 0) {
      lines[lines.length - 1] += " " + line.trim();
    } else {
      lines.push(line);
    }
  }
  return lines;
}

/**
 * Parse the RFC 822 header section (see `unfoldedHeaderLines` for where it
 * ends and how folding is handled); each header line yields `Name: Value`.
 * Header names are normalised to lowercase and EVERY occurrence is kept, in
 * order: MTAs honour every recipient line, so keeping only the last one would
 * judge a message on a recipient set Gmail does not use (F-3). Structured
 * fields are not parsed further.
 */
function parseHeaders(rfc822: string): Map<string, string[]> {
  const headers = new Map<string, string[]>();
  for (const line of unfoldedHeaderLines(rfc822)) {
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (name.length === 0) continue;
    const existing = headers.get(name);
    if (existing) existing.push(value);
    else headers.set(name, [value]);
  }
  return headers;
}

/** RFC 5322 §3.6.8 field-name: one or more printable US-ASCII characters
 *  other than the colon. */
const FIELD_NAME = /^[\x21-\x39\x3b-\x7e]+$/;

/**
 * Deny when a header line's field name is not RFC 5322 ftext (printable
 * US-ASCII except the colon), for example `Bcc\0: x@y` or `B cc: x@y`.
 * `parseHeaders` would file such a line under an unknown name, so it would
 * not be judged as a recipient header, while a lenient reader might still
 * treat it as one. Whitespace between the name and the colon (RFC 5322
 * obsolete syntax) is tolerated. Lines without a colon are left alone.
 */
function headerNameDecision(text: string): InspectResult | null {
  for (const line of unfoldedHeaderLines(text)) {
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    if (!FIELD_NAME.test(line.slice(0, colon).replace(/[ \t]+$/, ""))) {
      return {
        decision: "deny",
        category: "malformed",
        reason: "malformed-header-name",
        message:
          "A header name in the message contains a character other than printable US-ASCII " +
          "(or is empty); use plain header names such as To, Cc and Bcc",
      };
    }
  }
  return null;
}

/** First occurrence of a header (display-only fields such as Subject). */
function firstHeader(headers: Map<string, string[]>, name: string): string | undefined {
  return headers.get(name)?.[0];
}

/**
 * Deny when `To`, `Cc` or `Bcc` occurs more than once. RFC 5322 §3.6 allows
 * each at most once, and readers disagree on a repeat (first wins, last wins,
 * or all are merged), so the inspector refuses the ambiguity outright rather
 * than guessing which reading Gmail's MTA applies (F-3).
 */
function recipientHeaderDecision(headers: Map<string, string[]>): InspectResult | null {
  for (const name of ["to", "cc", "bcc"] as const) {
    if ((headers.get(name)?.length ?? 0) > 1) {
      return {
        decision: "deny",
        category: "malformed",
        reason: "duplicate-recipient-header",
        message: "The message repeats a To, Cc or Bcc header; send one header per recipient field",
      };
    }
  }
  return null;
}

/** Max bytes to decode when scanning an uploaded message for its header block.
 *  Headers precede the first blank line, so a small prefix suffices even for a
 *  50 MB attachment. */
const RFC822_HEADER_SCAN_BYTES = 64 * 1024;

/** Recipient addresses (to/cc/bcc, every occurrence) from parsed headers,
 *  un-normalised. Callers run `recipientHeaderDecision` first. */
function recipientsFromHeaders(headers: Map<string, string[]>): string[] {
  const collected: string[] = [];
  for (const name of ["to", "cc", "bcc"] as const) {
    for (const v of headers.get(name) ?? []) {
      if (v.length > 0) collected.push(...splitAddresses(v));
    }
  }
  return collected;
}

/** Recipients (to/cc/bcc) parsed from raw RFC 822 header text, or the
 *  ambiguous-line-ending, malformed-header-name or duplicate-recipient-header
 *  deny. */
function recipientsFromRfc822(text: string): { recipients: string[] } | { deny: InspectResult } {
  const lineEndingDeny = lineEndingDecision(text);
  if (lineEndingDeny) return { deny: lineEndingDeny };
  const nameDeny = headerNameDecision(text);
  if (nameDeny) return { deny: nameDeny };
  const headers = parseHeaders(text);
  const deny = recipientHeaderDecision(headers);
  if (deny) return { deny };
  const collected = recipientsFromHeaders(headers);
  return {
    recipients: Array.from(new Set(collected.map((s) => s.trim().toLowerCase()).filter((s) => s.length > 0))),
  };
}

/** Subject parsed from raw RFC 822 header text (display-only, encoded-words
 *  decoded; the first Subject occurrence wins). */
function subjectFromRfc822(text: string): string {
  return decodeEncodedWords(firstHeader(parseHeaders(text), "subject") ?? "");
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

/** True when the scanned prefix, with line endings normalised as
 *  `parseHeaders` does (CRLF to LF; a lone CR is not a line ending),
 *  contains the header/body blank-line terminator or begins with an empty
 *  line (an empty header section). `parseHeaders`
 *  silently treats its *entire* input as the header section when no
 *  terminator is found, so a candidate whose real terminator falls past the
 *  scan window must be rejected here rather than handed to `parseHeaders` —
 *  otherwise a recipient header sitting beyond the scanned prefix (e.g. behind
 *  >64 KiB of padding) would go unseen while a visible, allowlisted header
 *  earlier in the prefix causes a false allow. */
function hasHeaderTerminatorWithinScan(text: string): boolean {
  const normalised = normaliseLineEndings(text);
  return normalised.startsWith("\n") || normalised.includes("\n\n");
}

/** The candidate text when it can be judged: its header block ends within
 *  the scanned prefix, or its line endings are already ambiguous within that
 *  prefix (so `recipientsFromRfc822` denies it as ambiguous-line-ending rather
 *  than as send-no-recipients). Otherwise null. */
function judgeableCandidate(text: string): string | null {
  return hasHeaderTerminatorWithinScan(text) || lineEndingDecision(text) !== null ? text : null;
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
    return judgeableCandidate(text);
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
    return judgeableCandidate(text);
  }
  return null;
}

/** Caller-facing explanation for a recipient element that cannot be read as
 *  one plain address (F-18). */
export const UNREADABLE_RECIPIENT_MESSAGE =
  "A To, Cc or Bcc recipient could not be read as a single plain address, so it " +
  "cannot be checked against the outbound allowlist. Write each recipient as a bare " +
  "addr@host or as Name <addr@host>, with no quotes, comments or @ : ; , [ ] \\ in the name.";

/** Shared decision from a recipient set + lazy subject getter. */
function decideRecipients(
  recipients: string[],
  allowlist: readonly string[],
  getSubject: () => string,
): InspectResult {
  for (const r of recipients) {
    if (!isPlainAddrSpec(r.trim().toLowerCase())) {
      // Same audit code as an off-allowlist address (the element might hide
      // one), but tell the caller how to write recipients that can be read.
      return {
        decision: "deny",
        category: "external_data_flow",
        reason: "external-send",
        message: UNREADABLE_RECIPIENT_MESSAGE,
      };
    }
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
      return decodeEncodedWords(firstHeader(parseHeaders(decoded), "subject") ?? "");
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
 * `message.payload.headers`. Returns deduplicated, lowercase-normalised
 * addresses, or a deny when `raw` has ambiguous header line endings
 * (ambiguous-line-ending), a header name that is not RFC 5322 ftext
 * (malformed-header-name) or repeats a To/Cc/Bcc header
 * (duplicate-recipient-header). (`payload.headers` already yields every
 * occurrence, which is what Gmail sends to, so that path collects them all
 * and is not denied.)
 */
function extractRecipients(message: Record<string, unknown>): { recipients: string[] } | { deny: InspectResult } {
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
      const lineEndingDeny = lineEndingDecision(decoded);
      if (lineEndingDeny) return { deny: lineEndingDeny };
      const nameDeny = headerNameDecision(decoded);
      if (nameDeny) return { deny: nameDeny };
      const headers = parseHeaders(decoded);
      const deny = recipientHeaderDecision(headers);
      if (deny) return { deny };
      collected.push(...recipientsFromHeaders(headers));
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
  return { recipients: Array.from(new Set(normalized)) };
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
 *     4. Extract recipients from `raw` or `payload.headers`. A `raw` message
 *        with a lone CR, or mixed CRLF and bare LF, in its header block →
 *        deny/malformed/ambiguous-line-ending; one with a header name that
 *        is not RFC 5322 ftext → deny/malformed/malformed-header-name; one
 *        that repeats a To, Cc or Bcc header →
 *        deny/malformed/duplicate-recipient-header. Empty → deny/malformed.
 *
 *   Non-JSON payload (`req.rawBody` media upload, or `req.multipart` upload):
 *     Locate the uploaded RFC 822 message and extract recipients from its
 *     headers. No candidate message → deny/malformed; ambiguous header line
 *     endings → deny/malformed/ambiguous-line-ending; a header name that is
 *     not RFC 5322 ftext → deny/malformed/malformed-header-name; a repeated
 *     To, Cc or Bcc header → deny/malformed/duplicate-recipient-header; no
 *     recipients found → deny/malformed (fail closed).
 *
 *   RFC 822 text is read as RFC 5322 does: CRLF (or bare LF) line endings,
 *   the header block ending at the first empty line (see `parseHeaders`). A
 *   lone CR or mixed endings in the header block deny rather than pick one
 *   reading (see `lineEndingDecision`).
 *
 *   Either path then applies the same recipient decision:
 *     5. Any recipient off the deployment's allowlist (from the
 *        OUTBOUND_RECIPIENT_ALLOWLIST var; missing env/var → empty list, so
 *        every recipient denies) → deny/external_data_flow/external-send.
 *        An address that is not a plain addr-spec (two `@`, quotes, group
 *        syntax, …) is never on the allowlist, so it denies the same way;
 *        that includes any address-list element with a quoted string or a
 *        comment, which `splitAddresses` returns unread.
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

    const extracted = extractRecipients(message);
    if ("deny" in extracted) return extracted.deny;
    const recipients = extracted.recipients;
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
  const parsed = recipientsFromRfc822(text);
  if ("deny" in parsed) return parsed.deny;
  const recipients = parsed.recipients;
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
