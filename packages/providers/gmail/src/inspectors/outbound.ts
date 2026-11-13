import type { InspectEnv, InspectRequest, InspectResult } from "@local/shared";
import { isAllowedRecipient, isPlainAddrSpec, outboundAllowlistFromEnv } from "./allowlist.js";

/** Strictly-greater-than threshold for mass-send elicitation. 26+ recipients elicits. */
export const MASS_SEND_THRESHOLD = 25;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/** `a, b, c (+N)`: the first three of a list, and how many more. */
export function firstThree(list: readonly string[]): string {
  return list.slice(0, 3).join(", ") + (list.length > 3 ? ` (+${list.length - 3})` : "");
}

/** A JSON object body (not an array). */
export function isJsonObject(value: unknown): value is Record<string, unknown> {
  return isObject(value) && !Array.isArray(value);
}

/** Message keys Gmail reads on messages.send / messages.import: everything else
 *  on the resource is output-only, and `payload` in particular is never used to
 *  build the sent message — a carried `payload` is a decoy (F1-1), a carried
 *  `message` on messages.send is a decoy (F1-3). */
export const MESSAGE_INPUT_KEYS: ReadonlySet<string> = new Set(["raw", "threadId", "labelIds"]);
/** Inside a Draft's `message` on drafts.send, `id` may also ride along
 *  (drafts.get returns it). */
const DRAFT_MESSAGE_KEYS: ReadonlySet<string> = new Set([...MESSAGE_INPUT_KEYS, "id"]);
/** Keys of the Draft resource read on drafts.send. */
const DRAFT_KEYS: ReadonlySet<string> = new Set(["id", "message"]);

/** What Gmail builds the sent message from, for `unexpectedKeyDecision`. */
const SENT_FROM_RAW = "the sent message from `raw`";
const SENT_FROM_MESSAGE_RAW = "the sent message from `message.raw`";

/** "a", "a and b", "a, b and c". */
function listWords(words: readonly string[]): string {
  if (words.length <= 1) return words.join("");
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}

/**
 * Deny when `obj` has an own key outside `accepted`. Gmail ignores unknown and
 * output-only members on input, so a key the inspector does not read could
 * only be a decoy that makes the judged message differ from the sent one; it
 * is refused rather than ignored. `where` names the operation (and the member,
 * for a nested object) and `builtFrom` what Gmail builds the message from
 * (e.g. "the sent message from `message.raw`"), both in the caller-facing
 * message.
 */
export function unexpectedKeyDecision(
  obj: Record<string, unknown>,
  accepted: ReadonlySet<string>,
  where: string,
  builtFrom: string,
): InspectResult | null {
  const stray = Object.keys(obj).filter((k) => !accepted.has(k)).sort();
  if (stray.length === 0) return null;
  return {
    decision: "deny",
    category: "malformed",
    reason: "send-unexpected-key",
    message:
      `Only ${listWords([...accepted])} are read ${where}; remove: ${stray.join(", ")}. ` +
      `Gmail builds ${builtFrom} alone; \`payload\` is an output-only view.`,
  };
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
export function base64UrlDecode(s: string): string {
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
export function lineEndingDecision(text: string): InspectResult | null {
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
export function parseHeaders(rfc822: string): Map<string, string[]> {
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
export function headerNameDecision(text: string): InspectResult | null {
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
export function firstHeader(headers: Map<string, string[]>, name: string): string | undefined {
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

/** Locate the uploaded message text in a media upload's `rawBody`. Returns
 *  null when there is no rawBody or the header block's terminator falls outside
 *  the scanned prefix — caller fails closed in both cases. */
function rfc822FromRawBody(req: InspectRequest): string | null {
  if (req.rawBody === undefined) return null;
  // Note: the string branch slices by UTF-16 code units, not bytes, unlike
  // the byte-array branch. The scan window is generous enough for header-only
  // text that this distinction doesn't matter in practice.
  const text =
    typeof req.rawBody === "string"
      ? req.rawBody.slice(0, RFC822_HEADER_SCAN_BYTES)
      : bytesPrefixToText(req.rawBody instanceof Uint8Array ? req.rawBody : new Uint8Array(req.rawBody));
  return judgeableCandidate(text);
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
  extraSummary: Record<string, string> = {},
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
        recipients: firstThree(recipients),
        subject: String(subject ?? ""),
        count: recipients.length,
        ...extraSummary,
      },
    };
  }
  return { decision: "allow" };
}

/**
 * Judge a base64url RFC 822 `raw` (the JSON send paths): undecodable or
 * recipient-less → deny/malformed/send-no-recipients; ambiguous line endings,
 * a malformed header name or a repeated To/Cc/Bcc deny as in
 * `recipientsFromRfc822`; then the shared recipient decision.
 */
function judgeRawMessage(
  raw: string,
  allowlist: readonly string[],
  extraSummary?: Record<string, string>,
): InspectResult {
  let decoded: string;
  try {
    decoded = base64UrlDecode(raw);
  } catch {
    decoded = "";
  }
  if (decoded.length === 0) {
    return { decision: "deny", category: "malformed", reason: "send-no-recipients" };
  }
  const parsed = recipientsFromRfc822(decoded);
  if ("deny" in parsed) return parsed.deny;
  if (parsed.recipients.length === 0) {
    return { decision: "deny", category: "malformed", reason: "send-no-recipients" };
  }
  return decideRecipients(parsed.recipients, allowlist, () => subjectFromRfc822(decoded), extraSummary);
}

/**
 * Inspector for `gmail.users.messages.send`, the JSON endpoint. (drafts.create /
 * drafts.update are deliberately NOT inspected — a draft is inert until sent,
 * so it may address anyone; the allowlist bites at send time instead, here, in
 * `inspectDraftSend` and in `inspectOutboundMessageMedia`.)
 *
 * Gmail builds the sent message from the top-level `raw` and nothing else, so
 * that is the only thing judged (F1-1, F1-3):
 *
 *   1. a `rawBody` or `multipart` channel, or a body that is not a JSON
 *      object → deny/malformed/send-no-raw. Google parses a non-JSON body its
 *      own way (a form field or a JSON-ish text body can carry a `raw` the
 *      inspector never reads), so the only upload path is
 *      gmail.users.messages.send.media, which has its own inspector;
 *   2. any key other than raw, threadId, labelIds — so a `message` wrapper or
 *      Gmail's output-only `payload` — → deny/malformed/send-unexpected-key;
 *   3. `raw` not a non-empty string → deny/malformed/send-no-raw;
 *   4. `raw` decoded and judged (`judgeRawMessage`): RFC 822 text is read as
 *      RFC 5322 does — CRLF (or bare LF) line endings, the header block ending
 *      at the first empty line (see `parseHeaders`); a lone CR or mixed
 *      endings in the header block deny (`lineEndingDecision`), as do a header
 *      name outside RFC 5322 ftext and a repeated To/Cc/Bcc; no recipients →
 *      deny/malformed/send-no-recipients. Then:
 *        - any recipient off the deployment's allowlist (from the
 *          OUTBOUND_RECIPIENT_ALLOWLIST var; missing env/var → empty list, so
 *          every recipient denies) → deny/external_data_flow/external-send.
 *          An address that is not a plain addr-spec (two `@`, quotes, group
 *          syntax, …) is never on the allowlist, so it denies the same way;
 *          that includes any address-list element with a quoted string or a
 *          comment, which `splitAddresses` returns unread. (Off-allowlist wins
 *          over mass-send.)
 *        - recipient count > MASS_SEND_THRESHOLD → elicit/mass-send;
 *        - otherwise → allow.
 */
export function inspectOutboundMessage(req: InspectRequest, env?: InspectEnv): InspectResult {
  const body = req.body;
  if (req.rawBody !== undefined || req.multipart !== undefined || !isJsonObject(body)) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "send-no-raw",
      message:
        "gmail.users.messages.send takes a JSON Message object { raw } (base64url RFC 822). To upload the " +
        "message as message/rfc822 bytes, use gmail.users.messages.send.media " +
        "(POST /upload/gmail/v1/users/{userId}/messages/send?uploadType=media).",
    };
  }
  const keyDeny = unexpectedKeyDecision(body, MESSAGE_INPUT_KEYS, "on gmail.users.messages.send", SENT_FROM_RAW);
  if (keyDeny) return keyDeny;
  const raw = body["raw"];
  if (typeof raw !== "string" || raw.length === 0) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "send-no-raw",
      message: "gmail.users.messages.send reads the message from `raw` only (base64url RFC 822); supply it.",
    };
  }
  return judgeRawMessage(raw, outboundAllowlistFromEnv(env));
}

/** Caller-facing explanation for a drafts.send that does not carry its message. */
const DRAFT_SEND_UNVETTED_MESSAGE =
  "Refusing to send a draft whose content is not carried in the request: drafts are stored without " +
  "recipient checks and cannot be read at send time, so nothing here could be checked against the " +
  "outbound allowlist. Send { id, message: { raw } } carrying the full message.";

/**
 * Inspector for `gmail.users.drafts.send`. Drafts are created and updated
 * WITHOUT recipient gating (a draft is inert, and may legitimately address
 * anyone or no one while being composed), so a stored draft's recipients are
 * unvetted, and a synchronous inspector cannot read the stored draft.
 *
 * The only accepted shape is `{ id, message: { raw } }`: with `message.raw`
 * present Gmail replaces the draft's content before sending, so the judged
 * recipients are the delivered ones. Gmail never builds a message from
 * `payload` (its output-only parsed view), so a carried `payload` would be
 * judged while the stored draft went out (F1-1); it is refused. In order:
 *
 *   1. a non-JSON channel, or a body that is not an object →
 *      deny/malformed/draft-send-body-not-object;
 *   2. a key other than id, message → deny/malformed/send-unexpected-key;
 *   3. `id` not a non-empty string → deny/malformed/draft-send-no-id;
 *   4. `message` an object with a key other than raw, threadId, labelIds, id
 *      → deny/malformed/send-unexpected-key (checked before step 5, so a
 *      `payload` decoy is named whatever `raw` holds);
 *   5. `message` absent or not an object, or `message.raw` not a non-empty
 *      string (a bare `{ id }` included) →
 *      deny/external_data_flow/draft-send-unvetted-recipients;
 *   6. `message.raw` judged exactly as messages.send's `raw`.
 */
export function inspectDraftSend(req: InspectRequest, env?: InspectEnv): InspectResult {
  const body = req.body;
  if (req.rawBody !== undefined || req.multipart !== undefined || !isJsonObject(body)) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "draft-send-body-not-object",
      message: "gmail.users.drafts.send takes a JSON Draft object: { id, message: { raw } }.",
    };
  }
  const keyDeny = unexpectedKeyDecision(body, DRAFT_KEYS, "on gmail.users.drafts.send", SENT_FROM_MESSAGE_RAW);
  if (keyDeny) return keyDeny;
  const id = body["id"];
  if (typeof id !== "string" || id.length === 0) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "draft-send-no-id",
      message: "gmail.users.drafts.send needs the draft's `id` (a non-empty string): { id, message: { raw } }.",
    };
  }
  const message = body["message"];
  let raw: unknown;
  if (isJsonObject(message)) {
    const messageKeyDeny = unexpectedKeyDecision(
      message,
      DRAFT_MESSAGE_KEYS,
      "in message on gmail.users.drafts.send",
      SENT_FROM_MESSAGE_RAW,
    );
    if (messageKeyDeny) return messageKeyDeny;
    raw = message["raw"];
  }
  if (typeof raw !== "string" || raw.length === 0) {
    return {
      decision: "deny",
      category: "external_data_flow",
      reason: "draft-send-unvetted-recipients",
      message: DRAFT_SEND_UNVETTED_MESSAGE,
    };
  }
  return judgeRawMessage(raw, outboundAllowlistFromEnv(env));
}

// ---------------------------------------------------------------------------
// Media-upload send (gmail.users.messages.send.media, issue #59)
// ---------------------------------------------------------------------------

/** Gmail's media-upload ceiling for messages.send (the discovery document's
 *  `mediaUpload.maxSize`, 35 MiB). Checked against the exact assembled length
 *  so an oversize send is refused before any staged file is opened. */
export const GMAIL_MEDIA_MAX_BYTES = 36_700_160;

/** U+FFFC OBJECT REPLACEMENT CHARACTER: the scaffold's stand-in for a staged
 *  segment in a composed body's inspection view. */
const STAGED_SLOT = "\uFFFC";

/** Query parameters the media send may carry. `uploadType` (required, checked
 *  separately) and `upload_protocol` (absent or "raw") select how Google
 *  parses the body, so anything else there could change what is sent from
 *  what was inspected. `fields`, `prettyPrint` and `quotaUser` only shape the
 *  response or quota accounting. Everything else is refused: `alt`,
 *  `callback` and `$.xgafv` change the response format the scaffold parses,
 *  and `key`/`access_token`/`oauth_token` are credentials the host supplies,
 *  never the sandbox. */
const MEDIA_SEND_QUERY_KEYS: ReadonlySet<string> = new Set([
  "uploadType",
  "upload_protocol",
  "fields",
  "prettyPrint",
  "quotaUser",
]);

/** True for `message/rfc822`, in any case, with no parameter other than an
 *  optional `charset` token (quoted or not). A `boundary=` or any other
 *  parameter could change how Google's media parser reads the body. */
function isPlainRfc822ContentType(contentType: string | undefined): boolean {
  if (contentType === undefined) return false;
  const [type, ...params] = contentType.split(";");
  if (type!.trim().toLowerCase() !== "message/rfc822") return false;
  return params.every((p) => {
    const t = p.trim();
    return t.length === 0 || /^charset\s*=\s*(?:[A-Za-z0-9._-]+|"[A-Za-z0-9._-]+")$/i.test(t);
  });
}

/** First `max` code points of a string, never splitting a surrogate pair. */
function codePointPrefix(text: string, max: number): string {
  let out = "";
  let n = 0;
  for (const ch of text) {
    if (n++ >= max) break;
    out += ch;
  }
  return out;
}

/** UTF-8 byte length of a string without allocating its encoding. A lone
 *  surrogate counts as the 3-byte U+FFFD `TextEncoder` would write. */
function utf8Length(text: string): number {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const d = text.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        n += 4;
        i++;
      } else n += 3;
    } else n += 3;
  }
  return n;
}

/** Byte length of the outbound media body: the scaffold's exact assembled
 *  length for a composed body, else the length of the plain rawBody. */
function mediaBodyLength(req: InspectRequest): number {
  if (typeof req.assembledByteLength === "number") return req.assembledByteLength;
  const raw = req.rawBody;
  if (raw === undefined) return 0;
  if (typeof raw === "string") return utf8Length(raw);
  return raw.byteLength;
}

/** Offset just past the blank line that ends the header block (CRLF or bare
 *  LF line endings, as `parseHeaders` reads them), or -1 when the text has no
 *  such line. A text beginning with a line ending has an empty header block. */
function headerBlockEnd(text: string): number {
  const lineEnd = /\r?\n/g;
  let start = 0;
  let m: RegExpExecArray | null;
  while ((m = lineEnd.exec(text)) !== null) {
    const end = m.index + m[0].length;
    if (m.index === start) return end;
    start = end;
  }
  return -1;
}

/** Display form of a staged file's name for the approval summary: Unicode
 *  format characters (bidi overrides, zero-width marks) removed; C0/C1
 *  controls and line/paragraph separators collapsed to a space; capped at 100
 *  code points. */
function summaryFilename(name: string | null): string {
  if (name === null) return "(unnamed)";
  const clean = codePointPrefix(
    name
      .replace(/\p{Cf}/gu, "")
      .replace(/[\p{Cc}\p{Zl}\p{Zp}]+/gu, " ")
      .trim(),
    100,
  );
  return clean.length > 0 ? clean : "(unnamed)";
}

/**
 * Inspector for `gmail.users.messages.send.media` (POST
 * /upload/gmail/v1/users/{userId}/messages/send?uploadType=media). The body
 * is the raw RFC 822 message — either a plain `rawBody`, or a composed body
 * whose inspection view replaces each staged file with U+FFFC and carries the
 * files' metadata in `staged` and the exact wire length in
 * `assembledByteLength`. In order:
 *
 *   1. `uploadType` must be exactly `media` → else deny/upload-type-not-media;
 *   2. the content type must be `message/rfc822` → else deny/media-content-type;
 *   3. the body must fit Gmail's 35 MiB media limit → else deny/message-too-large;
 *   4. no staged slot may sit before the end of the header block (or with no
 *      header block at all) → else deny/attachment-before-header-end. Staged
 *      bytes are base64 (or, for a sole identity segment, the whole message),
 *      so after the blank line they cannot become headers; before it they
 *      could carry recipients the inspector never saw;
 *   5. recipients are then read from the header block (the same RFC 822
 *      reading and recipient decision as the JSON send's `raw`), the
 *      mass-send summary listing the staged attachments.
 *
 * A JSON or multipart body on this endpoint has no readable message and is
 * denied.
 */
export function inspectOutboundMessageMedia(req: InspectRequest, env?: InspectEnv): InspectResult {
  const query = req.query ?? {};
  const protocol = query["upload_protocol"];
  if (query["uploadType"] !== "media" || (protocol !== undefined && protocol !== "raw")) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "upload-type-not-media",
      message:
        "The Gmail media-upload send needs query { uploadType: \"media\" } (and upload_protocol, if given, must be \"raw\")",
    };
  }
  const stray = Object.keys(query).filter((k) => query[k] !== undefined && !MEDIA_SEND_QUERY_KEYS.has(k));
  if (stray.length > 0) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "media-query-param",
      message:
        "The Gmail media-upload send accepts only the query parameters uploadType, upload_protocol, fields, " +
        "prettyPrint and quotaUser",
    };
  }
  if (!isPlainRfc822ContentType(req.contentType)) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "media-content-type",
      message:
        "The Gmail media-upload send needs contentType \"message/rfc822\" (the raw RFC 822 message), " +
        "with no parameter other than an optional charset",
    };
  }
  const size = mediaBodyLength(req);
  if (size > GMAIL_MEDIA_MAX_BYTES) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "message-too-large",
      message:
        `The assembled message is ${size} bytes; Gmail accepts at most ${GMAIL_MEDIA_MAX_BYTES} ` +
        "bytes (35 MiB) on a media-upload send. Shrink or drop the attachment.",
    };
  }
  if (req.body !== undefined || req.multipart !== undefined || req.rawBody === undefined) {
    return { decision: "deny", category: "malformed", reason: "send-no-recipients" };
  }
  if (typeof req.rawBody === "string") {
    const slot = req.rawBody.indexOf(STAGED_SLOT);
    if (slot >= 0) {
      const end = headerBlockEnd(req.rawBody);
      if (end < 0 || slot < end) {
        return {
          decision: "deny",
          category: "malformed",
          reason: "attachment-before-header-end",
          message:
            "A staged file is placed before the message's header block has ended. Put every header, " +
            "and the blank line that ends them, before the first staged segment.",
        };
      }
    }
  }

  const allowlist = outboundAllowlistFromEnv(env);
  const text = rfc822FromRawBody(req);
  if (text === null) {
    return { decision: "deny", category: "malformed", reason: "send-no-recipients" };
  }
  const parsed = recipientsFromRfc822(text);
  if ("deny" in parsed) return parsed.deny;
  if (parsed.recipients.length === 0) {
    return { decision: "deny", category: "malformed", reason: "send-no-recipients" };
  }
  const extra: Record<string, string> = {};
  if (req.staged !== undefined && req.staged.length > 0) {
    extra["attachments"] = codePointPrefix(
      req.staged.map((f) => `${summaryFilename(f.filename)} (${f.byteLength} bytes)`).join(", "),
      500,
    );
  }
  return decideRecipients(parsed.recipients, allowlist, () => subjectFromRfc822(text), extra);
}
