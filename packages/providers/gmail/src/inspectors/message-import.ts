import type { InspectEnv, InspectRequest, InspectResult } from "@local/shared";
import {
  MESSAGE_INPUT_KEYS,
  base64UrlDecode,
  decodeEncodedWords,
  firstHeader,
  headerNameDecision,
  isJsonObject,
  lineEndingDecision,
  parseHeaders,
  unexpectedKeyDecision,
} from "./outbound.js";

/** Headers shown in the import approval dialog, in display order. */
const SUMMARY_HEADERS = ["from", "to", "subject", "date"] as const;

/**
 * Inspector for `gmail.users.messages.import` (statically `elicit`). It only
 * supplies the approval dialog's facts and refuses decoys; the decision on an
 * acceptable body is `allow`, so the static `elicit` stands.
 *
 *   1. a non-JSON channel, or a body that is not an object →
 *      deny/malformed/import-body-not-object;
 *   2. a key other than raw, threadId, labelIds (e.g. Gmail's output-only
 *      `payload`) → deny/malformed/send-unexpected-key: Gmail builds the
 *      imported message from `raw` alone, so anything else could only make the
 *      dialog differ from what is imported;
 *   3. `raw` not a non-empty, decodable string → deny/malformed/import-no-raw;
 *   4. a header block Gmail could read differently (lone CR or mixed line
 *      endings, a header name outside RFC 5322 ftext) → the same denials as a
 *      send;
 *   5. a From, To, Subject or Date header that occurs more than once →
 *      deny/malformed/duplicate-summary-header (readers disagree on which one
 *      they show, so the dialog could not show the one the user will see);
 *   6. allow, with `summary` holding From, To, Subject and Date as written
 *      (RFC 2047 encoded-words decoded); absent headers are omitted.
 *
 * `env` is unused (no per-deployment policy); it is accepted so the signature
 * matches `SurfaceReviewEntry.inspect`.
 */
export function inspectMessageImport(req: InspectRequest, _env?: InspectEnv): InspectResult {
  const body = req.body;
  if (req.rawBody !== undefined || req.multipart !== undefined || !isJsonObject(body)) {
    return {
      decision: "deny",
      category: "malformed",
      reason: "import-body-not-object",
      message: "gmail.users.messages.import takes a JSON Message object: { raw }.",
    };
  }
  const keyDeny = unexpectedKeyDecision(
    body,
    MESSAGE_INPUT_KEYS,
    "on gmail.users.messages.import",
    "the imported message from `raw`",
  );
  if (keyDeny) return keyDeny;
  const noRaw: InspectResult = {
    decision: "deny",
    category: "malformed",
    reason: "import-no-raw",
    message: "gmail.users.messages.import reads the message from `raw` only (base64url RFC 822); supply it.",
  };
  const raw = body["raw"];
  if (typeof raw !== "string" || raw.length === 0) return noRaw;
  let text: string;
  try {
    text = base64UrlDecode(raw);
  } catch {
    return noRaw;
  }
  if (text.length === 0) return noRaw;
  const lineEndingDeny = lineEndingDecision(text);
  if (lineEndingDeny) return lineEndingDeny;
  const nameDeny = headerNameDecision(text);
  if (nameDeny) return nameDeny;
  const headers = parseHeaders(text);
  for (const name of SUMMARY_HEADERS) {
    if ((headers.get(name)?.length ?? 0) > 1) {
      return {
        decision: "deny",
        category: "malformed",
        reason: "duplicate-summary-header",
        message:
          "The message repeats a From, To, Subject or Date header; mail readers disagree on which one they " +
          "show, so the approval dialog could not show the one you would see. Keep one of each.",
      };
    }
  }
  const summary: Record<string, string> = {};
  for (const name of SUMMARY_HEADERS) {
    const value = firstHeader(headers, name);
    if (value !== undefined) summary[name] = decodeEncodedWords(value);
  }
  return { decision: "allow", summary };
}
