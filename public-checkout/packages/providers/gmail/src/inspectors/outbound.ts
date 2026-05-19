import type { InspectRequest, InspectResult } from "@local/shared";
import { isAllowedRecipient } from "./allowlist.js";

/** Strictly-greater-than threshold for mass-send elicitation. 26+ recipients elicits. */
export const MASS_SEND_THRESHOLD = 25;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Decode a base64url-encoded string. Available in both Node 18+ and Workers
 * via the global `atob`. The output is a binary string; for the RFC 822
 * headers we care about (ASCII), this is sufficient.
 */
function base64UrlDecode(s: string): string {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return atob(b64);
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
 * variants), then walks each header line pulling `Name: Value`. Header names
 * are normalized to lowercase. Continuation lines and structured fields are
 * not handled — slice 1 fixtures are single-line.
 */
function parseHeaders(rfc822: string): Map<string, string> {
  const headers = new Map<string, string>();
  // Locate end of header section.
  let endIdx = rfc822.indexOf("\r\n\r\n");
  if (endIdx < 0) endIdx = rfc822.indexOf("\n\n");
  const headerSection = endIdx >= 0 ? rfc822.slice(0, endIdx) : rfc822;
  const lines = headerSection.split(/\r?\n/);
  for (const line of lines) {
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (name.length > 0) headers.set(name, value);
  }
  return headers;
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
      return headers.get("subject") ?? "";
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
          return value;
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
 * Inspector for outbound Gmail operations: messages.send, drafts.create,
 * drafts.update.
 *
 * Decision flow:
 *   1. Body must be an object. (Otherwise → deny/malformed/send-no-recipients.)
 *   2. If body looks like a drafts.update wrapper (`id` present, no usable
 *      `message`), return deny/malformed/draft-update-no-message.
 *   3. Unwrap `body.message` if present (drafts.create / drafts.update).
 *   4. Extract recipients from `raw` or `payload.headers`. Empty → deny/malformed.
 *   5. Any recipient off the allowlist → deny/external_data_flow/external-send.
 *      (Off-allowlist wins over mass-send.)
 *   6. Recipient count > MASS_SEND_THRESHOLD → elicit/mass-send.
 *   7. Otherwise → allow.
 */
export function inspectOutboundMessage(req: InspectRequest): InspectResult {
  const body = req.body;
  if (!isObject(body)) {
    return { decision: "deny", category: "malformed", reason: "send-no-recipients" };
  }

  // Detect drafts.create / drafts.update wrapper.
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

  for (const r of recipients) {
    if (!isAllowedRecipient(r)) {
      return {
        decision: "deny",
        category: "external_data_flow",
        reason: "external-send",
      };
    }
  }

  if (recipients.length > MASS_SEND_THRESHOLD) {
    const subject = extractSubject(message);
    return {
      decision: "elicit",
      category: "external_data_flow",
      reason: "mass-send",
      summary: {
        recipients: recipients.slice(0, 3).join(", ") + (recipients.length > 3 ? ` (+${recipients.length - 3})` : ""),
        subject: String(subject ?? "").slice(0, 200),
        count: recipients.length,
      },
    };
  }

  return { decision: "allow" };
}
