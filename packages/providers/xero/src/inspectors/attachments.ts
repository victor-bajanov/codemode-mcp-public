// packages/providers/xero/src/inspectors/attachments.ts
import type { InspectRequest, InspectResult } from "@local/shared";

export const ATTACHMENT_MIME_ALLOWLIST: ReadonlySet<string> = new Set([
  "application/pdf",
  "image/png",
  "image/jpeg",
  "image/gif",
  "text/csv",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-excel",
  "application/msword",
]);

export const ATTACHMENT_MAX_SIZE = 25 * 1024 * 1024;

const NOT_BYTES_MESSAGE =
  "this operation takes the file's bytes as the whole body (bodyBase64 or a composed staged reference) with the file's MIME type as contentType";
const INCLUDE_ONLINE_MESSAGE =
  "IncludeOnline publishes the attachment on the customer's online invoice; it is denied. Upload without IncludeOnline.";

/** True when any spelling of the `IncludeOnline` query key carries a value
 *  other than boolean `false` / string `"false"` (case-insensitive). A key
 *  present with an `undefined` value fails closed. */
function includeOnlineRequested(query: InspectRequest["query"]): boolean {
  if (query === undefined) return false;
  for (const key of Object.keys(query)) {
    if (key.toLowerCase() !== "includeonline") continue;
    const v = query[key];
    const off = v === false || (typeof v === "string" && v.toLowerCase() === "false");
    if (!off) return true;
  }
  return false;
}

/** Byte length of the outbound body: the assembled length of a composed
 *  body when present, else the raw body's bytes (UTF-8 for a string). */
function uploadByteLength(req: InspectRequest): number | undefined {
  if (req.assembledByteLength !== undefined) return req.assembledByteLength;
  const raw = req.rawBody;
  if (raw instanceof ArrayBuffer || raw instanceof Uint8Array) return raw.byteLength;
  if (typeof raw === "string") return new TextEncoder().encode(raw).byteLength;
  return undefined;
}

export function inspectAttachmentUpload(req: InspectRequest): InspectResult {
  if (req.body !== undefined || req.multipart !== undefined) {
    return { decision: "deny", category: "malformed", reason: "attachment-not-bytes", message: NOT_BYTES_MESSAGE };
  }
  if (includeOnlineRequested(req.query)) {
    return {
      decision: "deny",
      category: "external_data_flow",
      reason: "attachment-include-online",
      message: INCLUDE_ONLINE_MESSAGE,
    };
  }
  const ctRaw = req.contentType;
  if (typeof ctRaw !== "string" || ctRaw.length === 0) {
    return { decision: "deny", category: "malformed", reason: "attachment-bad-mime" };
  }
  const ct = ctRaw.toLowerCase().split(";")[0]!.trim();
  if (!ATTACHMENT_MIME_ALLOWLIST.has(ct)) {
    return { decision: "deny", category: "malformed", reason: "attachment-bad-mime" };
  }

  const size = uploadByteLength(req);
  if (size !== undefined && size > ATTACHMENT_MAX_SIZE) {
    return { decision: "deny", category: "malformed", reason: "attachment-too-large" };
  }
  return { decision: "allow" };
}
