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

export function inspectAttachmentUpload(req: InspectRequest): InspectResult {
  const ctRaw = req.contentType;
  if (typeof ctRaw !== "string" || ctRaw.length === 0) {
    return { decision: "deny", category: "malformed", reason: "attachment-bad-mime" };
  }
  const ct = ctRaw.toLowerCase().split(";")[0]!.trim();
  if (!ATTACHMENT_MIME_ALLOWLIST.has(ct)) {
    return { decision: "deny", category: "malformed", reason: "attachment-bad-mime" };
  }

  let size: number | undefined;
  if (req.rawBody instanceof ArrayBuffer) size = req.rawBody.byteLength;
  else if (req.rawBody instanceof Uint8Array) size = req.rawBody.byteLength;
  else if (typeof req.rawBody === "string") size = req.rawBody.length;

  if (size !== undefined && size > ATTACHMENT_MAX_SIZE) {
    return { decision: "deny", category: "malformed", reason: "attachment-too-large" };
  }
  return { decision: "allow" };
}
