import type { ApiProvider } from "@local/scaffold";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import specJson from "./spec.json" with { type: "json" };
import { surfaceReview } from "./surface-review.js";
import { gmailElicitRenderers } from "./elicit-renderers.js";

const spec = specJson as unknown as OpenApiSpec;

// Provider-specific Step-3 guidance for the staging workflow. Gmail accepts attachments
// only inside an RFC 822 message body (multipart/mixed), base64url-encoded and posted
// as { raw } to messages.send or { message: { raw } } to drafts.create. There is no
// raw-octet upload endpoint and no multipart/form-data endpoint — the LLM must NOT
// reach for codemode.request's bodyBase64 or multipart modes here. This snippet is the
// only path that works.
const GMAIL_ATTACHMENT_HINT =
  "Step 3 — Gmail has NO raw-octet or multipart/form-data upload endpoint. Attachments ride inside an RFC 822 MIME message, " +
  "base64url-encoded, sent as JSON `{ raw }` to /gmail/v1/users/me/messages/send (or `{ message: { raw } }` to /drafts).\n\n" +
  "Build the MIME message in execute() yourself — do not try `bodyBase64`, `multipart`, or `rawBody` on these endpoints (the API rejects them):\n\n" +
  "  const f = await __stagingHost.getFile(file_handle, token);\n" +
  "  if (!f.ok) throw new Error(`staging fetch: ${f.status} ${f.message}`);\n" +
  "  const boundary = \"----cm-\" + Math.random().toString(36).slice(2) + Date.now().toString(36);\n" +
  "  const wrapped = f.bytesBase64.match(/.{1,76}/g).join(\"\\r\\n\");  // RFC 822 76-char line wrap\n" +
  "  const mime = [\n" +
  "    `From: me`,\n" +
  "    `To: recipient@example.com`,\n" +
  "    `Subject: <subject>`,\n" +
  "    `MIME-Version: 1.0`,\n" +
  "    `Content-Type: multipart/mixed; boundary=\"${boundary}\"`,\n" +
  "    ``,\n" +
  "    `--${boundary}`,\n" +
  "    `Content-Type: text/plain; charset=\"UTF-8\"`,\n" +
  "    ``,\n" +
  "    `<email body text>`,\n" +
  "    ``,\n" +
  "    `--${boundary}`,\n" +
  "    `Content-Type: ${f.contentType ?? \"application/octet-stream\"}; name=\"${f.filename ?? \"file\"}\"`,\n" +
  "    `Content-Disposition: attachment; filename=\"${f.filename ?? \"file\"}\"`,\n" +
  "    `Content-Transfer-Encoding: base64`,\n" +
  "    ``,\n" +
  "    wrapped,\n" +
  "    ``,\n" +
  "    `--${boundary}--`,\n" +
  "  ].join(\"\\r\\n\");\n" +
  "  // base64url-encode the whole MIME string (standard base64 then URL-safe substitutions, strip padding)\n" +
  "  const raw = btoa(mime).replace(/\\+/g, \"-\").replace(/\\//g, \"_\").replace(/=+$/, \"\");\n" +
  "  await codemode.request({\n" +
  "    method: \"POST\",\n" +
  "    path: \"/gmail/v1/users/me/messages/send\",   // or /drafts with body: { message: { raw } }\n" +
  "    body: { raw },\n" +
  "  });\n\n" +
  "Notes:\n" +
  "- `raw` is base64url (URL-safe, NO padding) — `btoa(mime).replace(/\\+/g,\"-\").replace(/\\//g,\"_\").replace(/=+$/, \"\")`.\n" +
  "- Recipients must pass the send inspector's allowlist (see gmail.users.messages.send surface entry).\n" +
  "- For HTML body, change the first inner part to `Content-Type: text/html; charset=\"UTF-8\"`. For both, wrap text+html in a nested `multipart/alternative`.\n" +
  "- btoa works because the MIME string itself is ASCII (the attachment is already base64-encoded inside it). For non-ASCII headers/body, use RFC 2047 encoded-word or quoted-printable.\n\n" +
  "## Downloading an attachment FROM Gmail (gmail.users.messages.attachments.get)\n\n" +
  "This endpoint returns `{ size, data: <base64url>, attachmentId }`. Use `__stagingHost.stageFromUpstreamJson` — the host extracts the `data` field server-side (no 64KB truncation cap, no base64url→base64 conversion needed) and stages the bytes into R2 in one round trip:\n\n" +
  "  const f = await __stagingHost.stageFromUpstreamJson(\n" +
  "    { method: \"GET\", path: `/gmail/v1/users/me/messages/${messageId}/attachments/${attachmentId}` },\n" +
  "    \"data\",            // field name\n" +
  "    \"base64url\",       // Gmail returns base64url (this is the default; can be omitted)\n" +
  "    filename ?? null,  // optional override; otherwise null\n" +
  "  );\n" +
  "  if (!f.ok) throw new Error(`stage: ${f.status} ${f.message}`);\n" +
  "  return { file_handle: f.file_handle, token: f.token, fetch_url: f.fetch_url, byte_length: f.byte_length };\n\n" +
  "The MIME type and filename come from the parent `messages.get` payload (part headers); pass `filename` through so the eventual `/staging/fetch/*` response carries the right `Content-Disposition`. The endpoint's `mimeType` field (when present in the JSON envelope) is used by the host as `Content-Type`; otherwise it falls back to `application/octet-stream`.";

export const gmailProvider: ApiProvider = {
  name: "gmail",
  displayName: "Gmail (personal)",
  oauth: {
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    scopes: [
      "https://www.googleapis.com/auth/gmail.modify",
      "https://www.googleapis.com/auth/gmail.settings.basic",
      "openid",
      "email",
      "profile",
    ],
    clientIdSecretName: "GOOGLE_CLIENT_ID",
    clientSecretSecretName: "GOOGLE_CLIENT_SECRET",
    userInfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
    extraAuthorizeParams: {
      access_type: "offline",
      prompt: "consent",
      include_granted_scopes: "true",
    },
  },
  spec,
  surfaceReview,
  elicitRenderers: gmailElicitRenderers,
  apiBaseUrl: "https://gmail.googleapis.com",
  attachmentHint: GMAIL_ATTACHMENT_HINT,
  audit: {
    principalIdAccessor: (props) => props.userId as string | undefined,
  },
};

// re-exports for places that import bare:
export { spec, surfaceReview };
