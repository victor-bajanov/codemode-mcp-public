import type { ApiProvider } from "@local/scaffold";
import { mergeOpenApiSpecs, type OpenApiSpec } from "@local/spec-loaders-google-discovery";
import gmailSpecJson from "./spec.json" with { type: "json" };
import calendarSpecJson from "./calendar.spec.json" with { type: "json" };
import { surfaceReview } from "./surface-review.js";
import { gmailElicitRenderers } from "./elicit-renderers.js";

// Gmail + Calendar share one Google identity, OAuth client, and consent screen,
// so they ship as one provider. Both reach the shared www.googleapis.com origin
// (Gmail at /gmail/v1/..., Calendar at /calendar/v3/...), keeping the
// request-handler's single-origin invariance guard intact. Schema-name
// collisions throw at import time (see mergeOpenApiSpecs).
const spec = mergeOpenApiSpecs(
  [gmailSpecJson as unknown as OpenApiSpec, calendarSpecJson as unknown as OpenApiSpec],
  { title: "Google (Gmail + Calendar)", version: "v1", serverUrl: "https://www.googleapis.com" },
);

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
  "  // UTF-8-safe base64: btoa() needs a binary (Latin-1) string and THROWS on any code point > 255,\n" +
  "  // so convert text -> UTF-8 bytes EXACTLY ONCE. NEVER also wrap with encodeURIComponent/unescape and\n" +
  "  // NEVER run this twice — double-encoding is exactly what turns an em dash (—) into \"Ã¢Â€Â\".\n" +
  "  const b64 = (text) => { const u = new TextEncoder().encode(text); let s = \"\"; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000)); return btoa(s); };\n" +
  "  // Non-ASCII HEADER values (Subject, display names) MUST be RFC 2047 encoded-words; a raw UTF-8 byte\n" +
  "  // in an unlabelled header is what a mail client re-reads as CP1252 (mojibake). ASCII passes through.\n" +
  "  const encHeader = (text) => /[^\\x00-\\x7F]/.test(text) ? `=?UTF-8?B?${b64(text)}?=` : text;\n" +
  "  const mime = [\n" +
  "    `From: me`,\n" +
  "    `To: recipient@example.com`,\n" +
  "    `Subject: ${encHeader(subject)}`,   // subject is your plain string; encHeader RFC 2047-encodes it only if non-ASCII\n" +
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
  "  // base64url-encode the whole MIME (UTF-8 bytes -> standard base64 via b64() -> URL-safe, strip padding):\n" +
  "  const raw = b64(mime).replace(/\\+/g, \"-\").replace(/\\//g, \"_\").replace(/=+$/, \"\");\n" +
  "  await codemode.request({\n" +
  "    method: \"POST\",\n" +
  "    path: \"/gmail/v1/users/me/messages/send\",   // or /drafts with body: { message: { raw } }\n" +
  "    body: { raw },\n" +
  "  });\n\n" +
  "Notes:\n" +
  "- `raw` is base64url (URL-safe, NO padding). Build it from UTF-8 bytes via the `b64` helper above — do NOT call bare `btoa(mime)` (it throws on any non-ASCII char) and do NOT double-encode.\n" +
  "- Recipients must pass the send inspector's allowlist (see gmail.users.messages.send surface entry).\n" +
  "- For HTML body, change the first inner part to `Content-Type: text/html; charset=\"UTF-8\"`. For both, wrap text+html in a nested `multipart/alternative`.\n" +
  "- UNICODE (don't ship mojibake): non-ASCII in HEADERS (Subject, display names) must be wrapped with `encHeader` (RFC 2047 encoded-word) as shown — an unlabelled UTF-8 byte in a header is re-read as CP1252 and renders as mojibake (an em dash — becomes \"Ã¢Â€Â\"). Non-ASCII in the BODY is fine as long as the part declares `charset=\"UTF-8\"` (above), since the whole MIME is UTF-8-encoded into `raw` exactly once. Apply the UTF-8->bytes step ONCE: never wrap it with encodeURIComponent/unescape on top, and never base64 an already-base64'd string.\n\n" +
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
  "The MIME type and filename come from the parent `messages.get` payload (part headers); pass `filename` through so the eventual `/staging/fetch/*` response carries the right `Content-Disposition`. The endpoint's `mimeType` field (when present in the JSON envelope) is used by the host as `Content-Type`; otherwise it falls back to `application/octet-stream`.\n\n" +
  "## Send size limit\n\n" +
  "The JSON `{ raw }` path above is the ONLY send channel for Gmail — no `/upload/...` path is registered (it resolves to a denied no-op), and the scaffold's `bodyBase64`/`multipart` body modes do not work on Gmail send endpoints (see Step 3 above). An inspected send whose effective JSON body exceeds 50 MB is denied before it is sent, so keep the whole request under 50 MB. Note the attachment is base64-encoded twice on this path (once as the MIME part, once when the whole MIME becomes `raw`), inflating original bytes ~1.8x, so the practical ceiling is roughly 28 MB of original attachment content — this 50 MB cap binds before Gmail's own ~35 MB messages.send limit does. If a send is denied for size, shrink or drop the attachment; do not try an alternate upload channel (there isn't one).";

export const gmailProvider: ApiProvider = {
  name: "gmail",
  displayName: "Gmail + Calendar (personal)",
  oauth: {
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    scopes: [
      // Gmail: mail.google.com is the only scope granting permanent delete
      // (messages.delete/threads.delete/batchDelete); it supersedes gmail.modify.
      // settings.basic is still required for filters/sendAs (not covered by the
      // full mail scope).
      "https://mail.google.com/",
      "https://www.googleapis.com/auth/gmail.settings.basic",
      // Calendar: least-privilege set matched to the exposed surface
      // (read + event management). calendar.events covers all event read/write;
      // the readonly scopes cover calendars/calendarList/colors/settings reads;
      // freebusy covers availability queries.
      "https://www.googleapis.com/auth/calendar.events",
      "https://www.googleapis.com/auth/calendar.calendars.readonly",
      "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
      "https://www.googleapis.com/auth/calendar.freebusy",
      "https://www.googleapis.com/auth/calendar.settings.readonly",
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
  apiBaseUrl: "https://www.googleapis.com",
  attachmentHint: GMAIL_ATTACHMENT_HINT,
  audit: {
    principalIdAccessor: (props) => props.userId as string | undefined,
  },
};

// re-exports for places that import bare:
export { spec, surfaceReview };
