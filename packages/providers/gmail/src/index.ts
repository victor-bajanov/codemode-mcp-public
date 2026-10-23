import type { ApiProvider } from "@local/scaffold";
import { mergeOpenApiSpecs, type OpenApiSpec } from "@local/spec-loaders-google-discovery";
import gmailSpecJson from "./spec.json" with { type: "json" };
import calendarSpecJson from "./calendar.spec.json" with { type: "json" };
import gmailUploadSpecJson from "./gmail-upload.spec.json" with { type: "json" };
import { surfaceReview } from "./surface-review.js";
import { gmailElicitRenderers } from "./elicit-renderers.js";

// Gmail + Calendar share one Google identity, OAuth client, and consent screen,
// so they ship as one provider. Both reach the shared www.googleapis.com origin
// (Gmail at /gmail/v1/..., Calendar at /calendar/v3/...), keeping the
// request-handler's single-origin invariance guard intact. Schema-name
// collisions throw at import time (see mergeOpenApiSpecs).
// gmail-upload.spec.json is hand-written: the Discovery normaliser drops the
// media-upload protocols, so the three /upload/ operations (messages.send,
// drafts.create, drafts.update with uploadType=media) are declared there. Both
// Google hosts serve /upload/, so they stay on the shared origin.
const spec = mergeOpenApiSpecs(
  [
    gmailSpecJson as unknown as OpenApiSpec,
    calendarSpecJson as unknown as OpenApiSpec,
    gmailUploadSpecJson as unknown as OpenApiSpec,
  ],
  { title: "Google (Gmail + Calendar)", version: "v1", serverUrl: "https://www.googleapis.com" },
);

// Provider-specific Step-3 guidance for the staging workflow (issue #59).
// Gmail takes attachments only inside an RFC 822 MIME message. The media-upload
// endpoints (gmail-upload.spec.json) accept that message as raw bytes, so the
// sandbox writes the headers and MIME structure as text and the host splices
// the staged file in through `composed` — the file's bytes never cross into
// execute(). getFile + base64url `{ raw }` used to be the recipe; it cannot
// carry a large file and is no longer taught.
const GMAIL_ATTACHMENT_HINT =
  "Step 3 — send the staged file through Gmail's media-upload endpoint. Write the RFC 822 headers and MIME structure as text, " +
  "and put a `{ staged }` segment where the attachment's base64 goes; the host splices the file in, so its bytes never enter execute():\n\n" +
  "  // UTF-8-safe base64 for SHORT header text only (never for file data). btoa() THROWS on code points > 255,\n" +
  "  // so convert text -> UTF-8 bytes EXACTLY ONCE; never also wrap with encodeURIComponent/unescape.\n" +
  "  const b64 = (text) => { const u = new TextEncoder().encode(text); let s = \"\"; for (const x of u) s += String.fromCharCode(x); return btoa(s); };\n" +
  "  // Non-ASCII HEADER values (Subject, display names) MUST be RFC 2047 encoded-words; a raw UTF-8 byte\n" +
  "  // in an unlabelled header is what a mail client re-reads as CP1252 (mojibake). ASCII passes through.\n" +
  "  const encHeader = (text) => /[^\\x00-\\x7F]/.test(text) ? `=?UTF-8?B?${b64(text)}?=` : text;\n" +
  "  const boundary = \"----cm-\" + Math.random().toString(36).slice(2) + Date.now().toString(36);\n" +
  "  const head = [\n" +
  "    `From: me`,\n" +
  "    `To: recipient@example.com`,\n" +
  "    `Subject: ${encHeader(subject)}`,   // subject is your plain string; encHeader RFC 2047-encodes it only if non-ASCII\n" +
  "    `MIME-Version: 1.0`,\n" +
  "    `Content-Type: multipart/mixed; boundary=\"${boundary}\"`,\n" +
  "    ``,                                  // blank line: the header block MUST end here, before the first staged segment\n" +
  "    `--${boundary}`,\n" +
  "    `Content-Type: text/plain; charset=\"UTF-8\"`,\n" +
  "    ``,\n" +
  "    `<email body text>`,\n" +
  "    ``,\n" +
  "    `--${boundary}`,\n" +
  "    `Content-Type: application/pdf; name=\"q.pdf\"`,   // the type and filename you registered\n" +
  "    `Content-Disposition: attachment; filename=\"q.pdf\"`,\n" +
  "    `Content-Transfer-Encoding: base64`,\n" +
  "    ``,\n" +
  "    ``,                                  // ends in a blank line + CRLF: the base64 starts on the next line\n" +
  "  ].join(\"\\r\\n\");\n" +
  "  await codemode.request({\n" +
  "    method: \"POST\",\n" +
  "    path: \"/upload/gmail/v1/users/me/messages/send\",   // drafts: POST /upload/gmail/v1/users/me/drafts, PUT /upload/gmail/v1/users/me/drafts/{id}\n" +
  "    query: { uploadType: \"media\" },\n" +
  "    contentType: \"message/rfc822\",\n" +
  "    composed: { segments: [\n" +
  "      { text: head },\n" +
  "      { staged: { file_handle, token }, encoding: \"base64-lines\" },   // 76-char lines, CRLF after every line incl. the last\n" +
  "      { text: `--${boundary}--\\r\\n` },\n" +
  "    ] },\n" +
  "  });\n\n" +
  "Notes:\n" +
  "- The body is the raw RFC 822 message: no base64url, no `{ raw }`, no JSON. `composed` cannot be combined with `body`, `rawBody`, `bodyBase64` or `multipart`, and the JSON endpoint /gmail/v1/users/me/messages/send refuses it — use the /upload/ path.\n" +
  "- Every header, including all of To/Cc/Bcc, and the blank line that ends them must come before the first staged segment; a staged segment before the header block ends is denied.\n" +
  "- Recipients must pass the send inspector's allowlist (see the gmail.users.messages.send.media surface entry). Drafts are not recipient-checked until they are sent.\n" +
  "- Several attachments: repeat the `--${boundary}` part headers as text, each followed by its own staged segment (at most 32 segments in all).\n" +
  "- For an HTML body, change the first inner part to `Content-Type: text/html; charset=\"UTF-8\"`. For both, wrap text+html in a nested `multipart/alternative`.\n" +
  "- UNICODE (don't ship mojibake): non-ASCII in HEADERS (Subject, display names) must be wrapped with `encHeader` (RFC 2047 encoded-word) as shown — an unlabelled UTF-8 byte in a header is re-read as CP1252 and renders as mojibake (an em dash — becomes \"Ã¢Â€Â\"). Non-ASCII in the BODY text is fine as long as the part declares `charset=\"UTF-8\"`; text segments are sent as UTF-8 exactly once. Never base64 an already-base64'd string.\n" +
  "- `__stagingHost.getFile` is for reading small files in code (parse a CSV, read a PDF's text), not for sending them: it is capped at 8 MiB by default, while the composed path above is limited only by the 35 MiB message cap below.\n\n" +
  "## Send size limit\n\n" +
  "The whole assembled message (headers, text and the base64 attachment, about 1.37x the file's size) may be at most 35 MiB (36 700 160 bytes, Gmail's media-upload limit); a larger send is denied before anything is uploaded. " +
  "That makes the practical ceiling about 25 MiB of original attachment content. If a send is denied for size, shrink or drop the attachment. " +
  "The JSON `{ raw }` send still works for messages without attachments.";

// Provider-specific download guidance for the staging workflow (issue #41):
// the opposite direction of GMAIL_ATTACHMENT_HINT above, wired to
// `downloadHint` and spliced only into the `execute` tool description, right
// after the harness's Mode A/B/C staging block — never into
// `register_file_handle`, which is upload-only.
const GMAIL_DOWNLOAD_HINT =
  "## Downloading an attachment FROM Gmail (gmail.users.messages.attachments.get)\n\n" +
  "This endpoint returns `{ size, data: <base64url>, attachmentId }`. Use `__stagingHost.stageFromUpstreamJson` (also callable as `__stagingHost.stageFromAttachment`) — the host extracts the `data` field server-side (no 64KB truncation cap, no base64url→base64 conversion needed) and stages the bytes into R2 in one round trip:\n\n" +
  "  const f = await __stagingHost.stageFromUpstreamJson(\n" +
  "    { method: \"GET\", path: `/gmail/v1/users/me/messages/${messageId}/attachments/${attachmentId}` },\n" +
  "    \"data\",            // field name\n" +
  "    \"base64url\",       // Gmail returns base64url (this is the default; can be omitted)\n" +
  "    filename ?? null,  // optional override; otherwise null\n" +
  "    mimeType ?? null,  // from the parent messages.get part headers — the attachments.get envelope has NO mimeType field\n" +
  "  );\n" +
  "  if (!f.ok) throw new Error(`stage: ${f.status} ${f.message}`);\n" +
  "  return { file_handle: f.file_handle, token: f.token, fetch_url: f.fetch_url, byte_length: f.byte_length };\n\n" +
  "Gmail's attachments.get envelope never includes a `mimeType` field, so ALWAYS pass the part's mimeType — read it from the parent `messages.get` payload's part headers — as the 5th argument above; skip it and the staged file serves as `application/octet-stream`. Pass `filename` through too, so the eventual `/staging/fetch/*` response carries `X-Filename` and `Content-Disposition: attachment; filename=...`.";

// The dual-API fact ("this server also speaks Google Calendar") reaches
// clients in two forms since description-budget-docs-surface: the ≤200-char
// `compactHint` below is the piece carried inside the compact `execute` tool
// description — the ONLY client-visible description slot — and this fuller
// hint is served as the `docs` tool's "provider" section. Without them,
// clients read "Gmail" off the deployment name and never discover the
// Calendar half of the merged spec. The claims are pinned to
// surface-review.ts by __tests__/execute-hint-calendar.test.ts — update both
// together.
//
// The elicit tier is described as failing rather than prompting on purpose:
// scaffold/src/elicit.ts throws ToolError("...outcome: unsupported") without
// rendering anything when the client does not advertise the elicitation
// capability, and Claude.ai — the primary client for these deployments — does
// not. Promising a dialog there would have the model report a confirmation
// request the user never saw.
// The one thing a client cannot discover any other way: that this connection
// carries two APIs. Everything per-operation is generated onto each operation's
// own `description` by annotateSpecWithSurfaceReview, and the ACCESS convention
// itself is explained once by the scaffold for every provider
// (ACCESS_CONVENTION_BLOCK) — so this hint neither lists operations nor repeats
// the key. Only the compactHint is paid for in every context window; this
// fuller text costs a `docs` call. Keep both pointers, not manuals.
const GMAIL_CALENDAR_HINT =
  "## This connection serves TWO Google APIs on one identity: Gmail AND Google Calendar\n\n" +
  "Both are reachable through the same `codemode.request()` — Gmail under `/gmail/v1/users/me/...`, " +
  "Google Calendar under `/calendar/v3/...`. Meetings, availability, invitations and scheduling are in scope on this " +
  "connection, not just mail. `search` covers both specs at once — operationIds are prefixed `gmail.` and `calendar.`.\n\n" +
  "Availability varies per operation — see the ACCESS convention above; it applies to both APIs.\n";

export const gmailProvider: ApiProvider = {
  name: "gmail",
  // Provider-level, so every deployment built from this provider shares it —
  // gmail, gmail-dev and gmail-tester alike. There is no per-deployment
  // override (no wrangler var, no env resolution), so it must not describe any
  // one deployment's account; DEPLOYMENT_NAME is what distinguishes those.
  displayName: "Gmail + Calendar",
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
  executeHint: GMAIL_CALENDAR_HINT,
  // Distilled from GMAIL_CALENDAR_HINT above for the compact `execute`
  // description (≤200 chars — description-budget-docs-surface spec D3
  // item 4). Full prose stays in executeHint, which now also feeds the
  // `docs` tool's "provider" section.
  compactHint:
    "This connection serves Gmail AND Google Calendar on one identity. Calendar is reachable under /calendar/v3. operationIds are prefixed `gmail.` / `calendar.` — search covers both.",
  attachmentHint: GMAIL_ATTACHMENT_HINT,
  downloadHint: GMAIL_DOWNLOAD_HINT,
  audit: {
    principalIdAccessor: (props) => props.userId as string | undefined,
  },
};

// re-exports for places that import bare:
export { spec, surfaceReview };
