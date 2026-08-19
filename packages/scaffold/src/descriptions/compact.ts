// Compact (budget ≤1,800 chars) tool descriptions that replace codemode's
// search/execute text and the full register_file_handle body on every
// client. Pre-stubbed in Task 1 of the description-budget plan; filled by
// Task 3.
//
// Claude Code silently truncates every MCP tool `description` at 2,048
// chars (no log line, no marker) — see
// docs/specs/2026-08-18-description-budget-docs-surface-design.md. These
// builders target a 1,800-char budget (margin for wording drift) so the
// FULL compact text always survives, and point every client at the `docs`
// tool for anything that doesn't fit. The complete content still exists —
// see ./docs.ts — it just isn't inlined here.

import type { ApiProvider } from "../api-provider";
import { RESPONSE_CHAR_CAP } from "./fragments";

// (1) Docs mandate — MUST land in the first ~200 chars: this may be the
// only part of the description a truncating client shows at all.
const MANDATE =
  "IMPORTANT: this description may be truncated in your client — this may be all you ever see. " +
  "Call the `docs` tool (no args, or a section name below) before your first request.\n\n";

// (2) Response envelope — condensed form of fragments.ts's ENVELOPE_BLOCK.
// The rateLimit clause is appended only for providers that report it
// (ApiProvider.readRateLimit set) — otherwise the envelope shape described
// here wouldn't match what the client actually receives.
type CompactProviderFields = Pick<
  ApiProvider,
  "compactHint" | "attachmentHint" | "downloadHint" | "executeHint" | "readRateLimit"
>;

function compactEnvelope(provider: CompactProviderFields): string {
  return (
    "## Response envelope\n" +
    "codemode.request() never throws on non-2xx; it resolves to:\n" +
    "  { success: boolean, status: number, result: unknown, errors: {code,message}[] }\n" +
    "Check `.success` first — the payload is ALWAYS under `.result`, never top-level" +
    (provider.readRateLimit
      ? "; on 429 also read `rateLimit` — wait, don't retry in a tight loop (docs \"rate-limit\")"
      : "") +
    ".\n" +
    "  const r = await codemode.request({ method: \"GET\", path: \"/...\" });\n" +
    "  if (!r.success) throw new Error(`HTTP ${r.status}: ${r.errors[0]?.message}`);\n" +
    "  return r.result;\n\n"
  );
}

// (3) Every RequestOptions field name, presented as a closed, complete
// list — codemode's own declared interface omits headers/bodyBase64/
// multipart/returnAs, which reads as closed and is actively misleading.
// `returnAs` is annotated when staging is off: it hard-throws server-side
// (request-handler.ts) rather than being silently ignored, so listing it
// bare on a no-staging server would read as usable when it isn't.
function compactFieldList(stagingEnabled: boolean): string {
  const returnAsEntry = stagingEnabled ? "returnAs" : "returnAs (requires staging; disabled here)";
  return (
    "## codemode.request(options) — complete field list (nothing else exists)\n" +
    `method, path, query, body, contentType, rawBody, headers, bodyBase64, multipart, ${returnAsEntry}.\n` +
    "Binary body: use bodyBase64 or multipart — a raw Uint8Array/ArrayBuffer in body throws. " +
    "Full reference: docs \"request-options\".\n\n"
  );
}

// (4) Binary/staging pointers — only when this server has staging bindings.
// Modes A/B/C always live in docs "staging"; "downloads" exists only when the
// provider ships a downloadHint, so it is named only when actually present —
// pointing a model at a section that answers "not applicable" reads as
// "downloads are unsupported", the opposite of the truth.
function compactStagingPointer(sectionNames: readonly string[]): string {
  const downloadsRef = sectionNames.includes("downloads") ? ", \"downloads\"" : "";
  return (
    "## Attachments & downloads\n" +
    "Upload TO upstream: call the `register_file_handle` tool first — never inline bytes. " +
    "Download FROM upstream: use `returnAs: \"stage\"` or the __stagingHost capability. " +
    `Details: docs "staging"${downloadsRef}.\n\n`
  );
}

// (5) ACCESS-convention one-liner. A restricted operation marks its own
// `description` with a bare `ACCESS: ` line (annotate-spec.ts
// SURFACE_REVIEW_MARKER); only when that operation ALSO has a `summary`
// does a bracketed `[ACCESS: …]` tag get appended there too. Many providers
// (e.g. Gmail) have descriptions but no summaries, so telling the model to
// scan for the bracketed form alone would match nothing.
const COMPACT_ACCESS =
  "## Availability\n" +
  "A restricted op says so in its own `description` via an `ACCESS: ` line (plus a short " +
  "`[ACCESS: …]` tag in `summary` if one exists). No marker = plainly available. Docs: \"access\".\n\n";

function docSectionsList(sectionNames: readonly string[]): string {
  return `## Full docs: call \`docs\`. Sections: ${sectionNames.join(", ")}.\n`;
}

/**
 * `sectionNames` MUST be `Object.keys(buildProviderDocs(...).sections)` for
 * the same provider/staging pairing — the docs builder's actual output, not a
 * re-derivation. An earlier version re-implemented the inclusion conditions
 * here and had already diverged from docs.ts on two of them (a review
 * finding); requiring the real keys makes divergence structurally impossible.
 */
export function buildCompactExecuteDescription(
  provider: CompactProviderFields,
  stagingEnabled: boolean,
  sectionNames: readonly string[],
): string {
  return (
    MANDATE +
    compactEnvelope(provider) +
    compactFieldList(stagingEnabled) +
    (stagingEnabled ? compactStagingPointer(sectionNames) : "") +
    COMPACT_ACCESS +
    (provider.compactHint ? provider.compactHint + "\n\n" : "") +
    docSectionsList(sectionNames)
  );
}

export const COMPACT_SEARCH_DESCRIPTION =
  "Search this API's OpenAPI spec by running JavaScript against it. Your code MUST be an async " +
  "arrow function; it receives the spec via `codemode.spec()` and returns whatever JSON you want back.\n\n" +
  "Example — list every operationId:\n" +
  "  async () => { const s = await codemode.spec();\n" +
  "    return Object.values(s.paths).flatMap(i => Object.values(i).map(o => o.operationId).filter(Boolean)); }\n\n" +
  `Results are truncated at ${RESPONSE_CHAR_CAP.toLocaleString("en-US")} chars; the \`--- TRUNCATED ---\` ` +
  "footer does NOT say what was cut — narrow your query and re-run rather than guessing. For a " +
  "scan-ids-then-drill strategy sized to this spec, call the `docs` tool with section \"search-strategy\".";

export function buildCompactRegisterFileHandleDescription(): string {
  return (
    "Use this to upload/send a file TO the upstream API — never for downloads; downloads never use " +
    "this tool (the download modes are in the `docs` tool, section \"staging\").\n\n" +
    "1. Call this tool → { upload_url, token, file_handle, upload_ttl_seconds, fetch_ttl_seconds }.\n" +
    "2. POST the file bytes to upload_url with `Authorization: Bearer <token>`, out-of-band — your " +
    "host does this, not execute(). Must happen within upload_ttl_seconds; a 204 confirms the upload.\n" +
    "3. Inside execute(), read the bytes via `const f = await __stagingHost.getFile(file_handle, token)` " +
    "and forward them to the upstream API (readable for fetch_ttl_seconds after upload).\n\n" +
    "For this provider's exact Step-3 forwarding snippet, call the `docs` tool with section \"attachments\"."
  );
}

/** One-liner for the `docs` MCP tool. Must stay well under the 2,048-char
 *  client truncation cap — enforced (≤300) by the shared battery and the
 *  live-server test. Lives here (not in mcp-agent-factory.ts) so the battery
 *  can import it without dragging the factory's cloudflare:workers chain
 *  into every provider's test bundle. */
export const DOCS_TOOL_DESCRIPTION =
  "Full reference for this server. The search/execute tool descriptions are compact summaries " +
  "(and may be truncated by your client) — read this BEFORE your first execute() call. " +
  "No arguments returns the complete document; pass `section` for one part.";
