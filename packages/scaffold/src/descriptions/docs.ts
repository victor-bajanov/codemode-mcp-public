// Full-documentation builder — the single source the `docs` tool, the
// `codemode://docs` resource, and the `__docsHost.docs()` sandbox capability
// all read from. Pre-stubbed in Task 1 of the description-budget plan;
// filled by Task 2.

import type { ApiProvider } from "../api-provider";
import {
  ACCESS_CONVENTION_BLOCK,
  BODY_MODES_BLOCK,
  ENVELOPE_BLOCK,
  GENERIC_STEP_THREE,
  RATE_LIMIT_BLOCK,
  RESPONSE_CHAR_CAP,
  STAGING_BLOCK,
  buildSearchStrategyBlock,
} from "./fragments";

export const DOC_SECTIONS = [
  "overview",
  "envelope",
  "request-options",
  "staging",
  "attachments",
  "downloads",
  "search-strategy",
  "access",
  "body-modes",
  "rate-limit",
  "provider",
] as const;
export type DocSection = (typeof DOC_SECTIONS)[number];

// Human title used to derive a `##` heading for fragments that don't already
// start with one (rate-limit, attachments, downloads, provider, plus the two
// scaffold-owned sections below, which already carry their own). Fragments
// that already open with their own `##` line (envelope, staging,
// search-strategy, access, body-modes) pass through unchanged so we never
// double-heading them.
const SECTION_TITLES: Record<DocSection, string> = {
  overview: "Overview",
  envelope: "Response envelope",
  "request-options": "Request options",
  staging: "Staging",
  attachments: "Attachments",
  downloads: "Downloads",
  "search-strategy": "Search strategy",
  access: "Access",
  "body-modes": "Body modes",
  "rate-limit": "Rate limit",
  provider: "Provider notes",
};

function withHeading(section: DocSection, content: string): string {
  if (content.trimStart().startsWith("##")) return content;
  return `## ${SECTION_TITLES[section]}\n\n${content}`;
}


const OVERVIEW_TEXT =
  "## Overview\n\n" +
  "code is a JavaScript async arrow function that returns a JSON-serialisable result. Inside it you get three capabilities:\n\n" +
  "  • `codemode.spec()` — returns this API's OpenAPI spec, with `$ref` pointers already resolved, so you can inspect any operation's parameters and schema directly.\n" +
  "  • `codemode.request(options)` — performs one upstream API call via this server. See 'Response envelope' for what it resolves to, and 'Request options' for the complete options shape.\n" +
  '  • `codemode.docs(section?)` — returns this document. The argument is a BARE STRING section name (`codemode.docs("search-strategy")`), not an options object — `{ section: "…" }` will not match any section. No argument returns the complete document.\n\n' +
  "This server also registers a `search` tool for browsing the spec without executing anything: search first, then execute — see 'Search strategy' for the retrieval pattern this spec needs.\n\n" +
  "Authentication (API keys, OAuth tokens, bearer credentials) is held by this server and NEVER enters the sandbox — you cannot see it, and you never construct an Authorization header yourself.\n\n" +
  `Tool results over ${RESPONSE_CHAR_CAP} characters are truncated, with a \`--- TRUNCATED ---\` footer appended; the excess is silently dropped with no indication of what was lost. Narrow your query rather than requesting broad data in one call — see 'Search strategy'.\n\n` +
  "Each execute run has a wall-clock deadline and a budget of upstream calls (1,000 by default, set per deployment); a call past the budget throws. For bulk work (say, fetching hundreds of messages or paging a long list), process it in batches across several execute runs.\n\n";

// `stagingEnabled`-dependent because two things in this interface only make
// sense when staging bindings exist: `returnAs: "stage"` (otherwise the field
// would read as usable when calling it just throws) and the 'Staging'
// cross-references (otherwise they point at a section that doesn't exist in
// this provider's docs).
function buildRequestOptionsText(stagingEnabled: boolean): string {
  const returnAsLine = stagingEnabled
    ? '    returnAs?: "stage";                  // bytes stream upstream → R2 server-side; the call resolves to a file-handle envelope instead of the JSON body — see \'Staging\'\n'
    : '    returnAs?: "stage";                  // requires staging bindings — NOT enabled on this server\n';
  const closingCrossRefs = stagingEnabled
    ? "See 'Body modes' for how `rawBody` / `bodyBase64` / `multipart` interact, and 'Staging' for `returnAs: \"stage\"`. This interface only covers the call's input — what `codemode.request()` resolves to (success or failure) is described in 'Response envelope'.\n\n"
    : "See 'Body modes' for how `rawBody` / `bodyBase64` / `multipart` interact. This interface only covers the call's input — what `codemode.request()` resolves to (success or failure) is described in 'Response envelope'.\n\n";
  return (
    "## Request options\n\n" +
    "This is the COMPLETE shape accepted by `codemode.request(options)` — treat any other listing of this interface (including codemode's own built-in description) as incomplete; this section is authoritative.\n\n" +
    "  interface RequestOptions {\n" +
    '    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";\n' +
    "    path: string;                        // appended to this API's base URL\n" +
    "    query?: Record<string, string | number | boolean | undefined>;\n" +
    "    body?: unknown;                      // JSON-serialised by default\n" +
    "    contentType?: string;                // forwarded as-is for body / bodyBase64 / rawBody; multipart overrides it\n" +
    "    rawBody?: boolean;                   // suppress JSON serialisation of `body` (text bodies only — see 'Body modes')\n" +
    "    headers?: Record<string, string>;    // extra outbound request headers (e.g. Accept). Merged as the BASE of the outbound header set —\n" +
    "                                          // never overrides Authorization, the computed Content-Type (set that via `contentType`, not here),\n" +
    "                                          // or provider-set headers. Security-sensitive headers (method-override, authorization, cookie,\n" +
    "                                          // host, and similar) are REJECTED with a loud error — never silently dropped.\n" +
    "    bodyBase64?: string;                 // binary body as base64; host decodes before fetching upstream\n" +
    "    multipart?: Array<{ name: string; filename?: string; contentType?: string; value?: string; bodyBase64?: string }>;\n" +
    "                                          // host builds multipart/form-data and sets the boundary/Content-Type — never set contentType yourself alongside this\n" +
    returnAsLine +
    "  }\n\n" +
    "`method`, `path`, `query`, `body`, `contentType`, and `rawBody` are codemode's own base fields. `headers`, `bodyBase64`, `multipart`, and `returnAs` are extensions this server adds on top of them.\n\n" +
    closingCrossRefs
  );
}

// Transcribed verbatim from @cloudflare/codemode 0.4.2's internal
// `SPEC_TYPES` constant (`dist/mcp.js`, not exported) — the shape
// `codemode.spec()` resolves to. Relocated here (not deleted) from the
// compact descriptions per spec D3. Pinned by the drift test in
// `__tests__/codemode-cap-drift.test.ts`, which fails loudly if the
// installed bundle's copy diverges from this transcription.
const SPEC_TYPES_TEXT =
  "### OpenApiSpec / PathItem / OperationObject reference\n\n" +
  "  interface OperationObject {\n" +
  "    summary?: string;\n" +
  "    description?: string;\n" +
  "    operationId?: string;\n" +
  "    tags?: string[];\n" +
  "    parameters?: Array<{\n" +
  "      name: string;\n" +
  '      in: "query" | "header" | "path" | "cookie";\n' +
  "      required?: boolean;\n" +
  "      schema?: unknown;\n" +
  "      description?: string;\n" +
  "    }>;\n" +
  "    requestBody?: {\n" +
  "      required?: boolean;\n" +
  "      description?: string;\n" +
  "      content?: Record<string, { schema?: unknown }>;\n" +
  "    };\n" +
  "    responses?: Record<string, {\n" +
  "      description?: string;\n" +
  "      content?: Record<string, { schema?: unknown }>;\n" +
  "    }>;\n" +
  "    security?: Array<Record<string, string[]>>;\n" +
  "    deprecated?: boolean;\n" +
  "  }\n\n" +
  "  interface PathItem {\n" +
  "    summary?: string;\n" +
  "    description?: string;\n" +
  "    get?: OperationObject;\n" +
  "    post?: OperationObject;\n" +
  "    put?: OperationObject;\n" +
  "    patch?: OperationObject;\n" +
  "    delete?: OperationObject;\n" +
  "    head?: OperationObject;\n" +
  "    options?: OperationObject;\n" +
  "    trace?: OperationObject;\n" +
  '    parameters?: OperationObject["parameters"];\n' +
  "  }\n\n" +
  "  interface OpenApiSpec {\n" +
  "    openapi: string;\n" +
  "    info: { title: string; version: string; description?: string };\n" +
  "    paths: Record<string, PathItem>;\n" +
  "    servers?: Array<{ url: string; description?: string }>;\n" +
  "    components?: Record<string, unknown>;\n" +
  "    tags?: Array<{ name: string; description?: string }>;\n" +
  "  }\n\n";

export function buildProviderDocs(
  provider: Pick<
    ApiProvider,
    "attachmentHint" | "downloadHint" | "executeHint" | "readRateLimit"
  >,
  stagingEnabled: boolean,
  // `unknown` (not OpenApiSpec) to match buildSearchStrategyBlock's
  // convention — the annotated spec is a structural clone, not the typed
  // import.
  annotatedSpec: unknown,
): { full: string; sections: Partial<Record<DocSection, string>> } {
  // `||`, not `??` — an empty-string attachmentHint must fall back to the
  // generic Step-3 text rather than silently rendering an empty section.
  const searchStrategy = buildSearchStrategyBlock(annotatedSpec);
  const raw: Record<DocSection, string | undefined> = {
    overview: OVERVIEW_TEXT,
    envelope: ENVELOPE_BLOCK,
    "request-options": buildRequestOptionsText(stagingEnabled),
    staging: stagingEnabled ? STAGING_BLOCK : undefined,
    attachments: stagingEnabled ? provider.attachmentHint || GENERIC_STEP_THREE : undefined,
    downloads: stagingEnabled && provider.downloadHint ? provider.downloadHint : undefined,
    "search-strategy": searchStrategy ? searchStrategy + SPEC_TYPES_TEXT : undefined,
    access: ACCESS_CONVENTION_BLOCK,
    "body-modes": BODY_MODES_BLOCK,
    "rate-limit": provider.readRateLimit ? RATE_LIMIT_BLOCK : undefined,
    provider: provider.executeHint ? provider.executeHint : undefined,
  };

  const sections: Partial<Record<DocSection, string>> = {};
  const ordered: string[] = [];
  for (const section of DOC_SECTIONS) {
    const content = raw[section];
    if (!content) continue;
    const withHead = withHeading(section, content);
    sections[section] = withHead;
    ordered.push(withHead);
  }

  return { full: ordered.join("\n"), sections };
}
