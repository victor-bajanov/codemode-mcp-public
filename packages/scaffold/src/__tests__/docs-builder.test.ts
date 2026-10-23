import { describe, it, expect } from "vitest";
import { buildProviderDocs, DOC_SECTIONS, type DocSection } from "../descriptions/docs";
import type { ApiProvider } from "../api-provider";

// Same construction pattern as `dummyProvider` in mcp-agent-factory.test.ts:
// only the fields buildProviderDocs actually reads are real; the rest are
// cast away since ApiProvider's other fields (oauth, spec URLs, etc.) are
// irrelevant to doc assembly.
function makeProvider(overrides: Partial<ApiProvider> = {}): ApiProvider {
  return {
    name: "test",
    displayName: "Test",
    oauth: {} as never,
    spec: {} as never,
    surfaceReview: {} as never,
    apiBaseUrl: "https://test.example",
    ...overrides,
  } as unknown as ApiProvider;
}

// Minimal annotated spec with a couple of operations, so
// buildSearchStrategyBlock (search-strategy section) has content to report.
const annotatedSpec = {
  paths: {
    "/widgets": {
      get: { operationId: "widgets.list", description: "List widgets" },
      post: { operationId: "widgets.create", description: "Create a widget" },
    },
    "/widgets/{id}": {
      get: { operationId: "widgets.get", description: "Get a widget" },
    },
  },
};

const stagingProvider = makeProvider({
  readRateLimit: () => undefined,
  attachmentHint:
    "Step 3 — forward the parts, joined with CRLF: parts.join(\"\\r\\n\")",
  downloadHint: "Download-specific guidance goes here.",
  executeHint: "FLOW: do A then B.",
});

// Section titles as derived by docs.ts's own `withHeading` — duplicated here
// (not imported) so the heading-exactness assertions below actually pin the
// derivation logic rather than trivially agreeing with it.
const DERIVED_HEADING_TITLES: Partial<Record<DocSection, string>> = {
  "rate-limit": "Rate limit",
  attachments: "Attachments",
  downloads: "Downloads",
  provider: "Provider notes",
};

// One anchor string per section that could only appear if that section's
// real content — not a stand-in — was assembled. Kills mutants that swap
// section bodies, truncate them, or replace them with a placeholder.
const SECTION_ANCHORS: Record<DocSection, string> = {
  overview: "search first, then execute",
  envelope: "success: boolean",
  "request-options": "interface RequestOptions {",
  staging: "stageFromUpstreamJson",
  attachments: '.join("\\r\\n")',
  downloads: "Download-specific guidance goes here.",
  "search-strategy": "interface OpenApiSpec {",
  access: "ACCESS: ",
  "body-modes": "is rejected by the host with an error, so use the explicit binary modes",
  "rate-limit": "rateLimit",
  provider: "FLOW: do A then B.",
};

describe("buildProviderDocs", () => {
  it("returns every applicable section, non-empty, for a fully-configured staging provider", () => {
    const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    for (const section of DOC_SECTIONS) {
      expect(sections[section], `section "${section}" should be present`).toBeTruthy();
      expect(sections[section]!.length, `section "${section}" should be non-empty`).toBeGreaterThan(0);
    }
  });

  it("each present section contains its distinctive anchor content, not a placeholder", () => {
    const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    for (const section of DOC_SECTIONS) {
      expect(sections[section], `section "${section}" missing`).toContain(SECTION_ANCHORS[section]);
    }
  });

  it("staging section documents stageFromUpstreamJson, returnAs: stage, and putFile", () => {
    const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    expect(sections.staging).toContain("stageFromUpstreamJson");
    expect(sections.staging).toContain('returnAs: "stage"');
    expect(sections.staging).toContain("putFile");
  });

  it("request-options section lists every RequestOptions field, including scaffold extensions", () => {
    const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    const requestOptions = sections["request-options"]!;
    expect(requestOptions).toContain("interface RequestOptions {");
    for (const field of ["headers", "bodyBase64", "multipart", "returnAs", "rawBody", "contentType"]) {
      expect(requestOptions).toContain(field);
    }
  });

  it("request-options documents headers as a base-merge that can't override auth/content-type and errors loudly on disallowed headers", () => {
    const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    const requestOptions = sections["request-options"]!;
    expect(requestOptions).toContain("BASE of the outbound header set");
    expect(requestOptions).toContain("never overrides Authorization");
    expect(requestOptions).toContain("set that via `contentType`");
    expect(requestOptions).toContain("REJECTED with a loud error — never silently dropped");
  });

  describe("staged transfer v2 channels (issue #59)", () => {
    const COMPOSED_TYPE =
      'composed?: { segments: Array<{ text: string } | { staged: { file_handle: string; token: string }; encoding: "base64-lines" | "base64" | "identity" }> };';

    it("request-options declares the exact `composed` shape and `multipart[].staged`", () => {
      const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
      const requestOptions = sections["request-options"]!;
      expect(requestOptions).toContain(COMPOSED_TYPE);
      const multipartLine = requestOptions.split("\n").find((l) => l.includes("multipart?: Array<"));
      expect(multipartLine).toContain("staged?: { file_handle: string; token: string }");
    });

    it("request-options marks `composed` as unavailable when staging is disabled", () => {
      const { sections } = buildProviderDocs(stagingProvider, false, annotatedSpec);
      const line = sections["request-options"]!.split("\n").find((l) => l.includes("composed?:"));
      expect(line).toBeDefined();
      expect(sections["request-options"]).toContain(COMPOSED_TYPE);
      const comment = sections["request-options"]!.slice(sections["request-options"]!.indexOf(COMPOSED_TYPE));
      expect(comment.split("\n").slice(0, 2).join("\n")).toContain("NOT enabled on this server");
    });

    it("staging Step 3 sends by reference through `composed`, and getFile is for reading files ≤ 8 MiB", () => {
      const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
      const staging = sections.staging!;
      expect(staging).toContain("composed: { segments: [");
      expect(staging).toContain('encoding: "base64-lines"');
      expect(staging).toContain("staged: { file_handle, token }");
      expect(staging).toMatch(/getFile[^\n]*8 MiB/);
      // The v1 instruction to forward bytesBase64 upstream is gone.
      expect(staging).not.toContain("Forward `f.bytesBase64`");
    });

    it("staging states the composed limits and the opt-in rule for inspected operations", () => {
      const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
      const staging = sections.staging!;
      expect(staging).toMatch(/72 MiB/);                       // STAGING_COMPOSE_MAX_BYTES default
      expect(staging).toMatch(/4 MiB of text/);                // total text-segment cap
      expect(staging).toMatch(/staged-not-supported/);         // D10a
      expect(staging).toMatch(/do(es)? not accept staged files/);
    });

    it("body-modes exclusivity sentence names `composed` alongside body / bodyBase64 / multipart", () => {
      const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
      expect(sections["body-modes"]).toMatch(/Use exactly one of `body`, `bodyBase64`, `multipart` and `composed`/);
    });

    it("generic Step-3 fallback (no attachmentHint) sends by reference, never via bytesBase64", () => {
      const { sections } = buildProviderDocs(makeProvider(), true, annotatedSpec);
      const attachments = sections.attachments!;
      expect(attachments).toContain("composed");
      expect(attachments).toContain("staged: { file_handle, token }");
      // Binary and multipart endpoints no longer take the bytes back out of
      // the sandbox; only JSON-inline-base64 endpoints (no by-reference form,
      // a recorded non-goal) still point at getFile.
      expect(attachments).not.toContain("bodyBase64: f.bytesBase64");
      expect(attachments).toContain('encoding: "identity"');
    });
  });

  it("query is typed to allow undefined values, matching codemode/UpstreamCtx", () => {
    const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    expect(sections["request-options"]).toContain("Record<string, string | number | boolean | undefined>");
  });

  it("request-options annotates returnAs as unavailable, with no dangling Staging cross-reference, when staging is disabled", () => {
    const { sections } = buildProviderDocs(stagingProvider, false, annotatedSpec);
    const requestOptions = sections["request-options"]!;
    expect(requestOptions).toContain("returnAs?: \"stage\";                  // requires staging bindings — NOT enabled on this server");
    expect(requestOptions).not.toContain("'Staging'");
  });

  it("request-options keeps the returnAs -> Staging cross-reference when staging is enabled", () => {
    const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    expect(sections["request-options"]).toContain("'Staging'");
  });

  it("preserves literal CRLF join sequences in the attachments section (whitespace integrity, spec D7)", () => {
    const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    expect(sections.attachments).toContain('.join("\\r\\n")');
  });

  it("falls back to the generic Step-3 text when attachmentHint is an empty string, not just unset", () => {
    const provider = makeProvider({ attachmentHint: "" });
    const { sections } = buildProviderDocs(provider, true, annotatedSpec);
    expect(sections.attachments).toContain("Step 3 — send the file to the upstream API by reference");
  });

  it("search-strategy relocates the codemode spec type dump (OpenApiSpec/PathItem/OperationObject) rather than dropping it", () => {
    const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    const searchStrategy = sections["search-strategy"]!;
    expect(searchStrategy).toContain("interface OpenApiSpec {");
    expect(searchStrategy).toContain("interface PathItem {");
    expect(searchStrategy).toContain("interface OperationObject {");
  });

  it("overview names the search tool and the search-then-execute workflow", () => {
    const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    expect(sections.overview).toContain("`search` tool");
    expect(sections.overview).toContain("search first, then execute");
  });

  it("full concatenates all present sections, each under its own ## heading, in DOC_SECTIONS order", () => {
    const { full, sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    const headingCount = (full.match(/^## /gm) ?? []).length;
    const presentSections = Object.keys(sections).length;
    expect(headingCount).toBeGreaterThanOrEqual(presentSections);
    for (const value of Object.values(sections)) {
      expect(full).toContain(value as string);
    }

    // Order: each present section's block must appear strictly after the
    // previous present section's block, in DOC_SECTIONS order — catches a
    // reversed or shuffled assembly that would still pass the containment
    // checks above.
    const presentInOrder = DOC_SECTIONS.filter((s) => sections[s] !== undefined);
    const positions = presentInOrder.map((s) => full.indexOf(sections[s]!));
    expect(positions.every((p) => p >= 0)).toBe(true);
    for (let i = 1; i < positions.length; i++) {
      expect(positions[i]).toBeGreaterThan(positions[i - 1]!);
    }
  });

  it("derives an exact ## <Title> heading for sections whose fragment has none of its own", () => {
    const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    for (const [section, title] of Object.entries(DERIVED_HEADING_TITLES) as Array<[DocSection, string]>) {
      expect(sections[section]!.startsWith(`## ${title}\n\n`), `section "${section}"`).toBe(true);
    }
  });

  it("does not double-heading fragments that already open with their own ##", () => {
    const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
    // envelope opens with "## Response envelope — codemode.request() never..."
    // (fragments.ts) — a derived "## Response envelope\n\n" prefix would make
    // this false.
    expect(sections.envelope!.startsWith("## Response envelope\n\n")).toBe(false);
    expect(sections.envelope!.startsWith("## Response envelope —")).toBe(true);
  });

  describe("section omission", () => {
    it("omits staging, attachments, and downloads when staging is disabled", () => {
      const { sections } = buildProviderDocs(stagingProvider, false, annotatedSpec);
      expect(sections.staging).toBeUndefined();
      expect(sections.attachments).toBeUndefined();
      expect(sections.downloads).toBeUndefined();
    });

    it("omits rate-limit when the provider has no readRateLimit", () => {
      // Base `makeProvider()` simply omits readRateLimit (rather than setting
      // it to `undefined`), which is what exactOptionalPropertyTypes expects.
      const provider = makeProvider();
      const { sections } = buildProviderDocs(provider, true, annotatedSpec);
      expect(sections["rate-limit"]).toBeUndefined();
    });

    it("includes rate-limit when the provider has a readRateLimit", () => {
      const { sections } = buildProviderDocs(stagingProvider, true, annotatedSpec);
      expect(sections["rate-limit"]).toBeTruthy();
    });

    it("omits provider section when executeHint is unset", () => {
      const provider = makeProvider();
      const { sections } = buildProviderDocs(provider, true, annotatedSpec);
      expect(sections.provider).toBeUndefined();
    });

    it("includes attachments (with generic fallback) even without an attachmentHint, when staging is enabled", () => {
      const provider = makeProvider();
      const { sections } = buildProviderDocs(provider, true, annotatedSpec);
      expect(sections.attachments).toBeTruthy();
    });

    it("omits downloads when staging is enabled but no downloadHint is set", () => {
      const provider = makeProvider();
      const { sections } = buildProviderDocs(provider, true, annotatedSpec);
      expect(sections.downloads).toBeUndefined();
    });

    it("always includes overview, envelope, request-options, search-strategy, access, and body-modes", () => {
      const provider = makeProvider();
      const { sections } = buildProviderDocs(provider, false, annotatedSpec);
      expect(sections.overview).toBeTruthy();
      expect(sections.envelope).toBeTruthy();
      expect(sections["request-options"]).toBeTruthy();
      expect(sections["search-strategy"]).toBeTruthy();
      expect(sections.access).toBeTruthy();
      expect(sections["body-modes"]).toBeTruthy();
    });
  });
});
