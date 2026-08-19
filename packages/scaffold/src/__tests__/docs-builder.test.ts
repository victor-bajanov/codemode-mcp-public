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
  "body-modes": "Cannot freeze array buffer views",
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
    expect(sections.attachments).toContain("Step 3 — forward the bytes to the upstream API");
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
