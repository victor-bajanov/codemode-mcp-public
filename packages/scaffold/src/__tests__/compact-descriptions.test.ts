import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  buildCompactExecuteDescription,
  COMPACT_SEARCH_DESCRIPTION,
  buildCompactRegisterFileHandleDescription,
} from "../descriptions/compact";
import { DOC_SECTIONS, buildProviderDocs } from "../descriptions/docs";
import { annotateSpecWithSurfaceReview } from "../annotate-spec";
import { registerFileHandleTool } from "../staging/register-tool";
import { FakeD1 } from "../staging/__tests__/__fixtures__/fake-d1";
import type { ApiProvider } from "../api-provider";
import type { StagingConfig } from "../staging/types";

const BUDGET = 1800;

const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));
const gmailSpec = JSON.parse(
  readFileSync(`${repoRoot}/packages/providers/gmail/src/spec.json`, "utf-8"),
) as Record<string, unknown>;
const xeroSpec = JSON.parse(
  readFileSync(`${repoRoot}/packages/providers/xero/src/spec.json`, "utf-8"),
) as Record<string, unknown>;
const opticalSpec = JSON.parse(
  readFileSync(`${repoRoot}/packages/providers/optical/src/spec.json`, "utf-8"),
) as Record<string, unknown>;

const baseOauth = {
  authorizeUrl: "https://example.invalid/authorize",
  tokenUrl: "https://example.invalid/token",
  scopes: ["scope"],
  clientIdSecretName: "CLIENT_ID",
  clientSecretSecretName: "CLIENT_SECRET",
};

const COMPACT_HINT_200 = (
  "This connection also serves a second related API surface reachable under a distinct path prefix; " +
  "operationIds are namespaced accordingly. Rate limits and auth are shared across both. See docs."
).slice(0, 200);

// The true worst case per description-budget-docs-surface review: every
// optional block turned on simultaneously (staging, rate-limit clause,
// download/attachment/provider doc sections) with compactHint at the full
// 200-char budget, unpadded — the actual worst-case a real provider could hit.
const WORST_CASE_HINT = "x".repeat(200);
const worstCaseLike: ApiProvider = {
  name: "worst",
  displayName: "Worst Case",
  oauth: baseOauth,
  spec: gmailSpec as never,
  surfaceReview: {},
  apiBaseUrl: "https://worst.example.invalid",
  executeHint: "Use worst.op.list before drilling into individual records.",
  attachmentHint: "Step 3 — forward via multipart:\n  await codemode.request({ multipart: [...] });",
  downloadHint: "Use __stagingHost.stageFromUpstreamJson for large-record responses.",
  readRateLimit: () => undefined,
  compactHint: WORST_CASE_HINT,
};

const gmailLike: ApiProvider = {
  name: "gmail",
  displayName: "Gmail",
  oauth: baseOauth,
  spec: gmailSpec as never,
  surfaceReview: {},
  apiBaseUrl: "https://gmail.googleapis.com",
  executeHint: "Use gmail.users.messages.list before drilling into individual messages.",
  attachmentHint:
    "Step 3 — forward via multipart:\n" +
    "  await codemode.request({ method: \"POST\", path: \"/upload/gmail/v1/users/me/messages/send\", multipart: [...] });",
  downloadHint: "Use __stagingHost.stageFromUpstreamJson for attachments.get responses.",
  compactHint: COMPACT_HINT_200,
};

const xeroLike: ApiProvider = {
  name: "xero",
  displayName: "Xero",
  oauth: baseOauth,
  spec: xeroSpec as never,
  surfaceReview: {},
  apiBaseUrl: "https://api.xero.com",
  readRateLimit: () => undefined,
  compactHint: COMPACT_HINT_200,
};

const opticalLike: ApiProvider = {
  name: "optical",
  displayName: "Optical",
  oauth: baseOauth,
  spec: opticalSpec as never,
  surfaceReview: {},
  apiBaseUrl: "https://optical.example.invalid",
};


// Same pairing init() and the shared battery use: the advertised section list
// is the docs builder's actual output for the same provider/staging pairing.
function sectionsFor(provider: ApiProvider, stagingEnabled: boolean): string[] {
  return Object.keys(
    buildProviderDocs(
      provider,
      stagingEnabled,
      annotateSpecWithSurfaceReview(provider.spec as never, provider.surfaceReview),
    ).sections,
  );
}

describe("buildCompactExecuteDescription", () => {
  it("gmail-like (staging on) fits the 1800-char budget", () => {
    const desc = buildCompactExecuteDescription(gmailLike, true, sectionsFor(gmailLike, true));
    expect(desc.length).toBeLessThanOrEqual(BUDGET);
  });

  it("xero-like (staging on) fits the 1800-char budget", () => {
    const desc = buildCompactExecuteDescription(xeroLike, true, sectionsFor(xeroLike, true));
    expect(desc.length).toBeLessThanOrEqual(BUDGET);
  });

  it("optical-like (staging off, no compactHint) fits the 1800-char budget", () => {
    const desc = buildCompactExecuteDescription(opticalLike, false, sectionsFor(opticalLike, false));
    expect(desc.length).toBeLessThanOrEqual(BUDGET);
  });

  it("true worst case (staging + rate-limit + attachments + downloads + provider, 200-char hint) fits the budget", () => {
    const desc = buildCompactExecuteDescription(worstCaseLike, true, sectionsFor(worstCaseLike, true));
    expect(desc.length).toBeLessThanOrEqual(BUDGET);
  });

  it("contains the docs mandate within the first 200 chars", () => {
    const desc = buildCompactExecuteDescription(gmailLike, true, sectionsFor(gmailLike, true));
    const head = desc.slice(0, 200).toLowerCase();
    expect(head).toContain("docs");
    expect(head.includes("call") || head.includes("before")).toBe(true);
  });

  it("contains the response envelope fields", () => {
    const desc = buildCompactExecuteDescription(gmailLike, true, sectionsFor(gmailLike, true));
    for (const field of ["success", "status", "result", "errors"]) {
      expect(desc).toContain(field);
    }
  });

  it("lists every RequestOptions field name in the closed field-list line", () => {
    const desc = buildCompactExecuteDescription(gmailLike, true, sectionsFor(gmailLike, true));
    const fieldListLine = desc.split("\n").find((l) => l.startsWith("method, path, query"));
    expect(fieldListLine).toBeDefined();
    for (const field of [
      "method",
      "path",
      "query",
      "body",
      "contentType",
      "rawBody",
      "headers",
      "bodyBase64",
      "multipart",
      "returnAs",
    ]) {
      expect(fieldListLine).toContain(field);
    }
  });

  it("marks returnAs as staging-gated when staging is disabled, plain when enabled", () => {
    const withStaging = buildCompactExecuteDescription(gmailLike, true, sectionsFor(gmailLike, true));
    const withoutStaging = buildCompactExecuteDescription(opticalLike, false, sectionsFor(opticalLike, false));
    const lineWith = withStaging.split("\n").find((l) => l.startsWith("method, path, query"));
    const lineWithout = withoutStaging.split("\n").find((l) => l.startsWith("method, path, query"));
    expect(lineWith).toContain("returnAs");
    expect(lineWith).not.toContain("requires staging");
    expect(lineWithout).toContain("returnAs (requires staging");
  });

  it("staging=true output points at register_file_handle and returnAs:\"stage\"", () => {
    const desc = buildCompactExecuteDescription(gmailLike, true, sectionsFor(gmailLike, true));
    expect(desc).toContain("register_file_handle");
    expect(desc).toContain('returnAs: "stage"');
  });

  it("staging=false output does not tell the model to call register_file_handle", () => {
    const desc = buildCompactExecuteDescription(opticalLike, false, sectionsFor(opticalLike, false));
    expect(desc).not.toContain("register_file_handle");
  });

  it("carries the provider's compactHint verbatim when set", () => {
    const desc = buildCompactExecuteDescription(gmailLike, true, sectionsFor(gmailLike, true));
    expect(desc).toContain(COMPACT_HINT_200);
  });

  it("names every applicable docs section when all optional conditions are on", () => {
    // worstCaseLike sets staging + attachmentHint + downloadHint + readRateLimit
    // + executeHint, so every DOC_SECTIONS entry is applicable.
    const desc = buildCompactExecuteDescription(worstCaseLike, true, sectionsFor(worstCaseLike, true));
    for (const section of DOC_SECTIONS) {
      expect(desc).toContain(section);
    }
  });

  it("omits sections whose condition is off (optical: no staging, no hints)", () => {
    const desc = buildCompactExecuteDescription(opticalLike, false, sectionsFor(opticalLike, false));
    const sectionListLine = desc.split("\n").find((l) => l.startsWith("## Full docs:"));
    expect(sectionListLine).toBeDefined();
    for (const section of ["staging", "attachments", "downloads", "rate-limit", "provider"]) {
      expect(sectionListLine).not.toContain(section);
    }
    for (const section of ["overview", "envelope", "request-options", "search-strategy", "access", "body-modes"]) {
      expect(sectionListLine).toContain(section);
    }
  });

  it("does not contain the codemode OpenApiSpec type dump", () => {
    const desc = buildCompactExecuteDescription(gmailLike, true, sectionsFor(gmailLike, true));
    expect(desc).not.toContain("interface OpenApiSpec");
  });

  it("elements appear in the specified order: mandate, envelope, fields, compactHint, sections", () => {
    const desc = buildCompactExecuteDescription(gmailLike, true, sectionsFor(gmailLike, true));
    const iMandate = desc.toLowerCase().indexOf("docs");
    const iEnvelope = desc.indexOf("success");
    const iFields = desc.indexOf("bodyBase64");
    const iHint = desc.indexOf(COMPACT_HINT_200);
    const lastSection: string = DOC_SECTIONS[DOC_SECTIONS.length - 1] ?? "";
    const iSections = desc.indexOf(lastSection);
    expect(iMandate).toBeGreaterThanOrEqual(0);
    expect(iMandate).toBeLessThan(iEnvelope);
    expect(iEnvelope).toBeLessThan(iFields);
    expect(iFields).toBeLessThan(iHint);
    expect(iHint).toBeLessThan(iSections);
  });

  it("optical-like (no compactHint) omits a hint section but still fits and works", () => {
    const desc = buildCompactExecuteDescription(opticalLike, false, sectionsFor(opticalLike, false));
    expect(desc).toContain("success");
    expect(desc).toContain("bodyBase64");
  });
});

describe("COMPACT_SEARCH_DESCRIPTION", () => {
  it("fits its own budget", () => {
    expect(COMPACT_SEARCH_DESCRIPTION.length).toBeLessThanOrEqual(900);
  });

  it("documents the async-arrow contract, an example, the truncation warning, and the docs pointer", () => {
    expect(COMPACT_SEARCH_DESCRIPTION.toLowerCase()).toContain("async");
    expect(COMPACT_SEARCH_DESCRIPTION).toContain("=>");
    expect(COMPACT_SEARCH_DESCRIPTION).toContain("24,000");
    expect(COMPACT_SEARCH_DESCRIPTION).toContain("TRUNCATED");
    expect(COMPACT_SEARCH_DESCRIPTION).toContain("search-strategy");
  });
});

describe("buildCompactRegisterFileHandleDescription", () => {
  it("fits its own budget", () => {
    expect(buildCompactRegisterFileHandleDescription().length).toBeLessThanOrEqual(900);
  });

  it("documents the upload direction, the 3-step skeleton, and the attachments docs pointer", () => {
    const desc = buildCompactRegisterFileHandleDescription();
    expect(desc.toUpperCase()).toContain("UPLOAD");
    expect(desc).toContain("upload_url");
    expect(desc).toContain("token");
    expect(desc).toContain("file_handle");
    expect(desc).toContain("__stagingHost.getFile");
    expect(desc).toContain("attachments");
  });

  it("does not splice in a provider-specific attachmentHint", () => {
    const desc = buildCompactRegisterFileHandleDescription();
    expect(desc).not.toContain("multipart: [...]");
  });
});

describe("registerFileHandleTool descriptionMode", () => {
  const CFG: StagingConfig = { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 };

  it("defaults to the full (existing) description text", () => {
    const d1 = new FakeD1();
    const tool = registerFileHandleTool({
      STAGING_D1: d1 as unknown as D1Database,
      config: CFG,
      uploadOrigin: "https://x.test",
    });
    expect(tool.description).toContain("USE THIS TO UPLOAD");
    expect(tool.description).not.toBe(buildCompactRegisterFileHandleDescription());
  });

  it("descriptionMode: 'compact' yields buildCompactRegisterFileHandleDescription()", () => {
    const d1 = new FakeD1();
    const tool = registerFileHandleTool({
      STAGING_D1: d1 as unknown as D1Database,
      config: CFG,
      uploadOrigin: "https://x.test",
      descriptionMode: "compact",
    });
    expect(tool.description).toBe(buildCompactRegisterFileHandleDescription());
  });

  it("descriptionMode: 'compact' ignores attachmentHint (no inline splice, per spec)", () => {
    const d1 = new FakeD1();
    const tool = registerFileHandleTool({
      STAGING_D1: d1 as unknown as D1Database,
      config: CFG,
      uploadOrigin: "https://x.test",
      attachmentHint: "PROVIDER SPECIFIC SNIPPET SHOULD NOT APPEAR",
      descriptionMode: "compact",
    });
    expect(tool.description).not.toContain("PROVIDER SPECIFIC SNIPPET SHOULD NOT APPEAR");
  });
});
