// The spec handed to openApiMcpServer must be the ANNOTATED one — otherwise the
// per-operation availability text never reaches the `search` tool, which is the
// only place a client reads operation descriptions.
//
// openApiMcpServer is mocked here (and only here) so the test can read the exact
// `spec` argument the factory passes. Lives in its own file so the module mock
// cannot leak into mcp-agent-factory.test.ts, which constructs the real thing.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { SurfaceReview } from "@local/shared";

let capturedSpec: Record<string, unknown> | undefined;

vi.mock("@cloudflare/codemode/mcp", () => ({
  openApiMcpServer: (options: { spec: Record<string, unknown> }) => {
    capturedSpec = options.spec;
    return {
      registerTool: () => {},
      registerResource: () => {},
      // init() replaces both descriptions post-construction and throws if the
      // registry shape is missing — mirror the real SDK surface it relies on.
      _registeredTools: { execute: { update: () => {} }, search: { update: () => {} } },
      connect: async () => {},
      close: async () => {},
    };
  },
}));

const { createProviderMcpAgent } = await import("../mcp-agent-factory");
const { SURFACE_REVIEW_MARKER } = await import("../annotate-spec");
type ApiProvider = import("../api-provider").ApiProvider;

const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));
const gmailSpec = JSON.parse(
  readFileSync(`${repoRoot}/packages/providers/gmail/src/spec.json`, "utf-8"),
) as Record<string, unknown>;

const surfaceReview: SurfaceReview = {
  "gmail.users.settings.delegates.list": {
    decision: "deny",
    category: "capability_escalation",
    reasoning: "reviewer-only prose",
  },
};

/** Runs the agent's real init() and returns the spec it handed to codemode. */
async function specPassedToCodemode(spec: Record<string, unknown>): Promise<Record<string, unknown>> {
  const provider = {
    name: "test-provider",
    oauth: { scopes: [] },
    spec,
    surfaceReview,
    apiBaseUrl: "https://example.test",
  } as unknown as ApiProvider;
  const AgentClass = createProviderMcpAgent(provider);
  const agent = Object.create(AgentClass.prototype) as {
    env: Record<string, unknown>;
    props: Record<string, unknown>;
    ctx: { waitUntil: (p: Promise<unknown>) => void };
    init: () => Promise<void>;
  };
  agent.env = { LOADER: {}, DEPLOYMENT_NAME: "test-deployment" };
  agent.props = {};
  agent.ctx = { waitUntil: () => {} };
  await agent.init();
  if (!capturedSpec) throw new Error("openApiMcpServer was never called");
  return capturedSpec;
}

// biome-ignore lint/suspicious/noExplicitAny: walking a plain JSON spec in tests
const descriptionOf = (spec: any, operationId: string): string => {
  for (const item of Object.values(spec.paths ?? {})) {
    for (const op of Object.values(item as Record<string, any>)) {
      if (op && op.operationId === operationId) return op.description ?? "";
    }
  }
  throw new Error(`no operation ${operationId}`);
};

// The annotator reserves `ACCESS: ` and truncates any description at it. It now
// throws on a collision rather than silently eating upstream prose, but a throw
// at boot is still an outage — so pin the invariant here, where a spec
// regeneration that introduces the marker fails in CI instead.
describe("no bundled provider spec contains the reserved marker", () => {
  const specs = ["gmail/src/spec.json", "gmail/src/calendar.spec.json", "xero/src/spec.json", "optical/src/spec.json"];
  for (const rel of specs) {
    it(`${rel} is marker-free`, () => {
      const raw = readFileSync(`${repoRoot}/packages/providers/${rel}`, "utf-8");
      expect(raw.includes(SURFACE_REVIEW_MARKER), `${rel} contains "${SURFACE_REVIEW_MARKER}"`).toBe(false);
    });
  }
});

describe("mcp-agent-factory hands codemode an annotated spec", () => {
  beforeEach(() => {
    capturedSpec = undefined;
  });

  it("annotates the operation descriptions codemode search will read", async () => {
    const passed = await specPassedToCodemode(gmailSpec);
    const denied = descriptionOf(passed, "gmail.users.settings.delegates.list");
    expect(denied).toContain(SURFACE_REVIEW_MARKER);
    expect(denied).toMatch(/always fail/i);
    // An operation with no entry is implicitly denied — it must say so.
    const unlisted = descriptionOf(passed, "gmail.users.settings.updateVacation");
    expect(unlisted).toContain(SURFACE_REVIEW_MARKER);
    expect(unlisted).toMatch(/not on this server's reviewed surface/i);
  });

  it("leaves the provider's imported spec module untouched", async () => {
    const before = JSON.parse(JSON.stringify(gmailSpec));
    await specPassedToCodemode(gmailSpec);
    expect(gmailSpec).toEqual(before);
    expect(descriptionOf(gmailSpec, "gmail.users.settings.delegates.list")).not.toContain(
      SURFACE_REVIEW_MARKER,
    );
  });

  it("never leaks reviewer-facing `reasoning` into a client-visible description", async () => {
    const passed = await specPassedToCodemode(gmailSpec);
    expect(JSON.stringify(passed)).not.toContain("reviewer-only prose");
  });
});
