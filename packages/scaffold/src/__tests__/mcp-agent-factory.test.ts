import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { openApiMcpServer } from "@cloudflare/codemode/mcp";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { FakeD1 } from "../staging/__tests__/__fixtures__/fake-d1";
import { registerFileHandleTool } from "../staging";
import { buildExecuteAddendum } from "../mcp-agent-factory";
import type { ApiProvider } from "../api-provider";

const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));
const xeroSpec = JSON.parse(
  readFileSync(`${repoRoot}/packages/providers/xero/src/spec.json`, "utf-8"),
) as Record<string, unknown>;
const gmailSpec = JSON.parse(
  readFileSync(`${repoRoot}/packages/providers/gmail/src/spec.json`, "utf-8"),
) as Record<string, unknown>;

// Capturing executor: never evaluates the code argument; instead records the
// namespaces (second arg) that openApiMcpServer passes for each tool invocation.
// Under codemode 0.4.2 the codemode object is fully sandbox-internal (embedded in
// the generated code string). The host only passes __openapiHost for the execute
// tool, and nothing for the search tool.
type CapturedCall = { namespaces: Array<{ name: string; fns: unknown }> };

function makeCapturingExecutor() {
  const calls: CapturedCall[] = [];
  return {
    executor: {
      // biome-ignore lint/suspicious/noExplicitAny: satisfying Executor interface while capturing call args
      execute: async (_code: string, namespacesOrFns: any) => {
        const namespaces: Array<{ name: string; fns: unknown }> = Array.isArray(namespacesOrFns)
          ? namespacesOrFns
          : [];
        calls.push({ namespaces });
        return { result: "captured" };
      },
    },
    getCalls: () => calls,
  };
}

async function callSearch(
  // biome-ignore lint/suspicious/noExplicitAny: McpServer type isn't exported usefully
  server: any,
): Promise<void> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "test", version: "1.0" });
  await client.connect(clientTransport);
  await client.callTool({ name: "search", arguments: { code: "// any" } });
  await client.close();
  await server.close();
}

async function callExecute(
  // biome-ignore lint/suspicious/noExplicitAny: McpServer type isn't exported usefully
  server: any,
): Promise<void> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "test", version: "1.0" });
  await client.connect(clientTransport);
  await client.callTool({ name: "execute", arguments: { code: "// any" } });
  await client.close();
  await server.close();
}

describe("openApiMcpServer (codemode 0.4.2 contract)", () => {
  it("codemode 0.4.2: search tool passes no external namespaces to executor (codemode is sandbox-internal)", async () => {
    const { executor, getCalls } = makeCapturingExecutor();
    const server = openApiMcpServer({
      spec: xeroSpec,
      executor,
      request: async () => ({}),
    });
    await callSearch(server);

    const calls = getCalls();
    expect(calls).toHaveLength(1);
    // Under 0.4.2, codemode.spec() is fully sandbox-internal — it is constructed
    // inside the generated code string, not passed as an external namespace.
    // The search tool therefore passes an empty namespaces array.
    expect(calls[0]!.namespaces).toHaveLength(0);
    expect(calls[0]!.namespaces.find((n) => n.name === "codemode")).toBeUndefined();
  });

  it("codemode 0.4.2: execute tool passes __openapiHost (not codemode) as the only external namespace", async () => {
    const { executor, getCalls } = makeCapturingExecutor();
    const server = openApiMcpServer({
      spec: xeroSpec,
      executor,
      request: async () => ({}),
    });
    await callExecute(server);

    const calls = getCalls();
    expect(calls).toHaveLength(1);
    // execute tool wires the user-provided request fn via __openapiHost, not codemode.
    const names = calls[0]!.namespaces.map((n) => n.name);
    expect(names).toContain("__openapiHost");
    expect(names).not.toContain("codemode");
  });

  it("constructs cleanly with the Gmail spec (regression guard)", async () => {
    const { executor, getCalls } = makeCapturingExecutor();
    const server = openApiMcpServer({
      spec: gmailSpec,
      executor,
      request: async () => ({}),
    });
    await callSearch(server);

    const calls = getCalls();
    expect(calls).toHaveLength(1);
    // Search tool ran and executor was called — basic construction sanity check.
    expect(calls[0]!.namespaces).toBeDefined();
  });
});

describe("register_file_handle tool wiring", () => {
  it("issues a working token when bindings are present", async () => {
    const d1 = new FakeD1();
    const tool = registerFileHandleTool({
      STAGING_D1: d1 as unknown as D1Database,
      config: { uploadTtlSeconds: 300, fetchTtlSeconds: 3600, maxBytes: 50 * 1024 * 1024 },
      uploadOrigin: "https://x.test",
      now: () => 1,
    });
    const result = await tool.handler({});
    expect(result.upload_url).toBe("https://x.test/staging/upload");
    expect(result.token.startsWith("stg_")).toBe(true);
  });
});

const dummyProvider = {
  name: "test",
  displayName: "Test",
  oauth: {} as never,
  spec: {} as never,
  surfaceReview: {} as never,
  apiBaseUrl: "https://test.example",
} as unknown as ApiProvider;

describe("buildExecuteAddendum", () => {
  it("always documents the response envelope, before every other block", () => {
    for (const stagingEnabled of [true, false]) {
      const out = buildExecuteAddendum(
        { ...dummyProvider, executeHint: "FLOW: do A then B." },
        stagingEnabled,
      );
      const envIdx = out.indexOf("## Response envelope");
      expect(envIdx).toBeGreaterThanOrEqual(0);
      expect(out).toContain("result: unknown");
      expect(out).toContain("return r.result;");
      expect(envIdx).toBeLessThan(out.indexOf("FLOW: do A then B."));
      expect(envIdx).toBeLessThan(out.indexOf("## codemode.request body modes"));
    }
  });

  it("includes executeHint at the top of the addendum when set, before harness blocks", () => {
    const out = buildExecuteAddendum(
      { ...dummyProvider, executeHint: "FLOW: do A then B." },
      /* stagingEnabled */ true,
    );
    expect(out).toContain("FLOW: do A then B.");
    const hintIdx = out.indexOf("FLOW: do A then B.");
    const stagingIdx = out.indexOf("## Attachments / file uploads");
    const bodyIdx = out.indexOf("## codemode.request body modes");
    expect(stagingIdx).toBeGreaterThan(hintIdx);
    expect(bodyIdx).toBeGreaterThan(hintIdx);
  });

  it("omits executeHint section entirely when unset", () => {
    const without = buildExecuteAddendum(dummyProvider, /* stagingEnabled */ false);
    const withHint = buildExecuteAddendum(
      { ...dummyProvider, executeHint: "SHOULD-NOT-APPEAR" },
      /* stagingEnabled */ false,
    );
    expect(without).not.toContain("SHOULD-NOT-APPEAR");
    expect(withHint).toContain("SHOULD-NOT-APPEAR");
    // No leading hint marker: the addendum starts with the envelope block
    // (always present), preceded only by the standard newline separator.
    expect(without.trimStart().startsWith("## Response envelope")).toBe(true);
  });

  it("attachmentHint still appears at the bottom when staging + attachmentHint set", () => {
    const out = buildExecuteAddendum(
      { ...dummyProvider, attachmentHint: "ATTACH-MARKER" },
      /* stagingEnabled */ true,
    );
    expect(out).toContain("## Upstream-specific attachment snippet for this server");
    expect(out).toContain("ATTACH-MARKER");
    // Attachment block is the last block in the assembled addendum.
    expect(out.indexOf("ATTACH-MARKER")).toBeGreaterThan(
      out.indexOf("## codemode.request body modes"),
    );
  });
});
