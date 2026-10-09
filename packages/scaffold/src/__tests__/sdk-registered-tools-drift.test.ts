// Drift guard for the SDK-shape assumption description-budget-docs-surface
// relies on (spec D2/D3, Risks table row 2): `McpServer` keeps a private
// `_registeredTools` map whose entries expose a synchronous `update()`, and
// calling it BEFORE any transport connects is safe (no `sendToolListChanged`
// misfire — that call is guarded by `isConnected()`). mcp-agent-factory.ts's
// init() calls `_registeredTools.execute.update({description})` and
// `.search.update(...)` in exactly that pre-connect window; if a
// `@modelcontextprotocol/sdk` upgrade renames the field or drops `update`,
// this test fails loudly here instead of as a silent no-op in production.
//
// Constructed directly against the SDK (not through openApiMcpServer or
// mcp-agent-factory) so it isolates the SDK contract from codemode's.

import { describe, it, expect } from "vitest";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

describe("McpServer._registeredTools SDK-shape drift guard (Task 6)", () => {
  it("a freshly registered tool exposes `.update` as a function", () => {
    const server = new McpServer({ name: "sdk-shape-guard", version: "1.0.0" });
    server.registerTool(
      "dummy",
      { description: "original", inputSchema: {} },
      async () => ({ content: [{ type: "text" as const, text: "ok" }] }),
    );

    const registeredTools = (server as unknown as {
      _registeredTools: Record<string, { update: unknown }>;
    })._registeredTools;

    expect(
      registeredTools?.dummy,
      "McpServer._registeredTools — private field mcp-agent-factory.ts reads directly — is gone or renamed",
    ).toBeDefined();
    expect(typeof registeredTools.dummy!.update).toBe("function");
  });

  it("calling update({description}) BEFORE any transport connects does not throw", () => {
    const server = new McpServer({ name: "sdk-shape-guard", version: "1.0.0" });
    server.registerTool(
      "dummy",
      { description: "original", inputSchema: {} },
      async () => ({ content: [{ type: "text" as const, text: "ok" }] }),
    );
    const registeredTools = (server as unknown as {
      _registeredTools: Record<string, { update(u: { description?: string }): void }>;
    })._registeredTools;

    expect(() => registeredTools.dummy!.update({ description: "patched pre-connect" })).not.toThrow();
  });

  it("a description set pre-connect via update() is what a connected client actually sees", async () => {
    const server = new McpServer({ name: "sdk-shape-guard", version: "1.0.0" });
    server.registerTool(
      "dummy",
      { description: "original", inputSchema: { note: z.string().optional() } },
      async () => ({ content: [{ type: "text" as const, text: "ok" }] }),
    );
    const registeredTools = (server as unknown as {
      _registeredTools: Record<string, { update(u: { description?: string }): void }>;
    })._registeredTools;
    registeredTools.dummy!.update({ description: "patched pre-connect" });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: "test", version: "1.0" });
    await client.connect(clientTransport);

    const tools = (await client.listTools()).tools;
    const dummy = tools.find((t) => t.name === "dummy");
    expect(dummy?.description).toBe("patched pre-connect");
    expect(dummy?.description).not.toBe("original");

    await client.close();
    await server.close();
  });
});

// init() also sets `search`'s annotations to `{ readOnlyHint: true }` through
// the same pre-connect `update()` (2026-10-07 security review, F-4). Pin that
// the SDK applies an annotations update and that clients see it.
describe("McpServer._registeredTools annotations update (F-4)", () => {
  it("annotations set pre-connect via update() reach a connected client", async () => {
    const server = new McpServer({ name: "sdk-shape-guard", version: "1.0.0" });
    server.registerTool(
      "dummy",
      { description: "original", inputSchema: {} },
      async () => ({ content: [{ type: "text" as const, text: "ok" }] }),
    );
    const registeredTools = (server as unknown as {
      _registeredTools: Record<
        string,
        { update(u: { description?: string; annotations?: { readOnlyHint?: boolean } }): void }
      >;
    })._registeredTools;
    registeredTools.dummy!.update({ description: "patched", annotations: { readOnlyHint: true } });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: "test", version: "1.0" });
    await client.connect(clientTransport);

    const dummy = (await client.listTools()).tools.find((t) => t.name === "dummy");
    expect(dummy?.description).toBe("patched");
    expect(dummy?.annotations?.readOnlyHint).toBe(true);

    await client.close();
    await server.close();
  });
});
