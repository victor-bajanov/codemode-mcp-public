// Drift guard for codemode's response cap.
//
// The execute addendum states this cap to the model as fact and derives the
// "how many operations fit" numbers from it. If a codemode bump changes
// MAX_TOKENS or CHARS_PER_TOKEN, the hint silently starts lying — so read the
// INSTALLED source and assert the constants still evaluate to what we assume,
// rather than trusting a comment.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { openApiMcpServer } from "@cloudflare/codemode/mcp";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  RESPONSE_CHAR_CAP,
  CODEMODE_SANDBOX_ANCHOR,
  patchCodemodeDocsAlias,
} from "../mcp-agent-factory";

const require = createRequire(import.meta.url);
const mcpJs = readFileSync(
  require.resolve("@cloudflare/codemode/mcp").replace(/\.js$/, ".js"),
  "utf-8",
);

// Minimal valid OpenAPI spec — just enough for openApiMcpServer to construct
// and for createOpenApiSandboxCode to run without throwing.
const MINIMAL_SPEC = {
  openapi: "3.0.0",
  info: { title: "drift-guard-fixture", version: "1.0.0" },
  paths: {},
};

// Same shape as mcp-agent-factory.test.ts's makeCapturingExecutor, replicated
// locally per plan instructions (no cross-test-file imports): records the
// CODE STRING passed to executor.execute for each tool invocation, rather
// than the namespaces array — this test cares about the generated sandbox
// source, not the capability wiring.
function makeCodeCapturingExecutor() {
  const codes: string[] = [];
  return {
    executor: {
      execute: async (code: string, _namespacesOrFns: unknown) => {
        codes.push(code);
        return { result: "captured" };
      },
    },
    getCodes: () => codes,
  };
}

/** Read `const <name> = <number|expr>;` out of the installed bundle. */
function constant(name: string): string {
  const m = new RegExp(`const ${name} = ([^;]+);`).exec(mcpJs);
  if (!m) throw new Error(`codemode no longer defines ${name} — re-derive RESPONSE_CHAR_CAP`);
  return m[1]!.trim();
}

/** Top-level member names (`name: ...` or `name(...)`, one per line) of an
 *  object/interface BODY string — used against both the bundle's `declare
 *  const codemode: {...}` type and the sandbox's runtime-generated
 *  `const codemode = {...}` object literal, which share this line shape. */
function topLevelMemberNames(body: string): string[] {
  return body
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => /^([A-Za-z_][A-Za-z0-9_]*)\s*\(?[:(]/.exec(line)?.[1])
    .filter((name): name is string => Boolean(name));
}

describe("codemode response-cap drift guard", () => {
  it("MAX_TOKENS and CHARS_PER_TOKEN still have the values we assume", () => {
    expect(constant("CHARS_PER_TOKEN")).toBe("4");
    expect(constant("MAX_TOKENS")).toBe("6e3");
  });

  it("MAX_CHARS is still their product, and equals RESPONSE_CHAR_CAP", () => {
    expect(constant("MAX_CHARS")).toBe("MAX_TOKENS * CHARS_PER_TOKEN");
    const evaluated = Number(constant("MAX_TOKENS")) * Number(constant("CHARS_PER_TOKEN"));
    expect(evaluated).toBe(RESPONSE_CHAR_CAP);
    expect(RESPONSE_CHAR_CAP).toBe(24000);
  });

  it("truncation still appends the marker the addendum tells the model to watch for", () => {
    expect(mcpJs).toContain('const TRUNCATION_MARKER = "--- TRUNCATED ---"');
  });
});

// Drift guards for the description-budget-docs-surface feature (spec D5/D6,
// plan Task 6). Three things this feature depends on that a codemode upgrade
// could silently move or change:
//   (a) the sandbox-patch anchor createOpenApiSandboxCode's template still
//       produces, which patchCodemodeDocsAlias string-patches to inject the
//       best-effort `codemode.docs()` alias (D6);
//   (b) codemode still registers exactly the two tools `search` and
//       `execute` (the pair mcp-agent-factory.ts's init() looks up on
//       `_registeredTools` and unconditionally `.update()`s — D2/D3);
//   (c) codemode's own (incomplete) RequestOptions base-field list, which
//       our authoritative descriptions/docs.ts request-options section
//       states is "codemode's own base fields" (D5) — if upstream adds a
//       field, that claim goes stale.
describe("description-budget-docs-surface drift guards (Task 6)", () => {
  describe("sandbox anchor (D6)", () => {
    it("the TEMPLATE SOURCE in the installed bundle still contains the anchor's raw characters", () => {
      // createOpenApiSandboxCode's outer template literal is bundled as-is
      // (not evaluated), so the anchor plus the literal text immediately
      // following it in the SOURCE FILE is safe to pin verbatim — EXCEPT the
      // `${normalized}` interpolation placeholder just past it, which names
      // codemode's own internal local variable and would false-fire on a
      // purely cosmetic rename. Truncated right before that name.
      const TEMPLATE_TAIL_SOURCE = "\n};\nreturn __truncateResponse(await (";
      expect(TEMPLATE_TAIL_SOURCE.startsWith(CODEMODE_SANDBOX_ANCHOR)).toBe(true);
      expect(mcpJs).toContain(TEMPLATE_TAIL_SOURCE);
    });

    it("strongest form: a real openApiMcpServer + capturing executor sees the anchor in the CODE STRING for both search and execute, patchCodemodeDocsAlias splices cleanly, and the codemode object's members match", async () => {
      const { executor, getCodes } = makeCodeCapturingExecutor();
      const server = openApiMcpServer({
        spec: MINIMAL_SPEC,
        executor,
        request: async () => ({}),
      }) as unknown as {
        connect: (t: unknown) => Promise<void>;
        close: () => Promise<void>;
      };

      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      await server.connect(serverTransport);
      const client = new Client({ name: "drift-guard", version: "1.0" });
      try {
        await client.connect(clientTransport);

        await client.callTool({ name: "search", arguments: { code: "async () => 1" } });
        await client.callTool({ name: "execute", arguments: { code: "async () => 1" } });
      } finally {
        await client.close();
        await server.close();
      }

      const codes = getCodes();
      expect(codes).toHaveLength(2);
      const [searchCode, executeCode] = codes as [string, string];

      for (const code of codes) {
        expect(code, "generated sandbox code must contain the anchor patchCodemodeDocsAlias matches on")
          .toContain(CODEMODE_SANDBOX_ANCHOR);

        // F2: exercise the actual splice, not just the anchor's presence —
        // a drift that keeps the anchor but breaks the insertion (e.g. a
        // trailing-comma SyntaxError) would otherwise escape this file
        // entirely and only surface as every sandbox run failing at once.
        const patched = patchCodemodeDocsAlias(code);
        const DOCS_MARKER = "docs: async (section) => await __docsHost.docs(section)";
        const markerCount = patched.split(DOCS_MARKER).length - 1;
        expect(markerCount, "patchCodemodeDocsAlias must insert the docs alias exactly once").toBe(1);
        expect(
          patched.indexOf(DOCS_MARKER),
          "the inserted docs alias must land BEFORE the anchor it was spliced against",
        ).toBeLessThan(patched.indexOf(CODEMODE_SANDBOX_ANCHOR));
        expect(
          () => new Function(`"use strict"; return (${patched});`),
          "patched code must still be syntactically valid JavaScript",
        ).not.toThrow();
      }

      // F4 (strong form): the runtime-generated `const codemode = {...}`
      // object literal declares exactly the members OVERVIEW_TEXT documents
      // — `spec` always, `request` only where codemode wires it in (execute).
      const codemodeLiteral = (code: string): string => {
        const m = /const codemode = \{([\s\S]*?)\n\};/.exec(code);
        expect(m, "sandbox no longer defines `const codemode = {...}` in the shape this test expects").not.toBeNull();
        return m![1]!;
      };
      expect(topLevelMemberNames(codemodeLiteral(searchCode)).sort()).toEqual(["spec"]);
      expect(topLevelMemberNames(codemodeLiteral(executeCode)).sort()).toEqual(["request", "spec"]);
    });
  });

  describe("codemode sandbox API surface (D1/D6)", () => {
    it("the bundle's `declare const codemode: {...}` type (the request-capable variant) still declares exactly spec + request", () => {
      const declareBlocks = [...mcpJs.matchAll(/declare const codemode: \{([\s\S]*?)\n\};/g)];
      const withRequest = declareBlocks.find((m) => /\brequest\s*\(/.test(m[1]!));
      expect(
        withRequest,
        "codemode no longer declares a `codemode: {...}` type with a `request(...)` member — " +
          "update descriptions/docs.ts's OVERVIEW_TEXT (it documents both codemode.spec() and codemode.request())",
      ).toBeDefined();

      const members = topLevelMemberNames(withRequest![1]!).sort();
      expect(
        members,
        "codemode's sandbox API surface changed — update descriptions/docs.ts's OVERVIEW_TEXT accordingly",
      ).toEqual(["request", "spec"]);
    });
  });

  describe("registered tool set (D2/D3)", () => {
    it("codemode registers exactly `search` and `execute` via registerTool — no more, no fewer", () => {
      const server = openApiMcpServer({
        spec: MINIMAL_SPEC,
        executor: { execute: async () => ({ result: undefined }) },
        request: async () => ({}),
      });
      const registeredTools = (server as unknown as { _registeredTools?: Record<string, unknown> })
        ._registeredTools;
      expect(
        registeredTools,
        "codemode's McpServer no longer exposes _registeredTools — SDK/codemode registration shape changed",
      ).toBeDefined();
      expect(
        Object.keys(registeredTools!).sort(),
        "codemode's registered-tool set changed — init()'s unconditional " +
          "`_registeredTools.execute`/`.search` lookup in mcp-agent-factory.ts " +
          "assumes exactly these two names",
      ).toEqual(["execute", "search"]);
    });
  });

  describe("RequestOptions base fields (D5)", () => {
    // F1: field NAMES alone don't catch a type WIDENING (e.g. method gaining
    // "HEAD") or a field becoming optional (`path?:` instead of `path:`) —
    // either would silently make descriptions/docs.ts's transcribed
    // RequestOptions interface (buildRequestOptionsText) understate or
    // misstate what codemode itself accepts. Pin the whole interface body,
    // whitespace-normalised so reflowing/reformatting the bundle doesn't
    // false-fire.
    const EXPECTED_REQUEST_OPTIONS_BODY =
      'method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE"; ' +
      "path: string; " +
      "query?: Record<string, string | number | boolean | undefined>; " +
      "body?: unknown; " +
      "contentType?: string; " +
      "rawBody?: boolean;";

    it("codemode's bundled RequestOptions interface body is exactly what descriptions/docs.ts transcribes as 'codemode's own base fields'", () => {
      const match = /interface RequestOptions \{([\s\S]*?)\n\}/.exec(mcpJs);
      expect(
        match,
        "codemode no longer defines an `interface RequestOptions { ... }` block in its REQUEST_TYPES constant — " +
          "update descriptions/docs.ts's request-options section by hand and re-anchor this regex",
      ).not.toBeNull();
      const normalized = match![1]!.replace(/\s+/g, " ").trim();

      expect(
        normalized,
        "codemode's RequestOptions base interface changed (a field, its type, or its optionality) — " +
          "update descriptions/docs.ts's request-options section (buildRequestOptionsText) to keep the " +
          "authoritative interface and its 'codemode's own base fields' claim accurate",
      ).toBe(EXPECTED_REQUEST_OPTIONS_BODY);
    });
  });
});

// Drift guards for the 2026-10-07 security-review fixes in
// mcp-agent-factory.ts (F-4):
//   • createGuardedExecutor tells an `execute` run from a `search` run by the
//     presence of `__openapiHost` in the providers array, and appends
//     `__stagingHost` only to the former. If codemode ever hands `search` a
//     provider of that name (or renames it for `execute`), staging would leak
//     back into `search` or vanish from `execute`.
//   • init() sets `search`'s annotations to `{ readOnlyHint: true }` through
//     `RegisteredTool.update`, which REPLACES the annotations object. That is
//     only lossless while codemode registers `search` with none of its own.
describe("security-review drift guards (F-4)", () => {
  it("search runs get an empty providers array; execute runs get exactly __openapiHost", async () => {
    const seen: string[][] = [];
    const server = openApiMcpServer({
      spec: MINIMAL_SPEC,
      executor: {
        execute: async (_code: string, providersOrFns: unknown) => {
          seen.push(
            Array.isArray(providersOrFns)
              ? (providersOrFns as Array<{ name: string }>).map((p) => p.name)
              : ["<record form>"],
          );
          return { result: "captured" };
        },
      },
      request: async () => ({}),
    }) as unknown as {
      connect: (t: unknown) => Promise<void>;
      close: () => Promise<void>;
    };
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: "drift-guard", version: "1.0" });
    try {
      await client.connect(clientTransport);
      await client.callTool({ name: "search", arguments: { code: "async () => 1" } });
      await client.callTool({ name: "execute", arguments: { code: "async () => 1" } });
    } finally {
      await client.close();
      await server.close();
    }
    expect(
      seen,
      "codemode's per-tool providers changed — re-check createGuardedExecutor's execute/search discriminator",
    ).toEqual([[], ["__openapiHost"]]);
  });

  it("codemode registers `search` without annotations of its own (init() replaces them wholesale)", () => {
    const server = openApiMcpServer({
      spec: MINIMAL_SPEC,
      executor: { execute: async () => ({ result: undefined }) },
      request: async () => ({}),
    });
    const registeredTools = (server as unknown as {
      _registeredTools: Record<string, { annotations?: unknown }>;
    })._registeredTools;
    expect(
      registeredTools.search!.annotations,
      "codemode now annotates `search` — merge them into init()'s readOnlyHint update instead of replacing",
    ).toBeUndefined();
  });
});
