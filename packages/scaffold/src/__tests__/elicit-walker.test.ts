import { describe, it, expect } from "vitest";
import { genericWalker } from "../elicit";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";

const SPEC: OpenApiSpec = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://x" }],
  paths: {
    "/items": {
      post: {
        operationId: "createItem",
        requestBody: {
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  count: { type: "integer" },
                  active: { type: "boolean" },
                  blob: { type: "string" },
                  nested: { type: "object" },
                },
              },
            },
          },
        },
        responses: { "200": { description: "OK" } },
      },
    },
  },
  components: { schemas: {} },
};

const BODY_SIMPLE = { name: "alpha", count: 7, active: true };
const BODY_WITH_BLOB = { name: "alpha", blob: "A".repeat(300) };
const BODY_WITH_BASE64 = { name: "alpha", blob: "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo".repeat(10) };

describe("genericWalker", () => {
  it("picks top-level primitive string/number/boolean fields", () => {
    const out = genericWalker({
      spec: SPEC,
      operationId: "createItem",
      body: BODY_SIMPLE,
    });
    expect(out.facts).toEqual({ name: "alpha", count: 7, active: true });
    expect(out.headline).toBe("Confirm operation: createItem");
  });

  it("skips fields whose values exceed 256 chars", () => {
    const out = genericWalker({
      spec: SPEC,
      operationId: "createItem",
      body: BODY_WITH_BLOB,
    });
    expect(out.facts).toEqual({ name: "alpha" });
    expect(out.facts.blob).toBeUndefined();
  });

  it("skips fields whose values look base64 (>=200 chars of [A-Za-z0-9+/=_-])", () => {
    const out = genericWalker({
      spec: SPEC,
      operationId: "createItem",
      body: BODY_WITH_BASE64,
    });
    expect(out.facts).toEqual({ name: "alpha" });
  });

  it("skips object/array fields entirely", () => {
    const out = genericWalker({
      spec: SPEC,
      operationId: "createItem",
      body: { name: "alpha", nested: { foo: 1 } },
    });
    expect(out.facts).toEqual({ name: "alpha" });
  });

  it("merges inspectorSummary entries first (precedence over body fields)", () => {
    const out = genericWalker({
      spec: SPEC,
      operationId: "createItem",
      body: { name: "alpha" },
      inspectorSummary: { recipients: "x@y.com", count: 3 },
    });
    expect(out.facts.recipients).toBe("x@y.com");
    expect(out.facts.count).toBe(3);
    expect(out.facts.name).toBe("alpha");
  });

  it("caps the field count at 5", () => {
    const body: Record<string, string> = {};
    for (let i = 0; i < 10; i++) body["k" + i] = String(i);
    const out = genericWalker({
      spec: SPEC,
      operationId: "createItem",
      body,
      inspectorSummary: { extra: "z" },
    });
    expect(Object.keys(out.facts).length).toBeLessThanOrEqual(5);
    expect(out.facts.extra).toBe("z"); // inspectorSummary wins
  });

  it("returns no facts (never a confirm fact) when nothing usable is found", () => {
    const out = genericWalker({
      spec: SPEC,
      operationId: "createItem",
      body: { nested: { x: 1 } },
    });
    expect(out.facts).toEqual({});
    expect(out.headline).toBe("Confirm operation: createItem");
  });

  it("returns no facts when operationId is unknown", () => {
    const out = genericWalker({
      spec: SPEC,
      operationId: "unknownOp",
      body: { name: "x" },
    });
    expect(out.facts).toEqual({});
  });
});
