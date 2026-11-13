// packages/spec-loaders/xero-merge/src/__tests__/transforms-parameters.test.ts
//
// D-2 — the Xero sub-specs declare many query parameters (`unitdp`,
// `summarizeErrors`, `pageSize`, …) as `$ref: "#/components/parameters/<name>"`,
// but `unify` only carries `components.schemas`, so the merged spec had dangling
// refs and the query policy could not see those names. `inlineParameterRefs`
// replaces each parameter `$ref` with the referenced object from the sub-doc's
// own `components.parameters`; an unknown ref fails the build.

import { describe, it, expect } from "vitest";
import { inlineParameterRefs } from "../transforms/parameters";
import { mergeXeroSpecs } from "../merge";

const UNITDP = { in: "query", name: "unitdp", schema: { type: "integer" } };
const TENANT = { in: "header", name: "xero-tenant-id", required: true, schema: { type: "string" } };

describe("inlineParameterRefs", () => {
  it("inlines operation-level and path-item-level refs", () => {
    const out = inlineParameterRefs({
      paths: {
        "/Invoices": {
          parameters: [{ $ref: "#/components/parameters/requiredHeader" }],
          post: {
            operationId: "createInvoices",
            parameters: [
              { $ref: "#/components/parameters/requiredHeader" },
              { $ref: "#/components/parameters/unitdp" },
            ],
          },
        },
      },
      components: { parameters: { unitdp: UNITDP, requiredHeader: TENANT }, schemas: {} },
    });
    const item = out.paths["/Invoices"] as Record<string, unknown>;
    expect(item.parameters).toEqual([TENANT]);
    expect((item.post as { parameters: unknown[] }).parameters).toEqual([TENANT, UNITDP]);
  });

  it("returns copies, not shared references to the component objects", () => {
    const params = { unitdp: UNITDP };
    const out = inlineParameterRefs({
      paths: { "/a": { get: { parameters: [{ $ref: "#/components/parameters/unitdp" }] } } },
      components: { parameters: params },
    });
    const inlined = ((out.paths["/a"] as Record<string, { parameters: unknown[] }>).get!
      .parameters[0]) as Record<string, unknown>;
    expect(inlined).toEqual(UNITDP);
    expect(inlined).not.toBe(UNITDP);
  });

  it("leaves non-ref parameters untouched", () => {
    const inline = { in: "query", name: "where", schema: { type: "string" } };
    const out = inlineParameterRefs({
      paths: { "/a": { get: { parameters: [inline] } } },
      components: { parameters: { unitdp: UNITDP } },
    });
    expect((out.paths["/a"] as Record<string, { parameters: unknown[] }>).get!.parameters).toEqual([
      inline,
    ]);
  });

  it("throws on a dangling ref", () => {
    expect(() =>
      inlineParameterRefs({
        paths: { "/a": { get: { parameters: [{ $ref: "#/components/parameters/nope" }] } } },
        components: { parameters: { unitdp: UNITDP } },
      }),
    ).toThrow(/nope/);
  });

  it("throws on a ref that does not point into components.parameters", () => {
    expect(() =>
      inlineParameterRefs({
        paths: { "/a": { get: { parameters: [{ $ref: "#/components/schemas/unitdp" }] } } },
        components: { parameters: { unitdp: UNITDP } },
      }),
    ).toThrow();
  });

  it("does not resolve inherited Object.prototype names", () => {
    expect(() =>
      inlineParameterRefs({
        paths: { "/a": { get: { parameters: [{ $ref: "#/components/parameters/toString" }] } } },
        components: { parameters: {} },
      }),
    ).toThrow(/toString/);
  });

  it("a doc without components.parameters passes when it has no refs", () => {
    const doc = {
      paths: { "/a": { get: { parameters: [{ in: "query", name: "page" }] } } },
    };
    expect(inlineParameterRefs(doc)).toEqual(doc);
  });
});

describe("mergeXeroSpecs (parameters)", () => {
  const { spec } = mergeXeroSpecs();

  function findOp(id: string): { parameters?: Array<Record<string, unknown>> } {
    for (const item of Object.values(spec.paths)) {
      for (const op of Object.values(item as Record<string, unknown>)) {
        const o = op as { operationId?: string };
        if (o && o.operationId === id) return o as { parameters?: Array<Record<string, unknown>> };
      }
    }
    throw new Error(`op ${id} not found`);
  }

  it("leaves no parameter $ref in the merged spec", () => {
    expect(JSON.stringify(spec.paths)).not.toContain("#/components/parameters/");
  });

  it("createInvoices declares unitdp and summarizeErrors as query params", () => {
    const names = (findOp("xero.accounting.createInvoices").parameters ?? [])
      .filter((p) => p.in === "query")
      .map((p) => p.name);
    expect(names).toEqual(expect.arrayContaining(["unitdp", "summarizeErrors"]));
  });
});
