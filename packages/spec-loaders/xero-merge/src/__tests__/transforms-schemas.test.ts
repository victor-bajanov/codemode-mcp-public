// packages/spec-loaders/xero-merge/src/__tests__/transforms-schemas.test.ts

import { describe, it, expect } from "vitest";
import { prefixSchemas } from "../transforms/schemas";

describe("prefixSchemas", () => {
  it("renames every component schema by prefix", () => {
    const out = prefixSchemas(
      {
        paths: {},
        components: {
          schemas: {
            Invoice: { type: "object", properties: { id: { type: "string" } } },
            Contact: { type: "object" },
          },
        },
      },
      "Accounting",
    );
    expect(Object.keys(out.components!.schemas!).sort()).toEqual([
      "AccountingContact",
      "AccountingInvoice",
    ]);
  });

  it("rewrites $ref values across paths and components consistently", () => {
    const out = prefixSchemas(
      {
        paths: {
          "/x": {
            get: {
              operationId: "getX",
              responses: {
                "200": { description: "OK", content: { "application/json": { schema: { $ref: "#/components/schemas/Invoice" } } } },
              },
            },
          },
        },
        components: {
          schemas: {
            Invoice: { type: "object", properties: { line: { $ref: "#/components/schemas/LineItem" } } },
            LineItem: { type: "object" },
          },
        },
      },
      "Accounting",
    );
    expect(out.paths["/x"]!.get!.responses!["200"]!.content!["application/json"]!.schema!.$ref)
      .toBe("#/components/schemas/AccountingInvoice");
    expect((out.components!.schemas! as unknown as Record<string, { properties: { line: { $ref: string } } }>).AccountingInvoice!.properties.line.$ref)
      .toBe("#/components/schemas/AccountingLineItem");
  });

  it("does not double-prefix already-prefixed schema names", () => {
    const out = prefixSchemas(
      {
        paths: {},
        components: { schemas: { AccountingInvoice: { type: "object" } } },
      },
      "Accounting",
    );
    expect(Object.keys(out.components!.schemas!)).toEqual(["AccountingInvoice"]);
  });

  it("leaves non-#/components/schemas/ refs unchanged", () => {
    const out = prefixSchemas(
      {
        paths: {
          "/x": { get: { operationId: "getX", parameters: [{ $ref: "#/components/parameters/PageParam" }] } },
        },
        components: { schemas: {}, parameters: { PageParam: { name: "page", in: "query" } } },
      },
      "Accounting",
    );
    expect(out.paths["/x"]!.get!.parameters![0]!.$ref).toBe("#/components/parameters/PageParam");
  });
});
