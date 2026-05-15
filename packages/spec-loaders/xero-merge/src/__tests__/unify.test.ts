// packages/spec-loaders/xero-merge/src/__tests__/unify.test.ts

import { describe, it, expect } from "vitest";
import { unify } from "../unify";

const A = {
  openapi: "3.0.0",
  info: { title: "A", version: "1" },
  servers: [{ url: "https://a.example.com" }],
  paths: { "/api.xro/2.0/Invoices": { get: { operationId: "xero.accounting.getInvoices", responses: { "200": { description: "OK" } } } } },
  components: { schemas: { AccountingInvoice: { type: "object" } } },
} as const;

const B = {
  openapi: "3.0.0",
  info: { title: "B", version: "1" },
  servers: [{ url: "https://b.example.com" }],
  paths: { "/files.xro/1.0/Files": { get: { operationId: "xero.files.getFiles", responses: { "200": { description: "OK" } } } } },
  components: { schemas: { FilesFile: { type: "object" } } },
} as const;

describe("unify", () => {
  it("merges paths and component schemas", () => {
    const out = unify([A, B], { title: "Xero", version: "1.0", serverUrl: "https://api.xero.com" });
    expect(Object.keys(out.paths).sort()).toEqual([
      "/api.xro/2.0/Invoices",
      "/files.xro/1.0/Files",
    ]);
    expect(Object.keys(out.components.schemas).sort()).toEqual([
      "AccountingInvoice",
      "FilesFile",
    ]);
  });

  it("emits a single document-level server", () => {
    const out = unify([A, B], { title: "Xero", version: "1.0", serverUrl: "https://api.xero.com" });
    expect(out.servers).toEqual([{ url: "https://api.xero.com" }]);
  });

  it("uses the provided info.title/version, dropping per-spec values", () => {
    const out = unify([A, B], { title: "Xero", version: "9.9", serverUrl: "https://api.xero.com" });
    expect(out.info).toEqual({ title: "Xero", version: "9.9" });
  });

  it("throws on a path collision (same path key across input docs)", () => {
    const A2 = { ...A, paths: { "/dup": { get: { operationId: "a.dup", responses: {} } } } };
    const B2 = { ...B, paths: { "/dup": { get: { operationId: "b.dup", responses: {} } } } };
    expect(() => unify([A2, B2], { title: "X", version: "1", serverUrl: "https://x" })).toThrow(/path collision/i);
  });

  it("throws on a schema-name collision across input docs", () => {
    const A2 = { ...A, components: { schemas: { Shared: { type: "object" } } } };
    const B2 = { ...B, components: { schemas: { Shared: { type: "string" } } } };
    expect(() => unify([A2, B2], { title: "X", version: "1", serverUrl: "https://x" })).toThrow(/schema collision/i);
  });
});
