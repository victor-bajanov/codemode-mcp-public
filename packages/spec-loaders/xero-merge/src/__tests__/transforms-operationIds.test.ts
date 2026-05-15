// packages/spec-loaders/xero-merge/src/__tests__/transforms-operationIds.test.ts

import { describe, it, expect } from "vitest";
import { prefixOperationIds } from "../transforms/operationIds";

describe("prefixOperationIds", () => {
  it("prefixes every operationId with `<prefix>.`", () => {
    const out = prefixOperationIds(
      {
        paths: {
          "/api.xro/2.0/Invoices": {
            get: { operationId: "getInvoices" },
            post: { operationId: "createInvoices" },
          },
        },
      },
      "xero.accounting",
    );
    expect(out.paths["/api.xro/2.0/Invoices"]!.get!.operationId).toBe("xero.accounting.getInvoices");
    expect(out.paths["/api.xro/2.0/Invoices"]!.post!.operationId).toBe("xero.accounting.createInvoices");
  });

  it("skips method entries with no operationId without crashing", () => {
    const out = prefixOperationIds(
      { paths: { "/X": { get: {}, post: { operationId: "doX" } } } },
      "xero.files",
    );
    expect(out.paths["/X"]!.get).toEqual({});
    expect(out.paths["/X"]!.post!.operationId).toBe("xero.files.doX");
  });

  it("does not double-prefix already-prefixed ids", () => {
    const out = prefixOperationIds(
      { paths: { "/X": { get: { operationId: "xero.accounting.getX" } } } },
      "xero.accounting",
    );
    expect(out.paths["/X"]!.get!.operationId).toBe("xero.accounting.getX");
  });
});
