// packages/spec-loaders/xero-merge/src/__tests__/transforms-paths.test.ts
//
// Path-rewrite transform: rebases each path so that a single document-level
// server `https://api.xero.com` works for all three APIs.
//   Accounting paths → `/api.xro/2.0/<path>`
//   Files paths → `/files.xro/1.0/<path>`
//   Payroll AU paths → `/payroll.xro/1.0/<path>`

import { describe, it, expect } from "vitest";
import { rewritePaths } from "../transforms/paths";

describe("rewritePaths", () => {
  it("prefixes accounting paths with /api.xro/2.0", () => {
    const out = rewritePaths(
      { paths: { "/Invoices": { get: { operationId: "GetInvoices" } } } },
      "/api.xro/2.0",
    );
    expect(Object.keys(out.paths)).toEqual(["/api.xro/2.0/Invoices"]);
  });

  it("prefixes files paths with /files.xro/1.0", () => {
    const out = rewritePaths(
      { paths: { "/Files": { get: {} }, "/Files/{FileId}": { get: {} } } },
      "/files.xro/1.0",
    );
    expect(Object.keys(out.paths).sort()).toEqual([
      "/files.xro/1.0/Files",
      "/files.xro/1.0/Files/{FileId}",
    ]);
  });

  it("prefixes payroll-au paths with /payroll.xro/1.0", () => {
    const out = rewritePaths(
      { paths: { "/Employees": { get: {} } } },
      "/payroll.xro/1.0",
    );
    expect(Object.keys(out.paths)).toEqual(["/payroll.xro/1.0/Employees"]);
  });

  it("strips leading slash from prefix and ensures exactly one slash join", () => {
    const out = rewritePaths(
      { paths: { "/X": {} } },
      "api.xro/2.0/",   // intentionally messy input
    );
    expect(Object.keys(out.paths)).toEqual(["/api.xro/2.0/X"]);
  });

  it("preserves the per-operation method-keys and operation objects unchanged", () => {
    const op = { operationId: "GetX", description: "fetch X" };
    const out = rewritePaths(
      { paths: { "/X": { get: op } } },
      "/api.xro/2.0",
    );
    expect((out.paths as Record<string, unknown>)["/api.xro/2.0/X"]).toEqual({ get: op });
  });
});
