// packages/spec-loaders/xero-merge/src/__tests__/merge.test.ts
//
// Runs the full pipeline against the vendored YAML files and asserts:
//   - Output is deterministic across runs.
//   - Every operationId is properly namespaced (xero.accounting / xero.files / xero.payroll.au).
//   - At least one operationId from each source spec is present.
//   - openApiMcpServer accepts the result without throwing.

import { describe, it, expect } from "vitest";
import { mergeXeroSpecs } from "../merge";
import { openApiMcpServer } from "@cloudflare/codemode/mcp";

describe("mergeXeroSpecs (end-to-end against vendored YAMLs)", () => {
  it("is deterministic", () => {
    const a = mergeXeroSpecs();
    const b = mergeXeroSpecs();
    expect(JSON.stringify(a.spec)).toEqual(JSON.stringify(b.spec));
    expect(a.operationIds).toEqual(b.operationIds);
  });

  it("namespaces all operationIds with one of the three known prefixes", () => {
    const { operationIds } = mergeXeroSpecs();
    const allowed = ["xero.accounting.", "xero.files.", "xero.payroll.au."];
    for (const id of operationIds) {
      expect(allowed.some((p) => id.startsWith(p))).toBe(true);
    }
  });

  it("includes at least one expected operationId from each source", () => {
    const { operationIds } = mergeXeroSpecs();
    const ids = new Set(operationIds);
    // Touchstones from each upstream spec — expected to exist in any reasonably-current vendor.
    expect([...ids].some((id) => id.startsWith("xero.accounting."))).toBe(true);
    expect([...ids].some((id) => id.startsWith("xero.files."))).toBe(true);
    expect([...ids].some((id) => id.startsWith("xero.payroll.au."))).toBe(true);
  });

  it("openApiMcpServer accepts the merged spec without throwing", () => {
    const { spec } = mergeXeroSpecs();
    expect(() => {
      openApiMcpServer({
        spec: spec as unknown as Record<string, unknown>,
        // Stub executor + request callback — we just want to verify spec acceptance.
        executor: { execute: async () => ({}) } as never,
        request: async () => ({ success: true, status: 200, result: {}, errors: [] }),
      });
    }).not.toThrow();
  });
});
