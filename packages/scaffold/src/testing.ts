// Test battery for ApiProvider invariants. Imported from each provider's
// __tests__/. Kept out of the scaffold's main entry so the worker bundle
// doesn't pull vitest in.

import { describe, it, expect } from "vitest";
import type { ApiProvider } from "./api-provider.js";
import { genericWalker, buildRequestedSchema, resolveRenderer } from "./elicit.js";

const HTTP_METHODS_WITH_BODY = new Set(["POST", "PUT", "PATCH"]);

interface SpecLike {
  paths?: Record<string, Record<string, { operationId?: string }>>;
}

function collectOperationIdToMethod(spec: SpecLike): Map<string, string> {
  const m = new Map<string, string>();
  for (const methods of Object.values(spec.paths ?? {})) {
    for (const [methodKey, op] of Object.entries(methods)) {
      if (typeof op?.operationId === "string") {
        m.set(op.operationId, methodKey.toUpperCase());
      }
    }
  }
  return m;
}

/** Run the standard battery of surface-review invariants for an ApiProvider.
 *  Wraps describe/it from vitest; intended to be called from a *.test.ts file. */
export function providerSurfaceReviewTests<P extends Record<string, unknown>>(
  provider: ApiProvider<P>,
): void {
  describe(`${provider.name} surface-review battery`, () => {
    const idToMethod = collectOperationIdToMethod(provider.spec as unknown as SpecLike);

    it("every surface-review key matches a real spec operationId", () => {
      const missing = Object.keys(provider.surfaceReview).filter((k) => !idToMethod.has(k));
      expect(missing).toEqual([]);
    });

    it("every Tier-3 (deny) entry has a reasoning field", () => {
      const denyMissingReasoning = Object.entries(provider.surfaceReview)
        .filter(([, e]) => e.decision === "deny" && (e.reasoning === undefined || e.reasoning === ""))
        .map(([id]) => id);
      expect(denyMissingReasoning).toEqual([]);
    });

    it("every entry with an inspect hook is on a body-bearing method (POST/PUT/PATCH)", () => {
      const inspectorOnNonBody = Object.entries(provider.surfaceReview)
        .filter(([id, e]) => e.inspect !== undefined && !HTTP_METHODS_WITH_BODY.has(idToMethod.get(id) ?? ""))
        .map(([id]) => `${id} (method=${idToMethod.get(id) ?? "unknown"})`);
      expect(inspectorOnNonBody).toEqual([]);
    });

    it("every elicit entry resolves to a renderer (per-op, per-category, or non-empty walker output)", () => {
      const failures: string[] = [];
      for (const [opId, entry] of Object.entries(provider.surfaceReview)) {
        if (entry.decision !== "elicit") continue;
        const renderer = resolveRenderer(entry, entry.category, provider.elicitRenderers);
        if (renderer) continue;
        const out = genericWalker({
          spec: provider.spec,
          operationId: opId,
          body: undefined,                                    // schema-only check
        });
        if (!out.fields || Object.keys(out.fields).length === 0) {
          failures.push(opId);
        }
      }
      expect(failures).toEqual([]);
    });

    it("every renderer's output round-trips through buildRequestedSchema", () => {
      const failures: string[] = [];
      for (const [opId, entry] of Object.entries(provider.surfaceReview)) {
        if (entry.decision !== "elicit") continue;
        const renderer = resolveRenderer(entry, entry.category, provider.elicitRenderers);
        if (!renderer) continue;
        try {
          const out = renderer({ operationId: opId, body: undefined });
          const schema = buildRequestedSchema(out.fields);
          // Sanity: every required key has a primitive type entry.
          for (const k of schema.required) {
            const t = schema.properties[k]?.type;
            if (t !== "string" && t !== "number" && t !== "boolean") failures.push(opId);
          }
        } catch (e) {
          failures.push(`${opId}: ${(e as Error).message}`);
        }
      }
      expect(failures).toEqual([]);
    });

    it("every inspector that emits decision='elicit' also emits a category", () => {
      // Run each inspector against an empty body to surface any "elicit without
      // category" branch. Inspectors should default to deny on missing fields, so
      // this is a smoke not an exhaustive proof. Inspectors must explicitly set
      // category whenever they emit elicit.
      const failures: string[] = [];
      for (const [opId, entry] of Object.entries(provider.surfaceReview)) {
        if (!entry.inspect) continue;
        for (const probe of [{}, { criteria: {}, action: { removeLabelIds: ["INBOX"] } }]) {
          const result = entry.inspect({ body: probe });
          if (result.decision === "elicit" && !result.category) {
            failures.push(`${opId} (probe ${JSON.stringify(probe)})`);
          }
        }
      }
      expect(failures).toEqual([]);
    });
  });
}
