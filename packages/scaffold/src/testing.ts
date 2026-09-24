// Test battery for ApiProvider invariants. Imported from each provider's
// __tests__/. Kept out of the scaffold's main entry so the worker bundle
// doesn't pull vitest in.

import { describe, it, expect } from "vitest";
import type { ApiProvider } from "./api-provider.js";
import { genericWalker, buildRequestedSchema, resolveRenderer } from "./elicit.js";
import { annotateSpecWithSurfaceReview, type AnnotatableSpec } from "./annotate-spec.js";
import { buildProviderDocs } from "./descriptions/docs.js";
// DOCS_TOOL_DESCRIPTION comes from descriptions/compact.js, NOT
// mcp-agent-factory.js — the factory import would drag the
// agents/@cloudflare/codemode/cloudflare:workers chain into every provider
// test bundle (review finding; the per-provider vitest cloudflare stubs
// remain as belt-and-braces for other scaffold-entry imports).
import {
  buildCompactExecuteDescription,
  buildCompactRegisterFileHandleDescription,
  COMPACT_SEARCH_DESCRIPTION,
  DOCS_TOOL_DESCRIPTION,
} from "./descriptions/compact.js";

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

/** Run the shared description-budget + docs-completeness battery for an
 *  ApiProvider (description-budget-docs-surface, spec D3/D7). Wraps
 *  describe/it from vitest; intended to be called from a *.test.ts file.
 *
 *  `opts.stagingEnabled` must match how the real worker configures this
 *  provider (gmail/xero: true, optical: false) — several assertions below
 *  are conditioned on it, mirroring the docs builder's own conditions.
 *
 *  `opts.expectsCrlfJoin` and `opts.expectCompactHint` turn two previously
 *  best-effort checks into hard requirements for providers that must carry
 *  them (gmail's attachmentHint for the former; every real provider once
 *  Task 7's compactHint lands, for the latter) — see review findings F1/F4
 *  on the description-budget-docs-surface plan. */
export function providerDescriptionBudgetTests<P extends Record<string, unknown>>(
  provider: ApiProvider<P>,
  opts: { stagingEnabled: boolean; expectsCrlfJoin?: boolean; expectCompactHint?: boolean },
): void {
  describe(`${provider.name} description-budget battery`, () => {
    const annotatedSpec = annotateSpecWithSurfaceReview(
      provider.spec as unknown as AnnotatableSpec,
      provider.surfaceReview,
    );
    const docs = buildProviderDocs(provider, opts.stagingEnabled, annotatedSpec);
    // Same pairing init() uses: the advertised section list comes from the
    // docs builder's actual output, never a re-derivation.
    const compactExecute = buildCompactExecuteDescription(
      provider,
      opts.stagingEnabled,
      Object.keys(docs.sections),
    );

    it("compact execute description fits the 1,800-char client truncation budget", () => {
      expect(compactExecute.length).toBeLessThanOrEqual(1800);
    });

    it("compact execute description does not carry the evicted OpenApiSpec type dump", () => {
      expect(compactExecute).not.toContain("interface OpenApiSpec");
    });

    it("COMPACT_SEARCH_DESCRIPTION fits both the hard cap and its tighter target", () => {
      expect(COMPACT_SEARCH_DESCRIPTION.length).toBeLessThanOrEqual(1800);
      expect(COMPACT_SEARCH_DESCRIPTION.length).toBeLessThanOrEqual(900);
    });

    it("DOCS_TOOL_DESCRIPTION (the docs tool's own one-liner) fits its budget", () => {
      expect(DOCS_TOOL_DESCRIPTION.length).toBeLessThanOrEqual(300);
    });

    it("compactHint, when set, fits its 200-char slot and reaches the compact execute description verbatim", () => {
      // Absence is tolerated by default (not asserted required) — a provider
      // may not have landed a compactHint yet; this battery must not block
      // that unless the caller opts into requiring one (expectCompactHint).
      if (opts.expectCompactHint) {
        expect(provider.compactHint).toBeDefined();
      }
      if (provider.compactHint !== undefined) {
        expect(provider.compactHint.length).toBeLessThanOrEqual(200);
        expect(compactExecute).toContain(provider.compactHint);
      }
    });

    if (opts.stagingEnabled) {
      it("compact register_file_handle description fits both the hard cap and its tighter target", () => {
        const compactRegister = buildCompactRegisterFileHandleDescription();
        expect(compactRegister.length).toBeLessThanOrEqual(1800);
        expect(compactRegister.length).toBeLessThanOrEqual(900);
      });
    }

    it("docs.full carries the complete response-envelope shape", () => {
      // Distinctive substrings pinned against the real ENVELOPE_BLOCK text
      // (descriptions/fragments.ts) — bare words like "success" would also
      // match unrelated prose and wouldn't catch a shape regression.
      expect(docs.full).toContain("success: boolean");
      expect(docs.full).toContain("status: number");
      expect(docs.full).toContain("result: unknown");
      expect(docs.full).toContain("errors: { code: number, message: string }[]");
    });

    it("docs.full carries every RequestOptions field, base and scaffold extensions alike", () => {
      // Base fields (codemode's own).
      expect(docs.full).toContain('method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";');
      expect(docs.full).toContain("path: string;");
      expect(docs.full).toContain("query?: Record<string, string | number | boolean | undefined>;");
      expect(docs.full).toContain("body?: unknown;");
      expect(docs.full).toContain("contentType?: string;");
      expect(docs.full).toContain("rawBody?: boolean;");
      // Scaffold extensions — the ones codemode's own (incomplete) type dump
      // omits; a partial listing here would read as closed and mislead.
      expect(docs.full).toContain("headers?: Record<string, string>;");
      expect(docs.full).toContain("bodyBase64?: string;");
      expect(docs.full).toContain("multipart?: Array<{ name: string;");
      expect(docs.full).toContain('returnAs?: "stage";');
    });

    it("docs.full states the ACCESS availability convention", () => {
      expect(docs.full).toContain("ACCESS: ");
    });

    if (opts.stagingEnabled) {
      it("docs.full names every staging mode an agent needs (upload + all three return modes)", () => {
        expect(docs.full).toContain("register_file_handle");
        expect(docs.full).toContain("stageFromUpstreamJson");
        expect(docs.full).toContain('returnAs: "stage"');
        expect(docs.full).toContain("putFile");
      });
    }

    // F2: the provider-owned hints are the whole reason the docs plumbing
    // exists (Task 7 moved everything a provider says onto them) — pin that
    // each one actually reaches docs.full verbatim, not just that the
    // generic scaffold text is there.
    it("docs.full carries the provider's executeHint verbatim, when set", () => {
      if (provider.executeHint) {
        expect(docs.full).toContain(provider.executeHint);
      }
    });

    if (opts.stagingEnabled) {
      it("docs.full carries the provider's attachmentHint verbatim, when set", () => {
        if (provider.attachmentHint) {
          expect(docs.full).toContain(provider.attachmentHint);
        }
      });

      it("docs.full carries the provider's downloadHint verbatim, when set", () => {
        if (provider.downloadHint) {
          expect(docs.full).toContain(provider.downloadHint);
        }
      });
    }

    // F3: compact.ts's applicableDocSections() and docs.ts's own section
    // inclusion conditions are two parallel switches over the same provider
    // state — nothing forces them to agree. Pin that the section list the
    // compact execute description ADVERTISES is exactly the set of sections
    // the docs tool actually HAS, so a caller who reads the pointer never
    // finds a promised section missing (or an unadvertised one hiding).
    it("compact execute's advertised docs section list matches docs.sections exactly", () => {
      // Parsed against compact.ts's docSectionsList(), whose output always
      // ends with the line `## Full docs: call \`docs\`. Sections: <a>, <b>, ....`
      // (see descriptions/compact.ts) — if that format changes, this parse
      // failing loudly is the point, not a false negative to work around.
      const match = compactExecute.trimEnd().match(/Sections: ([^\n]+)\.$/);
      if (!match) {
        throw new Error(
          "compact execute description's trailing 'Sections: ...' line not found — " +
            "has compact.ts's docSectionsList() format changed?",
        );
      }
      const advertised = new Set(match[1]!.split(", ").map((s) => s.trim()));
      expect(advertised).toEqual(new Set(Object.keys(docs.sections)));
    });

    // Spec D7 (whitespace-is-content): a claude.ai capture showed newline
    // collapse turning `.join("\r\n")` into `.join(" ")` in RFC 822 material.
    // `crlfJoin` is a 13-character literal — `.`, `join(`, a quote, the two
    // TWO-CHARACTER escapes `\r` and `\n` (backslash + letter, not an actual
    // CR/LF), a closing quote, and `)`.
    const crlfJoin = '.join("\\r\\n")';
    if (opts.expectsCrlfJoin) {
      // F1: this used to be conditioned on the provider ALREADY having the
      // literal, which made the check evaporate silently if the hint's
      // wording ever changed. Require it outright for providers the caller
      // says must carry it (currently gmail).
      it("provider's attachmentHint contains the literal CRLF .join() (spec D7), preserved verbatim in docs.full", () => {
        expect(provider.attachmentHint ?? "").toContain(crlfJoin);
        // docs.full carries attachmentHint only when staging is enabled
        // (docs.ts's attachments condition) — asserting it there for a
        // non-staging provider would fail on a correctly configured server.
        if (opts.stagingEnabled) {
          expect(docs.full).toContain(crlfJoin);
        }
      });
    } else if (opts.stagingEnabled && provider.attachmentHint?.includes(crlfJoin)) {
      // Not required for this provider, but if it's there anyway (and staging
      // routes it into docs), the docs builder must still not mangle it.
      it("docs.full preserves the attachmentHint's literal CRLF .join() verbatim (spec D7)", () => {
        expect(docs.full).toContain(crlfJoin);
      });
    }
  });
}
