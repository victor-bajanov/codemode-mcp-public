// B7 — Does reviewer-only `reasoning` reach the client-visible spec or docs?
//
// SurfaceReviewEntry.reasoning is documented as "NEVER shown to a client";
// `clientNote` is the client-facing field. The `search` sandbox receives the
// whole annotated spec, and `docs`/`__docsHost` return buildProviderDocs.
// Check both over the three REAL providers.
//
// Status: REFUTED (control holds — no reasoning text leaks).
import { describe, it, expect } from "vitest";
import { annotateSpecWithSurfaceReview } from "../../annotate-spec";
import { buildProviderDocs } from "../../descriptions/docs";
import { gmailProvider } from "../../../../providers/gmail/src/index";
import { xeroProvider } from "../../../../providers/xero/src/index";
import { opticalProvider } from "../../../../providers/optical/src/index";
import type { ApiProvider } from "../../api-provider";

const providers: Array<[string, ApiProvider]> = [
  ["gmail", gmailProvider as unknown as ApiProvider],
  ["xero", xeroProvider as unknown as ApiProvider],
  ["optical", opticalProvider as unknown as ApiProvider],
];

/** Distinctive probes: sentences from `reasoning` that are unlikely to appear
 *  verbatim elsewhere (skip very short ones). */
function probesFrom(reasoning: string): string[] {
  return reasoning
    .split(/(?<=[.;])\s+|\n/)
    .map((s) => s.trim())
    .filter((s) => s.length >= 40)
    .map((s) => s.slice(0, 80));
}

describe("B7 — surface-review `reasoning` never leaks (REFUTED)", () => {
  for (const [name, provider] of providers) {
    it(`${name}: annotated spec and full docs contain no reasoning text`, () => {
      const annotated = annotateSpecWithSurfaceReview(
        provider.spec as unknown as Record<string, unknown>,
        provider.surfaceReview,
      );
      const specJson = JSON.stringify(annotated);
      const docs = buildProviderDocs(provider, true, annotated).full;
      let entriesWithReasoning = 0;
      let probes = 0;
      for (const [opId, entry] of Object.entries(provider.surfaceReview)) {
        if (!entry.reasoning) continue;
        entriesWithReasoning++;
        for (const probe of probesFrom(entry.reasoning)) {
          probes++;
          // A clientNote may legitimately echo a sentence of the reasoning —
          // only flag text that is NOT also in clientNote.
          if (entry.clientNote && entry.clientNote.includes(probe)) continue;
          expect(specJson, `${name}:${opId} reasoning leaked into annotated spec`).not.toContain(probe);
          expect(docs, `${name}:${opId} reasoning leaked into docs`).not.toContain(probe);
        }
      }
      // eslint-disable-next-line no-console
      console.log(`[B7] ${name}: ${entriesWithReasoning} entries with reasoning, ${probes} probes checked — none leaked`);
      expect(specJson).not.toContain('"reasoning"');
      expect(docs).not.toMatch(/\breasoning:/);
    });
  }

  it("docs builder takes no env: DEPLOYMENT_NAME / secrets cannot be interpolated", () => {
    expect(buildProviderDocs.length).toBe(3); // (provider, stagingEnabled, annotatedSpec)
    const docs = buildProviderDocs(gmailProvider as unknown as ApiProvider, true, gmailProvider.spec as never).full;
    for (const needle of ["GOOGLE_CLIENT_SECRET", "COOKIE_ENCRYPTION_KEY", "refresh_token", "client_secret"]) {
      expect(docs).not.toContain(needle);
    }
  });
});
