// F-1 (latent): `matchOperation` is first-template-wins and the re-resolve
// check uses the same matcher, so it cannot see a literal route shadowed by an
// earlier parameter template that the upstream router would prefer. Every
// such overlap in this spec must carry the same surface-review treatment, so
// whichever template wins, the decision is the one the upstream applies.

import { describe, it, expect } from "vitest";
import { findShadowConflicts } from "@local/scaffold";
import { spec, surfaceReview } from "../index";

describe("xero: overlapping same-method templates", () => {
  it("never differ in surface-review decision or inspector", () => {
    expect(findShadowConflicts(spec, surfaceReview)).toEqual([]);
  });
});
