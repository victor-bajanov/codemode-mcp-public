// Provider-wide surface-review invariants (identity match against bundled spec,
// Tier-3 reasoning presence, inspectors-on-body-methods). Implementation lives
// in @local/scaffold/testing so all providers share the same battery.

import { describe, it, expect } from "vitest";
import { providerSurfaceReviewTests } from "@local/scaffold/testing";
import { gmailProvider } from "../index";
import { surfaceReview } from "../surface-review";

providerSurfaceReviewTests(gmailProvider);

// Provider-specific extras retained from the original test file:
describe("gmail-specific surface-review entries", () => {
  it("explicitly-listed slice-2-closeout entries are present", () => {
    const explicit = [
      "gmail.users.settings.filters.list",
      "gmail.users.settings.filters.get",
      "gmail.users.messages.attachments.get",
    ];
    for (const id of explicit) {
      expect(surfaceReview[id], `expected ${id} in surface review`).toBeDefined();
    }
  });
});
