// Tests for the users.settings.filters.create inspector.
// The inspector module (../inspectors/filters) is implemented in Task 7;
// these tests are the failing red state for Task 6.

import { describe, it, expect } from "vitest";
import { inspectFilterCreate } from "../inspectors/filters";

describe("inspectFilterCreate", () => {
  it("allows action with only addLabelIds", () => {
    const result = inspectFilterCreate({
      body: { action: { addLabelIds: ["LBL"] } },
    });
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies action.forward as capability_escalation", () => {
    const result = inspectFilterCreate({
      body: { action: { forward: "x@y.com" } },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "capability_escalation",
      reason: "filter-forward",
    });
  });

  it("denies action.forwardingEmail (alternate spelling) as capability_escalation", () => {
    const result = inspectFilterCreate({
      body: { action: { forwardingEmail: "x@y.com" } },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "capability_escalation",
      reason: "filter-forward",
    });
  });

  it("elicits when action removes INBOX (auto-archive)", () => {
    const result = inspectFilterCreate({
      body: { action: { removeLabelIds: ["INBOX"] } },
    });
    expect(result).toMatchObject({
      decision: "elicit",
      category: "persistent_state",
      reason: "filter-skip-inbox",
    });
    expect(result.summary).toBeDefined();
  });

  it("denies action.delete as irreversible", () => {
    const result = inspectFilterCreate({
      body: { action: { delete: true } },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "irreversible",
      reason: "filter-delete",
    });
  });

  it("denies a body with no action field as malformed", () => {
    const result = inspectFilterCreate({
      body: { criteria: { from: "x" } },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "filter-no-action",
    });
  });

  it("returns the most restrictive decision when safe and dangerous actions coexist", () => {
    const result = inspectFilterCreate({
      body: { action: { addLabelIds: ["IMPORTANT"], forward: "x@y.com" } },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "capability_escalation",
      reason: "filter-forward",
    });
  });
});
