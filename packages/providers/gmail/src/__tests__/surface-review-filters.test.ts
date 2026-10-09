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

  it("refuses action.delete as an unknown FilterAction field (F-8)", () => {
    // "Delete it" is addLabelIds: ["TRASH"]; `delete` is not a FilterAction
    // field, so it now falls under the fail-closed unknown-key rule.
    const result = inspectFilterCreate({
      body: { action: { delete: true } },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "filter-unknown-action-field",
    });
  });

  // Google's proto3 JSON parser accepts the original proto field name as well
  // as the lowerCamelCase JSON name, so the snake_case spelling must be read.
  it.each([["TRASH"], ["SPAM"], ["trash"]])(
    "elicits when add_label_ids (proto field name) contains %s (F-8)",
    (label) => {
      expect(
        inspectFilterCreate({ body: { criteria: { from: "x" }, action: { add_label_ids: [label] } } }),
      ).toMatchObject({ decision: "elicit", category: "irreversible", reason: "filter-trash-or-spam" });
    },
  );

  it("elicits when add_label_ids is a bare TRASH string", () => {
    expect(inspectFilterCreate({ body: { action: { add_label_ids: "TRASH" } } })).toMatchObject({
      decision: "elicit",
      reason: "filter-trash-or-spam",
    });
  });

  it("elicits when remove_label_ids (proto field name) contains INBOX", () => {
    expect(
      inspectFilterCreate({ body: { criteria: { from: "x" }, action: { remove_label_ids: ["INBOX"] } } }),
    ).toMatchObject({ decision: "elicit", category: "persistent_state", reason: "filter-skip-inbox" });
  });

  it("checks both spellings when both are present", () => {
    expect(
      inspectFilterCreate({ body: { action: { addLabelIds: ["Label_1"], add_label_ids: ["SPAM"] } } }),
    ).toMatchObject({ decision: "elicit", reason: "filter-trash-or-spam" });
    expect(
      inspectFilterCreate({ body: { action: { removeLabelIds: [], remove_label_ids: ["inbox"] } } }),
    ).toMatchObject({ decision: "elicit", reason: "filter-skip-inbox" });
  });

  it("allows benign labels under the snake_case spelling", () => {
    expect(
      inspectFilterCreate({ body: { action: { add_label_ids: ["Label_1"], remove_label_ids: ["UNREAD"] } } }),
    ).toMatchObject({ decision: "allow" });
  });

  it.each([
    [{ addLabelIDs: ["TRASH"] }],
    [{ AddLabelIds: ["TRASH"] }],
    [{ addLabelIds: ["Label_1"], labelIds: ["TRASH"] }],
    [{ forwarding_email: "x@y.com" }],
  ])("denies an unknown action key as malformed: %j", (action) => {
    expect(inspectFilterCreate({ body: { action } })).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "filter-unknown-action-field",
    });
  });

  it("forwarding wins over an unknown action key", () => {
    expect(inspectFilterCreate({ body: { action: { forward: "x@y.com", delete: true } } })).toMatchObject({
      decision: "deny",
      reason: "filter-forward",
    });
  });

  it.each([["TRASH"], ["SPAM"], ["trash"], ["Spam"], [" TRASH "]])(
    "elicits when addLabelIds contains %s (F-8)",
    (label) => {
      const result = inspectFilterCreate({
        body: { criteria: { from: "alerts@bank.example" }, action: { addLabelIds: ["Label_1", label] } },
      });
      expect(result).toMatchObject({
        decision: "elicit",
        category: "irreversible",
        reason: "filter-trash-or-spam",
      });
      expect(result.summary).toMatchObject({
        criteria: JSON.stringify({ from: "alerts@bank.example" }),
      });
    },
  );

  it("elicits for a lower-case inbox in removeLabelIds", () => {
    const result = inspectFilterCreate({
      body: { action: { removeLabelIds: ["inbox"] } },
    });
    expect(result).toMatchObject({ decision: "elicit", reason: "filter-skip-inbox" });
  });

  it("forwarding still wins (deny) over TRASH", () => {
    const result = inspectFilterCreate({
      body: { action: { addLabelIds: ["TRASH"], forward: "x@y.com" } },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "capability_escalation",
      reason: "filter-forward",
    });
  });

  it("ignores non-string label ids and TRASH/SPAM in removeLabelIds", () => {
    expect(
      inspectFilterCreate({ body: { action: { addLabelIds: [1, null, { id: "TRASH" }] } } }),
    ).toMatchObject({ decision: "allow" });
    expect(
      inspectFilterCreate({ body: { action: { removeLabelIds: ["TRASH", "SPAM"] } } }),
    ).toMatchObject({ decision: "allow" });
  });

  it("treats a bare string label field as a one-element list (fails closed)", () => {
    expect(inspectFilterCreate({ body: { action: { addLabelIds: "TRASH" } } })).toMatchObject({
      decision: "elicit",
      reason: "filter-trash-or-spam",
    });
    expect(inspectFilterCreate({ body: { action: { addLabelIds: " spam " } } })).toMatchObject({
      decision: "elicit",
      reason: "filter-trash-or-spam",
    });
    expect(inspectFilterCreate({ body: { action: { removeLabelIds: "INBOX" } } })).toMatchObject({
      decision: "elicit",
      reason: "filter-skip-inbox",
    });
    expect(inspectFilterCreate({ body: { action: { addLabelIds: "Label_1" } } })).toMatchObject({
      decision: "allow",
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
