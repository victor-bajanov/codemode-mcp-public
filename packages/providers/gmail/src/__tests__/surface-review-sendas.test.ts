// Tests for the users.settings.sendAs.create inspector (Task 10).

import { describe, it, expect } from "vitest";
import { inspectSendAsCreate } from "../inspectors/sendas";

describe("inspectSendAsCreate", () => {
  it("allows when sendAsEmail is on the allowlist", () => {
    const result = inspectSendAsCreate({
      body: { sendAsEmail: "alias@example.com" },
    });
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies when sendAsEmail is off the allowlist", () => {
    const result = inspectSendAsCreate({
      body: { sendAsEmail: "someone@unrelated.com" },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "capability_escalation",
      reason: "external-sendas",
    });
  });

  it("denies as malformed when sendAsEmail is missing", () => {
    const result = inspectSendAsCreate({ body: {} });
    expect(result).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "sendas-no-email",
    });
  });

  it("denies as malformed when sendAsEmail is not a string", () => {
    const result = inspectSendAsCreate({
      body: { sendAsEmail: 123 },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "sendas-no-email",
    });
  });

  it("matches case-insensitively via the shared allowlist matcher", () => {
    const result = inspectSendAsCreate({
      body: { sendAsEmail: "ALIAS@example.com" },
    });
    expect(result).toMatchObject({ decision: "allow" });
  });
});
