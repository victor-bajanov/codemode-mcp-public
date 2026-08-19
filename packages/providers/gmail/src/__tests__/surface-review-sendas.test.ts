// Tests for the users.settings.sendAs.create inspector.

import { describe, it, expect } from "vitest";
import { inspectSendAsCreate } from "../inspectors/sendas";

// Mirrors the prod (gmail/gmail-dev) wrangler var.
const ENV = {
  OUTBOUND_RECIPIENT_ALLOWLIST: "*@example.com,adam@gmail.com",
};

describe("inspectSendAsCreate", () => {
  it("allows when sendAsEmail is on the allowlist", () => {
    const result = inspectSendAsCreate(
      { body: { sendAsEmail: "alias@example.com" } },
      ENV,
    );
    expect(result).toMatchObject({ decision: "allow" });
  });

  it("denies when sendAsEmail is off the allowlist", () => {
    const result = inspectSendAsCreate(
      { body: { sendAsEmail: "eve@unrelated.com" } },
      ENV,
    );
    expect(result).toMatchObject({
      decision: "deny",
      category: "capability_escalation",
      reason: "external-sendas",
    });
  });

  it("denies even an on-list address when no env is passed (fail closed)", () => {
    const result = inspectSendAsCreate({
      body: { sendAsEmail: "alias@example.com" },
    });
    expect(result).toMatchObject({
      decision: "deny",
      category: "capability_escalation",
      reason: "external-sendas",
    });
  });

  it("resolves the allowlist per deployment", () => {
    const testerEnv = { OUTBOUND_RECIPIENT_ALLOWLIST: "*@tester.example" };
    expect(
      inspectSendAsCreate({ body: { sendAsEmail: "me@tester.example" } }, testerEnv),
    ).toMatchObject({ decision: "allow" });
    expect(
      inspectSendAsCreate({ body: { sendAsEmail: "alias@example.com" } }, testerEnv),
    ).toMatchObject({ decision: "deny", reason: "external-sendas" });
  });

  it("denies as malformed when sendAsEmail is missing", () => {
    const result = inspectSendAsCreate({ body: {} }, ENV);
    expect(result).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "sendas-no-email",
    });
  });

  it("denies as malformed when sendAsEmail is not a string", () => {
    const result = inspectSendAsCreate({ body: { sendAsEmail: 123 } }, ENV);
    expect(result).toMatchObject({
      decision: "deny",
      category: "malformed",
      reason: "sendas-no-email",
    });
  });

  it("matches case-insensitively via the shared allowlist matcher", () => {
    const result = inspectSendAsCreate(
      { body: { sendAsEmail: "ALIAS@example.com" } },
      ENV,
    );
    expect(result).toMatchObject({ decision: "allow" });
  });
});
